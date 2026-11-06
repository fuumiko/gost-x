package quicsni

import (
	"net"
	"strings"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xnet "github.com/go-gost/x/internal/net"
	admission "github.com/go-gost/x/admission/wrapper"
	traffic_limiter "github.com/go-gost/x/limiter/traffic"
	limiter_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	stats "github.com/go-gost/x/observer/stats/wrapper"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ListenerRegistry().Register("quicsni", NewListener)
}

type quicsniListener struct {
	addr    net.Addr
	pc      net.PacketConn
	connCh  chan net.Conn
	done    chan struct{}
	logger  logger.Logger
	md      metadata
	options listener.Options
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &quicsniListener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *quicsniListener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	addr := l.options.Addr
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), "0")
	}

	network := "udp"
	if xnet.IsIPv4(addr) {
		network = "udp4"
	}
	laddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return
	}

	conn, err := net.ListenUDP(network, laddr)
	if err != nil {
		return
	}

	if l.md.socketBufferSize > 0 {
		conn.SetReadBuffer(l.md.socketBufferSize)
		conn.SetWriteBuffer(l.md.socketBufferSize)
	}

	l.addr = conn.LocalAddr()

	var pc net.PacketConn = conn
	pc = metrics.WrapPacketConn(l.options.Service, pc)
	pc = stats.WrapPacketConn(pc, l.options.Stats)
	pc = admission.WrapPacketConn(l.options.Admission, pc)
	pc = limiter_wrapper.WrapPacketConn(
		pc,
		l.options.TrafficLimiter,
		traffic_limiter.ServiceLimitKey,
		limiter.ScopeOption(limiter.ScopeService),
		limiter.ServiceOption(l.options.Service),
		limiter.NetworkOption(pc.LocalAddr().Network()),
	)
	l.pc = pc

	// Deliver the PacketConn once to the handler via Accept().
	l.connCh = make(chan net.Conn, 1)
	l.done = make(chan struct{})
	l.connCh <- &packetConnWrapper{PacketConn: pc}

	return
}

// Accept returns the underlying PacketConn exactly once.
// Subsequent calls block until Close.
func (l *quicsniListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connCh:
		return conn, nil
	case <-l.done:
		return nil, listener.ErrClosed
	}
}

func (l *quicsniListener) Addr() net.Addr {
	return l.addr
}

func (l *quicsniListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return l.pc.Close()
}

// packetConnWrapper bridges net.PacketConn to net.Conn
// so it can pass through the Accept/Handle interface.
type packetConnWrapper struct {
	net.PacketConn
}

func (c *packetConnWrapper) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *packetConnWrapper) Write(b []byte) (int, error) {
	return 0, net.ErrWriteToConnected
}

func (c *packetConnWrapper) RemoteAddr() net.Addr {
	return nil
}
