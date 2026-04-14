package quicsni

import (
	"net"
	"strings"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/udp"
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
	ln      net.Listener
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

	var conn *net.UDPConn
	conn, err = net.ListenUDP(network, laddr)
	if err != nil {
		return
	}

	if l.md.socketBufferSize > 0 {
		conn.SetReadBuffer(l.md.socketBufferSize)
		conn.SetWriteBuffer(l.md.socketBufferSize)
	}

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

	l.ln = udp.NewListener(pc, &udp.ListenConfig{
		Backlog:        l.md.backlog,
		ReadQueueSize:  l.md.readQueueSize,
		ReadBufferSize: l.md.readBufferSize,
		TTL:            l.md.ttl,
		Keepalive:      true,
		Logger:         l.logger,
	})

	return
}

func (l *quicsniListener) Accept() (conn net.Conn, err error) {
	conn, err = l.ln.Accept()
	if err != nil {
		return
	}
	conn = limiter_wrapper.WrapConn(
		conn,
		l.options.TrafficLimiter,
		conn.RemoteAddr().String(),
		limiter.ScopeOption(limiter.ScopeConn),
		limiter.ServiceOption(l.options.Service),
		limiter.NetworkOption(conn.LocalAddr().Network()),
		limiter.SrcOption(conn.RemoteAddr().String()),
	)
	return
}

func (l *quicsniListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *quicsniListener) Close() error {
	return l.ln.Close()
}
