package quicsni

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	quicsniff "github.com/go-gost/x/internal/util/quic/sniff"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("quicsni", NewHandler)
}

type quicsniHandler struct {
	hop     hop.Hop
	md      metadata
	options handler.Options
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &quicsniHandler{
		options: options,
	}
}

func (h *quicsniHandler) Init(md md.Metadata) (err error) {
	return h.parseMetadata(md)
}

// Forward implements handler.Forwarder.
func (h *quicsniHandler) Forward(hop hop.Hop) {
	h.hop = hop
}

type session struct {
	backend    net.Conn
	clientAddr net.Addr
	lastSeen   atomic.Int64 // UnixNano
}

// Handle receives the raw PacketConn from the listener and runs
// a direct packet relay loop. Each unique client address becomes
// a session with its own backend connection and reverse-relay goroutine.
func (h *quicsniHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	pc, ok := conn.(net.PacketConn)
	if !ok {
		return errors.New("quicsni: expected PacketConn")
	}

	log := h.options.Logger
	log.Infof("quicsni relay on %s", conn.LocalAddr())

	var sessions sync.Map

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go h.cleanupLoop(ctx, &sessions, log)

	buf := make([]byte, h.md.readBufferSize)
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}

		key := raddr.String()
		now := time.Now().UnixNano()

		// Fast path: existing session.
		if si, ok := sessions.Load(key); ok {
			sess := si.(*session)
			sess.lastSeen.Store(now)
			if _, err := sess.backend.Write(buf[:n]); err != nil {
				// Stale session; remove and let the client retransmit.
				sessions.Delete(key)
			}
			continue
		}

		// Slow path: new session.
		h.newSession(ctx, pc, buf[:n], raddr, key, now, &sessions, log)
	}
}

func (h *quicsniHandler) newSession(
	ctx context.Context,
	pc net.PacketConn,
	firstPacket []byte,
	raddr net.Addr,
	key string,
	now int64,
	sessions *sync.Map,
	log logger.Logger,
) {
	host := quicsniff.ExtractSNI(firstPacket)

	target := &chain.Node{}
	if h.hop != nil {
		selectOpts := []hop.SelectOption{
			hop.ProtocolSelectOption("udp"),
		}
		if host != "" {
			selectOpts = append(selectOpts, hop.HostSelectOption(host))
		}
		target = h.hop.Select(ctx, selectOpts...)
	}
	if target == nil {
		log.Warnf("quicsni: no target for %s (sni=%s)", raddr, host)
		return
	}

	cc, err := h.options.Router.Dial(ctx, "udp", target.Addr)
	if err != nil {
		log.Errorf("quicsni: dial %s: %v", target.Addr, err)
		if marker := target.Marker(); marker != nil {
			marker.Mark()
		}
		return
	}
	if marker := target.Marker(); marker != nil {
		marker.Reset()
	}

	sess := &session{
		backend:    cc,
		clientAddr: raddr,
	}
	sess.lastSeen.Store(now)
	sessions.Store(key, sess)

	log.Debugf("quicsni: %s -> %s (sni=%s)", raddr, target.Addr, host)

	if _, err := cc.Write(firstPacket); err != nil {
		cc.Close()
		sessions.Delete(key)
		return
	}

	go h.reverseRelay(pc, sess, sessions, key, log)
}

// reverseRelay forwards packets from the backend back to the client.
func (h *quicsniHandler) reverseRelay(
	pc net.PacketConn,
	sess *session,
	sessions *sync.Map,
	key string,
	log logger.Logger,
) {
	defer func() {
		sess.backend.Close()
		sessions.Delete(key)
		log.Debugf("quicsni: closed %s", key)
	}()

	buf := make([]byte, h.md.readBufferSize)
	for {
		n, err := sess.backend.Read(buf)
		if err != nil {
			return
		}
		sess.lastSeen.Store(time.Now().UnixNano())
		if _, err := pc.WriteTo(buf[:n], sess.clientAddr); err != nil {
			return
		}
	}
}

// cleanupLoop periodically removes idle sessions.
func (h *quicsniHandler) cleanupLoop(ctx context.Context, sessions *sync.Map, log logger.Logger) {
	ticker := time.NewTicker(h.md.ttl)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			ttlNano := int64(h.md.ttl)
			sessions.Range(func(key, value any) bool {
				sess := value.(*session)
				if now-sess.lastSeen.Load() > ttlNano {
					log.Debugf("quicsni: idle %s", key)
					sess.backend.Close()
					sessions.Delete(key)
				}
				return true
			})
		case <-ctx.Done():
			sessions.Range(func(key, value any) bool {
				value.(*session).backend.Close()
				return true
			})
			return
		}
	}
}
