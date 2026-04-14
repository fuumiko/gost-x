package quicsni

import (
	"bytes"
	"context"
	"errors"
	"net"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xnet "github.com/go-gost/x/internal/net"
	quicsniff "github.com/go-gost/x/internal/util/quic/sniff"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("quicsni", NewHandler)
}

type quicsniHandler struct {
	hop      hop.Hop
	md       metadata
	options  handler.Options
	recorder recorder.RecorderObject
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
	if err = h.parseMetadata(md); err != nil {
		return
	}

	for _, ro := range h.options.Recorders {
		if ro.Record == xrecorder.RecorderServiceHandler {
			h.recorder = ro
			break
		}
	}

	return
}

// Forward implements handler.Forwarder.
func (h *quicsniHandler) Forward(hop hop.Hop) {
	h.hop = hop
}

func (h *quicsniHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()

	ro := &xrecorder.HandlerRecorderObject{
		Service:    h.options.Service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		Network:    "udp",
		Time:       start,
		SID:        xctx.SidFromContext(ctx).String(),
	}

	if srcAddr := xctx.SrcAddrFromContext(ctx); srcAddr != nil {
		ro.ClientAddr = srcAddr.String()
	}

	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"client": ro.ClientAddr,
		"sid":    ro.SID,
	})

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(start)
		if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration":    time.Since(start),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return rate_limiter.ErrRateLimit
	}

	// Read first packet to attempt SNI extraction.
	buf := make([]byte, h.md.readBufferSize)
	if h.md.readTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(h.md.readTimeout))
	}
	n, err := conn.Read(buf)
	if err != nil {
		log.Error("read first packet: ", err)
		return err
	}
	if h.md.readTimeout > 0 {
		conn.SetReadDeadline(time.Time{})
	}

	// Best-effort SNI extraction from QUIC Initial.
	host := quicsniff.ExtractSNI(buf[:n])
	ro.Host = host

	log = log.WithFields(map[string]any{
		"host": host,
	})
	log.Debugf("%s >> quicsni (sni=%s)", conn.RemoteAddr(), host)

	// Select backend via hop.
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
		err = errors.New("node not available")
		log.Error(err)
		return err
	}

	addr := target.Addr
	ro.DstAddr = addr

	log = log.WithFields(map[string]any{
		"node": target.Name,
		"dst":  addr,
	})
	log.Debugf("%s >> %s", conn.RemoteAddr(), addr)

	// Dial backend.
	var routeBuf bytes.Buffer
	cc, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &routeBuf), "udp", addr)
	ro.Route = routeBuf.String()
	if err != nil {
		log.Error(err)
		if marker := target.Marker(); marker != nil {
			marker.Mark()
		}
		return err
	}
	if marker := target.Marker(); marker != nil {
		marker.Reset()
	}
	defer cc.Close()

	// Forward the first packet.
	if _, err := cc.Write(buf[:n]); err != nil {
		log.Error("write first packet: ", err)
		return err
	}

	log.Infof("%s <-> %s", conn.RemoteAddr(), addr)
	t := time.Now()

	// Bidirectional pipe for remaining packets.
	xnet.Pipe(ctx, conn, cc)

	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), addr)

	return nil
}

func (h *quicsniHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}
	return true
}
