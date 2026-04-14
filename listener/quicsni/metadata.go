package quicsni

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultReadBufferSize   = 4096
	defaultReadQueueSize    = 4096
	defaultBacklog          = 1024
	defaultTTL              = 90 * time.Second
	defaultSocketBufferSize = 4 * 1024 * 1024 // 4MB
)

type metadata struct {
	readBufferSize   int
	readQueueSize    int
	backlog          int
	ttl              time.Duration
	socketBufferSize int
}

func (l *quicsniListener) parseMetadata(md mdata.Metadata) (err error) {
	l.md.readBufferSize = mdutil.GetInt(md, "readBufferSize", "udp.readBufferSize")
	if l.md.readBufferSize <= 0 {
		l.md.readBufferSize = defaultReadBufferSize
	}

	l.md.readQueueSize = mdutil.GetInt(md, "readQueueSize", "udp.readQueueSize")
	if l.md.readQueueSize <= 0 {
		l.md.readQueueSize = defaultReadQueueSize
	}

	l.md.backlog = mdutil.GetInt(md, "backlog")
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	l.md.ttl = mdutil.GetDuration(md, "ttl")
	if l.md.ttl <= 0 {
		l.md.ttl = defaultTTL
	}

	l.md.socketBufferSize = mdutil.GetInt(md, "socketBufferSize", "udp.socketBufferSize")
	if l.md.socketBufferSize <= 0 {
		l.md.socketBufferSize = defaultSocketBufferSize
	}

	return
}
