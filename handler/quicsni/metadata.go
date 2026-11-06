package quicsni

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultReadBufferSize = 4096
	defaultTTL            = 90 * time.Second
)

type metadata struct {
	readBufferSize int
	ttl            time.Duration
}

func (h *quicsniHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.readBufferSize = mdutil.GetInt(md, "readBufferSize")
	if h.md.readBufferSize <= 0 {
		h.md.readBufferSize = defaultReadBufferSize
	}

	h.md.ttl = mdutil.GetDuration(md, "ttl")
	if h.md.ttl <= 0 {
		h.md.ttl = defaultTTL
	}

	return
}
