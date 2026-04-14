package quicsni

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultReadBufferSize = 4096
	defaultReadTimeout    = 15 * time.Second
)

type metadata struct {
	readBufferSize int
	readTimeout    time.Duration
}

func (h *quicsniHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.readBufferSize = mdutil.GetInt(md, "readBufferSize")
	if h.md.readBufferSize <= 0 {
		h.md.readBufferSize = defaultReadBufferSize
	}

	h.md.readTimeout = mdutil.GetDuration(md, "readTimeout")
	if h.md.readTimeout <= 0 {
		h.md.readTimeout = defaultReadTimeout
	}

	return
}
