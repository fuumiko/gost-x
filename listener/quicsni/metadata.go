package quicsni

import (
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultSocketBufferSize = 4 * 1024 * 1024 // 4MB
)

type metadata struct {
	socketBufferSize int
}

func (l *quicsniListener) parseMetadata(md mdata.Metadata) (err error) {
	l.md.socketBufferSize = mdutil.GetInt(md, "socketBufferSize", "udp.socketBufferSize")
	if l.md.socketBufferSize <= 0 {
		l.md.socketBufferSize = defaultSocketBufferSize
	}
	return
}
