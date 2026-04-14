package quicsniff

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"sort"

	dissector "github.com/go-gost/tls-dissector"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/crypto/hkdf"
)

// ReadCryptoPayload decrypts a QUIC Initial packet and extracts the
// assembled CRYPTO frame data (raw TLS ClientHello bytes).
func ReadCryptoPayload(packet []byte) ([]byte, error) {
	hdr, offset, err := ParseInitialHeader(packet)
	if err != nil {
		return nil, err
	}
	if hdr.Version != V1 && hdr.Version != V2 {
		return nil, fmt.Errorf("unsupported version: %x", hdr.Version)
	}
	if offset == 0 || hdr.Length == 0 {
		return nil, errors.New("invalid packet")
	}

	initialSecret := hkdf.Extract(crypto.SHA256.New, hdr.DestConnectionID, getSalt(hdr.Version))
	clientSecret := hkdfExpandLabel(crypto.SHA256.New, initialSecret, "client in", []byte{}, crypto.SHA256.Size())
	key, err := NewInitialProtectionKey(clientSecret, hdr.Version)
	if err != nil {
		return nil, fmt.Errorf("NewInitialProtectionKey: %w", err)
	}
	pp := NewPacketProtector(key)
	if int64(len(packet)) < offset+hdr.Length {
		return nil, fmt.Errorf("packet is too short: %d < %d", len(packet), offset+hdr.Length)
	}
	unProtectedPayload, err := pp.UnProtect(packet[:offset+hdr.Length], offset, 2)
	if err != nil {
		return nil, err
	}
	frs, err := extractCryptoFrames(bytes.NewReader(unProtectedPayload))
	if err != nil {
		return nil, err
	}
	data := assembleCryptoFrames(frs)
	if data == nil {
		return nil, errors.New("unable to assemble crypto frames")
	}
	return data, nil
}

// ExtractSNI attempts to extract the SNI hostname from a raw QUIC Initial packet.
// Returns empty string on any failure (non-Initial, decryption error, no SNI extension, etc.).
func ExtractSNI(packet []byte) string {
	payload, err := ReadCryptoPayload(packet)
	if err != nil {
		return ""
	}
	if len(payload) < 4 || payload[0] != 0x01 {
		return ""
	}

	msg := &dissector.ClientHelloMsg{}
	if err := msg.Decode(payload); err != nil {
		return ""
	}
	for _, ext := range msg.Extensions {
		if ext.Type() == dissector.ExtServerName {
			if sne, ok := ext.(*dissector.ServerNameExtension); ok {
				return sne.Name
			}
		}
	}
	return ""
}

const (
	paddingFrameType = 0x00
	pingFrameType    = 0x01
	cryptoFrameType  = 0x06
)

type cryptoFrame struct {
	Offset int64
	Data   []byte
}

func extractCryptoFrames(r *bytes.Reader) ([]cryptoFrame, error) {
	var frames []cryptoFrame
	for r.Len() > 0 {
		typ, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		if typ == paddingFrameType || typ == pingFrameType {
			continue
		}
		if typ != cryptoFrameType {
			return nil, fmt.Errorf("encountered unexpected frame type: %d", typ)
		}
		var frame cryptoFrame
		offset, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		frame.Offset = int64(offset)
		dataLen, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		frame.Data = make([]byte, dataLen)
		if _, err := io.ReadFull(r, frame.Data); err != nil {
			return nil, err
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

func assembleCryptoFrames(frames []cryptoFrame) []byte {
	if len(frames) == 0 {
		return nil
	}
	if len(frames) == 1 {
		return frames[0].Data
	}
	sort.Slice(frames, func(i, j int) bool { return frames[i].Offset < frames[j].Offset })
	for i := 1; i < len(frames); i++ {
		if frames[i].Offset != frames[i-1].Offset+int64(len(frames[i-1].Data)) {
			return nil
		}
	}
	data := make([]byte, frames[len(frames)-1].Offset+int64(len(frames[len(frames)-1].Data)))
	for _, frame := range frames {
		copy(data[frame.Offset:], frame.Data)
	}
	return data
}
