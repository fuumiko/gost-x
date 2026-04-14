package quicsniff

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/hkdf"

	dissector "github.com/go-gost/tls-dissector"
	"github.com/quic-go/quic-go/quicvarint"
)

// buildQUICInitial constructs a minimal QUIC v1 Initial packet containing
// a ClientHello with the given SNI. This verifies our parser round-trips correctly.
func buildQUICInitial(t *testing.T, sni string) []byte {
	t.Helper()

	// Build a minimal TLS ClientHello with SNI.
	ch := &dissector.ClientHelloMsg{
		Version: 0x0303, // TLS 1.2 (legacy in QUIC)
		CipherSuites: []uint16{
			0x1301, // TLS_AES_128_GCM_SHA256
		},
		CompressionMethods: []uint8{0},
	}
	ch.Random.Time = 0x12345678
	ch.SessionID = make([]byte, 32)
	rand.Read(ch.SessionID)
	rand.Read(ch.Random.Opaque[:])

	sne := &dissector.ServerNameExtension{Name: sni}
	ch.Extensions = []dissector.Extension{sne}

	chBytes, err := ch.Encode()
	if err != nil {
		t.Fatal(err)
	}

	// Build the CRYPTO frame wrapping the ClientHello.
	var cryptoFrame []byte
	cryptoFrame = append(cryptoFrame, byte(cryptoFrameType))
	cryptoFrame = quicvarint.Append(cryptoFrame, 0) // offset
	cryptoFrame = quicvarint.Append(cryptoFrame, uint64(len(chBytes)))
	cryptoFrame = append(cryptoFrame, chBytes...)

	// Pad to meet minimum Initial packet size.
	plaintext := cryptoFrame
	for len(plaintext) < 1100 {
		plaintext = append(plaintext, 0x00) // PADDING frames
	}

	// Construct QUIC v1 Initial packet header.
	dcid := make([]byte, 8)
	rand.Read(dcid)
	scid := make([]byte, 8)
	rand.Read(scid)

	// Derive Initial keys.
	initialSecret := hkdf.Extract(crypto.SHA256.New, dcid, getSalt(V1))
	clientSecret := hkdfExpandLabel(crypto.SHA256.New, initialSecret, "client in", []byte{}, crypto.SHA256.Size())

	key := hkdfExpandLabel(crypto.SHA256.New, clientSecret, keyLabel(V1), nil, 16)
	iv := hkdfExpandLabel(crypto.SHA256.New, clientSecret, ivLabel(V1), nil, 12)
	hpKey := hkdfExpandLabel(crypto.SHA256.New, clientSecret, headerProtectionLabel(V1), nil, 16)

	// Encrypt payload: pn=0, pnLen=1 byte
	pn := int64(0)
	pnLen := 1

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], uint64(pn))
	for i := range iv {
		nonce[i] ^= iv[i]
	}

	c, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(c)

	// Build unprotected header.
	var header []byte
	typeByte := byte(0xc0) // long header + Initial for V1 (type bits 00)
	typeByte |= byte(pnLen - 1) // pn length
	header = append(header, typeByte)
	header = binary.BigEndian.AppendUint32(header, V1)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = quicvarint.Append(header, 0) // token length = 0

	// Payload length = pnLen + plaintext + AEAD tag
	payloadLen := pnLen + len(plaintext) + gcm.Overhead()
	header = quicvarint.Append(header, uint64(payloadLen))

	pnOffset := len(header)
	header = append(header, byte(pn)) // 1-byte packet number

	// Encrypt.
	encrypted := gcm.Seal(nil, nonce, plaintext, header)

	// Build final packet: [header (incl. pn byte)] [encrypted payload].
	packet := make([]byte, 0, len(header)+len(encrypted))
	packet = append(packet, header...)
	packet = append(packet, encrypted...)

	// Apply header protection.
	// Sample is at pnOffset+4 in the full packet.
	// encrypted starts at pnOffset+pnLen, so sample is at encrypted[4-pnLen].
	sampleIdx := pnOffset + 4
	if sampleIdx+16 > len(packet) {
		t.Fatal("packet too short for HP sample")
	}
	sample := packet[sampleIdx : sampleIdx+16]

	hp, _ := aes.NewCipher(hpKey)
	mask := make([]byte, hp.BlockSize())
	hp.Encrypt(mask, sample)

	packet[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		packet[pnOffset+i] ^= mask[1+i]
	}

	return packet
}

func TestExtractSNI(t *testing.T) {
	tests := []struct {
		name     string
		sni      string
	}{
		{"simple", "example.com"},
		{"subdomain", "sub.example.org"},
		{"long", "very.long.subdomain.example.co.uk"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := buildQUICInitial(t, tt.sni)
			got := ExtractSNI(packet)
			if got != tt.sni {
				t.Errorf("ExtractSNI() = %q, want %q", got, tt.sni)
			}
		})
	}
}

func TestExtractSNI_InvalidPacket(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
	}{
		{"empty", nil},
		{"too_short", []byte{0xc0, 0x00}},
		{"not_quic", []byte("GET / HTTP/1.1\r\n")},
		{"random_bytes", func() []byte {
			b := make([]byte, 1200)
			rand.Read(b)
			return b
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractSNI(tt.packet)
			if got != "" {
				t.Errorf("ExtractSNI() = %q, want empty string", got)
			}
		})
	}
}
