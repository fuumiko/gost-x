package relay

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/gosocks5"
)

// pipeConn is a net.Conn backed by bytes.Buffer — Write writes to buf, Read reads from buf.
type pipeConn struct {
	net.Conn
	buf []byte
}

func newPipeConn() *pipeConn {
	return &pipeConn{}
}
func (c *pipeConn) Read(b []byte) (int, error) {
	n := copy(b, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}
func (c *pipeConn) Write(b []byte) (int, error) {
	c.buf = append(c.buf, b...)
	return len(b), nil
}
func (c *pipeConn) Close() error { return nil }

func Test_udpTunConn_domainRoundTrip(t *testing.T) {
	pc1 := newPipeConn()
	server := UDPTunServerConn(pc1)

	domain := &domainAddr{network: "udp", host: "dns.google", port: 53}
	_, err := server.WriteTo([]byte("hello"), domain)
	if err != nil {
		t.Fatal(err)
	}

	pc2 := newPipeConn()
	pc2.Write(pc1.buf)

	_, addr, err := UDPTunServerConn(pc2).ReadFrom(make([]byte, 1500))
	if err != nil {
		t.Fatal(err)
	}

	da, ok := addr.(*domainAddr)
	if !ok {
		t.Fatalf("expected *domainAddr, got %T: %s", addr, addr)
	}
	if da.host != "dns.google" || da.port != 53 {
		t.Fatalf("expected dns.google:53, got %s:%d", da.host, da.port)
	}
}

// slowConn is a net.Conn that pauses inside every Write before appending.
//
// A datagram frame is not written to the stream atomically:
// UDPDatagram.WriteTo issues three separate Write calls (RSV/FRAG, SOCKS5
// address, payload). Individually each Write is concurrency-safe, so when
// several per-endpoint handlers share one stream the frames can interleave
// between those calls and corrupt each other. Pausing inside Write widens the
// window so a test observes that interleaving reliably instead of rarely.
type slowConn struct {
	net.Conn
	delay time.Duration

	mu  sync.Mutex
	buf bytes.Buffer
}

func newSlowConn(d time.Duration) *slowConn { return &slowConn{delay: d} }

func (c *slowConn) Read(b []byte) (int, error) { return 0, net.ErrClosed }

func (c *slowConn) Write(b []byte) (int, error) {
	time.Sleep(c.delay)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(b)
}

func (c *slowConn) Close() error { return nil }

// stream returns everything written so far, as the far end would see it.
func (c *slowConn) stream() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.buf.Bytes()
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// Test_udpTunConn_concurrentWriteTo checks that endpoints sharing one reverse
// tunnel stream cannot interleave inside a datagram frame.
//
// Each writer targets a distinct address and sends a payload of its own id
// byte, so a frame assembled from the wrong segments is detected both as a
// payload mismatch and as a misattributed address. This is the seam behind
// gost#911: concurrent UDP endpoints over one RUDP reverse tunnel produced
// corrupted datagrams, and torn frames left half a header in the stream, which
// the far end read as "unexpected EOF" and answered by tearing down and
// rebinding the whole tunnel every second.
func Test_udpTunConn_concurrentWriteTo(t *testing.T) {
	const writers = 4
	const datagramsPerWriter = 25
	const payloadLen = 1200

	conn := newSlowConn(50 * time.Microsecond)
	pc := UDPTunClientPacketConn(conn)

	addrs := make([]string, writers)
	for i := range addrs {
		addrs[i] = fmt.Sprintf("127.0.0.1:%d", 10001+i)
	}

	payloadFor := func(id byte) []byte {
		b := make([]byte, payloadLen)
		for i := range b {
			b[i] = id
		}
		return b
	}

	var wg sync.WaitGroup
	for w := 1; w <= writers; w++ {
		wg.Add(1)
		go func(id byte) {
			defer wg.Done()
			taddr := mustUDPAddr(t, addrs[int(id)-1])
			for range datagramsPerWriter {
				if _, err := pc.WriteTo(payloadFor(id), taddr); err != nil {
					t.Errorf("writer %d WriteTo: %v", id, err)
					return
				}
			}
		}(byte(w))
	}
	wg.Wait()

	// Parse the raw stream the way the far end does, one frame at a time. A
	// torn frame shows up here as an unparseable header or a payload that does
	// not match the address it was framed with.
	stream := bytes.NewReader(conn.stream())
	seen := make(map[string]int, writers)
	total := writers * datagramsPerWriter
	for i := range total {
		socksAddr := gosocks5.Addr{}
		dgram := gosocks5.UDPDatagram{
			Header: &gosocks5.UDPHeader{Addr: &socksAddr},
		}
		if _, err := dgram.ReadFrom(stream); err != nil {
			t.Fatalf("frame %d of %d: stream corrupted by concurrent writers: %v",
				i, total, err)
		}
		id, ok := payloadID(dgram.Data)
		if !ok {
			t.Fatalf("frame %d of %d: payload is not a single-writer payload "+
				"(%d bytes), corrupted by concurrent writers", i, total, len(dgram.Data))
		}
		got := socksAddr.String()
		if got != addrs[id-1] {
			t.Fatalf("frame %d of %d: payload from writer %d framed with address %s, want %s "+
				"— frames interleaved", i, total, id, got, addrs[id-1])
		}
		seen[got]++
	}

	for _, a := range addrs {
		if seen[a] != datagramsPerWriter {
			t.Errorf("addr %s: got %d frames, want %d", a, seen[a], datagramsPerWriter)
		}
	}
}

// payloadID recovers the writer id from a payload built by payloadFor.
func payloadID(b []byte) (byte, bool) {
	if len(b) == 0 {
		return 0, false
	}
	id := b[0]
	for _, c := range b {
		if c != id {
			return 0, false
		}
	}
	return id, true
}

func mustUDPAddr(t *testing.T, s string) net.Addr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		t.Fatalf("resolve %s: %v", s, err)
	}
	return a
}

func Test_udpTunConn_ipRoundTrip(t *testing.T) {
	pc1 := newPipeConn()
	server := UDPTunServerConn(pc1)

	ipAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53}
	_, err := server.WriteTo([]byte("hello"), ipAddr)
	if err != nil {
		t.Fatal(err)
	}

	pc2 := newPipeConn()
	pc2.Write(pc1.buf)

	_, addr, err := UDPTunServerConn(pc2).ReadFrom(make([]byte, 1500))
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := addr.(*net.UDPAddr); !ok {
		t.Fatalf("expected *net.UDPAddr, got %T: %s", addr, addr)
	}
}
