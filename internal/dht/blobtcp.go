// blobtcp.go — the TCP blob channel (v0.19.9): bulk release-archive
// transfer where the KERNEL paces the sender instead of our rate limiter
// guessing. The UDP blob.get stays for small/fragmented paths and as the
// fallback; TCP exists for the case that motivated it — moving 13 MB
// between fleet boxes at LAN speed without a datagram ceiling, a
// 265-request swarm, or a per-source rate bucket to tune.
//
// SECURITY MODEL (deliberately minimal, reasoned in full):
//
//   - TOKEN: every connection must present a write token minted over the
//     UDP DHT (a completed round trip from the true source). That ties
//     bulk pulls to protocol membership — drive-by scanners and
//     impersonators get nothing — and, because obtaining a token
//     requires receiving a response, preserves the anti-DDoS property
//     the whole design rests on.
//   - NO TLS: the bytes are verified against the ORIGIN manifest's
//     per-chunk SHA-256; injected content fails its hash. A MITM can
//     only cause denial (it could also stop the transfer), exactly as
//     with the UDP path. TLS would add certificate machinery for zero
//     integrity gain, and the token already handles authorization.
//   - RESOURCE BOUNDS: per-IP and global connection caps, handshake and
//     transfer deadlines, and a per-connection byte-rate pace — a
//     datacenter peer must not be able to drain a home seeder's uplink
//     at line rate. TCP's flow control makes the RECEIVER pace, so the
//     pace here is only an abuse ceiling, not a congestion mechanism.
//
// FRAMING (fixed-size, little-endian; a bulk channel, not a consensus
// protocol — no wire.Message, no signatures on every 60 KB):
//
//	request : token[32] id[32] offset u64 length u64          ( 80 B)
//	response: status u8 total u64                             (9 B)
//	          then min(length, total-offset) data bytes when status == 0
//
// statuses: 0 ok, 1 bad request, 2 invalid token, 3 blob not cached.
package dht

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Blob TCP defaults. Deliberately conservative: these are abuse ceilings,
// not performance targets (the receiver's requests bound the useful work).
const (
	blobTCPHandshakeTimeout = 10 * time.Second
	blobTCPConnDeadline     = 10 * time.Minute
	blobTCPMaxConnsGlobal   = 8
	blobTCPMaxConnsPerIP    = 2
	blobTCPBytesPerSec      = 32 << 20 // 32 MiB/s per connection ceiling
)

const (
	blobTCPStatusOK       = 0
	blobTCPStatusBadReq   = 1
	blobTCPStatusBadToken = 2
	blobTCPStatusAbsent   = 3
)

type blobTCPRequest struct {
	token  []byte
	id     []byte
	offset uint64
	length uint64
}

// StartBlobTCP starts the TCP blob listener on addr (typically the DHT
// port, TCP). Serving requires a BlobCache (NodeConfig.BlobCache) — with
// none configured this is a no-op. The listener stops with ctx or Close.
func (n *Node) StartBlobTCP(ctx context.Context, addr string) error {
	if n.blobCache == nil {
		return errors.New("dht: blob TCP serving needs BlobCache")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	n.blobTCPMu.Lock()
	n.blobTCPLn = ln
	n.blobTCPMu.Unlock()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go n.blobTCPAcceptLoop(ctx, ln)
	return nil
}

// BlobTCPAddr returns the listener's bound address ("" before Start).
func (n *Node) BlobTCPAddr() string {
	n.blobTCPMu.Lock()
	defer n.blobTCPMu.Unlock()
	if n.blobTCPLn == nil {
		return ""
	}
	return n.blobTCPLn.Addr().String()
}

func (n *Node) blobTCPAcceptLoop(ctx context.Context, ln net.Listener) {
	var (
		mu      sync.Mutex
		global  int
		perIP   = map[string]int{}
		release func(ip string)
	)
	release = func(ip string) {
		mu.Lock()
		defer mu.Unlock()
		global--
		perIP[ip]--
		if perIP[ip] <= 0 {
			delete(perIP, ip)
		}
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed (ctx) or fatal accept error
		}
		ip := ""
		if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			ip = string(normIP(ta.IP))
		}
		mu.Lock()
		over := global >= blobTCPMaxConnsGlobal || perIP[ip] >= blobTCPMaxConnsPerIP
		if !over {
			global++
			perIP[ip]++
		}
		mu.Unlock()
		if over {
			_ = conn.Close() // abuse ceiling: drop, don't queue
			continue
		}
		go func(c net.Conn) {
			defer release(ip)
			n.handleBlobTCPConn(c)
		}(conn)
	}
}

func (n *Node) handleBlobTCPConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(blobTCPConnDeadline))
	_ = c.SetReadDeadline(time.Now().Add(blobTCPHandshakeTimeout))
	req, err := readBlobTCPRequest(c)
	if err != nil {
		_, _ = c.Write([]byte{blobTCPStatusBadReq, 0, 0, 0, 0, 0, 0, 0, 0})
		return
	}
	ip := net.IPv4zero
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		ip = ta.IP
	}
	if !n.tokens.Verify(normIP(ip), req.token, 1) {
		_, _ = c.Write([]byte{blobTCPStatusBadToken, 0, 0, 0, 0, 0, 0, 0, 0})
		return
	}
	f, size, err := n.blobCache.Open(req.id)
	if err != nil {
		_, _ = c.Write([]byte{blobTCPStatusAbsent, 0, 0, 0, 0, 0, 0, 0, 0})
		return
	}
	defer f.Close()
	if req.offset >= uint64(size) {
		_, _ = c.Write([]byte{blobTCPStatusBadReq, 0, 0, 0, 0, 0, 0, 0, 0})
		return
	}
	length := req.length
	if r := uint64(size) - req.offset; length == 0 || length > r {
		length = r // length 0 = "everything from offset"
	}
	hdr := make([]byte, 9)
	hdr[0] = blobTCPStatusOK
	binary.LittleEndian.PutUint64(hdr[1:], uint64(size))
	if _, err := c.Write(hdr); err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	// Per-connection byte pace: an abuse ceiling, not congestion control
	// (the receiver's flow control is the real pacing).
	pacer := newBytePacer(blobTCPBytesPerSec)
	buf := make([]byte, 64*1024)
	remain := int64(length)
	off := int64(req.offset)
	for remain > 0 {
		want := int64(len(buf))
		if remain < want {
			want = remain
		}
		nr, rerr := f.ReadAt(buf[:want], off)
		if nr > 0 {
			pacer.wait(nr)
			if _, werr := c.Write(buf[:nr]); werr != nil {
				return
			}
			off += int64(nr)
			remain -= int64(nr)
		}
		if rerr != nil {
			return
		}
	}
}

func readBlobTCPRequest(r io.Reader) (*blobTCPRequest, error) {
	buf := make([]byte, 32+32+8+8)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return &blobTCPRequest{
		token:  append([]byte(nil), buf[:32]...),
		id:     append([]byte(nil), buf[32:64]...),
		offset: binary.LittleEndian.Uint64(buf[64:]),
		length: binary.LittleEndian.Uint64(buf[72:]),
	}, nil
}

// bytePacer throttles a stream to bytesPerSec with coarse sleeps (64 KiB
// granularity): enough to bound abuse, cheap enough to stay out of the
// fast path's way.
type bytePacer struct {
	bytesPerSec int64
	start       time.Time
	sent        int64
}

func newBytePacer(bytesPerSec int64) *bytePacer {
	return &bytePacer{bytesPerSec: bytesPerSec, start: time.Now()}
}

func (p *bytePacer) wait(n int) {
	if p.bytesPerSec <= 0 {
		return
	}
	p.sent += int64(n)
	expected := time.Duration(float64(p.sent) / float64(p.bytesPerSec) * float64(time.Second))
	if behind := expected - time.Since(p.start); behind > 0 {
		time.Sleep(behind)
	}
}

// BlobTCPGet streams [offset, offset+length) of the cached blob id from
// peer, returning a reader over exactly that many bytes (length 0 = the
// rest of the blob) and the blob's total size. The caller MUST verify the
// streamed bytes against the origin manifest (and must have obtained the
// token via the UDP DHT — see BlobSession.RefreshToken). The connection
// is closed when the reader is closed.
func (n *Node) BlobTCPGet(ctx context.Context, peer Peer, token, id []byte, offset, length uint64) (io.ReadCloser, int64, error) {
	if len(token) != 32 || len(id) != 32 {
		return nil, 0, errors.New("dht: blob TCP request needs a 32-byte token and 32-byte id")
	}
	host, _, err := net.SplitHostPort(peer.Addr)
	if err != nil {
		return nil, 0, err
	}
	// The TCP channel shares the DHT's port number.
	addr := net.JoinHostPort(host, strconv.Itoa(portOf(peer.Addr)))
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, 0, err
	}
	req := make([]byte, 0, 80)
	req = append(req, token...)
	req = append(req, id...)
	var num [8]byte
	binary.LittleEndian.PutUint64(num[:], offset)
	req = append(req, num[:]...)
	binary.LittleEndian.PutUint64(num[:], length)
	req = append(req, num[:]...)
	_ = conn.SetDeadline(time.Now().Add(blobTCPHandshakeTimeout))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, 0, err
	}
	hdr := make([]byte, 9)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		conn.Close()
		return nil, 0, err
	}
	switch hdr[0] {
	case blobTCPStatusOK:
	case blobTCPStatusBadToken:
		conn.Close()
		return nil, 0, ErrBlobTCPBadToken
	case blobTCPStatusAbsent:
		conn.Close()
		return nil, 0, ErrBlobAbsent
	default:
		conn.Close()
		return nil, 0, errors.New("dht: blob TCP bad request")
	}
	total := int64(binary.LittleEndian.Uint64(hdr[1:]))
	want := length
	if want == 0 || int64(want) > total-int64(offset) {
		want = uint64(total - int64(offset))
	}
	_ = conn.SetDeadline(time.Time{})
	return &blobTCPReader{conn: conn, remain: int64(want)}, total, nil
}

// ErrBlobTCPBadToken is BlobTCPGet's token refusal (refresh the token and
// retry once, like the UDP path's 302 handling).
var ErrBlobTCPBadToken = errors.New("dht: blob TCP token refused")

type blobTCPReader struct {
	conn   net.Conn
	remain int64
}

func (r *blobTCPReader) Read(p []byte) (int, error) {
	if r.remain <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remain {
		p = p[:r.remain]
	}
	nr, err := r.conn.Read(p)
	r.remain -= int64(nr)
	if nr > 0 && err == io.EOF && r.remain > 0 {
		err = io.ErrUnexpectedEOF
	}
	return nr, err
}

func (r *blobTCPReader) Close() error { return r.conn.Close() }
