// client.go — the freens TURN client: one allocation on a relay server,
// exposed as a near-net.PacketConn whose ReadFrom/WriteTo transparently
// carry Data/Send indications (see the package comment for the model).
package turn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/camalolo/freens/internal/crypto"
)

const (
	dialTimeout        = 3 * time.Second // one Allocate round trip
	dialAttempts       = 2
	permWait           = time.Second // CreatePermission response wait
	refreshFailMax     = 3           // consecutive refresh failures ⇒ dead conn
	dataChBuffer       = 64
	clientReadBuf      = 2048
	defaultReqLifetime = 600 // seconds, matches the server default
)

// Client dials one allocation. Server ("host:port") and NodeKey are
// REQUIRED; Log is optional (nil ⇒ silent — the dht layer passes its own
// logger, standalone users usually want quiet).
type Client struct {
	Server  string
	NodeKey *crypto.Keypair
	Log     interface {
		Info(msg string, args ...any)
		Warn(msg string, args ...any)
		Debug(msg string, args ...any)
	}
}

// Conn is an established allocation. ReadFrom returns payloads from
// permitted peers; WriteTo tunnels to peers (creating permissions lazily).
// Close releases the allocation. Safe for concurrent use.
type Conn struct {
	server  string
	nodeKey *crypto.Keypair
	conn    *net.UDPConn // the control socket (connected to the server)
	relayed *net.UDPAddr
	lt      time.Duration
	log     interface {
		Info(msg string, args ...any)
		Warn(msg string, args ...any)
		Debug(msg string, args ...any)
	}

	mu       sync.Mutex
	perms    map[string]bool
	pending  map[string]chan *pendingResult // txid hex → waiter
	dl       time.Time                      // ReadFrom deadline
	deadErr  error
	closeOne sync.Once
	doneOnce sync.Once
	done     chan struct{}

	dataCh chan dataMsg
	fails  atomic.Int32 // consecutive refresh failures

	wg sync.WaitGroup
}

// pendingResult carries one request/response correlation result.
type pendingResult struct {
	msg *message
	err error
}

// dataMsg is one inbound payload with its peer.
type dataMsg struct {
	peer    *net.UDPAddr
	payload []byte
}

// Dial performs the signed Allocate (retried once on timeout) and starts
// the Conn's internal reader + refresh loop. The returned Conn's RelayedAddr
// is what the caller should advertise (§6.2).
func (c *Client) Dial(ctx context.Context) (*Conn, error) {
	if c.Server == "" || c.NodeKey == nil {
		return nil, errors.New("turn: Client requires Server and NodeKey")
	}
	raddr, err := net.ResolveUDPAddr("udp", c.Server)
	if err != nil {
		return nil, fmt.Errorf("turn: resolve relay %q: %w", c.Server, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("turn: dial relay %q: %w", c.Server, err)
	}
	log := c.Log
	if log == nil {
		log = nopLog{}
	}
	cc := &Conn{
		server:  c.Server,
		nodeKey: c.NodeKey,
		conn:    conn,
		lt:      defaultReqLifetime * time.Second,
		log:     log,
		perms:   make(map[string]bool),
		pending: make(map[string]chan *pendingResult),
		done:    make(chan struct{}),
		dataCh:  make(chan dataMsg, dataChBuffer),
	}

	cc.wg.Add(1)
	go cc.readLoop() // MUST run before the Allocate: it feeds roundTrip's waiters

	resp, err := cc.roundTrip(ctx, methodAllocate, defaultReqLifetime)
	if err != nil {
		_ = conn.Close() // unblocks readLoop; the allocation (if any) expires server-side
		cc.wg.Wait()
		return nil, fmt.Errorf("turn: allocate on %q: %w", c.Server, err)
	}
	raw := resp.get(attrXORRelayedAddress)
	if raw == nil {
		_ = conn.Close()
		return nil, fmt.Errorf("turn: allocate response carries no relayed address")
	}
	relayed, err := decodeXORAddr(raw, resp.txid)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("turn: bad relayed address: %w", err)
	}
	cc.relayed = relayed
	if lt := resp.lifetime(); lt > 0 {
		cc.lt = time.Duration(lt) * time.Second
	}

	cc.wg.Add(1)
	go cc.refreshLoop()
	return cc, nil
}

// RelayedAddr returns the allocation's relayed address (nil only in the
// brief window before Dial completes).
func (c *Conn) RelayedAddr() *net.UDPAddr { return c.relayed }

// LocalAddr returns the control socket's local address (the identity half
// of the 5-tuple; net.PacketConn compatibility).
func (c *Conn) LocalAddr() net.Addr {
	if c.conn == nil {
		return nil
	}
	return c.conn.LocalAddr()
}

// SetDeadline sets the ReadFrom deadline (net.PacketConn compatibility;
// write deadlines are not meaningful for fire-and-forget indications).
func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.dl = t
	c.mu.Unlock()
	return nil
}

// ReadFrom returns the next payload a permitted peer sent to the relayed
// address. Refresh responses are absorbed by the internal reader and never
// surface here. Honors SetDeadline; returns an error once closed.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		var timerC <-chan time.Time
		c.mu.Lock()
		dl := c.dl
		c.mu.Unlock()
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, errTimeout
			}
			timer := time.NewTimer(d)
			timerC = timer.C
			defer timer.Stop()
		}
		select {
		case dm := <-c.dataCh:
			n := copy(p, dm.payload)
			return n, dm.peer, nil
		case <-timerC:
			return 0, nil, errTimeout
		case <-c.done:
			c.mu.Lock()
			err := c.deadErr
			c.mu.Unlock()
			if err == nil {
				err = errClosed
			}
			return 0, nil, err
		}
	}
}

// WriteTo tunnels p to addr: lazily creates the permission (bounded wait),
// then sends a Send indication. Returns len(p) on fire (indications are
// unacknowledged per the RFC); a permission timeout still sends best-effort
// — the permission may land moments later.
func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		u, err := net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			return 0, fmt.Errorf("turn: bad peer address %v: %w", addr, err)
		}
		ua = u
	}
	c.mu.Lock()
	known := c.perms[ua.String()]
	c.mu.Unlock()
	if !known {
		c.createPermission(ua)
	}
	m := newMessage(methodSend, classIndication)
	v, err := xorAddr(ua, m.txid)
	if err != nil {
		return 0, err
	}
	m.add(attrXORPeerAddress, v)
	m.add(attrData, p)
	b, err := m.encode()
	if err != nil {
		return 0, err
	}
	if _, err := c.conn.Write(b); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close releases the allocation (best-effort Lifetime-0 Refresh), stops the
// loops, and closes the control socket. In-flight ReadFrom returns
// promptly. Idempotent.
func (c *Conn) Close() error {
	var err error
	c.closeOne.Do(func() {
		// Best-effort deallocate before the socket goes away.
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		_, _ = c.roundTrip(ctx, methodRefresh, 0)
		cancel()
		err = c.conn.Close()
		c.mu.Lock()
		if c.deadErr == nil {
			c.deadErr = errClosed
		}
		c.mu.Unlock()
		c.closeDone()
	})
	c.wg.Wait()
	return err
}

// closeDone signals termination exactly once (Close and the refresh loop's
// dead-marking can race; sync.Once guards the channel close).
func (c *Conn) closeDone() {
	c.doneOnce.Do(func() { close(c.done) })
}

// createPermission sends a signed CreatePermission for peer and waits (≤
// permWait) for its response. Errors are logged at Debug and swallowed:
// WriteTo proceeds best-effort (see its doc).
func (c *Conn) createPermission(peer *net.UDPAddr) {
	ctx, cancel := context.WithTimeout(context.Background(), permWait)
	defer cancel()
	if _, err := c.roundTrip(ctx, methodCreatePermission, 0, peer); err != nil {
		c.log.Debug("turn: createPermission", "peer", peer.String(), "err", err)
		return
	}
	c.mu.Lock()
	c.perms[peer.String()] = true
	c.mu.Unlock()
}

// roundTrip sends a signed request and awaits the matching-txid response.
// extra peers (CreatePermission) are appended as XOR-PEER-ADDRESS attrs.
// Two attempts are made for Allocate; other methods get one.
func (c *Conn) roundTrip(ctx context.Context, method uint16, lifetimeSec uint32, peers ...*net.UDPAddr) (*message, error) {
	attempts := 1
	if method == methodAllocate {
		attempts = dialAttempts
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m, err := newTxID(method, classRequest)
		if err != nil {
			return nil, err
		}
		if lifetimeSec > 0 || method == methodRefresh {
			m.add(attrLifetime, be32(lifetimeSec))
		}
		for _, p := range peers {
			if v, err := xorAddr(p, m.txid); err == nil {
				m.add(attrXORPeerAddress, v)
			}
		}
		sign(m, c.nodeKey.Public(), c.nodeKey.Sign)
		b, err := m.encode()
		if err != nil {
			return nil, err
		}
		ch := make(chan *pendingResult, 1)
		key := fmt.Sprintf("%x", m.txid)
		c.mu.Lock()
		if c.deadErr != nil {
			c.mu.Unlock()
			return nil, errClosed
		}
		c.pending[key] = ch
		c.mu.Unlock()
		if _, err := c.conn.Write(b); err != nil {
			c.mu.Lock()
			delete(c.pending, key)
			c.mu.Unlock()
			return nil, err
		}
		wait := dialTimeout
		if method != methodAllocate {
			wait = permWait
		}
		timer := time.NewTimer(wait)
		select {
		case r := <-ch:
			timer.Stop()
			if r.err != nil {
				return nil, r.err
			}
			if r.msg.class == classError {
				code, reason := decodeErrorCode(r.msg.get(attrErrorCode))
				return nil, fmt.Errorf("turn: server error %d (%s)", code, reason)
			}
			return r.msg, nil
		case <-timer.C:
			c.mu.Lock()
			delete(c.pending, key)
			c.mu.Unlock()
			if attempt+1 < attempts {
				continue
			}
			return nil, errTimeout
		case <-ctx.Done():
			timer.Stop()
			c.mu.Lock()
			delete(c.pending, key)
			c.mu.Unlock()
			return nil, ctx.Err()
		case <-c.done:
			timer.Stop()
			c.mu.Lock()
			delete(c.pending, key)
			c.mu.Unlock()
			return nil, errClosed
		}
	}
	return nil, errTimeout
}

// readLoop owns the control socket: success/error responses resolve their
// pending waiters; Data indications queue to dataCh (dropped-oldest on
// overflow — a slow consumer must not stall the reader); anything else is
// dropped.
func (c *Conn) readLoop() {
	defer c.wg.Done()
	buf := make([]byte, clientReadBuf+headerLen)
	for {
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			c.mu.Lock()
			if c.deadErr == nil {
				c.deadErr = errClosed
			}
			c.mu.Unlock()
			return
		}
		m, perr := parseMessage(buf[:n])
		if perr != nil {
			continue
		}
		switch m.class {
		case classSuccess, classError:
			key := fmt.Sprintf("%x", m.txid)
			c.mu.Lock()
			ch := c.pending[key]
			delete(c.pending, key)
			c.mu.Unlock()
			if ch != nil {
				ch <- &pendingResult{msg: m}
				continue
			}
			// Unsolicited response (a late retry echo): drop.
		case classIndication:
			if m.method != methodData {
				continue
			}
			rawPeer, data := m.get(attrXORPeerAddress), m.get(attrData)
			if rawPeer == nil || data == nil {
				continue
			}
			peer, err := decodeXORAddr(rawPeer, m.txid)
			if err != nil {
				continue
			}
			payload := make([]byte, len(data))
			copy(payload, data)
			select {
			case c.dataCh <- dataMsg{peer: peer, payload: payload}:
			default:
				// Backpressure: drop the OLDEST queued payload and retry —
				// fresher DHT traffic is more useful than stale.
				select {
				case <-c.dataCh:
				default:
				}
				select {
				case c.dataCh <- dataMsg{peer: peer, payload: payload}:
				default:
				}
				c.log.Warn("turn: data queue overflow; dropped a payload")
			}
		}
	}
}

// refreshLoop keeps the allocation alive: every lifetime/2 a signed
// Refresh. After refreshFailMax consecutive failures the conn is marked
// dead (ReadFrom errors, dht readLoop exits) — silently losing an
// allocation would leave a relayed node unreachable without notice.
func (c *Conn) refreshLoop() {
	defer c.wg.Done()
	for {
		iv := c.lt / 2
		if iv < 250*time.Millisecond {
			iv = 250 * time.Millisecond
		}
		select {
		case <-time.After(iv):
		case <-c.done:
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		resp, err := c.roundTrip(ctx, methodRefresh, defaultReqLifetime)
		cancel()
		if err != nil {
			f := c.fails.Add(1)
			if f >= refreshFailMax {
				c.log.Warn("turn: refresh failed repeatedly; marking allocation dead",
					"relay", c.server, "consecutive_failures", f)
				c.mu.Lock()
				if c.deadErr == nil {
					c.deadErr = fmt.Errorf("turn: allocation lost: %w", err)
				}
				c.mu.Unlock()
				_ = c.conn.Close()
				c.closeDone()
				return
			}
			continue
		}
		c.fails.Store(0)
		if lt := resp.lifetime(); lt > 0 {
			c.lt = time.Duration(lt) * time.Second
		}
	}
}

// Sentinel errors.
var (
	errClosed  = errors.New("turn: conn closed")
	errTimeout = errors.New("turn: i/o timeout")
)
