// server.go — the freens community TURN relay (RFC 8656 subset; see the
// package comment for scope, auth, and the permission model).
package turn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/camalolo/freens/internal/crypto"
)

// ServerConfig configures a TURN server. Zero values select the defaults
// noted per field.
type ServerConfig struct {
	// ListenAddr is the UDP bind address, e.g. "0.0.0.0:3478".
	ListenAddr string
	// MaxAllocsPerIP caps concurrent allocations per client source IP
	// (default 8) — the primary abuse gate (see package comment).
	MaxAllocsPerIP int
	// DefaultLifetime is granted when an Allocate carries no LIFETIME or
	// asks for 0 (default 600s, RFC 8656's recommendation). Allocations
	// die at expiry unless Refreshed.
	DefaultLifetime time.Duration
	// MaxLifetime caps a requested lifetime (default 3600s).
	MaxLifetime time.Duration
	// MaxPermissions caps permissions per allocation (default 64).
	MaxPermissions int
	// Log (nil ⇒ slog.Default()).
	Log interface {
		Info(msg string, args ...any)
		Warn(msg string, args ...any)
		Debug(msg string, args ...any)
	}
}

// The Log field is typed as the minimal interface the server uses so the
// package does not force a slog import on embedders that only need defaults.
// (cmd/freens passes *slog.Logger, which satisfies it structurally.)

const (
	defaultMaxAllocsPerIP = 8
	defaultLifetime       = 600 * time.Second
	defaultMaxLifetime    = 3600 * time.Second
	defaultMaxPermissions = 64
	authFailWindow        = time.Minute
	authFailBudget        = 10 // failed Allocate auths per IP per window
	maxRelayedReadBuf     = 2048
)

// allocation is one client's relay state: the relayed socket (its local
// address is what the client advertises), the permission list, and the
// expiry that Refresh extends.
type allocation struct {
	client  *net.UDPAddr // the 5-tuple's source (allocations are keyed by it)
	relay   *net.UDPConn // the relayed socket; peers' traffic flows through it
	relayed *net.UDPAddr
	mu      sync.Mutex
	perms   map[string]*net.UDPAddr // peer addr string → addr
	expires time.Time
}

// hasPerm reports whether peer is permitted. Caller holds a.mu or accepts a
// racy read over the map (map reads are lock-safe in Go for our usage, but
// we lock anyway to pair with writers).
func (a *allocation) hasPerm(peer *net.UDPAddr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.perms[peer.String()]
	return ok
}

// Server is one TURN relay. All public methods are safe for concurrent use.
type Server struct {
	cfg  ServerConfig
	conn *net.UDPConn
	log  interface {
		Info(msg string, args ...any)
		Warn(msg string, args ...any)
		Debug(msg string, args ...any)
	}

	mu      sync.Mutex
	allocs  map[string]*allocation // client addr string → allocation
	perIP   map[string]int
	fails   map[string]int // failed Allocate auths per IP (fixed window)
	window  time.Time      // start of the current fail window
	closed  atomic.Bool
	wg      sync.WaitGroup
	addrErr atomic.Value // set once by Close; Addr() reports it
}

// ListenTURN binds the TURN socket and starts the serve loop.
func ListenTURN(cfg ServerConfig) (*Server, error) {
	if cfg.MaxAllocsPerIP <= 0 {
		cfg.MaxAllocsPerIP = defaultMaxAllocsPerIP
	}
	if cfg.DefaultLifetime <= 0 {
		cfg.DefaultLifetime = defaultLifetime
	}
	if cfg.MaxLifetime <= 0 {
		cfg.MaxLifetime = defaultMaxLifetime
	}
	if cfg.MaxPermissions <= 0 {
		cfg.MaxPermissions = defaultMaxPermissions
	}
	log := cfg.Log
	if log == nil {
		log = nopLog{}
	}
	addr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("turn: resolve %q: %w", cfg.ListenAddr, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("turn: listen %q: %w", cfg.ListenAddr, err)
	}
	s := &Server{
		cfg:    cfg,
		conn:   conn,
		log:    log,
		allocs: make(map[string]*allocation),
		perIP:  make(map[string]int),
		fails:  make(map[string]int),
		window: time.Now(),
	}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

// Addr returns the concrete bound address (useful with ":0").
func (s *Server) Addr() (*net.UDPAddr, error) {
	if s.closed.Load() {
		if e, ok := s.addrErr.Load().(error); ok && e != nil {
			return nil, e
		}
		return nil, errors.New("turn: server closed")
	}
	return net.ResolveUDPAddr("udp", s.conn.LocalAddr().String())
}

// Allocations returns the number of live allocations (metrics/tests).
func (s *Server) Allocations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.allocs)
}

// Close stops the serve loop, tears down every allocation (closing its
// relayed socket, which ends its relay loop), and waits for all goroutines.
// Idempotent.
func (s *Server) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	s.addrErr.Store(errors.New("turn: server closed"))
	err := s.conn.Close() // unblocks serve
	s.mu.Lock()
	for _, a := range s.allocs {
		a.relay.Close() // ends each relayLoop
	}
	s.allocs = make(map[string]*allocation)
	s.perIP = make(map[string]int)
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

type nopLog struct{}

func (nopLog) Info(string, ...any)  {}
func (nopLog) Warn(string, ...any)  {}
func (nopLog) Debug(string, ...any) {}

// serve is the main read loop: STUN Binding requests get a Binding success
// (the socket doubles as a -stun server); TURN requests are authenticated
// and dispatched; Send indications are relayed; everything else is dropped.
func (s *Server) serve() {
	defer s.wg.Done()
	buf := make([]byte, maxRelayedReadBuf+headerLen)
	for {
		n, raddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed (Close) or fatal
		}
		if raddr == nil {
			continue
		}
		m, perr := parseMessage(buf[:n])
		if perr != nil {
			continue // malformed datagram: drop (never panic)
		}
		switch {
		case m.method == methodBinding && m.class == classRequest:
			s.replyBinding(m, raddr)
		case m.method == methodAllocate && m.class == classRequest:
			s.handleAllocate(m, raddr)
		case m.method == methodRefresh && m.class == classRequest:
			s.handleRefresh(m, raddr)
		case m.method == methodCreatePermission && m.class == classRequest:
			s.handleCreatePermission(m, raddr)
		case m.method == methodSend && m.class == classIndication:
			s.handleSend(m, raddr)
		default:
			// Unknown method/class (incl. error responses aimed at
			// nobody): drop.
		}
	}
}

// replyBinding answers a plain STUN Binding request with XOR-MAPPED-ADDRESS
// — the standard TURN-server behavior that lets -turn double as -stun.
func (s *Server) replyBinding(m *message, raddr *net.UDPAddr) {
	resp := newMessage(methodBinding, classSuccess)
	resp.txid = m.txid
	if v, err := xorAddr(raddr, m.txid); err == nil {
		resp.add(attrXORMappedAddress, v)
	}
	if b, err := resp.encode(); err == nil {
		_, _ = s.conn.WriteToUDP(b, raddr)
	}
}

// errorResp replies with an ERROR-CODE response echoing the request's txid.
func (s *Server) errorResp(m *message, raddr *net.UDPAddr, code int, reason string) {
	resp := newMessage(m.method, classError)
	resp.txid = m.txid
	resp.add(attrErrorCode, encodeErrorCode(code, reason))
	if b, err := resp.encode(); err == nil {
		_, _ = s.conn.WriteToUDP(b, raddr)
	}
}

// failLimited applies the per-IP failed-auth budget: beyond authFailBudget
// failures in the current window the source is silently dropped (no
// response — answering abuse amplifies it).
func (s *Server) failLimited(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.window) > authFailWindow {
		s.window, s.fails = time.Now(), make(map[string]int)
	}
	s.fails[ip]++
	return s.fails[ip] > authFailBudget
}

func (s *Server) clearFails(ip string) {
	s.mu.Lock()
	delete(s.fails, ip)
	s.mu.Unlock()
}

// handleAllocate authenticates, enforces caps, and grants a relayed socket.
// An existing allocation for the same 5-tuple is REPLACED (idempotent for
// client retries after a lost response; RFC 8656 would 437 here — our
// client's Dial retries make replace the friendlier choice).
func (s *Server) handleAllocate(m *message, raddr *net.UDPAddr) {
	ip := raddr.IP.String()
	if !verifyAuth(m, crypto.Verify) {
		if !s.failLimited(ip) {
			s.errorResp(m, raddr, 401, "unauthenticated")
		}
		return
	}
	s.clearFails(ip)

	lt := s.grantLifetime(m.lifetime())

	// The relayed socket must carry a CONCRETE, dialable IP (it becomes
	// the client's advertised §6.2 address). A wildcard bind would
	// surface as 0.0.0.0/[::] — useless. Prefer the main socket's own
	// local IP when concrete; otherwise derive the source IP this server
	// would use toward THIS client (the connected-socket routing trick:
	// no packet is sent), so dual-homed servers relay on the right face.
	relayIP := s.relayIP(raddr)
	relayed, err := net.ListenUDP("udp", &net.UDPAddr{IP: relayIP, Port: 0})
	if err != nil {
		s.errorResp(m, raddr, 508, "no relay port")
		return
	}
	relayedAddr, err := net.ResolveUDPAddr("udp", relayed.LocalAddr().String())
	if err != nil {
		_ = relayed.Close()
		s.errorResp(m, raddr, 508, "bad relay port")
		return
	}
	a := &allocation{
		client:  raddr,
		relay:   relayed,
		relayed: relayedAddr,
		perms:   make(map[string]*net.UDPAddr),
		expires: time.Now().Add(lt),
	}

	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		_ = relayed.Close()
		return
	}
	if s.perIP[ip] >= s.cfg.MaxAllocsPerIP {
		s.mu.Unlock()
		_ = relayed.Close()
		s.errorResp(m, raddr, 438, "allocation capacity exhausted")
		s.log.Warn("turn: allocate rejected — per-IP cap", "ip", ip, "cap", s.cfg.MaxAllocsPerIP)
		return
	}
	if old, ok := s.allocs[raddr.String()]; ok { // replace (see doc comment)
		delete(s.allocs, raddr.String())
		s.perIP[ip]--
		_ = old.relay.Close()
	}
	s.allocs[raddr.String()] = a
	s.perIP[ip]++
	s.mu.Unlock()

	// Expire unless Refreshed; the timer re-checks under the alloc lock so
	// a Refresh that just extended wins the race.
	time.AfterFunc(lt, func() { s.expire(raddr.String(), a) })
	s.wg.Add(1)
	go s.relayLoop(a)

	resp := newMessage(methodAllocate, classSuccess)
	resp.txid = m.txid
	if v, err := xorAddr(relayedAddr, m.txid); err == nil {
		resp.add(attrXORRelayedAddress, v)
	}
	resp.add(attrLifetime, be32(uint32(lt/time.Second)))
	if b, err := resp.encode(); err == nil {
		_, _ = s.conn.WriteToUDP(b, raddr)
	}
	s.log.Info("turn: allocation granted", "client", raddr.String(), "relayed", relayedAddr.String(), "lifetime", lt)
}

// relayIP picks the local IP for a relayed socket serving client raddr: the
// main socket's own local IP when it is concrete (a non-wildcard ListenAddr
// like "192.0.2.7:3478" or "[2001:db8::7]:3478"), else the source IP the OS
// would route toward raddr (a connected throwaway UDP socket reveals it
// without sending — same address family as the client), nil when even that
// fails (the bind degrades to wildcard — logged by the caller's allocation
// of a useless address, never a crash).
func (s *Server) relayIP(raddr *net.UDPAddr) net.IP {
	if la, err := net.ResolveUDPAddr("udp", s.conn.LocalAddr().String()); err == nil && la.IP != nil && !la.IP.IsUnspecified() {
		return la.IP
	}
	fam := "udp4"
	if raddr.IP.To4() == nil {
		fam = "udp6" // IPv6 clients relay on a v6 face; a v4-mapped face
		// would hand out a v4 address the v6 peer cannot dial.
	}
	c, err := net.DialUDP(fam, nil, raddr)
	if err != nil {
		return nil
	}
	defer c.Close()
	if la, err := net.ResolveUDPAddr("udp", c.LocalAddr().String()); err == nil && la.IP != nil && !la.IP.IsUnspecified() {
		return la.IP
	}
	return nil
}

// grantLifetime clamps a requested LIFETIME seconds value.
func (s *Server) grantLifetime(requested uint32) time.Duration {
	if requested == 0 {
		return s.cfg.DefaultLifetime
	}
	lt := time.Duration(requested) * time.Second
	if lt > s.cfg.MaxLifetime {
		lt = s.cfg.MaxLifetime
	}
	if lt < time.Second {
		lt = time.Second
	}
	return lt
}

// expire removes the allocation if its lifetime has actually elapsed.
func (s *Server) expire(key string, a *allocation) {
	s.mu.Lock()
	cur, ok := s.allocs[key]
	if !ok || cur != a {
		s.mu.Unlock()
		return
	}
	a.mu.Lock()
	if time.Now().Before(a.expires) {
		a.mu.Unlock()
		s.mu.Unlock()
		return // refreshed in the meantime
	}
	delete(s.allocs, key)
	ip := a.client.IP.String()
	if s.perIP[ip] > 0 {
		s.perIP[ip]--
	}
	a.mu.Unlock()
	_ = a.relay.Close()
	s.mu.Unlock()
	s.log.Info("turn: allocation expired", "client", a.client.String())
}

// handleRefresh extends (Lifetime>0) or releases (Lifetime=0) the caller's
// allocation.
func (s *Server) handleRefresh(m *message, raddr *net.UDPAddr) {
	if !verifyAuth(m, crypto.Verify) {
		if !s.failLimited(raddr.IP.String()) {
			s.errorResp(m, raddr, 401, "unauthenticated")
		}
		return
	}
	s.mu.Lock()
	a, ok := s.allocs[raddr.String()]
	s.mu.Unlock()
	if !ok {
		s.errorResp(m, raddr, 437, "no allocation")
		return
	}
	req := m.lifetime()
	if req == 0 { // explicit deallocate
		s.mu.Lock()
		delete(s.allocs, raddr.String())
		if s.perIP[raddr.IP.String()] > 0 {
			s.perIP[raddr.IP.String()]--
		}
		s.mu.Unlock()
		_ = a.relay.Close()
		resp := newMessage(methodRefresh, classSuccess)
		resp.txid = m.txid
		resp.add(attrLifetime, be32(0))
		if b, err := resp.encode(); err == nil {
			_, _ = s.conn.WriteToUDP(b, raddr)
		}
		s.log.Info("turn: allocation released", "client", raddr.String())
		return
	}
	lt := s.grantLifetime(req)
	a.mu.Lock()
	a.expires = time.Now().Add(lt)
	a.mu.Unlock()
	time.AfterFunc(lt, func() { s.expire(raddr.String(), a) })
	resp := newMessage(methodRefresh, classSuccess)
	resp.txid = m.txid
	resp.add(attrLifetime, be32(uint32(lt/time.Second)))
	if b, err := resp.encode(); err == nil {
		_, _ = s.conn.WriteToUDP(b, raddr)
	}
}

// handleCreatePermission adds XOR-PEER-ADDRESS entries to the caller's
// allocation (full IP:port — see package comment).
func (s *Server) handleCreatePermission(m *message, raddr *net.UDPAddr) {
	if !verifyAuth(m, crypto.Verify) {
		if !s.failLimited(raddr.IP.String()) {
			s.errorResp(m, raddr, 401, "unauthenticated")
		}
		return
	}
	s.mu.Lock()
	a, ok := s.allocs[raddr.String()]
	s.mu.Unlock()
	if !ok {
		s.errorResp(m, raddr, 437, "no allocation")
		return
	}
	a.mu.Lock()
	for _, raw := range m.all(attrXORPeerAddress) {
		peer, err := decodeXORAddr(raw, m.txid)
		if err != nil {
			continue
		}
		if len(a.perms) >= s.cfg.MaxPermissions {
			a.mu.Unlock()
			s.errorResp(m, raddr, 508, "permission table full")
			return
		}
		a.perms[peer.String()] = peer
	}
	a.mu.Unlock()
	resp := newMessage(methodCreatePermission, classSuccess)
	resp.txid = m.txid
	if b, err := resp.encode(); err == nil {
		_, _ = s.conn.WriteToUDP(b, raddr)
	}
}

// handleSend relays a Send indication's DATA to its XOR-PEER-ADDRESS from
// the allocation's relayed socket (so the peer sees the relayed address as
// the source). Unpermitted peers are dropped.
func (s *Server) handleSend(m *message, raddr *net.UDPAddr) {
	s.mu.Lock()
	a, ok := s.allocs[raddr.String()]
	s.mu.Unlock()
	if !ok {
		return
	}
	rawPeer := m.get(attrXORPeerAddress)
	data := m.get(attrData)
	if rawPeer == nil || data == nil {
		return
	}
	peer, err := decodeXORAddr(rawPeer, m.txid)
	if err != nil {
		return
	}
	if !a.hasPerm(peer) {
		s.log.Debug("turn: send to unpermitted peer dropped", "peer", peer.String())
		return
	}
	_, _ = a.relay.WriteToUDP(data, peer)
}

// relayLoop reads the relayed socket: datagrams from PERMITTED peers are
// wrapped as Data indications to the client; anything else is dropped (TURN
// anti-spam, see package comment). Exits when the socket closes.
func (s *Server) relayLoop(a *allocation) {
	defer s.wg.Done()
	buf := make([]byte, maxRelayedReadBuf+headerLen)
	for {
		n, peer, err := a.relay.ReadFromUDP(buf)
		if err != nil {
			return // closed (expiry/release/Close)
		}
		if peer == nil || !a.hasPerm(peer) {
			continue
		}
		m := newMessage(methodData, classIndication)
		if v, err := xorAddr(peer, m.txid); err == nil {
			m.add(attrXORPeerAddress, v)
		}
		m.add(attrData, buf[:n])
		if b, err := m.encode(); err == nil {
			_, _ = s.conn.WriteToUDP(b, a.client)
		}
	}
}

// be32 is a big-endian uint32 helper.
func be32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}
