// Package dht — transport.go implements the §6.3 UDP Kademlia RPC transport:
// the signed CBOR message envelope on the wire (Appendix B.1), the ping /
// find_node / get / put methods, rotating write-token defense (§6.3), the
// 256-bucket routing table (§6.2), and the iterative Kademlia GET lookup
// (§6.4) that turns a set of independent envelope-store "islands" into a real
// multi-node network.
//
// Wire framing. Every UDP datagram is exactly one wire.Message (canonical CBOR).
// A message is verified on receipt: id == SHA-256(pk) AND sig verifies over
// [t, id, recipient_id, a] where recipient_id is THIS node's ID (transport
// context, §6.3 line 437). This makes address spoofing and Node-ID forgery
// detectable. Because recipient_id is inside the signed material, a node can
// only address a peer whose public key it already knows — so bootstrap peers
// are supplied as (addr, public_key) pairs (see cmd/freens -peers).
//
// Method payloads (the "a" map). Bstr-valued args (key, token, target) decode
// to []byte; the SignedEnvelope carried by get/put is transported as an opaque
// bstr whose content is the envelope's canonical CBOR (a "bstr .cbor
// SignedEnvelope" in CDDL); the node list returned by find_node / get-miss is a
// CBOR array of [ip, port, node_id, pk] arrays.
//
// Concurrency model. A single goroutine runs readLoop on the UDP socket. It
// (a) delivers responses (y="r"/"e") to the per-txid pending-response channel
// of the issuing sendQuery call, and (b) dispatches inbound queries (y="q") to
// the handlers, which answer from local state only (no nested network RPCs, so
// the loop never self-deadlocks). Client-side iterative lookups run on the
// caller's goroutine and block on sendQuery, which is fed by readLoop.
//
// This file is pure stdlib (net, crypto, sync) plus internal/{constants,crypto,
// naming,wire}; it does not import internal/resolver (the RecordLookup adapter
// DHTLookup satisfies that interface structurally).
package dht

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/wire"
)

// ErrTimeout is returned when an RPC receives no response within
// constants.RPCTimeoutSec.
var ErrTimeout = errors.New("dht: rpc timeout")

// maxLookupRounds bounds the iterative lookup's outer loop (a safety net; the
// loop terminates naturally once no un-queried shortlist contacts remain).
// 256 == ID bit-length, the theoretical Kademlia depth.
const maxLookupRounds = 256

// dhtLookupTimeout bounds the whole iterative GET a resolver lookup may spend,
// so a DNS query never hangs indefinitely on a slow/unreachable DHT.
const dhtLookupTimeout = 6 * time.Second

// Peer is a bootstrap peer: a UDP address plus the peer's 32-byte node public
// key (required because recipient_id is part of every message signature, so a
// node can only send a signed RPC to a peer whose key it knows).
type Peer struct {
	Addr      string // "ip:port"
	PublicKey []byte // 32-byte Ed25519 node public key
}

// NodeConfig configures a DHT transport Node.
type NodeConfig struct {
	// Keypair is this node's Ed25519 identity (Node ID = SHA-256(Public)).
	Keypair *crypto.Keypair
	// ListenAddr is the UDP address to bind, e.g. ":15353" (spec default port).
	ListenAddr string
	// Store is the shared envelope store; gets read from it and fetched
	// envelopes are cached into it. Must be non-nil.
	Store *EnvelopeStore
	// Logger receives diagnostic output; nil ⇒ slog.Default().
	Logger *slog.Logger
	// Now supplies the clock (unix seconds) for LastSeen/token epochs; nil ⇒
	// time.Now().Unix().
	Now func() int64
}

// Node is one freens DHT participant: a UDP socket, an identity, a routing
// table, a rotating write-token store, and a shared envelope store. It serves
// inbound RPCs and offers client-side Ping / IterativeGet / Publish.
//
// All public methods are safe for concurrent use.
type Node struct {
	kp         *crypto.Keypair
	id         []byte
	listenAddr string
	conn       *net.UDPConn
	closed     atomic.Bool

	store  *EnvelopeStore
	rt     *RoutingTable
	tokens *TokenStore
	log    *slog.Logger
	nowFn  func() int64

	mu      sync.Mutex
	pending map[string]chan *wire.Message
}

// NewNode validates cfg and constructs (but does not Start) a Node. The routing
// table (K entries/bucket) and token store (300s rotation) are created
// internally; the token root secret is derived deterministically from the node
// seed so a stable identity yields stable token epochs across restarts.
func NewNode(cfg NodeConfig) (*Node, error) {
	if cfg.Keypair == nil {
		return nil, errors.New("dht: NodeConfig.Keypair is required")
	}
	if cfg.ListenAddr == "" {
		return nil, errors.New("dht: NodeConfig.ListenAddr is required")
	}
	if cfg.Store == nil {
		return nil, errors.New("dht: NodeConfig.Store is required")
	}
	id, err := crypto.NodeID(cfg.Keypair.Public())
	if err != nil {
		return nil, err
	}
	rt, err := NewRoutingTable(id, constants.K)
	if err != nil {
		return nil, err
	}
	// Derive a per-node token root secret from the seed so token epochs are
	// stable for a stable identity. 32 bytes ≫ the 16-byte minimum.
	h := sha256.New()
	h.Write(cfg.Keypair.Seed())
	h.Write([]byte("freens-dht-tokens-v1"))
	rootSecret := h.Sum(nil)
	tokens, err := NewTokenStore(constants.TokenRotation, rootSecret, cfg.Now)
	if err != nil {
		return nil, err
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	now := cfg.Now
	if now == nil {
		now = func() int64 { return time.Now().Unix() }
	}
	return &Node{
		kp:         cfg.Keypair,
		id:         id,
		listenAddr: cfg.ListenAddr,
		store:      cfg.Store,
		rt:         rt,
		tokens:     tokens,
		log:        log,
		nowFn:      now,
		pending:    make(map[string]chan *wire.Message),
	}, nil
}

// ID returns this node's 32-byte Node ID (= SHA-256(Public)).
func (n *Node) ID() []byte { return append([]byte(nil), n.id...) }

// LocalAddr returns the bound UDP address (useful when ListenAddr was ":0" or
// ":port" and the concrete address is needed to configure peers).
func (n *Node) LocalAddr() (*net.UDPAddr, error) {
	if n.conn == nil {
		return nil, errors.New("dht: transport not started")
	}
	a, err := net.ResolveUDPAddr("udp", n.conn.LocalAddr().String())
	if err != nil {
		return nil, err
	}
	return a, nil
}

// PublicKey returns this node's 32-byte Ed25519 public key.
func (n *Node) PublicKey() []byte { return append([]byte(nil), n.kp.Public()...) }

// RoutingTable returns the node's routing table (for diagnostics/tests).
func (n *Node) RoutingTable() *RoutingTable { return n.rt }

// Start binds the UDP socket and launches the read loop. It returns once the
// socket is bound; the read loop runs until Close.
func (n *Node) Start() error {
	addr, err := net.ResolveUDPAddr("udp", n.listenAddr)
	if err != nil {
		return fmt.Errorf("dht: resolve %q: %w", n.listenAddr, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("dht: listen %q: %w", n.listenAddr, err)
	}
	n.conn = conn
	// Reasonable socket buffers for bursty small DHT datagrams.
	_ = conn.SetReadBuffer(1 << 20)
	_ = conn.SetWriteBuffer(1 << 20)
	go n.readLoop()
	return nil
}

// Close stops the read loop and closes the UDP socket. Pending sendQuery
// callers will time out normally.
func (n *Node) Close() error {
	n.closed.Store(true)
	if n.conn != nil {
		return n.conn.Close()
	}
	return nil
}

func (n *Node) now() int64 {
	if n.nowFn != nil {
		return n.nowFn()
	}
	return time.Now().Unix()
}

// rpcTimeout returns the per-RPC deadline (spec §A: RPC_TIMEOUT = 5s).
func rpcTimeout() time.Duration { return time.Duration(constants.RPCTimeoutSec) * time.Second }

// ---------------------------------------------------------------------------
// Inbound: read loop + dispatch
// ---------------------------------------------------------------------------

func (n *Node) readLoop() {
	buf := make([]byte, 65535)
	for {
		nread, raddr, err := n.conn.ReadFromUDP(buf)
		if err != nil {
			if n.closed.Load() {
				return
			}
			n.log.Debug("dht: read error", "err", err)
			continue
		}
		// Copy out of the read buffer (the next ReadFromUDP overwrites it).
		pkt := make([]byte, nread)
		copy(pkt, buf[:nread])
		n.handle(pkt, raddr)
	}
}

// handle decodes, verifies, and routes one inbound datagram. Malformed or
// unverified messages are dropped silently (never answered — answering an
// unverified source would aid amplification).
func (n *Node) handle(data []byte, raddr *net.UDPAddr) {
	m, err := wire.DecodeMessage(data)
	if err != nil {
		return
	}
	// Verify: id == SHA-256(pk) (already enforced by DecodeMessage) AND sig
	// covers [t, id, OUR_id, a] (recipient_id = this node).
	if !m.Verify(n.id) {
		return
	}
	// Learn/refresh the sender in the routing table from any signed traffic.
	n.learnPeer(m.PK, raddr)
	switch m.Y {
	case wire.MsgTypeResponse, wire.MsgTypeError:
		n.deliver(m)
	case wire.MsgTypeQuery:
		n.handleQuery(m, raddr)
	}
}

// deliver routes a response/error to the sendQuery call waiting on its txid.
func (n *Node) deliver(m *wire.Message) {
	key := string(m.T)
	n.mu.Lock()
	ch, ok := n.pending[key]
	if ok {
		delete(n.pending, key)
	}
	n.mu.Unlock()
	if !ok {
		return // stray response (timeout or duplicate); drop.
	}
	select {
	case ch <- m:
	default: // buffer full (shouldn't happen with cap 1 + single deliver)
	}
}

// learnPeer adds/refreshes a contact learned from inbound traffic. The sender's
// public key and Node ID come from the (already-verified) message; the address
// is the observed source (resistant to spoofing precisely because the message
// was signed to OUR id).
func (n *Node) learnPeer(pk []byte, raddr *net.UDPAddr) {
	id, err := crypto.NodeID(pk)
	if err != nil || bytes.Equal(id, n.id) {
		return
	}
	c, err := NewNodeContact(id, pk, raddr.String(), n.now())
	if err != nil {
		return
	}
	if evict := n.rtAddOrIgnore(c); evict != nil {
		// Bucket full and the sender is new. A full implementation would
		// ping-oldest-then-replace (§6.2); for the transport layer we simply
		// drop the new contact. Refreshing an existing contact (above) still
		// succeeds.
	}
}

// rtAddOrIgnore adds c, returning a non-nil eviction candidate if the bucket is
// full (so callers may, in future, perform live eviction). It never errors on a
// self/unknown contact.
func (n *Node) rtAddOrIgnore(c *NodeContact) *NodeContact {
	evict, err := n.rt.Add(c)
	if err != nil {
		return nil
	}
	return evict
}

func (n *Node) handleQuery(m *wire.Message, raddr *net.UDPAddr) {
	var resp *wire.Message
	switch m.Q {
	case "ping":
		resp = n.hPing(m, raddr)
	case "find_node":
		resp = n.hFindNode(m, raddr)
	case "get":
		resp = n.hGet(m, raddr)
	case "put":
		resp = n.hPut(m, raddr)
	default:
		resp = n.errResp(m, 301, "unknown method")
	}
	if resp == nil {
		return
	}
	data, err := resp.Bytes()
	if err != nil {
		n.log.Debug("dht: encode response", "err", err)
		return
	}
	if _, err := n.conn.WriteToUDP(data, raddr); err != nil {
		n.log.Debug("dht: write response", "err", err)
	}
}

// ---------------------------------------------------------------------------
// Inbound method handlers (answer from local state only)
// ---------------------------------------------------------------------------

// hPing answers {} and issues a write token so the peer may later put (§6.3:
// tokens are obtained from a prior get/ping).
func (n *Node) hPing(m *wire.Message, raddr *net.UDPAddr) *wire.Message {
	return n.okResp(m, map[string]any{"token": n.issueToken(raddr)})
}

// hFindNode returns the K contacts nearest to {target} (§6.3).
func (n *Node) hFindNode(m *wire.Message, raddr *net.UDPAddr) *wire.Message {
	target, _ := m.A["target"].([]byte)
	if len(target) != constants.NodeIDLen {
		return n.errResp(m, 305, "bad target")
	}
	closest := n.rt.Closest(target, constants.K)
	return n.okResp(m, map[string]any{
		"nodes": encodeNodes(closest),
		"token": n.issueToken(raddr),
	})
}

// hGet returns the stored envelope for {key} if present; otherwise the K closest
// contacts (§6.4 GET). Either way a write token is included.
func (n *Node) hGet(m *wire.Message, raddr *net.UDPAddr) *wire.Message {
	key, _ := m.A["key"].([]byte)
	if len(key) != constants.SHA256Len {
		return n.errResp(m, 305, "bad key")
	}
	now := n.now()
	env, _ := n.store.Get(key, now)
	args := map[string]any{"token": n.issueToken(raddr)}
	if env != nil {
		if eb, err := env.Bytes(); err == nil {
			args["envelope"] = eb // bstr .cbor SignedEnvelope
		}
	} else {
		// Miss: return the closest known contacts so the requester iterates.
		args["nodes"] = encodeNodes(n.rt.Closest(key, constants.K))
	}
	return n.okResp(m, args)
}

// hPut stores an envelope after verifying the write token, the envelope
// signature, and the §6.4 winner rule (delegated to EnvelopeStore.Put).
func (n *Node) hPut(m *wire.Message, raddr *net.UDPAddr) *wire.Message {
	token, _ := m.A["token"].([]byte)
	envBytes, _ := m.A["envelope"].([]byte)
	// Write-token defense (§6.3): HMAC over the observed source IP.
	if !n.tokens.Verify(normIP(raddr.IP), token, 1) {
		return n.errResp(m, 302, "invalid token")
	}
	env, err := wire.DecodeEnvelope(envBytes)
	if err != nil {
		return n.errResp(m, 305, "invalid record")
	}
	if !env.VerifySignature() {
		return n.errResp(m, 303, "invalid signature")
	}
	key, err := KeyForWireName(env.Record.Name)
	if err != nil {
		return n.errResp(m, 305, "bad record name")
	}
	accepted, err := n.store.Put(key, env, n.now(), false) // sig already verified
	if err != nil {
		return n.errResp(m, 301, "store error")
	}
	if !accepted {
		// Distinguish idempotent republication (same envelope) from a strictly
		// stale loser of the winner rule (§6.4 step 3).
		if inc, _ := n.store.Get(key, n.now()); inc != nil {
			ih, e1 := inc.RecordHash()
			ph, e2 := env.RecordHash()
			if e1 == nil && e2 == nil && bytes.Equal(ih, ph) {
				return n.okResp(m, map[string]any{}) // idempotent: already the winner
			}
		}
		return n.errResp(m, 304, "stale record")
	}
	return n.okResp(m, map[string]any{})
}

// ---------------------------------------------------------------------------
// Outbound: query send + response matching
// ---------------------------------------------------------------------------

// sendQuery transmits a signed query to addr and awaits the matching response
// (correlated by txid via readLoop→deliver). Returns ErrTimeout on no response
// within RPC_TIMEOUT, or ctx.Err() if the caller's context expires first.
func (n *Node) sendQuery(ctx context.Context, addr *net.UDPAddr, recipientID []byte, method string, args map[string]any) (*wire.Message, error) {
	txid := make([]byte, 8)
	if _, err := rand.Read(txid); err != nil {
		return nil, err
	}
	msg, err := wire.NewQuery(method, args, n.kp, recipientID, txid)
	if err != nil {
		return nil, err
	}
	data, err := msg.Bytes()
	if err != nil {
		return nil, err
	}
	ch := make(chan *wire.Message, 1)
	key := string(txid)
	n.mu.Lock()
	n.pending[key] = ch
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.pending, key)
		n.mu.Unlock()
	}()
	if n.conn == nil {
		return nil, errors.New("dht: transport not started")
	}
	if _, err := n.conn.WriteToUDP(data, addr); err != nil {
		return nil, err
	}
	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(rpcTimeout()):
		return nil, ErrTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Ping sends a ping to peer and returns nil on a successful response.
func (n *Node) Ping(ctx context.Context, peer Peer) error {
	recipientID, err := crypto.NodeID(peer.PublicKey)
	if err != nil {
		return err
	}
	addr, err := net.ResolveUDPAddr("udp", peer.Addr)
	if err != nil {
		return err
	}
	resp, err := n.sendQuery(ctx, addr, recipientID, "ping", map[string]any{})
	if err != nil {
		return err
	}
	if resp.Y == wire.MsgTypeError {
		return fmt.Errorf("dht: ping error code %v", resp.A["code"])
	}
	return nil
}

// AddPeer adds a bootstrap contact to the routing table (no network IO). The
// peer's public key is required because it determines the recipient_id used to
// sign any subsequent RPC to it.
func (n *Node) AddPeer(pk []byte, addr string) error {
	id, err := crypto.NodeID(pk)
	if err != nil {
		return err
	}
	c, err := NewNodeContact(id, pk, addr, n.now())
	if err != nil {
		return err
	}
	n.rtAddOrIgnore(c)
	return nil
}

// Bootstrap pings each peer (best-effort, concurrent), which both verifies
// reachability and seeds the routing tables in both directions (the peer learns
// us from our signed ping). Failures are logged at debug level and do not abort.
func (n *Node) Bootstrap(ctx context.Context, peers []Peer) {
	for _, p := range peers {
		if err := n.AddPeer(p.PublicKey, p.Addr); err != nil {
			n.log.Debug("dht: bootstrap add peer", "addr", p.Addr, "err", err)
			continue
		}
		go func(p Peer) {
			c, cancel := context.WithTimeout(ctx, rpcTimeout())
			defer cancel()
			if err := n.Ping(c, p); err != nil {
				n.log.Debug("dht: bootstrap ping", "addr", p.Addr, "err", err)
				return
			}
			n.log.Info("dht: bootstrapped peer", "addr", p.Addr)
		}(p)
	}
}

// ---------------------------------------------------------------------------
// Client-side iterative Kademlia GET (§6.4)
// ---------------------------------------------------------------------------

// IterativeGet performs the §6.4 GET: an iterative Kademlia lookup on key,
// querying ALPHA=3 contacts per round in parallel, collecting closer contacts
// and any envelopes encountered, and returning the winner by (sequence desc,
// H_record desc) — the deterministic, convergent selection of §6.4 step 2.
//
// Returns (nil, nil) when no envelope is found anywhere reachable.
func (n *Node) IterativeGet(ctx context.Context, key []byte) (*wire.SignedEnvelope, error) {
	if len(key) != constants.SHA256Len {
		return nil, fmt.Errorf("dht: key must be %d bytes, got %d", constants.SHA256Len, len(key))
	}
	shortlist := append([]*NodeContact(nil), n.rt.Closest(key, constants.K)...)
	if len(shortlist) == 0 {
		return nil, nil // no peers known: an island.
	}
	queried := make(map[string]bool, len(shortlist))
	var bestEnv *wire.SignedEnvelope

	for round := 0; round < maxLookupRounds; round++ {
		// Nearest-first so the ALPHA un-queried we pick are the closest.
		sort.SliceStable(shortlist, func(i, j int) bool {
			return CompareDistance(key, shortlist[i].NodeID, shortlist[j].NodeID) < 0
		})
		var batch []*NodeContact
		for _, c := range shortlist {
			if !queried[string(c.NodeID)] {
				batch = append(batch, c)
				if len(batch) >= constants.Alpha {
					break
				}
			}
		}
		if len(batch) == 0 {
			break // every known contact queried: converged.
		}

		type res struct {
			env   *wire.SignedEnvelope
			nodes []*NodeContact
		}
		results := make([]res, len(batch))
		var wg sync.WaitGroup
		for i, c := range batch {
			queried[string(c.NodeID)] = true
			wg.Add(1)
			go func(i int, c *NodeContact) {
				defer wg.Done()
				e, ns := n.getFromPeer(ctx, key, c)
				results[i] = res{e, ns}
			}(i, c)
		}
		wg.Wait()

		for _, r := range results {
			for _, nc := range r.nodes {
				n.learnContact(nc)
				if !contactIn(shortlist, nc.NodeID) {
					shortlist = append(shortlist, nc)
				}
			}
			if r.env != nil && r.env.VerifySignature() {
				if bestEnv == nil || wire.EnvelopeWins(r.env, bestEnv) {
					bestEnv = r.env
				}
			}
		}
	}
	return bestEnv, nil
}

// getFromPeer issues a single get(key) RPC to c and parses the response into the
// envelope (if the peer had it) and/or the closer-contacts list (if it didn't).
func (n *Node) getFromPeer(ctx context.Context, key []byte, c *NodeContact) (*wire.SignedEnvelope, []*NodeContact) {
	addr, err := net.ResolveUDPAddr("udp", c.Addr)
	if err != nil {
		return nil, nil
	}
	resp, err := n.sendQuery(ctx, addr, c.NodeID, "get", map[string]any{"key": key})
	if err != nil || resp == nil || resp.Y == wire.MsgTypeError {
		return nil, nil
	}
	var env *wire.SignedEnvelope
	if eb, ok := resp.A["envelope"].([]byte); ok && len(eb) > 0 {
		if e, derr := wire.DecodeEnvelope(eb); derr == nil {
			env = e
		}
	}
	var nodes []*NodeContact
	if raw, ok := resp.A["nodes"]; ok {
		nodes = parseNodes(raw)
	}
	return env, nodes
}

// learnContact refreshes/inserts a contact discovered via find_node/get (a
// parsed node list, so LastSeen is stamped here).
func (n *Node) learnContact(c *NodeContact) {
	if c == nil || bytes.Equal(c.NodeID, n.id) {
		return
	}
	c.LastSeen = n.now()
	n.rtAddOrIgnore(c)
}

// Publish stores env on the R closest nodes to its key (§6.4 PUT), obtaining a
// write token from each first via a get. It is best-effort: it returns nil if at
// least one store accepted the envelope. With no peers known it returns
// ErrNoPeers (the record remains only in the local store).
//
// This is the §6.4 publish path; the resolver path uses IterativeGet (pull).
func (n *Node) Publish(ctx context.Context, env *wire.SignedEnvelope) error {
	if env == nil || env.Record == nil {
		return errors.New("dht: nil envelope")
	}
	key, err := KeyForWireName(env.Record.Name)
	if err != nil {
		return err
	}
	envBytes, err := env.Bytes()
	if err != nil {
		return err
	}
	closest := n.rt.Closest(key, constants.RReplication)
	if len(closest) == 0 {
		return ErrNoPeers
	}
	accepted := 0
	for _, c := range closest {
		if err := n.putToPeer(ctx, key, envBytes, c); err == nil {
			accepted++
		}
	}
	if accepted == 0 {
		return fmt.Errorf("dht: publish accepted by 0 of %d peers", len(closest))
	}
	return nil
}

// ErrNoPeers signals that Publish had no peers to store to.
var ErrNoPeers = errors.New("dht: no peers known")

// putToPeer obtains a write token (via get) then issues put to c.
func (n *Node) putToPeer(ctx context.Context, key, envBytes []byte, c *NodeContact) error {
	addr, err := net.ResolveUDPAddr("udp", c.Addr)
	if err != nil {
		return err
	}
	// §6.3: obtain a token via a prior get (the get response carries one).
	resp, err := n.sendQuery(ctx, addr, c.NodeID, "get", map[string]any{"key": key})
	if err != nil || resp == nil {
		return ErrTimeout
	}
	token, _ := resp.A["token"].([]byte)
	if len(token) == 0 {
		// Some peers only mint tokens on ping; fall back to ping.
		pr, perr := n.sendQuery(ctx, addr, c.NodeID, "ping", map[string]any{})
		if perr != nil || pr == nil {
			return ErrTimeout
		}
		token, _ = pr.A["token"].([]byte)
	}
	putResp, err := n.sendQuery(ctx, addr, c.NodeID, "put", map[string]any{
		"token":    token,
		"envelope": envBytes,
	})
	if err != nil {
		return err
	}
	if putResp == nil || putResp.Y == wire.MsgTypeError {
		return fmt.Errorf("dht: put rejected: %v", putResp.A["code"])
	}
	return nil
}

// ---------------------------------------------------------------------------
// DHTLookup — RecordLookup adapter (local store first, then network GET)
// ---------------------------------------------------------------------------

// DHTLookup adapts (local store + Node) to the resolver.RecordLookup interface
// (structurally — it does not import resolver). On a local-store miss it runs an
// iterative network GET and, on success, caches the fetched envelope into the
// local store (§6.4 "nodes along the lookup path MAY cache") so subsequent
// lookups are local.
type DHTLookup struct {
	store *EnvelopeStore
	node  *Node
}

// NewDHTLookup wraps store (local) and node (network) into a RecordLookup.
func NewDHTLookup(store *EnvelopeStore, node *Node) *DHTLookup {
	return &DHTLookup{store: store, node: node}
}

// Lookup returns the winning SignedEnvelope for wireName: the local store first,
// then an iterative network GET (cached on success). Returns (nil, nil) when no
// record is available locally or across the reachable network.
func (l *DHTLookup) Lookup(ctx context.Context, wireName []byte, now int64) (*wire.SignedEnvelope, error) {
	key, err := KeyForWireName(wireName)
	if err != nil {
		return nil, err
	}
	if env, _ := l.store.Get(key, now); env != nil {
		return env, nil
	}
	if l.node == nil {
		return nil, nil
	}
	c, cancel := context.WithTimeout(ctx, dhtLookupTimeout)
	defer cancel()
	env, err := l.node.IterativeGet(c, key)
	if err != nil {
		return nil, err
	}
	if env == nil {
		return nil, nil
	}
	// Cache the fetched envelope locally (verifySignature=true defensively
	// re-checks the signature before storing).
	_, _ = l.store.Put(key, env, now, true)
	return env, nil
}

// ---------------------------------------------------------------------------
// response builders
// ---------------------------------------------------------------------------

func (n *Node) okResp(req *wire.Message, args map[string]any) *wire.Message {
	resp, err := wire.NewResponse(args, n.kp, req.ID, req.T)
	if err != nil {
		n.log.Debug("dht: build ok response", "err", err)
		return nil
	}
	return resp
}

// errResp builds a y="e" message carrying a §6.3 error code in args.
func (n *Node) errResp(req *wire.Message, code int, msg string) *wire.Message {
	resp, err := wire.NewError(map[string]any{"code": uint64(code), "msg": msg}, n.kp, req.ID, req.T)
	if err != nil {
		n.log.Debug("dht: build error response", "err", err)
		return nil
	}
	return resp
}

func (n *Node) issueToken(raddr *net.UDPAddr) []byte {
	return n.tokens.Issue(normIP(raddr.IP))
}

// ---------------------------------------------------------------------------
// node-list (de)serialization + small helpers
// ---------------------------------------------------------------------------

// encodeNodes serializes contacts as a CBOR array of [ip, port, node_id, pk]
// arrays (the {nodes: [...]} payload of find_node / get-miss). IPv4 is emitted
// as 4 bytes, IPv6 as 16.
func encodeNodes(contacts []*NodeContact) []any {
	out := make([]any, 0, len(contacts))
	for _, c := range contacts {
		ip := net.ParseIP(hostOf(c.Addr))
		var ipBytes []byte
		if ip != nil {
			if v4 := ip.To4(); v4 != nil {
				ipBytes = []byte(v4)
			} else {
				ipBytes = []byte(ip)
			}
		} else {
			ipBytes = []byte{}
		}
		port := uint64(portOf(c.Addr))
		out = append(out, []any{ipBytes, port, c.NodeID, c.PublicKey})
	}
	return out
}

// parseNodes decodes a {nodes: [...]} value (a []any of []any) into contacts.
// Malformed entries are skipped rather than failing the whole list.
func parseNodes(raw any) []*NodeContact {
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]*NodeContact, 0, len(arr))
	for _, e := range arr {
		ea, ok := e.([]any)
		if !ok || len(ea) != 4 {
			continue
		}
		ipBytes, ok := ea[0].([]byte)
		if !ok {
			continue
		}
		port, ok := asUint64(ea[1])
		if !ok {
			continue
		}
		nodeID, ok := ea[2].([]byte)
		if !ok {
			continue
		}
		pk, ok := ea[3].([]byte)
		if !ok {
			continue
		}
		ip := net.IP(ipBytes)
		addr := net.JoinHostPort(ip.String(), strconv.FormatUint(port, 10))
		c, err := NewNodeContact(nodeID, pk, addr, 0)
		if err != nil {
			continue
		}
		out = append(out, c)
	}
	return out
}

// asUint64 coerces a decoded CBOR integer (uint64/int64/float64) to uint64.
func asUint64(v any) (uint64, bool) {
	switch x := v.(type) {
	case uint64:
		return x, true
	case int64:
		return uint64(x), true
	case int:
		return uint64(x), true
	case uint:
		return uint64(x), true
	case float64:
		return uint64(x), true
	}
	return 0, false
}

// normIP reduces a net.IP to its canonical form (4 bytes for v4) so that token
// issue (on a get/ping) and token verify (on a put) see identical bytes.
func normIP(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return []byte(v4)
	}
	return []byte(ip)
}

func contactIn(list []*NodeContact, id []byte) bool {
	for _, c := range list {
		if bytes.Equal(c.NodeID, id) {
			return true
		}
	}
	return false
}

// hostOf/portOf split an "ip:port" or "[ip]:port" string.
func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}
