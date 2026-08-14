// Package dht — transport.go implements the §6.3 UDP Kademlia RPC transport:
// the signed CBOR message envelope on the wire (Appendix B.1), the ping /
// find_node / get / put / witness methods, rotating write-token defense (§6.3),
// the 256-bucket routing table (§6.2), the iterative Kademlia GET lookup
// (§6.4) that turns a set of independent envelope-store "islands" into a real
// multi-node network, and the background maintenance loops: the §6.2 bucket
// refresh, the §6.4 step 4 republish timer, and the §6.2 live-eviction check
// (ping-oldest, replace on failure) that keeps full buckets healthy. Read
// queries (get / find_node) are additionally rate-limited per source IP per
// §12 line 914 ("Implementations MAY throttle passive clients' get rates").
//
// It also carries the §7 registration machinery that touches the network: the
// §6.3 `witness` RPC (§7.3 witness attestations, §7.4 registration steps 3-4),
// the §7.4/C.1 claim-envelope publication at K_claim (PublishClaim), and the
// K_claim lookup side used by resolvers (DHTLookup.LookupClaim).
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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laurent/freens/internal/claims"
	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/naming"
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

// lookupProbeTimeout bounds each iterative-lookup candidate probe (§6.4 GET).
// It is deliberately shorter than RPC_TIMEOUT (5s): solicited single RPCs
// (publish token handshakes, pings) get the full spec window, but an iterative
// lookup probes multiple candidates per round and must not serialise dead
// contacts at 5s each — a peer that cannot answer a tiny UDP get in 2s is
// effectively unavailable and gets evicted (§6.2 failure handling).
const lookupProbeTimeout = 2 * time.Second

// defaultRepublishInterval is the default scan period of the §6.4 step 4
// republish timer (overridable via NodeConfig.RepublishInterval). It is a
// daemon-level knob, not a spec constant: the spec only fixes WHEN a record is
// due (past RefreshFraction = 80% of its lifetime, checked on every scan).
const defaultRepublishInterval = 60 * time.Second

// Default per-source-IP get/find_node throttle (§12 line 914). 50 req/s with a
// burst of 100 is ~2 orders of magnitude above honest lookup traffic (an
// iterative GET issues one get per round-trip per ALPHA=3 candidate) while
// still capping a single source's read amplification.
const (
	defaultGetRateLimit = 50.0 // req/s per source IP
	defaultGetBurst     = 100  // back-to-back queries per idle source
	// limiterMaxEntries triggers a lazy sweep of idle per-IP buckets (the map
	// is keyed by observed source IP of SIGNED queries, so reaching it implies
	// 10k distinct abusive sources).
	limiterMaxEntries = 10_000
	// limiterIdle is how long an entry must be unused before a sweep may drop
	// it (well above burst/rate for the defaults).
	limiterIdle = 10 * time.Minute
)

// evictQueueCap bounds the pending §6.2 live-eviction requests. Combined with
// the per-bucket coalescing (evictPending) it guarantees the maintenance path
// can never accumulate unbounded work under a contact flood.
const evictQueueCap = 64

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
	// Passive selects the §6.1 opt-out ("clients MAY disable participation,
	// at the cost of relying on others", spec lines 397-408; §12 economics,
	// lines 900-915). Interpretation implemented here: "participation" is the
	// STORING side of the DHT. A passive node still ANSWERS ping / find_node /
	// get (serving its own store and cache — serving reads is cheap and keeps
	// the network healthy) and still performs its own iterative GETs, but it
	// REFUSES put (hPut answers error 301 "passive node") and never runs the
	// §6.4 republish timer (it does not volunteer to keep others' records
	// alive).
	Passive bool
	// BucketRefreshInterval overrides the §6.2 bucket-refresh period (spec
	// lines 410-424). Zero ⇒ constants.BucketRefresh (900s). Negative disables
	// the refresh loop. The refresh runs regardless of Passive (even a passive
	// node needs a healthy routing table for its own iterative GETs).
	BucketRefreshInterval time.Duration
	// RepublishInterval overrides the scan period of the §6.4 step 4 republish
	// timer (spec lines 471-473: records are republished once past
	// RefreshFraction = 80% of their lifetime). Zero ⇒ 60s. Negative disables
	// the republish loop; Passive disables it regardless.
	RepublishInterval time.Duration
	// BucketCapacity overrides the per-bucket capacity of the §6.2 routing
	// table (K). Zero ⇒ constants.K (20). It exists mainly so tests can
	// exercise bucket-full behavior (including live eviction) without minting
	// K real peers; production nodes leave it at the spec default.
	BucketCapacity int
	// PingTimeout overrides the deadline of the §6.2 live-eviction liveness
	// ping (ping-oldest-then-replace, spec lines 410-424). Zero ⇒ RPC_TIMEOUT
	// (5s, Appendix A). It bounds ONLY the maintenance ping — solicited
	// client-side RPCs (Ping, publish handshakes, lookups) keep their own
	// deadlines — so tests can shorten the eviction wait without loosening
	// any other timing.
	PingTimeout time.Duration
	// GetRateLimit caps get and find_node queries per observed source IP
	// (token bucket, requests/second) per §12 line 914: "Implementations MAY
	// throttle passive clients' get rates". A node cannot distinguish passive
	// freeloaders from active clients on the wire, so the limit applies to
	// every source; the default (50/s) is far above honest lookup traffic.
	// Zero ⇒ 50. Negative disables throttling. Excess queries are answered
	// with error 301 "throttled" (not silently dropped: the spec's error
	// table, §6.3, has no flood row requiring silence, a signed error is as
	// cheap as the query it answers, and explicit feedback lets well-behaved
	// clients back off instead of hammering through full RPC timeouts).
	GetRateLimit float64
	// GetBurst is the token-bucket burst size paired with GetRateLimit (the
	// number of queries an idle source may send back-to-back). Zero ⇒ 100.
	// Ignored when GetRateLimit < 0.
	GetBurst int
	// Advertise is the address peers should dial to reach this node (§6.2
	// line 422-423: "nodes advertise (ip, port, node_pubkey)"). Empty ⇒
	// today's behavior (peers learn the OBSERVED UDP source address, which
	// is correct except behind NAT/port-forwarding). When set it must be a
	// resolvable host:port; it is validated once at Start (a bad value logs
	// a warning and falls back to observed) and then stamped into every
	// outbound query ("advertise" arg), so peers learnPeer this node at the
	// advertised — e.g. public — address instead of a private observed
	// source.
	Advertise string
}

// Node is one freens DHT participant: a UDP socket, an identity, a routing
// table, a rotating write-token store, and a shared envelope store. It serves
// inbound RPCs and offers client-side Ping / IterativeGet / Publish, plus
// background maintenance started by Start and stopped by Close: the §6.2
// bucket refresh, the §6.4 step 4 republish timer (only when not Passive),
// and the §6.2 live-eviction check (ping-oldest, replace on failure).
//
// All public methods are safe for concurrent use.
type Node struct {
	kp             *crypto.Keypair
	id             []byte
	listenAddr     string
	conn           *net.UDPConn
	closed         atomic.Bool
	passive        bool
	refreshEvery   time.Duration // resolved: >0 = run refresh loop
	republishEvery time.Duration // resolved: >0 = run republish loop
	pingTimeout    time.Duration // resolved: §6.2 eviction-ping deadline
	bgCancel       context.CancelFunc
	bgOnce         sync.Once
	bgWg           sync.WaitGroup

	store  *EnvelopeStore
	rt     *RoutingTable
	tokens *TokenStore
	claims *ClaimPool       // §7.4 "storing nodes keep the top 2 by ordering" (claims_pool.go)
	diff   *difficultyState // Appendix A.4 own difficulty + observed ring (gossip.go)
	getLim *rateLimiter     // per-source-IP get/find_node throttle (§12); nil = off
	log    *slog.Logger
	nowFn  func() int64

	// advertise is the validated §6.2 advertised address ("" ⇒ peers learn
	// the observed source). Parsed from NodeConfig.Advertise once at Start;
	// written before any goroutine reads it.
	advertise string

	// §6.2 live eviction: readLoop-side callers (learnPeer runs on the read
	// goroutine) hand full-bucket contacts to a single serialized maintenance
	// goroutine via evictCh; evictPending coalesces per bucket index so at
	// most one request per bucket is queued or in flight. Nothing in the
	// inbound path ever blocks on the maintenance goroutine.
	evictCh      chan *NodeContact
	evictMu      sync.Mutex
	evictPending map[int]bool

	// witnessLast implements the §7.3 WITNESS_COOLDOWN rule: alias → the last
	// claim this node co-signed (identified by its §7.3 PoW prefix hash) and
	// when. Guarded by witnessMu.
	witnessMu   sync.Mutex
	witnessLast map[string]witnessSigned

	mu      sync.Mutex
	pending map[string]chan *wire.Message
}

// witnessSigned records one witnessed claim for the WITNESS_COOLDOWN check:
// the SHA-256 of the claim's §7.3 PoW prefix (which binds alias, tld_id,
// timestamp, and claimant_pk — two different claims for the same alias never
// share it) and the unix second the node signed.
type witnessSigned struct {
	prefixHash []byte
	at         int64
}

// NewNode validates cfg and constructs (but does not Start) a Node. The routing
// table (NodeConfig.BucketCapacity, default K entries/bucket) and token store
// (300s rotation) are created internally; the token root secret is derived
// deterministically from the node seed so a stable identity yields stable token
// epochs across restarts.
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
	bucketCap := cfg.BucketCapacity
	if bucketCap <= 0 {
		bucketCap = constants.K
	}
	rt, err := NewRoutingTable(id, bucketCap)
	if err != nil {
		return nil, err
	}
	pingTimeout := cfg.PingTimeout
	if pingTimeout <= 0 {
		pingTimeout = rpcTimeout()
	}
	// Resolve the background-loop periods: zero ⇒ default, negative ⇒ off.
	refreshEvery := cfg.BucketRefreshInterval
	if refreshEvery == 0 {
		refreshEvery = time.Duration(constants.BucketRefresh) * time.Second
	} else if refreshEvery < 0 {
		refreshEvery = 0
	}
	republishEvery := cfg.RepublishInterval
	if republishEvery == 0 {
		republishEvery = defaultRepublishInterval
	} else if republishEvery < 0 {
		republishEvery = 0
	}
	// Per-source-IP read throttle (§12 line 914): negative rate ⇒ disabled.
	var getLim *rateLimiter
	if cfg.GetRateLimit >= 0 {
		rate := cfg.GetRateLimit
		if rate == 0 {
			rate = defaultGetRateLimit
		}
		burst := cfg.GetBurst
		if burst <= 0 {
			burst = defaultGetBurst
		}
		getLim = newRateLimiter(rate, burst)
	}
	return &Node{
		kp:             cfg.Keypair,
		id:             id,
		listenAddr:     cfg.ListenAddr,
		passive:        cfg.Passive,
		refreshEvery:   refreshEvery,
		republishEvery: republishEvery,
		pingTimeout:    pingTimeout,
		store:          cfg.Store,
		rt:             rt,
		tokens:         tokens,
		claims:         NewClaimPool(),
		diff:           newDifficultyState(now()),
		getLim:         getLim,
		log:            log,
		nowFn:          now,
		advertise:      cfg.Advertise,
		evictCh:        make(chan *NodeContact, evictQueueCap),
		evictPending:   make(map[int]bool),
		witnessLast:    make(map[string]witnessSigned),
		pending:        make(map[string]chan *wire.Message),
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

// Start binds the UDP socket and launches the read loop and the background
// maintenance loops (§6.2 bucket refresh; §6.4 step 4 republish timer unless
// Passive). It returns once the socket is bound; the loops run until Close.
func (n *Node) Start() error {
	// §6.2 advertised address: validate ONCE here. A non-resolvable
	// host:port (or a missing host/port) logs a warning and falls back to
	// the observed-source behavior — a bad Advertise must not brick the node.
	if n.advertise != "" {
		if a, err := net.ResolveUDPAddr("udp", n.advertise); err != nil || a.IP == nil || a.Port == 0 {
			n.log.Warn("dht: invalid Advertise address (want resolvable host:port); "+
				"peers will learn the observed source address", "advertise", n.advertise)
			n.advertise = ""
		} else {
			n.advertise = a.String() // canonical resolved form
		}
	}
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
	n.startBackground()
	go n.readLoop()
	return nil
}

// Close stops the background loops (blocking until they have exited — their
// in-flight RPCs return promptly via context cancellation, so no goroutines
// leak), stops the read loop, and closes the UDP socket. Pending sendQuery
// callers will time out normally.
func (n *Node) Close() error {
	n.stopBackground()
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
	// A peer with a validated Advertise (§6.2) stamps it on its queries; a
	// syntactically bad value is ignored in favor of the observed source.
	adv, _ := m.A["advertise"].(string)
	n.learnPeer(m.PK, raddr, adv)
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
// public key and Node ID come from the (already-verified) message. The address
// is the OBSERVED source (resistant to spoofing precisely because the message
// was signed to OUR id) — unless the sender advertised a concrete host:port
// (§6.2 line 422-423: "nodes advertise (ip, port, node_pubkey)"), in which
// case the advertised address wins: behind NAT/port-forwarding the observed
// source is a private address peers cannot dial back. The advertised value is
// only trusted as an ADDRESS (never as an identity — the key/ID still come
// from the verified signature), and only when it parses as a literal
// host:port with a port (no DNS on the read-loop hot path; honest -advertise
// values are pre-resolved at the sender's Start).
func (n *Node) learnPeer(pk []byte, raddr *net.UDPAddr, advertised string) {
	id, err := crypto.NodeID(pk)
	if err != nil || bytes.Equal(id, n.id) {
		return
	}
	addr := raddr.String()
	if advertised != "" {
		if a, ok := parseAdvertisedAddr(advertised); ok {
			addr = a
		}
	}
	c, err := NewNodeContact(id, pk, addr, n.now())
	if err != nil {
		return
	}
	n.learn(c)
}

// parseAdvertisedAddr validates a peer-advertised address as a literal
// host:port with a non-zero port, returning its canonical "ip:port" string.
// It performs NO name resolution (the read loop must never block on DNS);
// hostnames are rejected in favor of the observed source.
func parseAdvertisedAddr(s string) (string, bool) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil || host == "" || portStr == "" {
		return "", false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", false // hostname: not resolvable without DNS; ignore
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), true
}

// rtAddOrIgnore adds c, returning a non-nil eviction candidate if the bucket is
// full (the §6.2 ping-oldest signal — see learn/evictCandidate). It never
// errors on a self/unknown contact.
func (n *Node) rtAddOrIgnore(c *NodeContact) *NodeContact {
	evict, err := n.rt.Add(c)
	if err != nil {
		return nil
	}
	return evict
}

// learn inserts or refreshes c, performing §6.2 live eviction when c's bucket
// is full (spec lines 410-424: "standard Kademlia eviction (ping-oldest,
// replace on failure)"). The eviction check is ASYNC — learn runs on the
// readLoop goroutine (learnPeer) and must not block on a network round-trip
// that only readLoop itself could deliver — so a full bucket schedules the
// candidate on the maintenance channel and returns immediately. Coalescing:
// at most one request per bucket index is queued or in flight; later
// candidates for the same bucket are dropped (the bucket has one contested
// slot, and the next verified traffic retries cheaply).
func (n *Node) learn(c *NodeContact) {
	if evict := n.rtAddOrIgnore(c); evict != nil {
		n.scheduleEviction(c)
	}
}

// scheduleEviction hands c to the maintenance goroutine unless a check for its
// bucket is already queued or in flight. Never blocks (bounded channel,
// non-blocking send): a flooded bucket degrades to "drop the newcomer", never
// to backpressure on readLoop.
func (n *Node) scheduleEviction(c *NodeContact) {
	b, err := n.rt.BucketFor(c.NodeID)
	if err != nil {
		return // self/invalid: nothing to maintain
	}
	n.evictMu.Lock()
	if n.evictPending[b.Index] {
		n.evictMu.Unlock()
		return // coalesce: a check for this bucket is already pending
	}
	n.evictPending[b.Index] = true
	n.evictMu.Unlock()
	select {
	case n.evictCh <- c:
	default: // queue full: back out the pending mark and drop the request
		n.evictMu.Lock()
		delete(n.evictPending, b.Index)
		n.evictMu.Unlock()
	}
}

// evictionLoop is the single serialized §6.2 maintenance goroutine. It serves
// the evictCh queue one request at a time — a request may block for up to
// NodeConfig.PingTimeout inside the liveness ping, which is exactly why this
// work must not run inline on readLoop. Started by Start, stopped by Close
// (the shared background context cancels an in-flight ping promptly).
func (n *Node) evictionLoop(ctx context.Context) {
	defer n.bgWg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-n.evictCh:
			n.evictCandidate(ctx, c)
			if b, err := n.rt.BucketFor(c.NodeID); err == nil {
				n.evictMu.Lock()
				delete(n.evictPending, b.Index)
				n.evictMu.Unlock()
			}
		}
	}
}

// evictCandidate performs the §6.2 ping-oldest check for newcomer c, whose
// bucket was full when the request was scheduled:
//
//   - Re-add c first: the table may have changed while the request waited
//     (contact evicted elsewhere, bucket drained). A nil return from
//     rtAddOrIgnore means c was inserted or refreshed — done.
//   - Otherwise ping the CURRENT oldest (head) of c's bucket with the
//     maintenance deadline. Any verified response proves the oldest is live
//     (readLoop→learnPeer refreshes it as a side effect, moving it to the
//     tail): keep it, drop c — the §6.2 rule favors retained, live contacts.
//   - On timeout / unreachable, remove the oldest and insert c in the freed
//     slot. A shutdown cancellation (ctx.Err) is NOT a peer failure: never
//     evict for it.
//
// The ping runs on the maintenance goroutine, so its response is delivered by
// the still-running readLoop — no self-deadlock with sendQuery.
func (n *Node) evictCandidate(ctx context.Context, c *NodeContact) {
	if ctx.Err() != nil || n.conn == nil {
		return
	}
	oldest := n.rtAddOrIgnore(c)
	if oldest == nil {
		return // bucket got room (or c became known) while queued: inserted
	}
	pctx, cancel := context.WithTimeout(ctx, n.pingTimeout)
	defer cancel()
	addr, err := net.ResolveUDPAddr("udp", oldest.Addr)
	if err != nil {
		n.log.Debug("dht: eviction ping address unresolvable", "addr", oldest.Addr, "err", err)
		return // keep the incumbent on our own failure; drop the newcomer
	}
	resp, err := n.sendQuery(pctx, addr, oldest.NodeID, "ping", map[string]any{})
	if err == nil && resp != nil {
		// Oldest answered (verified by handle before delivery): alive — keep
		// it, and with it the rest of the bucket; the newcomer loses (§6.2).
		return
	}
	if ctx.Err() != nil {
		return // our shutdown, not the peer's failure: evict nothing
	}
	n.rt.Remove(oldest.NodeID)
	n.rtAddOrIgnore(c)
	n.log.Debug("dht: evicted unresponsive oldest contact",
		"addr", oldest.Addr, "err", err)
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
	case "witness":
		resp = n.hWitness(m, raddr)
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

// hFindNode returns the K contacts nearest to {target} (§6.3). It shares the
// per-source-IP read throttle with get (§12 line 914 names get; find_node is
// the same unauthenticated-read lookup shape, so it is throttled alike).
func (n *Node) hFindNode(m *wire.Message, raddr *net.UDPAddr) *wire.Message {
	if !n.allowRead(raddr) {
		return n.errResp(m, 301, "throttled")
	}
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

// hGet answers a get(key) with everything this node can offer for key:
//
//   - `envelope`: the store winner (§6.4 single-envelope get), if present.
//
//   - `envelopes`: DEVIATION from §6.3's single-envelope get response
//     (documented; the table's response shape is `{envelope} or {nodes}` and
//     cannot express §7.4 line 602-604: "storing nodes keep the top 2 by
//     ordering"): a CBOR array of bstr, each a canonical SignedEnvelope
//     ("bstr .cbor SignedEnvelope"), BEST-FIRST by the §7.4 ordering, carried
//     whenever the ClaimPool holds claims for the key — on a store HIT (where
//     it refines the single `envelope`, which stays the §6.4 winner for
//     legacy clients) and on a MISS (alongside `nodes`, so an iterative
//     collector merges the competing claims instead of settling for whatever
//     one envelope a node happened to keep).
//
//   - `nodes`: the K closest contacts on a store miss (§6.4 GET), absent on a
//     hit.
//
//   - Audit fallback (§8.3 transfer chains): on a store miss with len(key)==32
//     the store's superseded-envelope history is consulted by the key — which
//     for this path is an H_record — so a superseded envelope stays fetchable
//     network-wide by its hash and third parties can verify hand-off history
//     offline. A history hit is returned as `envelope` exactly like a live
//     winner.
//
// §12 line 914 ("Implementations MAY throttle passive clients' get rates"):
// each source IP draws from a token bucket (NodeConfig.GetRateLimit /
// GetBurst; default 50/s burst 100). A node cannot distinguish passive
// freeloaders from active clients on the wire, so the limit is uniform; the
// generous default leaves honest lookups untouched while capping one source's
// read amplification. Excess queries get a signed error 301 "throttled" — see
// NodeConfig.GetRateLimit for why an answer beats a silent drop.
func (n *Node) hGet(m *wire.Message, raddr *net.UDPAddr) *wire.Message {
	if !n.allowRead(raddr) {
		return n.errResp(m, 301, "throttled")
	}
	key, _ := m.A["key"].([]byte)
	if len(key) != constants.SHA256Len {
		return n.errResp(m, 305, "bad key")
	}
	now := n.now()
	env, _ := n.store.Get(key, now)
	if env == nil {
		// §8.3 audit path: fetch a superseded envelope by its H_record.
		if h := n.store.GetHistory(key); h != nil {
			env = h
		}
	}
	args := map[string]any{"token": n.issueToken(raddr)}
	if env != nil {
		if eb, err := env.Bytes(); err == nil {
			args["envelope"] = eb // bstr .cbor SignedEnvelope
		}
	} else {
		// Miss: return the closest known contacts so the requester iterates.
		args["nodes"] = encodeNodes(n.rt.Closest(key, constants.K))
	}
	// §7.4 top-2 claim offers: whenever the pool holds claims for this key,
	// advertise them best-first (see the doc comment for the wire shape).
	if pooled := n.claims.Top2(key); len(pooled) > 0 {
		arr := make([]any, 0, len(pooled))
		for _, e := range pooled {
			if eb, err := e.Bytes(); err == nil {
				arr = append(arr, eb)
			}
		}
		if len(arr) > 0 {
			args["envelopes"] = arr
		}
	}
	return n.okResp(m, args)
}

// hPut stores an envelope after verifying the write token, the envelope
// signature, and the §6.4 winner rule (delegated to EnvelopeStore.Put).
//
// Storage key. The spec's put arguments are {token, envelope} (§6.3 table),
// implying the key is derived from the envelope — KeyForWireName(name) covers
// K_tld and K_name. But §7.4 step 5 / Appendix C.1 step 4 require the SAME
// claim-carrying TLD envelope to be stored at BOTH K_tld and K_claim, which a
// name-derived key cannot express. DEVIATION (documented; §6.3 is
// underspecified for the claim key space): the put arguments MAY carry an
// explicit "key" bstr. It is honored only when it equals the key derived from
// the record name (a no-op restatement) or K_claim of the AliasClaim embedded
// in field 11 — anything else is rejected with 305. An absent/empty "key"
// keeps the pre-existing name-derived behavior, so older senders are
// unaffected.
//
// A Passive node (§6.1) refuses the method outright with error 301 "passive
// node" — before any token or signature work — so passivity is observable on
// the wire rather than inferred from silence.
//
// §7.4 top-2 pool: an explicit-K_claim put ALSO offers the envelope into the
// node's ClaimPool ("storing nodes keep the top 2 by ordering", lines
// 602-604). A claim that loses the single-slot §6.4 winner race but is
// retained by the pool answers SUCCESS, not 304 — the node did keep it;
// 304 is reserved for an envelope retained nowhere.
func (n *Node) hPut(m *wire.Message, raddr *net.UDPAddr) *wire.Message {
	if n.passive {
		return n.errResp(m, 301, "passive node")
	}
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
	key, err := n.putKeyFor(m, env)
	if err != nil {
		return n.errResp(m, 305, "bad record name or key")
	}
	// §7.4 line 602-604 ("storing nodes keep the top 2 by ordering"): a put
	// landing at K_claim ALSO offers the envelope into the top-2 claim pool —
	// REGARDLESS of the winner-slot outcome below. Two competing claims at
	// equal sequence resolve the single store slot by the H_record
	// tie-break, but both belong in the pool so verifiers collecting "all
	// competing claims nodes offer" still see the pair.
	poolKept := false
	if claim, cerr := claims.DecodeAliasClaim(env.Record.Claim); cerr == nil {
		if kClaim, kerr := KeyForClaim(claim.Alias); kerr == nil && bytes.Equal(key, kClaim) {
			n.claims.Offer(kClaim, env)
			poolKept = n.claims.Contains(kClaim, recordHashOrNil(env)) // offered now or already pooled
		}
	}
	accepted, err := n.store.Put(key, env, n.now(), false) // sig already verified
	if err != nil {
		return n.errResp(m, 301, "store error")
	}
	if !accepted {
		// Distinguish idempotent republication (same envelope) from a strictly
		// stale loser of the winner rule (§6.4 step 3). A claim retained by
		// the §7.4 top-2 pool is ALSO a success: the node did keep it.
		if inc, _ := n.store.Get(key, n.now()); inc != nil {
			ih, e1 := inc.RecordHash()
			ph, e2 := env.RecordHash()
			if e1 == nil && e2 == nil && bytes.Equal(ih, ph) {
				return n.okResp(m, map[string]any{}) // idempotent: already the winner
			}
		}
		if poolKept {
			return n.okResp(m, map[string]any{}) // §7.4: retained in the top-2
		}
		return n.errResp(m, 304, "stale record")
	}
	return n.okResp(m, map[string]any{})
}

// recordHashOrNil returns env's H_record or nil (a nil never matches a pooled
// 32-byte hash, so Contains simply reports false for an unhashable envelope).
func recordHashOrNil(env *wire.SignedEnvelope) []byte {
	h, err := env.RecordHash()
	if err != nil {
		return nil
	}
	return h
}

// putKeyFor resolves the storage key for an inbound put per the hPut key rule:
// the name-derived key (K_tld / K_name), optionally restated by the sender,
// or — only when the envelope carries a decodable AliasClaim — the sender's
// explicit K_claim for that claim (§7.4 step 5 / C.1 step 4: the claim
// envelope lives at K_claim as well as K_tld).
func (n *Node) putKeyFor(m *wire.Message, env *wire.SignedEnvelope) ([]byte, error) {
	derived, err := KeyForWireName(env.Record.Name)
	if err != nil {
		return nil, err
	}
	explicit, _ := m.A["key"].([]byte)
	if len(explicit) == 0 || bytes.Equal(explicit, derived) {
		return derived, nil
	}
	claim, cerr := claims.DecodeAliasClaim(env.Record.Claim)
	if cerr != nil {
		return nil, fmt.Errorf("dht: explicit put key given but envelope carries no alias claim")
	}
	kClaim, kerr := KeyForClaim(claim.Alias)
	if kerr != nil {
		return nil, kerr
	}
	if !bytes.Equal(explicit, kClaim) {
		return nil, fmt.Errorf("dht: explicit put key is neither the name-derived key nor K_claim")
	}
	return kClaim, nil
}

// ---------------------------------------------------------------------------
// Inbound: §6.3 `witness` method (§7.3 witness attestations, §7.4 steps 3-4)
// ---------------------------------------------------------------------------

// hWitness answers the §6.3 `witness` method (table line 449): it co-signs an
// alias claim with THIS node's keypair and returns the attestation (§7.4
// registration step 3-4: "send each a witness RPC ... Assemble the claim with
// ≥ W attestations"; §7.3 lines 580-587: "a claim is attested when it carries
// valid signatures from W = 5 distinct witnesses").
//
// DEVIATION from §6.3 (documented, spec is underspecified here): the table
// gives arguments {claim_prefix_hash, claimant, ts} only, but the
// WitnessAttestation signature input (§7.3 lines 561-563) is
// ("freens-witness-v1", alias, tld_id, claimant_pk, ts). The PoW prefix hash
// is SHA-256 over the canonical CBOR identity fields {alias, tld_id, ts,
// claimant_pk} (Appendix C.1) and is a one-way digest — a witness cannot
// recover alias/tld_id from it, yet it MUST bind both into the signed
// attestation. The method therefore carries two extra arguments: "alias"
// (text) and "tld_id" (bstr). Both are re-verified against the supplied
// claim_prefix_hash, so a requester cannot make the node sign a message for
// (alias, tld_id) pairs other than the ones hashed into the prefix.
//
// Checks performed, in order:
//
//  1. Structural: alias validates per §3.2; tld_id is 32 bytes; claimant is a
//     32-byte Ed25519 public key; ts is a uint.
//  2. Prefix binding: claim_prefix_hash == SHA-256(PoW prefix(alias, tld_id,
//     claimant, ts)) — recomputed via the claims package's prefix builder, so
//     client and witness agree byte-for-byte with the mining input.
//  3. §7.3 WITNESS_COOLDOWN (constants.WitnessCooldown = 3600 s): the node
//     signs at most ONE claim per alias per cooldown window. Re-signing the
//     SAME claim (same prefix hash) is allowed (idempotent refresh); a
//     DIFFERENT claim for the same alias inside the window is refused with
//     error 301 "cooldown". (§7.3 line 584-586 also permits signing a strictly
//     earlier-ordered claim; ordering is a verifier-side computation, so the
//     conservative refusal here is safe — the requester retries after the
//     cooldown or with other witnesses.)
//  4. Co-sign via claims.NewWitnessAttestation with the NODE's keypair; the
//     attestation TS is this witness's OWN clock (§7.3 line 560: "witness's
//     own timestamp"), not the claimant-asserted ts.
//
// On success the response carries {attestation: canonical-CBOR
// WitnessAttestation} plus the node's current PoW difficulty (Appendix A.4:
// "Nodes gossip the current D in witness responses"). Attesting is logged at
// info level.
//
// A Passive node (§6.1) still witnesses: witnessing signs a timestamp, it
// stores nothing, so it is participation only in the weak §7 sense this node
// already opted into by joining the network.
func (n *Node) hWitness(m *wire.Message, _ *net.UDPAddr) *wire.Message {
	alias, _ := m.A["alias"].(string)
	tldID, _ := m.A["tld_id"].([]byte)
	claimant, _ := m.A["claimant"].([]byte)
	prefixHash, _ := m.A["claim_prefix_hash"].([]byte)
	ts, ok := asUint64(m.A["ts"])
	aliasN, aerr := naming.ValidateAlias(alias)
	if !ok || aerr != nil {
		return n.errResp(m, 305, "bad witness args")
	}
	if len(tldID) != constants.SHA256Len || len(claimant) != constants.Ed25519PublicKeyLen {
		return n.errResp(m, 305, "bad tld_id/claimant length")
	}
	// Prefix binding: recompute SHA-256(PoW prefix) from the identity fields.
	want, err := claimPrefixHash(aliasN, tldID, claimant, ts)
	if err != nil {
		return n.errResp(m, 305, "bad claim identity")
	}
	if len(prefixHash) != constants.SHA256Len || !bytes.Equal(prefixHash, want) {
		return n.errResp(m, 305, "bad claim prefix hash")
	}

	// §7.3 WITNESS_COOLDOWN: one (re-signable) claim per alias per window.
	now := n.now()
	n.witnessMu.Lock()
	last, seen := n.witnessLast[aliasN]
	cooling := seen &&
		now-last.at < int64(constants.WitnessCooldown) &&
		!bytes.Equal(last.prefixHash, prefixHash)
	if !cooling {
		n.witnessLast[aliasN] = witnessSigned{
			prefixHash: append([]byte(nil), prefixHash...),
			at:         now,
		}
	}
	n.witnessMu.Unlock()
	if cooling {
		return n.errResp(m, 301, "cooldown")
	}

	// Co-sign with the node keypair; TS is the witness's own clock.
	att, err := claims.NewWitnessAttestation(n.kp, uint64(now), aliasN, tldID, claimant)
	if err != nil {
		return n.errResp(m, 305, "attestation failed")
	}
	attBytes, err := att.CanonicalBytes()
	if err != nil {
		return n.errResp(m, 301, "attestation encode failed")
	}
	// Appendix A.4: count the accepted claim; every PoWRetargetBlock
	// acceptances the node's own difficulty retargets over the block span.
	n.diff.recordAccepted(now)
	n.log.Info("dht: witnessed alias claim",
		"alias", aliasN, "claimant", HexID(claimant), "ts", now)
	return n.okResp(m, map[string]any{
		"attestation": attBytes,                           // bstr .cbor WitnessAttestation
		"difficulty":  uint64(n.diff.currentDifficulty()), // Appendix A.4 gossip
	})
}

// claimPrefixHash returns SHA-256(PoW prefix) for a claim identity, where the
// prefix is the canonical CBOR of AliasClaim fields {1:alias, 2:tld_id,
// 3:timestamp, 5:claimant_pk} (§7.3 lines 566-567 as resolved by Appendix
// C.1; see the claims package's Prefix documentation). The claims package owns
// the byte-exact builder, so the mining side and the witness side always agree.
func claimPrefixHash(alias string, tldID, claimantPK []byte, ts uint64) ([]byte, error) {
	c := claims.AliasClaim{
		Alias:      alias,
		TldID:      tldID,
		Timestamp:  ts,
		ClaimantPK: claimantPK,
	}
	prefix, err := c.Prefix()
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(prefix)
	return h[:], nil
}

// ---------------------------------------------------------------------------
// Outbound: query send + response matching
// ---------------------------------------------------------------------------

// sendQuery transmits a signed query to addr and awaits the matching response
// (correlated by txid via readLoop→deliver). Returns ErrTimeout on no response
// within RPC_TIMEOUT, or ctx.Err() if the caller's context expires first.
func (n *Node) sendQuery(ctx context.Context, addr *net.UDPAddr, recipientID []byte, method string, args map[string]any) (*wire.Message, error) {
	// §6.2 advertised address: stamp it on every outbound query so the peer
	// learns THIS node at the advertised (public) address, not a NAT'd
	// private observed source. The map is copied, never the caller's.
	if n.advertise != "" {
		stamped := make(map[string]any, len(args)+1)
		for k, v := range args {
			stamped[k] = v
		}
		stamped["advertise"] = n.advertise
		args = stamped
	}
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

// AddPeer adds a bootstrap contact to the routing table (no synchronous
// network IO). The peer's public key is required because it determines the
// recipient_id used to sign any subsequent RPC to it. If the target bucket is
// already full, the §6.2 eviction check is merely SCHEDULED (async; see learn)
// — at bootstrap time tables are empty, so in practice this inserts directly.
func (n *Node) AddPeer(pk []byte, addr string) error {
	id, err := crypto.NodeID(pk)
	if err != nil {
		return err
	}
	c, err := NewNodeContact(id, pk, addr, n.now())
	if err != nil {
		return err
	}
	n.learn(c)
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
			envs  []*wire.SignedEnvelope // every envelope the peer offered (§7.4 `envelopes` + legacy `envelope`)
			nodes []*NodeContact
			err   error // probe failure (timeout/unreachable) — triggers eviction
		}
		results := make([]res, len(batch))
		var wg sync.WaitGroup
		for i, c := range batch {
			queried[string(c.NodeID)] = true
			wg.Add(1)
			go func(i int, c *NodeContact) {
				defer wg.Done()
				// Probe budget: an iterative-lookup candidate gets a shorter
				// deadline than a solicited single RPC (RPC_TIMEOUT = 5s). A
				// peer that cannot answer a tiny UDP get within 2s is
				// effectively unavailable; burning the full 5s per dead
				// candidate makes misses unboundedly slow (§6.4 GET latency).
				pctx, cancel := context.WithTimeout(ctx, lookupProbeTimeout)
				defer cancel()
				es, ns, err := n.getFromPeer(pctx, key, c)
				results[i] = res{es, ns, err}
			}(i, c)
		}
		wg.Wait()

		for i, r := range results {
			// Kademlia failure handling (§6.2): a contact that failed its
			// probe (timeout / unreachable / malformed address) is evicted
			// from the routing table so it is neither re-probed by later
			// lookups on this node nor advertised to others in {nodes} lists.
			// A parent-context cancellation is NOT a peer failure — never
			// evict for that.
			if r.err != nil && !errors.Is(r.err, context.Canceled) && ctx.Err() == nil {
				n.rt.Remove(batch[i].NodeID)
				n.log.Debug("dht: evicted unresponsive contact", "addr", batch[i].Addr, "err", r.err)
			}
			for _, nc := range r.nodes {
				n.learnContact(nc)
				if !contactIn(shortlist, nc.NodeID) {
					shortlist = append(shortlist, nc)
				}
			}
			for _, e := range r.envs {
				if e != nil && e.VerifySignature() {
					if bestEnv == nil || wire.EnvelopeWins(e, bestEnv) {
						bestEnv = e
					}
				}
			}
		}
	}
	return bestEnv, nil
}

// getFromPeer issues a single get(key) RPC to c and parses the response into
// the envelopes offered by the peer and/or the closer-contacts list. The
// offers are, best-first: the §7.4 `envelopes` extension (top-2 claim pool,
// see hGet) when present, then the legacy single `envelope` (the §6.4 store
// winner — a pool-carrying peer repeats it inside `envelopes`, deduplicated
// by callers via H_record / EnvelopeWins). The returned error signals probe
// failure (drives §6.2 eviction in IterativeGet); a y="e" response is a
// successful exchange and yields a nil error.
func (n *Node) getFromPeer(ctx context.Context, key []byte, c *NodeContact) ([]*wire.SignedEnvelope, []*NodeContact, error) {
	addr, err := net.ResolveUDPAddr("udp", c.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve: %w", err)
	}
	resp, err := n.sendQuery(ctx, addr, c.NodeID, "get", map[string]any{"key": key})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Y == wire.MsgTypeError {
		return nil, nil, nil
	}
	var envs []*wire.SignedEnvelope
	if raw, ok := resp.A["envelopes"].([]any); ok {
		for _, e := range raw {
			if eb, ok := e.([]byte); ok && len(eb) > 0 {
				if env, derr := wire.DecodeEnvelope(eb); derr == nil {
					envs = append(envs, env)
				}
			}
		}
	}
	if eb, ok := resp.A["envelope"].([]byte); ok && len(eb) > 0 {
		if env, derr := wire.DecodeEnvelope(eb); derr == nil {
			envs = append(envs, env)
		}
	}
	var nodes []*NodeContact
	if raw, ok := resp.A["nodes"]; ok {
		nodes = parseNodes(raw)
	}
	return envs, nodes, nil
}

// learnContact refreshes/inserts a contact discovered via find_node/get (a
// parsed node list, so LastSeen is stamped here). A full bucket schedules the
// async §6.2 eviction check (see learn).
func (n *Node) learnContact(c *NodeContact) {
	if c == nil || bytes.Equal(c.NodeID, n.id) {
		return
	}
	c.LastSeen = n.now()
	n.learn(c)
}

// Publish stores env on the R closest nodes to its key (§6.4 PUT), obtaining a
// write token from each first via a get. It is best-effort: it returns nil if at
// least one store accepted the envelope. With no peers known it returns
// ErrNoPeers (the record remains only in the local store).
//
// This is the §6.4 publish path; the resolver path uses IterativeGet (pull).
// The envelope is keyed at K_tld / K_name per KeyForWireName; to publish a
// claim envelope at K_claim use [Node.PublishClaim].
func (n *Node) Publish(ctx context.Context, env *wire.SignedEnvelope) error {
	if env == nil || env.Record == nil {
		return errors.New("dht: nil envelope")
	}
	key, err := KeyForWireName(env.Record.Name)
	if err != nil {
		return err
	}
	return n.publishKeyed(ctx, key, env)
}

// PublishClaim publishes the TLD-record envelope carrying an alias claim at
// K_claim = SHA-256(0x03 || "claim:" || alias) (§7.4 registration step 5 /
// Appendix C.1 step 4: "publishes at K_tld = tld_id AND the claim envelope at
// K_claim"). The alias is extracted by decoding the AliasClaim embedded in the
// record's field 11 (raw canonical CBOR), so the K_claim key and the claim are
// bound by construction.
//
// Per §7.4/C.1 the SAME envelope is ALSO published at K_tld by the ordinary
// [Node.Publish] — callers do both:
//
//	err := node.Publish(ctx, env)      // K_tld (the TLD record itself)
//	err = node.PublishClaim(ctx, env)  // K_claim (the claim pointer)
//
// Like Publish it talks to peers only (best-effort, ≥1 acceptance is success,
// ErrNoPeers with no peers); storing it in the local store is the caller's
// business (the daemon puts both).
func (n *Node) PublishClaim(ctx context.Context, env *wire.SignedEnvelope) error {
	if env == nil || env.Record == nil {
		return errors.New("dht: nil envelope")
	}
	claim, err := claims.DecodeAliasClaim(env.Record.Claim)
	if err != nil {
		return fmt.Errorf("dht: envelope carries no decodable alias claim (field 11): %w", err)
	}
	key, err := KeyForClaim(claim.Alias)
	if err != nil {
		return err
	}
	return n.publishKeyed(ctx, key, env)
}

// publishKeyed is the shared §6.4 PUT body of Publish and PublishClaim: locate
// the R closest nodes to key, obtain a write token from each (via get), and
// issue put. Best-effort — nil iff at least one peer accepted the envelope.
func (n *Node) publishKeyed(ctx context.Context, key []byte, env *wire.SignedEnvelope) error {
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

// ---------------------------------------------------------------------------
// Client-side witness collection (§7.4 registration steps 3-4)
// ---------------------------------------------------------------------------

// CollectWitnesses implements the claimant side of §7.4 registration step 3:
// "iteratively find the WITNESS_SET closest nodes to K_claim; send each a
// witness RPC with (prefix_hash, claimant_pk, timestamp)". It selects the
// count contacts of the routing table closest to K_claim (count <= 0 defaults
// to constants.WitnessSet = 8), sends the signed witness queries in parallel,
// and returns every attestation that (a) decodes, (b) verifies for the exact
// claim context (alias, tldID, claimantPK) per §7.3, and (c) was produced by
// the node it was fetched from (attestation NodeID == the queried contact's
// Node ID) — so a malicious peer cannot relay someone else's or a forged
// attestation. Results are deduplicated by NodeID.
//
// Errors from unreachable/refusing peers are swallowed (witness gathering is
// best-effort; the caller re-queries or proceeds when < W attestations come
// back). The returned slice may therefore be shorter than count — possibly
// empty; assembling ≥ W attestations (§7.3 quorum) is the caller's check.
func (n *Node) CollectWitnesses(ctx context.Context, alias string, tldID, claimantPK []byte, ts uint64, count int) ([]*claims.WitnessAttestation, error) {
	aliasN, err := naming.ValidateAlias(alias)
	if err != nil {
		return nil, err
	}
	if len(tldID) != constants.SHA256Len {
		return nil, fmt.Errorf("dht: tld_id must be %d bytes, got %d", constants.SHA256Len, len(tldID))
	}
	if len(claimantPK) != constants.Ed25519PublicKeyLen {
		return nil, fmt.Errorf("dht: claimant must be %d bytes, got %d", constants.Ed25519PublicKeyLen, len(claimantPK))
	}
	if count <= 0 {
		count = constants.WitnessSet // WITNESS_SET = 8 candidate witnesses (§7.3)
	}
	prefixHash, err := claimPrefixHash(aliasN, tldID, claimantPK, ts)
	if err != nil {
		return nil, err
	}
	kClaim, err := KeyForClaim(aliasN)
	if err != nil {
		return nil, err
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out []*claims.WitnessAttestation
	)
	for _, c := range n.rt.Closest(kClaim, count) {
		wg.Add(1)
		go func(c *NodeContact) {
			defer wg.Done()
			att := n.witnessFromPeer(ctx, c, aliasN, tldID, claimantPK, ts, prefixHash)
			if att == nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			out = append(out, att)
		}(c)
	}
	wg.Wait()

	// Deduplicate by NodeID (§7.3 counts DISTINCT witnesses).
	seen := make(map[string]bool, len(out))
	deduped := make([]*claims.WitnessAttestation, 0, len(out))
	for _, att := range out {
		k := string(att.NodeID)
		if seen[k] {
			continue
		}
		seen[k] = true
		deduped = append(deduped, att)
	}
	return deduped, nil
}

// witnessFromPeer issues one §6.3 witness RPC to c and returns the parsed,
// context-verified attestation (nil on any failure — see CollectWitnesses).
// The arguments carry the §6.3-documented deviation: alias and tld_id ride
// alongside claim_prefix_hash/claimant/ts because the attestation signature
// input (§7.3 lines 561-563) needs both.
func (n *Node) witnessFromPeer(ctx context.Context, c *NodeContact, alias string, tldID, claimantPK []byte, ts uint64, prefixHash []byte) *claims.WitnessAttestation {
	addr, err := net.ResolveUDPAddr("udp", c.Addr)
	if err != nil {
		return nil
	}
	resp, err := n.sendQuery(ctx, addr, c.NodeID, "witness", map[string]any{
		"alias":             alias,
		"tld_id":            tldID,
		"claimant":          claimantPK,
		"ts":                ts,
		"claim_prefix_hash": prefixHash,
	})
	if err != nil || resp == nil || resp.Y != wire.MsgTypeResponse {
		return nil
	}
	// Appendix A.4 ("Nodes gossip the current D in witness responses"):
	// record the advertised difficulty in the observed ring for
	// DHTLookup.NetworkDifficulty's median.
	if d, ok := asUint64(resp.A["difficulty"]); ok {
		n.diff.observe(int(d))
	}
	raw, _ := resp.A["attestation"].([]byte)
	if len(raw) == 0 {
		return nil
	}
	att, err := claims.DecodeWitnessAttestation(raw)
	if err != nil {
		return nil
	}
	// Verify against the claim context AND bind to the answering node.
	if !att.Verify(alias, tldID, claimantPK) {
		return nil
	}
	if !bytes.Equal(att.NodeID, c.NodeID) {
		return nil
	}
	return att
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
		"key":      key, // explicit target (hPut accepts derived or K_claim only)
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
// Background maintenance: §6.2 bucket refresh + §6.4 step 4 republish timer
// ---------------------------------------------------------------------------

// startBackground launches the background loops: the §6.2 live-eviction
// maintenance goroutine (always — full buckets can fill from inbound traffic
// alone), the §6.2 bucket refresh (unless disabled via
// NodeConfig.BucketRefreshInterval < 0), and the §6.4 step 4 republish timer
// (skipped for Passive nodes and when disabled via NodeConfig.RepublishInterval
// < 0). All loops share one context that Close cancels, and are tracked by bgWg
// so Close can wait for their exit.
func (n *Node) startBackground() {
	ctx, cancel := context.WithCancel(context.Background())
	n.bgCancel = cancel
	n.bgWg.Add(1)
	go n.evictionLoop(ctx)
	if n.refreshEvery > 0 {
		n.bgWg.Add(1)
		go n.bucketRefreshLoop(ctx)
	}
	if !n.passive && n.republishEvery > 0 {
		n.bgWg.Add(1)
		go n.republishLoop(ctx)
	}
}

// stopBackground cancels the background context (idempotently) and waits for
// every loop goroutine to return. In-flight sendQuery calls observe ctx
// cancellation immediately, so this returns well within an RPC timeout.
func (n *Node) stopBackground() {
	n.bgOnce.Do(func() {
		if n.bgCancel != nil {
			n.bgCancel()
		}
	})
	n.bgWg.Wait()
}

// bucketRefreshLoop periodically refreshes routing-table buckets whose entries
// have gone stale (§6.2, spec lines 410-424: buckets not looked up within
// BUCKET_REFRESH = 900s are refreshed by a lookup in their range, which both
// keeps old contacts alive and discovers new ones).
func (n *Node) bucketRefreshLoop(ctx context.Context) {
	defer n.bgWg.Done()
	t := time.NewTicker(n.refreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.refreshStaleBuckets(ctx)
		}
	}
}

// refreshStaleBuckets scans the routing table for buckets holding a contact
// whose LastSeen is older than the refresh period and, for each, performs a
// find_node round on a random target ID inside that bucket's prefix range.
// Responses both refresh the queried contacts (any verified inbound message
// refreshes the sender via learnPeer) and merge newly discovered contacts via
// learnContact — the same path an iterative GET uses.
func (n *Node) refreshStaleBuckets(ctx context.Context) {
	now := n.now()
	stale := make(map[int]bool)
	for _, c := range n.rt.AllContacts() {
		if time.Duration(now-c.LastSeen)*time.Second >= n.refreshEvery {
			if b, err := n.rt.BucketFor(c.NodeID); err == nil {
				stale[b.Index] = true
			}
		}
	}
	for idx := range stale {
		if ctx.Err() != nil {
			return
		}
		target := randomTargetInBucket(n.id, idx)
		// Query the K closest known contacts to the target in parallel; every
		// response refreshes its sender and may reveal new contacts.
		var wg sync.WaitGroup
		for _, c := range n.rt.Closest(target, constants.K) {
			wg.Add(1)
			go func(c *NodeContact) {
				defer wg.Done()
				n.findNodeFromPeer(ctx, target, c)
			}(c)
		}
		wg.Wait()
	}
}

// randomTargetInBucket returns a random 32-byte ID sharing exactly idx leading
// bits with selfID (bit idx differs, the rest are random) — i.e. an ID that
// lives in the routing-table bucket of index idx (bucket index == common
// prefix length, §6.2). idx is assumed in [0, 255].
func randomTargetInBucket(selfID []byte, idx int) []byte {
	t := make([]byte, constants.NodeIDLen)
	_, _ = rand.Read(t)
	copyBits := func(i int, val byte) {
		bit := byte(1) << (7 - uint(i)%8)
		if val != 0 {
			t[i/8] |= bit
		} else {
			t[i/8] &^= bit
		}
	}
	for i := 0; i < idx; i++ {
		copyBits(i, selfID[i/8]>>(7-uint(i)%8)&1)
	}
	// Bit idx must DIFFER from self so the common prefix is exactly idx.
	copyBits(idx, 1-(selfID[idx/8]>>(7-uint(idx)%8)&1))
	return t
}

// findNodeFromPeer issues a find_node(target) RPC to c (§6.3) and merges the
// returned node list into the routing table via learnContact. It returns the
// parsed contacts (useful for diagnostics). Errors are swallowed: a refresh
// round is best-effort and the next tick retries.
func (n *Node) findNodeFromPeer(ctx context.Context, target []byte, c *NodeContact) []*NodeContact {
	if ctx.Err() != nil {
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp", c.Addr)
	if err != nil {
		return nil
	}
	resp, err := n.sendQuery(ctx, addr, c.NodeID, "find_node", map[string]any{"target": target})
	if err != nil || resp == nil || resp.Y == wire.MsgTypeError {
		return nil
	}
	nodes := parseNodes(resp.A["nodes"])
	for _, nc := range nodes {
		n.learnContact(nc)
	}
	return nodes
}

// republishLoop periodically rescans the local store and re-publishes records
// past RefreshFraction of their lifetime (§6.4 PUT step 4, spec lines 471-473:
// "Stored records are republished by the owner at REFRESH_INTERVAL (80% of
// time-to-expiry)"). Any node holding a record — not just the owner — may act
// as a refresh helper, which keeps seeded records alive on the network. The
// loop is skipped for Passive nodes (§6.1: they do not volunteer others'
// records).
func (n *Node) republishLoop(ctx context.Context) {
	defer n.bgWg.Done()
	t := time.NewTicker(n.republishEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.republishDue(ctx)
		}
	}
}

// republishDue re-publishes every store entry past RefreshFraction (80%) of
// its lifetime — (now - Created) >= 0.8 * (Expires - Created) — to the R
// closest peers via the existing Publish path. Failures are logged at debug
// level and never fatal; the next tick retries. Nothing is re-put into the
// LOCAL store (the entry is already there; Publish only talks to peers).
func (n *Node) republishDue(ctx context.Context) {
	now := n.now()
	for _, e := range n.store.Entries(now) {
		if ctx.Err() != nil {
			return
		}
		r := e.Env.Record
		if r == nil {
			continue
		}
		lifetime := int64(r.Expires) - int64(r.Created)
		if lifetime <= 0 {
			continue
		}
		if float64(now-int64(r.Created)) < constants.RefreshFraction*float64(lifetime) {
			continue // not yet due
		}
		if err := n.Publish(ctx, e.Env); err != nil {
			n.log.Debug("dht: republish failed", "key", HexID(e.Key), "err", err)
		}
	}
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

	// fetchedAt records when THIS lookup last fetched each key from the
	// network (unix seconds). A key absent from the map is authoritative-
	// local (seeded via -load or published by this node) and is always
	// served without re-validation; a key present is a NETWORK CACHE entry
	// whose freshness window is the record's own TTL (§6.4 caching "subject
	// to expiry", in DNS-cache semantics — an update published elsewhere
	// propagates here within one record TTL instead of one record LIFETIME).
	fetchedAt map[[constants.SHA256Len]byte]int64
	mu        sync.Mutex
}

// NewDHTLookup wraps store (local) and node (network) into a RecordLookup.
func NewDHTLookup(store *EnvelopeStore, node *Node) *DHTLookup {
	return &DHTLookup{store: store, node: node, fetchedAt: make(map[[constants.SHA256Len]byte]int64)}
}

// cacheFreshness returns the re-validation window for env: the minimum RR TTL
// across its RRset (a delegation-only record with an empty RRset falls back to
// RecordDefaultTTL), capped at constants.ResponseTTLCap (1 h) so very long
// record TTLs cannot pin a stale cache for the record's whole lifetime.
func cacheFreshness(env *wire.SignedEnvelope) int64 {
	if env == nil || env.Record == nil || len(env.Record.RRset) == 0 {
		return int64(constants.RecordDefaultTTL)
	}
	min := int64(env.Record.RRset[0].TTL)
	for _, rr := range env.Record.RRset[1:] {
		if int64(rr.TTL) < min {
			min = int64(rr.TTL)
		}
	}
	if min < 1 {
		min = 1
	}
	if min > int64(constants.ResponseTTLCap) {
		min = int64(constants.ResponseTTLCap)
	}
	return min
}

// freshLocked reports whether the cached env under key is still fresh at now.
// Keys never fetched by this lookup (authoritative-local) are always fresh.
func (l *DHTLookup) freshLocked(key []byte, env *wire.SignedEnvelope, now int64) bool {
	var k [constants.SHA256Len]byte
	copy(k[:], key)
	fa, ok := l.fetchedAt[k]
	if !ok {
		return true
	}
	return now < fa+cacheFreshness(env)
}

// Lookup returns the winning SignedEnvelope for wireName: a fresh local hit
// first; a stale network-cached hit triggers re-validation via an iterative
// GET (on fetch failure the stale copy is served — offline resilience, the
// §6.4 grace analogue); a total miss fetches and caches. Returns (nil, nil)
// when no record is available locally or across the reachable network.
func (l *DHTLookup) Lookup(ctx context.Context, wireName []byte, now int64) (*wire.SignedEnvelope, error) {
	key, err := KeyForWireName(wireName)
	if err != nil {
		return nil, err
	}
	cached, _ := l.store.Get(key, now)
	l.mu.Lock()
	fresh := cached != nil && l.freshLocked(key, cached, now)
	l.mu.Unlock()
	if fresh {
		return cached, nil
	}
	if l.node == nil {
		return cached, nil // island: serve the stale cache or nil
	}
	c, cancel := context.WithTimeout(ctx, dhtLookupTimeout)
	defer cancel()
	env, err := l.node.IterativeGet(c, key)
	if err != nil || env == nil {
		// Fetch failure or a network-wide miss: fall back to the stale cache
		// (better a still-valid-signature stale record than NXDOMAIN).
		return cached, nil
	}
	// Cache the fetched envelope locally (verifySignature=true defensively
	// re-checks the signature before storing) and stamp its fetch time.
	_, _ = l.store.Put(key, env, now, true)
	l.mu.Lock()
	var k [constants.SHA256Len]byte
	copy(k[:], key)
	l.fetchedAt[k] = now
	l.mu.Unlock()
	return env, nil
}

// FetchMetaJSON serializes the fetched-keys metadata (key hex → fetchedAt unix
// seconds) so a daemon can persist WHICH envelopes are network caches (vs
// authoritative-local seeds) across restarts — without it, a restart launders
// every cached envelope into an always-fresh authoritative copy.
func (l *DHTLookup) FetchMetaJSON() ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]int64, len(l.fetchedAt))
	for k, v := range l.fetchedAt {
		out[hex.EncodeToString(k[:])] = v
	}
	if len(out) == 0 {
		return []byte("{}"), nil
	}
	return json.Marshal(out)
}

// LoadFetchMetaJSON restores fetched-keys metadata written by FetchMetaJSON.
// Malformed entries are skipped.
func (l *DHTLookup) LoadFetchMetaJSON(data []byte) error {
	var m map[string]int64
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for kh, v := range m {
		k, err := hex.DecodeString(kh)
		if err != nil || len(k) != constants.SHA256Len {
			continue
		}
		var key [constants.SHA256Len]byte
		copy(key[:], k)
		l.fetchedAt[key] = v
	}
	return nil
}

// LookupClaim returns the SignedEnvelope stored at K_claim for alias — the
// §7.4/C.1 claim pointer: the TLD-record envelope whose field 11 carries the
// AliasClaim. It mirrors [DHTLookup.Lookup] for the claim key space: local
// store first, then an iterative network GET, caching on success so subsequent
// lookups are local. Returns (nil, nil) when no claim envelope is available
// locally or across the reachable network.
//
// This structurally satisfies the resolver's optional ClaimResolver interface
// (§9.2 step 3a network alias resolution); no import of internal/resolver is
// needed (or possible — it would cycle).
func (l *DHTLookup) LookupClaim(ctx context.Context, alias string, now int64) (*wire.SignedEnvelope, error) {
	key, err := KeyForClaim(alias)
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
	// Cache the fetched claim envelope locally (§6.4 "nodes along the lookup
	// path MAY cache"; verifySignature=true defensively re-checks it).
	_, _ = l.store.Put(key, env, now, true)
	return env, nil
}

// ---------------------------------------------------------------------------
// Per-source-IP read throttling (§12 line 914; §10.2)
// ---------------------------------------------------------------------------

// allowRead consumes one read-RPC token for the observed source of raddr, per
// §12 line 914. Keyed on normIP(raddr.IP) — the same canonical observed-source
// binding the write-token defense uses (§6.3), so a flooder cannot rotate
// ports to dodge it and a spoofer cannot pre-fill someone else's bucket.
// Always true when throttling is disabled (nil limiter).
func (n *Node) allowRead(raddr *net.UDPAddr) bool {
	if n.getLim == nil {
		return true
	}
	return n.getLim.allow(normIP(raddr.IP))
}

// rateLimiter is a mutex-guarded map of token buckets keyed by source IP:
// each key holds `burst` tokens, refilled at `rate` per second; a query costs
// one. State is tiny (two fields/IP) and lazily expired: once the map exceeds
// limiterMaxEntries, entries unused for limiterIdle are swept (reaching the
// cap requires 10k distinct SIGNED sources, i.e. sustained abuse — and if all
// entries are somehow recent, new keys are still admitted rather than letting
// an attacker lock honest IPs out of the map).
type rateLimiter struct {
	rate    float64 // tokens/second
	burst   float64 // bucket capacity
	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time // last allow() attempt, drives the idle sweep
}

func newRateLimiter(rate float64, burst int) *rateLimiter {
	return &rateLimiter{
		rate:    rate,
		burst:   float64(burst),
		buckets: make(map[string]*tokenBucket),
	}
}

// allow reports whether one request from key fits the bucket, refilling it
// lazily from the elapsed time since the previous request.
func (l *rateLimiter) allow(key []byte) bool {
	k := string(key)
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[k]
	if !ok {
		if len(l.buckets) >= limiterMaxEntries {
			l.sweepIdleLocked(now)
		}
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[k] = b
	}
	if dt := now.Sub(b.last); dt > 0 {
		b.tokens = min(l.burst, b.tokens+dt.Seconds()*l.rate)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// sweepIdleLocked drops entries no request has touched within limiterIdle.
// Caller must hold l.mu.
func (l *rateLimiter) sweepIdleLocked(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.last) > limiterIdle {
			delete(l.buckets, k)
		}
	}
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
