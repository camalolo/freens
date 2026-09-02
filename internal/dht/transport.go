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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/turn"
	"github.com/camalolo/freens/internal/wire"
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

// defaultContactIdleTTL is the anti-ghost sweep horizon (issue #2): a
// contact with no DIRECT exchange for this long is evicted, no matter how
// enthusiastically peers re-advertise it. One-shot CLI nodes (ephemeral
// ports), crashed daemons and stale port-forwards all converge to evicted
// within one TTL; healthy meshes confirm constantly (republish traffic,
// bucket refreshes) and never approach it.
const defaultContactIdleTTL = time.Hour

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

// Default per-source-IP put throttle (v0.7.1). A put is the most expensive
// unauthenticated-CPU work a peer can induce (envelope decode + signature +
// PoW + up to maxWitnessEvaluations witness verifies per packet, inline on
// the readLoop goroutine), and its only authorization gate — the write
// token — is minted freely by every ping/get response, so token possession
// bounds nothing. 10 puts/s per source with a burst of 20 is ~2 orders of
// magnitude above honest publication traffic (republish waves land at a few
// puts per source per 60 s scan) while capping one source's store-CPU
// share; excess puts are answered with error 301 "throttled" like reads
// (explicit backpressure beats silence).
const (
	defaultPutRateLimit = 10.0 // req/s per source IP
	defaultPutBurst     = 20   // back-to-back puts per idle source
)

// Default GLOBAL inbound packet budget (v0.9.2). The per-source-IP buckets
// above bound one source's share, but a botnet (or a spoofed-source flood)
// draws a fresh bucket per IP, so they cannot bound the aggregate. Everything
// inbound — decode (canonical-CBOR parse of up to 64 KiB) and the Ed25519
// verify in handle — runs on the single readLoop goroutine, and an invalid
// signature costs the SAME verify as a valid one: a well-formed-CBOR,
// garbage-signature flood pins one core at ~1000 verifies/s without the
// budget. 1000 packets/s burst 2000 is ~2 orders of magnitude above honest
// fleet traffic (a 7-node mesh idles under 10 pps; republish waves land at a
// few pps per node) while capping the pre-auth CPU at roughly one core-tenth
// of verify work. Excess packets drop silently in handle() BEFORE decode —
// the kernel's 1 MiB socket buffer already sheds the rest.
const (
	defaultPacketRateLimit = 1000.0 // packets/s across ALL sources
	defaultPacketBurst     = 2000   // back-to-back packets after idle
)

// defaultWalkConcurrency bounds simultaneously in-flight OUTBOUND iterative
// walks (v0.9.2). Every distinct inbound DNS/DHT question fans out into a
// walk of up to dhtLookupTimeout (6 s) issuing rounds × ≤K probes — a
// distinct-name query flood is a work-AMPLIFICATION attack that the inbound
// packet budget cannot see (each question is one cheap packet). 64 concurrent
// walks is far above honest resolver traffic (single-flight already collapses
// identical questions; the LAN fleet resolves a handful of distinct names per
// second) while capping the outbound probe fan-out at 64 × K RPCs.
const defaultWalkConcurrency = 64

// evictQueueCap bounds the pending §6.2 live-eviction requests. Combined with
// the per-bucket coalescing (evictPending) it guarantees the maintenance path
// can never accumulate unbounded work under a contact flood.
const evictQueueCap = 64

// Peer is a bootstrap peer: a UDP address plus the peer's 32-byte node public
// key (required because recipient_id is part of every message signature, so a
// node can only send a signed RPC to a peer whose key it knows). Confirmed
// carries the peerbook's last-direct-exchange timestamp across restarts
// (issue #2 probation continuity; 0 = unknown/legacy entry).
type Peer struct {
	Addr      string // "ip:port"
	PublicKey []byte // 32-byte Ed25519 node public key
	Confirmed int64  // unix seconds; 0 = never/unknown

	// Alts carries the node's other known addresses (multi-homed contacts,
	// 2026-09-01): a seed holding its public IP while sitting on the LAN is
	// reachable at both, and surfaces should show that instead of one
	// flip-flopping address.
	Alts []AddrState
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
	// ContactIdleTTL bounds how long a contact survives without a DIRECT
	// exchange (advertisement re-teaching does not count — issue #2).
	// Zero ⇒ the default (1 h); negative ⇒ the idle sweep is disabled.
	ContactIdleTTL time.Duration
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
	// PutRateLimit caps put requests per observed source IP (token bucket,
	// requests/second). See defaultPutRateLimit for the rationale: a put is
	// the costliest CPU work a peer can induce and the write token gates
	// authorization, not rate. Zero ⇒ 10. Negative disables put throttling.
	// Excess puts are answered with error 301 "throttled".
	PutRateLimit float64
	// PutBurst is the token-bucket burst paired with PutRateLimit. Zero ⇒ 20.
	// Ignored when PutRateLimit < 0.
	PutBurst int
	// PacketRateLimit caps INBOUND packets per second across ALL sources (a
	// single global token bucket, checked in handle BEFORE the canonical-CBOR
	// decode and the Ed25519 signature verify — both run on the one readLoop
	// goroutine, and an invalid signature costs the same verify as a valid
	// one, so a distributed well-formed-garbage flood pins the core without
	// this budget; the per-source-IP buckets above cannot bound the aggregate
	// because every distinct/spoofed source draws a fresh bucket). Zero ⇒
	// 1000. Negative disables the global budget. Excess packets are dropped
	// silently (never answered — answering an unverified source would aid
	// amplification; a busy error is itself a response).
	PacketRateLimit float64
	// PacketBurst is the token-bucket burst paired with PacketRateLimit (the
	// number of packets the node accepts back-to-back after an idle period).
	// Zero ⇒ 2000. Ignored when PacketRateLimit < 0.
	PacketBurst int
	// WalkConcurrency bounds simultaneously in-flight outbound iterative
	// walks (IterativeGet / CollectClaims / evidence lookups). It is the
	// work-amplification cap: every distinct inbound question can spawn a
	// multi-second walk fanning out rounds × ALPHA probes, so a distinct-name
	// flood must not be able to open unbounded walks. A walk that cannot
	// acquire a slot fails immediately with ErrWalkBusy (never queues —
	// queueing would pile up goroutines, and ErrWalkBusy maps to SERVFAIL
	// upstream, which is never cached, so honest clients transparently
	// retry). Zero ⇒ 64. Negative disables the cap. IterativeFindNode (the
	// registration client's table-population walk) is NOT gated: it is
	// self-initiated, not remotely triggerable.
	WalkConcurrency int
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
	// Stun is a STUN server "host:port" (RFC 5389 Binding; e.g.
	// "stun.example.net:3478") used to discover this node's
	// server-reflexive public address, which is then advertised to peers
	// exactly like Advertise (§6.2). Refreshed periodically so address
	// changes are picked up. Empty ⇒ off. Ignored when Advertise is set
	// (an explicit address always wins over a discovered one).
	Stun string
	// TurnRelay is a freens TURN server "host:port" (RFC 8656 subset, internal/turn).
	// When set (and Advertise empty), the node allocates a relayed address on that
	// server, routes ALL peer UDP through the allocation, and advertises the
	// RELAYED address to peers (§6.2) — for symmetric-NAT nodes no dialable
	// address exists otherwise. Precedence: Advertise > TurnRelay > Stun, with
	// graceful fallback to direct UDP when the allocation fails (warn log).
	TurnRelay string
	// TurnServer, when non-nil, runs a TURN server alongside the node: nodes with
	// spare bandwidth relay for the network (community relay tier). Auth is
	// freens-native (node-key signatures, internal/turn docs); the socket also
	// answers STUN Binding, so it doubles as a -stun target.
	TurnServer *turn.ServerConfig
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
	conn           net.PacketConn
	closed         atomic.Bool
	passive        bool
	refreshEvery   time.Duration // resolved: >0 = run refresh loop
	republishEvery time.Duration // resolved: >0 = run republish loop
	contactIdleTTL time.Duration // resolved: >0 = run the idle sweep
	pingTimeout    time.Duration // resolved: §6.2 eviction-ping deadline
	bgCancel       context.CancelFunc
	bgOnce         sync.Once
	bgWg           sync.WaitGroup

	store   *EnvelopeStore
	rt      *RoutingTable
	tokens  *TokenStore
	claims  *ClaimPool       // §7.4 "storing nodes keep the top 2 by ordering" (claims_pool.go)
	diff    *difficultyState // Appendix A.4 own difficulty + observed ring (gossip.go)
	getLim  *rateLimiter     // per-source-IP get/find_node throttle (§12); nil = off
	putLim  *rateLimiter     // per-source-IP put throttle (see defaultPutRateLimit); nil = off
	pktLim  *packetBudget    // GLOBAL pre-verify inbound packet budget; nil = off
	walkSem chan struct{}    // outbound walk concurrency cap (nil = uncapped)
	log     *slog.Logger
	nowFn   func() int64

	// advertise is the validated §6.2 advertised address ("" ⇒ peers learn
	// the observed source). Parsed from NodeConfig.Advertise once at Start;
	// written before any goroutine reads it — EXCEPT by the STUN monitor
	// (stun_loop.go), which may update it at runtime under advMu. All
	// runtime READS go through advertised(); all runtime WRITES through
	// setAdvertise().
	advertise string
	// advMu guards advertise across the readLoop/sendQuery goroutines and
	// the STUN monitor's runtime updates.
	advMu sync.RWMutex

	// stun is the raw NodeConfig.Stun server address ("" ⇒ no monitor).
	stun string

	// TURN wiring (see Start steps (b)/(d)): turnRelay is the raw
	// NodeConfig.TurnRelay server address ("" ⇒ client relay off);
	// turnSrvCfg is the NodeConfig.TurnServer config (nil ⇒ no co-located
	// server). turnServer is the running server handle once ListenTURN
	// succeeded at Start (nil otherwise; read via TURNServer). turnConn is
	// the active allocation in relay mode (nil in direct mode — including
	// the graceful fallback). relayed mirrors turnConn != nil atomically so
	// RelayedMode is race-free from any goroutine.
	turnRelay  string
	turnSrvCfg *turn.ServerConfig
	turnServer *turn.Server
	turnConn   *turn.Conn
	relayed    atomic.Bool

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

	// deadUntil implements the walk-level dead-peer penalty (issue #1):
	// node ID → unix time until which the contact is skipped as a LOOKUP
	// candidate. Set when a lookup probe fails; expires after
	// deadPenaltyWindow. The routing table's own eviction (§6.2) remains
	// the source of truth for table membership — the penalty only stops
	// repeated walks from re-probing corpses that live peers keep
	// re-advertising in {nodes} lists during churn.
	penaltyMu sync.Mutex
	deadUntil map[string]int64

	mu      sync.Mutex
	pending map[string]chan *wire.Message
}

// deadPenaltyWindow is how long a probe-failed contact is skipped as a
// lookup candidate before it may be probed again (it may have come back —
// reboots, crash loops). Short enough to re-admit recovering nodes within
// a walk-minute, long enough that a churn window does not burn a 2 s probe
// budget on the same corpse per query (field-observed: minute-long dig
// timeouts while 3/7 nodes were down).
const deadPenaltyWindow = 30 * time.Second

// markDead records the dead-peer penalty for id (now + window).
func (n *Node) markDead(id []byte, now int64) {
	n.penaltyMu.Lock()
	defer n.penaltyMu.Unlock()
	if n.deadUntil == nil {
		return
	}
	n.deadUntil[string(id)] = now + int64(deadPenaltyWindow/time.Second)
}

// penalized reports whether id is inside its dead-peer penalty window.
func (n *Node) penalized(id []byte, now int64) bool {
	n.penaltyMu.Lock()
	defer n.penaltyMu.Unlock()
	until, ok := n.deadUntil[string(id)]
	return ok && now < until
}

// LookupStats reports what one iterative lookup did (issue #1
// observability + the degraded-miss classification).
type LookupStats struct {
	ProbesSent      int      // candidate probes issued
	ProbesFailed    int      // probes that errored (timeout / unreachable / malformed)
	ProbesThrottled int      // probes answered with §12 error 301 "throttled" (peer alive, rate-limited)
	ProbedNodeIDs   [][]byte // IDs probed, in order (penalized contacts excluded)
}

// ErrDegradedMiss reports a lookup that found nothing while some probes
// failed: the network could not be interrogated fully, so the miss is NOT
// authoritative. Callers must treat it as "try again soon" (SERVFAIL /
// uncached) rather than "does not exist" (NXDOMAIN / negative-cached) —
// field-churn showed 60 s NXDOMAIN windows for names whose holders were
// alive the whole time (issue #1).
var ErrDegradedMiss = errors.New("dht: degraded miss (probe failures; the network could not be fully interrogated)")

// ErrWalkBusy reports an iterative walk REFUSED because the node's outbound
// walk budget (NodeConfig.WalkConcurrency) is exhausted — the work-
// amplification cap against distinct-name query floods. Semantically it is
// "overloaded, retry", exactly like ErrDegradedMiss: the resolver maps it to
// SERVFAIL (never NXDOMAIN, never cached), and DHTLookup serves a stale
// cached envelope where it has one. Residual, documented: the §8.4 evidence
// fetch inside the resolver's chain verification folds fetch errors into a
// boolean, so an ErrWalkBusy there degrades to an ordinary verification
// failure (NXDOMAIN) rather than SERVFAIL — reachable only for recovery-root
// names while simultaneously walk-saturated; the resolver-level resolution
// cap rejects most overload before that walk starts.
var ErrWalkBusy = errors.New("dht: walk budget exhausted (too many concurrent iterative walks)")

// acquireWalk reports whether a caller may start an outbound iterative walk
// (non-blocking: a saturated budget fails immediately rather than queueing —
// queueing would pile one goroutine per waiting query onto the flood).
func (n *Node) acquireWalk() bool {
	if n.walkSem == nil {
		return true
	}
	select {
	case n.walkSem <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseWalk returns one walk slot. No-op when the cap is disabled.
func (n *Node) releaseWalk() {
	if n.walkSem == nil {
		return
	}
	<-n.walkSem
}

// ErrThrottled reports a get probe that was answered with the §12 rate-limit
// error 301 "throttled": the peer is ALIVE but refused to serve the answer
// (get-rate bucket exhausted). It is NOT a probe failure — the contact must
// not be evicted or penalized — but the answer ("held" or "not held") was
// never obtained, so a lookup that found nothing while throttled is a
// degraded miss, not an authoritative one (found live while profiling: a
// client bursting past the 50/s bucket got clean-miss NXDOMAINs that
// negative-cached, exactly the failure mode issue #1 built ErrDegradedMiss
// to prevent).
var ErrThrottled = errors.New("dht: peer throttled get (§12 rate limit)")

// witnessSigned records one witnessed claim for the WITNESS_COOLDOWN check:
// the SHA-256 of the claim's §7.3 PoW prefix (which binds alias, tld_id,
// timestamp, and claimant_pk — two different claims for the same alias never
// share it), the claimant's public key, and the unix second the node signed.
type witnessSigned struct {
	prefixHash []byte
	claimant   []byte
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
	contactIdleTTL := cfg.ContactIdleTTL
	if contactIdleTTL == 0 {
		contactIdleTTL = defaultContactIdleTTL
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
	// Per-source-IP put throttle: negative rate ⇒ disabled.
	var putLim *rateLimiter
	if cfg.PutRateLimit >= 0 {
		rate := cfg.PutRateLimit
		if rate == 0 {
			rate = defaultPutRateLimit
		}
		burst := cfg.PutBurst
		if burst <= 0 {
			burst = defaultPutBurst
		}
		putLim = newRateLimiter(rate, burst)
	}
	// Global pre-verify packet budget: negative rate ⇒ disabled.
	var pktLim *packetBudget
	if cfg.PacketRateLimit >= 0 {
		rate := cfg.PacketRateLimit
		if rate == 0 {
			rate = defaultPacketRateLimit
		}
		burst := cfg.PacketBurst
		if burst <= 0 {
			burst = defaultPacketBurst
		}
		pktLim = newPacketBudget(rate, burst)
	}
	// Outbound walk concurrency cap: negative ⇒ uncapped (nil channel).
	var walkSem chan struct{}
	if cfg.WalkConcurrency >= 0 {
		cap := cfg.WalkConcurrency
		if cap == 0 {
			cap = defaultWalkConcurrency
		}
		walkSem = make(chan struct{}, cap)
	}
	return &Node{
		kp:             cfg.Keypair,
		id:             id,
		listenAddr:     cfg.ListenAddr,
		passive:        cfg.Passive,
		refreshEvery:   refreshEvery,
		republishEvery: republishEvery,
		contactIdleTTL: contactIdleTTL,
		pingTimeout:    pingTimeout,
		store:          cfg.Store,
		rt:             rt,
		tokens:         tokens,
		claims:         NewClaimPool(),
		diff:           newDifficultyState(now()),
		getLim:         getLim,
		putLim:         putLim,
		pktLim:         pktLim,
		walkSem:        walkSem,
		log:            log,
		nowFn:          now,
		advertise:      cfg.Advertise,
		stun:           cfg.Stun,
		turnRelay:      cfg.TurnRelay,
		turnSrvCfg:     cfg.TurnServer,
		evictCh:        make(chan *NodeContact, evictQueueCap),
		evictPending:   make(map[int]bool),
		witnessLast:    make(map[string]witnessSigned),
		deadUntil:      make(map[string]int64),
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

// TURNServer returns the co-located TURN server started from
// NodeConfig.TurnServer, or nil when none is running — the daemon's
// freens_turn_allocations gauge guards on this.
func (n *Node) TURNServer() *turn.Server { return n.turnServer }

// RelayedMode reports whether this node's transport currently routes peer
// UDP through a TURN allocation (the NodeConfig.TurnRelay dial succeeded at
// Start): every datagram flows via the relayed address, which is also the
// address advertised to peers. False in direct-UDP mode, including the
// graceful fallback when the allocation failed.
func (n *Node) RelayedMode() bool { return n.relayed.Load() }

// advertised returns the current §6.2 advertised address ("" ⇒ observed
// source). Safe for concurrent use; the STUN monitor may change it at runtime.
func (n *Node) advertised() string {
	n.advMu.RLock()
	defer n.advMu.RUnlock()
	return n.advertise
}

// setAdvertise atomically replaces the advertised address (used by the STUN
// monitor after a successful reflexive-address discovery).
func (n *Node) setAdvertise(a string) {
	n.advMu.Lock()
	n.advertise = a
	n.advMu.Unlock()
}

// validateAdvertise canonicalizes an advertised address exactly as Start
// does: resolvable host:port with a concrete IP and non-zero port. The empty
// string passes through (observed-source mode).
func validateAdvertise(addr string) (string, error) {
	if addr == "" {
		return "", nil
	}
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil || a.IP == nil || a.Port == 0 {
		return "", fmt.Errorf("dht: invalid advertise address %q (want resolvable host:port)", addr)
	}
	return a.String(), nil
}

// UpdateAdvertise replaces the §6.2 advertised address at RUNTIME (after
// Start): peers learn the new address from the stamp on this node's next
// outbound query, no restart needed. The UPnP renewal loop and the STUN
// monitor are the callers. An empty address returns to observed-source
// mode; an invalid one is rejected without changing anything.
func (n *Node) UpdateAdvertise(addr string) error {
	canonical, err := validateAdvertise(addr)
	if err != nil {
		return err
	}
	n.setAdvertise(canonical)
	return nil
}

// Advertised returns the current §6.2 advertised address ("" ⇒ observed
// source) — the exported, race-safe view for daemons, orchestrators, and
// tests (the hostname re-resolve monitor of advertise_resolve.go is
// observed through it).
func (n *Node) Advertised() string { return n.advertised() }

// Start binds the UDP socket and launches the read loop and the background
// maintenance loops (§6.2 bucket refresh; §6.4 step 4 republish timer unless
// Passive). In relay mode (NodeConfig.TurnRelay set, Advertise empty) it
// first allocates a TURN relayed address and REPLACES the direct socket with
// the tunnel; the STUN monitor then no-ops naturally (an address is already
// advertised). With NodeConfig.TurnServer set it finally starts the
// co-located TURN server. It returns once the socket is bound (and the
// allocation, if any, is active); the loops run until Close.
func (n *Node) Start() error {
	// §6.2 advertised address: validate ONCE here. A non-resolvable
	// host:port (or a missing host/port) logs a warning and falls back to
	// the observed-source behavior — a bad Advertise must not brick the node.
	if canonical, verr := validateAdvertise(n.advertise); verr != nil {
		n.log.Warn("dht: invalid Advertise address (want resolvable host:port); "+
			"peers will learn the observed source address", "advertise", n.advertise)
		n.advertise = ""
	} else {
		n.advertise = canonical
	}
	// (a) Direct UDP bind. The socket is ALWAYS the node's own; in relay
	// mode (step b) the tunnel replaces it — peers then reach this node
	// only at its relayed address.
	addr, err := net.ResolveUDPAddr("udp", n.listenAddr)
	if err != nil {
		return fmt.Errorf("dht: resolve %q: %w", n.listenAddr, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("dht: listen %q: %w", n.listenAddr, err)
	}
	n.conn = conn
	// Reasonable socket buffers for bursty small DHT datagrams. The field is
	// typed net.PacketConn so it can hold a tunneled (TURN-relayed) conn in
	// relay mode; kernel buffer knobs only exist on a real *net.UDPConn, so
	// the assertion doubles as the guard — tunneled conns skip it. (On THIS
	// path conn is always the direct UDP socket; the swap happens below.)
	if u, ok := n.conn.(*net.UDPConn); ok {
		_ = u.SetReadBuffer(1 << 20)
		_ = u.SetWriteBuffer(1 << 20)
	}

	// (b) TURN client relay (§6.2 dialable address via the RFC 8656 subset
	// in internal/turn): with no explicit Advertise, allocate a relayed
	// address and route ALL peer UDP through the allocation — for a
	// symmetric-NAT node no dialable address exists otherwise. Precedence:
	// Advertise > TurnRelay > Stun. An unreachable relay degrades to direct
	// UDP + observed source (warn; never fail Start). The refresh loop for
	// the allocation lives INSIDE turn.Conn (its Close deallocates); none of
	// this runs on a bgWg-tracked goroutine, so Close ordering is safe.
	if n.turnRelay != "" && n.advertised() == "" {
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		tc, derr := (&turn.Client{Server: n.turnRelay, NodeKey: n.kp, Log: n.log}).Dial(dctx)
		dcancel()
		switch {
		case derr != nil:
			n.log.Warn("dht: TURN relay allocation failed; falling back to direct UDP + observed source",
				"relay", n.turnRelay, "err", derr)
		case tc.RelayedAddr() == nil:
			// Defensive: an allocation without a relayed address is useless.
			n.log.Warn("dht: TURN relay returned no relayed address; falling back to direct UDP + observed source",
				"relay", n.turnRelay)
			_ = tc.Close()
		default:
			relayed := tc.RelayedAddr()
			_ = conn.Close() // the direct socket is replaced by the tunnel
			n.conn = turnPacketConn{tc}
			n.turnConn = tc
			n.relayed.Store(true)
			n.setAdvertise(relayed.String())
			n.log.Info("dht: TURN relay active; routing peer UDP via allocation",
				"relay", n.turnRelay, "relayed", relayed.String())
		}
	} else if n.turnRelay != "" {
		n.log.Info("dht: explicit Advertise set; TURN relay disabled (explicit address wins)",
			"advertise", n.advertised(), "relay", n.turnRelay)
	}

	n.startBackground()
	// (c) STUN AFTER the relay attempt: in relay mode an address (the
	// relayed one) is already advertised, so startSTUN's existing
	// no-op-when-advertised check skips the monitor naturally; when the
	// allocation failed the direct socket survived and STUN remains the
	// discovery fallback.
	n.startSTUN()
	go n.readLoop()

	// (d) Co-located TURN server (community relay tier): nodes with spare
	// bandwidth relay for the network. A listen failure fails Start — the
	// operator explicitly requested a server, and a silently missing one is
	// an outage — after tearing down what already started above.
	if n.turnSrvCfg != nil {
		srv, serr := turn.ListenTURN(*n.turnSrvCfg)
		if serr != nil {
			n.stopBackground()
			n.closed.Store(true)
			_ = n.conn.Close()
			return fmt.Errorf("dht: TURN server listen %q: %w", n.turnSrvCfg.ListenAddr, serr)
		}
		n.turnServer = srv
		if a, aerr := srv.Addr(); aerr == nil {
			n.log.Info("dht: TURN server listening (community relay tier; socket also answers STUN Binding)",
				"addr", a.String())
		}
	}
	return nil
}

// Close stops the background loops (blocking until they have exited — their
// in-flight RPCs return promptly via context cancellation, so no goroutines
// leak), stops the read loop, closes the transport socket (in relay mode
// this deallocates the TURN allocation via turn.Conn.Close) and the
// co-located TURN server. The TURN server closes FIRST so relaying peers
// observe the shutdown before the node's own transport does. Pending
// sendQuery callers will time out normally.
func (n *Node) Close() error {
	n.stopBackground()
	n.closed.Store(true)
	var errs []error
	if n.turnServer != nil {
		if err := n.turnServer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if n.conn != nil {
		if err := n.conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// turnPacketConn adapts a *turn.Conn (the pinned internal/turn client API:
// ReadFrom/WriteTo/LocalAddr/Close/SetDeadline) to the net.PacketConn that
// Node.conn requires. The two per-direction deadline setters have no turn
// counterpart and both map to SetDeadline; nothing in the dht transport
// sets deadlines on n.conn, so the collapsing is unobservable here.
type turnPacketConn struct{ c *turn.Conn }

func (t turnPacketConn) ReadFrom(p []byte) (int, net.Addr, error)  { return t.c.ReadFrom(p) }
func (t turnPacketConn) WriteTo(p []byte, a net.Addr) (int, error) { return t.c.WriteTo(p, a) }
func (t turnPacketConn) LocalAddr() net.Addr                       { return t.c.LocalAddr() }
func (t turnPacketConn) Close() error                              { return t.c.Close() }
func (t turnPacketConn) SetDeadline(tm time.Time) error            { return t.c.SetDeadline(tm) }
func (t turnPacketConn) SetReadDeadline(tm time.Time) error        { return t.c.SetDeadline(tm) }
func (t turnPacketConn) SetWriteDeadline(tm time.Time) error       { return t.c.SetDeadline(tm) }

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
		nread, raddr, err := n.conn.ReadFrom(buf)
		if err != nil {
			if n.closed.Load() {
				return
			}
			n.log.Debug("dht: read error", "err", err)
			continue
		}
		// Copy out of the read buffer (the next ReadFrom overwrites it).
		pkt := make([]byte, nread)
		copy(pkt, buf[:nread])
		// Narrow the interface-typed remote address; a non-UDP-shaped one
		// (nil — see asUDP) is dropped: the §6.3 handlers key on the UDP
		// observed source and have nothing to act on without it.
		if u := asUDP(raddr); u != nil {
			n.handle(pkt, u)
		}
	}
}

// asUDP narrows a read-loop remote address to *net.UDPAddr, keeping the
// inbound handlers (handle/learnPeer/token binding) on the concrete UDP
// address type. The direct socket always yields *net.UDPAddr; a tunneled
// (TURN-relayed, relay mode) conn reports whatever net.Addr its ReadFrom
// returns — normally also *net.UDPAddr (peers dial the relayed address over
// UDP). Any other address type is recovered from its "ip:port" string form,
// and a nil is returned when even that fails, in which case readLoop drops
// the datagram (nothing downstream can address it).
func asUDP(a net.Addr) *net.UDPAddr {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v
	case nil:
		return nil
	default:
		u, err := net.ResolveUDPAddr("udp", v.String())
		if err != nil {
			return nil
		}
		return u
	}
}

// handle decodes, verifies, and routes one inbound datagram. Malformed or
// unverified messages are dropped silently (never answered — answering an
// unverified source would aid amplification).
//
// Cost-ordering (v0.9.2 DoS hardening): each step is only reached if the
// cheaper ones passed, so an attacker pays for the expensive work only after
// paying for — and being bounded by — the cheap gates:
//
//  1. GLOBAL packet budget (pktLim): one token per datagram across ALL
//     sources, consumed BEFORE anything else. The per-source-IP buckets
//     cannot bound a distributed flood (every distinct or spoofed source
//     draws a fresh bucket); this does. Excess drops here, pre-decode.
//  2. Canonical-CBOR decode + structural validate (DecodeMessage), which
//     includes the id == SHA-256(pk) identity check — a forged-ID message
//     dies at one hash, not one verify.
//  3. Stray-response filter: a y="r"/"e" message whose txid matches no
//     pending outbound query (sendQuery registers the txid BEFORE the query
//     leaves, so a legitimate reply always finds its entry) is dropped
//     WITHOUT the Ed25519 verify — response-flood traffic costs one map
//     lookup instead of one signature check. The check is a filter, not the
//     authoritative routing (deliver re-looks-up under n.mu; a benign race
//     with a just-timed-out sendQuery drops a reply nobody waits for).
//  4. Ed25519 verify — the expensive step — now only for messages that
//     cleared 1-3.
func (n *Node) handle(data []byte, raddr *net.UDPAddr) {
	if n.pktLim != nil && !n.pktLim.allow() {
		return // global budget exhausted: cheapest possible drop
	}
	m, err := wire.DecodeMessage(data)
	if err != nil {
		return
	}
	if (m.Y == wire.MsgTypeResponse || m.Y == wire.MsgTypeError) && !n.hasPending(m.T) {
		return // stray response/error: nobody is waiting on this txid
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

// hasPending reports whether some in-flight sendQuery is waiting on txid.
// It is a pre-verify filter for inbound responses/errors, NOT the routing
// lookup — deliver remains the authoritative consumer.
func (n *Node) hasPending(txid []byte) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	_, ok := n.pending[string(txid)]
	return ok
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
	c.ConfirmedAt = n.now() // a verified inbound message: direct confirmation
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
// probeFailed implements §6.2 probe-failure handling with a grace for
// directly-confirmed contacts. The probe budget is 2s (lookupProbeTimeout)
// on a real network — NAT mapping churn, PPPoE jitter, a busy peer — and
// one missed probe must not disconnect a peer we exchanged with directly
// moments ago, least of all a community seed reachable only via such a
// path. Found live on the desktop box (2026-09-01): its only non-LAN
// anchor was hard-evicted whenever a single lookup probe tripped, and the
// peers table showed the seed gone until some walk happened to re-learn
// and re-confirm it.
//
// A contact with a confirmation on record keeps its slot, demoted back to
// probation (ConfirmedAt cleared — the peers surface shows "advertised");
// the caller-applied 30s dead penalty keeps walks off it briefly, and the
// next successful exchange re-confirms it. A never-confirmed contact — or
// one already demoted by an earlier miss — is removed exactly as before,
// so genuinely dead peers still converge within a probe round (or the
// idle sweep), not the full TTL.
func (n *Node) probeFailed(c *NodeContact) {
	if live := n.rt.Get(c.NodeID); live != nil {
		// Failover first: another known address for this node takes over
		// as preferred before we give up on the node. Only addresses with
		// recency qualify — a direct confirmation, or a learn within the
		// idle TTL (all of them, when the sweep is disabled).
		for _, a := range live.OtherAddrs() {
			if a.Addr == c.Addr {
				continue
			}
			recent := true
			if n.contactIdleTTL > 0 {
				recent = n.now()-a.LastSeen <= int64(n.contactIdleTTL/time.Second)
			}
			if !recent {
				continue
			}
			if n.rt.PromoteAlt(live.NodeID, a.Addr) {
				n.log.Debug("dht: probe missed, switched to alternate address",
					"addr", c.Addr, "next", a.Addr)
				return
			}
		}
		if live.ConfirmedAt > 0 {
			n.rt.Demote(c.NodeID)
			n.log.Debug("dht: probe missed, demoted confirmed contact", "addr", c.Addr)
			return
		}
	}
	n.rt.Remove(c.NodeID)
	n.log.Debug("dht: evicted unresponsive contact", "addr", c.Addr)
}

// evictCandidate implements §6.4 step 3: a newcomer arrived at a full
// bucket; quiz the oldest incumbent and swap them out if it fails to
// answer a PING. The ping runs on the maintenance goroutine, so its
// response is delivered by the still-running readLoop — no self-deadlock
// with sendQuery.
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
	// Multi-homing (2026-09-01): before declaring the NODE dead, try its
	// other known addresses — a node reachable at LAN+WAN is only dead when
	// every address is. The answering address becomes preferred so future
	// probes use it.
	if live := n.rt.Get(oldest.NodeID); live != nil {
		for _, a := range live.OtherAddrs() {
			if a.Addr == oldest.Addr {
				continue
			}
			altAddr, rerr := net.ResolveUDPAddr("udp", a.Addr)
			if rerr != nil {
				continue
			}
			actx, acancel := context.WithTimeout(ctx, n.pingTimeout)
			r2, err2 := n.sendQuery(actx, altAddr, oldest.NodeID, "ping", map[string]any{})
			acancel()
			if err2 == nil && r2 != nil {
				n.rt.PromoteAlt(oldest.NodeID, a.Addr)
				return // alive at its other address: keep the incumbent
			}
		}
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
	if _, err := n.conn.WriteTo(data, raddr); err != nil {
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
	// evidenceFor is the H_record key the §8.4 evidence piggyback below is
	// served for: the served envelope's own hash, or the probed key itself
	// on a miss (a hash-keyed evidence probe — the key IS the H_record).
	var evidenceFor []byte
	if env != nil {
		if eb, err := env.Bytes(); err == nil {
			args["envelope"] = eb // bstr .cbor SignedEnvelope
		}
		if h, err := env.RecordHash(); err == nil {
			evidenceFor = h
		}
	} else {
		// Miss: return the closest known contacts so the requester iterates.
		args["nodes"] = encodeNodes(n.rt.Closest(key, constants.K))
		evidenceFor = key
	}
	// §8.4 evidence piggyback: whatever recovery evidence this node retained
	// for the record the response is about rides along, so verifiers can
	// re-check the §8.4 quorum without a second round trip (LookupEvidence).
	if len(evidenceFor) == constants.SHA256Len {
		if ev := n.store.GetEvidence(evidenceFor); ev != nil {
			args["evidence"] = ev
		}
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
	// Per-source-IP put throttle (v0.7.1; see defaultPutRateLimit): the
	// put path's CPU cost (envelope decode + verify + PoW + witness checks)
	// runs inline on the readLoop goroutine, and write tokens are minted
	// freely by every ping/get — only a rate gate bounds a single source's
	// share of that CPU. Checked BEFORE the token: cheaper, and a source
	// hammering puts should learn to back off even if its tokens are valid.
	if !n.allowPut(raddr) {
		return n.errResp(m, 301, "throttled")
	}
	token, _ := m.A["token"].([]byte)
	envBytes, _ := m.A["envelope"].([]byte)
	// §8.4 recovery evidence (optional): the put of a recovery hand-off
	// record rides its quorum declaration along (see PublishWithEvidence);
	// retained — keyed by the envelope's H_record — only if the envelope
	// itself is kept (accepted or already the winner below).
	evidence, _ := m.A["evidence"].([]byte)
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
	// landing at K_claim passes the §7.4 step-2 claim screen BEFORE it can
	// enter the node's stores — claimant consistency (tld_id binds to the
	// claimant key), a recomputed PoW, and ≥ W corroborating v2 witnesses
	// (claims.VerifyFull; witnessSetIDs is nil here — membership is a
	// RESOLVER-side check that needs a converged routing view, not a
	// storing-node one). Before v0.7.0 a garbage claim — fabricated quorum,
	// invalid PoW, backdated timestamps — was pooled and stored as long as
	// its CARRIER envelope was well-signed, which made claim-space seeding
	// (DHT pollution / backdated-priority propagation) free; the screen
	// costs ~W Ed25519 verifies, the same order as the envelope verify
	// above. The envelope then ALSO goes into the top-2 claim pool so
	// verifiers collecting "all competing claims nodes offer" still see the
	// pair.
	poolKept := false
	if claim, cerr := claims.DecodeAliasClaim(env.Record.Claim); cerr == nil {
		if kClaim, kerr := KeyForClaim(claim.Alias); kerr == nil && bytes.Equal(key, kClaim) {
			if !claims.VerifyFull(claim, claims.InferDifficulty, nil, constants.W) {
				return n.errResp(m, 305, "claim fails the §7.4 filter (PoW/quorum)")
			}
			// §8.4 reuse window (v0.8.0; same-identity rule relaxed in
			// v0.9.1): a put at K_claim of a claim whose alias is cooling
			// off inside ALIAS_REUSE_DELAY past a dead claim's expiry is
			// refused — the tombstone is the expired claim envelope this
			// node's pool still holds (fully re-verified;
			// claims_tombstone.go). Only DIFFERENT-identity claims are
			// refused: the same identity re-carried by its claimant is
			// ownership continuity (renewal or resurrection), never a
			// re-claim.
			if inPH, perr := claim.PrefixHash(); perr == nil {
				if n.claimReuseRefusal(claim.Alias, inPH, n.now()) > 0 {
					return n.errResp(m, 301, "alias in reuse window")
				}
			}
			n.claims.Offer(kClaim, env)
			poolKept = n.claims.Contains(kClaim, recordHashOrNil(env)) // offered now or already pooled
		}
	}
	accepted, err := n.store.PutWithEvidence(key, env, n.now(), false, evidence) // sig already verified
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
				n.retainEvidence(env, evidence)      // §8.4: kept (already winner)
				return n.okResp(m, map[string]any{}) // idempotent: already the winner
			}
		}
		if poolKept {
			return n.okResp(m, map[string]any{}) // §7.4: retained in the top-2
		}
		return n.errResp(m, 304, "stale record")
	}
	n.retainEvidence(env, evidence) // §8.4: kept (accepted as winner)
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
// gives arguments {claim_prefix_hash, claimant, ts} only, but the attestation
// must bind the full claim identity, and §7.3 also demands "witnesses MUST
// verify the PoW before signing" — neither is computable from a one-way
// digest alone. The method therefore carries four extra arguments: "alias"
// (text), "tld_id" (bstr), "nonce" (bstr) and "pow_hash" (bstr). The identity
// fields are re-verified against the supplied claim_prefix_hash, and the PoW
// pair is re-verified against the prefix (below), so a requester cannot make
// the node sign a message for a claim other than the one it can demonstrate.
//
// Checks performed, in order:
//
//  1. Throttle (§12): the same per-source-IP token bucket as get/find_node
//     (NodeConfig.GetRateLimit / GetBurst; default 50/s burst 100). A witness
//     RPC costs a CBOR decode, a SHA-256 PoW re-verification AND an Ed25519
//     signature — the most expensive unauthenticated work a stranger can
//     induce — so it draws from the same read budget rather than floating
//     free (a witness-RPC flood is a CPU DoS otherwise; excess requests get
//     error 301 "throttled", an answer rather than a drop).
//  2. Structural: alias validates per §3.2; tld_id is 32 bytes; claimant is a
//     32-byte Ed25519 public key; ts is a uint; nonce/pow_hash are present.
//  3. Prefix binding: claim_prefix_hash == SHA-256(PoW prefix(alias, tld_id,
//     claimant, ts)) — recomputed via the claims package's prefix builder, so
//     client and witness agree byte-for-byte with the mining input.
//  4. PoW verification (§7.3: "witnesses MUST verify the PoW before
//     signing"): SHA-256(prefix || nonce) must equal the supplied pow_hash
//     AND meet the difficulty inferred from nonce[0] (Appendix A.4
//     convention, floored at PoWDifficultyInit). The hash is recomputed,
//     never trusted; an invalid PoW is refused with 305 — this node does not
//     lend its identity to a claim it has not checked.
//  5. §7.3 WITNESS_COOLDOWN (constants.WitnessCooldown = 3600 s): the node
//     signs at most ONE claim per alias per cooldown window. Re-signing the
//     SAME claim (same prefix hash) is allowed (idempotent refresh); a
//     DIFFERENT claim for the same alias inside the window is refused with
//     error 301 "cooldown". (§7.3 line 584-586 also permits signing a strictly
//     earlier-ordered claim; ordering is a verifier-side computation, so the
//     conservative refusal here is safe — the requester retries after the
//     cooldown or with other witnesses.)
//  6. Co-sign via claims.NewWitnessAttestation with the NODE's keypair. The
//     attestation is v2-bound to the recomputed claim prefix hash (so the
//     signature commits to the claim identity INCLUDING its timestamp — it
//     cannot be transplanted onto a re-mined, backdated claim), and its TS is
//     this witness's OWN clock (§7.3 line 560: "witness's own timestamp"),
//     not the claimant-asserted ts.
//
// On success the response carries {attestation: canonical-CBOR
// WitnessAttestation} plus the node's current PoW difficulty (Appendix A.4:
// "Nodes gossip the current D in witness responses"). Attesting is logged at
// info level.
//
// Appendix A.4 retarget accounting: only the FIRST co-sign of a given alias
// by this node counts as an "accepted claim" (n.diff.recordAccepted).
// Idempotent re-signs of the same claim and competing claims for an alias
// this node already signed do not inflate the acceptance count — otherwise a
// re-sign flood (or honest retry traffic) would drive the network difficulty
// up through the gossiped median. witnessLast is in-memory, so a restarted
// node counts each alias once per run: acceptable for a retarget statistic,
// and stated here so the limitation is explicit.
//
// A Passive node (§6.1) still witnesses: witnessing signs a timestamp, it
// stores nothing, so it is participation only in the weak §7 sense this node
// already opted into by joining the network.
func (n *Node) hWitness(m *wire.Message, raddr *net.UDPAddr) *wire.Message {
	// (1) §12 per-source-IP throttle, shared with get/find_node.
	if !n.allowRead(raddr) {
		return n.errResp(m, 301, "throttled")
	}
	alias, _ := m.A["alias"].(string)
	tldID, _ := m.A["tld_id"].([]byte)
	claimant, _ := m.A["claimant"].([]byte)
	prefixHash, _ := m.A["claim_prefix_hash"].([]byte)
	nonce, _ := m.A["nonce"].([]byte)
	powHash, _ := m.A["pow_hash"].([]byte)
	ts, ok := asUint64(m.A["ts"])
	aliasN, aerr := naming.ValidateAlias(alias)
	if !ok || aerr != nil || len(nonce) == 0 || len(powHash) != constants.SHA256Len {
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
	// (4) PoW verification via the claims package's exact prefix builder and
	// difficulty inference (nonce[0] when sane, else PoWDifficultyInit):
	// VerifyPoW recomputes SHA-256(prefix || nonce), compares it to the
	// supplied pow_hash, and checks the leading zero bits.
	if !(&claims.AliasClaim{
		Alias:      aliasN,
		TldID:      tldID,
		Timestamp:  ts,
		Nonce:      nonce,
		ClaimantPK: claimant,
		PowHash:    powHash,
	}).VerifyPoW(claims.InferDifficulty) {
		return n.errResp(m, 305, "invalid proof-of-work")
	}

	// Claim-timestamp sanity (the §7.3 anti-forgery gate, found auditing
	// what becomes of a revoked alias): §7.4 orders competing claims
	// EARLIEST-timestamp-first, so a claim forged with ts≈0 would
	// permanently out-order every honest claim once its holder's cooldown
	// lapses — stealing the alias without breaking any key. A legitimate
	// claim is witnessed at mining time (|ts - now| ≈ seconds) or
	// re-presented during register's cooldown-safe retries (ts up to
	// WITNESS_PRESENT_WINDOW old). Anything outside
	// [now - present window, now + skew] is refused: not future-dated
	// beyond the live-race skew window, not older than the window that
	// legitimizes re-presentation.
	//
	// v0.9.0 ANTI-SNIPING TIGHTENING (was WITNESS_COOLDOWN = 1 h): this
	// RPC necessarily discloses the alias to its witness set (the alias is
	// inside the PoW prefix the witness must re-verify), so a listener on
	// the witness round could mine a competing claim BACKDATED to the
	// gate's edge and out-order the victim under §7.4's earliest-first
	// rule. Such a steal is feasible only while the accepted age exceeds
	// the victim's mine-plus-witness latency (the sniper needs
	// ts_sniper < ts_victim ≈ now - victim_elapsed, with ts_sniper ≥
	// now - window). An honest registration — mining at D=24 plus the
	// 3×10 s retry cycle — completes well inside 5 minutes, so a 5-minute
	// window covers every honest re-presentation while shrinking the
	// backdate margin 12×. Parked claims older than the window are
	// discarded by the register flow (loadReusableClaim), which re-mines
	// instead of dead-looping against refusals.
	//
	// All comparisons are uint64-native: ts is an attacker-controlled
	// uint64, and a CBOR negative int decodes through asUint64 to a HUGE
	// value — the pre-v0.7.1 int64(ts) conversions made both gates below
	// wrap negative (future check false, age check underflow false) for any
	// ts >= 2^63, admitting year-292-billion claims past the sanity gate.
	nowU := uint64(n.now())
	if ts > nowU+uint64(constants.SkewTolerance) {
		return n.errResp(m, 305, "claim ts in the future")
	}
	if ts <= nowU && nowU-ts > uint64(constants.WitnessPresentWindow) {
		return n.errResp(m, 305, "claim ts too old")
	}

	// §7.3 WITNESS_COOLDOWN: one (re-signable) claim per alias per window.
	//
	// §8.4 reuse window (v0.8.0), checked BEFORE any state is recorded: if
	// this node's pool still holds a fully-verified tombstone (an expired
	// claim envelope) for the alias whose ALIAS_REUSE_DELAY window is open,
	// a DIFFERENT claim for it is refused — the alias is cooling off. The
	// incoming claim's own identity is exempt here (re-presentations are
	// bounded by the ts gate above; a resurrection attempt cannot pass it),
	// and the pooled evidence is re-verified from its signatures (a rogue
	// peer pooling a PoW-valid but quorum-less fabrication must not be able
	// to lock an alias — claims_tombstone.go).
	now := n.now()
	if n.claimReuseRefusal(aliasN, prefixHash, now) > 0 {
		return n.errResp(m, 301, "alias in reuse window")
	}
	n.witnessMu.Lock()
	last, seen := n.witnessLast[aliasN]
	cooling := seen &&
		now-last.at < int64(constants.WitnessCooldown) &&
		!bytes.Equal(last.prefixHash, prefixHash) &&
		// Same-claimant exemption (2026-09-01): the cooldown exists to stop
		// COMPETING claims — a second claimant racing for the same alias
		// within the window. A claimant re-mining their OWN pending
		// registration is not competition: register mints a fresh claim
		// timestamp whenever an attempt's present-window lapses (or the
		// daemon restarts), and under the alias-wide cooldown every witness
		// that signed an earlier attempt then REFUSED the next one — the
		// quorum shuffled itself below 5 forever (found live 2026-09-01: a
		// fresh VPS's lucasvps registration collected 3, then 2, then 0
		// witnesses as each attempt poisoned the previous signers for an
		// hour). Same claimant = the same registration, still honest.
		!bytes.Equal(last.claimant, claimant)
	if !cooling {
		n.witnessLast[aliasN] = witnessSigned{
			prefixHash: append([]byte(nil), prefixHash...),
			claimant:   append([]byte(nil), claimant...),
			at:         now,
		}
	}
	n.witnessMu.Unlock()
	if cooling {
		return n.errResp(m, 301, "cooldown")
	}

	// Co-sign with the node keypair; TS is the witness's own clock; the
	// v2 attestation binds the recomputed prefix hash `want` (the claim
	// identity, timestamp included).
	att, err := claims.NewWitnessAttestation(n.kp, uint64(now), want)
	if err != nil {
		return n.errResp(m, 305, "attestation failed")
	}
	attBytes, err := att.CanonicalBytes()
	if err != nil {
		return n.errResp(m, 301, "attestation encode failed")
	}
	// Appendix A.4: count the accepted claim only on this node's FIRST
	// co-sign of the alias (`seen` from the witnessLast probe above);
	// every PoWRetargetBlock acceptances the node's own difficulty
	// retargets over the block span.
	if !seen {
		n.diff.recordAccepted(now)
	}
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
	if adv := n.advertised(); adv != "" {
		stamped := make(map[string]any, len(args)+1)
		for k, v := range args {
			stamped[k] = v
		}
		stamped["advertise"] = adv
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
	if _, err := n.conn.WriteTo(data, addr); err != nil {
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
	// A seed is an explicit trust statement, not an advertisement: it
	// starts probation from now (ConfirmedAt 0) unless the caller knows
	// better (AddPeerConfirmed, the peerbook reload path).
	n.learn(c)
	return nil
}

// AddPeerConfirmed is AddPeer with a known last-direct-exchange timestamp
// (the peerbook reload: issue #2 probation continuity — a restart must not
// reset a contact's age).
func (n *Node) AddPeerConfirmed(pk []byte, addr string, confirmedAt int64) error {
	id, err := crypto.NodeID(pk)
	if err != nil {
		return err
	}
	c, err := NewNodeContact(id, pk, addr, n.now())
	if err != nil {
		return err
	}
	c.ConfirmedAt = confirmedAt
	n.learn(c)
	return nil
}

// Bootstrap pings each peer (best-effort, concurrent), which both verifies
// reachability and seeds the routing tables in both directions (the peer learns
// us from our signed ping). Failures are logged at debug level and do not abort.
func (n *Node) Bootstrap(ctx context.Context, peers []Peer) {
	for _, p := range peers {
		var err error
		if p.Confirmed > 0 {
			// Peerbook entry: carry its probation age (issue #2 continuity).
			err = n.AddPeerConfirmed(p.PublicKey, p.Addr, p.Confirmed)
		} else {
			err = n.AddPeer(p.PublicKey, p.Addr)
		}
		if err != nil {
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
	env, _, err := n.IterativeGetDetailed(ctx, key)
	return env, err
}

// IterativeGetDetailed is IterativeGet with walk telemetry and the
// degraded-miss classification (issue #1): a nil envelope with
// ErrDegradedMiss means probes failed — the miss is not authoritative and
// callers must not negative-cache it; a clean (nil, nil) means every
// reachable holder answered "not held".
//
// Churn behavior (found live on a 7-node LAN): contacts whose probes fail
// are penalized for deadPenaltyWindow so a later walk skips them instead of
// re-burning the 2 s probe budget on corpses that live peers keep
// re-advertising; and a round in which NO probe answered doubles the next
// round's batch (ALPHA → 2·ALPHA → … ≤ K), so the walk reaches live holders
// past a cluster of dead closest-candidates in one extra round instead of
// rounds × 2 s of serial timeouts.
func (n *Node) IterativeGetDetailed(ctx context.Context, key []byte) (*wire.SignedEnvelope, LookupStats, error) {
	var stats LookupStats
	if len(key) != constants.SHA256Len {
		return nil, stats, fmt.Errorf("dht: key must be %d bytes, got %d", constants.SHA256Len, len(key))
	}
	shortlist := append([]*NodeContact(nil), n.rt.Closest(key, constants.K)...)
	if len(shortlist) == 0 {
		return nil, stats, nil // no peers known: an island.
	}
	// Work-amplification cap: this walk holds one of WalkConcurrency slots
	// for its whole run (islands returned above — they hold no slot).
	if !n.acquireWalk() {
		return nil, stats, ErrWalkBusy
	}
	defer n.releaseWalk()
	queried := make(map[string]bool, len(shortlist))
	var bestEnv *wire.SignedEnvelope
	batchSize := constants.Alpha

	for round := 0; round < maxLookupRounds; round++ {
		// Nearest-first so the ALPHA un-queried we pick are the closest.
		sort.SliceStable(shortlist, func(i, j int) bool {
			return CompareDistance(key, shortlist[i].NodeID, shortlist[j].NodeID) < 0
		})
		now := n.now()
		var batch []*NodeContact
		for _, c := range shortlist {
			if queried[string(c.NodeID)] {
				continue
			}
			if n.penalized(c.NodeID, now) {
				continue // recently-failed corpse: skip as a candidate
			}
			batch = append(batch, c)
			if len(batch) >= batchSize {
				break
			}
		}
		if len(batch) == 0 {
			break // every known contact queried or penalized: converged.
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
			stats.ProbesSent++
			stats.ProbedNodeIDs = append(stats.ProbedNodeIDs, c.NodeID)
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

		roundAnswered := 0
		for i, r := range results {
			// §12 throttle: the peer is alive but withheld its answer. NOT a
			// §6.2 failure (no eviction/penalty — the peer did nothing wrong;
			// hammering it harder via the adaptive batch is also wrong, so it
			// counts as answered), but the "held or not" question went
			// unanswered, so a finding-nothing walk below degrades.
			if errors.Is(r.err, ErrThrottled) {
				stats.ProbesThrottled++
				roundAnswered++
				continue
			}
			// Kademlia failure handling (§6.2): a contact that failed its
			// probe (timeout / unreachable / malformed address) is evicted
			// from the routing table so it is neither re-probed by later
			// lookups on this node nor advertised to others in {nodes} lists.
			// A parent-context cancellation is NOT a peer failure — never
			// evict for that. It is ALSO penalized for deadPenaltyWindow:
			// eviction alone does not stop this walk (and the next) from
			// re-probing it, because live peers keep re-advertising the
			// corpse in their {nodes} lists until they probe it themselves.
			if r.err != nil && !errors.Is(r.err, context.Canceled) && ctx.Err() == nil {
				stats.ProbesFailed++
				n.probeFailed(batch[i])
				n.markDead(batch[i].NodeID, n.now())
			} else if r.err == nil {
				roundAnswered++
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
		// Adaptive batch: a fully-dead round means the closest candidates
		// are corpses — widen the next round so the walk reaches live
		// holders now rather than one dead-batch at a time.
		if roundAnswered == 0 {
			batchSize *= 2
			if batchSize > constants.K {
				batchSize = constants.K
			}
		}
	}
	if bestEnv == nil && (stats.ProbesFailed > 0 || stats.ProbesThrottled > 0) {
		return nil, stats, ErrDegradedMiss
	}
	return bestEnv, stats, nil
}

// IterativeFindNode performs the §6.2 node lookup: an iterative Kademlia
// walk toward target (ALPHA contacts per round, closer contacts learned into
// the routing table as it goes), returning up to want contacts closest to
// target by XOR distance. It is the table-population step a registration
// client runs before CollectWitnesses — the §7.3 WITNESS_SET are "the W
// nodes whose IDs are closest to K_claim", and a freshly-bootstrapped node
// knows only its bootstrap peers until it walks. Errors of individual
// candidates evict them (same §6.2 rule as IterativeGet); the walk itself
// never fails, it just returns what it could reach.
func (n *Node) IterativeFindNode(ctx context.Context, target []byte, want int) []*NodeContact {
	if len(target) != constants.SHA256Len || want <= 0 {
		return nil
	}
	shortlist := append([]*NodeContact(nil), n.rt.Closest(target, constants.K)...)
	if len(shortlist) == 0 {
		return nil // island
	}
	queried := make(map[string]bool, len(shortlist))
	for round := 0; round < maxLookupRounds; round++ {
		sort.SliceStable(shortlist, func(i, j int) bool {
			return CompareDistance(target, shortlist[i].NodeID, shortlist[j].NodeID) < 0
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
			break
		}
		type res struct {
			nodes []*NodeContact
			err   error
		}
		results := make([]res, len(batch))
		var wg sync.WaitGroup
		for i, c := range batch {
			queried[string(c.NodeID)] = true
			wg.Add(1)
			go func(i int, c *NodeContact) {
				defer wg.Done()
				pctx, cancel := context.WithTimeout(ctx, lookupProbeTimeout)
				defer cancel()
				results[i].nodes, results[i].err = n.findNodeRound(pctx, target, c)
			}(i, c)
		}
		wg.Wait()
		for i, r := range results {
			if r.err != nil && !errors.Is(r.err, context.Canceled) && ctx.Err() == nil {
				n.probeFailed(batch[i])
			}
			for _, nc := range r.nodes {
				n.learnContact(nc)
				if !contactIn(shortlist, nc.NodeID) {
					shortlist = append(shortlist, nc)
				}
			}
		}
		// NO shortlist-size early break: the shortlist can already hold
		// want+ STALE/dead contacts at round 0 (garbage from past sessions),
		// and stopping then would starve the walk of the live nodes deeper
		// in the list — IterativeGet (which runs to convergence) has no such
		// break for exactly this reason. The loop naturally ends when every
		// candidate has been queried; dead probes demote or evict their
		// contacts (either way the walk's `queried` map makes progress), so
		// each round makes progress. maxLookupRounds (256) × ALPHA bounds
		// the worst case.
	}
	sort.SliceStable(shortlist, func(i, j int) bool {
		return CompareDistance(target, shortlist[i].NodeID, shortlist[j].NodeID) < 0
	})
	if len(shortlist) > want {
		shortlist = shortlist[:want]
	}
	return shortlist
}

// findNodeRound issues one find_node(target) RPC to c and returns the
// offered closer contacts (an error signals probe failure → eviction).
func (n *Node) findNodeRound(ctx context.Context, target []byte, c *NodeContact) ([]*NodeContact, error) {
	addr, err := net.ResolveUDPAddr("udp", c.Addr)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}
	resp, err := n.sendQuery(ctx, addr, c.NodeID, "find_node", map[string]any{"target": target})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Y == wire.MsgTypeError {
		return nil, nil
	}
	return parseNodes(resp.A["nodes"]), nil
}

// getFromPeer issues a single get(key) RPC to c and parses the response into
// the envelopes offered by the peer and/or the closer-contacts list. The
// offers are, best-first: the §7.4 `envelopes` extension (top-2 claim pool,
// see hGet) when present, then the legacy single `envelope` (the §6.4 store
// winner — a pool-carrying peer repeats it inside `envelopes`, deduplicated
// by callers via H_record / EnvelopeWins). The returned error signals probe
// failure (drives §6.2 eviction in IterativeGet) — with ONE exception: a
// §12 301 "throttled" answer returns [ErrThrottled], which the walks treat
// as "peer alive, answer withheld" (no eviction, not an authoritative miss).
func (n *Node) getFromPeer(ctx context.Context, key []byte, c *NodeContact) ([]*wire.SignedEnvelope, []*NodeContact, error) {
	addr, err := net.ResolveUDPAddr("udp", c.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve: %w", err)
	}
	resp, err := n.sendQuery(ctx, addr, c.NodeID, "get", map[string]any{"key": key})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil {
		return nil, nil, nil
	}
	if resp.Y == wire.MsgTypeError {
		if code, ok := errorCode(resp); ok && code == 301 {
			return nil, nil, ErrThrottled
		}
		return nil, nil, nil // any other y="e": a successful exchange, nothing offered
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
// parsed node list, so LastSeen is stamped here). ConfirmedAt stays 0 for
// new entries — advertisement is not evidence of life (issue #2) — and is
// never advanced by re-teaching; only a direct exchange (learnPeer) does
// that. A full bucket schedules the async §6.2 eviction check (see learn).
func (n *Node) learnContact(c *NodeContact) {
	if c == nil || bytes.Equal(c.NodeID, n.id) {
		return
	}
	c.LastSeen = n.now()
	isNew := n.rt.Get(c.NodeID) == nil
	// c.ConfirmedAt is left as the caller set it (0 from {nodes} parsing);
	// AddOrRefresh keeps the stored entry's confirmation untouched.
	n.learn(c)
	if isNew && c.ConfirmedAt == 0 {
		// Confirm-on-learn (2026-09-01): a newly learned, never-confirmed
		// contact is probed right away. The newcomer bootstrap path taught
		// the hard lesson: the seed's first answer hands a fresh node the
		// whole fleet (multi-addr advertisement), but NOTHING probed those
		// contacts until some walk happened to touch them — a fresh VPS
		// sat with 8 known / 0 confirmed peers and a witness collection
		// that could not find a quorum. Learning now carries its own
		// liveness check; the reply path confirms via learnPeer.
		go n.confirmContact(c.clone())
	}
}

// confirmInflight dedups concurrent confirmation pings per NodeID (see
// confirmContact).
var confirmInflight sync.Map

// confirmContact probes a newly-learned contact: the preferred address
// first, then its known alternates — promoting the first alternate when the
// preferred misses, so the stored address follows to wherever the peer is
// actually reachable. Best-effort: the reply path (learnPeer) does the
// confirming; a total miss just leaves the contact to the idle sweep.
func (n *Node) confirmContact(c *NodeContact) {
	if _, busy := confirmInflight.LoadOrStore(string(c.NodeID), struct{}{}); busy {
		return
	}
	defer confirmInflight.Delete(string(c.NodeID))

	cands := []string{c.Addr}
	if live := n.rt.Get(c.NodeID); live != nil {
		for _, a := range live.OtherAddrs() {
			recent := true
			if n.contactIdleTTL > 0 {
				recent = n.now()-a.LastSeen <= int64(n.contactIdleTTL/time.Second)
			}
			if recent && a.Addr != c.Addr {
				cands = append(cands, a.Addr)
			}
		}
	}
	for i, addr := range cands {
		a, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			continue
		}
		pctx, cancel := context.WithTimeout(context.Background(), lookupProbeTimeout)
		resp, err := n.sendQuery(pctx, a, c.NodeID, "ping", map[string]any{})
		cancel()
		if err == nil && resp != nil {
			return // answered: the read loop confirmed the contact
		}
		if i == 0 && len(cands) > 1 {
			// the preferred address missed: follow the table to the next
			// candidate (clears the missed address's confirmation stamp per
			// the anti-ghost invariant — advertisement recency is not life)
			n.rt.PromoteAlt(c.NodeID, cands[1])
		}
	}
}

// sweepIdleContacts evicts contacts whose last DIRECT confirmation (or, for
// never-confirmed advertised contacts, their original learn time) is older
// than the idle TTL (issue #2: one-shot CLI nodes and other ghosts leave
// ephemeral-address contacts behind; peers re-advertise them, so only a
// confirmation-age sweep converges). Called from the maintenance loop.
func (n *Node) sweepIdleContacts(now int64) {
	if n.contactIdleTTL <= 0 {
		return // disabled
	}
	ttl := int64(n.contactIdleTTL / time.Second)
	for _, c := range n.rt.AllContacts() {
		effective := c.ConfirmedAt
		if effective == 0 {
			effective = c.LastSeen // never confirmed: probation from learn time
		}
		if now-effective > ttl {
			n.rt.Remove(c.NodeID)
			n.log.Debug("dht: evicted idle contact", "addr", c.Addr,
				"confirmed_at", c.ConfirmedAt, "ttl", n.contactIdleTTL.String())
		}
	}
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
	return n.publishKeyed(ctx, key, env, nil)
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
	return n.publishKeyed(ctx, key, env, nil)
}

// PublishKeyedAt publishes env at the EXPLICIT keys (the dht.StorageKeys
// set: K_tld/K_name plus K_claim for claim-carrying records). Exported for
// the daemon's auto-renew loop, which re-publishes a re-signed envelope at
// every key its predecessor legitimately lived at. Best-effort like Publish:
// nil when at least one target accepted. On total failure the LAST underlying
// error is returned (v0.9.1: it used to collapse every failure — including
// "accepted by 0 of N peers", i.e. peers refusing the put — into ErrNoPeers,
// which masked the 2026-08-22 §8.4 deadlock as a phantom connectivity
// problem); ErrNoPeers is returned only when no key could even be attempted
// against a known peer.
func (n *Node) PublishKeyedAt(ctx context.Context, keys [][]byte, env *wire.SignedEnvelope) error {
	published := false
	var lastErr error
	for _, k := range keys {
		if err := n.publishKeyed(ctx, k, env, nil); err == nil {
			published = true
		} else {
			lastErr = err
		}
	}
	if !published {
		if lastErr != nil {
			return lastErr
		}
		return ErrNoPeers
	}
	return nil
}

// publishKeyed is the shared §6.4 PUT body of Publish, PublishClaim and
// PublishWithEvidence: locate the R closest nodes to key, obtain a write
// token from each (via get), and issue put (evidence, when non-nil, is the
// §8.4 recovery blob riding along; see hPut). Best-effort — nil iff at least
// one peer accepted the envelope.
func (n *Node) publishKeyed(ctx context.Context, key []byte, env *wire.SignedEnvelope, evidence []byte) error {
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
		if err := n.putToPeer(ctx, key, envBytes, evidence, c); err == nil {
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

// witnessSelfSlack is how many EXTRA candidates CollectWitnesses asks the
// iterative walk for, so that dropping this node's own ID (which the walk
// legitimately returns among the closest — Kademlia does not exclude the
// walker) still leaves `count` witness candidates.
const witnessSelfSlack = 4

// CollectWitnesses implements the claimant side of §7.4 registration step 3:
// "iteratively find the WITNESS_SET closest nodes to K_claim; send each a
// witness RPC with (prefix_hash, claimant_pk, timestamp)". It runs the
// iterative Kademlia walk on K_claim (§7.4 "iteratively find" — a converged,
// not merely local-table, view of the closest set) and takes the count
// closest contacts it yields (count <= 0 defaults to constants.WitnessSet =
// 8), sending the signed witness queries in parallel. Each query carries the
// claim's nonce and pow_hash so the witnesses can verify the PoW (§7.3).
// CollectWitnesses returns every attestation that (a) decodes, (b) verifies
// against the claim's prefix hash (v2 binding) per §7.3, and (c) was
// produced by the node it was fetched from (attestation NodeID == the
// queried contact's Node ID) — so a malicious peer cannot relay someone
// else's or a forged attestation. Results are deduplicated by NodeID.
//
// Errors from unreachable/refusing peers are swallowed (witness gathering is
// best-effort; the caller re-queries or proceeds when < W attestations come
// back). The returned slice may therefore be shorter than count — possibly
// empty; assembling ≥ W attestations (§7.3 quorum) is the caller's check.
func (n *Node) CollectWitnesses(ctx context.Context, alias string, tldID, claimantPK []byte, ts uint64, nonce, powHash []byte, count int) ([]*claims.WitnessAttestation, error) {
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
	if len(nonce) == 0 || len(powHash) != constants.SHA256Len {
		return nil, fmt.Errorf("dht: witness RPC needs the PoW pair (nonce, pow_hash) — witnesses verify the PoW before signing (§7.3)")
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

	// §7.4 step 3: "Iteratively find the WITNESS_SET closest nodes to
	// K_claim". The walk (not a bare local-table Closest) is what makes the
	// registrant's witness set and a verifier's converged view of the 8
	// closest agree — Kademlia convergence — which the resolver-side
	// witness-set membership check depends on. On a cold table the walk
	// simply returns the bootstrap-reachable candidates. SELF is excluded
	// (the walk's shortlist legitimately contains this node's own ID —
	// learned back from peers — but the routing table never holds it, and a
	// claimant co-signing its own claim is no witness at all); the walk is
	// therefore asked for count+witnessSelfSlack candidates so the filter
	// cannot shrink the haul below count.
	candidates := n.IterativeFindNode(ctx, kClaim, count+witnessSelfSlack)
	filtered := candidates[:0]
	for _, c := range candidates {
		if !bytes.Equal(c.NodeID, n.ID()) {
			filtered = append(filtered, c)
		}
	}
	candidates = filtered
	if len(candidates) > count {
		candidates = candidates[:count]
	}
	if len(candidates) == 0 {
		// Island / no reachable peers: fall back to the local view (empty
		// on a true island) so the caller still gets whatever it can.
		candidates = n.rt.Closest(kClaim, count)
	}

	var (
		mu            sync.Mutex
		wg            sync.WaitGroup
		out           []*claims.WitnessAttestation
		refusedWindow int32 // atomic: candidates that answered "alias in reuse window"
	)
	for _, c := range candidates {
		wg.Add(1)
		go func(c *NodeContact) {
			defer wg.Done()
			att, refused := n.witnessFromPeer(ctx, c, aliasN, tldID, claimantPK, ts, nonce, powHash, prefixHash)
			if refused {
				atomic.AddInt32(&refusedWindow, 1)
			}
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
	// §8.4: an empty haul because every candidate refused on the reuse
	// window is a DISTINCT failure from "network too small" — surface the
	// sentinel so registrants can tell the user to retry after the window
	// instead of adding peers.
	if len(deduped) == 0 && atomic.LoadInt32(&refusedWindow) > 0 {
		return nil, ErrAliasReuseWindow
	}
	return deduped, nil
}

// witnessFromPeer issues one §6.3 witness RPC to c and returns the parsed,
// claim-verified attestation (nil on any failure — see CollectWitnesses),
// plus whether the peer's refusal was an §8.4 reuse-window refusal (used by
// CollectWitnesses to distinguish "alias cooling off" from "no witnesses").
// The arguments carry the §6.3-documented deviation: alias, tld_id and the
// PoW pair (nonce, pow_hash) ride alongside claim_prefix_hash/claimant/ts —
// the witness re-derives the prefix hash from the identity fields, and
// re-verifies the PoW, before its v2 signature (bound to the prefix hash) is
// worth anything.
func (n *Node) witnessFromPeer(ctx context.Context, c *NodeContact, alias string, tldID, claimantPK []byte, ts uint64, nonce, powHash, prefixHash []byte) (*claims.WitnessAttestation, bool) {
	addr, err := net.ResolveUDPAddr("udp", c.Addr)
	if err != nil {
		return nil, false
	}
	resp, err := n.sendQuery(ctx, addr, c.NodeID, "witness", map[string]any{
		"alias":             alias,
		"tld_id":            tldID,
		"claimant":          claimantPK,
		"ts":                ts,
		"nonce":             nonce,
		"pow_hash":          powHash,
		"claim_prefix_hash": prefixHash,
	})
	if err != nil || resp == nil {
		return nil, false
	}
	// §8.4: a peer's explicit "alias in reuse window" refusal is reported
	// separately from a generic failure so CollectWitnesses can classify
	// the haul (error responses carry {"code", "msg"}).
	if resp.Y == wire.MsgTypeError {
		if msg, _ := resp.A["msg"].(string); strings.Contains(msg, "reuse window") {
			return nil, true
		}
		return nil, false
	}
	if resp.Y != wire.MsgTypeResponse {
		return nil, false
	}
	// Appendix A.4 ("Nodes gossip the current D in witness responses"):
	// record the advertised difficulty in the observed ring for
	// DHTLookup.NetworkDifficulty's median.
	if d, ok := asUint64(resp.A["difficulty"]); ok {
		n.diff.observe(int(d))
	}
	raw, _ := resp.A["attestation"].([]byte)
	if len(raw) == 0 {
		return nil, false
	}
	att, err := claims.DecodeWitnessAttestation(raw)
	if err != nil {
		return nil, false
	}
	// Verify against the claim identity (via the prefix hash the peer was
	// asked to bind) AND bind to the answering node.
	if !att.Verify(prefixHash) {
		return nil, false
	}
	if !bytes.Equal(att.NodeID, c.NodeID) {
		return nil, false
	}
	return att, false
}

// ErrNoPeers signals that Publish had no peers to store to.
var ErrNoPeers = errors.New("dht: no peers known")

// putToPeer obtains a write token (via get) then issues put to c. evidence,
// when non-nil, is the §8.4 recovery blob riding along as an extra put arg.
func (n *Node) putToPeer(ctx context.Context, key, envBytes, evidence []byte, c *NodeContact) error {
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
	putArgs := map[string]any{
		"token":    token,
		"envelope": envBytes,
		"key":      key, // explicit target (hPut accepts derived or K_claim only)
	}
	if len(evidence) > 0 {
		putArgs["evidence"] = evidence // §8.4 recovery declaration (see hPut)
	}
	putResp, err := n.sendQuery(ctx, addr, c.NodeID, "put", putArgs)
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
	if n.contactIdleTTL > 0 {
		n.bgWg.Add(1)
		go n.idleSweepLoop(ctx)
	}
}

// idleSweepLoop runs sweepIdleContacts on a 1-minute cadence (issue #2).
func (n *Node) idleSweepLoop(ctx context.Context) {
	defer n.bgWg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	n.sweepIdleContacts(n.now()) // also at startup: reload hygiene
	for {
		select {
		case <-t.C:
			n.sweepIdleContacts(n.now())
		case <-ctx.Done():
			return
		}
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

// Store returns the lookup's local envelope store (the admin socket's
// status gauges read it; nil never happens for NewDHTLookup values).
func (l *DHTLookup) Store() *EnvelopeStore { return l.store }

// cacheFreshness returns the re-validation window for env: the minimum RR TTL
// across its RRset (a delegation-only record with an empty RRset falls back
// to RecordDefaultTTL), capped at constants.ResponseTTLCap (1 h) so very long
// record TTLs cannot pin a stale cache for the record's whole lifetime.
//
// A REVOKED record (§9.5 tombstone) always uses the SHORT window: a
// tombstone's RRset is empty by definition, so the generic fallback would
// let nodes serve it un-re-checked for a full day — asymmetrical with
// revocation itself (which propagates within the victim's TTL) and hostile
// to un-revokes (found live: an un-revoke stalled behind a day-fresh
// tombstone cache). 60 s = the resolver's NegTTL.
func cacheFreshness(env *wire.SignedEnvelope) int64 {
	if env != nil && env.IsRevoked() {
		return 60
	}
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
	env, _, gerr := l.node.IterativeGetDetailed(c, key)
	if env != nil {
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
	// Miss. A stale cached copy is still served (offline resilience —
	// better a valid-signature stale record than an error). This includes
	// the CLEAN-miss case (every reachable holder answered "not held"):
	// a deleted or lapsed name may keep resolving from a local cache until
	// its SIGNED expires — the lease semantics of §4.4/§6.4 (deletion in
	// freens is "stop renewing and let the lease die", never a network
	// erase), NOT a bug; the resolver's per-serve IsBasicValid gate is what
	// bounds it. Only with NOTHING cached does the miss classification
	// escape:
	//
	//   clean miss (every reachable holder answered "not held"):
	//     (nil, nil) — the resolver's NXDOMAIN, negative-cacheable.
	//   degraded miss (some probes failed; issue #1): ErrDegradedMiss —
	//     the resolver maps it to SERVFAIL, which is NEVER cached, so the
	//     next query retries instead of sitting out a 60 s negative TTL
	//     for a name whose holders were alive all along.
	if cached != nil {
		return cached, nil
	}
	if gerr != nil {
		return nil, gerr
	}
	return nil, nil
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

// allowPut consumes one put token for the observed source of raddr (see
// defaultPutRateLimit). Always true when put throttling is disabled.
func (n *Node) allowPut(raddr *net.UDPAddr) bool {
	if n.putLim == nil {
		return true
	}
	return n.putLim.allow(normIP(raddr.IP))
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

// packetBudget is the GLOBAL inbound packet budget (NodeConfig.
// PacketRateLimit/PacketBurst): one token bucket for ALL sources together,
// consulted at the very top of handle() — before decode and verify — so a
// distributed or spoofed flood (which the per-source-IP rateLimiter cannot
// bound, every distinct source drawing a fresh bucket) hits a hard,
// dirt-cheap ceiling. State is two fields behind one mutex; no map, no idle
// sweep, nothing an attacker can grow.
type packetBudget struct {
	rate   float64 // tokens/second
	burst  float64 // capacity
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newPacketBudget(rate float64, burst int) *packetBudget {
	return &packetBudget{rate: rate, burst: float64(burst)}
}

// allow reports whether one more inbound packet fits the global budget,
// refilling lazily from the elapsed time since the previous packet. The
// first packet after construction sees a FULL bucket (tokens starts at 0 but
// last is zero-valued, so the initial refill grants the full burst).
func (p *packetBudget) allow() bool {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if dt := now.Sub(p.last); dt > 0 {
		p.tokens = min(p.burst, p.tokens+dt.Seconds()*p.rate)
	}
	p.last = now
	if p.tokens >= 1 {
		p.tokens--
		return true
	}
	return false
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
			// The idle sweep may not free enough (an attacker sustaining
			// >10k distinct live sources — IPv6 gives them unbounded
			// source addresses). Cap the map for real: evict the
			// least-recently-touched entries down to 3/4 of the ceiling,
			// then admit the new key (a hard cap that refuses new keys
			// would let an attacker lock honest IPs out of the map; an
			// uncapped map is an unbounded-memory bug — found auditing
			// the flood paths).
			if len(l.buckets) >= limiterMaxEntries {
				l.evictLRULocked(limiterMaxEntries - limiterMaxEntries/4)
			}
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

// evictLRULocked drops least-recently-touched entries until len(buckets) is
// at most target (never dropping a bucket touched within the last second, so
// an in-progress honest burst survives). Caller must hold l.mu.
func (l *rateLimiter) evictLRULocked(target int) {
	type lastT struct {
		k    string
		last time.Time
	}
	all := make([]lastT, 0, len(l.buckets))
	for k, b := range l.buckets {
		all = append(all, lastT{k, b.last})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].last.Before(all[j].last) })
	cutoff := time.Now().Add(-time.Second)
	dropped := 0
	for _, e := range all {
		if len(l.buckets)-dropped <= target || e.last.After(cutoff) {
			break
		}
		delete(l.buckets, e.k)
		dropped++
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

// errorCode extracts the numeric "code" from a y="e" response's args, if
// present and numeric (fxamacker/cbor decodes CBOR uints into uint64; the
// other cases are pure defensiveness). ok is false for absent/non-numeric.
func errorCode(resp *wire.Message) (code int, ok bool) {
	if resp == nil {
		return 0, false
	}
	switch v := resp.A["code"].(type) {
	case uint64:
		return int(v), true
	case int64:
		return int(v), true
	case int:
		return v, true
	case float64:
		return int(v), true
	}
	return 0, false
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
//
// Addresses that are not literal "ip:port" (hostname-shaped seeds.conf
// contacts: freens.camalolo.com:15353) are SKIPPED, never encoded: §6.2
// advertises (ip, port, node_pubkey) — an IP — and encoding a hostname would
// emit empty IP bytes, which receivers decode as a literal "<nil>:port"
// contact (found live 2026-09-02: the community seed propagated
// "<nil>:15353" alts fleet-wide through every {nodes} reply that listed it).
// The hostname contact stays dialable LOCALLY (ResolveUDPAddr resolves at
// ping time); only its wire advertisement is suppressed.
func encodeNodes(contacts []*NodeContact) []any {
	out := make([]any, 0, len(contacts))
	for _, c := range contacts {
		if advertiseableAddr(c.Addr) {
			out = append(out, encodeNodeEntry(c.Addr, c.NodeID, c.PublicKey))
		}
		// Multi-homing (2026-09-01, operator idea: "all the peers known
		// should be returned by the seed"): every known address rides
		// along as its own entry — same NodeID, different addr. Newcomers
		// accumulate LAN+WAN for the whole fleet on their FIRST exchange,
		// so no single node's death (the seed's included) strands them;
		// v0.13.3+ receivers merge the entries into one multi-homed
		// contact, older receivers just re-learn (their classic
		// overwrite behavior, transient). Advertisement never confirms:
		// the anti-ghost invariant is enforced at learn time, not here.
		for _, a := range c.Alts {
			if advertiseableAddr(a.Addr) {
				out = append(out, encodeNodeEntry(a.Addr, c.NodeID, c.PublicKey))
			}
		}
	}
	return out
}

// advertiseableAddr reports whether addr is a literal "ip:port" whose host
// parses as a SPECIFIED IP address — the only shape §6.2 allows on the wire.
// See the encodeNodes doc for the "<nil>:port" failure this prevents.
func advertiseableAddr(addr string) bool {
	ip := net.ParseIP(hostOf(addr))
	return ip != nil && !ip.IsUnspecified()
}

// encodeNodeEntry renders one {nodes} element: [ipBytes, port, nodeID, pk].
func encodeNodeEntry(addr string, nodeID, pk []byte) []any {
	ip := net.ParseIP(hostOf(addr))
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
	port := uint64(portOf(addr))
	return []any{ipBytes, port, nodeID, pk}
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
		// Defense against old peers (pre-2026-09-02) that encoded
		// hostname-shaped contacts as EMPTY ip bytes: net.IP{}.String() is
		// the literal "<nil>", and learning "<nil>:port" poisons the table
		// with an undialable address. Only real 4-byte (IPv4) or 16-byte
		// (IPv6) addresses are contacts; the unspecified address advertises
		// nothing dialable either.
		if n := len(ipBytes); n != net.IPv4len && n != net.IPv6len {
			continue
		}
		if ip.IsUnspecified() {
			continue
		}
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
