// Package constants holds the normative protocol constants for freens.
//
// Every value mirrors specifications.md "Appendix A. Constants (normative)"
// (spec lines 965-993) and the difficulty-retarget rule of Appendix A.4
// (spec lines 995-1008). Durations are in seconds; sizes in bytes (the spec's
// MiB values are materialised as byte counts).
package constants

import "math"

// Protocol version (record "version" field).
const ProtoVersion = 1

// Name structure.
const (
	MaxLabels   = 8  // max name depth (labels under TLD)
	MaxLabelLen = 63 // max length of a single DNS-style label (bytes)
)

// Network / DHT (Kademlia parameters).
const (
	FreensPort    = 15353 // default DHT UDP port
	K             = 20    // k-bucket size / closest-set size
	Alpha         = 3     // lookup parallelism
	RReplication  = 8     // replication factor for put (exported; R is reserved in some contexts)
	GetClosest    = 4     // nodes merged when selecting a winner
	RPCTimeoutSec = 5     // per-RPC timeout (seconds)
	BucketRefresh = 900   // Kademlia bucket refresh interval (15 min)
	TokenRotation = 300   // write-token epoch (5 min)
)

// Records / TTL.
const (
	RecordDefaultTTL = 86400   // default record lifetime (24 h)
	RecordMaxTTL     = 2592000 // max record lifetime (30 d)
	RefreshFraction  = 0.8     // republish at 80% of lifetime
	ExpiryGrace      = 86400   // store past expiry (24 h; skew/partitions)
	MaxRRsPerRecord  = 64      // max resource records within a single record
)

// Witnessing.
const (
	W                    = 5    // witness quorum size
	WitnessSet           = 8    // candidate witnesses (closest to K_claim)
	WitnessCooldown      = 3600 // min spacing between a witness's signatures on competing claims (1 h)
	WitnessPresentWindow = 300  // max age of a claim ts a witness accepts (5 min; v0.9.0)
)

// Proof-of-Work / difficulty.
const (
	PoWDifficultyInit = 24  // initial claim PoW difficulty (bits)
	PoWRetargetBlock  = 256 // difficulty retarget interval (accepted claims)
	PoWTargetInterval = 600 // target global claim interval (seconds)
)

// Aliases / claims / timing.
const (
	SkewTolerance    = 60      // near-simultaneous claim window (seconds)
	ContestWindow    = 172800  // contested-alias finalization wait (48 h)
	AliasReuseDelay  = 2592000 // alias re-claimable after expiry (30 d)
	RecoveryTimelock = 259200  // default recovery delay (72 h)
)

// Re-attestation (the v2 renewal amendment, §8.3/§7.3): renewals re-collect
// witness attestations for the UNCHANGED claim identity, dated NOW. The §6.3
// ts gate guarantees an honest witness only ever signs a claim whose ts is
// within WitnessPresentWindow of its own clock, so a claim whose FRESH
// attestations exist has been continuously held and witnessed — the
// resolver-side freshness evidence that anchors past-horizon claims.
const (
	// ReAttestHold is how long a storing node must have held a claim
	// identity before it re-attests it: fresh forgeries cannot farm
	// signatures in the window between their put and their re-attest round,
	// so a fresh attestation quorum carries real age. 24 h = one renewal
	// cycle; churned-in witnesses become eligible one cycle after
	// acquiring the chain.
	ReAttestHold = 86400
	// ReAttestFresh is how recent an attestation must be (witness clock vs
	// now) to count as freshness evidence at the verifier: one contest
	// window, so a claim re-attested every renewal cycle (24 h leases)
	// always carries live evidence.
	ReAttestFresh = ContestWindow
)

// Resolver caching.
const (
	ResponseTTLCap = 3600 // max TTL emitted by resolver (seconds)
	NegTTL         = 60   // negative caching (seconds)
	// StaleServeSecs bounds the serve-stale-while-revalidate window (§10.4,
	// amended): an EXPIRED positive answer may still be answered — marked as
	// it always was, validated when it was fetched — while a background
	// refresh revalidates it, for at most this many seconds past expiry.
	// Only positive answers qualify (negatives must go dark within their
	// TTL), and a successful refresh replaces the entry immediately, so the
	// window only ever matters when the namespace is UNREACHABLE — where
	// answering with the last known good address beats an outage. Negative
	// answers never serve stale. 6 h (found live: 30 min still left the
	// first query after an idle evening walking cold on the client).
	StaleServeSecs = 6 * 3600
)

// Storage.
const NodeStorageMax = 256 * 1024 * 1024 // per-node envelope storage cap (256 MiB)

// Self-certifying TLS (§9.5).
const (
	TLSCADeriveInfo    = "freens-tls-ca-v1" // HKDF info for §9.5.1 owner-CA derivation
	TLSCAValidityDays  = 3650               // TLS_CA_VALIDITY: owner-CA / local-root cert lifetime (10 y)
	TLSLeafTTLSec      = 604800             // TLS_LEAF_TTL: max leaf certificate lifetime (7 d)
	TLSCrossCertTTLSec = 604800             // TLS_CROSSCERT_TTL: max cross-cert lifetime (7 d; ≤ record expiry)
	TLSCAResponseTTL   = 3600               // rrset TTL carried by the TLSCA RR itself (capped by record expiry)
)

// Cryptographic primitive sizes (bytes).
const (
	Ed25519PublicKeyLen  = 32
	Ed25519SignatureLen  = 64
	SHA256Len            = 32
	NodeIDLen            = 32
	Ed25519PrivateKeyLen = 32 // raw seed
)

// Wire-format markers / DHT key prefixes.
const (
	WireNameLabelMarker byte = 0x01 // precedes each label in a wire-encoded name
	WireNameTerminator  byte = 0x00 // terminates a wire-encoded name
	DHTKeyPrefixName    byte = 0x02 // K_name  = SHA-256(0x02 || wire_name)
	DHTKeyPrefixClaim   byte = 0x03 // K_claim = SHA-256(0x03 || "claim:" || alias)
)

// RetargetDifficulty implements the Appendix A.4 difficulty-retarget rule
// (v0.8.0 corrected form):
//
//	D_new = D_old + clamp(round(log2(target_block_span / actual_block_span)), -2, +2)
//
// where actualBlockSpan is the wall-clock span over which the last
// PoWRetargetBlock accepted claims arrived and targetBlockSpan is the span
// the target rate (PoWRetargetBlock claims, one per PoWTargetInterval)
// would produce. The control direction is anti-squatting load-sensitive: a
// block that completes FASTER than the target span — claims arriving too
// quickly, the mass-squatting scenario — RAISES the difficulty; a slower
// block lowers it, floored at PoWDifficultyInit. (Before v0.8.0 the ratio
// was inverted AND compared the whole block's span against the per-claim
// target, so a registration flood lowered D to the floor and a quiet
// network ratcheted it up — the exact opposite of the stated A.4 goal; the
// ceil→round change removes the upward drift unbiased span jitter caused.)
func RetargetDifficulty(dOld, actualBlockSpan, targetBlockSpan int) int {
	var delta int
	switch {
	case targetBlockSpan <= 0:
		return max(dOld, PoWDifficultyInit) // degenerate target: no change
	case actualBlockSpan <= 0:
		delta = 2 // instantaneous block: maximally fast ⇒ maximal step up
	default:
		delta = int(math.Round(math.Log2(float64(targetBlockSpan) / float64(actualBlockSpan))))
		if delta < -2 {
			delta = -2
		} else if delta > 2 {
			delta = 2
		}
	}
	dNew := dOld + delta
	if dNew < PoWDifficultyInit {
		dNew = PoWDifficultyInit
	}
	return dNew
}
