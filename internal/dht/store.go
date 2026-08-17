// Package dht — store.go implements the in-process DHT envelope store backing
// the storing-node side of specifications.md §6.4 (Store and retrieve
// semantics, spec lines 459-490) and §12 (Economics and incentives, lines
// 900-915).
//
// Each 32-byte DHT storage key (K_tld / K_name / K_claim — all SHA-256
// digests) retains AT MOST ONE winning SignedEnvelope. A fresh Put replaces
// the incumbent only when wire.EnvelopeWins reports a strict win (§6.4 step 3,
// lines 466-470), OR when the incumbent is past expires + EXPIRY_GRACE (in
// which case the slot is treated as empty — §6.4 step 4, lines 471-477).
//
// Storage is capped (constants.NodeStorageMax = 256 MiB, Appendix A line
// 993). When the cap is exceeded, entries are evicted expired-first then by
// least-recently-used (§12 line 908). The just-put entry is protected from the
// LRU pass so it always survives the post-accept sweep.
//
// Superseded-envelope history (§8.3 lines 666-688): every envelope that leaves
// the live map — displaced by a winning successor in Put, or dropped by the
// expired/LRU sweeps — is retained in a bounded history keyed by its H_record
// (GetHistory). §8.3 chains transfers via prev_hash "into an auditable chain",
// and the network accepts a transfer "because the previous owner ... signed
// it"; verifying a transferred TLD root therefore requires the PREDECESSOR
// envelopes, which the single-winner live map alone would forget. History
// entries never expire by record time (they are audit trail, not live
// records); they are bounded only by count (historyMax), evicting the
// least-recently-touched first.
//
// This file ports archive/python-v0.1/freens/dht/store.py. It is pure stdlib
// (bytes, sync, time) plus internal/constants and internal/wire; it does NOT
// import internal/crypto (signature verification is delegated to
// SignedEnvelope.VerifySignature in package wire). A single sync.Mutex guards
// every public method; internal "*Locked" helpers run with the lock already
// held so Put may EvictExpired + enforceCap re-entrantly without self-deadlock.
package dht

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// entry is the per-key store record: the single winning envelope plus the
// cached wire byte size (so the byte budget recomputes in O(1) per entry) and
// the last-access unix timestamp that drives the §12 LRU eviction order.
type entry struct {
	env        *wire.SignedEnvelope
	size       int   // cached len(env.Bytes()); set once at Put
	lastAccess int64 // unix seconds; refreshed on every successful Put/Get
}

// historyMax bounds the superseded-envelope history (§8.3 audit trail): the
// number of displaced/swept envelopes retained for transfer-chain
// verification. At this size a map + linear min-scan eviction is fine — no
// heap or LRU list bookkeeping is warranted.
const historyMax = 4096

// historyMaxBytes bounds the history's total canonical bytes (v0.7.1): the
// count cap alone admitted ~4096 × 64 KB ≈ 256 MB of network-sourced
// envelopes pinned in "audit" memory on top of the 256 MiB live-store
// budget — ~2× the documented NodeStorageMax ceiling. The byte budget keeps
// the audit trail's footprint proportional to what it actually holds.
const historyMaxBytes = 16 << 20 // 16 MiB

// evidenceMax bounds the §8.4 recovery-evidence table (evidence.go): like the
// §8.3 history, a bounded audit side-table next to the single-winner live
// map, evicting first-inserted-first-out at overflow.
const evidenceMax = 4096

// Evidence-table byte bounds (v0.7.1): the count cap alone admitted
// ~4096 × 64 KB ≈ 256 MB of network-sourced blobs (the UDP datagram limit is
// the only per-blob ceiling, and a blob needs only DECODE validity — not a
// quorum — to be retained). The per-blob cap rejects pathological blobs
// outright; the total budget keeps the table's footprint bounded, and also
// shrinks the §6.3 get-reflection payload an attacker can pre-plant.
const (
	maxEvidenceBlobLen = 64 << 10 // 64 KiB per blob (datagram-sized ceiling)
	evidenceMaxBytes   = 16 << 20 // 16 MiB total
)

// EnvelopeStore is the in-process DHT envelope store implementing the §6.4
// winner rule and the §12 eviction policy. Each 32-byte key retains at most
// one winning *wire.SignedEnvelope.
//
// All public methods are safe for concurrent use.
type EnvelopeStore struct {
	maxBytes int
	nowFn    func() int64
	mu       sync.Mutex
	entries  map[[constants.SHA256Len]byte]*entry

	// history retains superseded envelopes (§8.3) keyed by THEIR OWN H_record
	// (not by DHT key): the displaced incumbent on every winning Put, plus
	// everything dropped by the expired/LRU sweeps. Bounded by historyMax
	// entries AND histMaxBytes total bytes (fields so tests can shrink the
	// budgets; the exported defaults are the consts above).
	history      map[[constants.SHA256Len]byte]*entry
	histMaxBytes int // byte budget; set by NewEnvelopeStore from historyMaxBytes
	historyBytes int // sum of history entries' cached sizes (byte budget)

	// evidence retains §8.4 recovery-declaration evidence (wire.Recovery
	// Evidence) keyed by the H_record of the envelope it was published WITH
	// (the recovery record itself, not the recovered predecessor) — the key
	// the resolver's hand-off walk fetches it by. Bounded by evidenceMax
	// entries, maxEvidenceBlobLen bytes per blob and evidMaxBytes total
	// (FIFO via evidenceOrder; a field so tests can shrink the budget).
	// Guarded by mu like every other field.
	evidence      map[[constants.SHA256Len]byte][]byte
	evidenceOrder [][constants.SHA256Len]byte // insertion order, oldest first (FIFO eviction)
	evidMaxBytes  int                         // byte budget; set by NewEnvelopeStore from evidenceMaxBytes
	evidenceBytes int                         // sum of retained blob lengths (byte budget)
}

// NewEnvelopeStore constructs an empty EnvelopeStore. If maxBytes <= 0 it
// defaults to constants.NodeStorageMax (256 MiB). If nowFn is nil it defaults
// to time.Now().Unix(); tests inject a deterministic clock. The injected clock
// is used only by callers that read s.nowFn; the Put/Get/Has/EvictExpired
// methods on this type take an explicit now argument and never touch the wall
// clock, which keeps every test deterministic.
func NewEnvelopeStore(maxBytes int, nowFn func() int64) *EnvelopeStore {
	if maxBytes <= 0 {
		maxBytes = constants.NodeStorageMax
	}
	clock := nowFn
	if clock == nil {
		clock = func() int64 { return time.Now().Unix() }
	}
	return &EnvelopeStore{
		maxBytes:     maxBytes,
		nowFn:        clock,
		entries:      make(map[[constants.SHA256Len]byte]*entry),
		history:      make(map[[constants.SHA256Len]byte]*entry),
		histMaxBytes: historyMaxBytes,
		evidence:     make(map[[constants.SHA256Len]byte][]byte),
		evidMaxBytes: evidenceMaxBytes,
	}
}

// Now returns the store's current clock reading (the injected nowFn, or the
// wall clock). It is a convenience for callers that want the same notion of
// "now" the store would use internally.
func (s *EnvelopeStore) Now() int64 { return s.nowFn() }

// Put attempts to store env under key at time now. It returns (accepted, nil):
// accepted is true iff env was installed as the winner for key.
//
// Acceptance rules (applied in order):
//
//  1. key must be exactly constants.SHA256_LEN (32) bytes — else an error.
//  2. env must be a non-nil *wire.SignedEnvelope with a non-nil Record — else
//     an error. If verifySignature is true, env.VerifySignature() MUST return
//     true; a bad signature rejects the put (returns false, nil; count
//     unchanged). verifySignature=false skips the check (testing only) but the
//     argument must still be a structurally valid SignedEnvelope.
//  3. Incumbent / winner check (§6.4 step 3): if an entry exists for key and
//     is still alive (now < incumbent.expires + ExpiryGrace), the newcomer is
//     accepted only when wire.EnvelopeWins(env, incumbent) returns true. A
//     newcomer that carries prev_hash (field 9) ASSERTS a chain link, so it is
//     additionally rejected unless wire.VerifyChainLink(newcomer, incumbent)
//     holds (§4.4 rule 4 / §8.3: prev_hash == H_record(incumbent) and a
//     strictly increasing sequence). A prev_hash-asserting newcomer signed by
//     a key OTHER than the incumbent's owner is neither an ordinary update
//     (§8.2: the owner signs) nor a §8.3 transfer (the previous owner signs),
//     so it is accepted only as a §8.4 recovery hand-off — see
//     [EnvelopeStore.PutWithEvidence] (plain Put passes nil evidence, i.e.
//     such a newcomer is rejected). A newcomer WITHOUT prev_hash is judged by
//     the plain winner rule for the incumbent's OWNER (an ordinary §8.2
//     update/republication: same signer); a no-prev_hash newcomer signed by a
//     DIFFERENT key is rejected outright (v0.7.0 anti-censorship rule — see
//     rule 3's inline comment). A dead or absent incumbent means the slot is
//     empty, so the newcomer is accepted unconditionally (re-creation after
//     expiry+grace).
//  4. On acceptance: cache len(env.Bytes()), set lastAccess = now, then run
//     EvictExpired(now) followed by enforceCap(now, protected=key). The
//     post-accept sweeps MAY evict other entries but never the just-put key
//     (a single oversized entry that alone exceeds the cap is retained rather
//     than evicted in an infinite loop).
func (s *EnvelopeStore) Put(key []byte, env *wire.SignedEnvelope, now int64, verifySignature bool) (bool, error) {
	return s.PutWithEvidence(key, env, now, verifySignature, nil)
}

// PutWithEvidence is [EnvelopeStore.Put] with an OPTIONAL §8.4
// recovery-evidence blob riding along (nil keeps Put's exact behavior). It
// governs rule 3's hand-off authorization: when a prev_hash-asserting
// newcomer displacing an alive incumbent is signed by a key other than the
// incumbent's owner (not §8.2/§8.3), the newcomer is accepted ONLY as a §8.4
// recovery — owner = signer = the new primary key, with evidence that
// decodes, names that same new key (NewOwnerPK), and satisfies a QUORUM of
// the incumbent's §5.4 policy over H_record(incumbent).
//
// The §8.4 timelock is deliberately NOT enforced here: the store verifies
// with now = evidence.NotBefore so the time gate trivially passes while the
// quorum is fully enforced. §8.4 step 1 says the declaration is "published
// like any record (sequence +1)" — retention during the timelock is what
// makes step 2's cancellation race work (the current primary cancels by
// publishing a higher-sequence record, which the §6.4 winner rule arbitrates
// exactly as always). WHEN the recovery takes effect (step 3, "after the
// timelock elapses") is the RESOLVER's decision, made per query against the
// caller's clock (wire.VerifyAuthorityChainWithHandoffs).
func (s *EnvelopeStore) PutWithEvidence(key []byte, env *wire.SignedEnvelope, now int64, verifySignature bool, evidence []byte) (bool, error) {
	// --- rule 1: key length ----------------------------------------------
	if len(key) != constants.SHA256Len {
		return false, fmt.Errorf("dht: key must be %d bytes, got %d", constants.SHA256Len, len(key))
	}
	// --- rule 2: envelope type + structural validity ---------------------
	if env == nil {
		return false, errors.New("dht: env must be a non-nil *wire.SignedEnvelope")
	}
	if env.Record == nil {
		return false, errors.New("dht: env.Record must be non-nil")
	}
	if verifySignature && !env.VerifySignature() {
		return false, nil
	}

	var k [constants.SHA256Len]byte
	copy(k[:], key)

	s.mu.Lock()
	defer s.mu.Unlock()

	// --- rule 3: winner check vs an alive incumbent (§6.4 step 3) --------
	if cur, ok := s.entries[k]; ok && s.aliveLocked(cur, now) {
		// Alive incumbent: the newcomer must STRICTLY win.
		if !wire.EnvelopeWins(env, cur.env) {
			return false, nil
		}
		// The newcomer asserts a prev_hash chain link: enforce it against the
		// incumbent (§4.4 rule 4 / §8.3). A nil prev_hash skips this check so
		// pre-prev_hash publishers keep working (backward compatibility).
		if len(env.Record.PrevHash) > 0 && !wire.VerifyChainLink(env, cur.env) {
			return false, nil
		}
		// §8.3/§8.4 hand-off authorization: a prev_hash-asserting newcomer
		// signed by someone OTHER than the incumbent's owner is neither an
		// ordinary update (§8.2) nor a transfer (§8.3). It is accepted only
		// as a §8.4 recovery hand-off backed by quorum evidence (see
		// PutWithEvidence for the timelock rationale).
		if len(env.Record.PrevHash) > 0 && !bytes.Equal(env.Signer, cur.env.Record.Owner) &&
			!s.recoveryAcceptableLocked(env, cur.env, evidence) {
			return false, nil
		}
		// v0.7.0 anti-censorship rule: a DIFFERENT-signer newcomer WITHOUT
		// prev_hash is no ordinary path — not §8.2 (the owner signs), not
		// §8.3 (a transfer MUST carry prev_hash), not §8.4 (recovery rides
		// its quorum evidence, above). Before v0.7.0 such a record won the
		// slot on a bare higher sequence (EnvelopeWins), so anyone could
		// evict a LIVE record with sequence = MAX_UINT64 — not stealing it
		// (the resolver's authority chain still rejects the impostor) but
		// censoring the honest record out of every storing node until
		// expiry. It is accepted ONLY when the store's live PARENT record
		// authorizes the newcomer's key (parent.Owner == newcomer.Signer —
		// the name was re-owned up the chain — or parent.Delegation ==
		// newcomer.Signer, §3.4 delegated republication): that is the one
		// legitimate way a name changes hands without a prev_hash link (a
		// §8.3 TLD transfer re-delegates the subtree, and the new owner
		// republishes; the resolver proves it against the parent chain,
		// the store merely pre-screens it). TLD roots (no parent) get no
		// exception: their hand-offs must use prev_hash + §8.3/§8.4.
		if len(env.Record.PrevHash) == 0 && !bytes.Equal(env.Signer, cur.env.Record.Owner) &&
			!s.parentAuthorizesLocked(env, cur.env, now) {
			return false, nil
		}
	}
	// else: no incumbent, or incumbent past grace -> slot is empty -> accept.

	// --- accept: install the new winner ---------------------------------
	// Cache the byte size once so the cap budget recomputes in O(1) per entry
	// (we never recompute Bytes() on every SizeBytes() call).
	b, err := env.Bytes()
	if err != nil {
		return false, fmt.Errorf("dht: encode envelope: %w", err)
	}
	// §8.3 retention: the displaced incumbent — alive loser of the winner
	// check, or an already-dead envelope the newcomer recycles the slot from —
	// becomes audit history keyed by its own H_record.
	if cur, ok := s.entries[k]; ok {
		s.retainHistoryLocked(cur)
	}
	s.entries[k] = &entry{env: env, size: len(b), lastAccess: now}

	// --- rule 4: post-accept eviction sweeps (§6.4 step 4 + §12) --------
	// Expired-first (may drop the just-put key iff IT is past grace — an
	// already-long-dead envelope does not deserve storage), then cap
	// enforcement (LRU; the just-put key is protected there).
	s.evictExpiredLocked(now)
	s.enforceCapLocked(now, k)
	return true, nil
}

// Get returns the stored envelope for key at time now, or (nil, nil) if no
// live entry is present. A dead entry (now >= expires + ExpiryGrace) is
// lazily evicted on access (§6.4 step 4): if present but dead, it is dropped
// and nil is returned. On a successful hit, lastAccess is refreshed to now
// (LRU bookkeeping).
//
// A non-32-byte key is an error.
func (s *EnvelopeStore) Get(key []byte, now int64) (*wire.SignedEnvelope, error) {
	if len(key) != constants.SHA256Len {
		return nil, fmt.Errorf("dht: key must be %d bytes, got %d", constants.SHA256Len, len(key))
	}
	var k [constants.SHA256Len]byte
	copy(k[:], key)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[k]
	if !ok {
		return nil, nil
	}
	if !s.aliveLocked(e, now) {
		// Lazy eviction of a dead entry (§6.4 step 4 / §12) — retained in the
		// §8.3 history like every other envelope leaving the live map.
		s.retainHistoryLocked(e)
		delete(s.entries, k)
		return nil, nil
	}
	e.lastAccess = now
	return e.env, nil
}

// Has reports whether an ALIVE entry is stored under key at time now. It is
// non-mutating: it does NOT lazily evict a dead entry (use Get or EvictExpired
// for that); it simply reports false for a dead or absent key. A wrong-length
// key reports false.
func (s *EnvelopeStore) Has(key []byte, now int64) bool {
	if len(key) != constants.SHA256Len {
		return false
	}
	var k [constants.SHA256Len]byte
	copy(k[:], key)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[k]
	if !ok {
		return false
	}
	return s.aliveLocked(e, now)
}

// Remove unconditionally drops the entry for key and returns true iff
// something was removed. Not on the §6.4 critical path; provided for
// administration and testability. A wrong-length key reports false. Unlike the
// eviction sweeps, Remove does NOT retain the envelope in the §8.3 history —
// it is an explicit administrative drop, not an organic supersession.
func (s *EnvelopeStore) Remove(key []byte) bool {
	if len(key) != constants.SHA256Len {
		return false
	}
	var k [constants.SHA256Len]byte
	copy(k[:], key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[k]; !ok {
		return false
	}
	delete(s.entries, k)
	return true
}

// EvictExpired removes every entry past expires + ExpiryGrace at time now and
// returns the count evicted. This is the "expired envelopes first" half of the
// §12 eviction policy and the §6.4 step 4 sweep.
func (s *EnvelopeStore) EvictExpired(now int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evictExpiredLocked(now)
}

// SizeBytes returns the total cached wire bytes (the sum of len(Bytes()) over
// all live entries, computed from the per-entry size cache).
func (s *EnvelopeStore) SizeBytes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.totalBytesLocked()
}

// Count returns the number of entries currently held. Entries that are past
// expires + ExpiryGrace but not yet swept (by Get, EvictExpired, or a Put) are
// still counted here; they are removed lazily on the next access. Call
// EvictExpired first if an exact "live" count is required.
func (s *EnvelopeStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Keys returns a fresh snapshot of the store's current keys. The order is
// unspecified (Go map iteration). Each key is a freshly allocated 32-byte
// slice so callers may mutate freely.
func (s *EnvelopeStore) Keys() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, 0, len(s.entries))
	for k := range s.entries {
		cp := make([]byte, constants.SHA256Len)
		copy(cp, k[:])
		out = append(out, cp)
	}
	return out
}

// StoreEntry is one entry of an Entries snapshot: the 32-byte DHT key and the
// winning envelope (whose Record carries the Created / Expires timestamps used
// by the §6.4 step 4 republish scan).
type StoreEntry struct {
	Key []byte
	Env *wire.SignedEnvelope
}

// Entries returns a snapshot of the ALIVE entries at time now (§6.4 step 4:
// entries past expires + ExpiryGrace are dead and are excluded, mirroring the
// lazy eviction of Get). Unlike Keys(), which returns every stored key
// including not-yet-swept dead ones, Entries yields only live entries, sorted
// by bytewise-ascending key for deterministic iteration. The envelope pointers
// are shared with the store (envelopes are never mutated in place); the key
// slices are fresh copies.
func (s *EnvelopeStore) Entries(now int64) []StoreEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]StoreEntry, 0, len(s.entries))
	for k, e := range s.entries {
		if !s.aliveLocked(e, now) {
			continue
		}
		key := make([]byte, constants.SHA256Len)
		copy(key, k[:])
		out = append(out, StoreEntry{Key: key, Env: e.env})
	}
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i].Key, out[j].Key) < 0
	})
	return out
}

// PersistTo writes every ALIVE entry into dir as <keyhex>.cbor, where the file
// content is the envelope's canonical CBOR (SignedEnvelope.Bytes()) — exactly
// the format the daemon's -load seeding and freens-cli make-record produce, so
// a persisted directory can be re-seeded on the next start (the §6.4 winner
// rule makes re-seeding idempotent). dir is created if missing. Each file is
// written to a temp file in dir and atomically renamed into place, so a crash
// mid-write never leaves a torn envelope. Returns the number of envelopes
// written. An envelope whose encoding fails is skipped (it stays in the
// in-process store); directory/write errors abort with the count so far.
func (s *EnvelopeStore) PersistTo(dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("dht: persist mkdir %q: %w", dir, err)
	}
	written := 0
	for _, e := range s.Entries(s.nowFn()) {
		b, err := e.Env.Bytes()
		if err != nil {
			continue
		}
		final := filepath.Join(dir, hex.EncodeToString(e.Key)+".cbor")
		tmp, err := os.CreateTemp(dir, "."+hex.EncodeToString(e.Key)+".tmp-*")
		if err != nil {
			return written, fmt.Errorf("dht: persist temp file in %q: %w", dir, err)
		}
		if _, err := tmp.Write(b); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return written, fmt.Errorf("dht: persist write %q: %w", tmp.Name(), err)
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmp.Name())
			return written, fmt.Errorf("dht: persist close %q: %w", tmp.Name(), err)
		}
		if err := os.Rename(tmp.Name(), final); err != nil {
			os.Remove(tmp.Name())
			return written, fmt.Errorf("dht: persist rename %q: %w", final, err)
		}
		written++
	}
	return written, nil
}

// ----------------------------------------------------------------------
// Internal helpers — callers MUST already hold s.mu.
// ----------------------------------------------------------------------

// parentAuthorizesLocked reports whether the store's LIVE parent record of
// the incumbent authorizes a different-signer newcomer: the parent is the
// same tld_id with the incumbent's most-specific label dropped (§3.4 chain;
// display-order labels, so the parent of [www] is the TLD root []), looked
// up at its own name-derived key. Authorization is parent.Owner ==
// newcomer.Signer (the name was re-owned up the chain) OR parent.Delegation
// == newcomer.Signer (a delegated republication, e.g. after a §8.3 TLD
// transfer re-delegates the subtree). No parent locally held (TLD root,
// not-yet-cached parent, dead parent) → NOT authorized: the store pre-screens
// what it can see, and the resolver's full §3.4/§8.3 chain walk remains the
// actual authority. Caller must hold s.mu.
func (s *EnvelopeStore) parentAuthorizesLocked(newcomer, incumbent *wire.SignedEnvelope, now int64) bool {
	labels, tldID, err := naming.DecodeWireName(incumbent.Record.Name)
	if err != nil || len(labels) == 0 {
		return false // undecodable or a TLD root: no parent to ask
	}
	// EncodeWireName validates its alias argument but does not encode it
	// (wire names are labels + tld_id only), so a placeholder keeps the
	// parent's bytes identical to the original publication's.
	parentWire, err := naming.EncodeWireName(labels[1:], "x", tldID)
	if err != nil {
		return false
	}
	parentKey, err := KeyForWireName(parentWire)
	if err != nil {
		return false
	}
	var pk [constants.SHA256Len]byte
	copy(pk[:], parentKey)
	parent, ok := s.entries[pk]
	if !ok || !s.aliveLocked(parent, now) {
		return false
	}
	return bytes.Equal(parent.env.Record.Owner, newcomer.Signer) ||
		(parent.env.Record.Delegation != nil && bytes.Equal(parent.env.Record.Delegation, newcomer.Signer))
}

// aliveLocked reports whether e is still within expires + ExpiryGrace at time
// now (§6.4 step 4 / Appendix A line 980). Caller must hold s.mu.
func (s *EnvelopeStore) aliveLocked(e *entry, now int64) bool {
	if e == nil || e.env == nil || e.env.Record == nil {
		return false
	}
	return now < int64(e.env.Record.Expires)+int64(constants.ExpiryGrace)
}

// totalBytesLocked returns the sum of cached per-entry sizes. Caller must hold
// s.mu.
func (s *EnvelopeStore) totalBytesLocked() int {
	total := 0
	for _, e := range s.entries {
		total += e.size
	}
	return total
}

// evictExpiredLocked drops every entry past expires + ExpiryGrace and returns
// the count. Swept entries are retained in the §8.3 history (audit trail —
// expired predecessors remain verifiable transfer-chain links). Caller must
// hold s.mu.
func (s *EnvelopeStore) evictExpiredLocked(now int64) int {
	evicted := 0
	for k, e := range s.entries {
		if !s.aliveLocked(e, now) {
			s.retainHistoryLocked(e)
			delete(s.entries, k)
			evicted++
		}
	}
	return evicted
}

// enforceCapLocked realises the §12 "then LRU" half of the eviction policy.
// If the total cached bytes exceed maxBytes, entries are evicted in order:
//
//   - expired-first (a defensive re-check — evictExpiredLocked normally
//     already ran), EXCLUDING the protected key; then
//   - least-recently-used (smallest lastAccess first; bytewise-smaller key
//     breaks ties for determinism), EXCLUDING the protected key.
//
// The protected key (the just-put entry) is NEVER evicted by this method: it
// is excluded from the candidate set. A single oversized entry that alone
// exceeds maxBytes is retained — the LRU loop stops when fewer than two
// evictable candidates remain, so one oversized envelope does not cause an
// infinite eviction cycle. Swept entries are retained in the §8.3 history.
// Caller must hold s.mu.
func (s *EnvelopeStore) enforceCapLocked(now int64, protected [constants.SHA256Len]byte) int {
	evicted := 0
	// --- expired-first re-check (excludes the protected key) ------------
	for k, e := range s.entries {
		if k == protected {
			continue
		}
		if !s.aliveLocked(e, now) {
			s.retainHistoryLocked(e)
			delete(s.entries, k)
			evicted++
		}
	}
	// --- then LRU until under cap (or nothing evictable remains) ---------
	for s.totalBytesLocked() > s.maxBytes && len(s.entries) > 1 {
		var lruKey [constants.SHA256Len]byte
		var lruLast int64
		found := false
		for k, e := range s.entries {
			if k == protected {
				continue // the just-put entry is never an LRU candidate
			}
			if !found {
				lruKey, lruLast, found = k, e.lastAccess, true
				continue
			}
			// Smaller lastAccess wins; ties broken by bytewise-smaller key.
			if e.lastAccess < lruLast ||
				(e.lastAccess == lruLast && bytes.Compare(k[:], lruKey[:]) < 0) {
				lruKey, lruLast = k, e.lastAccess
			}
		}
		if !found {
			// Only the protected entry remains; keep it (single-oversized
			// edge case).
			break
		}
		s.retainHistoryLocked(s.entries[lruKey])
		delete(s.entries, lruKey)
		evicted++
	}
	return evicted
}

// ----------------------------------------------------------------------
// Superseded-envelope history (§8.3 audit trail)
// ----------------------------------------------------------------------

// GetHistory returns the superseded envelope whose H_record
// (SHA-256(canonical_cbor(SignedEnvelope)), §4.2) equals h, or nil when no
// such envelope is retained. This is the §8.3 transfer-chain predecessor
// lookup: a transferred record's prev_hash names exactly this hash, and the
// predecessor need not be inside its validity window (it is audit history,
// not a live record). The returned pointer is shared with the store;
// envelopes are never mutated in place (matching Get). A wrong-length h
// yields nil.
func (s *EnvelopeStore) GetHistory(h []byte) *wire.SignedEnvelope {
	if len(h) != constants.SHA256Len {
		return nil
	}
	var k [constants.SHA256Len]byte
	copy(k[:], h)
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.history[k]; ok {
		return e.env
	}
	return nil
}

// HistoryCount returns the number of superseded envelopes currently retained
// (bounded by historyMax). Entries never leave the history by record time —
// only by the bound (oldest lastAccess first).
func (s *EnvelopeStore) HistoryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.history)
}

// RetainHistory force-inserts env into the §8.3 audit history keyed by its own
// H_record, without touching the live map. It is the seeding path for
// persisted history files: a reloaded predecessor envelope must land in
// history even though Put would reject it as a stale loser of the winner rule
// (the live winner at that key is its successor). A nil/invalid env or an
// encoding failure is ignored. Retention is idempotent (re-retaining the same
// envelope refreshes its lastAccess only).
func (s *EnvelopeStore) RetainHistory(env *wire.SignedEnvelope) {
	if env == nil || env.Record == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Build a synthetic entry and reuse the bounded-insert path.
	s.retainHistoryLocked(&entry{env: env, lastAccess: s.nowFn()})
}

// HistoryEntries returns a snapshot of the retained audit-history envelopes,
// sorted by bytewise-ascending H_record for deterministic iteration. It is the
// PersistHistoryTo source (live entries come from Entries/PersistTo).
func (s *EnvelopeStore) HistoryEntries() []StoreEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]StoreEntry, 0, len(s.history))
	for k, e := range s.history {
		key := make([]byte, constants.SHA256Len)
		copy(key, k[:])
		out = append(out, StoreEntry{Key: key, Env: e.env})
	}
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i].Key, out[j].Key) < 0
	})
	return out
}

// PersistHistoryTo writes every retained audit-history envelope as
// <H_record hex>.cbor into dir (created if missing), using the same
// temp-file-then-rename atomic write as [EnvelopeStore.PersistTo]. Files are
// named by H_record — a DIFFERENT digest namespace than the live files'
// storage keys — so one directory can hold both. Returns the number written.
func (s *EnvelopeStore) PersistHistoryTo(dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("dht: persist-history mkdir %q: %w", dir, err)
	}
	written := 0
	for _, e := range s.HistoryEntries() {
		b, err := e.Env.Bytes()
		if err != nil {
			continue
		}
		final := filepath.Join(dir, hex.EncodeToString(e.Key)+".cbor")
		tmp, err := os.CreateTemp(dir, "."+hex.EncodeToString(e.Key)+".tmp-*")
		if err != nil {
			return written, fmt.Errorf("dht: persist-history temp file in %q: %w", dir, err)
		}
		if _, err := tmp.Write(b); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return written, fmt.Errorf("dht: persist-history write %q: %w", tmp.Name(), err)
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmp.Name())
			return written, fmt.Errorf("dht: persist-history close %q: %w", tmp.Name(), err)
		}
		if err := os.Rename(tmp.Name(), final); err != nil {
			os.Remove(tmp.Name())
			return written, fmt.Errorf("dht: persist-history rename %q: %w", tmp.Name(), err)
		}
		written++
	}
	return written, nil
}

// retainHistoryLocked moves a departing envelope (displaced by a winning Put
// or dropped by an expired/LRU sweep) into the bounded §8.3 history, keyed by
// its own H_record. On overflow — by count (historyMax) or total bytes
// (historyMaxBytes) — the entry with the smallest lastAccess is evicted
// (bytewise-smaller hash breaks ties for determinism, mirroring
// enforceCapLocked). An envelope whose CBOR encoding fails is silently not
// retained — retention must never fail the caller's accept/evict path.
// Caller must hold s.mu.
func (s *EnvelopeStore) retainHistoryLocked(e *entry) {
	if e == nil || e.env == nil || e.env.Record == nil {
		return
	}
	h, err := e.env.RecordHash()
	if err != nil {
		return
	}
	if e.size == 0 {
		// Synthetic entries (RetainHistory's seeding path) carry no cached
		// size; compute it once for the byte budget.
		if b, berr := e.env.Bytes(); berr == nil {
			e.size = len(b)
		}
	}
	var hk [constants.SHA256Len]byte
	copy(hk[:], h)
	// The entry pointer left the live map on every call path, so owning it
	// here is exclusive; its lastAccess freezes at the retention order.
	if old, ok := s.history[hk]; ok {
		s.historyBytes -= old.size // replace: the old bytes leave the budget
	}
	s.history[hk] = e
	s.historyBytes += e.size
	for (len(s.history) > historyMax || s.historyBytes > s.histMaxBytes) && len(s.history) > 1 {
		s.evictHistoryOldestLocked()
	}
}

// evictHistoryOldestLocked deletes the history entry with the smallest
// lastAccess (bytewise-smaller hash key breaks ties), mirroring the
// min-scan shape of enforceCapLocked, and returns its bytes to the budget.
// Caller must hold s.mu.
func (s *EnvelopeStore) evictHistoryOldestLocked() {
	var oldestKey [constants.SHA256Len]byte
	var oldest int64
	found := false
	for k, e := range s.history {
		if !found || e.lastAccess < oldest ||
			(e.lastAccess == oldest && bytes.Compare(k[:], oldestKey[:]) < 0) {
			oldestKey, oldest, found = k, e.lastAccess, true
		}
	}
	if found {
		s.historyBytes -= s.history[oldestKey].size
		delete(s.history, oldestKey)
	}
}
