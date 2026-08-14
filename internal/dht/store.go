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

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/wire"
)

// entry is the per-key store record: the single winning envelope plus the
// cached wire byte size (so the byte budget recomputes in O(1) per entry) and
// the last-access unix timestamp that drives the §12 LRU eviction order.
type entry struct {
	env        *wire.SignedEnvelope
	size       int   // cached len(env.Bytes()); set once at Put
	lastAccess int64 // unix seconds; refreshed on every successful Put/Get
}

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
		maxBytes: maxBytes,
		nowFn:    clock,
		entries:  make(map[[constants.SHA256Len]byte]*entry),
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
//     strictly increasing sequence). A newcomer WITHOUT prev_hash is judged by
//     the plain winner rule unchanged (backward compatibility: existing
//     publishers emit sequence-1 records with no prev_hash). A dead or absent
//     incumbent means the slot is empty, so the newcomer is accepted
//     unconditionally.
//  4. On acceptance: cache len(env.Bytes()), set lastAccess = now, then run
//     EvictExpired(now) followed by enforceCap(now, protected=key). The
//     post-accept sweeps MAY evict other entries but never the just-put key
//     (a single oversized entry that alone exceeds the cap is retained rather
//     than evicted in an infinite loop).
func (s *EnvelopeStore) Put(key []byte, env *wire.SignedEnvelope, now int64, verifySignature bool) (bool, error) {
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
	}
	// else: no incumbent, or incumbent past grace -> slot is empty -> accept.

	// --- accept: install the new winner ---------------------------------
	// Cache the byte size once so the cap budget recomputes in O(1) per entry
	// (we never recompute Bytes() on every SizeBytes() call).
	b, err := env.Bytes()
	if err != nil {
		return false, fmt.Errorf("dht: encode envelope: %w", err)
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
		// Lazy eviction of a dead entry (§6.4 step 4 / §12).
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
// administration and testability. A wrong-length key reports false.
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
// the count. Caller must hold s.mu.
func (s *EnvelopeStore) evictExpiredLocked(now int64) int {
	evicted := 0
	for k, e := range s.entries {
		if !s.aliveLocked(e, now) {
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
// infinite eviction cycle. Caller must hold s.mu.
func (s *EnvelopeStore) enforceCapLocked(now int64, protected [constants.SHA256Len]byte) int {
	evicted := 0
	// --- expired-first re-check (excludes the protected key) ------------
	for k, e := range s.entries {
		if k == protected {
			continue
		}
		if !s.aliveLocked(e, now) {
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
		delete(s.entries, lruKey)
		evicted++
	}
	return evicted
}
