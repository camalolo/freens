// Package blacklist is the v1 peer-reputation ledger: identities
// (pubkey-derived Node IDs), never IPs — UDP source addresses are spoofable,
// so an IP blacklist is slanderable (an attacker frames any IP by sending
// garbage with that source), while signatures make pubkey attribution
// unforgable. Only CRYPTOGRAPHICALLY PROVABLE violations are recorded
// (wrong blob slices, invalid signatures, fabricated PoW, reserved-claim
// witnessing); volume/flood stays in the rate limiter — pacing for
// ambiguity, exclusion only for proof. Entries expire (TTL from the last
// violation, re-violation re-arms) so one-off bugs and reformed peers
// recover; enforcement is containment (refuse their writes, never serve
// them blobs, never advertise them onward) WITHOUT routing exclusion — a
// wrong verdict must not partition the network. Propagation (witness-quorum
// shared evidence) is deliberately NOT here; v2 ships it only after v1
// evidence has run long enough to trust the classes.
package blacklist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Class names one provable violation family. The wire-verified SENDER
// identity is always the recorded party — never a payload field (an
// envelope's Signer or a claim's Claimant is attacker-chosen; only the
// transport signature binds an identity to the bytes).
type Class string

const (
	// ClassWrongSlice: a peer served blob bytes that fail the origin
	// manifest's chunk hash — self-evidencing corruption (an honest daemon
	// serves verified cache reads; injected/forged bytes fail provably).
	ClassWrongSlice Class = "blob-wrong-slice"
	// ClassBadEnvelope: a peer relayed an envelope whose Ed25519 signature
	// does not verify. Publish paths verify before relay, so an honest node
	// never puts one on the wire.
	ClassBadEnvelope Class = "sig-invalid-envelope"
	// ClassBadPoW: a witness request whose proof-of-work does not verify —
	// the nonce genuinely does not hash to the claimed prefix. Mining
	// precedes every honest registration.
	ClassBadPoW Class = "invalid-pow"
	// ClassReservedClaim: asking this node to co-sign a claim on a reserved
	// TLD/special-use name (spec §7.7 — the phishing-with-a-padlock class).
	// Refused since v0.15.0; recording makes the attempt persistent.
	ClassReservedClaim Class = "reserved-claim"
)

// DefaultTTL bounds a flag: 24 h from the LAST violation. One proven slip
// (disk corruption, a buggy build) costs a node a day of write/blob/
// advertisement service from the offended peer — reads and walks are never
// blocked (containment, not partition).
const DefaultTTL = 24 * time.Hour

// maxViolationsPerEntry caps ledger growth per identity (keep the most
// recent; the flag state only needs the latest timestamp + a sample).
const maxViolationsPerEntry = 32

// Violation is one recorded proof.
type Violation struct {
	Class  Class     `json:"class"`
	At     time.Time `json:"at"`
	Detail string    `json:"detail,omitempty"`
	// Proof is the hex SHA-256 of the offending bytes (envelope, claim
	// prefix, or served slice) — reproducible evidence, never the bytes
	// themselves (unbounded size).
	Proof string `json:"proof,omitempty"`
}

// Entry is the ledger row for one identity.
type Entry struct {
	NodeID     string      `json:"nodeId"`
	Violations []Violation `json:"violations"`
	FlaggedAt  time.Time   `json:"flaggedAt"`
	// ExpiresAt = FlaggedAt + TTL; a re-violation re-arms it.
	ExpiresAt time.Time `json:"expiresAt"`
}

// Ledger is the persistent, mutex-guarded violation store. nil Ledgers are
// legal throughout the DHT (every enforcement site is nil-safe): ledger
// open failure degrades to "no blacklist", never to "no node".
type Ledger struct {
	mu      sync.Mutex
	path    string
	ttl     time.Duration
	entries map[string]*Entry
}

// Open loads (or creates) the ledger at path (typically
// <home>/blacklist.json). Expired entries are dropped on load.
func Open(path string) (*Ledger, error) {
	if path == "" {
		return nil, errors.New("blacklist: empty path")
	}
	l := &Ledger{path: path, ttl: DefaultTTL, entries: make(map[string]*Entry)}
	data, err := readFile(path)
	if err != nil {
		return l, nil // first run: no ledger yet
	}
	var saved struct {
		Entries []*Entry `json:"entries"`
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("blacklist: corrupt ledger %s: %w", path, err)
	}
	now := time.Now()
	for _, e := range saved.Entries {
		if e == nil || now.After(e.ExpiresAt) {
			continue // expired while we were dark: decay applies
		}
		l.entries[e.NodeID] = e
	}
	return l, nil
}

// Record accrues one provable violation against nodeID (32-byte Node ID,
// as carried by every verified wire message). The identity is flagged
// IMMEDIATELY — every class in this package is cryptographically
// self-evidencing, so a single instance is verdict enough (contrast the
// rate limiter, which never feeds this ledger). Returns true if the
// identity is flagged after this call.
func (l *Ledger) Record(nodeID []byte, class Class, detail string, proof []byte) (bool, error) {
	if l == nil {
		return false, nil
	}
	if len(nodeID) != 32 {
		return false, fmt.Errorf("blacklist: node id must be 32 bytes, got %d", len(nodeID))
	}
	id := hex.EncodeToString(nodeID)
	now := time.Now()
	v := Violation{Class: class, At: now, Detail: detail}
	if len(proof) > 0 {
		sum := sha256.Sum256(proof)
		v.Proof = hex.EncodeToString(sum[:])
	}
	l.mu.Lock()
	// Merge-on-write: the daemon and one-shot CLI verbs (the upgrade
	// swarm) share the ledger FILE but hold separate in-memory maps, so a
	// plain save would silently drop the other writer's rows. Adopt any
	// file entry we lack or that outlives our copy before appending.
	l.adoptFileLocked()
	e := l.entries[id]
	if e == nil {
		e = &Entry{NodeID: id}
		l.entries[id] = e
	}
	e.Violations = append(e.Violations, v)
	if len(e.Violations) > maxViolationsPerEntry {
		e.Violations = e.Violations[len(e.Violations)-maxViolationsPerEntry:]
	}
	e.FlaggedAt = now
	e.ExpiresAt = now.Add(l.ttl)
	err := l.saveLocked()
	l.mu.Unlock()
	return true, err
}

// Flagged reports whether the identity is currently blacklisted. Expired
// entries decay lazily here (and are dropped from the map).
func (l *Ledger) Flagged(nodeID []byte) bool {
	if l == nil || len(nodeID) != 32 {
		return false
	}
	return l.FlaggedID(hex.EncodeToString(nodeID))
}

// FlaggedID is Flagged for an already-hexed Node ID (routing-table paths
// hold string IDs).
func (l *Ledger) FlaggedID(idHex string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[idHex]
	if !ok {
		return false
	}
	if time.Now().After(e.ExpiresAt) {
		delete(l.entries, idHex) // TTL decay: the peer gets its clean slate
		_ = l.saveLocked()
		return false
	}
	return true
}

// Entries returns the live (unexpired) flags, oldest flag first. Expired
// entries are dropped as a side effect.
func (l *Ledger) Entries() []Entry {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	out := make([]Entry, 0, len(l.entries))
	for id, e := range l.entries {
		if now.After(e.ExpiresAt) {
			delete(l.entries, id)
			continue
		}
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FlaggedAt.Before(out[j].FlaggedAt) })
	if len(out) != len(l.entries) {
		_ = l.saveLocked()
	}
	return out
}

// Remove clears one identity's flag (operator verb: `freens blacklist rm`).
// Reports whether a live entry was removed.
func (l *Ledger) Remove(idHex string) bool {
	if l == nil {
		return false
	}
	idHex = strings.ToLower(strings.TrimSpace(idHex))
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.entries[idHex]
	if ok {
		delete(l.entries, idHex)
	}
	if ok {
		_ = l.saveLocked()
	}
	return ok
}

// adoptFileLocked merges on-disk entries into the map: entries missing
// locally (another process recorded while we ran) or with a later expiry
// are adopted. Caller holds l.mu. Best-effort: a read failure keeps the
// in-memory verdict standing.
func (l *Ledger) adoptFileLocked() {
	if l.path == "" {
		return
	}
	data, err := readFile(l.path)
	if err != nil {
		return
	}
	var saved struct {
		Entries []*Entry `json:"entries"`
	}
	if json.Unmarshal(data, &saved) != nil {
		return
	}
	now := time.Now()
	for _, e := range saved.Entries {
		if e == nil || now.After(e.ExpiresAt) {
			continue
		}
		if cur, ok := l.entries[e.NodeID]; !ok || e.ExpiresAt.After(cur.ExpiresAt) {
			l.entries[e.NodeID] = e
		}
	}
}

// saveLocked persists the ledger; caller holds l.mu. A failed save leaves
// the in-memory verdict standing (memory is the enforcement source; disk
// is only continuity across restarts) — the error is returned for the
// caller's log.
func (l *Ledger) saveLocked() error {
	if l.path == "" {
		return nil
	}
	saved := struct {
		Entries []*Entry `json:"entries"`
	}{Entries: make([]*Entry, 0, len(l.entries))}
	for _, e := range l.entries {
		cp := *e
		saved.Entries = append(saved.Entries, &cp)
	}
	data, err := json.MarshalIndent(&saved, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(l.path, data)
}
