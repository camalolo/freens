// Package dht — evidence.go adds the §8.4 recovery-evidence machinery
// (specifications.md lines 689-707): the side-table that retains
// wire.RecoveryEvidence blobs alongside the envelopes they were published
// with, the serving side (hGet piggyback), the publishing side
// (Node.PublishWithEvidence), and the resolver-side fetch
// (DHTLookup.LookupEvidence: local table first, then an iterative DHT get
// asking peers for evidence by hash — mirroring history.go's LookupByHash).
//
// §8.4 declares the recovery record R2 "published like any record (sequence
// +1, `recovery` fields updated)" but its PROOF — the threshold-of-keys
// declaration — lives OUTSIDE the record (the §4.1 schema has no field for
// it), so it travels and is retained as a separate hash-addressed object,
// keyed by H_record(R2): exactly the key the §8.4 hop of the authority-chain
// walk (wire.VerifyAuthorityChainWithHandoffs) fetches it by.
package dht

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/wire"
)

// evidenceLookup pins the §8.4 fetch shape DHTLookup exposes.
var _ interface {
	LookupEvidence(ctx context.Context, recordHash []byte) (*wire.RecoveryEvidence, error)
} = (*DHTLookup)(nil)

// RecoveryEvidence is LookupEvidence under the resolver-side §8.4 interface's
// method name, so DHTLookup structurally satisfies the resolver's optional
// RecoveryEvidenceResolver (the same capability-discovery pattern as
// LookupClaim / ClaimResolver).
func (l *DHTLookup) RecoveryEvidence(ctx context.Context, recordHash []byte) (*wire.RecoveryEvidence, error) {
	return l.LookupEvidence(ctx, recordHash)
}

// ---------------------------------------------------------------------------
// EnvelopeStore — §8.4 evidence retention
// ---------------------------------------------------------------------------

// PutEvidence validates and retains a §8.4 recovery-evidence blob under
// recordHash, the H_record (§4.2) of the envelope the evidence was published
// WITH (the recovery record itself). recordHash must be exactly 32 bytes and
// the blob must decode via wire.DecodeRecoveryEvidence; anything else is an
// error and leaves the table untouched. The table is capped at evidenceMax
// entries, evicting the oldest-inserted first (FIFO). Retention is
// idempotent (re-put refreshes the bytes, keeping the original queue
// position).
func (s *EnvelopeStore) PutEvidence(recordHash []byte, evidence []byte) error {
	return s.putEvidenceValidated(recordHash, evidence)
}

// PutEvidenceRaw is the daemon-seeding load path for persisted evidence
// files (<dir>/evidence/<hex H_record>.cbor written by PersistEvidenceTo):
// the same decode-validation as PutEvidence, spelled separately so the -load
// code path reads clearly. The raw bytes are stored as-is (they were
// canonical when persisted).
func (s *EnvelopeStore) PutEvidenceRaw(recordHash, raw []byte) error {
	return s.putEvidenceValidated(recordHash, raw)
}

// putEvidenceValidated is the shared body of PutEvidence/PutEvidenceRaw.
func (s *EnvelopeStore) putEvidenceValidated(recordHash, raw []byte) error {
	if len(recordHash) != constants.SHA256Len {
		return fmt.Errorf("dht: evidence key must be %d bytes, got %d", constants.SHA256Len, len(recordHash))
	}
	if _, err := wire.DecodeRecoveryEvidence(raw); err != nil {
		return fmt.Errorf("dht: invalid recovery evidence: %w", err)
	}
	var k [constants.SHA256Len]byte
	copy(k[:], recordHash)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putEvidenceLocked(k, append([]byte(nil), raw...))
	return nil
}

// GetEvidence returns the retained §8.4 evidence for recordHash, or nil when
// none is retained. A wrong-length hash yields nil. The returned slice is
// shared with the store (evidence is immutable once retained).
func (s *EnvelopeStore) GetEvidence(recordHash []byte) []byte {
	if len(recordHash) != constants.SHA256Len {
		return nil
	}
	var k [constants.SHA256Len]byte
	copy(k[:], recordHash)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evidence[k]
}

// EvidenceCount returns the number of retained §8.4 evidence blobs (bounded
// by evidenceMax).
func (s *EnvelopeStore) EvidenceCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.evidence)
}

// PersistEvidenceTo writes every retained §8.4 evidence blob as
// <H_record hex>.cbor into dir (created if missing), using the same
// temp-file-then-rename atomic write as [EnvelopeStore.PersistTo] /
// PersistHistoryTo. The filename IS the H_record key, so the daemon's -load
// seeding can PutEvidenceRaw it back under the same key (the §8.4 evidence
// analogue of the §8.3 history round trip). Returns the number written.
func (s *EnvelopeStore) PersistEvidenceTo(dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("dht: persist-evidence mkdir %q: %w", dir, err)
	}
	// Snapshot + sort bytewise for deterministic iteration (mirrors
	// HistoryEntries).
	s.mu.Lock()
	type kv struct {
		k   [constants.SHA256Len]byte
		raw []byte
	}
	snapshot := make([]kv, 0, len(s.evidence))
	for k, raw := range s.evidence {
		snapshot = append(snapshot, kv{k, raw})
	}
	s.mu.Unlock()
	sort.Slice(snapshot, func(i, j int) bool {
		return bytes.Compare(snapshot[i].k[:], snapshot[j].k[:]) < 0
	})
	written := 0
	for _, e := range snapshot {
		final := filepath.Join(dir, hex.EncodeToString(e.k[:])+".cbor")
		tmp, err := os.CreateTemp(dir, "."+hex.EncodeToString(e.k[:])+".tmp-*")
		if err != nil {
			return written, fmt.Errorf("dht: persist-evidence temp file in %q: %w", dir, err)
		}
		if _, err := tmp.Write(e.raw); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return written, fmt.Errorf("dht: persist-evidence write %q: %w", tmp.Name(), err)
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmp.Name())
			return written, fmt.Errorf("dht: persist-evidence close %q: %w", tmp.Name(), err)
		}
		if err := os.Rename(tmp.Name(), final); err != nil {
			os.Remove(tmp.Name())
			return written, fmt.Errorf("dht: persist-evidence rename %q: %w", final, err)
		}
		written++
	}
	return written, nil
}

// putEvidenceLocked inserts raw under k, tracking first-insertion order for
// the FIFO bound; on overflow the oldest-inserted entry is dropped. Caller
// must hold s.mu.
func (s *EnvelopeStore) putEvidenceLocked(k [constants.SHA256Len]byte, raw []byte) {
	if _, ok := s.evidence[k]; !ok {
		s.evidenceOrder = append(s.evidenceOrder, k)
	}
	s.evidence[k] = raw
	for len(s.evidence) > evidenceMax && len(s.evidenceOrder) > 0 {
		oldest := s.evidenceOrder[0]
		s.evidenceOrder = s.evidenceOrder[1:]
		delete(s.evidence, oldest)
	}
}

// recoveryAcceptableLocked decides rule 3's §8.4 hand-off gate of
// PutWithEvidence: whether a prev_hash-asserting newcomer signed by a key
// other than the incumbent's owner may displace the incumbent as a §8.4
// recovery hand-off. The evidence must decode, the newcomer must have the
// §8.4 shape (owner == signer, and the declaration names that same key as
// NewOwnerPK), and a QUORUM of the incumbent's §5.4 policy must have signed
// the declaration anchored at H_record(incumbent). The timelock is verified
// at now = ev.NotBefore (trivially true) on purpose — see PutWithEvidence.
//
// When no evidence bytes accompany the Put (a plain Put — e.g. daemon
// start-up re-seeding <persist>/*.cbor), the gate falls back to THIS store's
// retained evidence table keyed by the newcomer's own H_record: seedFromDir
// loads <persist>/evidence/*.cbor alongside the records, so a restart
// re-accepts its own recovery winners without the original hPut's in-band
// evidence arg. The quorum is still fully re-verified here, so the fallback
// grants nothing the in-band path would not. Caller must hold s.mu.
func (s *EnvelopeStore) recoveryAcceptableLocked(newEnv, prevEnv *wire.SignedEnvelope, evidence []byte) bool {
	if newEnv == nil || newEnv.Record == nil || prevEnv == nil || prevEnv.Record == nil {
		return false
	}
	if len(evidence) == 0 {
		// Restart/seed path: look up evidence retained for THIS record.
		hNew, err := newEnv.RecordHash()
		if err != nil {
			return false
		}
		var k [constants.SHA256Len]byte
		copy(k[:], hNew)
		evidence = s.evidence[k]
		if len(evidence) == 0 {
			return false // no evidence anywhere: not a §8.4 recovery
		}
	}
	ev, err := wire.DecodeRecoveryEvidence(evidence)
	if err != nil {
		return false
	}
	// §8.4 shape: the NEW primary key both owns and signs the hand-off record
	// (the opposite of §8.3, where the previous owner signs).
	if !bytes.Equal(newEnv.Signer, newEnv.Record.Owner) {
		return false
	}
	// The declaration must name THIS record's new key as the new primary.
	if !bytes.Equal(ev.NewOwnerPK, newEnv.Signer) {
		return false
	}
	hPrev, err := prevEnv.RecordHash()
	if err != nil {
		return false
	}
	// Quorum over the incumbent's policy; timelock trivially passed
	// (now = NotBefore) — effectiveness is decided at resolve time.
	return wire.VerifyRecovery(prevEnv.Record.Recovery, ev, hPrev, ev.NotBefore)
}

// ---------------------------------------------------------------------------
// Node — §8.4 publishing
// ---------------------------------------------------------------------------

// retainEvidence stores a §8.4 evidence blob under env's H_record,
// best-effort (a failure is logged, never fatal: retention must not fail the
// enclosing accept/publish path).
func (n *Node) retainEvidence(env *wire.SignedEnvelope, evidence []byte) {
	if len(evidence) == 0 {
		return
	}
	h, err := env.RecordHash()
	if err != nil {
		return
	}
	if err := n.store.PutEvidence(h, evidence); err != nil {
		n.log.Debug("dht: retain recovery evidence failed", "err", err)
	}
}

// PublishWithEvidence is [Node.Publish] for a §8.4 recovery record: the
// envelope is stored/published at its K_tld/K_name key with the recovery
// evidence riding along as an extra "evidence" arg on every put (the peer's
// hPut retains it, keyed by the envelope's H_record, only when it keeps the
// envelope). Unlike Publish — which talks to peers only — the local store is
// updated too (PutWithEvidence): the publishing node's OWN resolver must be
// able to re-verify the §8.4 chain it just created, so the winning envelope
// AND its evidence are retained locally. Best-effort like Publish: nil iff at
// least one peer accepted the envelope (ErrNoPeers with no peers); a local
// rejection (e.g. a stale local incumbent) does not abort the network
// publication.
func (n *Node) PublishWithEvidence(ctx context.Context, env *wire.SignedEnvelope, evidence []byte) error {
	if env == nil || env.Record == nil {
		return errors.New("dht: nil envelope")
	}
	if _, err := wire.DecodeRecoveryEvidence(evidence); err != nil {
		return fmt.Errorf("dht: invalid §8.4 recovery evidence: %w", err)
	}
	key, err := KeyForWireName(env.Record.Name)
	if err != nil {
		return err
	}
	// Local side: install as winner through the §8.4-aware gate and retain
	// the evidence next to it.
	if accepted, aerr := n.store.PutWithEvidence(key, env, n.now(), true, evidence); aerr == nil && accepted {
		n.retainEvidence(env, evidence)
	}
	return n.publishKeyed(ctx, key, env, evidence)
}

// ---------------------------------------------------------------------------
// DHTLookup — §8.4 evidence fetch (local table first, then network)
// ---------------------------------------------------------------------------

// LookupEvidence returns the §8.4 recovery evidence retained for recordHash
// (the H_record of the recovery record the evidence accompanies): the local
// store's evidence table first ([EnvelopeStore.GetEvidence]), then — when the
// lookup has a node — an iterative DHT get on recordHash AS the key, mirroring
// [DHTLookup.LookupByHash]'s network path (peers answer from their own
// evidence table via the hGet "evidence" piggyback, including on an
// envelope-miss hash probe). A nil node degrades to local only. Returns
// (nil, nil) when the evidence is available neither locally nor across the
// reachable network — an unprovable §8.4 hop. Fetched evidence is cached
// into the local table (it is immutable, hash-addressed audit data, like the
// §8.3 history entries LookupByHash deliberately does NOT cache into the live
// map — the evidence table is not the live map).
func (l *DHTLookup) LookupEvidence(ctx context.Context, recordHash []byte) (*wire.RecoveryEvidence, error) {
	if len(recordHash) != constants.SHA256Len {
		return nil, fmt.Errorf("dht: record hash must be %d bytes, got %d", constants.SHA256Len, len(recordHash))
	}
	if raw := l.store.GetEvidence(recordHash); raw != nil {
		return wire.DecodeRecoveryEvidence(raw)
	}
	if l.node == nil {
		return nil, nil // island: local evidence only.
	}
	c, cancel := context.WithTimeout(ctx, dhtLookupTimeout)
	defer cancel()
	raw, err := l.node.iterativeGetEvidence(c, recordHash)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	ev, derr := wire.DecodeRecoveryEvidence(raw)
	if derr != nil {
		return nil, nil // not the requested evidence: a miss, not an error.
	}
	_ = l.store.PutEvidenceRaw(recordHash, raw)
	return ev, nil
}

// iterativeGetEvidence performs the §8.4 evidence analogue of IterativeGet:
// an iterative Kademlia lookup on recordHash, querying ALPHA=3 contacts per
// round in parallel, merging closer contacts, and returning the first
// "evidence" arg any peer offers. Returns (nil, nil) when no reachable peer
// has evidence for the hash.
func (n *Node) iterativeGetEvidence(ctx context.Context, recordHash []byte) ([]byte, error) {
	shortlist := append([]*NodeContact(nil), n.rt.Closest(recordHash, constants.K)...)
	if len(shortlist) == 0 {
		return nil, nil // no peers known: an island.
	}
	queried := make(map[string]bool, len(shortlist))
	for round := 0; round < maxLookupRounds; round++ {
		// Nearest-first so the ALPHA un-queried we pick are the closest.
		sort.SliceStable(shortlist, func(i, j int) bool {
			return CompareDistance(recordHash, shortlist[i].NodeID, shortlist[j].NodeID) < 0
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
			raw   []byte
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
				pctx, cancel := context.WithTimeout(ctx, lookupProbeTimeout)
				defer cancel()
				raw, nodes, err := n.evidenceFromPeer(pctx, recordHash, c)
				results[i] = res{raw, nodes, err}
			}(i, c)
		}
		wg.Wait()

		for i, r := range results {
			// Kademlia failure handling (§6.2), as in IterativeGet.
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
			if r.raw != nil {
				return r.raw, nil
			}
		}
	}
	return nil, nil
}

// evidenceFromPeer issues a single get(recordHash) RPC to c and parses the
// §8.4 "evidence" piggyback and the closer-contacts list out of the response.
// A y="e" response is a successful exchange (no evidence offered).
func (n *Node) evidenceFromPeer(ctx context.Context, recordHash []byte, c *NodeContact) ([]byte, []*NodeContact, error) {
	addr, err := net.ResolveUDPAddr("udp", c.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve: %w", err)
	}
	resp, err := n.sendQuery(ctx, addr, c.NodeID, "get", map[string]any{"key": recordHash})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Y == wire.MsgTypeError {
		return nil, nil, nil
	}
	raw, _ := resp.A["evidence"].([]byte)
	var nodes []*NodeContact
	if v, ok := resp.A["nodes"]; ok {
		nodes = parseNodes(v)
	}
	return raw, nodes, nil
}
