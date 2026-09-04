// Package dht — gossip.go implements the Appendix A.4 difficulty machinery:
//
//	"Every POW_RETARGET_BLOCK accepted claims, computing nodes adjust:
//	    D_new = D_old + clamp(round(log2(target_block_span / actual_block_span)), -2, +2)
//	 where target_block_span = POW_RETARGET_BLOCK x 600 s. Blocks completing
//	 FASTER than the target span raise D (claims arriving too quickly — the
//	 mass-squatting scenario); slower blocks lower it, floored at
//	 POW_DIFFICULTY_INIT. Nodes gossip the current D in witness responses;
//	 clients use the median of the GET_CLOSEST nodes' advertised values.
//	 Forks in D are harmless: claims are individually verified against *any*
//	 historically valid D >= POW_DIFFICULTY_INIT recorded with the claim."
//
// (v0.8.0 corrected form; the v0.1 draft inverted the ratio and compared a
// whole block's span against the per-claim target, so a registration flood
// lowered D and a quiet network ratcheted it up.)
//
// Two halves live here:
//
//   - The OWN difficulty (difficultyState): starts at constants.PoWDifficultyInit
//     (24 bits), counts accepted claims (each successful hWitness co-sign is
//     one acceptance, §7.4 registration step 3), and every
//     constants.PoWRetargetBlock (256) accepted claims recomputes D via
//     constants.RetargetDifficulty over the wall-clock span of the block,
//     resetting the block start. It is stamped into every witness response
//     ("Nodes gossip the current D in witness responses").
//
//   - The OBSERVED difficulties: a ring of the last difficultyRingSize (8 =
//     WITNESS_SET) values received in witness responses from peers
//     (Node.CollectWitnesses feeds it), from which DHTLookup.NetworkDifficulty
//     computes the median ("clients use the median of the ... advertised
//     values") — falling back to the node's own current D when nothing has
//     been observed yet.
package dht

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/camalolo/freens/internal/constants"
)

// difficultyRingSize caps the observed-difficulty ring at the WITNESS_SET
// size (8): the freshest witness responses, oldest dropped first.
const difficultyRingSize = 8

// maxObservedDifficulty is the sanity ceiling for an observed value (SHA-256
// difficulty cannot exceed its 256-bit digest; anything larger is garbage).
const maxObservedDifficulty = 256

// difficultyState is one node's Appendix A.4 difficulty state: the node's own
// current D, the accepted-claim counter and block-start timestamp driving the
// POW_RETARGET_BLOCK retarget, and the ring of recently observed peer
// difficulties. All methods are safe for concurrent use.
type difficultyState struct {
	mu         sync.Mutex
	current    int   // own current difficulty (bits); starts at PoWDifficultyInit
	accepted   int   // accepted claims since the current block started
	blockStart int64 // unix seconds when the current retarget block started
	observed   []int // last difficultyRingSize observed peer difficulties, oldest first
}

// newDifficultyState returns a state at the initial difficulty
// (constants.PoWDifficultyInit) whose retarget block starts at now.
func newDifficultyState(now int64) *difficultyState {
	return &difficultyState{
		current:    constants.PoWDifficultyInit,
		blockStart: now,
	}
}

// currentDifficulty returns the node's own current difficulty (bits).
func (d *difficultyState) currentDifficulty() int {
	if d == nil {
		return constants.PoWDifficultyInit
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.current
}

// recordAccepted counts one accepted claim (a successful witness co-sign) and
// performs the Appendix A.4 retarget when the block completes: every
// constants.PoWRetargetBlock acceptances, D is adjusted by
// clamp(round(log2(target_block_span / actual_block_span)), -2, +2) where
// actual_block_span is the wall-clock span now-blockStart and the target span
// is PoWRetargetBlock × PoWTargetInterval (v0.8.0: fast blocks raise D,
// slow blocks lower it — see constants.RetargetDifficulty). The block then
// restarts at now. now is the node's own clock.
func (d *difficultyState) recordAccepted(now int64) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.accepted++
	if d.accepted >= constants.PoWRetargetBlock {
		d.current = constants.RetargetDifficulty(
			d.current,
			int(now-d.blockStart),
			constants.PoWRetargetBlock*constants.PoWTargetInterval,
		)
		d.blockStart = now
		d.accepted = 0
	}
}

// observe records one difficulty value advertised by a peer in a witness
// response. Values outside [PoWDifficultyInit, 256] are ignored: A.4 only
// recognises historically valid D >= POW_DIFFICULTY_INIT, and a difficulty
// above the 256-bit digest width is meaningless — a lying witness cannot
// poison the median with values no honest node would advertise.
func (d *difficultyState) observe(v int) {
	if d == nil || v < constants.PoWDifficultyInit || v > maxObservedDifficulty {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.observed = append(d.observed, v)
	if len(d.observed) > difficultyRingSize {
		// Drop the oldest (the ring keeps the LAST difficultyRingSize values).
		d.observed = d.observed[len(d.observed)-difficultyRingSize:]
	}
}

// observedSnapshot returns a copy of the observed ring (oldest first,
// unsorted) — for diagnostics and tests.
func (d *difficultyState) observedSnapshot() []int {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]int(nil), d.observed...)
}

// medianObserved returns the median of the observed ring: the element at
// index (n-1)/2 of the ascending-sorted values — the exact middle for an odd
// count, the LOWER of the two middle elements for an even count. The
// lower-middle convention is chosen (over an average) so the answer is always
// a difficulty some peer actually advertised, never a synthetic value. It
// returns (0, false) when nothing has been observed.
func (d *difficultyState) medianObserved() (int, bool) {
	if d == nil {
		return 0, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.observed) == 0 {
		return 0, false
	}
	sorted := append([]int(nil), d.observed...)
	sort.Ints(sorted)
	return sorted[(len(sorted)-1)/2], true
}

// ---------------------------------------------------------------------------
// Appendix A.4 state persistence (v0.8.0)
// ---------------------------------------------------------------------------

// difficultyStateJSON is the persisted form of difficultyState: without it a
// restart reset the node to PoWDifficultyInit with a fresh block — an
// attacker could dodge a raised difficulty (or donate a lowered one) with a
// reboot, and honest nodes lost their accepted-claim progress. The observed
// ring rides along (losing it only resets the gossiped median until fresh
// witness responses arrive).
type difficultyStateJSON struct {
	Current    int   `json:"current"`
	Accepted   int   `json:"accepted"`
	BlockStart int64 `json:"block_start"`
	Observed   []int `json:"observed,omitempty"`
}

// snapshot returns the persisted form under the state's lock.
func (d *difficultyState) snapshot() difficultyStateJSON {
	if d == nil {
		return difficultyStateJSON{Current: constants.PoWDifficultyInit}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return difficultyStateJSON{
		Current:    d.current,
		Accepted:   d.accepted,
		BlockStart: d.blockStart,
		Observed:   append([]int(nil), d.observed...),
	}
}

// restore loads a persisted snapshot (defensively floored at
// PoWDifficultyInit and sanity-capped; accepted is clamped below one block).
func (d *difficultyState) restore(j difficultyStateJSON) {
	if d == nil {
		return
	}
	cur := j.Current
	if cur < constants.PoWDifficultyInit || cur > maxObservedDifficulty {
		cur = constants.PoWDifficultyInit
	}
	acc := j.Accepted
	if acc < 0 || acc >= constants.PoWRetargetBlock {
		acc = 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.current = cur
	d.accepted = acc
	d.blockStart = j.BlockStart
	if len(j.Observed) > 0 {
		obs := make([]int, 0, difficultyRingSize)
		for _, v := range j.Observed {
			if v >= constants.PoWDifficultyInit && v <= maxObservedDifficulty {
				obs = append(obs, v)
			}
		}
		if len(obs) > difficultyRingSize {
			obs = obs[len(obs)-difficultyRingSize:]
		}
		d.observed = obs
	}
}

// SaveDifficultyState atomically writes the node's Appendix A.4 difficulty
// state (own D, block counter/start, observed ring) to path as JSON.
func (n *Node) SaveDifficultyState(path string) error {
	if n == nil || n.diff == nil {
		return nil
	}
	b, err := json.Marshal(n.diff.snapshot())
	if err != nil {
		return fmt.Errorf("dht: encode difficulty state: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("dht: write difficulty state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("dht: rename difficulty state: %w", err)
	}
	return nil
}

// LoadDifficultyState restores a persisted difficulty state. A missing file
// is not an error (first boot); a malformed one is (corrupt state should be
// loud, not silently resettable).
func (n *Node) LoadDifficultyState(path string) error {
	if n == nil || n.diff == nil {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("dht: read difficulty state: %w", err)
	}
	var j difficultyStateJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return fmt.Errorf("dht: decode difficulty state %q: %w", path, err)
	}
	n.diff.restore(j)
	return nil
}

// NetworkDifficulty returns the difficulty a claimant should mine at: the
// median of the difficulties observed in peers' witness responses (Appendix
// A.4: "clients use the median of the ... advertised values") when any have
// been observed, else this node's own current difficulty. A node-less lookup
// (an island resolver) reports the initial POW_DIFFICULTY_INIT.
//
// Even-length samples take the lower-middle element (see
// difficultyState.medianObserved).
func (l *DHTLookup) NetworkDifficulty() int {
	if l == nil || l.node == nil {
		return constants.PoWDifficultyInit
	}
	if med, ok := l.node.diff.medianObserved(); ok {
		return med
	}
	return l.node.diff.currentDifficulty()
}
