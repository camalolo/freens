package dht

// convergedWitnessSet regression tests (v0.14.1): the witness set a walk
// reports MUST include the walking node's own ID. A walk-from-self never
// "reaches" itself, so the pre-fix set was really "the 8 closest OTHER
// nodes" — and any claim this node had WITNESSED could never pass §7.3
// membership from this node (its own attestation counted 0/5, the other
// four landed 4/5). Found live fleet-wide: the seed witnessed every
// registration and then NXDOMAINed all of them but its own name.

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/camalolo/freens/internal/constants"
)

// idsForClaim derives test node IDs deterministically from tag bytes.
func idFor(tag string) []byte {
	sum := sha256.Sum256([]byte("converged-witness-test:" + tag))
	return sum[:]
}

func contactFor(tag string) *NodeContact {
	return &NodeContact{NodeID: idFor(tag)}
}

func TestConvergedWitnessSetIncludesSelf(t *testing.T) {
	const alias = "selfmember"
	key, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}

	// The fleet incident, minimally: SEVEN answered contacts (so only self
	// is missing from a full WITNESS_SET), and a claim whose five witnesses
	// are self + four of the contacts. Before the fix: 7 reached < 8 ⇒ nil
	// set here, or — on a busier table — a set without self that left the
	// quorum at 4/5. After the fix the set is complete and the quorum holds.
	selfID := idFor("the-seed-itself")
	answered := map[string]*NodeContact{
		hex.EncodeToString(idFor("w1")): contactFor("w1"),
		hex.EncodeToString(idFor("w2")): contactFor("w2"),
		hex.EncodeToString(idFor("w3")): contactFor("w3"),
		hex.EncodeToString(idFor("w4")): contactFor("w4"),
		hex.EncodeToString(idFor("o1")): contactFor("o1"),
		hex.EncodeToString(idFor("o2")): contactFor("o2"),
		hex.EncodeToString(idFor("o3")): contactFor("o3"),
	}
	if len(answered) >= constants.WitnessSet {
		t.Fatal("test setup: answered must be below the witness-set size so self is load-bearing")
	}

	set := convergedWitnessSet(answered, key, selfID)
	if set == nil {
		t.Fatal("self did not complete the witness set (7 contacts + self >= 8)")
	}
	if !set[hex.EncodeToString(selfID)] {
		t.Error("witness set does not contain the walking node's own ID")
	}

	// The §7.3 quorum math with the returned set: self + the four witness
	// contacts are all members ⇒ 5/5.
	witnesses := [][]byte{selfID, idFor("w1"), idFor("w2"), idFor("w3"), idFor("w4")}
	counted := 0
	for _, w := range witnesses {
		if set[hex.EncodeToString(w)] {
			counted++
		}
	}
	if counted < constants.W {
		t.Errorf("quorum counting got %d/%d with the self-inclusive set", counted, constants.W)
	}
}

func TestConvergedWitnessSetSparseStillNil(t *testing.T) {
	key, err := KeyForClaim("sparse")
	if err != nil {
		t.Fatal(err)
	}
	answered := map[string]*NodeContact{
		hex.EncodeToString(idFor("s1")): contactFor("s1"),
		hex.EncodeToString(idFor("s2")): contactFor("s2"),
	}
	// 2 contacts + self = 3 < WitnessSet: the density guard must still hold
	// (self-inclusion must not manufacture a set out of a partition).
	if set := convergedWitnessSet(answered, key, idFor("lonely")); set != nil {
		t.Fatalf("sparse view produced a set (%d entries), want nil", len(set))
	}
}

func TestConvergedWitnessSetSelfDisplacedWhenFar(t *testing.T) {
	key, err := KeyForClaim("faraway")
	if err != nil {
		t.Fatal(err)
	}
	// Eight answered contacts, self FAR from the key: the set is the eight
	// answered nodes and self must NOT displace any of them (self-inclusion
	// is accuracy, not self-preference).
	answered := map[string]*NodeContact{}
	for _, tag := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		id := idFor(tag)
		answered[hex.EncodeToString(id)] = contactFor(tag)
	}
	farSelf := make([]byte, 32)
	for i := range farSelf {
		farSelf[i] = ^key[i] // bitwise complement: maximally far from key
	}
	set := convergedWitnessSet(answered, key, farSelf)
	if set == nil {
		t.Fatal("dense view yielded nil")
	}
	if set[hex.EncodeToString(farSelf)] {
		t.Error("far-away self made it into the witness set")
	}
	if len(set) != constants.WitnessSet {
		t.Errorf("set size = %d, want %d", len(set), constants.WitnessSet)
	}
}
