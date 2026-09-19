package dht

import (
	"crypto/rand"
	"crypto/sha256"
	"sort"
	"testing"

	"github.com/camalolo/freens/internal/crypto"
)

// Brute-force: heap Closest must equal the reference full-sort.
func TestClosestMatchesReference(t *testing.T) {
	kp, _ := crypto.Generate()
	self, _ := crypto.NodeID(kp.Public())
	for round := 0; round < 200; round++ {
		rt, _ := NewRoutingTable(self, 20)
		n := 3 + round%40
		ids := make([][]byte, 0, n)
		for i := 0; i < n; i++ {
			pk := make([]byte, 32)
			rand.Read(pk)
			id, _ := crypto.NodeID(pk)
			if _, err := rt.Add(&NodeContact{NodeID: id, PublicKey: pk, Addr: "127.0.0.1:1", LastSeen: 1}); err == nil {
				ids = append(ids, id)
			}
		}
		target := sha256.Sum256([]byte{byte(round)})
		for _, k := range []int{1, 5, 8, 20} {
			got := rt.Closest(target[:], k)
			ref := make([][]byte, 0, len(ids))
			for _, lc := range rt.AllContacts() { // the table's truth (Add may evict on full buckets)
				ref = append(ref, lc.NodeID)
			}
			sort.Slice(ref, func(a, b int) bool {
				return CompareDistance(target[:], ref[a], ref[b]) < 0
			})
			if len(ref) > k {
				ref = ref[:k]
			}
			if len(got) != len(ref) {
				t.Fatalf("round %d k=%d: len %d != %d", round, k, len(got), len(ref))
			}
			for i := range ref {
				if string(got[i].NodeID) != string(ref[i]) {
					t.Fatalf("round %d k=%d pos %d: got %x want %x", round, k, i, got[i].NodeID[:6], ref[i][:6])
				}
			}
		}
	}
}
