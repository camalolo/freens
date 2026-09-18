package dht

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/camalolo/freens/internal/crypto"
)

// BenchmarkClosest pins the per-inbound-packet cost of the full-table sort
// in rt.Closest (called by hFindNode and hGet on the read loop).
func BenchmarkClosest(b *testing.B) {
	for _, n := range []int{64, 256, 1024} {
		b.Run(string(rune('0'+n/64))+"x64", func(b *testing.B) {
			kp, _ := crypto.Generate()
			self, _ := crypto.NodeID(kp.Public())
			rt, _ := NewRoutingTable(self, 20)
			for i := 0; i < n; i++ {
				pk := sha256.Sum256([]byte{byte(i), byte(i >> 8), 0xAA})
				id, _ := crypto.NodeID(ed25519.PublicKey(pk[:]))
				c, _ := NewNodeContact(id, pk[:], "192.0.2.1:15353", 1)
				_, _ = rt.Add(c)
			}
			target := sha256.Sum256([]byte("target"))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = rt.Closest(target[:], 8)
			}
		})
	}
}
