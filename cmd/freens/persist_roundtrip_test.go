// persist_roundtrip_test.go — the persistence ROUND TRIP contract (found
// live on the 7-node LAN, v0.3.1): -persist wrote snapshots but nothing
// reloaded them; a fleet-wide restart emptied every store while the .cbor
// files sat on disk. The fix: an unset -load defaults to the persist dir.
package main

import "testing"

func TestEffectiveLoadDir(t *testing.T) {
	cases := []struct {
		load, persist, want string
	}{
		{"", "", ""}, // nothing configured: no seeding
		{"", "/var/lib/freens", "/var/lib/freens"}, // the round trip: persist dir reloads
		{"/seeds", "/var/lib/freens", "/seeds"},    // explicit -load wins
		{"/seeds", "", "/seeds"},                   // load without persist (classic -load)
	}
	for _, c := range cases {
		if got := effectiveLoadDir(c.load, c.persist); got != c.want {
			t.Errorf("effectiveLoadDir(%q, %q) = %q, want %q", c.load, c.persist, got, c.want)
		}
	}
}
