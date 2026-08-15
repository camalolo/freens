// persist_roundtrip_test.go — the persistence ROUND TRIP contract (found
// live on the 7-node LAN, v0.3.1): -persist wrote snapshots but nothing
// reloaded them; a fleet-wide restart emptied every store while the .cbor
// files sat on disk. The fix: an unset -load defaults to the persist dir.
// Plus the fresh-install case (found live on the cross-internet test node,
// v0.3.2): a defaulted load on a not-yet-existing dir must be skipped, not
// a startup error — only an explicit -load errors.
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

// TestDefaultedLoadSkipsMissingDir: the DEFAULTED load dir (persist, no
// explicit -load) that does not exist yet is dropped, so a fresh install
// boots instead of failing "load: open ...: no such file or directory".
// An explicit -load is kept verbatim (missing dir = loud user error).
func TestDefaultedLoadSkipsMissingDir(t *testing.T) {
	dir := t.TempDir()
	missing := dir + "/does-not-exist"

	// Defaulted (persist) → skipped.
	if got := resolveLoadForBoot("", missing); got != "" {
		t.Errorf("defaulted load on missing dir = %q, want \"\" (skip)", got)
	}
	// Defaulted and existing → used.
	if got := resolveLoadForBoot("", dir); got != dir {
		t.Errorf("defaulted load on existing dir = %q, want %q", got, dir)
	}
	// Explicit → kept even when missing (errors later, loudly).
	if got := resolveLoadForBoot(missing, dir); got != missing {
		t.Errorf("explicit -load must win verbatim: got %q, want %q", got, missing)
	}
}
