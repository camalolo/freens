package naming

import (
	"errors"
	"strings"
	"testing"
)

// TestIsReservedTLD spot-checks both data kinds (§7.7): delegated root-zone
// TLDs (famous + ccTLD + an IDN A-label from the IANA snapshot) and the
// hand-maintained special-use names, against near-miss non-reserved aliases.
func TestIsReservedTLD(t *testing.T) {
	cases := []struct {
		alias string
		want  bool
	}{
		{"com", true}, {"net", true}, {"org", true}, {"de", true},
		{"fr", true}, {"io", true}, {"dev", true}, {"zip", true},
		{"foo", true},                      // delegated in a recent gTLD round — the resolver suite's old canonical test alias had to move off it
		{"xn--vermgensberatung-pwb", true}, // a real IDN gTLD A-label
		// special-use
		{"localhost", true}, {"onion", true}, {"test", true},
		{"example", true}, {"invalid", true}, {"local", true},
		{"arpa", true}, {"home", true},
		// the project's own namespace (v0.16): not TLD-shaped, but the name
		// this software, its docs, its tooling and the Windows suffix rescue
		// already mean — a stranger must never own `www.freens`.
		{"freens", true},
		// case is the caller's concern (aliases arrive normalized), but the
		// data is lowercase and IsReservedTLD does no folding.
		{"COM", false},
		// not reserved
		{"camalolo", false}, {"minipc", false},
		{"foo-bar", false}, {"abc123", false}, {"comm", false},
		{"com2", false}, {"", false},
	}
	for _, c := range cases {
		if got := IsReservedTLD(c.alias); got != c.want {
			t.Errorf("IsReservedTLD(%q) = %v, want %v", c.alias, got, c.want)
		}
	}
	if r := ReservedReason("com"); r == "" {
		t.Error(`ReservedReason("com") is empty, want a reason`)
	}
	if r := ReservedReason("freens"); r == "" || !strings.Contains(r, "project") {
		t.Errorf(`ReservedReason("freens") = %q, want a project-namespace reason`, r)
	}
	if r := ReservedReason("camalolo"); r != "" {
		t.Errorf(`ReservedReason("camalolo") = %q, want ""`, r)
	}
}

// TestReservedTLDsDataSanity: the whole embedded set must be lowercase LDH
// (every entry is itself a VALID alias — the gate refuses names that would
// otherwise pass ValidateAlias), free of duplicates, and big enough that a
// broken generation run cannot go unnoticed.
func TestReservedTLDsDataSanity(t *testing.T) {
	if len(reservedTLDs) < 1400 {
		t.Fatalf("reservedTLDs has %d entries, want >= 1400 (IANA snapshot ~1438 + special-use)", len(reservedTLDs))
	}
	for a := range reservedTLDs {
		if a != strings.ToLower(a) {
			t.Errorf("entry %q is not lowercase", a)
		}
		if _, err := ValidateAlias(a); err != nil {
			t.Errorf("entry %q is not a valid alias: %v", a, err)
		}
	}
	// Map keys cannot duplicate, but assert a couple of exact members so a
	// regeneration that drops the special-use additions cannot pass silently.
	for _, must := range []string{"com", "de", "localhost", "onion", "home"} {
		if !IsReservedTLD(must) {
			t.Errorf("reservedTLDs is missing required entry %q", must)
		}
	}
	if ReservedTLDsSnapshot == "" {
		t.Error("ReservedTLDsSnapshot is empty — stamp the IANA version")
	}
}

// TestCheckRegisterable: the mint-side funnel — valid + unreserved returns
// the normalized alias; a reserved alias wraps ErrReserved with the override
// hint; an invalid alias still reports the §3.2 error (not the gate).
func TestCheckRegisterable(t *testing.T) {
	norm, err := CheckRegisterable("Camalolo")
	if err != nil || norm != "camalolo" {
		t.Fatalf("CheckRegisterable(Camalolo) = %q, %v; want camalolo, nil", norm, err)
	}
	_, err = CheckRegisterable("com")
	if err == nil || !errors.Is(err, ErrReserved) {
		t.Fatalf("CheckRegisterable(com) = %v, want an ErrReserved wrap", err)
	}
	for _, want := range []string{"com", "spec §7.7", "-allow-reserved"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if _, err := CheckRegisterable("bad_alias"); err == nil || errors.Is(err, ErrReserved) {
		t.Errorf("CheckRegisterable(bad_alias) = %v, want a plain §3.2 error", err)
	}
}
