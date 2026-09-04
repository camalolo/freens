package cli

// register_reserved_test.go — the §7.7 registration gate on `freens register`
// (naming.CheckRegisterable): a claim on a delegated ICANN TLD / IANA
// special-use alias is refused BEFORE any key generation, PoW mining, or
// network traffic, with the -allow-reserved hint; the flag lets a deliberate
// operator past the gate (the run then continues into the normal flow and
// fails later, on transport, in the test sandbox).

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/naming"
)

func TestRegisterRefusesReservedAlias(t *testing.T) {
	tempHome(t)
	for _, alias := range []string{"com", "localhost", "net", "de"} {
		err := cmdRegister([]string{alias, "-ip", "203.0.113.6"})
		if err == nil {
			t.Fatalf("register %s: want the §7.7 reserved-alias error, got nil", alias)
		}
		if !errors.Is(err, naming.ErrReserved) {
			t.Fatalf("register %s: error %v does not wrap naming.ErrReserved", alias, err)
		}
		for _, want := range []string{alias, "reserved", "-allow-reserved"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("register %s: error %q does not mention %q", alias, err, want)
			}
		}
		// The gate fires before any key material exists.
		if _, statErr := os.Stat(filepath.Join(home.KeysDir(), alias+".key")); !os.IsNotExist(statErr) {
			t.Fatalf("register %s: key material exists after the refusal (gate must fire before keygen)", alias)
		}
	}
}

// TestRegisterAllowReservedPassesGate: with -allow-reserved the SAME alias
// gets past the §7.7 gate — the run proceeds and fails later (test sandbox:
// no daemon on the admin socket), never with the reserved-alias refusal.
func TestRegisterAllowReservedPassesGate(t *testing.T) {
	if testing.Short() {
		t.Skip("generates a key + touches the keychain")
	}
	tempHome(t)
	err := cmdRegister([]string{"com", "-allow-reserved", "-ip", "203.0.113.6"})
	if err == nil {
		t.Skip("register somehow completed in the sandbox — unexpected but not a gate failure")
	}
	if errors.Is(err, naming.ErrReserved) {
		t.Fatalf("-allow-reserved did not pass the gate: %v", err)
	}
}
