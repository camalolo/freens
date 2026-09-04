package webui

// webui_reserved_test.go — the §7.6 registration gate on the web UI register
// form (ops.Register): a claim on a delegated ICANN TLD / IANA special-use
// alias is refused with the ErrReserved-flavored user error and NO key
// material is written. The web UI deliberately has NO override — the error
// points to the CLI's -allow-reserved, the deliberate operator's path.
// The gate fires before any daemon/network contact, so no fixture is needed.

import (
	"errors"
	"strings"
	"testing"

	"github.com/camalolo/freens/internal/keychain"
	"github.com/camalolo/freens/internal/naming"
)

func TestOpsRegisterRefusesReservedAlias(t *testing.T) {
	keys := t.TempDir()
	ops := &opsEnv{keysDir: keys}
	for _, alias := range []string{"com", "localhost", "org"} {
		res, err := ops.Register(nil, RegisterInput{Alias: alias, IP: "203.0.113.55", Passphrase: "not empty"}, nil)
		if err == nil {
			t.Fatalf("register %s via web UI: want the §7.6 reserved-alias error, got %+v", alias, res)
		}
		if !errors.Is(err, naming.ErrReserved) {
			t.Fatalf("register %s: err %v does not wrap naming.ErrReserved", alias, err)
		}
		if !strings.Contains(err.Error(), "-allow-reserved") {
			t.Fatalf("register %s: err %q does not point at the CLI override", alias, err)
		}
		if fileExists(keychain.OwnerKeyPath(keys, alias)) {
			t.Fatalf("register %s: owner key written despite the refusal", alias)
		}
	}
}
