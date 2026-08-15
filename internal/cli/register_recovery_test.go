// register_recovery_test.go — register's default-ON recovery (spec 5.4):
// the keyfile/policy builder helper (3 keyfiles, 2-of-3, 72 h timelock) and
// the -no-recovery opt-out, unit-tested without a live network (the
// end-to-end witness path is covered by register_test.go's in-process net).
package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/home"
)

// TestRegisterRecoveryPlanDefaults: the default plan generates exactly 3
// 0600 keyfiles <alias>.rec1/2/3.key and a 2-of-3 policy whose keys are
// those keyfiles' public keys and whose timelock is the spec default
// (259200 s = 72 h).
func TestRegisterRecoveryPlanDefaults(t *testing.T) {
	tempHome(t)
	if err := home.Ensure(); err != nil {
		t.Fatal(err)
	}
	keysDir := home.KeysDir()

	paths, pol, err := recoveryPlan(false, keysDir, "alice")
	if err != nil {
		t.Fatalf("recoveryPlan: %v", err)
	}
	if len(paths) != recoveryKeyfileCount {
		t.Fatalf("keyfiles = %v, want %d", paths, recoveryKeyfileCount)
	}
	if pol == nil {
		t.Fatal("policy nil with recovery ON")
	}
	if pol.Threshold != 2 || len(pol.Keys) != 3 {
		t.Errorf("policy = %d-of-%d, want 2-of-3", pol.Threshold, len(pol.Keys))
	}
	if pol.Timelock != constants.RecoveryTimelock {
		t.Errorf("timelock = %d, want constants.RecoveryTimelock (%d)", pol.Timelock, constants.RecoveryTimelock)
	}
	if constants.RecoveryTimelock != 259200 {
		t.Errorf("constants.RecoveryTimelock = %d, want the 72 h default 259200", constants.RecoveryTimelock)
	}
	for i, p := range paths {
		if want := filepath.Join(keysDir, "alice.rec"+string(rune('1'+i))+".key"); p != want {
			t.Errorf("keyfile[%d] = %s, want %s", i, p, want)
		}
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("keyfile %s: %v", p, err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("keyfile %s mode = %o, want 0600", p, st.Mode().Perm())
		}
		// The keyfile reloads to exactly the policy's i-th key.
		kp, err := seedKeypair("@"+p, "-test")
		if err != nil {
			t.Fatalf("keyfile %s reload: %v", p, err)
		}
		if string(kp.Public()) != string(pol.Keys[i]) {
			t.Errorf("keyfile %d yields %x, policy key %x", i, kp.Public(), pol.Keys[i])
		}
	}
}

// TestRegisterRecoveryOptOut: -no-recovery writes no files and embeds no
// policy.
func TestRegisterRecoveryOptOut(t *testing.T) {
	tempHome(t)
	if err := home.Ensure(); err != nil {
		t.Fatal(err)
	}
	paths, pol, err := recoveryPlan(true, home.KeysDir(), "alice")
	if err != nil {
		t.Fatalf("recoveryPlan(opt-out): %v", err)
	}
	if paths != nil || pol != nil {
		t.Errorf("opt-out plan = (%v, %v), want (nil, nil)", paths, pol)
	}
	entries, err := os.ReadDir(home.KeysDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("opt-out still wrote keyfiles: %v", entries)
	}
}

// TestOutboundIPv4: the UDP-dial discovery (no packet sent). Skipped on
// machines with no route at all (hermetic CI).
func TestOutboundIPv4(t *testing.T) {
	ip, err := outboundIPv4()
	if err != nil {
		t.Skipf("no outbound route in this environment: %v", err)
	}
	if ip == nil || ip.To4() == nil {
		t.Fatalf("outboundIPv4 = %v, want an IPv4", ip)
	}
}
