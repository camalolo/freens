// trustbridge_test.go — the §9.5.4 privileged bridge installer's repair
// semantics: a unit written by an OLDER release must be upgraded in place
// (the boxes that need the start-limit fix are exactly the boxes that have
// units), identical content must write nothing, and a tripped bridge is
// reset-failed + restarted either way.
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stubBridgeForTest(t *testing.T) (puPath, suPath string) {
	t.Helper()
	dir := t.TempDir()
	oldPu, oldSu := pathTrustBridgePathUnit, pathTrustBridgeSvcUnit
	pathTrustBridgePathUnit = filepath.Join(dir, "freens-trust.path")
	pathTrustBridgeSvcUnit = filepath.Join(dir, "freens-trust.service")
	t.Cleanup(func() { pathTrustBridgePathUnit, pathTrustBridgeSvcUnit = oldPu, oldSu })
	return pathTrustBridgePathUnit, pathTrustBridgeSvcUnit
}

func TestTrustBridgeRepairsStaleUnits(t *testing.T) {
	pu, su := stubBridgeForTest(t)
	h := tempHome(t)

	// A unit from an older release: no start-limit relief, no trigger cap.
	oldSvc := "[Unit]\nDescription=freens TLS trust bridge (refresh the system CA bundle from the §9.5 spool)\n\n[Service]\nType=oneshot\nExecStart=/bin/true\n"
	if err := os.WriteFile(pu, []byte("[Unit]\nDescription=old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(su, []byte(oldSvc), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, _, wantSvc := trustBridgePaths(h)
	installTrustBridge()

	gotSvc, err := os.ReadFile(su)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotSvc) != wantSvc {
		t.Errorf("stale service unit not repaired in place")
	}
	if !strings.Contains(string(gotSvc), "StartLimitIntervalSec=0") {
		t.Error("repaired unit lacks the start-limit relief")
	}
	gotPu, err := os.ReadFile(pu)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gotPu), "TriggerLimitBurst=64") {
		t.Error("repaired path unit lacks the trigger cap")
	}
}

func TestTrustBridgeIdempotent(t *testing.T) {
	pu, su := stubBridgeForTest(t)
	installTrustBridge() // first run writes both units

	puFi1, _ := os.Stat(pu)
	suFi1, _ := os.Stat(su)

	// A tripped bridge must be revived even when the files already match.
	revived := false
	oldSudo := sysSudo
	sysSudo = func(args ...string) error {
		if len(args) > 0 && args[0] == "systemctl" && len(args) > 1 && args[1] == "reset-failed" {
			revived = true
		}
		return nil
	}
	t.Cleanup(func() { sysSudo = oldSudo })

	installTrustBridge() // second run: no writes, but reset-failed + start

	puFi2, _ := os.Stat(pu)
	suFi2, _ := os.Stat(su)
	if !puFi1.ModTime().Equal(puFi2.ModTime()) || !suFi1.ModTime().Equal(suFi2.ModTime()) {
		t.Error("idempotent run rewrote a current unit")
	}
	if !revived {
		t.Error("idempotent run did not reset-failed a possibly-tripped bridge")
	}
}
