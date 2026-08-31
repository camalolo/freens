// uninstall_test.go — `freens uninstall`: every active freens* unit is
// disabled (from the stubbed list-units), unit files and OS wiring are
// reversed, keys/state survive without -purge, -purge is the gated one-way
// step, and -trust removes the §9.5 anchors from their (sandboxed) paths.
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/camalolo/freens/internal/home"
)

func TestUninstallEndToEnd(t *testing.T) {
	tempHome(t)
	rec := stubSysForTest(t)

	// A prior setup's unit file exists in the sandbox unit dir.
	if _, err := captureStdout(t, func() error { return cmdSetup([]string{}) }); err != nil {
		t.Fatalf("setup: %v", err)
	}

	out, err := captureStdout(t, func() error { return cmdUninstall([]string{}) })
	if err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	if !rec.ran("sudo", "-n", "systemctl", "disable", "--now", "freens.service") {
		t.Errorf("daemon unit not disabled: %v", rec.cmds)
	}
	if !rec.ran("sudo", "-n", "rm", "-f", pathSystemctlUnit) {
		t.Errorf("unit file removal not run: %v", rec.cmds)
	}
	if !rec.ran("sudo", "-n", "nft", "delete", "table", "ip", nftTableName) {
		t.Errorf(":53 redirect table not removed: %v", rec.cmds)
	}
	if _, err := os.Stat(home.KeysDir()); err != nil {
		t.Errorf("keys dir removed by uninstall: %v", err)
	}
	if !strings.Contains(out, "KEPT") {
		t.Errorf("uninstall output does not say keys/store were kept:\n%s", out)
	}
	if !strings.Contains(out, "trust root is still installed") {
		t.Errorf("uninstall output does not mention the -trust follow-up:\n%s", out)
	}
}

func TestUninstallPurgeDeletesState(t *testing.T) {
	dir := tempHome(t)
	rec := stubSysForTest(t)
	marker := filepath.Join(home.KeysDir(), "camalolo.key")
	if err := os.MkdirAll(home.KeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("aa\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := captureStdout(t, func() error { return cmdUninstall([]string{"-purge", "-yes"}) })
	if err != nil {
		t.Fatalf("uninstall -purge: %v\n%s", err, out)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("state dir survived -purge: %v", err)
	}
	if !strings.Contains(out, "purged") {
		t.Errorf("output missing the purge line:\n%s", out)
	}
	if rec == nil {
		t.Error("no recorder")
	}
}

func TestUninstallPurgeNonInteractiveRequiresYes(t *testing.T) {
	tempHome(t)
	stubSysForTest(t)
	oldTerm := sysIsTerminal
	sysIsTerminal = func() bool { return false }
	t.Cleanup(func() { sysIsTerminal = oldTerm })

	err := cmdUninstall([]string{"-purge"})
	if err == nil || !strings.Contains(err.Error(), "-yes") {
		t.Fatalf("-purge without -yes: %v; want a -yes refusal", err)
	}
	if _, err := os.Stat(home.Dir()); err != nil {
		t.Errorf("state dir touched despite refusal: %v", err)
	}
}

func TestUninstallTrustRemovesAnchors(t *testing.T) {
	tempHome(t)
	rec := stubSysForTest(t)

	sandbox := t.TempDir()
	oldGlob := trustSystemCertGlob
	trustSystemCertGlob = filepath.Join(sandbox, "freens-*.crt")
	t.Cleanup(func() { trustSystemCertGlob = oldGlob })

	anchor := filepath.Join(sandbox, "freens-local-root.crt")
	if err := os.WriteFile(anchor, []byte("-----BEGIN CERTIFICATE-----"), 0o644); err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(home.Dir(), "tls", "spool")
	if err := os.MkdirAll(spool, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spool, "freens-cross-camalolo.crt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := captureStdout(t, func() error { return cmdUninstall([]string{"-trust", "-yes"}) })
	if err != nil {
		t.Fatalf("uninstall -trust: %v\n%s", err, out)
	}
	if !rec.ran("sudo", "-n", "rm", "-f", anchor) {
		t.Errorf("trust anchor removal not run: %v", rec.cmds)
	}
	if !rec.ran("sudo", "-n", "update-ca-certificates") {
		t.Errorf("CA bundle rebuild not run: %v", rec.cmds)
	}
	if _, err := os.Stat(filepath.Join(home.Dir(), "tls")); !os.IsNotExist(err) {
		t.Errorf("tls tree survived -trust: %v", err)
	}
	if !strings.Contains(out, "NSS") {
		t.Errorf("output missing the NSS hint:\n%s", out)
	}
}
