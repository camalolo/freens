// keychain_test.go — locks the on-disk keychain semantics shared by the CLI
// and the web UI: alias discovery, plaintext/encrypted load+save round trips
// with the exact sentinel errors, inventory, recovery plan, and the parked
// reusable claim.
package keychain

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/wire"
)

func mustKP(t *testing.T) *crypto.Keypair {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func TestAliasesAndInventory(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"alice.key", "alice.rec1.key", "alice.rec2.key", "bob.key", "notes.txt", "sub"} {
		if name == "sub" {
			if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := Aliases(dir); len(got) != 2 || got[0] != "alice" || got[1] != "bob" {
		t.Errorf("Aliases = %v, want [alice bob]", got)
	}
	inv := Inventory(dir)
	if len(inv) != 4 {
		t.Fatalf("Inventory rows = %d, want 4 (alice owner+2 recovery, bob owner): %+v", len(inv), inv)
	}
	if inv[0].Alias != "alice" || inv[0].Kind != "owner" {
		t.Errorf("row0 = %+v, want alice/owner", inv[0])
	}
	if inv[1].Kind != "recovery" || inv[2].Kind != "recovery" {
		t.Errorf("recovery rows wrong: %+v", inv[1:])
	}
	if Aliases(filepath.Join(dir, "does-not-exist")) != nil {
		t.Error("Aliases on a missing dir must return nil, not panic")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	kp := mustKP(t)
	p := filepath.Join(dir, "sub", "owner.key")

	// Plaintext form.
	if err := Save(p, kp, ""); err != nil {
		t.Fatal(err)
	}
	if IsEncryptedPath(p) {
		t.Error("plaintext save reported encrypted")
	}
	got, err := Load(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Public(), kp.Public()) {
		t.Error("plaintext round trip lost the key")
	}

	// Encrypted form: no passphrase -> ErrNeedsPassphrase; wrong -> ErrWrongPassphrase.
	enc := filepath.Join(dir, "owner-enc.key")
	if err := Save(enc, kp, "hunter2"); err != nil {
		t.Fatal(err)
	}
	if !IsEncryptedPath(enc) {
		t.Fatal("encrypted save reported plaintext")
	}
	if _, err := Load(enc, ""); !errors.Is(err, ErrNeedsPassphrase) {
		t.Errorf("empty passphrase err = %v, want ErrNeedsPassphrase", err)
	}
	if _, err := Load(enc, "wrong"); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("wrong passphrase err = %v, want ErrWrongPassphrase", err)
	}
	got, err = Load(enc, "hunter2")
	if err != nil || !bytes.Equal(got.Public(), kp.Public()) {
		t.Fatalf("encrypted round trip: %v", err)
	}

	// Missing file -> ErrNotFound.
	if _, err := Load(filepath.Join(dir, "nope.key"), ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing file err = %v, want ErrNotFound", err)
	}
}

func TestRecoveryPlan(t *testing.T) {
	dir := t.TempDir()
	if paths, pol, _ := RecoveryPlan(true, dir, "alice", "", 3, 2, 3600); paths != nil || pol != nil {
		t.Error("noRecovery must short-circuit to nil")
	}
	paths, pol, err := RecoveryPlan(false, dir, "alice", "", 3, 2, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 3 {
		t.Fatalf("paths = %d, want 3", len(paths))
	}
	for i, p := range paths {
		if filepath.Base(p) != "alice.rec1.key" && filepath.Base(p) != "alice.rec2.key" && filepath.Base(p) != "alice.rec3.key" {
			t.Errorf("path[%d] = %q", i, p)
		}
	}
	if pol == nil || pol.Threshold != 2 || len(pol.Keys) != 3 {
		t.Fatalf("policy = %+v, want threshold 2 over 3 keys", pol)
	}
	if _, _, err := RecoveryPlan(false, dir, "alice", "", 2, 3, 3600); err == nil {
		t.Error("threshold > count must error")
	}
}

// TestReusableClaimRoundTrip parks a real mined claim and reloads it under
// the exact conditions register's retry path relies on.
func TestReusableClaimRoundTrip(t *testing.T) {
	dir := t.TempDir()
	kp := mustKP(t)
	// Production mines at the network baseline (24 bits, ~4 s); this test
	// mines at 24 with the generous production iteration cap.
	const diff = constants.PoWDifficultyInit
	c, err := claims.MineAliasClaim("alice", kp, 2_000_000, diff, 500_000_000, 16)
	if err != nil {
		t.Fatal(err)
	}
	SaveReusableClaim(dir, "alice", c)

	got := LoadReusableClaim(dir, "alice", kp, diff)
	if got == nil {
		t.Fatal("parked claim did not reload")
	}
	if got.Timestamp != c.Timestamp || !bytes.Equal(got.Nonce, c.Nonce) || !got.VerifyPoW(diff) {
		t.Error("reloaded claim lost its PoW identity")
	}
	// A sub-baseline claim (fast-test difficulty 8) parks at the baseline
	// per difficultyOf and can NEVER reload (VerifyPoW at 24 fails on an
	// 8-bit PoW) — same semantics the CLI always had: only production-
	// difficulty claims are reusable.
	fast, err := claims.MineAliasClaim("alice", kp, 2_000_000, 8, 2_000_000, 16)
	if err != nil {
		t.Fatal(err)
	}
	SaveReusableClaim(dir, "fast", fast)
	if LoadReusableClaim(dir, "fast", kp, difficultyOf(fast)) != nil {
		t.Error("sub-baseline parked claim must not reload (recorded difficulty exceeds its PoW)")
	}
	// Wrong difficulty / wrong key / wrong alias -> nil (re-mine).
	if LoadReusableClaim(dir, "alice", kp, diff+1) != nil {
		t.Error("difficulty mismatch must invalidate the parked claim")
	}
	if LoadReusableClaim(dir, "alice", mustKP(t), diff) != nil {
		t.Error("owner mismatch must invalidate the parked claim")
	}
	if LoadReusableClaim(dir, "bob", kp, diff) != nil {
		t.Error("alias mismatch must invalidate the parked claim")
	}
}

func TestBuildBackup(t *testing.T) {
	dir := t.TempDir()
	kp := mustKP(t)
	for _, n := range []string{"alice.key", "alice.rec1.key", "alice.claim.json"} {
		if err := Save(filepath.Join(dir, n), kp, ""); err != nil && n != "alice.claim.json" {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(dir, "alice.claim.json"), []byte("{}"), 0o600)
	os.WriteFile(filepath.Join(dir, "evil.sh"), []byte("rm -rf /"), 0o600) // must be excluded

	var buf bytes.Buffer
	files, err := BuildBackup(&buf, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("bundled %v, want the 3 keychain files", files)
	}
	gz, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
		if strings.HasPrefix(hdr.Name, "/") || strings.Contains(hdr.Name, "..") {
			t.Errorf("dangerous entry %q", hdr.Name)
		}
	}
	seen := map[string]bool{}
	for _, n := range append(names, "RESTORE.txt") {
		seen[n] = true
	}
	for _, want := range []string{"alice.key", "alice.rec1.key", "alice.claim.json", "RESTORE.txt"} {
		if !seen[want] {
			t.Errorf("archive missing %q (have %v)", want, names)
		}
	}
	if seen["evil.sh"] {
		t.Error("non-keychain file leaked into the backup")
	}

	// Empty / missing keychain -> error, not an empty archive.
	if _, err := BuildBackup(&bytes.Buffer{}, t.TempDir()); err == nil {
		t.Error("empty keychain must error")
	}
}

// Compile-time: wire.RecoveryPolicyWire is the policy type register embeds.
var _ *wire.RecoveryPolicyWire = nil
