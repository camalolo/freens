// webui_ops_test.go — the operations engine against a REAL admin server
// backed by REAL DHT nodes (the admin_test.go fixture pattern, extended to
// a 6-node witness quorum): full register (mine → 5 witnesses → double
// publish), set-name, renew, revoke — everything the mutation endpoints
// drive.
package webui

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/keychain"
)

// opsFixture: one admin-served node + 5 peers (a full W=5 witness quorum),
// a temp keychain, and the opsEnv over them.
type opsFixture struct {
	ops  *opsEnv
	keys string
	node *dht.Node
	daem Daemon
}

func newOpsFixture(t *testing.T) *opsFixture {
	t.Helper()
	saved := claimsPoWInit()
	t.Cleanup(func() { claimsPoWRestore(saved) })

	// The admin-served node (the "daemon").
	main := startOpsNode(t)
	// Five peers cross-connected so the witness walk finds a quorum.
	for i := 0; i < 5; i++ {
		p := startOpsNode(t)
		connectOpsPeers(t, main, p)
	}
	lookup := dht.NewDHTLookup(dht.NewEnvelopeStore(0, nil), main)
	sock := startOpsAdmin(t, main, lookup)
	keys := filepath.Join(t.TempDir(), "keys")
	if err := mkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	d := NewDaemonClient(sock)
	// Warm the routing table (witness candidates) before returning.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	main.IterativeFindNode(ctx, mustKeyForClaim("ops"), 8)
	return &opsFixture{ops: &opsEnv{keysDir: keys, d: d}, keys: keys, node: main, daem: d}
}

func TestOpsRegisterFullFlow(t *testing.T) {
	f := newOpsFixture(t)
	ctx, cancelMain := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancelMain()

	var steps []string
	res, err := f.ops.Register(ctx, RegisterInput{
		Alias:      "opsflow",
		IP:         "203.0.113.90",
		Passphrase: "flow secret one", // F3: the web UI always encrypts
	}, func(s string) { steps = append(steps, s) })
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if res.Alias != "opsflow" || res.Sequence != 1 || res.IP != "203.0.113.90" {
		t.Errorf("result = %+v", res)
	}
	if res.Witnesses < 5 {
		t.Errorf("witnesses = %d, want >= 5", res.Witnesses)
	}
	if len(steps) == 0 {
		t.Error("no progress steps reported")
	}

	// The alias resolves through the daemon.
	if r, err := f.daem.Resolve(context.Background(), "opsflow"); err != nil || r == nil || !r.Found {
		t.Fatalf("resolve after register: %v %+v", err, r)
	} else {
		if got := firstAdminIPText(r.RRset); got != "203.0.113.90" {
			t.Errorf("resolved IP = %q, want 203.0.113.90", got)
		}
	}

	// The keychain got the owner key, recovery keys, and the parked claim.
	if !fileExists(keychain.OwnerKeyPath(f.keys, "opsflow")) {
		t.Error("owner key not written")
	}
	for i := 1; i <= 3; i++ {
		p := filepath.Join(f.keys, sprintf("opsflow.rec%d.key", i))
		if !fileExists(p) {
			t.Errorf("recovery key %s not written", p)
		}
	}
	if !fileExists(keychain.ClaimStatePath(f.keys, "opsflow")) {
		t.Error("parked claim not written")
	}

	// Re-register reuses the claim (no re-mine) and bumps the sequence.
	res2, err := f.ops.Register(context.Background(), RegisterInput{Alias: "opsflow", IP: "203.0.113.91", Passphrase: "flow secret one"}, nil)
	if err != nil {
		t.Fatalf("re-Register: %v", err)
	}
	if !res2.ClaimReused {
		t.Error("second register re-mined instead of reusing the parked claim")
	}
	if res2.Sequence != 2 {
		t.Errorf("re-register sequence = %d, want 2", res2.Sequence)
	}
}

func TestOpsSetNameRenewRevoke(t *testing.T) {
	f := newOpsFixture(t)
	ctx, cancelMain := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancelMain()

	// F3: the owner key is always encrypted now, so every op below must
	// present the passphrase Register chose.
	const pass = "cycle secret"
	if _, err := f.ops.Register(ctx, RegisterInput{Alias: "lifecycle", IP: "203.0.113.80", Passphrase: pass}, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Sub-name.
	if seq, err := f.ops.SetName(ctx, "www.lifecycle", "203.0.113.81", 300, pass); err != nil || seq != 1 {
		t.Fatalf("SetName www: seq=%d err=%v", seq, err)
	}
	if r, err := f.daem.Resolve(ctx, "www.lifecycle"); err != nil || r == nil || !r.Found {
		t.Fatalf("resolve www: %v %+v", err, r)
	} else if got := firstAdminIPText(r.RRset); got != "203.0.113.81" {
		t.Errorf("www IP = %q", got)
	}

	// Change it (sequence bumps).
	if seq, err := f.ops.SetName(ctx, "www.lifecycle", "203.0.113.82", 300, pass); err != nil || seq != 2 {
		t.Fatalf("SetName change: seq=%d err=%v", seq, err)
	}

	// Renew the fresh record without force: refused.
	if _, err := f.ops.Renew(ctx, "www.lifecycle", pass, false); err == nil {
		t.Fatal("renew of a fresh record without force must refuse")
	}
	if seq, err := f.ops.Renew(ctx, "www.lifecycle", pass, true); err != nil || seq != 3 {
		t.Fatalf("forced renew: seq=%d err=%v", seq, err)
	}

	// Revoke the apex (typed confirmation is the handler's job). The apex
	// carries its own sequence: register=1, so the tombstone is 2 (www's
	// sequence above is a different key's).
	if seq, err := f.ops.Revoke(ctx, "lifecycle", pass); err != nil || seq != 2 {
		t.Fatalf("Revoke: seq=%d err=%v", seq, err)
	}
	if r, err := f.daem.Resolve(ctx, "lifecycle"); err != nil || r == nil || !r.Revoked {
		t.Fatalf("resolve revoked: %v %+v", err, r)
	}
	// And the tombstone bumps the next publish's sequence base.
	if seq, err := f.ops.SetName(ctx, "lifecycle", "203.0.113.83", 300, pass); err != nil || seq != 3 {
		t.Fatalf("post-revoke SetName: seq=%d err=%v", seq, err)
	}
}

func TestOpsRegisterBadInputs(t *testing.T) {
	f := newOpsFixture(t)
	// Passphrase supplied so each failure below is the INPUT's fault, not
	// F3's empty-passphrase gate.
	if _, err := f.ops.Register(context.Background(), RegisterInput{Alias: "BAD!", IP: "1.2.3.4", Passphrase: "bad inputs"}, nil); err == nil {
		t.Error("uppercase alias must fail")
	}
	if _, err := f.ops.Register(context.Background(), RegisterInput{Alias: "ok", IP: "not-an-ip", Passphrase: "bad inputs"}, nil); err == nil {
		t.Error("garbage IP must fail")
	}
	if _, err := f.ops.SetName(context.Background(), "no-owner.example", "1.2.3.4", 300, ""); err == nil {
		t.Error("set-name without an owner key must fail")
	}
}

// encrypted-owner-key path: SetName with the right passphrase works, empty
// fails with the ask-for-passphrase error.
func TestOpsEncryptedOwnerKey(t *testing.T) {
	f := newOpsFixture(t)
	ctx, cancelMain := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancelMain()

	if _, err := f.ops.Register(ctx, RegisterInput{Alias: "locked", IP: "203.0.113.70", Passphrase: "open sesame"}, nil); err != nil {
		t.Fatalf("Register (encrypted): %v", err)
	}
	_, err := f.ops.SetName(ctx, "www.locked", "203.0.113.71", 300, "")
	if err == nil {
		t.Fatal("SetName without the passphrase must fail")
	}
	var ek errEncryptedKey
	if !errorsAs(err, &ek) || ek.alias != "locked" {
		t.Fatalf("err = %v, want errEncryptedKey{locked}", err)
	}
	if _, err := f.ops.SetName(ctx, "www.locked", "203.0.113.71", 300, "open sesame"); err != nil {
		t.Fatalf("SetName with passphrase: %v", err)
	}
	if _, err := f.ops.SetName(ctx, "www2.locked", "203.0.113.72", 300, "wrong"); err == nil {
		t.Fatal("wrong passphrase must fail")
	}
}

// --- fixture helpers (test-local, mirrors of admin_test.go patterns) ---

func startOpsNode(t *testing.T) *dht.Node {
	t.Helper()
	return startDHTNodeT(t)
}

func connectOpsPeers(t *testing.T, a, b *dht.Node) {
	t.Helper()
	aAddr, _ := a.LocalAddr()
	bAddr, _ := b.LocalAddr()
	if err := a.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(a.PublicKey(), aAddr.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.Ping(ctx, dht.Peer{Addr: bAddr.String(), PublicKey: b.PublicKey()}); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func startOpsAdmin(t *testing.T, node *dht.Node, lookup *dht.DHTLookup) string {
	t.Helper()
	srv := admin.New(node, lookup, "v-ops-test", slog.New(slog.NewTextHandler(discard{}, nil)))
	sock := filepath.Join(t.TempDir(), "admin.sock")
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(sock) }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if admin.Alive(sock) {
			return sock
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("admin socket never came up")
	return ""
}

// --- tiny local shims (kept here so the file is self-contained) ---

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func claimsPoWInit() int                     { return powDifficultyInit() }
func claimsPoWRestore(v int) func()          { return func() { powDifficultySet(v) } }
func fileExists(p string) bool               { _, err := statFile(p); return err == nil }
func mkdirAll(p string, m uint32) error      { return mkdirAllImpl(p, os.FileMode(m)) }
func sprintf(format string, a ...any) string { return fmtSprintf(format, a...) }
func errorsAs(err error, target any) bool    { return errorsAsImpl(err, target) }
func mustKeyForClaim(alias string) []byte {
	k, err := dht.KeyForClaim(alias)
	if err != nil {
		panic(err)
	}
	return k
}
func startDHTNodeT(t *testing.T) *dht.Node {
	t.Helper()
	kp := genKP(t)
	n, err := dht.NewNode(dht.NodeConfig{
		Keypair:      kp,
		ListenAddr:   "127.0.0.1:0",
		Store:        dht.NewEnvelopeStore(0, nil),
		GetRateLimit: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.Close() })
	return n
}
