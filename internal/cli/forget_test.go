// forget_test.go — `freens forget` against the in-process witness network:
// a live name gets tombstoned FIRST and its key files pruned SECOND; an
// unpublished name just gets pruned; -keep-keys revokes without deleting;
// non-interactive runs refuse without -yes (key deletion is one-way).
package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/keychain"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// forgetKeychain plants the three file kinds forget prunes and returns the
// keypair they belong to.
func forgetKeychain(t *testing.T, alias string) *crypto.Keypair {
	t.Helper()
	dir := tempHome(t)
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	files := []struct {
		path string
		body string
	}{
		{keychain.OwnerKeyPath(home.KeysDir(), alias), hexPK(kp.Seed()) + "\n"},
		{keychain.ClaimStatePath(home.KeysDir(), alias), "{}\n"},
		{filepath.Join(home.KeysDir(), alias+".rec1.key"), hexPK(kp.Seed()) + "\n"},
	}
	if err := os.MkdirAll(home.KeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := os.WriteFile(f.path, []byte(f.body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_ = dir
	return kp
}

// forgetSeedRecord publishes a live record for alias on the boot node and
// returns its storage key.
func forgetSeedRecord(t *testing.T, boot *dht.Node, kp *crypto.Keypair, alias string) []byte {
	t.Helper()
	tid, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, alias, tid)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	rec, err := wire.NewRecord(wn, kp.Public(), 1, uint64(now), uint64(now+int64(constants.RecordDefaultTTL)))
	if err != nil {
		t.Fatal(err)
	}
	rr, err := wire.A([]byte{203, 0, 113, 7}, 300)
	if err != nil {
		t.Fatal(err)
	}
	rec.RRset = []*wire.RR{rr}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := boot.Publish(ctx, env); err != nil {
		t.Fatalf("seeding %s: %v", alias, err)
	}
	key, err := dht.KeyForWireName(wn)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestForgetLiveNameRevokesThenPrunes(t *testing.T) {
	kp := forgetKeychain(t, "laurent")
	boot, peers := startWitnessNet(t, 2)
	key := forgetSeedRecord(t, boot, kp, "laurent")

	out, err := captureStdout(t, func() error {
		return cmdForget([]string{"-yes", "-peers", peers[0], "laurent"})
	})
	if err != nil {
		t.Fatalf("forget: %v\n%s", err, out)
	}
	if !strings.Contains(out, "revoked at sequence 2") || !strings.Contains(out, "key files removed: 3") {
		t.Errorf("forget output incomplete:\n%s", out)
	}
	// The tombstone is on the network (sequence 2, revoke=true) — queried
	// through a FRESH one-shot lookup, the same plumbing forget used (a
	// node's own IterativeGet walks its contacts and never consults its
	// local store, so reading through boot itself would miss what boot's
	// hGet happily answers).
	tr, err := pickTransport(peers[0])
	if err != nil {
		t.Fatal(err)
	}
	cur, err := discoverEnvelope(tr, key)
	if err != nil {
		t.Fatalf("post-forget lookup: %v", err)
	}
	if cur == nil || !cur.IsRevoked() || cur.Record.Sequence != 2 {
		t.Fatalf("network envelope = %v; want seq 2 revoked", envString(cur))
	}
	// Every keychain file for the alias is gone.
	for _, f := range []string{
		keychain.OwnerKeyPath(home.KeysDir(), "laurent"),
		keychain.ClaimStatePath(home.KeysDir(), "laurent"),
		filepath.Join(home.KeysDir(), "laurent.rec1.key"),
	} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("%s survived forget: %v", f, err)
		}
	}
}

func TestForgetNothingPublishedJustPrunes(t *testing.T) {
	forgetKeychain(t, "ghost")
	_, peers := startWitnessNet(t, 2)

	out, err := captureStdout(t, func() error {
		return cmdForget([]string{"-yes", "-peers", peers[0], "ghost"})
	})
	if err != nil {
		t.Fatalf("forget: %v\n%s", err, out)
	}
	if !strings.Contains(out, "nothing published") || !strings.Contains(out, "key files removed: 3") {
		t.Errorf("forget output incomplete:\n%s", out)
	}
	if _, err := os.Stat(keychain.OwnerKeyPath(home.KeysDir(), "ghost")); !os.IsNotExist(err) {
		t.Error("owner key survived forget")
	}
}

func TestForgetKeepKeysRevokesButKeepsFiles(t *testing.T) {
	kp := forgetKeychain(t, "laurent")
	boot, peers := startWitnessNet(t, 2)
	key := forgetSeedRecord(t, boot, kp, "laurent")

	out, err := captureStdout(t, func() error {
		return cmdForget([]string{"-yes", "-keep-keys", "-peers", peers[0], "laurent"})
	})
	if err != nil {
		t.Fatalf("forget: %v\n%s", err, out)
	}
	if !strings.Contains(out, "keys kept") {
		t.Errorf("forget output missing the keep notice:\n%s", out)
	}
	if _, err := os.Stat(keychain.OwnerKeyPath(home.KeysDir(), "laurent")); err != nil {
		t.Errorf("owner key deleted despite -keep-keys: %v", err)
	}
	tr, err := pickTransport(peers[0])
	if err != nil {
		t.Fatal(err)
	}
	cur, err := discoverEnvelope(tr, key)
	if err != nil {
		t.Fatalf("post-forget lookup: %v", err)
	}
	if cur == nil || !cur.IsRevoked() {
		t.Fatalf("name not revoked under -keep-keys: %v", envString(cur))
	}
}

// envString renders a lookup result for assertion messages.
func envString(env *wire.SignedEnvelope) string {
	if env == nil {
		return "<nil>"
	}
	return "seq " + itoaUint(env.Record.Sequence) + " revoked=" + fmtBool(env.IsRevoked())
}

func itoaUint(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func fmtBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestForgetNonInteractiveRequiresYes(t *testing.T) {
	forgetKeychain(t, "laurent")
	boot, peers := startWitnessNet(t, 2)
	_ = boot

	oldTerm := sysIsTerminal
	sysIsTerminal = func() bool { return false }
	t.Cleanup(func() { sysIsTerminal = oldTerm })

	err := cmdForget([]string{"-peers", peers[0], "laurent"})
	if err == nil || !strings.Contains(err.Error(), "-yes") {
		t.Fatalf("non-interactive forget without -yes: %v; want a -yes refusal", err)
	}
	// The refusal must have kept the key material.
	if _, err := os.Stat(keychain.OwnerKeyPath(home.KeysDir(), "laurent")); err != nil {
		t.Errorf("owner key touched despite refusal: %v", err)
	}
}
