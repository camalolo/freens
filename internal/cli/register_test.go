// register_test.go pins the register flow against a real in-process DHT
// network: enough nodes that W=5 DISTINCT live witnesses exist beyond the
// single bootstrap peer (the IterativeFindNode walk must discover them), the
// owner keyfile lifecycle (generated, 0600, @file reload), and the
// @keyfile seed spec shared by every seed flag. (Moved from cmd/freens-cli;
// runs against FREENS_HOME temp dirs.)
package cli

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/tlsca"
	"github.com/camalolo/freens/internal/wire"
)

// TestRegisterEndToEnd: the full flow against 7 live in-process nodes — key
// generated to a 0600 file, PoW at floor difficulty (12 would be faster but
// register enforces the network floor; 24 bits ≈ seconds), witnesses
// discovered PAST the single bootstrap peer, publication verifiable by get.
func TestRegisterEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("mines real PoW")
	}
	tempHome(t) // recovery keyfiles + admin socket paths land in a temp home
	boot, peerArgs := startWitnessNet(t, 7)
	dir := t.TempDir()

	keyPath := filepath.Join(dir, "alice.key")
	envPath := filepath.Join(dir, "alice.tld.cbor")
	err := cmdRegister([]string{
		"alice", // positional form (the README headline command)
		"-ip", "203.0.113.5",
		"-peers", peerArgs[0],
		"-difficulty", "24",
		"-out-key", keyPath,
		"-out-dir", dir,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Keyfile: 0600, hex seed, reloads to the same key.
	st, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("keyfile: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("keyfile mode = %o, want 0600", st.Mode().Perm())
	}
	kp, err := seedKeypair("@"+keyPath, "-test")
	if err != nil {
		t.Fatalf("keyfile reload: %v", err)
	}
	tldID, _ := crypto.TldID(kp.Public())

	// The envelope on the wire: K_tld holds the record, embedded claim has
	// W distinct witnesses.
	kTld, err := dht.KeyForWireName(mustWireName(t, "alice", tldID))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	env, err := boot.IterativeGet(ctx, kTld)
	if err != nil || env == nil {
		t.Fatalf("registered record not found on the network: %v %v", env, err)
	}
	if env.Record.Sequence != 1 || len(env.Record.RRset) != 2 {
		t.Fatalf("unexpected record shape: seq=%d rrset=%d", env.Record.Sequence, len(env.Record.RRset))
	}
	// §9.5: the apex carries A + TLSCA (the owner-CA binding).
	if env.Record.RRset[0].Type != wire.RRTypeA {
		t.Fatalf("first RR type = %d, want A", env.Record.RRset[0].Type)
	}
	if env.Record.RRset[1].Type != wire.RRTypeTLSCA {
		t.Fatalf("second RR type = %d, want TLSCA (§9.5)", env.Record.RRset[1].Type)
	}
	if _, err := tlsca.ParseCertDER(env.Record.RRset[1].Rdata); err != nil {
		t.Fatalf("TLSCA rdata is not a DER certificate: %v", err)
	}
	if len(env.Record.Claim) == 0 {
		t.Fatal("record carries no embedded claim")
	}
	// Default-on recovery (spec 5.4): register embeds a 2-of-3 policy.
	if env.Record.Recovery == nil ||
		env.Record.Recovery.Threshold != recoveryThreshold ||
		len(env.Record.Recovery.Keys) != recoveryKeyfileCount ||
		env.Record.Recovery.Timelock != 259200 {
		t.Fatalf("apex recovery policy = %+v, want 2-of-3 timelock 259200", env.Record.Recovery)
	}
	if _, err := os.Stat(envPath); err != nil {
		t.Fatalf("envelope artifact: %v", err)
	}
}

// TestRegisterTooFewWitnesses: with fewer reachable witnesses than W the
// command fails with the guidance error (and no partial publication).
func TestRegisterTooFewWitnesses(t *testing.T) {
	if testing.Short() {
		t.Skip("mines real PoW")
	}
	tempHome(t)
	boot, peerArgs := startWitnessNet(t, 2) // bootstrap + 1: < W=5
	_ = boot
	err := cmdRegister([]string{
		"-alias", "lone",
		"-ip", "203.0.113.6",
		"-peers", peerArgs[0],
		"-difficulty", "24",
		"-out-key", filepath.Join(t.TempDir(), "lone.key"),
		"-out-dir", t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "witness") {
		t.Fatalf("expected witness-shortage error, got: %v", err)
	}
}

// TestRegisterAliasForms: the alias may be positional (`register alice`,
// the README headline form) or -alias; ambiguous input is a usage error
// that names the right form. These paths exit before any PoW/network work.
func TestRegisterAliasForms(t *testing.T) {
	if err := cmdRegister(nil); err == nil || !strings.Contains(err.Error(), "register <alias>") {
		t.Fatalf("no alias: want usage error naming `register <alias>`, got %v", err)
	}
	if err := cmdRegister([]string{"a", "b"}); err == nil || !strings.Contains(err.Error(), "one alias") {
		t.Fatalf("two positionals: want `one alias` error, got %v", err)
	}
	if err := cmdRegister([]string{"-alias", "x", "y"}); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("alias given twice: want `twice` error, got %v", err)
	}
}

// TestRegisterDaemonPathCooldownSafe: the daemon transport (admin socket)
// must present the SAME claim prefix hash on every retry — register passes
// claim.Timestamp, not a fresh now, so §7.3's witness cooldown treats
// retries as idempotent re-signs instead of refusing them. Serves a REAL
// admin socket from the witness net's bootstrap node; run 1 is a full
// register through it, then the SAME claim identity is re-witnessed
// directly (the retry path) and must again gather the full quorum.
// Regression: the pre-fix code passed time.Now(), degrading the signer
// count on each retry (observed 4→2→0 live).
func TestRegisterDaemonPathCooldownSafe(t *testing.T) {
	if testing.Short() {
		t.Skip("mines real PoW")
	}
	tempHome(t)
	boot, _ := startWitnessNet(t, 7)

	srv := admin.New(boot, nil, "test", testAdminLogger{})
	sock := home.AdminSock()
	_ = os.Remove(sock)
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(sock) }()
	for i := 0; i < 100 && !admin.Alive(sock); i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if !admin.Alive(sock) {
		t.Fatalf("admin server never came up: %v", <-errCh)
	}
	t.Cleanup(func() { _ = srv.Close() })

	dir := t.TempDir()
	if err := cmdRegister([]string{
		"alice", "-ip", "203.0.113.9", "-difficulty", "24",
		"-out-key", filepath.Join(dir, "alice.key"), "-out-dir", dir,
	}); err != nil {
		t.Fatalf("register run 1 (daemon transport): %v", err)
	}

	// The retry: same owner key, same persisted claim (same Timestamp =>
	// same prefix hash), re-witnessed through the daemon transport inside
	// the 3600 s cooldown window. The witnesses signed this alias already;
	// they must re-sign the IDENTICAL claim, not refuse it.
	kp, err := seedKeypair("@"+filepath.Join(dir, "alice.key"), "-owner")
	if err != nil {
		t.Fatal(err)
	}
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	claim := loadReusableClaim("alice", kp, 24)
	if claim == nil {
		t.Fatal("persisted claim not reusable after run 1")
	}
	c := maybeAdmin()
	if c == nil {
		t.Fatal("admin client gone")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	atts, err := collectWitnessesViaAdmin(ctx, c, "alice", tldID, kp.Public(), claim.Timestamp, claim.Nonce, claim.PowHash)
	if err != nil {
		t.Fatalf("re-witness (daemon transport): %v", err)
	}
	if len(atts) < constants.W {
		t.Fatalf("cooldown-locked: only %d of %d witnesses re-signed the identical claim", len(atts), constants.W)
	}
}

// testAdminLogger sinks admin-server logs (keep test output clean).
type testAdminLogger struct{}

func (testAdminLogger) Info(string, ...any)  {}
func (testAdminLogger) Warn(string, ...any)  {}
func (testAdminLogger) Debug(string, ...any) {}

// TestSeedSpecKeyfile: the @file form loads from disk; plain hex still
// works; a missing file is a usage error, not a panic.
func TestSeedSpecKeyfile(t *testing.T) {
	dir := t.TempDir()
	kp := mustTestKeypair(t)
	path := filepath.Join(dir, "k.key")
	if err := writeKeyFile(path, kp); err != nil {
		t.Fatal(err)
	}
	got, err := seedKeypair("@"+path, "-x")
	if err != nil || string(got.Public()) != string(kp.Public()) {
		t.Fatalf("keyfile spec: %v", err)
	}
	got2, err := seedKeypair(hexPK(kp.Seed()), "-x")
	if err != nil || string(got2.Public()) != string(kp.Public()) {
		t.Fatalf("hex spec: %v", err)
	}
	if _, err := seedKeypair("@"+filepath.Join(dir, "nope"), "-x"); err == nil {
		t.Fatal("missing keyfile accepted")
	}
	_ = hex.EncodeToString
}
