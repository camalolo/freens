package dht

// blacklist_test.go — the v1 peer-reputation ledger's wire behavior:
// flagged identities are refused put/witness/blob.get, never re-confirmed,
// never advertised onward, yet still SERVED reads (containment, not
// partition); provable violations are recorded against the transport-
// verified SENDER, and a ledger removal restores service.

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/blacklist"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/wire"
)

// startBlackNode is the shared fixture: a server node with a real
// (temp-file) ledger.
func startBlackNode(t *testing.T) (*Node, *blacklist.Ledger) {
	t.Helper()
	led, err := blacklist.Open(filepath.Join(t.TempDir(), "blacklist.json"))
	if err != nil {
		t.Fatal(err)
	}
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	n, err := NewNode(NodeConfig{
		Keypair:    kp,
		ListenAddr: "127.0.0.1:0",
		Store:      NewEnvelopeStore(0, nil),
		Blacklist:  led,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n, led
}

// TestBlacklistedPeerContainment: a flagged sender keeps its READS (ping
// answered) and loses its WRITES (put/witness/blob.get refused with 403),
// and is never re-confirmed in the table.
func TestBlacklistedPeerContainment(t *testing.T) {
	srv, led := startBlackNode(t)
	cli := startFlagTestNode(t, false)

	empty32 := make([]byte, 32)
	if _, err := led.Record(cli.ID(), blacklist.ClassWrongSlice, "test flag", empty32); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, err := srv.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}

	// READS stay served: the ping answers (containment, not partition)…
	if err := cli.Ping(ctx, peerOf(t, srv)); err != nil {
		t.Fatalf("flagged ping must still be answered: %v", err)
	}
	// …but the flagged sender is never re-confirmed (liveness not refreshed).
	if c := srv.rt.Get(cli.ID()); c != nil && c.ConfirmedAt != 0 {
		t.Fatalf("flagged sender refreshed in the routing table: ConfirmedAt=%d", c.ConfirmedAt)
	}

	// Writes are refused BEFORE any argument validation (403 proves the
	// gate fired; the unflagged control below proves the discriminator).
	resp, err := cli.sendQuery(ctx, addr, srv.ID(), "put", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.Y != wire.MsgTypeError {
		t.Fatalf("flagged put not refused: %+v", resp)
	}
	if code, _ := asUint64(resp.A["code"]); code != 403 {
		t.Fatalf("flagged put code = %d, want 403", code)
	}

	// Witness requests are refused the same way.
	resp, err = cli.sendQuery(ctx, addr, srv.ID(), "witness", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := asUint64(resp.A["code"]); code != 403 {
		t.Fatalf("flagged witness code = %d, want 403", code)
	}

	// blob.get: refused server-side even with a freshly minted token
	// (the read path mints tokens freely; the bulk channel checks the flag).
	sess := cli.BlobSession()
	tok, terr := sess.RefreshToken(ctx, peerOf(t, srv))
	if terr != nil {
		t.Fatal(terr)
	}
	resp, err = cli.sendQuery(ctx, addr, srv.ID(), "blob.get", map[string]any{
		"token": tok,
		"id":    make([]byte, 32),
		"off":   uint64(0),
		"len":   uint64(16),
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := asUint64(resp.A["code"]); code != 403 {
		t.Fatalf("flagged blob.get code = %d, want 403", code)
	}

	// RECOVERY: clearing the flag restores service — the same put now
	// fails on its missing token (302), proving it reached the normal path.
	if !led.Remove(hex.EncodeToString(cli.ID())) {
		t.Fatal("Remove found no entry")
	}
	resp, err = cli.sendQuery(ctx, addr, srv.ID(), "put", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := asUint64(resp.A["code"]); code != 302 {
		t.Fatalf("post-recovery put code = %d, want 302 (invalid token — the gate is gone)", code)
	}
}

// TestBlobSessionSkipsFlaggedPeers: the client-side containment — a peer
// flagged in MY ledger (e.g. it served a wrong slice last run) is refused
// before any bytes go on the wire.
func TestBlobSessionSkipsFlaggedPeers(t *testing.T) {
	srv, _ := startBlackNode(t)
	// The CLIENT holds its own ledger (as every node does): flag the
	// server in the client's copy.
	cliLed, err := blacklist.Open(filepath.Join(t.TempDir(), "cli-blacklist.json"))
	if err != nil {
		t.Fatal(err)
	}
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewNode(NodeConfig{
		Keypair:    kp,
		ListenAddr: "127.0.0.1:0",
		Store:      NewEnvelopeStore(0, nil),
		Blacklist:  cliLed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close() })
	if _, err := cliLed.Record(srv.ID(), blacklist.ClassWrongSlice, "served a wrong slice", nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := cli.BlobSession().Get(ctx, peerOf(t, srv), make([]byte, 32), 0, 16); err != ErrBlacklisted {
		t.Fatalf("flagged peer Get = %v, want ErrBlacklisted (no dial)", err)
	}
}

// TestControlPeerUnaffected is the discriminator guard: an unflagged peer's
// malformed writes fail on their CONTENT (302), never on 403.
func TestControlPeerUnaffected(t *testing.T) {
	srv, _ := startBlackNode(t)
	cli := startFlagTestNode(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, err := srv.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cli.sendQuery(ctx, addr, srv.ID(), "put", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := asUint64(resp.A["code"]); code != 302 {
		t.Fatalf("control put code = %d, want 302 (invalid token, NOT 403)", code)
	}
}

// TestBlacklistRecordsProvenViolations: each detection site flags the
// transport-verified SENDER (never a payload's claimed identity).
func TestBlacklistRecordsProvenViolations(t *testing.T) {
	srv, led := startBlackNode(t)
	cli := startFlagTestNode(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, err := srv.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}

	// (1) reserved-alias witness request → ClassReservedClaim.
	tldID := make([]byte, 32)
	claimant := make([]byte, 32)
	now := time.Now().Unix()
	resp, err := cli.sendQuery(ctx, addr, srv.ID(), "witness", map[string]any{
		"alias":    "com",
		"tld_id":   tldID,
		"claimant": claimant,
		"ts":       uint64(now),
		"nonce":    []byte{1, 2, 3},
		"pow_hash": make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := asUint64(resp.A["code"]); code != 305 {
		t.Fatalf("reserved witness code = %d, want 305", code)
	}
	entries := led.Entries()
	if len(entries) != 1 || entries[0].NodeID != hex.EncodeToString(cli.ID()) {
		t.Fatalf("reserved-claim violation not recorded against the sender: %+v", entries)
	}
	if entries[0].Violations[0].Class != blacklist.ClassReservedClaim {
		t.Fatalf("class = %q", entries[0].Violations[0].Class)
	}

	// (2) fabricated PoW → ClassBadPoW (clear the flag to observe the
	// second, independent record).
	if !led.Remove(hex.EncodeToString(cli.ID())) {
		t.Fatal("remove")
	}
	alias := "blacklistpowtest"
	ph, err := claimPrefixHash(alias, tldID, claimant, uint64(now))
	if err != nil {
		t.Fatal(err)
	}
	resp, err = cli.sendQuery(ctx, addr, srv.ID(), "witness", map[string]any{
		"alias":             alias,
		"tld_id":            tldID,
		"claimant":          claimant,
		"claim_prefix_hash": ph,
		"ts":                uint64(now),
		"nonce":             []byte{9, 9, 9},
		"pow_hash":          make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := asUint64(resp.A["code"]); code != 305 {
		t.Fatalf("bad-pow witness code = %d, want 305", code)
	}
	entries = led.Entries()
	if len(entries) != 1 || entries[0].Violations[0].Class != blacklist.ClassBadPoW {
		t.Fatalf("bad-pow violation not recorded: %+v", entries)
	}
}

// TestBlacklistRecordsBadEnvelope: a put carrying a well-formed envelope
// whose signature does not verify flags the SENDER identity — the envelope
// claims a different Signer on purpose (an attacker must not be able to
// frame the key named in the payload).
func TestBlacklistRecordsBadEnvelope(t *testing.T) {
	srv, led := startBlackNode(t)
	cli := startFlagTestNode(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, err := srv.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	// A validly-signed envelope, with the signature corrupted: decodes
	// fine, fails VerifySignature.
	env, _ := makeEnvAt(t, "blacklistbadenv", time.Now().Unix(), time.Now().Unix()+3600)
	raw, err := env.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	corrupted := append([]byte(nil), raw...)
	corrupted[len(corrupted)-1] ^= 0xff

	sess := cli.BlobSession()
	tok, err := sess.RefreshToken(ctx, peerOf(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cli.sendQuery(ctx, addr, srv.ID(), "put", map[string]any{
		"token":    tok,
		"envelope": corrupted,
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := asUint64(resp.A["code"]); code != 303 {
		t.Fatalf("bad-envelope put code = %d, want 303", code)
	}
	entries := led.Entries()
	if len(entries) != 1 || entries[0].NodeID != hex.EncodeToString(cli.ID()) {
		// The SENDER is flagged, not the envelope's Signer.
		t.Fatalf("bad-envelope violation not recorded against the sender: %+v", entries)
	}
	if entries[0].Violations[0].Class != blacklist.ClassBadEnvelope {
		t.Fatalf("class = %q", entries[0].Violations[0].Class)
	}
}

// TestAdvertiseableNodesSkipsFlagged: a flagged identity never spreads via
// {nodes} (containment of the contact, not exclusion from routing).
func TestAdvertiseableNodesSkipsFlagged(t *testing.T) {
	srv, led := startBlackNode(t)
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	id, err := crypto.NodeID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewNodeContact(id, kp.Public(), "192.0.2.9:15353", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	c.ConfirmedAt = time.Now().Unix()
	if got := len(srv.advertiseableNodes([]*NodeContact{c})); got != 1 {
		t.Fatalf("clean contact dropped: %d entries", got)
	}
	if _, err := led.Record(id, blacklist.ClassBadEnvelope, "x", nil); err != nil {
		t.Fatal(err)
	}
	if got := len(srv.advertiseableNodes([]*NodeContact{c})); got != 0 {
		t.Fatalf("flagged contact advertised onward: %d entries", got)
	}
}
