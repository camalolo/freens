// renew_store_test.go — the auto-renewal stall regression (found live
// 2026-08-31 on the seed box): renewOnce published seq N+1 to peers but
// never installed it in the LOCAL store, so every later tick re-read the
// stale N, re-signed a different envelope at the SAME sequence+1, and got
// refused everywhere ("accepted by 0 of 7 peers") while the network record
// starved toward expiry. After the fix the local store carries the renewal,
// the next tick sees a fresh record, and the sequence advances exactly once.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

func renewTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// renewTestNode boots one DHT node on loopback with an inspectable store.
func renewTestNode(t *testing.T) (*dht.Node, *dht.EnvelopeStore) {
	t.Helper()
	store := dht.NewEnvelopeStore(0, nil)
	node, err := dht.NewNode(dht.NodeConfig{
		Keypair:               renewTestKeypair(t),
		ListenAddr:            "127.0.0.1:0",
		Store:                 store,
		BucketRefreshInterval: -1,
		RepublishInterval:     -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	return node, store
}

// renewKeychain points FREENS_HOME at a temp dir with one plaintext owner
// keyfile (the hex form auto-renew reads) and returns its keypair.
func renewKeychain(t *testing.T) *crypto.Keypair {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("FREENS_HOME", dir)
	kp := renewTestKeypair(t)
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys", "camalolo.key"),
		[]byte(hex.EncodeToString(kp.Seed())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return kp
}

// nearExpiryRecord signs a claim-less apex record inside ShouldRenew's
// final window (the last 20% of its own lifetime).
func nearExpiryRecord(t *testing.T, kp *crypto.Keypair, seq uint64, now int64) (*wire.SignedEnvelope, []byte) {
	t.Helper()
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, "camalolo", tldID)
	if err != nil {
		t.Fatal(err)
	}
	created := now - int64(constants.RecordDefaultTTL)
	expires := now + int64(constants.RecordDefaultTTL)/10
	rec, err := wire.NewRecord(wn, kp.Public(), seq, uint64(created), uint64(expires))
	if err != nil {
		t.Fatal(err)
	}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	key, err := dht.KeyForWireName(wn)
	if err != nil {
		t.Fatal(err)
	}
	return env, key
}

// TestRenewOnceStoresRenewalLocally is the stall regression: pass 1 must
// leave seq N+1 in BOTH stores; pass 2 (local copy now fresh) must not
// touch the sequence again.
func TestRenewOnceStoresRenewalLocally(t *testing.T) {
	kp := renewKeychain(t)
	daemon, daemonStore := renewTestNode(t)
	peer, peerStore := renewTestNode(t)

	peerAddr, err := peer.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.AddPeer(peer.PublicKey(), peerAddr.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := daemon.Ping(ctx, dht.Peer{Addr: peerAddr.String(), PublicKey: peer.PublicKey()}); err != nil {
		t.Fatalf("bootstrap ping: %v", err)
	}
	cancel()

	now := time.Now().Unix()
	env, key := nearExpiryRecord(t, kp, 7, now)
	if ok, err := daemonStore.Put(key, env, now, false); !ok || err != nil {
		t.Fatalf("seeding the near-expiry record: %v, %v", ok, err)
	}

	renewOnce(daemon, daemonStore, renewTestLogger())

	got, err := daemonStore.Get(key, time.Now().Unix())
	if err != nil || got == nil {
		t.Fatalf("local store lost the record: %v, %v", got, err)
	}
	if got.Record.Sequence != 8 {
		t.Fatalf("local sequence = %d; want 8 (the renewal must be stored locally)", got.Record.Sequence)
	}
	peerGot, err := peerStore.Get(key, time.Now().Unix())
	if err != nil || peerGot == nil || peerGot.Record.Sequence != 8 {
		t.Fatalf("peer did not receive the renewal: %v, %v", peerGot, err)
	}

	// Pass 2: the local record is fresh now — the sequence must NOT move.
	renewOnce(daemon, daemonStore, renewTestLogger())
	got, err = daemonStore.Get(key, time.Now().Unix())
	if err != nil || got == nil || got.Record.Sequence != 8 {
		t.Fatalf("second pass moved the stalled sequence: seq=%v, %v", got, err)
	}
}

// TestStorePutIdenticalRecordAccepted: a put whose record is ALREADY stored
// (identical envelope — the replica-refresh case) must report success, not
// refusal, while a strictly newer record still wins and a stale re-put of
// an OLD sequence cannot resurrect itself over a live higher sequence.
func TestStorePutIdenticalRecordAccepted(t *testing.T) {
	s := dht.NewEnvelopeStore(0, nil)
	kp := renewTestKeypair(t)
	now := time.Now().Unix()

	env3, key := nearExpiryRecord(t, kp, 3, now)
	if ok, err := s.Put(key, env3, now, false); !ok || err != nil {
		t.Fatalf("first put: %v, %v", ok, err)
	}
	// The identical envelope again (replica refresh): accepted, not refused.
	if ok, err := s.Put(key, env3, now, false); !ok || err != nil {
		t.Fatalf("identical re-put: %v, %v — republishing an already-stored record is a successful put", ok, err)
	}
	// The stored record is unchanged by the idempotent put.
	got, _ := s.Get(key, now)
	gotHash, hashErr := got.RecordHash()
	wantHash, wantErr := env3.RecordHash()
	if hashErr != nil || wantErr != nil || !bytes.Equal(gotHash, wantHash) {
		t.Fatal("idempotent put displaced the stored record")
	}

	// A strictly newer record wins as always.
	env4, _ := nearExpiryRecord(t, kp, 4, now)
	if ok, err := s.Put(key, env4, now, false); !ok || err != nil {
		t.Fatalf("higher-sequence put: %v, %v", ok, err)
	}
	// ... and a re-put of the OLD sequence must NOT resurrect over it (the
	// identical-check compares against the CURRENT incumbent).
	if ok, err := s.Put(key, env3, now, false); ok || err != nil {
		t.Fatalf("stale re-put accepted: %v, %v", ok, err)
	}
	got, _ = s.Get(key, now)
	if got == nil || got.Record.Sequence != 4 {
		t.Fatalf("sequence after stale re-put = %v; want 4", got.Record.Sequence)
	}
}

func renewTestKeypair(t *testing.T) *crypto.Keypair {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}
