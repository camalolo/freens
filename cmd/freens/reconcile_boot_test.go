// reconcile_boot_test.go — the reconciler's boot tick (v0.18): the first
// tick of reconcileLoop runs immediately at daemon start and IS the old
// boot lease warm-up (v0.16.7) — keyspace walks plus network-verify of
// every own envelope, re-publishing lost leases before the first client
// query. The post-restart window used to run cold: first queries ate
// walks, and a renewal whose publish died with the old process stayed
// lost until the first verify, surfacing hours later as an NXDOMAIN that
// looked like an upgrade bug (2026-09-13/14).
package main

import (
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/dht"
)

// TestReconcileBootTickRepublishesLostLease: the persisted store holds a
// fresh lease the network lost (the upgrade-restart shape) — the boot
// tick must re-publish the SAME envelope to the network without touching
// the sequence.
func TestReconcileBootTickRepublishesLostLease(t *testing.T) {
	kp := renewKeychain(t)
	daemon, daemonStore := renewTestNode(t)
	peer, peerStore := renewTestNode(t)
	connectTestPair(t, daemon, peer)

	now := time.Now().Unix()
	env, key := freshRecord(t, kp, 5, now)
	if ok, err := daemonStore.Put(key, env, now, false); !ok || err != nil {
		t.Fatalf("seeding the fresh record locally: %v, %v", ok, err)
	}

	reconcileTick(daemon, daemonStore, renewTestLogger(), true)

	got, err := peerStore.Get(key, time.Now().Unix())
	if err != nil || got == nil {
		t.Fatalf("the network did not receive the lost lease: %v, %v", got, err)
	}
	if got.Record.Sequence != 5 {
		t.Fatalf("network sequence = %d, want 5 (the boot tick re-publishes, never re-signs)", got.Record.Sequence)
	}
}

// TestReconcileBootTickNoKeychainIsQuiet: a relay node with no keys must
// return immediately without touching the network.
func TestReconcileBootTickNoKeychainIsQuiet(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FREENS_HOME", dir)
	daemon, _ := renewTestNode(t)
	// No keys dir at all: the boot tick must no-op without error or hang.
	done := make(chan struct{})
	go func() {
		reconcileTick(daemon, dht.NewEnvelopeStore(0, nil), renewTestLogger(), true)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the boot tick hung with an empty keychain")
	}
}

// TestReconcileBootTickLogsRunbookLine: the boot tick keeps the "boot
// lease warm-up complete" completion line — fleet runbooks grep for it
// after every upgrade restart, so the consolidation must not rename it.
func TestReconcileBootTickLogsRunbookLine(t *testing.T) {
	kp := renewKeychain(t)
	daemon, daemonStore := renewTestNode(t)
	peer, _ := renewTestNode(t)
	connectTestPair(t, daemon, peer)

	now := time.Now().Unix()
	env, key := freshRecord(t, kp, 2, now)
	if ok, err := daemonStore.Put(key, env, now, false); !ok || err != nil {
		t.Fatalf("seeding the fresh record locally: %v, %v", ok, err)
	}
	logger, buf := renewTestLoggerBuf()

	reconcileTick(daemon, daemonStore, logger, true)

	if !strings.Contains(buf.String(), "boot lease warm-up complete") {
		t.Fatalf("boot tick did not log the runbook line:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "names_verified=1") {
		t.Fatalf("boot tick line should count the verified own name:\n%s", buf.String())
	}
}
