// boot_warmup_test.go — the boot lease warm-up (v0.16.7, "the
// boring-upgrade release"): the post-restart window used to run cold —
// first queries ate walks, and a renewal whose publish died with the old
// process stayed lost until the first hourly verify, surfacing hours
// later as an NXDOMAIN that looked like an upgrade bug. The warm-up walks
// both keyspaces per keychain name and network-verifies own leases at
// boot, re-publishing lost ones immediately.
package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/dht"
)

// TestBootLeaseWarmupRepublishesLostLease: the persisted store holds a
// fresh lease the network lost (the upgrade-restart shape) — the warm-up
// must re-publish the SAME envelope to the network without touching the
// sequence.
func TestBootLeaseWarmupRepublishesLostLease(t *testing.T) {
	kp := renewKeychain(t)
	daemon, daemonStore := renewTestNode(t)
	peer, peerStore := renewTestNode(t)
	connectTestPair(t, daemon, peer)

	now := time.Now().Unix()
	env, key := freshRecord(t, kp, 5, now)
	if ok, err := daemonStore.Put(key, env, now, false); !ok || err != nil {
		t.Fatalf("seeding the fresh record locally: %v, %v", ok, err)
	}

	bootLeaseWarmup(daemon, daemonStore, renewTestLogger())

	got, err := peerStore.Get(key, time.Now().Unix())
	if err != nil || got == nil {
		t.Fatalf("the network did not receive the lost lease: %v, %v", got, err)
	}
	if got.Record.Sequence != 5 {
		t.Fatalf("network sequence = %d, want 5 (warm-up re-publishes, never re-signs)", got.Record.Sequence)
	}
	nh, e1 := got.RecordHash()
	lh, e2 := env.RecordHash()
	if e1 != nil || e2 != nil || !bytes.Equal(nh, lh) {
		t.Fatal("the re-published envelope differs from the local one")
	}
}

// TestBootLeaseWarmupNoKeychainIsQuiet: a relay node with no keys must
// return immediately without touching the network.
func TestBootLeaseWarmupNoKeychainIsQuiet(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FREENS_HOME", dir)
	daemon, _ := renewTestNode(t)
	// No keys dir at all: the warm-up must no-op without error or hang.
	done := make(chan struct{})
	go func() {
		bootLeaseWarmup(daemon, dht.NewEnvelopeStore(0, nil), renewTestLogger())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("bootLeaseWarmup hung with an empty keychain")
	}
}
