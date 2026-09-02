package admin

// network_resolve_test.go — POST /resolve {"network": true}: the
// network-forced view (the 2026-09-02 camalolo incident detector). The
// local-first resolve can be green on the owner while the network lost the
// lease; the network view must show that honestly, and the fresh case must
// read healthy.

import (
	"context"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// claimApexEnv signs a claim-carrying apex record with a W=5 witness
// quorum — what the hPut K_claim screen (PoW floor + §7.3 quorum) demands
// before a storing node accepts the put. PoW is mined at difficulty 8
// (the floor atom lowered, the dht test pattern) so the test stays fast.
func claimApexEnv(t *testing.T, alias string) (*wire.SignedEnvelope, *crypto.Keypair) {
	t.Helper()
	prev := claims.PoWDifficultyInit.Load()
	claims.PoWDifficultyInit.Store(8)
	t.Cleanup(func() { claims.PoWDifficultyInit.Store(prev) })
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tid, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	ts := uint64(time.Now().Unix())
	claim, err := claims.MineAliasClaim(alias, kp, ts, 8, 1<<12, 16)
	if err != nil {
		t.Fatalf("MineAliasClaim: %v", err)
	}
	ph, err := claim.PrefixHash()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		wkp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		w, err := claims.NewWitnessAttestation(wkp, ts+uint64(i), ph)
		if err != nil {
			t.Fatal(err)
		}
		claim.Witnesses = append(claim.Witnesses, w)
	}
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, alias, tid)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())
	rec, err := wire.NewRecord(wn, kp.Public(), 1, now-10, now+3600)
	if err != nil {
		t.Fatal(err)
	}
	rec.Claim = cb
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	return env, kp
}

// TestResolveNetworkViewFresh: after a publish, the network view reports
// the record AND claim live from the peer's perspective.
func TestResolveNetworkViewFresh(t *testing.T) {
	a, b, lookup, client := adminPair(t, "test")
	_ = a
	_ = b
	env, _ := claimApexEnv(t, "netview")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := client.Publish(ctx, env); err != nil {
		t.Fatalf("publish: %v", err)
	}
	r, err := client.ResolveNetwork(ctx, "netview")
	if err != nil {
		t.Fatalf("ResolveNetwork: %v", err)
	}
	if r.Network == nil {
		t.Fatal("network view missing from the resolve response")
	}
	if !r.Network.RecordFound || r.Network.RecordSequence != 1 {
		t.Errorf("network record = found:%v seq:%d, want found seq 1",
			r.Network.RecordFound, r.Network.RecordSequence)
	}
	if !r.Network.ClaimFound || r.Network.ClaimSequence != 1 {
		t.Errorf("network claim = found:%v seq:%d, want found seq 1",
			r.Network.ClaimFound, r.Network.ClaimSequence)
	}
	if r.Network.ClaimExpires <= uint64(time.Now().Unix()) {
		t.Errorf("network claim expires at %d — already stale", r.Network.ClaimExpires)
	}
	_ = lookup
}

// TestResolveNetworkViewLostLease: nothing published → the network view
// reports the claim missing (the incident signature) while remaining a
// clean, non-degraded answer.
func TestResolveNetworkViewLostLease(t *testing.T) {
	_, _, _, client := adminPair(t, "test")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := client.ResolveNetwork(ctx, "ghost")
	if err != nil {
		t.Fatalf("ResolveNetwork: %v", err)
	}
	if r.Network == nil {
		t.Fatal("network view missing from the resolve response")
	}
	if r.Found {
		t.Error("local resolve found a record for an unpublished alias")
	}
	if r.Network.ClaimFound || r.Network.RecordFound {
		t.Errorf("network view invented entries: %+v", r.Network)
	}
	if r.Network.Degraded {
		t.Error("a clean two-node network must answer, not degrade")
	}
}
