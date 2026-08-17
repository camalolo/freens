// witness_ts_test.go — the §7.4 anti-forgery gate: witnesses bound the
// CLAIM's timestamp (earliest-first ordering makes a forged ts≈0 claim a
// permanent alias theft once cooldowns lapse). Legitimate windows: signed
// at mining time (fresh) or re-presented inside register's cooldown-safe
// retry window; anything future-dated beyond skew or older than the
// cooldown is refused. Since v0.7.0 the witness ALSO verifies the claim's
// PoW (§7.3) — the fixture mines a real difficulty-8 pair per case.
package dht

import (
	"context"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
)

// witnessTSCase drives one CollectWitnesses against a live peer with the
// given claim timestamp offset, returning the attestation count.
func witnessTSCase(t *testing.T, tsOffset int64) int {
	t.Helper()
	a, _ := startTestNode(t, nil)
	b, _ := startTestNode(t, nil)
	defer a.Close()
	defer b.Close()

	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	ts := uint64(time.Now().Unix() + tsOffset)
	const alias = "ts-test"
	withFastWitnessPoW(t)

	// Mine the PoW for this exact (backdated/fresh/future) identity: the
	// witness verifies it before its timestamp gate, so the refusal under
	// test is the ts gate's, not a PoW artifact.
	prefix, err := (&claims.AliasClaim{Alias: alias, TldID: tldID, Timestamp: ts, ClaimantPK: kp.Public()}).Prefix()
	if err != nil {
		t.Fatal(err)
	}
	nonce, powHash, err := crypto.MinePoW(prefix, 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MinePoW (fixture): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	atts, err := a.CollectWitnesses(ctx, alias, tldID, kp.Public(), ts, nonce, powHash, 1)
	if err != nil {
		t.Fatalf("CollectWitnesses(offset=%d): %v", tsOffset, err)
	}
	return len(atts)
}

func TestWitnessRefusesFutureDatedClaim(t *testing.T) {
	if got := witnessTSCase(t, int64(constants.SkewTolerance)+300); got != 0 {
		t.Errorf("future-dated claim gathered %d attestations; witnesses must refuse", got)
	}
}

func TestWitnessRefusesAncientClaim(t *testing.T) {
	offset := -int64(constants.WitnessCooldown) - 3600 // an hour past the cooldown
	if got := witnessTSCase(t, offset); got != 0 {
		t.Errorf("forged ancient (ts≈0-style) claim gathered %d attestations; witnesses must refuse", got)
	}
}

func TestWitnessAcceptsFreshClaim(t *testing.T) {
	if got := witnessTSCase(t, 0); got != 1 {
		t.Errorf("fresh claim gathered %d attestations, want 1", got)
	}
}

func TestWitnessAcceptsCooldownAgedRetry(t *testing.T) {
	// A register retry re-presents the mined claim up to the cooldown
	// later (the cooldown-safe retry design) — must still be witnessed.
	offset := -int64(constants.WitnessCooldown) + 120 // just inside the window
	if got := witnessTSCase(t, offset); got != 1 {
		t.Errorf("cooldown-aged retry gathered %d attestations, want 1", got)
	}
}
