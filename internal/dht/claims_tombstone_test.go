package dht

// claims_tombstone_test.go — the §8.4 reuse window on the DHT side (v0.8.0):
// reuseWindowEnd's evidence matrix (what is and is not a tombstone),
// claimReuseRefusal's renewal-vs-resurrection rule, the wire-level witness
// refusal (ErrAliasReuseWindow) and hPut refusal, the rogue-fabrication
// negative (a quorum-less pooled envelope must NOT lock an alias), the pool
// Sweep/persist round trip, and the difficulty-state persistence.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// tombstoneFixture is a claim-carrying TLD envelope with a CALLER-chosen
// validity window (the stock builders always straddle the clock) plus
// optional sabotage: quorum=false builds the PoW-valid/quorum-less
// fabrication a rogue node could pool at zero witness cost; revoke=true
// builds a §8.5 deliberate death.
func tombstoneFixture(t *testing.T, alias string, claimTS uint64, created, expires int64, quorum, revoke bool) (*wire.SignedEnvelope, *claims.AliasClaim, *crypto.Keypair) {
	t.Helper()
	withFastWitnessPoW(t)
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tid, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	claim, err := claims.MineAliasClaim(alias, kp, claimTS, 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MineAliasClaim: %v", err)
	}
	if quorum {
		ph, err := claim.PrefixHash()
		if err != nil {
			t.Fatal(err)
		}
		witnesses := make([]*claims.WitnessAttestation, 0, constants.W)
		for i := 0; i < constants.W; i++ {
			wkp, err := crypto.Generate()
			if err != nil {
				t.Fatal(err)
			}
			w, err := claims.NewWitnessAttestation(wkp, claimTS+uint64(i), ph)
			if err != nil {
				t.Fatal(err)
			}
			witnesses = append(witnesses, w)
		}
		claim.Witnesses = witnesses
	}
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, alias, tid)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(wn, kp.Public(), 1, uint64(created), uint64(expires))
	if err != nil {
		t.Fatal(err)
	}
	rec.Claim = cb
	if revoke {
		rev := true
		rec.Revoke = &rev
	}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	return env, claim, kp
}

// TestReuseWindowEndMatrix: only a fully content-verified (signature,
// claimant binding, PoW, W-quorum), non-revoked, DEAD and IN-WINDOW carrier
// is tombstone evidence — every other shape yields 0.
func TestReuseWindowEndMatrix(t *testing.T) {
	now := int64(1_700_000_000)
	alias := "matrixfoo"

	// In window: died 1 h ago, 30-day window open.
	env, _, _ := tombstoneFixture(t, alias, uint64(now-90000), now-90000, now-3600, true, false)
	if end := reuseWindowEnd(env, alias, now); end != now-3600+int64(constants.AliasReuseDelay) {
		t.Errorf("in-window tombstone: end = %d, want %d", end, now-3600+int64(constants.AliasReuseDelay))
	}
	// Still alive: not a tombstone.
	alive, _, _ := tombstoneFixture(t, alias, uint64(now-100), now-100, now+3600, true, false)
	if end := reuseWindowEnd(alive, alias, now); end != 0 {
		t.Errorf("alive carrier: end = %d, want 0", end)
	}
	// Window closed (> 30 d past expiry): inert.
	closedAt := now - int64(constants.AliasReuseDelay) - 10
	closed, _, _ := tombstoneFixture(t, alias, uint64(closedAt-86400), closedAt-86400, closedAt, true, false)
	if end := reuseWindowEnd(closed, alias, now); end != 0 {
		t.Errorf("closed window: end = %d, want 0", end)
	}
	// Revoked (§8.5 deliberate death): NOT a tombstone.
	revoked, _, _ := tombstoneFixture(t, alias, uint64(now-90000), now-90000, now-3600, true, true)
	if end := reuseWindowEnd(revoked, alias, now); end != 0 {
		t.Errorf("revoked carrier: end = %d, want 0", end)
	}
	// Quorum-less fabrication: NOT a tombstone (locking must cost a real
	// registration — the rigged-node bar).
	fabricated, _, _ := tombstoneFixture(t, alias, uint64(now-90000), now-90000, now-3600, false, false)
	if end := reuseWindowEnd(fabricated, alias, now); end != 0 {
		t.Errorf("quorum-less fabrication: end = %d, want 0", end)
	}
	// Wrong alias: evidence for a different K_claim.
	if end := reuseWindowEnd(env, "otheralias", now); end != 0 {
		t.Errorf("alias mismatch: end = %d, want 0", end)
	}
	// Foreign signer (carrier not signed by the claimant): NOT a tombstone.
	foreignKP, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	rec := *env.Record
	foreign, err := wire.SignRecord(&rec, foreignKP)
	if err != nil {
		t.Fatal(err)
	}
	if end := reuseWindowEnd(foreign, alias, now); end != 0 {
		t.Errorf("foreign signer: end = %d, want 0", end)
	}
}

// TestClaimReuseRefusalRenewalVsResurrection: a same-identity presentation
// (renewal or resurrection — v0.9.1 treats both as ownership continuity)
// is never refused; a different identity is refused outright while the
// window is open; a quorum-less fabrication pools but locks nothing.
func TestClaimReuseRefusalRenewalVsResurrection(t *testing.T) {
	now := time.Now().Unix()
	alias := "renewfoo"
	dead, deadClaim, _ := tombstoneFixture(t, alias, uint64(now-90000), now-90000, now-3600, true, false)
	phDead, err := deadClaim.PrefixHash()
	if err != nil {
		t.Fatal(err)
	}

	n := gossipStateNode(t)
	kClaim, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}
	if !n.claims.Offer(kClaim, dead) {
		t.Fatal("fixture: dead claim not pooled")
	}

	// Same identity (renewal — created before the death — or resurrection —
	// created after; v0.9.1 treats both as ownership continuity): never
	// refused. The v0.8.0 refusal of the resurrection case deadlocked the
	// whole LAN fleet on 2026-08-22 when auto-renewal arrived one tick
	// late.
	if end := n.claimReuseRefusal(alias, phDead, now); end != 0 {
		t.Errorf("same-identity presentation refused (end=%d), want allowed", end)
	}

	// Different identity inside the window: refused.
	_, otherClaim, _ := tombstoneFixture(t, alias, uint64(now-10), now-10, now+86000, true, false)
	phOther, err := otherClaim.PrefixHash()
	if err != nil {
		t.Fatal(err)
	}
	if end := n.claimReuseRefusal(alias, phOther, now); end == 0 {
		t.Error("different identity inside the window allowed, want refused")
	}

	// Rogue fabrication pooled instead: no refusal (no lock).
	n2 := gossipStateNode(t)
	fake, fakeClaim, _ := tombstoneFixture(t, alias, uint64(now-90000), now-90000, now-3600, false, false)
	if !n2.claims.Offer(kClaim, fake) {
		t.Fatal("fixture: fabrication not pooled (Offer screens PoW only)")
	}
	phFake, err := fakeClaim.PrefixHash()
	if err != nil {
		t.Fatal(err)
	}
	if end := n2.claimReuseRefusal(alias, phOther, now); end != 0 {
		t.Errorf("quorum-less fabrication locked the alias (end=%d)", end)
	}
	_ = phFake
}

// resignCarrier wraps the SAME claim identity in a fresh carrier record with
// the given window and sequence, signed by kp.
func resignCarrier(t *testing.T, proto *wire.SignedEnvelope, kp *crypto.Keypair, claim *claims.AliasClaim, created, expires int64, seq uint64) *wire.SignedEnvelope {
	t.Helper()
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(proto.Record.Name, kp.Public(), seq, uint64(created), uint64(expires))
	if err != nil {
		t.Fatal(err)
	}
	rec.Claim = cb
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// TestWitnessRefusalInsideWindow (wire level): a node whose pool holds a
// verified tombstone refuses to co-sign a DIFFERENT claim for the alias, and
// CollectWitnesses surfaces ErrAliasReuseWindow (distinct from "network too
// small"); a rogue quorum-less pooled envelope does NOT lock; a same-identity
// re-presentation dies at the §6.3 ts gate (not at the window check).
func TestWitnessRefusalInsideWindow(t *testing.T) {
	now := time.Now().Unix()
	alias := "windowfoo"

	w, _ := startTestNode(t, nil)
	defer w.Close()
	a, _ := startTestNode(t, nil)
	defer a.Close()
	wAddr, err := w.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddPeer(w.PublicKey(), wAddr.String()); err != nil {
		t.Fatal(err)
	}

	// Pool the tombstone on the witness.
	dead, deadClaim, _ := tombstoneFixture(t, alias, uint64(now-90000), now-90000, now-3600, true, false)
	kClaim, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}
	if !w.claims.Offer(kClaim, dead) {
		t.Fatal("fixture: tombstone not pooled")
	}

	// A DIFFERENT claim identity: refused with the §8.4 sentinel.
	id := newWitnessIdentity(t, uint64(now))
	nonce, powHash := id.mineWitnessPoW(t, alias)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	atts, err := a.CollectWitnesses(ctx, alias, id.tldID, id.claimantKP.Public(), id.ts, nonce, powHash, 1)
	if !errors.Is(err, ErrAliasReuseWindow) {
		t.Fatalf("CollectWitnesses err = %v, want ErrAliasReuseWindow (atts=%d)", err, len(atts))
	}

	// Same-identity re-presentation of the long-dead claim: the §6.3 ts
	// gate refuses it as "too old" (best-effort: empty haul, no sentinel —
	// it is neither a witness failure nor a window signal for the caller).
	phDead, err := deadClaim.PrefixHash()
	if err != nil {
		t.Fatal(err)
	}
	atts, err = a.CollectWitnesses(ctx, alias, deadClaim.TldID, deadClaim.ClaimantPK, deadClaim.Timestamp, deadClaim.Nonce, deadClaim.PowHash, 1)
	if err != nil || len(atts) != 0 {
		t.Fatalf("same-identity dead presentation: atts=%d err=%v, want 0/nil (ts gate, pre-window)", len(atts), err)
	}
	_ = phDead

	// Rogue variant: a quorum-less pooled fabrication must not lock the
	// alias — the witness co-signs normally.
	w2, _ := startTestNode(t, nil)
	defer w2.Close()
	a2, _ := startTestNode(t, nil)
	defer a2.Close()
	w2Addr, err := w2.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := a2.AddPeer(w2.PublicKey(), w2Addr.String()); err != nil {
		t.Fatal(err)
	}
	fake, _, _ := tombstoneFixture(t, alias, uint64(now-90000), now-90000, now-3600, false, false)
	if !w2.claims.Offer(kClaim, fake) {
		t.Fatal("fixture: fabrication not pooled")
	}
	id2 := newWitnessIdentity(t, uint64(now))
	nonce2, powHash2 := id2.mineWitnessPoW(t, alias)
	atts, err = a2.CollectWitnesses(ctx, alias, id2.tldID, id2.claimantKP.Public(), id2.ts, nonce2, powHash2, 1)
	if err != nil || len(atts) != 1 {
		t.Fatalf("rogue fabrication locked the alias: atts=%d err=%v, want 1/nil", len(atts), err)
	}
}

// TestHPutRefusalInsideWindow drives hPut directly: a different-identity
// claim put at K_claim inside the window is refused with 301 "alias in reuse
// window"; a same-identity carrier OVERLAPPING the dead lease (renewal) is
// accepted.
func TestHPutRefusalInsideWindow(t *testing.T) {
	now := time.Now().Unix()
	alias := "putwindowfoo"

	n := gossipStateNode(t)
	dead, deadClaim, deadKP := tombstoneFixture(t, alias, uint64(now-90000), now-90000, now-3600, true, false)
	kClaim, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}
	if !n.claims.Offer(kClaim, dead) {
		t.Fatal("fixture: tombstone not pooled")
	}

	raddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 39999}
	put := func(env *wire.SignedEnvelope) (*wire.Message, error) {
		envBytes, err := env.Bytes()
		if err != nil {
			return nil, err
		}
		m := &wire.Message{
			Y:  wire.MsgTypeQuery,
			T:  []byte{7},
			Q:  "put",
			ID: n.ID(),
			A: map[string]any{
				"token":    n.issueToken(raddr),
				"envelope": envBytes,
				"key":      kClaim,
			},
		}
		return n.hPut(m, raddr), nil
	}

	// Different identity, fully valid: refused on the window.
	other, _, _ := tombstoneFixture(t, alias, uint64(now-10), now-10, now+86000, true, false)
	resp, err := put(other)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.Y != wire.MsgTypeError {
		t.Fatalf("different-identity put: resp.Y = %v, want error", resp.Y)
	}
	if msg, _ := resp.A["msg"].(string); !bytes.Contains([]byte(msg), []byte("reuse window")) {
		t.Fatalf("different-identity put error msg = %q, want the reuse-window refusal", msg)
	}

	// Same identity, overlapping carrier (renewal): accepted.
	renewal := resignCarrier(t, dead, deadKP, deadClaim, now-70000, now+80000, 2)
	resp, err = put(renewal)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.Y != wire.MsgTypeResponse {
		t.Fatalf("renewal put: resp.Y = %v, want ok", resp.Y)
	}

	// Same identity, carrier created AFTER the death (resurrection): ALSO
	// accepted (v0.9.1, the 2026-08-22 fleet deadlock: after a renewal
	// lapse the pools hold the dead generation, and refusing the
	// claimant's own re-assertion locked the alias for ALIAS_REUSE_DELAY).
	resurrection := resignCarrier(t, dead, deadKP, deadClaim, now-1800, now+80000, 3)
	resp, err = put(resurrection)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.Y != wire.MsgTypeResponse {
		msg, _ := resp.A["msg"].(string)
		t.Fatalf("resurrection put: resp.Y = %v msg=%q, want ok (v0.9.1 ownership continuity)", resp.Y, msg)
	}
}

// TestClaimPoolSweepWindow: in-window dead claims stay pooled (the §8.4
// evidence), past-window entries are dropped (bounded memory), and the byte
// accounting follows.
func TestClaimPoolSweepWindow(t *testing.T) {
	now := int64(1_700_000_000)
	alias := "sweepfoo"
	p := NewClaimPool()
	kClaim, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}
	inWindow, _, _ := tombstoneFixture(t, alias, uint64(now-90000), now-90000, now-3600, true, false)
	pastDeath := now - int64(constants.AliasReuseDelay) - 10
	pastWindow, _, _ := tombstoneFixture(t, "sweepbar", uint64(pastDeath-86400), pastDeath-86400, pastDeath, true, false)
	k2, err := KeyForClaim("sweepbar")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Offer(kClaim, inWindow) || !p.Offer(k2, pastWindow) {
		t.Fatal("fixture: offers rejected")
	}
	if p.bytes == 0 {
		t.Fatal("fixture: byte budget not accounting pooled envelopes")
	}

	if dropped := p.Sweep(now); dropped != 1 {
		t.Fatalf("Sweep(in-window now) dropped %d, want 1 (the past-window entry)", dropped)
	}
	if p.Top2(kClaim) == nil {
		t.Error("in-window tombstone swept early")
	}
	if dropped := p.Sweep(now + int64(constants.AliasReuseDelay) + 10); dropped != 1 {
		t.Fatalf("Sweep(past window) dropped %d, want 1", dropped)
	}
	if p.Top2(kClaim) != nil {
		t.Error("past-window tombstone still pooled")
	}
	if p.bytes != 0 {
		t.Errorf("byte accounting after full sweep = %d, want 0", p.bytes)
	}
	if len(p.Entries()) != 0 {
		t.Errorf("entries after full sweep = %d, want 0", len(p.Entries()))
	}
}

// (len2 removed — the sweep test asserts the byte budget directly.)

// TestClaimPoolPersistRoundTrip: persist → fresh pool retain restores the
// in-window tombstone; a tombstone persisted before its window closed but
// reloaded after is skipped (self-cleaning reload).
func TestClaimPoolPersistRoundTrip(t *testing.T) {
	now := time.Now().Unix()
	alias := "persistfoo"
	dir := t.TempDir()

	n := gossipStateNode(t)
	dead, _, _ := tombstoneFixture(t, alias, uint64(now-90000), now-90000, now-3600, true, false)
	kClaim, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}
	if !n.claims.Offer(kClaim, dead) {
		t.Fatal("fixture: tombstone not pooled")
	}
	if _, err := n.PersistClaimPoolDir(dir); err != nil {
		t.Fatalf("PersistClaimPoolDir: %v", err)
	}

	// Fresh pool reloads it.
	p2 := NewClaimPool()
	count, err := p2.RetainClaimPool(dir, now)
	if err != nil {
		t.Fatalf("RetainClaimPool: %v", err)
	}
	if count != 1 || p2.Top2(kClaim) == nil {
		t.Fatalf("round trip restored %d entries, want 1 with the tombstone pooled", count)
	}

	// Reload after the window closed: skipped.
	p3 := NewClaimPool()
	count, err = p3.RetainClaimPool(dir, now+int64(constants.AliasReuseDelay)+10)
	if err != nil {
		t.Fatalf("RetainClaimPool (late): %v", err)
	}
	if count != 0 || p3.Top2(kClaim) != nil {
		t.Fatalf("late reload pooled %d entries, want 0 (window closed)", count)
	}
}

// TestDifficultyStatePersistenceRoundTrip: Save → Load restores own D, block
// progress and the observed ring; a missing file is a no-op; a malformed
// file is a loud error.
func TestDifficultyStatePersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "difficulty.json")

	n := gossipStateNode(t)
	// Advance the state past the floor: fast block ⇒ +2 (24 -> 26).
	t0 := int64(1_700_000_000)
	st := n.diff
	for i := 0; i < constants.PoWRetargetBlock; i++ {
		st.recordAccepted(t0)
	}
	if got := st.currentDifficulty(); got != constants.PoWDifficultyInit+2 {
		t.Fatalf("fixture: difficulty = %d, want +2", got)
	}
	st.observe(30)
	if err := n.SaveDifficultyState(path); err != nil {
		t.Fatalf("SaveDifficultyState: %v", err)
	}

	n2 := gossipStateNode(t)
	if err := n2.LoadDifficultyState(path); err != nil {
		t.Fatalf("LoadDifficultyState: %v", err)
	}
	if got := n2.diff.currentDifficulty(); got != constants.PoWDifficultyInit+2 {
		t.Errorf("restored difficulty = %d, want %d (a restart must not reset a raised D)", got, constants.PoWDifficultyInit+2)
	}
	if got := n2.diff.snapshot().Accepted; got != 0 {
		t.Errorf("restored accepted = %d, want 0 (block just completed)", got)
	}
	if ring := n2.diff.observedSnapshot(); len(ring) != 1 || ring[0] != 30 {
		t.Errorf("restored observed ring = %v, want [30]", ring)
	}

	// Missing file: not an error.
	n3 := gossipStateNode(t)
	if err := n3.LoadDifficultyState(filepath.Join(dir, "nope.json")); err != nil {
		t.Errorf("missing file: err = %v, want nil", err)
	}
	// Malformed file: loud.
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := n3.LoadDifficultyState(path); err == nil {
		t.Error("malformed file: err = nil, want loud")
	}
	// Sanity-capped restore: a garbage difficulty falls back to the floor.
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`{"current":9999,"accepted":0,"block_start":%d}`, t0)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := n3.LoadDifficultyState(path); err != nil {
		t.Fatalf("capped restore: %v", err)
	}
	if got := n3.diff.currentDifficulty(); got != constants.PoWDifficultyInit {
		t.Errorf("garbage difficulty restored as %d, want the floor %d", got, constants.PoWDifficultyInit)
	}
}

// TestClaimEvidenceStructureScreen: ClaimEvidence is the ONE shared
// evidence screen (v0.15.3 folded the resolver's drifted copy into it) —
// the structural bits (version, sequence, §4.4 record validation) must
// refuse evidence, not just the signature/content checks.
func TestClaimEvidenceStructureScreen(t *testing.T) {
	now := time.Now().Unix()
	alias := "evidfoo"
	env, claim, kp := tombstoneFixture(t, alias, uint64(now-100), now-100, now+80000, true, false)
	if _, ph := ClaimEvidence(env, alias, now); ph == nil {
		t.Fatal("healthy live carrier: want evidence")
	}

	rebuild := func(mutate func(*wire.Record)) *wire.SignedEnvelope {
		rec := *env.Record
		mutate(&rec)
		e, err := wire.SignRecord(&rec, kp)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	if _, ph := ClaimEvidence(rebuild(func(r *wire.Record) { r.Version = 99 }), alias, now); ph != nil {
		t.Error("wrong protocol version accepted as evidence")
	}
	if _, ph := ClaimEvidence(rebuild(func(r *wire.Record) { r.Sequence = 0 }), alias, now); ph != nil {
		t.Error("sequence-0 carrier accepted as evidence")
	}
	// Identity must be stable across carrier regenerations (the same claim
	// re-carried by a renewal envelope is the SAME evidence identity).
	ph1, err := claim.PrefixHash()
	if err != nil {
		t.Fatal(err)
	}
	_, ph2 := ClaimEvidence(env, alias, now)
	if !bytes.Equal(ph1, ph2) {
		t.Error("ClaimEvidence prefix hash != claim.PrefixHash")
	}
}

// TestLiveClaimConflictMatrix: the §7.3 witness exclusivity screen (v0.15.3,
// the first slice of the #8 backdated-claim defense) — a LIVE, fully
// content-valid, DIFFERENT-identity claim conflicts; same identity (renewal
// / parked-claim retry), dead incumbents (the tombstone path's job), and
// quorum-less pooled fabrications (DoS safety) do not.
func TestLiveClaimConflictMatrix(t *testing.T) {
	now := time.Now().Unix()
	alias := "conflictfoo"
	kClaim, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}

	live, liveClaim, _ := tombstoneFixture(t, alias, uint64(now-100), now-100, now+80000, true, false)
	phLive, err := liveClaim.PrefixHash()
	if err != nil {
		t.Fatal(err)
	}
	_, otherClaim, _ := tombstoneFixture(t, alias, uint64(now-10), now-10, now+86000, true, false)
	phOther, err := otherClaim.PrefixHash()
	if err != nil {
		t.Fatal(err)
	}

	n := gossipStateNode(t)
	if !n.claims.Offer(kClaim, live) {
		t.Fatal("fixture: live claim not pooled")
	}
	if !n.liveClaimConflict(alias, phOther, now) {
		t.Error("live different-identity claim: want conflict")
	}
	if n.liveClaimConflict(alias, phLive, now) {
		t.Error("same identity (renewal/retry): want no conflict")
	}

	// Dead incumbent: no conflict — the §8.4 tombstone path owns that case.
	n3 := gossipStateNode(t)
	dead, _, _ := tombstoneFixture(t, alias, uint64(now-90000), now-90000, now-3600, true, false)
	if !n3.claims.Offer(kClaim, dead) {
		t.Fatal("fixture: dead claim not pooled")
	}
	if n3.liveClaimConflict(alias, phOther, now) {
		t.Error("dead incumbent flagged as a live conflict")
	}

	// Quorum-less pooled fabrication: no conflict (a rogue peer must not be
	// able to freeze registrations by pooling a PoW-valid fake).
	n4 := gossipStateNode(t)
	fake, _, _ := tombstoneFixture(t, alias, uint64(now-100), now-100, now+80000, false, false)
	if !n4.claims.Offer(kClaim, fake) {
		t.Fatal("fixture: fabrication not pooled")
	}
	if n4.liveClaimConflict(alias, phOther, now) {
		t.Error("quorum-less fabrication blocked a registration (DoS)")
	}
}

// TestWitnessRefusesLiveConflictingClaim (wire level): a witness whose pool
// holds a live claim does not co-sign a DIFFERENT claim for that alias —
// the mint a takeover needs — while a witness holding only a quorum-less
// fabrication still co-signs (no lock).
func TestWitnessRefusesLiveConflictingClaim(t *testing.T) {
	now := time.Now().Unix()
	alias := "exclufoo"

	w, _ := startTestNode(t, nil)
	defer w.Close()
	a, _ := startTestNode(t, nil)
	defer a.Close()
	wAddr, err := w.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddPeer(w.PublicKey(), wAddr.String()); err != nil {
		t.Fatal(err)
	}

	live, _, _ := tombstoneFixture(t, alias, uint64(now-100), now-100, now+80000, true, false)
	kClaim, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}
	if !w.claims.Offer(kClaim, live) {
		t.Fatal("fixture: live claim not pooled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id := newWitnessIdentity(t, uint64(now))
	nonce, powHash := id.mineWitnessPoW(t, alias)
	atts, err := a.CollectWitnesses(ctx, alias, id.tldID, id.claimantKP.Public(), id.ts, nonce, powHash, 1)
	if err != nil {
		t.Fatalf("CollectWitnesses: %v", err)
	}
	if len(atts) != 0 {
		t.Fatalf("witness co-signed over its own live claim: %d attestations, want 0", len(atts))
	}

	// Rogue variant: a pooled fabrication must not freeze registrations.
	w2, _ := startTestNode(t, nil)
	defer w2.Close()
	a2, _ := startTestNode(t, nil)
	defer a2.Close()
	w2Addr, err := w2.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := a2.AddPeer(w2.PublicKey(), w2Addr.String()); err != nil {
		t.Fatal(err)
	}
	fake, _, _ := tombstoneFixture(t, alias, uint64(now-100), now-100, now+80000, false, false)
	if !w2.claims.Offer(kClaim, fake) {
		t.Fatal("fixture: fabrication not pooled")
	}
	id2 := newWitnessIdentity(t, uint64(now))
	nonce2, powHash2 := id2.mineWitnessPoW(t, alias)
	atts, err = a2.CollectWitnesses(ctx, alias, id2.tldID, id2.claimantKP.Public(), id2.ts, nonce2, powHash2, 1)
	if err != nil || len(atts) != 1 {
		t.Fatalf("fabrication froze the alias: atts=%d err=%v, want 1/nil", len(atts), err)
	}
}
