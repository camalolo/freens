package dht

// witness_test.go exercises the §6.3 `witness` RPC (§7.3 lines 544-587,
// §7.4 lines 588-624) between two REAL loopback nodes: the round trip through
// Node.CollectWitnesses, the §7.3 WITNESS_COOLDOWN refusal, the bad-prefix-hash
// rejection, the §7.4/C.1 claim publication at K_claim (PublishClaim), and the
// DHTLookup.LookupClaim fetch-and-cache path used by the resolver's §9.2
// step-3a network alias resolution.
//
// Mining is not needed for the RPC-level tests (the witness verifies the PoW
// PREFIX hash binding, not the PoW itself — the nonce is not yet known at
// witnessing time, §7.4 step 3 precedes step 2's assembly); the claim identity
// (alias, tld_id, claimant_pk, ts) is therefore drawn from a fresh keypair.

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/laurent/freens/internal/claims"
	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/naming"
	"github.com/laurent/freens/internal/wire"
)

// witnessIdentity is a claim identity fixture: a fresh claimant keypair, its
// self-certifying tld_id, and a claimant-asserted timestamp.
type witnessIdentity struct {
	claimantKP *crypto.Keypair
	tldID      []byte
	ts         uint64
}

func newWitnessIdentity(t *testing.T, ts uint64) *witnessIdentity {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("gen claimant keypair: %v", err)
	}
	tid, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatalf("TldID: %v", err)
	}
	return &witnessIdentity{claimantKP: kp, tldID: tid, ts: ts}
}

// witnessArgs builds the §6.3 `witness` method arguments for the identity (the
// documented deviation from the spec's {claim_prefix_hash, claimant, ts}:
// alias and tld_id ride along because the §7.3 attestation signature input
// needs them).
func witnessArgs(t *testing.T, alias string, id *witnessIdentity) map[string]any {
	t.Helper()
	ph, err := claimPrefixHash(alias, id.tldID, id.claimantKP.Public(), id.ts)
	if err != nil {
		t.Fatalf("claimPrefixHash: %v", err)
	}
	return map[string]any{
		"alias":             alias,
		"tld_id":            id.tldID,
		"claimant":          id.claimantKP.Public(),
		"ts":                id.ts,
		"claim_prefix_hash": ph,
	}
}

// TestWitnessRoundTrip: A (claimant) gathers witnesses via CollectWitnesses; B
// (its only known peer, hence the closest to K_claim) co-signs with its node
// keypair and A receives a §7.3-verifiable attestation.
func TestWitnessRoundTrip(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	const alias = "witfoo"
	id := newWitnessIdentity(t, uint64(time.Now().Unix()))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	atts, err := a.CollectWitnesses(ctx, alias, id.tldID, id.claimantKP.Public(), id.ts, 0 /* default WITNESS_SET */)
	if err != nil {
		t.Fatalf("CollectWitnesses: %v", err)
	}
	if len(atts) != 1 {
		t.Fatalf("got %d attestations, want 1 (B is the only candidate witness)", len(atts))
	}
	att := atts[0]
	// §7.3: the attestation verifies for the exact claim context...
	if !att.Verify(alias, id.tldID, id.claimantKP.Public()) {
		t.Error("attestation does not Verify for the claim context")
	}
	// ...and was produced by B's node keypair (NodeID == SHA-256(node_pk)).
	if !bytes.Equal(att.NodeID, b.ID()) {
		t.Errorf("attestation NodeID = %s, want B's node ID %s", HexID(att.NodeID), HexID(b.ID()))
	}
	if !bytes.Equal(att.NodePK, b.PublicKey()) {
		t.Error("attestation NodePK is not B's node public key")
	}
	if att.TS == 0 {
		t.Error("attestation TS should be the witness's own clock, got 0")
	}
	// The attestation must round-trip through its canonical CBOR.
	cb, err := att.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	if _, err := claims.DecodeWitnessAttestation(cb); err != nil {
		t.Errorf("DecodeWitnessAttestation(round-trip): %v", err)
	}
}

// TestWitnessCooldownRefusesDifferentClaim verifies the §7.3 WITNESS_COOLDOWN
// rule as implemented: after signing a claim for an alias, the node refuses a
// DIFFERENT claim for the SAME alias within constants.WitnessCooldown (error
// 301 "cooldown"), while re-signing the same claim and signing a different
// alias both still succeed.
func TestWitnessCooldownRefusesDifferentClaim(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	const alias = "coolfoo"
	id1 := newWitnessIdentity(t, 1_000_000)
	addr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// First claim for `alias`: accepted.
	resp, err := a.sendQuery(ctx, addr, b.ID(), "witness", witnessArgs(t, alias, id1))
	if err != nil {
		t.Fatalf("witness #1: %v", err)
	}
	if resp.Y != wire.MsgTypeResponse {
		t.Fatalf("witness #1: expected response, got %q (args %v)", resp.Y, resp.A)
	}

	// A DIFFERENT claim (different claimant ⇒ different prefix hash) for the
	// SAME alias inside the cooldown: refused with error 301 "cooldown".
	id2 := newWitnessIdentity(t, 1_000_000)
	resp, err = a.sendQuery(ctx, addr, b.ID(), "witness", witnessArgs(t, alias, id2))
	if err != nil {
		t.Fatalf("witness #2 (competing claim): %v", err)
	}
	if resp.Y != wire.MsgTypeError {
		t.Fatalf("witness #2 (competing claim): expected error, got %q", resp.Y)
	}
	if code, _ := asUint64(resp.A["code"]); code != 301 {
		t.Errorf("witness #2 error code = %v, want 301 (cooldown); msg=%q", resp.A["code"], resp.A["msg"])
	}

	// Re-signing the SAME claim (same prefix hash) is idempotent, not cooling.
	resp, err = a.sendQuery(ctx, addr, b.ID(), "witness", witnessArgs(t, alias, id1))
	if err != nil {
		t.Fatalf("witness #3 (same claim re-sign): %v", err)
	}
	if resp.Y != wire.MsgTypeResponse {
		t.Fatalf("witness #3 (same claim re-sign): expected response, got %q (args %v)", resp.Y, resp.A)
	}

	// A different alias is a different cooldown bucket: accepted.
	resp, err = a.sendQuery(ctx, addr, b.ID(), "witness", witnessArgs(t, "coolbar", id2))
	if err != nil {
		t.Fatalf("witness #4 (other alias): %v", err)
	}
	if resp.Y != wire.MsgTypeResponse {
		t.Fatalf("witness #4 (other alias): expected response, got %q (args %v)", resp.Y, resp.A)
	}
}

// TestWitnessBadPrefixHashRejected: a claim_prefix_hash that does not match
// SHA-256(PoW prefix(alias, tld_id, claimant, ts)) is rejected (305) — the
// witness refuses to bind its signature to an identity it cannot recompute.
func TestWitnessBadPrefixHashRejected(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	const alias = "badhash"
	id := newWitnessIdentity(t, 2_000_000)
	args := witnessArgs(t, alias, id)
	forged := make([]byte, constants.SHA256Len)
	for i := range forged {
		forged[i] = 0x5a
	}
	args["claim_prefix_hash"] = forged

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addr, _ := b.LocalAddr()
	resp, err := a.sendQuery(ctx, addr, b.ID(), "witness", args)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	if resp.Y != wire.MsgTypeError {
		t.Fatalf("expected error for bad prefix hash, got %q", resp.Y)
	}
	if code, _ := asUint64(resp.A["code"]); code != 305 {
		t.Errorf("error code = %v, want 305; msg=%q", resp.A["code"], resp.A["msg"])
	}
	// And nothing was signed: the alias has no cooldown entry, so a subsequent
	// DIFFERENT claim for the same alias must still be accepted (the refused
	// request did not consume the bucket).
	idOther := newWitnessIdentity(t, 2_000_000)
	resp, err = a.sendQuery(ctx, addr, b.ID(), "witness", witnessArgs(t, alias, idOther))
	if err != nil {
		t.Fatalf("witness after refusal: %v", err)
	}
	if resp.Y != wire.MsgTypeResponse {
		t.Fatalf("refused request must not consume the cooldown bucket; got %q (args %v)", resp.Y, resp.A)
	}
}

// TestWitnessAttestationContextBinding: attestations are cryptographically
// bound to the exact claim context (§7.3 signature input: alias, tld_id,
// claimant_pk, ts). Gathered attestations therefore verify ONLY for the
// context they were requested for — the same attestation presented as part of
// a claim for a different tld_id fails Verify, so a witness signature cannot
// be replayed onto a competing claim.
func TestWitnessAttestationContextBinding(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	const alias = "ctxfoo"
	id := newWitnessIdentity(t, 3_000_000)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Gather attestations naming a DIFFERENT tld_id than the claimant's own.
	wrongTld := make([]byte, constants.SHA256Len)
	for i := range wrongTld {
		wrongTld[i] = 0x11
	}
	atts, err := a.CollectWitnesses(ctx, alias, wrongTld, id.claimantKP.Public(), id.ts, 0)
	if err != nil {
		t.Fatalf("CollectWitnesses: %v", err)
	}
	if len(atts) != 1 {
		t.Fatalf("got %d attestations, want 1", len(atts))
	}
	// Verifies for the context that was requested...
	if !atts[0].Verify(alias, wrongTld, id.claimantKP.Public()) {
		t.Error("attestation does not Verify for the context it was gathered for")
	}
	// ...but NOT for the claimant's real tld_id, nor a different alias/ts.
	if atts[0].Verify(alias, id.tldID, id.claimantKP.Public()) {
		t.Error("attestation for wrong tld_id verified against the real tld_id")
	}
	if atts[0].Verify("otheralias", wrongTld, id.claimantKP.Public()) {
		t.Error("attestation verified against a different alias")
	}
}

// claimedTLDRecord builds a TLD-root envelope for alias whose field 11 embeds a
// low-difficulty mined, fully-attested claim (§7.4 steps 1-5 / C.1 steps 1-4).
// The witnesses are the provided node keypairs ("gathered" out of band, as the
// registration flow would have done via the witness RPC). Returns the envelope
// and K_claim. The TLD record's own storage key (K_tld) can be derived by the
// caller via KeyForWireName(env.Record.Name).
//
// NOTE on difficulty: mining happens at difficulty 8, but nothing in these
// DHT-layer tests verifies the PoW (that is the resolver/claims layer's job),
// so claims.PoWDifficultyInit is NOT lowered here and the default
// difficulty-inference path is irrelevant to the assertions.
func claimedTLDRecord(t *testing.T, alias string, witnessKPs []*crypto.Keypair) (*wire.SignedEnvelope, []byte) {
	t.Helper()
	claimant, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tid, err := crypto.TldID(claimant.Public())
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())
	claim, err := claims.MineAliasClaim(alias, claimant, now, 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MineAliasClaim: %v", err)
	}
	witnesses := make([]*claims.WitnessAttestation, 0, len(witnessKPs))
	for i, wkp := range witnessKPs {
		w, err := claims.NewWitnessAttestation(wkp, now+uint64(i), alias, tid, claimant.Public())
		if err != nil {
			t.Fatalf("NewWitnessAttestation: %v", err)
		}
		witnesses = append(witnesses, w)
	}
	claim.Witnesses = witnesses
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, alias, tid)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(wn, claimant.Public(), 1, now, now+3600)
	if err != nil {
		t.Fatal(err)
	}
	rec.Claim = cb
	env, err := wire.SignRecord(rec, claimant)
	if err != nil {
		t.Fatal(err)
	}
	kClaim, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}
	return env, kClaim
}

// TestPublishClaimStoresAtKClaimOnPeer exercises §7.4 step 5 / C.1 step 4: A
// publishes the claim envelope at K_claim via PublishClaim and B's store ends
// up holding it under K_claim — NOT under K_tld (that is ordinary Publish's
// business) — proving the two key spaces stay distinct.
func TestPublishClaimStoresAtKClaimOnPeer(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	wkp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	env, kClaim := claimedTLDRecord(t, "pubclaim", []*crypto.Keypair{wkp})
	kTld, err := KeyForWireName(env.Record.Name)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.PublishClaim(ctx, env); err != nil {
		t.Fatalf("PublishClaim: %v", err)
	}
	now := time.Now().Unix()
	if !b.store.Has(kClaim, now) {
		t.Error("claim envelope not stored on peer at K_claim")
	}
	if b.store.Has(kTld, now) {
		t.Error("PublishClaim must not store at K_tld (that is Publish's key space)")
	}

	// Ordinary Publish of the same envelope stores it at K_tld (§7.4 step 5:
	// BOTH keys end up carrying the TLD record).
	if err := a.Publish(ctx, env); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !b.store.Has(kTld, time.Now().Unix()) {
		t.Error("Publish did not store the TLD record at K_tld on the peer")
	}
}

// TestPublishClaimRejectsClaimlessEnvelope: an envelope without a decodable
// field-11 AliasClaim cannot be keyed at K_claim — PublishClaim errors instead
// of guessing.
func TestPublishClaimRejectsClaimlessEnvelope(t *testing.T) {
	a, _ := startTestNode(t, nil)
	defer a.Close()

	owner, _ := crypto.Generate()
	env, _ := makeTLDRecord(t, owner, "noclaim")
	err := a.PublishClaim(context.Background(), env)
	if err == nil {
		t.Fatal("PublishClaim accepted an envelope with no embedded claim")
	}
}

// TestDHTLookupClaimFetchAndCache verifies the resolver-side K_claim path
// (§9.2 step 3a via ClaimResolver): on a local miss DHTLookup.LookupClaim runs
// an iterative GET, returns the claim envelope, and caches it locally so the
// second lookup is served from the local store (mirroring the Lookup flow).
func TestDHTLookupClaimFetchAndCache(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	wkp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	env, kClaim := claimedTLDRecord(t, "lookupclaim", []*crypto.Keypair{wkp})
	// Seed A's store directly at K_claim (simulating -load), NOT via publish.
	if accepted, err := a.store.Put(kClaim, env, time.Now().Unix(), true); err != nil || !accepted {
		t.Fatalf("seed A store at K_claim: accepted=%v err=%v", accepted, err)
	}

	lookup := NewDHTLookup(b.store, b)
	now := time.Now().Unix()
	if got, _ := b.store.Get(kClaim, now); got != nil {
		t.Fatal("precondition: B should not have the claim envelope yet")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	got, err := lookup.LookupClaim(ctx, "lookupclaim", now)
	if err != nil {
		t.Fatalf("LookupClaim: %v", err)
	}
	if got == nil {
		t.Fatal("LookupClaim returned nil (network GET failed)")
	}
	gh, _ := got.RecordHash()
	eh, _ := env.RecordHash()
	if !bytes.Equal(gh, eh) {
		t.Error("fetched claim envelope mismatch")
	}
	// Cached in B's local store under K_claim.
	if cached, _ := b.store.Get(kClaim, now); cached == nil {
		t.Error("fetched claim envelope was not cached locally")
	}

	// An unknown alias returns (nil, nil), not an error.
	got, err = lookup.LookupClaim(ctx, "no-such-alias-anywhere", now)
	if err != nil || got != nil {
		t.Errorf("LookupClaim(unknown) = (%v, %v), want (nil, nil)", got, err)
	}
}
