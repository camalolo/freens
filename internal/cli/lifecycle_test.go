// lifecycle_test.go — transfer (§8.3) / rotate (§8.6) / recover (§8.4)
// end-to-end through the real CLI builders + DHT store. (Moved from
// cmd/freens-cli, unchanged semantics.)
package cli

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// ---------------------------------------------------------------------------
// transfer (§8.3) — end to end through the real CLI + DHT store
// ---------------------------------------------------------------------------

func TestTransferEndToEnd(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Unix()

	owner := lifecycleKeypair(t, 0xa1) // current owner (A7C91... in §8.3's example)
	buyer := lifecycleKeypair(t, 0xb2) // new owner (B82F1...)
	tldID, err := crypto.TldID(owner.Public())
	if err != nil {
		t.Fatal(err)
	}

	// "make-record": the incumbent record for www.<tld>.foo.
	rec := newSubNameRecord(t, []string{"www"}, owner, tldID, 1, now)
	prevEnv, prevPath := writeEnvelope(t, dir, "prev", rec, owner)

	// "transfer": signed by the CURRENT owner per §8.3 line 677/680-681.
	outPath := filepath.Join(dir, "transfer.cbor")
	args := []string{
		"-prev-envelope", prevPath,
		"-new-owner-seed", hex.EncodeToString(buyer.Seed()),
		"-signer-seed", hex.EncodeToString(owner.Seed()),
		"-out", outPath,
	}
	out, err := captureStdout(t, func() error { return cmdTransfer(args) })
	if err != nil {
		t.Fatalf("cmdTransfer: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "envelope_cbor=") || !strings.Contains(out, "handoff=transfer") {
		t.Errorf("transfer output missing make-record-style lines:\n%s", out)
	}

	// Decode + structural round-trip.
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	newEnv, err := wire.DecodeEnvelope(data)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	if !newEnv.VerifySignature() {
		t.Fatal("transferred envelope signature invalid")
	}
	if !bytes.Equal(newEnv.Record.Owner, buyer.Public()) {
		t.Error("owner must be the new owner key")
	}
	if !bytes.Equal(newEnv.Signer, owner.Public()) {
		t.Error("§8.3: signer must be the CURRENT (previous) owner key")
	}
	if newEnv.Record.Sequence != prevEnv.Record.Sequence+1 {
		t.Errorf("sequence = %d, want prev+1 = %d", newEnv.Record.Sequence, prevEnv.Record.Sequence+1)
	}
	if !bytes.Equal(newEnv.Record.Name, prevEnv.Record.Name) {
		t.Error("name must be carried over verbatim")
	}
	ph, err := prevEnv.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(newEnv.Record.PrevHash, ph) {
		t.Error("prev_hash must equal H_record(previous envelope)")
	}
	if !bytes.Equal(newEnv.Record.Delegation, buyer.Public()) {
		t.Error("delegation must follow the hand-off (subtree authority follows)")
	}
	if len(newEnv.Record.RRset) != 1 || newEnv.Record.RRset[0].Type != wire.RRTypeA ||
		!bytes.Equal(newEnv.Record.RRset[0].Rdata, []byte{203, 0, 113, 42}) {
		t.Error("RRset must carry over when -ip is not given")
	}

	// §8.3/§4.4-rule-4 chain link.
	if !wire.VerifyChainLink(newEnv, prevEnv) {
		t.Error("VerifyChainLink(new, prev) must hold")
	}

	// Store winner-rule path: a real EnvelopeStore accepts the transfer over
	// the alive incumbent (§6.4 step 3 + prev_hash enforcement).
	store := dht.NewEnvelopeStore(0, func() int64 { return now })
	key := naming.DHTKeyName(newEnv.Record.Name)
	if ok, err := store.Put(key, prevEnv, now, true); err != nil || !ok {
		t.Fatalf("incumbent put: accepted=%v err=%v", ok, err)
	}
	if ok, err := store.Put(key, newEnv, now+10, true); err != nil || !ok {
		t.Fatalf("transfer put over alive incumbent: accepted=%v err=%v", ok, err)
	}
	got, err := store.Get(key, now+10)
	if err != nil || got == nil {
		t.Fatalf("get after transfer: %v", err)
	}
	gh, _ := got.RecordHash()
	nh, _ := newEnv.RecordHash()
	if !bytes.Equal(gh, nh) {
		t.Error("store must serve the transferred envelope as the winner")
	}

	// A forged chain link is rejected: same shape but a wrong prev_hash.
	forged, err := wire.SignRecord(func() *wire.Record {
		r, err := wire.NewRecord(newEnv.Record.Name, buyer.Public(), newEnv.Record.Sequence+1, uint64(now), uint64(now+constants.RecordDefaultTTL))
		if err != nil {
			t.Fatal(err)
		}
		r.PrevHash = bytes.Repeat([]byte{0x00}, constants.SHA256Len)
		r.RRset = newEnv.Record.RRset
		return r
	}(), buyer)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.Put(key, forged, now+20, true); err != nil || ok {
		t.Errorf("forged prev_hash must be rejected by the store: accepted=%v err=%v", ok, err)
	}
}

func TestTransferWithIPReplacesRRset(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Unix()
	owner := lifecycleKeypair(t, 0xa1)
	tldID, _ := crypto.TldID(owner.Public())
	rec := newSubNameRecord(t, []string{"www"}, owner, tldID, 3, now)
	_, prevPath := writeEnvelope(t, dir, "prev", rec, owner)
	outPath := filepath.Join(dir, "t.cbor")

	out, err := captureStdout(t, func() error {
		return cmdTransfer([]string{
			"-prev-envelope", prevPath,
			"-new-owner-seed", hex.EncodeToString(lifecycleKeypair(t, 0xb2).Seed()),
			"-signer-seed", hex.EncodeToString(owner.Seed()),
			"-ip", "192.0.2.9", "-ttl", "60",
			"-out", outPath,
		})
	})
	if err != nil {
		t.Fatalf("cmdTransfer -ip: %v\n%s", err, out)
	}
	env, err := wire.DecodeEnvelope(mustRead(t, outPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Record.RRset) != 1 || env.Record.RRset[0].Type != wire.RRTypeA ||
		!bytes.Equal(env.Record.RRset[0].Rdata, []byte{192, 0, 2, 9}) || env.Record.RRset[0].TTL != 60 {
		t.Errorf("-ip must replace the RRset with one A record, got %+v", env.Record.RRset)
	}
}

func TestTransferWrongSignerRejected(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Unix()
	owner := lifecycleKeypair(t, 0xa1)
	impostor := lifecycleKeypair(t, 0xde)
	tldID, _ := crypto.TldID(owner.Public())
	rec := newSubNameRecord(t, []string{"www"}, owner, tldID, 1, now)
	_, prevPath := writeEnvelope(t, dir, "prev", rec, owner)

	// §8.3: the previous owner signs the transfer — the transferee cannot.
	if _, err := captureStdout(t, func() error {
		return cmdTransfer([]string{
			"-prev-envelope", prevPath,
			"-new-owner-seed", hex.EncodeToString(lifecycleKeypair(t, 0xb2).Seed()),
			"-signer-seed", hex.EncodeToString(impostor.Seed()),
		})
	}); err == nil {
		t.Error("transfer signed by a non-owner must be rejected")
	}
	// Missing required flags.
	if _, err := captureStdout(t, func() error { return cmdTransfer([]string{"-prev-envelope", prevPath}) }); err == nil {
		t.Error("transfer without -new-owner-seed/-signer-seed must be a usage error")
	}
}

// ---------------------------------------------------------------------------
// rotate (§8.6) — transfer to a fresh key
// ---------------------------------------------------------------------------

func TestRotateEndToEnd(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Unix()

	old := lifecycleKeypair(t, 0x01)
	fresh := lifecycleKeypair(t, 0x02)
	fresh2 := lifecycleKeypair(t, 0x03)
	tldID, _ := crypto.TldID(old.Public())

	rec := newSubNameRecord(t, []string{"www"}, old, tldID, 1, now)
	env1, prevPath := writeEnvelope(t, dir, "v1", rec, old)

	// First rotation: old -> fresh, signed by the current owner (old).
	out1 := filepath.Join(dir, "v2.cbor")
	if out, err := captureStdout(t, func() error {
		return cmdRotate([]string{
			"-prev-envelope", prevPath,
			"-new-seed", hex.EncodeToString(fresh.Seed()),
			"-signer-seed", hex.EncodeToString(old.Seed()),
			"-out", out1,
		})
	}); err != nil {
		t.Fatalf("cmdRotate: %v\n%s", err, out)
	}
	env2, err := wire.DecodeEnvelope(mustRead(t, out1))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(env2.Record.Owner, fresh.Public()) || !bytes.Equal(env2.Signer, old.Public()) {
		t.Errorf("rotate: owner=%x signer=%x, want owner=fresh signer=old", env2.Record.Owner, env2.Signer)
	}
	if !wire.VerifyChainLink(env2, env1) {
		t.Error("rotate must chain to the previous envelope (§8.6 -> §8.3 prev_hash)")
	}

	// Second rotation: fresh is now the current owner; the OLD key must no
	// longer be able to sign updates (§8.3 line 681-682: "After the transfer,
	// only B82F1... can sign further updates").
	out2 := filepath.Join(dir, "v3.cbor")
	if _, err := captureStdout(t, func() error {
		return cmdRotate([]string{
			"-prev-envelope", out1,
			"-new-seed", hex.EncodeToString(fresh2.Seed()),
			"-signer-seed", hex.EncodeToString(fresh.Seed()),
			"-out", out2,
		})
	}); err != nil {
		t.Fatalf("cmdRotate (2nd): %v", err)
	}
	env3, err := wire.DecodeEnvelope(mustRead(t, out2))
	if err != nil {
		t.Fatal(err)
	}
	if env3.Record.Sequence != 3 || !wire.VerifyChainLink(env3, env2) {
		t.Errorf("second rotate: sequence=%d chainlink=%v", env3.Record.Sequence, wire.VerifyChainLink(env3, env2))
	}
	if _, err := captureStdout(t, func() error {
		return cmdRotate([]string{
			"-prev-envelope", out1,
			"-new-seed", hex.EncodeToString(fresh2.Seed()),
			"-signer-seed", hex.EncodeToString(old.Seed()),
		})
	}); err == nil {
		t.Error("the pre-rotation key must not be able to sign after the rotation took effect")
	}
}

// ---------------------------------------------------------------------------
// recover (§8.4) — evidence generation + wire.VerifyRecovery
// ---------------------------------------------------------------------------

func TestRecoverEndToEnd(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Unix()

	owner := lifecycleKeypair(t, 0xa1)
	newOwner := lifecycleKeypair(t, 0xb2)
	r1 := lifecycleKeypair(t, 0x51)
	r2 := lifecycleKeypair(t, 0x52)
	r3 := lifecycleKeypair(t, 0x53)
	tldID, err := crypto.TldID(owner.Public())
	if err != nil {
		t.Fatal(err)
	}

	// Previous record with a 2-of-3 recovery policy (field 10).
	rec := newSubNameRecord(t, []string{"www"}, owner, tldID, 1, now)
	policy, err := wire.NewRecoveryPolicyWire(2, [][]byte{r1.Public(), r2.Public(), r3.Public()}, constants.RecoveryTimelock)
	if err != nil {
		t.Fatal(err)
	}
	rec.Recovery = policy
	prevEnv, prevPath := writeEnvelope(t, dir, "prev", rec, owner)
	prevHash, err := prevEnv.RecordHash()
	if err != nil {
		t.Fatal(err)
	}

	evPath := filepath.Join(dir, "evidence.cbor")
	args := []string{
		"-prev-envelope", prevPath,
		"-new-owner-seed", hex.EncodeToString(newOwner.Seed()),
		"-recovery-seeds", strings.Join([]string{
			hex.EncodeToString(r3.Seed()), // order-insensitive quorum
			hex.EncodeToString(r1.Seed()),
		}, ","),
		"-out", evPath,
	}
	if out, err := captureStdout(t, func() error { return cmdRecover(args) }); err != nil {
		t.Fatalf("cmdRecover: %v\n%s", err, out)
	}

	ev, err := wire.DecodeRecoveryEvidence(mustRead(t, evPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ev.NewOwnerPK, newOwner.Public()) {
		t.Error("evidence must name the new primary key")
	}
	// §8.4 line 694: execute_not_before = now + timelock (allow a 1-2 s
	// skew between the test's clock reading and the command's).
	if ev.NotBefore < uint64(now)+constants.RecoveryTimelock || ev.NotBefore > uint64(now)+constants.RecoveryTimelock+2 {
		t.Errorf("execute_not_before = %d, want now+timelock ≈ %d", ev.NotBefore, uint64(now)+constants.RecoveryTimelock)
	}

	// §8.4 step 3: verifies only once the timelock has elapsed.
	if wire.VerifyRecovery(policy, ev, prevHash, uint64(now)) {
		t.Error("recovery must not verify before the timelock elapses")
	}
	if !wire.VerifyRecovery(policy, ev, prevHash, ev.NotBefore) {
		t.Error("threshold quorum after the timelock must verify")
	}

	// Below threshold: one recovery key is not a 2-of-3 quorum.
	subPath := filepath.Join(dir, "sub.cbor")
	if out, err := captureStdout(t, func() error {
		return cmdRecover([]string{
			"-prev-envelope", prevPath,
			"-new-owner-seed", hex.EncodeToString(newOwner.Seed()),
			"-recovery-seeds", hex.EncodeToString(r1.Seed()),
			"-out", subPath,
		})
	}); err != nil {
		t.Fatalf("cmdRecover (partial quorum should still assemble): %v\n%s", err, out)
	}
	sub, err := wire.DecodeRecoveryEvidence(mustRead(t, subPath))
	if err != nil {
		t.Fatal(err)
	}
	if wire.VerifyRecovery(policy, sub, prevHash, sub.NotBefore) {
		t.Error("below-threshold evidence must not verify")
	}

	// A key that is not in the policy may not sign the declaration.
	if _, err := captureStdout(t, func() error {
		return cmdRecover([]string{
			"-prev-envelope", prevPath,
			"-new-owner-seed", hex.EncodeToString(newOwner.Seed()),
			"-recovery-seeds", hex.EncodeToString(lifecycleKeypair(t, 0xee).Seed()),
			"-out", filepath.Join(dir, "bad.cbor"),
		})
	}); err == nil {
		t.Error("recovery seed outside the policy's key set must be rejected")
	}

	// No policy on the record -> §8.4: the name cannot be re-pointered.
	bare := newSubNameRecord(t, []string{"www2"}, owner, tldID, 1, now)
	_, barePath := writeEnvelope(t, dir, "bare", bare, owner)
	if _, err := captureStdout(t, func() error {
		return cmdRecover([]string{
			"-prev-envelope", barePath,
			"-new-owner-seed", hex.EncodeToString(newOwner.Seed()),
			"-recovery-seeds", hex.EncodeToString(r1.Seed()),
			"-out", filepath.Join(dir, "x.cbor"),
		})
	}); err == nil {
		t.Error("recover against a record with no field-10 policy must fail")
	}
}
