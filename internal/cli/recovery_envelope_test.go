// recovery_envelope_test.go exercises the §8.4 recovered-record side of the
// CLI: `recover -out-envelope` (the R2 signed envelope the NEW owner signs —
// the opposite of §8.3's transfer signer), `verify-recovery` (the pure-wire
// quorum/threshold/timelock report), and `publish -evidence`'s flag/decode
// validation plus the no-silent-fallback guarantee of the evidence
// transport helper. (Moved from cmd/freens-cli, unchanged semantics.)
package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/dht"
	"github.com/laurent/freens/internal/naming"
	"github.com/laurent/freens/internal/wire"
)

// runRecover executes cmdRecover with captureStdout and returns the printed
// lines plus the decoded evidence written to evPath.
func runRecover(t *testing.T, args []string) (string, *wire.RecoveryEvidence) {
	t.Helper()
	out, err := captureStdout(t, func() error { return cmdRecover(args) })
	if err != nil {
		t.Fatalf("cmdRecover: %v\noutput:\n%s", err, out)
	}
	ev, err := wire.DecodeRecoveryEvidence(mustRead(t, args[evidenceOutIndex(t, args)]))
	if err != nil {
		t.Fatalf("DecodeRecoveryEvidence: %v", err)
	}
	return out, ev
}

// evidenceOutIndex returns the value position of -out in args (for runRecover).
func evidenceOutIndex(t *testing.T, args []string) int {
	t.Helper()
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-out" {
			return i + 1
		}
	}
	t.Fatal("args missing -out")
	return -1
}

// TestRecoverOutEnvelopeBuildsR2: -out-envelope writes the §8.4 recovered
// record R2 — name/rrset/policy carried over from R1, owner = the new key,
// sequence = R1+1, prev_hash = H(R1), fresh window, and signed by the NEW
// owner (the OPPOSITE signer convention of §8.3 transfer).
func TestRecoverOutEnvelopeBuildsR2(t *testing.T) {
	dir := t.TempDir()
	owner := lifecycleKeypair(t, 0xa1)
	r1k := lifecycleKeypair(t, 0x51)
	r2k := lifecycleKeypair(t, 0x52)
	newOwner := lifecycleKeypair(t, 0xb2)

	recPath := filepath.Join(dir, "r1.cbor")
	_, r1 := runMakeRecord(t, makeRecordArgs(t, "www.example", owner,
		"-recovery-keys", strings.Join([]string{
			hex.EncodeToString(r1k.Public()),
			hex.EncodeToString(r2k.Public()),
		}, ","),
		"-recovery-threshold", "2",
		"-recovery-timelock", "3600",
		"-ttl", "300",
		"-out", recPath,
	))
	r1Hash, err := r1.RecordHash()
	if err != nil {
		t.Fatal(err)
	}

	evPath := filepath.Join(dir, "evidence.cbor")
	r2Path := filepath.Join(dir, "r2.cbor")
	out, ev := runRecover(t, []string{
		"-prev-envelope", recPath,
		"-new-owner-seed", hex.EncodeToString(newOwner.Seed()),
		"-recovery-seeds", strings.Join([]string{
			hex.EncodeToString(r1k.Seed()),
			hex.EncodeToString(r2k.Seed()),
		}, ","),
		"-out", evPath,
		"-out-envelope", r2Path,
	})

	// Output conventions (handoff-style lines + the rotate advice).
	for _, want := range []string{
		"envelope_file=" + r2Path + "\n",
		"signer=" + hex.EncodeToString(newOwner.Public()) + " (NEW owner, spec 8.4",
		"recovery_policy=carried over unchanged (threshold 2 of 2)\n",
		"wrote=" + r2Path + "\n",
		"rotate the recovery keys afterwards",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("recover output missing %q:\n%s", want, out)
		}
	}

	// R2 structure per §8.4 ("published like any record (sequence +1)").
	r2, err := wire.DecodeEnvelope(mustRead(t, r2Path))
	if err != nil {
		t.Fatal(err)
	}
	rec := r2.Record
	if !bytes.Equal(rec.Name, r1.Record.Name) {
		t.Error("R2 must carry over R1's wire name verbatim")
	}
	if !bytes.Equal(rec.Owner, newOwner.Public()) {
		t.Errorf("R2 owner = %x, want the new owner %x", rec.Owner, newOwner.Public())
	}
	if rec.Sequence != r1.Record.Sequence+1 {
		t.Errorf("R2 sequence = %d, want R1+1 = %d", rec.Sequence, r1.Record.Sequence+1)
	}
	if !bytes.Equal(rec.PrevHash, r1Hash) {
		t.Error("R2 prev_hash must be H(R1 envelope)")
	}
	// The §8.4 signer convention: the NEW owner signs (in a transfer the
	// PREVIOUS owner signs — recovery is the opposite).
	if !bytes.Equal(r2.Signer, newOwner.Public()) {
		t.Errorf("R2 signer = %x, want the NEW owner %x", r2.Signer, newOwner.Public())
	}
	if !r2.VerifySignature() {
		t.Error("R2 signature must verify")
	}
	// Policy carried over unchanged.
	if rec.Recovery == nil || rec.Recovery.Threshold != 2 || len(rec.Recovery.Keys) != 2 || rec.Recovery.Timelock != 3600 {
		t.Errorf("R2 recovery policy = %+v, want R1's 2-of-2 timelock 3600", rec.Recovery)
	}
	// RRset carried over with its TTL.
	if len(rec.RRset) != 1 || rec.RRset[0].TTL != 300 || !bytes.Equal(rec.RRset[0].Rdata, r1.Record.RRset[0].Rdata) {
		t.Errorf("R2 rrset = %+v, want R1's carried verbatim", rec.RRset)
	}
	// Fresh window, floored at 3600 s (§task: remaining lifetime, min 3600).
	if rec.Created < uint64(time.Now().Unix())-5 {
		t.Errorf("R2 created = %d, want ~now", rec.Created)
	}
	if rec.Expires < rec.Created+constants.ResponseTTLCap {
		t.Errorf("R2 expires-created = %d, want >= the 3600 s floor", rec.Expires-rec.Created)
	}
	// The pairing invariant: R2 + this evidence verify against R1's policy
	// at the earliest executable instant (the self-check cmdRecover ran).
	if !wire.VerifyRecovery(rec.Recovery, ev, r1Hash, ev.NotBefore) {
		t.Error("R2's paired evidence must verify against R1's policy after the timelock")
	}
}

// TestRecoverOutEnvelopeTTLDefaultAndExpiresFloor: a TTL-less (0) carried RR
// defaults to 3600, and an almost-expired R1 still yields an R2 with the
// 3600 s minimum lifetime.
func TestRecoverOutEnvelopeTTLDefaultAndExpiresFloor(t *testing.T) {
	dir := t.TempDir()
	owner := lifecycleKeypair(t, 0xa1)
	r1k := lifecycleKeypair(t, 0x51)
	newOwner := lifecycleKeypair(t, 0xb2)

	// Build R1 by hand: an RR with TTL 0 (NewRR would reject it, but a
	// decoded envelope can carry one) and an expiry 100 s out.
	now := uint64(time.Now().Unix())
	tldID, err := crypto.TldID(owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	wireName, err := naming.EncodeWireName([]string{"www"}, "example", tldID)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(wireName, owner.Public(), 7, now, now+100)
	if err != nil {
		t.Fatal(err)
	}
	rec.RRset = []*wire.RR{{Type: wire.RRTypeA, TTL: 0, Rdata: []byte{203, 0, 113, 42}}}
	pol, err := wire.NewRecoveryPolicyWire(1, [][]byte{r1k.Public()}, 60)
	if err != nil {
		t.Fatal(err)
	}
	rec.Recovery = pol
	r1, err := wire.SignRecord(rec, owner)
	if err != nil {
		t.Fatal(err)
	}
	r1Bytes, err := r1.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	recPath := filepath.Join(dir, "r1.cbor")
	if err := os.WriteFile(recPath, r1Bytes, 0o644); err != nil {
		t.Fatal(err)
	}

	r2Path := filepath.Join(dir, "r2.cbor")
	_, _ = runRecover(t, []string{
		"-prev-envelope", recPath,
		"-new-owner-seed", hex.EncodeToString(newOwner.Seed()),
		"-recovery-seeds", hex.EncodeToString(r1k.Seed()),
		"-out", filepath.Join(dir, "evidence.cbor"),
		"-out-envelope", r2Path,
	})
	r2, err := wire.DecodeEnvelope(mustRead(t, r2Path))
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.Record.RRset) != 1 || r2.Record.RRset[0].TTL != constants.ResponseTTLCap {
		t.Errorf("carried RR TTL = %d, want the 3600 default", r2.Record.RRset[0].TTL)
	}
	if d := int64(r2.Record.Expires) - int64(now); d < int64(constants.ResponseTTLCap)-5 {
		t.Errorf("R2 lifetime = %d s from R1's expiry, want the >= 3600 s floor", d)
	}
	if r2.Record.Sequence != 8 {
		t.Errorf("R2 sequence = %d, want 8", r2.Record.Sequence)
	}
}

// TestVerifyRecoveryStatuses: the human-readable report for the three
// §8.4 outcomes — quorum OK + timelock elapsed (nil error), quorum OK +
// timelock pending, and quorum below threshold (both failures exit 2 via
// cryptoErr) — plus usage validation.
func TestVerifyRecoveryStatuses(t *testing.T) {
	dir := t.TempDir()
	owner := lifecycleKeypair(t, 0xa1)
	r1k := lifecycleKeypair(t, 0x51)
	r2k := lifecycleKeypair(t, 0x52)
	newOwner := lifecycleKeypair(t, 0xb2)

	recPath := filepath.Join(dir, "r1.cbor")
	runMakeRecord(t, makeRecordArgs(t, "www.example", owner,
		"-recovery-keys", strings.Join([]string{
			hex.EncodeToString(r1k.Public()),
			hex.EncodeToString(r2k.Public()),
		}, ","),
		"-recovery-threshold", "2",
		"-recovery-timelock", "3600",
		"-out", recPath,
	))
	evPath := filepath.Join(dir, "evidence.cbor")
	_, ev := runRecover(t, []string{
		"-prev-envelope", recPath,
		"-new-owner-seed", hex.EncodeToString(newOwner.Seed()),
		"-recovery-seeds", strings.Join([]string{
			hex.EncodeToString(r1k.Seed()),
			hex.EncodeToString(r2k.Seed()),
		}, ","),
		"-out", evPath,
	})

	// After the timelock: OK, quorum 2/2, human-readable expiry instant.
	out, err := captureStdout(t, func() error {
		return cmdVerifyRecovery([]string{"-prev-envelope", recPath, "-evidence", evPath, "-now", strconv.FormatUint(ev.NotBefore, 10)})
	})
	if err != nil {
		t.Fatalf("verify at NotBefore must succeed: %v\n%s", err, out)
	}
	for _, want := range []string{
		"quorum=2\n",
		"threshold=2\n",
		"keys=2\n",
		"status=quorum 2/2 OK, timelock expires ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output missing %q:\n%s", want, out)
		}
	}

	// Before the timelock: quorum fine but not executable — failure (exit 2).
	out, err = captureStdout(t, func() error {
		return cmdVerifyRecovery([]string{"-prev-envelope", recPath, "-evidence", evPath, "-now", strconv.FormatUint(ev.NotBefore-1, 10)})
	})
	if err == nil {
		t.Fatalf("verify before the timelock must fail:\n%s", out)
	}
	if !strings.Contains(err.Error(), "timelock not elapsed") || !strings.Contains(err.Error(), "quorum 2/2 OK") {
		t.Errorf("failure reason = %q, want the timelock-pending breakdown", err)
	}
	if !strings.Contains(out, "quorum=2\n") {
		t.Errorf("the quorum lines must still print on failure:\n%s", out)
	}

	// Below threshold: only 1 of 2 keys signed (recover warns, not errors).
	partialPath := filepath.Join(dir, "partial.cbor")
	if pout, perr := captureStdout(t, func() error {
		return cmdRecover([]string{
			"-prev-envelope", recPath,
			"-new-owner-seed", hex.EncodeToString(newOwner.Seed()),
			"-recovery-seeds", hex.EncodeToString(r1k.Seed()),
			"-out", partialPath,
		})
	}); perr != nil {
		t.Fatalf("gathering a partial quorum is not an error: %v\n%s", perr, pout)
	}
	out, err = captureStdout(t, func() error {
		return cmdVerifyRecovery([]string{"-prev-envelope", recPath, "-evidence", partialPath})
	})
	if err == nil || !strings.Contains(err.Error(), "quorum 1/2 BELOW THRESHOLD") {
		t.Errorf("below-threshold verdict = %v, want quorum 1/2 BELOW THRESHOLD\n%s", err, out)
	}

	// Evidence replayed against the WRONG previous record: 0 signatures
	// match (the §8.4 message binds H_record), so below threshold.
	otherPath := filepath.Join(dir, "other.cbor")
	runMakeRecord(t, makeRecordArgs(t, "www.example", owner,
		"-recovery-keys", strings.Join([]string{
			hex.EncodeToString(r1k.Public()),
			hex.EncodeToString(r2k.Public()),
		}, ","),
		"-recovery-threshold", "2",
		"-recovery-timelock", "3600",
		"-seq", "5",
		"-out", otherPath,
	))
	out, err = captureStdout(t, func() error {
		return cmdVerifyRecovery([]string{"-prev-envelope", otherPath, "-evidence", evPath})
	})
	if err == nil || !strings.Contains(err.Error(), "quorum 0/2 BELOW THRESHOLD") {
		t.Errorf("wrong-prev verdict = %v, want quorum 0/2 BELOW THRESHOLD\n%s", err, out)
	}

	// Usage validation.
	for _, args := range [][]string{
		{"-prev-envelope", recPath},
		{"-evidence", evPath},
	} {
		if _, err := captureStdout(t, func() error { return cmdVerifyRecovery(args) }); err == nil {
			t.Errorf("verify-recovery %v must be a usage error", args)
		}
	}
}

// TestPublishEvidenceFlagValidation: -evidence requires exactly ONE -file,
// and the evidence bytes are read + decoded BEFORE the transport is chosen
// (a typo'd path or garbage file is a fast local error, not a network one).
func TestPublishEvidenceFlagValidation(t *testing.T) {
	tempHome(t) // publish consults the admin socket via pickTransport
	dir := t.TempDir()
	owner := lifecycleKeypair(t, 0xa1)
	f1 := filepath.Join(dir, "a.cbor")
	f2 := filepath.Join(dir, "b.cbor")
	runMakeRecord(t, makeRecordArgs(t, "t.example", owner, "-out", f1))
	runMakeRecord(t, makeRecordArgs(t, "t.example", owner, "-out", f2))
	evPath := filepath.Join(dir, "evidence.cbor")

	// Two files: usage error naming the one-file shape.
	_, err := captureStdout(t, func() error {
		return cmdPublish([]string{"-files", f1 + "," + f2, "-evidence", evPath, "-peers", "127.0.0.1:15354#" + strings.Repeat("ab", 32)})
	})
	if err == nil || !strings.Contains(err.Error(), "exactly ONE -file") {
		t.Errorf("two-file -evidence verdict = %v, want the one-file usage error", err)
	}

	// Missing evidence path: fails on the read, before the transport is even
	// chosen (the error names the evidence file, not the peers/daemon).
	_, err = captureStdout(t, func() error {
		return cmdPublish([]string{"-files", f1, "-evidence", filepath.Join(dir, "missing.cbor")})
	})
	if err == nil || !strings.Contains(err.Error(), "missing.cbor") || strings.Contains(err.Error(), "peers") {
		t.Errorf("missing evidence verdict = %v, want the local read error naming the evidence file", err)
	}

	// Garbage evidence bytes: decode error.
	junkPath := filepath.Join(dir, "junk.cbor")
	if werr := os.WriteFile(junkPath, []byte("not cbor"), 0o644); werr != nil {
		t.Fatal(werr)
	}
	_, err = captureStdout(t, func() error {
		return cmdPublish([]string{"-files", f1, "-evidence", junkPath})
	})
	if err == nil || !strings.Contains(err.Error(), "decode evidence") {
		t.Errorf("garbage evidence verdict = %v, want a decode error", err)
	}
}

// TestPublishNoPeersNoDaemon: neither -peers nor a daemon — the standing
// product error telling the user to run setup.
func TestPublishNoPeersNoDaemon(t *testing.T) {
	tempHome(t)
	dir := t.TempDir()
	owner := lifecycleKeypair(t, 0xa1)
	f1 := filepath.Join(dir, "a.cbor")
	runMakeRecord(t, makeRecordArgs(t, "t.example", owner, "-out", f1))
	_, err := captureStdout(t, func() error {
		return cmdPublish([]string{"-files", f1})
	})
	if err == nil || err.Error() != errNoDaemon.Error() {
		t.Errorf("publish without peers/daemon verdict = %v, want %v", err, errNoDaemon)
	}
}

// TestPublishWithEvidenceNeverSilentlyFallsBack: the §8.4 transport helper
// must never quietly degrade to a plain Publish. With the internal/dht
// PublishWithEvidence merge, *dht.Node satisfies evidencePublisher and the
// call runs the real transport: valid evidence + a peerless node fails with
// the publish-side error, and junk evidence fails the transport's own
// decode gate. Either way this call cannot succeed.
func TestPublishWithEvidenceNeverSilentlyFallsBack(t *testing.T) {
	owner := lifecycleKeypair(t, 0xa1)
	rkey := lifecycleKeypair(t, 0x51)
	tldID, err := crypto.TldID(owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	wireName, err := naming.EncodeWireName(nil, "example", tldID)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(wireName, owner.Public(), 1, uint64(time.Now().Unix()), uint64(time.Now().Unix())+3600)
	if err != nil {
		t.Fatal(err)
	}
	aRR, err := wire.A([]byte{203, 0, 113, 42}, 300)
	if err != nil {
		t.Fatal(err)
	}
	rec.RRset = []*wire.RR{aRR}
	env, err := wire.SignRecord(rec, owner)
	if err != nil {
		t.Fatal(err)
	}
	// Valid §8.4 evidence over this envelope's H_record (1-of-1 policy key).
	envHash, err := env.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := wire.RecoverySigningMessage(envHash, owner.Public(), uint64(time.Now().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	ev := &wire.RecoveryEvidence{NewOwnerPK: owner.Public(), Signatures: [][]byte{rkey.Sign(msg)}, NotBefore: uint64(time.Now().Unix())}
	evBytes, err := ev.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	node, err := dht.NewNode(dht.NodeConfig{
		Keypair:               owner,
		ListenAddr:            "127.0.0.1:0",
		Store:                 dht.NewEnvelopeStore(0, nil),
		Logger:                slog.New(slog.NewTextHandler(io.Discard, nil)),
		BucketRefreshInterval: -1,
		RepublishInterval:     -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Start(); err != nil {
		t.Fatal(err)
	}
	defer node.Close()

	// Valid evidence, no peers: the real transport runs and must fail — no
	// silent success, and no plain-publish detour around the evidence.
	err = publishWithEvidence(context.Background(), node, env, evBytes)
	if err == nil {
		t.Fatal("publishWithEvidence with no peers must not succeed (and must never fall back to a plain publish)")
	}
	if !strings.Contains(err.Error(), "peer") && !strings.Contains(err.Error(), "PublishWithEvidence") {
		t.Errorf("peerless publish error shape: %v", err)
	}

	// Junk evidence: refused by the transport's own decode gate.
	if err := publishWithEvidence(context.Background(), node, env, []byte{0xa0}); err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Errorf("junk evidence verdict = %v, want the transport's evidence decode gate", err)
	}
}
