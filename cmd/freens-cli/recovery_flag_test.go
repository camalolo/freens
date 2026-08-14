package main

// recovery_flag_test.go exercises make-record's -recovery-* flags (spec 5.4,
// lines 373-394): the CLI-side construction of the field-10 recovery policy
// that `freens-cli recover` (§8.4) later consumes. Until these flags existed
// the §8.4 flow was only reachable programmatically (see lifecycle_test.go).

import (
	"encoding/base32"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/wire"
)

// makeRecordArgs assembles a make-record flag slice for name owned by owner
// (-pin derived from the owner's tld_id), plus extra flags.
func makeRecordArgs(t *testing.T, name string, owner *crypto.Keypair, extra ...string) []string {
	t.Helper()
	tldID, err := crypto.TldID(owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	args := []string{
		"-name", name,
		"-owner-seed", hex.EncodeToString(owner.Seed()),
		"-ip", "203.0.113.42",
		"-pin", base32.StdEncoding.EncodeToString(tldID),
	}
	return append(args, extra...)
}

// runMakeRecord executes cmdMakeRecord with captureStdout and returns the
// printed lines plus the envelope decoded from -out.
func runMakeRecord(t *testing.T, args []string) (string, *wire.SignedEnvelope) {
	t.Helper()
	out, err := captureStdout(t, func() error { return cmdMakeRecord(args) })
	if err != nil {
		t.Fatalf("cmdMakeRecord: %v\noutput:\n%s", err, out)
	}
	env, err := wire.DecodeEnvelope(mustRead(t, args[outFlagIndex(t, args)]))
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	return out, env
}

// outFlagIndex returns the value position of -out in args (for runMakeRecord).
func outFlagIndex(t *testing.T, args []string) int {
	t.Helper()
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-out" {
			return i + 1
		}
	}
	t.Fatal("args missing -out")
	return -1
}

// TestMakeRecordRecoveryRoundTrip asserts the -recovery-* flags embed a
// field-10 policy (spec 5.4: {1: threshold, 2: keys, 3: timelock}) that
// round-trips through the written envelope, and that the §8.4 recover flow
// consumes the CLI-produced record end to end.
func TestMakeRecordRecoveryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	owner := lifecycleKeypair(t, 0xa1)
	r1 := lifecycleKeypair(t, 0x51)
	r2 := lifecycleKeypair(t, 0x52)
	newOwner := lifecycleKeypair(t, 0xb2)

	recPath := filepath.Join(dir, "rec.cbor")
	out, env := runMakeRecord(t, makeRecordArgs(t, "www.example", owner,
		"-recovery-keys", strings.Join([]string{
			hex.EncodeToString(r1.Public()),
			hex.EncodeToString(r2.Public()),
		}, ","),
		"-recovery-threshold", "2",
		"-recovery-timelock", "3600",
		"-out", recPath,
	))

	// Output summary lines, like the other make-record extras.
	for _, want := range []string{
		"recovery_threshold=2\n",
		"recovery_keys=2\n",
		"recovery_timelock=3600\n",
		"wrote=" + recPath + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("make-record output missing %q:\n%s", want, out)
		}
	}

	// §5.4 field-10 round-trip via wire.
	if !env.VerifySignature() {
		t.Error("envelope signature must cover the embedded policy")
	}
	pol := env.Record.Recovery
	if pol == nil {
		t.Fatal("Record.Recovery must be set when -recovery-keys is given")
	}
	if pol.Threshold != 2 || len(pol.Keys) != 2 || pol.Timelock != 3600 {
		t.Errorf("policy = %d-of-%d timelock=%d, want 2-of-2 timelock=3600", pol.Threshold, len(pol.Keys), pol.Timelock)
	}
	for i, kp := range []*crypto.Keypair{r1, r2} {
		if string(pol.Keys[i]) != string(kp.Public()) {
			t.Errorf("policy key %d = %x, want %x", i, pol.Keys[i], kp.Public())
		}
	}

	// §8.4: recover reads the PREV record's field-10 policy — previously
	// only reachable programmatically.
	evPath := filepath.Join(dir, "evidence.cbor")
	recOut, err := captureStdout(t, func() error {
		return cmdRecover([]string{
			"-prev-envelope", recPath,
			"-new-owner-seed", hex.EncodeToString(newOwner.Seed()),
			"-recovery-seeds", strings.Join([]string{
				hex.EncodeToString(r1.Seed()),
				hex.EncodeToString(r2.Seed()),
			}, ","),
			"-out", evPath,
		})
	})
	if err != nil {
		t.Fatalf("cmdRecover over make-record output: %v\n%s", err, recOut)
	}
	ev, err := wire.DecodeRecoveryEvidence(mustRead(t, evPath))
	if err != nil {
		t.Fatal(err)
	}
	prevHash, err := env.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	if !wire.VerifyRecovery(pol, ev, prevHash, ev.NotBefore) {
		t.Error("threshold evidence over the CLI-built policy must verify after the timelock")
	}
}

// TestMakeRecordRecoveryTimelockDefault: -recovery-timelock absent or
// present-but-zero falls back to constants.RecoveryTimelock (259200 = 72 h,
// spec 5.4), mirroring -ttl/-expires default handling.
func TestMakeRecordRecoveryTimelockDefault(t *testing.T) {
	dir := t.TempDir()
	owner := lifecycleKeypair(t, 0xa1)
	r1 := lifecycleKeypair(t, 0x51)

	for _, tc := range []struct {
		name string
		flag []string
	}{
		{name: "absent", flag: nil},
		{name: "zero", flag: []string{"-recovery-timelock", "0"}},
	} {
		args := makeRecordArgs(t, "t.example", owner,
			"-recovery-keys", hex.EncodeToString(r1.Public()),
			"-recovery-threshold", "1",
			"-out", filepath.Join(dir, tc.name+".cbor"))
		args = append(args, tc.flag...)
		_, env := runMakeRecord(t, args)
		if pol := env.Record.Recovery; pol == nil {
			t.Fatalf("%s: Record.Recovery unset", tc.name)
		} else if pol.Timelock != constants.RecoveryTimelock {
			t.Errorf("%s: timelock = %d, want default %d (72 h)", tc.name, pol.Timelock, constants.RecoveryTimelock)
		}
	}
}

// TestMakeRecordRecoveryInvalidThreshold: threshold 0 (absent) and threshold
// greater than the key count are usage errors (spec 5.4: 1 <= t <= len(keys)).
func TestMakeRecordRecoveryInvalidThreshold(t *testing.T) {
	dir := t.TempDir()
	owner := lifecycleKeypair(t, 0xa1)
	r1 := lifecycleKeypair(t, 0x51)
	r2 := lifecycleKeypair(t, 0x52)
	keys := strings.Join([]string{
		hex.EncodeToString(r1.Public()),
		hex.EncodeToString(r2.Public()),
	}, ",")

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "absent threshold", args: []string{"-recovery-keys", keys}},
		{name: "zero threshold", args: []string{"-recovery-keys", keys, "-recovery-threshold", "0"}},
		{name: "threshold above key count", args: []string{"-recovery-keys", keys, "-recovery-threshold", "3"}},
	} {
		args := makeRecordArgs(t, "t.example", owner, tc.args...)
		args = append(args, "-out", filepath.Join(dir, "x.cbor"))
		if _, err := captureStdout(t, func() error {
			return cmdMakeRecord(args)
		}); err == nil {
			t.Errorf("%s must be rejected", tc.name)
		}
	}
}

// TestMakeRecordRecoveryBadKeyHex: non-hex and wrong-length keys are usage
// errors (spec 5.4 field 2 is bstr(32) = exactly 64 hex chars).
func TestMakeRecordRecoveryBadKeyHex(t *testing.T) {
	owner := lifecycleKeypair(t, 0xa1)
	for _, key := range []string{
		"not-hex!",                    // invalid hex
		strings.Repeat("ab", 31),      // 62 hex chars = 31 bytes
		strings.Repeat("ab", 33),      // 66 hex chars = 33 bytes
		hex.EncodeToString([]byte{0}), // decodes fine, wrong length
	} {
		if _, err := captureStdout(t, func() error {
			return cmdMakeRecord(makeRecordArgs(t, "t.example", owner,
				"-recovery-keys", key,
				"-recovery-threshold", "1"))
		}); err == nil {
			t.Errorf("-recovery-keys %q must be rejected", key)
		}
	}
}

// TestMakeRecordNoRecoveryFlags: without -recovery-* the record carries no
// policy (field 10 omitted) — regression guard for the pre-existing behavior.
func TestMakeRecordNoRecoveryFlags(t *testing.T) {
	owner := lifecycleKeypair(t, 0xa1)
	out, env := runMakeRecord(t, makeRecordArgs(t, "t.example", owner,
		"-out", filepath.Join(t.TempDir(), "bare.cbor")))
	if env.Record.Recovery != nil {
		t.Error("Record.Recovery must stay nil without -recovery-keys")
	}
	if strings.Contains(out, "recovery_") {
		t.Errorf("no policy summary expected without flags:\n%s", out)
	}
}
