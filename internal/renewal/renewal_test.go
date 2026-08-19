// renewal_test.go — the lease-extension semantics: seq+1, fresh window,
// everything carried, owner-only, revoked-refused, threshold math.
package renewal

import (
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

func buildRecord(t *testing.T, seq, created, expires uint64, rev bool) (*wire.SignedEnvelope, *crypto.Keypair) {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	name, err := naming.EncodeWireName(nil, "renew-test", tldID)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(name, kp.Public(), seq, created, expires)
	if err != nil {
		t.Fatal(err)
	}
	a, err := wire.A([]byte{203, 0, 113, 7}, 300)
	if err != nil {
		t.Fatal(err)
	}
	rec.RRset = []*wire.RR{a}
	if rev {
		b := true
		rec.Revoke = &b
		rec.RRset = nil
	}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	return env, kp
}

func TestRenewEnvelope(t *testing.T) {
	now := time.Now().Unix()
	env, kp := buildRecord(t, 4, uint64(now-3600), uint64(now+1000), false)

	out, err := RenewEnvelope(env, kp, now)
	if err != nil {
		t.Fatalf("RenewEnvelope: %v", err)
	}
	if out.Record.Sequence != 5 {
		t.Errorf("sequence = %d, want 5", out.Record.Sequence)
	}
	if out.Record.Expires != uint64(now+constants.RecordDefaultTTL) {
		t.Errorf("expires = %d, want now+86400", out.Record.Expires)
	}
	if len(out.Record.RRset) != 1 {
		t.Errorf("rrset = %d entries, want carried over", len(out.Record.RRset))
	}
	if out.IsRevoked() {
		t.Error("renewal marked revoked (input was not)")
	}
	if !out.VerifySignature() {
		t.Error("renewed envelope fails signature")
	}
}

func TestRenewEnvelopeOwnerOnly(t *testing.T) {
	now := time.Now().Unix()
	env, _ := buildRecord(t, 1, uint64(now-10), uint64(now+80000), false)
	other, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RenewEnvelope(env, other, now); err == nil {
		t.Fatal("non-owner renewal accepted")
	}
}

func TestRenewEnvelopeRefusesRevoked(t *testing.T) {
	now := time.Now().Unix()
	env, kp := buildRecord(t, 2, uint64(now-10), uint64(now+80000), true)
	if _, err := RenewEnvelope(env, kp, now); err == nil {
		t.Fatal("revoked record renewed (revocation is deliberate death)")
	}
}

func TestShouldRenew(t *testing.T) {
	now := time.Now().Unix()
	ttl := int64(constants.RecordDefaultTTL)
	if !ShouldRenew(now, now-ttl, now-10) {
		t.Error("expired record does not need renewal")
	}
	if !ShouldRenew(now, now-ttl, now+1000) {
		t.Error("record inside the final 20% of its own lifetime does not renew")
	}
	if ShouldRenew(now, now-ttl, now+int64(float64(ttl)*0.9)) {
		t.Error("record at 90% of its own lifetime renews too early")
	}
	// v0.8.0: the anchor is the record's OWN window, not RecordDefaultTTL —
	// a 30-day record (RecordMaxTTL) must NOT be renewed at the 24 h cadence
	// (day 19 of 30 was ~37% elapsed, far outside any renewal threshold).
	long := int64(constants.RecordMaxTTL)
	if ShouldRenew(now, now-long, now+int64(float64(long)*0.7)) {
		t.Error("30-day record at 30% elapsed renewed at the default-TTL cadence (anchor regression)")
	}
	if !ShouldRenew(now, now-long, now+int64(float64(long)*0.05)) {
		t.Error("30-day record inside its final 20% does not renew")
	}
	// Degenerate window (created after expires, still "unexpired" on the
	// clock — unreachable through wire.Validate, defensive only) falls
	// back to the default-TTL cadence: a large remaining lifetime does
	// NOT renew instantly.
	if ShouldRenew(now, now+80000, now+77760) {
		t.Error("degenerate (created>expires) record with a large remaining lifetime renews instantly")
	}
}
