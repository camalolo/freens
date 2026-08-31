// tlsca_embedding_test.go — §9.5: apexes carry the owner-CA binding through
// renewal (the migration choke point), sub-names never do, and the binding
// bytes stay stable across renewals.
package renewal

import (
	"bytes"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/tlsca"
	"github.com/camalolo/freens/internal/wire"
	"github.com/fxamacker/cbor/v2"
)

// buildClaimedApex is buildRecord plus the embedded §7 claim EnsureTLSCA
// reads the alias from (difficulty 8: tests, not the network).
func buildClaimedApex(t *testing.T, alias string, kp *crypto.Keypair, seq, created, expires uint64, labels ...string) *wire.SignedEnvelope {
	t.Helper()
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	name, err := naming.EncodeWireName(labels, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := claims.MineAliasClaim(alias, kp, uint64(created), 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MineAliasClaim: %v", err)
	}
	cb, err := claim.CanonicalBytes()
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
	rec.Claim = cbor.RawMessage(cb)
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func tlscaRRs(env *wire.SignedEnvelope) []*wire.RR {
	var out []*wire.RR
	for _, rr := range env.Record.RRset {
		if rr.Type == wire.RRTypeTLSCA {
			out = append(out, rr)
		}
	}
	return out
}

func TestRenewApexGainsTLSCA(t *testing.T) {
	now := time.Now().Unix()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	env := buildClaimedApex(t, "bob", kp, 3, uint64(now-3600), uint64(now+1000))

	out, err := RenewEnvelope(env, kp, now)
	if err != nil {
		t.Fatalf("RenewEnvelope: %v", err)
	}
	rrs := tlscaRRs(out)
	if len(rrs) != 1 {
		t.Fatalf("renewed apex carries %d TLSCA RRs, want 1", len(rrs))
	}
	cert, err := tlsca.ParseCertDER(rrs[0].Rdata)
	if err != nil {
		t.Fatalf("TLSCA rdata not a DER cert: %v", err)
	}
	if cert.Subject.CommonName != "bob" {
		t.Fatalf("CA CN = %q, want bob", cert.Subject.CommonName)
	}
	// The rest of the record is unchanged: A record still first.
	if out.Record.RRset[0].Type != wire.RRTypeA {
		t.Fatalf("first RR type = %d, want A", out.Record.RRset[0].Type)
	}
}

func TestRenewTLSCACopyForwardStable(t *testing.T) {
	now := time.Now().Unix()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	env := buildClaimedApex(t, "bob", kp, 3, uint64(now-3600), uint64(now+1000))

	first, err := RenewEnvelope(env, kp, now)
	if err != nil {
		t.Fatal(err)
	}
	// Renew the RENEWED record: the TLSCA bytes must be copied verbatim
	// (byte stability — no rrset churn, no visitor re-syncs).
	second, err := RenewEnvelope(first, kp, now)
	if err != nil {
		t.Fatal(err)
	}
	f, s := tlscaRRs(first), tlscaRRs(second)
	if len(s) != 1 {
		t.Fatalf("second renewal carries %d TLSCA RRs, want 1", len(s))
	}
	if !bytes.Equal(f[0].Rdata, s[0].Rdata) {
		t.Fatal("TLSCA bytes changed across a renewal")
	}
}

func TestRenewSubNameNoTLSCA(t *testing.T) {
	now := time.Now().Unix()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	env := buildClaimedApex(t, "bob", kp, 3, uint64(now-3600), uint64(now+1000), "host1")

	out, err := RenewEnvelope(env, kp, now)
	if err != nil {
		t.Fatalf("RenewEnvelope: %v", err)
	}
	if got := len(tlscaRRs(out)); got != 0 {
		t.Fatalf("sub-name record carries %d TLSCA RRs, want 0", got)
	}
}

func TestRenewNoClaimNoTLSCA(t *testing.T) {
	now := time.Now().Unix()
	env, kp := buildRecord(t, 4, uint64(now-3600), uint64(now+1000), false)
	out, err := RenewEnvelope(env, kp, now)
	if err != nil {
		t.Fatalf("RenewEnvelope: %v", err)
	}
	if got := len(tlscaRRs(out)); got != 0 {
		t.Fatalf("claim-less apex gained %d TLSCA RRs, want 0", got)
	}
}
