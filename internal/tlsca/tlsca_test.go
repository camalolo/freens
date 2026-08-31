package tlsca

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func testSeed(t *testing.T) []byte {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return seed
}

// TestOwnerCADeterministic: §9.5.1 — deriving twice from the same seed MUST
// yield the same KEY (restore-safety) and the same validity window; cert
// bytes differ per mint (stdlib ECDSA signatures are randomized — see the
// OwnerCA doc comment), which is why renewal copies a TLSCA RR verbatim
// instead of re-deriving.
func TestOwnerCADeterministic(t *testing.T) {
	now := time.Date(2026, 8, 31, 15, 4, 5, 0, time.FixedZone("X", 9*3600)) // non-UTC TZ on purpose
	der1, key1, err := OwnerCA(testSeed(t), "bob", now)
	if err != nil {
		t.Fatal(err)
	}
	der2, key2, err := OwnerCA(testSeed(t), "bob", now.Add(3*time.Hour)) // same UTC day
	if err != nil {
		t.Fatal(err)
	}
	if key1.D.Cmp(key2.D) != 0 {
		t.Fatal("derived keys differ for the same seed")
	}
	c1, c2 := mustParse(t, der1), mustParse(t, der2)
	if !c1.NotBefore.Equal(c2.NotBefore) || !c1.NotAfter.Equal(c2.NotAfter) {
		t.Fatalf("same-day windows differ: %v..%v vs %v..%v", c1.NotBefore, c1.NotAfter, c2.NotBefore, c2.NotAfter)
	}
	if c1.Subject.CommonName != "bob" || c2.Subject.CommonName != "bob" {
		t.Fatalf("CN = %q / %q, want bob", c1.Subject.CommonName, c2.Subject.CommonName)
	}
	// A different alias MUST yield a different CA (the CN is the alias and
	// the serial is derived from the pubkey — same key, but the cert bytes
	// differ; the KEY is the same because it derives from the seed alone).
	derOther, _, err := OwnerCA(testSeed(t), "alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if string(derOther) == string(der1) {
		t.Fatal("different aliases produced identical CA certs")
	}
	// Different seed → different key.
	seed2 := append([]byte(nil), testSeed(t)...)
	seed2[0] ^= 0xff
	_, key3, err := OwnerCA(seed2, "bob", now)
	if err != nil {
		t.Fatal(err)
	}
	if key1.D.Cmp(key3.D) == 0 {
		t.Fatal("different seeds produced the same CA key")
	}
}

// TestOwnerCAProperties checks the §9.5.1 template: self-signed CA with
// CN = alias, 10 y validity, CertSign usage, no path len below.
func TestOwnerCAProperties(t *testing.T) {
	now := time.Now()
	der, _, err := OwnerCA(testSeed(t), "bob", now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCertDER(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateOwnerCA(c, "bob"); err != nil {
		t.Fatalf("ValidateOwnerCA: %v", err)
	}
	if !c.IsCA || c.MaxPathLen != 0 || !c.MaxPathLenZero {
		t.Fatalf("bad CA constraints: IsCA=%v MaxPathLen=%d Zero=%v", c.IsCA, c.MaxPathLen, c.MaxPathLenZero)
	}
	if c.Subject.CommonName != "bob" {
		t.Fatalf("CN = %q, want bob", c.Subject.CommonName)
	}
	if got := c.NotAfter.Sub(c.NotBefore); got < 364*24*time.Hour {
		t.Fatalf("validity only %s, want ~10 y", got)
	}
	if c.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("CertSign usage missing")
	}
}

// TestCrossCertChain is the heart of §9.5.4: leaf(ownerCA) must verify
// through cross → local root, the nameConstraint must admit the namespace
// and REJECT anything else (including a WebPKI name), and the cross-cert
// must die with the record.
func TestCrossCertChain(t *testing.T) {
	now := time.Now()
	rootDER, rootKey, err := LocalRoot(now)
	if err != nil {
		t.Fatal(err)
	}
	caDER, caKey, err := OwnerCA(testSeed(t), "bob", now)
	if err != nil {
		t.Fatal(err)
	}
	recordExpires := now.Add(24 * time.Hour)
	crossDER, err := CrossCert(rootDER, rootKey, caDER, "bob", recordExpires, now)
	if err != nil {
		t.Fatal(err)
	}

	leafDER, _, err := Leaf(caDER, caKey, []string{"blog.bob", "*.bob"}, now)
	if err != nil {
		t.Fatal(err)
	}

	verify := func(leaf []byte) error {
		leafCert, err := ParseCertDER(leaf)
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		roots.AddCert(mustParse(t, rootDER))
		inters := x509.NewCertPool()
		inters.AddCert(mustParse(t, crossDER))
		_, err = leafCert.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: inters,
			CurrentTime:   now,
		})
		return err
	}

	if err := verify(leafDER); err != nil {
		t.Fatalf("namespace leaf must verify: %v", err)
	}

	// A leaf for a WebPKI name issued by the SAME owner CA must be rejected
	// by the enforced name constraint on the cross-cert.
	evilDER, _, err := Leaf(caDER, caKey, []string{"bank.com"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(evilDER); err == nil {
		t.Fatal("name constraint not enforced: bank.com leaf verified")
	}

	// Cross-cert lifetime is capped by the record expiry, not the 7 d ceiling.
	cross := mustParse(t, crossDER)
	if diff := cross.NotAfter.Sub(recordExpires); diff < -time.Second || diff > time.Second {
		t.Fatalf("cross-cert NotAfter = %s, want capped at record expiry %s", cross.NotAfter, recordExpires)
	}

	// A short record expiry wins over the ceiling.
	short := now.Add(2 * time.Hour)
	cross2DER, err := CrossCert(rootDER, rootKey, caDER, "bob", short, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := mustParse(t, cross2DER).NotAfter; got.Sub(short) > time.Second {
		t.Fatalf("short-record cross-cert NotAfter = %s, want ≤ %s", got, short)
	}

	// An already-expired record is refused.
	if _, err := CrossCert(rootDER, rootKey, caDER, "bob", now.Add(-time.Minute), now); !errors.Is(err, ErrTLSCA) {
		t.Fatalf("expired record accepted: %v", err)
	}

	// A foreign CA whose CN doesn't match the alias is refused (mismatched
	// constraint would be the worst kind of bug).
	if _, err := CrossCert(rootDER, rootKey, caDER, "alice", recordExpires, now); !errors.Is(err, ErrTLSCA) {
		t.Fatalf("CN/alias mismatch accepted: %v", err)
	}
}

// TestLeafProperties: EKU serverAuth, SANs, ≤ TLS_LEAF_TTL, signed by the
// owner CA (not self-signed).
func TestLeafProperties(t *testing.T) {
	now := time.Now()
	caDER, caKey, err := OwnerCA(testSeed(t), "bob", now)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, keyDER, err := Leaf(caDER, caKey, []string{"bob", "*.bob"}, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ParseCertDER(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	ca := mustParse(t, caDER)
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("leaf not signed by owner CA: %v", err)
	}
	if len(leaf.DNSNames) != 2 || leaf.DNSNames[0] != "bob" || leaf.DNSNames[1] != "*.bob" {
		t.Fatalf("SANs = %v", leaf.DNSNames)
	}
	foundServerAuth := false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			foundServerAuth = true
		}
	}
	if !foundServerAuth {
		t.Fatal("serverAuth EKU missing")
	}
	if got := leaf.NotAfter.Sub(now); got > (time.Duration(604800)*time.Second)+2*time.Hour {
		t.Fatalf("leaf validity %s exceeds TLS_LEAF_TTL", got)
	}
	if _, err := x509.ParsePKCS8PrivateKey(keyDER); err != nil {
		t.Fatalf("leaf key not PKCS#8: %v", err)
	}
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("leaf key type = %T, want ECDSA", leaf.PublicKey)
	}
}

// TestValidateOwnerCARejects: a non-CA cert, a foreign self-signed cert and
// a cert with the wrong CN must all fail the §9.5.4 screen.
func TestValidateOwnerCARejects(t *testing.T) {
	now := time.Now()
	seed := testSeed(t)
	caDER, caKey, err := OwnerCA(seed, "bob", now)
	if err != nil {
		t.Fatal(err)
	}
	ca := mustParse(t, caDER)
	if err := ValidateOwnerCA(ca, "bob"); err != nil {
		t.Fatalf("valid CA rejected: %v", err)
	}
	if err := ValidateOwnerCA(ca, "alice"); !errors.Is(err, ErrTLSCA) {
		t.Fatal("CN mismatch accepted")
	}
	leafDER, _, err := Leaf(caDER, caKey, []string{"bob"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateOwnerCA(mustParse(t, leafDER), "bob"); !errors.Is(err, ErrTLSCA) {
		t.Fatal("leaf accepted as CA")
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := ParseCertDER(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
