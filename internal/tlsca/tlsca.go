// Package tlsca implements the §9.5 self-certifying TLS layer: the
// namespace's certificate authority is the name owner.
//
//   - Owner CA (§9.5.1): an ECDSA P-256 key DERIVED from the TLD owner seed
//     (HKDF-SHA256, info "freens-tls-ca-v1") — no new secret to back up, and
//     a §8.3 transfer / §8.6 rotation re-keys TLS for free (the new owner
//     derives a different CA). The CA cert is self-signed with CN = alias.
//   - Local root (§9.5.4): one randomly generated root per installation,
//     generated once and persisted (it is the visitor-side trust anchor).
//   - Cross-cert (§9.5.4): the local root cross-signs a foreign owner CA
//     into a name-constrained intermediate (permittedSubtrees
//     dNSName { alias, *.alias }), NotAfter capped by the record's expiry.
//
// Only crypto/x509, crypto/ecdsa and golang.org/x/crypto/hkdf are used —
// no homegrown crypto (Appendix D guiding rule). P-256 rather than Ed25519
// because universal client (browser/NSS/OS-store) compatibility is the
// entire point of the layer.
package tlsca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"golang.org/x/crypto/hkdf"
)

// ErrTLSCA marks every tlsca failure (wrap with %w and errors.Is).
var ErrTLSCA = errors.New("tlsca: error")

// caValidUntil returns the CA lifetime: from the start of today (UTC) to
// start-of-today + TLS_CA_VALIDITY_DAYS. Truncating NotBefore to the day
// makes same-day derivations byte-identical, so re-deriving a CA does not
// churn the TLSCA rrset within a day (the cert is deterministic given the
// seed and the calendar day).
func caValidUntil(now time.Time) (time.Time, time.Time) {
	day := now.UTC().Truncate(24 * time.Hour)
	return day.Add(-time.Hour), day.AddDate(0, 0, constants.TLSCAValidityDays)
}

// deriveOwnerKey implements §9.5.1: seed_tls = HKDF-SHA256(ikm = sk_tld_seed,
// salt = ∅, info = "freens-tls-ca-v1" [+ counter byte], L = 32); the P-256
// private key is that scalar. The negligible seed_tls >= n case re-derives
// with a counter appended to info (per spec).
func deriveOwnerKey(seed []byte) (*ecdsa.PrivateKey, error) {
	if len(seed) == 0 {
		return nil, fmt.Errorf("%w: empty owner seed", ErrTLSCA)
	}
	for counter := 0; ; counter++ {
		info := []byte(constants.TLSCADeriveInfo)
		if counter > 0 {
			info = append(info, byte(counter))
		}
		okm := make([]byte, 32)
		r := hkdf.New(sha256.New, seed, nil, info)
		if _, err := r.Read(okm); err != nil {
			return nil, fmt.Errorf("%w: hkdf: %v", ErrTLSCA, err)
		}
		k := new(big.Int).SetBytes(okm)
		n := elliptic.P256().Params().N
		if k.Sign() > 0 && k.Cmp(n) < 0 {
			priv := new(ecdsa.PrivateKey)
			priv.D = k
			priv.Curve = elliptic.P256()
			priv.X, priv.Y = elliptic.P256().ScalarBaseMult(k.Bytes())
			return priv, nil
		}
	}
}

// serial returns a deterministic RFC 5280 serial (positive, ≤ 20 octets):
// SHA-256(domain || DER public key), truncated to 20 bytes with the top bit
// cleared. The mask matters: a 20-byte value with bit 7 set DER-encodes to
// 21 octets (leading zero pad) and NSS rejects the cert outright
// ("Serial number is longer than 20 octets" — found live in the fleet
// browser test 2026-08-31). Same key ⇒ same serial, so derived certificates
// are stable given the same template.
func serial(domain string, pubDER []byte) *big.Int {
	h := sha256.Sum256(append([]byte(domain), pubDER...))
	h[0] &= 0x7f
	return new(big.Int).SetBytes(h[:20])
}

// OwnerCA derives the §9.5.1 owner CA for alias from the TLD owner seed and
// returns the self-signed CA certificate in DER.
//
// Determinism note: the KEY is fully deterministic (same seed ⇒ same key —
// that is what makes restores work), but the CERT BYTES are not: Go's
// stdlib ECDSA signatures are randomized (RFC 6979 would mean hand-rolled
// crypto, against the Appendix D rule). Byte-stability of the TLSCA rrset
// therefore comes from renewal semantics, not from re-derivation: a TLSCA
// RR is minted once and copied forward verbatim until it no longer parses
// (see renewal.EnsureTLSCA). Same-day derivations share the same validity
// window (caValidUntil truncates NotBefore to the UTC day).
func OwnerCA(seed []byte, alias string, now time.Time) ([]byte, *ecdsa.PrivateKey, error) {
	key, err := deriveOwnerKey(seed)
	if err != nil {
		return nil, nil, err
	}
	notBefore, notAfter := caValidUntil(now)
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: marshal pub: %v", ErrTLSCA, err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial("freens-owner-ca", pubDER),
		Subject:               pkix.Name{CommonName: alias, Organization: []string{"freens"}, OrganizationalUnit: []string{"freens owner ca"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // no CAs below the owner CA — leaves only
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: create owner CA: %v", ErrTLSCA, err)
	}
	return der, key, nil
}

// LocalRoot generates the visitor-side §9.5.4 trust anchor (random P-256,
// 10 y). Unlike the owner CA it is NOT derived — it is per-installation
// random material and MUST be persisted by the caller (0600).
func LocalRoot(now time.Time) (der []byte, key *ecdsa.PrivateKey, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: generate local root: %v", ErrTLSCA, err)
	}
	_, notAfter := caValidUntil(now)
	notBefore := now.Add(-time.Hour)
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: marshal pub: %v", ErrTLSCA, err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial("freens-local-root", pubDER),
		Subject:               pkix.Name{CommonName: "freens local root", Organization: []string{"freens"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1, // cross-cert intermediates below the root
	}
	der, err = x509.CreateCertificate(crand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: create local root: %v", ErrTLSCA, err)
	}
	return der, key, nil
}

// CrossCert mints the §9.5.4 constrained intermediate: the local root
// cross-signs the FOREIGN owner-CA public key (ownerCADER) with
// permittedSubtrees dNSName { alias, *.alias } and NotAfter =
// min(recordExpires, now + TLS_CROSSCERT_TTL). The browser enforces the
// constraint from this intermediate — the enforcement point of the whole
// design (a stolen owner CA can then only misrepresent its own namespace).
func CrossCert(rootDER []byte, rootKey *ecdsa.PrivateKey, ownerCADER []byte, alias string, recordExpires, now time.Time) ([]byte, error) {
	ownerCA, err := x509.ParseCertificate(ownerCADER)
	if err != nil {
		return nil, fmt.Errorf("%w: parse owner CA: %v", ErrTLSCA, err)
	}
	if err := ValidateOwnerCA(ownerCA, alias); err != nil {
		return nil, err
	}
	notAfter := recordExpires
	if cap := now.Add(time.Duration(constants.TLSCrossCertTTLSec) * time.Second); notAfter.After(cap) {
		notAfter = cap
	}
	if !notAfter.After(now) {
		return nil, fmt.Errorf("%w: record already expired at %s", ErrTLSCA, recordExpires.Format(time.RFC3339))
	}
	ownerSub := ownerCA.RawSubject
	tpl := &x509.Certificate{
		SerialNumber:          serial("freens-cross-cert", ownerCA.RawSubjectPublicKeyInfo),
		Subject:               ownerCA.Subject,
		RawSubject:            ownerSub,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		PermittedDNSDomains:   []string{alias, "*." + alias},
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, fmt.Errorf("%w: parse local root: %v", ErrTLSCA, err)
	}
	der, err := x509.CreateCertificate(crand.Reader, tpl, root, ownerCA.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("%w: create cross-cert: %v", ErrTLSCA, err)
	}
	return der, nil
}

// ValidateOwnerCA applies the §9.5.4 pre-install screen to a foreign owner
// CA: it must parse as a CA cert (CertSign), be self-signed, and carry the
// alias as its CN so trust-store listings are human-checkable. Structural
// checks only — the AUTHENTICATION comes from the TLSCA RR riding inside the
// signed apex record (§9.5.2), never from the cert itself.
func ValidateOwnerCA(cert *x509.Certificate, alias string) error {
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("%w: owner CA is not a CA cert", ErrTLSCA)
	}
	if cert.Subject.CommonName != alias {
		return fmt.Errorf("%w: owner CA CN %q != alias %q", ErrTLSCA, cert.Subject.CommonName, alias)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("%w: owner CA is not self-signed: %v", ErrTLSCA, err)
	}
	return nil
}

// Leaf issues a §9.5.3 server certificate for names (e.g.
// {"laurent", "*.laurent"}): SANs, EKU serverAuth, lifetime ≤ TLS_LEAF_TTL,
// fresh key (returned alongside, PKCS#8 DER). Signed by the owner CA.
func Leaf(caDER []byte, caKey *ecdsa.PrivateKey, names []string, now time.Time) (certDER, keyDER []byte, err error) {
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: parse CA: %v", ErrTLSCA, err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: leaf key: %v", ErrTLSCA, err)
	}
	notAfter := now.Add(time.Duration(constants.TLSLeafTTLSec) * time.Second)
	pubDER, err := x509.MarshalPKIXPublicKey(&leafKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: marshal pub: %v", ErrTLSCA, err)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial("freens-leaf", pubDER),
		Subject:      pkix.Name{CommonName: names[0], Organization: []string{"freens"}},
		// NOTE: deliberately NO OrganizationalUnit — the leaf's subject MUST
		// differ from its issuer (the owner CA carries OU "freens owner ca"),
		// or verifiers match the leaf as its own issuer (issuer==subject)
		// and fail with "self-signed certificate" before ever reaching the
		// cross-cert. Found live in the fleet test 2026-08-31.
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              names,
	}
	der, err := x509.CreateCertificate(crand.Reader, tpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: create leaf: %v", ErrTLSCA, err)
	}
	keyDER, err = x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: marshal leaf key: %v", ErrTLSCA, err)
	}
	return der, keyDER, nil
}

// SameCA reports whether existing is the SAME CA as fresh (the current
// derivation). Compares the full TBS identity — subject, key, serial,
// validity window, constraints — field by field, because the SIGNATURE can
// never match (stdlib ECDSA signs with a randomized nonce): a template
// change anywhere else in the cert therefore swaps the binding at the next
// renewal instead of leaving the record authorizing a cert no server
// presents. Near-expiry is a replace as well.
func SameCA(existing, fresh *x509.Certificate, now time.Time) bool {
	if existing.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
		return false
	}
	if existing.SerialNumber.Cmp(fresh.SerialNumber) != 0 ||
		existing.NotBefore.Unix() != fresh.NotBefore.Unix() ||
		existing.NotAfter.Unix() != fresh.NotAfter.Unix() {
		return false
	}
	if existing.KeyUsage != fresh.KeyUsage ||
		existing.IsCA != fresh.IsCA ||
		existing.MaxPathLen != fresh.MaxPathLen ||
		existing.MaxPathLenZero != fresh.MaxPathLenZero {
		return false
	}
	if !equalStrings(existing.PermittedDNSDomains, fresh.PermittedDNSDomains) ||
		!equalStrings(existing.DNSNames, fresh.DNSNames) ||
		!equalEKU(existing.ExtKeyUsage, fresh.ExtKeyUsage) {
		return false
	}
	return bytes.Equal(existing.RawSubject, fresh.RawSubject) &&
		bytes.Equal(existing.RawIssuer, fresh.RawIssuer) &&
		bytes.Equal(existing.RawSubjectPublicKeyInfo, fresh.RawSubjectPublicKeyInfo)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalEKU(a, b []x509.ExtKeyUsage) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ParseCertDER parses a single DER certificate.
func ParseCertDER(der []byte) (*x509.Certificate, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: parse certificate: %v", ErrTLSCA, err)
	}
	return c, nil
}

// CertPEM wraps DER in the canonical PEM block.
func CertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ParseCertPEM extracts the FIRST certificate from a PEM bundle.
func ParseCertPEM(data []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(data)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: no CERTIFICATE block in PEM", ErrTLSCA)
	}
	return ParseCertDER(blk.Bytes)
}

// KeyPEM wraps a PKCS#8 DER private key.
func KeyPEM(keyDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// Fingerprint is the colon-free hex SHA-256 of the DER cert (the display
// form for trust-install / doctor).
func Fingerprint(der []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(der))
}
