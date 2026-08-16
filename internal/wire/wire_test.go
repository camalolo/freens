package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/fxamacker/cbor/v2"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func mustKeypair(t *testing.T) *crypto.Keypair {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func mustTldID(t *testing.T, pk []byte) []byte {
	t.Helper()
	id, err := crypto.TldID(pk)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustNodeID(t *testing.T, pk []byte) []byte {
	t.Helper()
	id, err := crypto.NodeID(pk)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustWireName(t *testing.T, labels []string, alias string, tldID []byte) []byte {
	t.Helper()
	w, err := naming.EncodeWireName(labels, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func mustRecord(t *testing.T, name, owner []byte, seq, created, expires uint64) *Record {
	t.Helper()
	r, err := NewRecord(name, owner, seq, created, expires)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mustSign(t *testing.T, rec *Record, kp *crypto.Keypair) *SignedEnvelope {
	t.Helper()
	env, err := SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func zeroOwner() []byte { return bytes.Repeat([]byte{0}, constants.Ed25519PublicKeyLen) }

// forgeSigner builds a fresh envelope reusing env's record and signature but
// claiming a different signer — the standard forgery probe. It builds a NEW
// SignedEnvelope (not a value copy) because envelopes carry lazily-cached
// canonical bytes and are shared as immutable values (see the struct comment).
func forgeSigner(env *SignedEnvelope, signer []byte) *SignedEnvelope {
	return &SignedEnvelope{
		Record: env.Record,
		Sig:    append([]byte(nil), env.Sig...),
		Signer: signer,
	}
}

// ---------------------------------------------------------------------------
// RR
// ---------------------------------------------------------------------------

func TestRRConstructors(t *testing.T) {
	a, err := A([]byte{203, 0, 113, 42}, 300)
	if err != nil {
		t.Fatal(err)
	}
	if a.Type != RRTypeA || a.TTL != 300 || len(a.Rdata) != 4 {
		t.Errorf("A = %+v", a)
	}
	if want := []byte{203, 0, 113, 42}; !bytes.Equal(a.Rdata, want) {
		t.Errorf("A Rdata = %v, want %v", a.Rdata, want)
	}
	aaaa, err := AAAA(bytes.Repeat([]byte{1}, 16), 600)
	if err != nil {
		t.Fatal(err)
	}
	if aaaa.Type != RRTypeAAAA || len(aaaa.Rdata) != 16 {
		t.Errorf("AAAA = %+v", aaaa)
	}
	if aaaa.TTL != 600 {
		t.Errorf("AAAA TTL = %d, want 600", aaaa.TTL)
	}
	txt, err := TXT("hello", 100)
	if err != nil {
		t.Fatal(err)
	}
	if txt.Type != RRTypeTXT || string(txt.Rdata) != "hello" {
		t.Errorf("TXT = %+v", txt)
	}
	if txt.TTL != 100 {
		t.Errorf("TXT TTL = %d, want 100", txt.TTL)
	}
}

func TestRRValidation(t *testing.T) {
	if _, err := NewRR(RRTypeA, 0, []byte{1, 2, 3, 4}); err == nil {
		t.Error("NewRR should reject ttl=0")
	}
	if _, err := NewRR(RRTypeA, constants.RecordMaxTTL+1, []byte{1, 2, 3, 4}); err == nil {
		t.Error("NewRR should reject ttl>RecordMaxTTL")
	}
	if _, err := A([]byte{1, 2, 3}, 300); err == nil {
		t.Error("A should reject 3-byte rdata")
	}
	if _, err := AAAA([]byte{1, 2, 3}, 300); err == nil {
		t.Error("AAAA should reject short rdata")
	}
}

// RR marshals as the §4.3 3-element array [type, ttl, rdata] and round-trips.
func TestRRWireArray(t *testing.T) {
	rr, _ := NewRR(RRTypeA, 300, []byte{203, 0, 113, 42})
	got, err := canonicalEM.Marshal(rr)
	if err != nil {
		t.Fatal(err)
	}
	// Expect: 83(=array(3)) 01(=1) 19 012c(=300) 44 cb00712a(=h'',4 bytes)
	want := []byte{0x83, 0x01, 0x19, 0x01, 0x2c, 0x44, 0xcb, 0x00, 0x71, 0x2a}
	if !bytes.Equal(got, want) {
		t.Errorf("RR wire = %s, want %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
	// Round-trip.
	var rr2 RR
	if err := cbor.Unmarshal(got, &rr2); err != nil {
		t.Fatal(err)
	}
	if rr2.Type != rr.Type || rr2.TTL != rr.TTL || !bytes.Equal(rr2.Rdata, rr.Rdata) {
		t.Errorf("RR round-trip mismatch: %+v vs %+v", rr2, rr)
	}
	// Reject a non-3-element array.
	if err := cbor.Unmarshal([]byte{0x82, 0x01, 0x02}, &rr2); err == nil {
		t.Error("RR.UnmarshalCBOR should reject 2-element array")
	}
}

// TestRREmptyRdataEncodesAsEmptyBstr pins the B1 fix: a nil Rdata (reachable
// via TXT("") or NewRR(typ,ttl,nil), since []byte("") and append(nil,nil...)
// are nil) must encode as CBOR empty bstr (0x40), NOT CBOR null (0xf6). The
// Python reference emits b"" never null, and strict CBOR decoders reject null
// for a bstr-typed field. Both the global canonicalEM NilContainerAsEmpty
// setting and the defensive normalization in RR.MarshalCBOR guard this.
func TestRREmptyRdataEncodesAsEmptyBstr(t *testing.T) {
	// TXT("") yields a nil Rdata: []byte("") is nil, and NewRR's
	// append([]byte(nil), nil...) returns nil.
	rr, err := TXT("", 300)
	if err != nil {
		t.Fatal(err)
	}
	if rr.Rdata != nil {
		t.Fatalf("precondition: TXT(\"\").Rdata = %v, want nil", rr.Rdata)
	}

	// Direct marshal via the exported MarshalCBOR (uses canonicalEM + nil
	// normalization defensively).
	got, err := rr.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	// And also marshal via canonicalEM.Marshal(rr) — the path the rest of the
	// package uses for embedded RR serialization inside Record/envelope.
	embedded, err := canonicalEM.Marshal(rr)
	if err != nil {
		t.Fatal(err)
	}
	for label, b := range map[string][]byte{"MarshalCBOR": got, "canonicalEM.Marshal": embedded} {
		if bytes.Contains(b, []byte{0xf6}) {
			t.Errorf("%s: marshalled RR %s contains CBOR null (0xf6)", label, hex.EncodeToString(b))
		}
		if !bytes.Contains(b, []byte{0x40}) {
			t.Errorf("%s: marshalled RR %s does not contain empty bstr (0x40)", label, hex.EncodeToString(b))
		}
	}

	// Decode and confirm Rdata is empty (len 0) on both sides of the wire.
	var rr2 RR
	if err := cbor.Unmarshal(got, &rr2); err != nil {
		t.Fatalf("UnmarshalCBOR: %v", err)
	}
	if len(rr2.Rdata) != 0 {
		t.Errorf("decoded Rdata len = %d, want 0 (empty)", len(rr2.Rdata))
	}

	// Round-trip a full Record containing the empty-Rdata RR byte-stably
	// through SignRecord / DecodeEnvelope.
	kp := mustKeypair(t)
	tldID := mustTldID(t, kp.Public())
	name := mustWireName(t, nil, "foo", tldID)
	rec := mustRecord(t, name, kp.Public(), 1, 0, 1)
	rec.RRset = []*RR{rr}
	env := mustSign(t, rec, kp)
	orig, err := env.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeEnvelope(orig)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	reenc, err := dec.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(orig, reenc) {
		t.Errorf("empty-Rdata record not byte-stable\n  orig %s\n  re   %s",
			hex.EncodeToString(orig), hex.EncodeToString(reenc))
	}
}

// ---------------------------------------------------------------------------
// Record golden vectors
// ---------------------------------------------------------------------------

// A minimal Record marshals identically to the equivalent hand-built map.
func TestRecordMinimalEqualsHandMap(t *testing.T) {
	tldID := bytes.Repeat([]byte{0xAB}, 32)
	name := mustWireName(t, nil, "foo", tldID) // 0x00 || 32 bytes = 33 bytes
	if len(name) != 33 {
		t.Fatalf("wire_name len = %d, want 33", len(name))
	}
	owner := zeroOwner()
	rec := &Record{
		Version: 1, Name: name, Owner: owner,
		Sequence: 1, Created: 0, Expires: 1, RRset: nil,
	}
	got, err := rec.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	hand := map[uint64]any{
		1: uint64(1), 2: name, 3: owner,
		4: uint64(1), 5: uint64(0), 6: uint64(1), 7: []any{},
	}
	want, err := canonicalEM.Marshal(hand)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("minimal record\n  got  %s\n  want %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

// Optional fields 8-12 are OMITTED when nil/absent.
func TestRecordOptionalOmitted(t *testing.T) {
	tldID := bytes.Repeat([]byte{0xAB}, 32)
	name := mustWireName(t, nil, "foo", tldID)
	rec := mustRecord(t, name, zeroOwner(), 1, 0, 1)
	b, err := rec.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	var m map[any]any
	if err := cbor.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []uint64{8, 9, 10, 11, 12} {
		if _, ok := m[k]; ok {
			t.Errorf("optional key %d should be omitted", k)
		}
	}
}

// Revoke is emitted only when it points at true.
func TestRecordRevokeOnlyWhenTrue(t *testing.T) {
	tldID := bytes.Repeat([]byte{0xAB}, 32)
	name := mustWireName(t, nil, "foo", tldID)
	makeMap := func(revoke *bool) map[any]any {
		rec := mustRecord(t, name, zeroOwner(), 1, 0, 1)
		rec.Revoke = revoke
		b, err := rec.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		var m map[any]any
		if err := cbor.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	tr := true
	fl := false
	if v := makeMap(&tr)[uint64(12)]; v == nil {
		t.Error("revoke=true should emit key 12")
	} else if v != true {
		t.Errorf("key 12 = %v, want true", v)
	}
	if _, ok := makeMap(&fl)[uint64(12)]; ok {
		t.Error("revoke=false should omit key 12")
	}
	if _, ok := makeMap(nil)[uint64(12)]; ok {
		t.Error("revoke=nil should omit key 12")
	}
}

// NewRecord / Validate reject malformed required fields.
func TestRecordValidation(t *testing.T) {
	name := mustWireName(t, nil, "foo", bytes.Repeat([]byte{0xAB}, 32))
	cases := []struct {
		name    string
		rec     *Record
		wantErr string
	}{
		{"bad version", &Record{Version: 2, Name: name, Owner: zeroOwner(), Sequence: 1, Created: 0, Expires: 1}, "version"},
		{"empty name", &Record{Version: 1, Name: nil, Owner: zeroOwner(), Sequence: 1, Created: 0, Expires: 1}, "name"},
		{"short owner", &Record{Version: 1, Name: name, Owner: []byte{1, 2, 3}, Sequence: 1, Created: 0, Expires: 1}, "owner"},
		{"zero sequence", &Record{Version: 1, Name: name, Owner: zeroOwner(), Sequence: 0, Created: 0, Expires: 1}, "sequence"},
		{"created>expires", &Record{Version: 1, Name: name, Owner: zeroOwner(), Sequence: 1, Created: 10, Expires: 5}, "created"},
	}
	for _, c := range cases {
		err := c.rec.Validate()
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: err = %v, want substring %q", c.name, err, c.wantErr)
		}
	}
	// Delegation / prev_hash length checks.
	r := mustRecord(t, name, zeroOwner(), 1, 0, 1)
	r.Delegation = []byte{1, 2}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "delegation") {
		t.Errorf("bad delegation: err = %v", err)
	}
	r.Delegation = nil
	r.PrevHash = []byte{1, 2}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "prev_hash") {
		t.Errorf("bad prev_hash: err = %v", err)
	}
}

// ---------------------------------------------------------------------------
// SignedEnvelope: sign / verify / hash / tamper / round-trip
// ---------------------------------------------------------------------------

func TestSignRecordAndVerify(t *testing.T) {
	kp := mustKeypair(t)
	tldID := mustTldID(t, kp.Public())
	name := mustWireName(t, nil, "foo", tldID)
	rr, _ := A([]byte{203, 0, 113, 42}, 300)
	rec := mustRecord(t, name, kp.Public(), 1, 1000, 2000)
	rec.RRset = []*RR{rr}
	env := mustSign(t, rec, kp)

	if !env.VerifySignature() {
		t.Fatal("VerifySignature false after SignRecord")
	}
	// RecordHash == SHA-256(Bytes()).
	b, err := env.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	h, err := env.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(b)
	if !bytes.Equal(h, want[:]) {
		t.Error("RecordHash != SHA-256(Bytes())")
	}
	// Signer is the signer public key.
	if !bytes.Equal(env.Signer, kp.Public()) {
		t.Error("Signer != kp.Public()")
	}
}

func TestTamperBreaksSignature(t *testing.T) {
	kp := mustKeypair(t)
	tldID := mustTldID(t, kp.Public())
	name := mustWireName(t, nil, "foo", tldID)
	rec := mustRecord(t, name, kp.Public(), 1, 1000, 2000)
	rec.RRset = []*RR{mustA(t)}
	env := mustSign(t, rec, kp)
	if !env.VerifySignature() {
		t.Fatal("pre-tamper verify failed")
	}

	// Tamper with the record content. Per the SignedEnvelope immutability
	// contract, tampering is observed on a FRESH envelope over the mutated
	// record (exactly what tampered wire bytes decode to — a cold-cache
	// object); a warm cached envelope keeps serving its signed snapshot.
	tampered := func() *SignedEnvelope {
		return &SignedEnvelope{Record: rec, Sig: env.Sig, Signer: env.Signer}
	}
	// Mutate RRset after signing — rec aliases the envelope's record.
	rec.RRset = append(rec.RRset, mustA(t))
	if tampered().VerifySignature() {
		t.Error("VerifySignature true after tampering RRset")
	}
	// Restore + mutate TTL.
	rec.RRset = []*RR{mustA(t)}
	rec.RRset[0].TTL = 999
	if tampered().VerifySignature() {
		t.Error("VerifySignature true after tampering TTL")
	}

	// The warm envelope's cached view is its SIGNED snapshot: VerifySignature
	// still holds because the bytes it verified (and would re-serve) are the
	// originally signed ones — the in-place mutation is invisible by design,
	// which is why the immutability contract above exists.
	if !env.VerifySignature() {
		t.Error("warm envelope lost its valid signature (cache must serve the signed snapshot)")
	}
}

func TestRoundTripByteStability(t *testing.T) {
	kp := mustKeypair(t)
	tldID := mustTldID(t, kp.Public())
	name := mustWireName(t, []string{"www", "alice"}, "foo", tldID)
	rec := mustRecord(t, name, kp.Public(), 7, 1000, 2000)
	rec.RRset = []*RR{mustA(t), mustAAAA(t)}
	rec.Delegation = bytes.Repeat([]byte{0xDE}, 32)
	rec.PrevHash = bytes.Repeat([]byte{0xAD}, 32)
	env := mustSign(t, rec, kp)

	orig, err := env.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeEnvelope(orig)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	reenc, err := dec.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(orig, reenc) {
		t.Errorf("round-trip not byte-stable\n  orig %s\n  re   %s", hex.EncodeToString(orig), hex.EncodeToString(reenc))
	}
	if !dec.VerifySignature() {
		t.Error("decoded envelope fails VerifySignature")
	}
}

func TestDecodeEnvelopeRejectsBad(t *testing.T) {
	// Garbage.
	if _, err := DecodeEnvelope([]byte("not cbor")); err == nil {
		t.Error("DecodeEnvelope should reject non-CBOR")
	}
	// Missing required key (owner) inside the embedded record.
	name := mustWireName(t, nil, "foo", bytes.Repeat([]byte{0xAB}, 32))
	badRecord := map[uint64]any{
		1: uint64(1), 2: name, 4: uint64(1), 5: uint64(0), 6: uint64(1), 7: []any{}, // no key 3
	}
	badEnv := map[uint64]any{1: badRecord, 2: bytes.Repeat([]byte{0}, 64), 3: zeroOwner()}
	bad, err := canonicalEM.Marshal(badEnv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeEnvelope(bad); err == nil {
		t.Error("DecodeEnvelope should reject record missing owner")
	}
	// Bad sig length.
	goodRec := map[uint64]any{
		1: uint64(1), 2: name, 3: zeroOwner(), 4: uint64(1), 5: uint64(0), 6: uint64(1), 7: []any{},
	}
	shortSig := map[uint64]any{1: goodRec, 2: []byte{1, 2, 3}, 3: zeroOwner()}
	sb, _ := canonicalEM.Marshal(shortSig)
	if _, err := DecodeEnvelope(sb); err == nil {
		t.Error("DecodeEnvelope should reject short sig")
	}
}

// ---------------------------------------------------------------------------
// EnvelopeWins (§6.4 step 3)
// ---------------------------------------------------------------------------

func TestEnvelopeWins(t *testing.T) {
	kp1, kp2 := mustKeypair(t), mustKeypair(t)
	tldID1 := mustTldID(t, kp1.Public())
	name1 := mustWireName(t, nil, "foo", tldID1)
	high := mustSign(t, mustRecord(t, name1, kp1.Public(), 5, 0, 1), kp1)
	low := mustSign(t, mustRecord(t, name1, kp1.Public(), 4, 0, 1), kp1)

	// Higher sequence wins; lower rejected.
	if !EnvelopeWins(high, low) {
		t.Error("higher seq should win")
	}
	if EnvelopeWins(low, high) {
		t.Error("lower seq should not win")
	}

	// Same sequence, different content (different owner) => bytewise-greater hash wins.
	tldID2 := mustTldID(t, kp2.Public())
	name2 := mustWireName(t, nil, "bar", tldID2)
	e1 := mustSign(t, mustRecord(t, name1, kp1.Public(), 5, 0, 1), kp1)
	e2 := mustSign(t, mustRecord(t, name2, kp2.Public(), 5, 0, 1), kp2)
	h1, _ := e1.RecordHash()
	h2, _ := e2.RecordHash()
	var greater, lesser *SignedEnvelope
	if bytes.Compare(h1, h2) > 0 {
		greater, lesser = e1, e2
	} else {
		greater, lesser = e2, e1
	}
	if !EnvelopeWins(greater, lesser) {
		t.Error("bytewise-greater hash should win at same sequence")
	}
	if EnvelopeWins(lesser, greater) {
		t.Error("bytewise-lesser hash should not win at same sequence")
	}
	// Identical envelopes => neither strictly wins.
	if EnvelopeWins(high, high) {
		t.Error("identical envelopes should not win (equal hash)")
	}
}

// ---------------------------------------------------------------------------
// IsBasicValid / IsRevoked
// ---------------------------------------------------------------------------

func TestIsBasicValid(t *testing.T) {
	kp := mustKeypair(t)
	tldID := mustTldID(t, kp.Public())
	name := mustWireName(t, nil, "foo", tldID)
	rec := mustRecord(t, name, kp.Public(), 1, 100, 200)
	env := mustSign(t, rec, kp)

	if !IsBasicValid(env, 150) {
		t.Error("in-window should be valid")
	}
	if IsBasicValid(env, 99) {
		t.Error("now<created should be invalid")
	}
	// created <= now < expires — now==created is allowed (boundary).
	if !IsBasicValid(env, 100) {
		t.Error("now==created (created<=now) should be valid")
	}
	if IsBasicValid(env, 200) {
		t.Error("now==expires (now<expires fails) should be invalid")
	}
	if IsBasicValid(env, 300) {
		t.Error("now>expires should be invalid")
	}
	// Bad signature.
	forged := forgeSigner(env, zeroOwner())
	if IsBasicValid(forged, 150) {
		t.Error("bad signature should be invalid")
	}
}

func TestIsRevoked(t *testing.T) {
	kp := mustKeypair(t)
	tldID := mustTldID(t, kp.Public())
	name := mustWireName(t, nil, "foo", tldID)
	rec := mustRecord(t, name, kp.Public(), 1, 100, 200)
	env := mustSign(t, rec, kp)
	if env.IsRevoked() {
		t.Error("non-revoke envelope should not be revoked")
	}
	tr := true
	rec2 := mustRecord(t, name, kp.Public(), 2, 100, 200)
	rec2.Revoke = &tr
	env2 := mustSign(t, rec2, kp)
	if !env2.IsRevoked() {
		t.Error("revoke=true envelope should be revoked")
	}
}

// ---------------------------------------------------------------------------
// VerifyChainLink (§4.4 rule 4 / §8.3)
// ---------------------------------------------------------------------------

// chainEnv builds a self-certifying TLD envelope with the given sequence and
// prev_hash (nil allowed), freshly signed so VerifySignature holds.
func chainEnv(t *testing.T, kp *crypto.Keypair, sequence uint64, prevHash []byte) *SignedEnvelope {
	t.Helper()
	tldID := mustTldID(t, kp.Public())
	name := mustWireName(t, nil, "foo", tldID)
	rec := mustRecord(t, name, kp.Public(), sequence, 1000, 2000)
	rec.PrevHash = prevHash
	return mustSign(t, rec, kp)
}

func TestVerifyChainLink(t *testing.T) {
	kp := mustKeypair(t)
	first := chainEnv(t, kp, 1, nil)
	firstHash, err := first.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	wrongHash := append([]byte(nil), firstHash...)
	wrongHash[0] ^= 0xFF

	second := chainEnv(t, kp, 2, firstHash)   // correct transfer-style link
	secondEq := chainEnv(t, kp, 1, firstHash) // correct hash, NON-increasing seq
	wrongLink := chainEnv(t, kp, 2, wrongHash)
	plainHigher := chainEnv(t, kp, 2, nil) // ordinary §8.2 update, no prev_hash
	freshFirst := chainEnv(t, kp, 1, nil)  // first publication of a fresh name
	freshSecond := chainEnv(t, kp, 2, nil) // gap on a fresh name (no older, no link)

	tests := []struct {
		name         string
		newer, older *SignedEnvelope
		want         bool
	}{
		{"nil args", nil, nil, false},
		{"nil newer", nil, first, false},
		{"nil newer record", &SignedEnvelope{}, first, false},
		{"valid transfer link", second, first, true},
		{"wrong prev_hash", wrongLink, first, false},
		{"hash ok but seq not increasing", secondEq, first, false},
		{"prev_hash set but no predecessor", second, nil, false},
		{"nil prev_hash ordinary update", plainHigher, first, true},
		{"nil prev_hash seq decreasing", first, second, false},
		{"nil prev_hash first publication", freshFirst, nil, true},
		{"nil prev_hash gap on fresh name", freshSecond, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyChainLink(tt.newer, tt.older); got != tt.want {
				t.Errorf("VerifyChainLink(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// VerifyAuthorityChain (§3.4)
// ---------------------------------------------------------------------------

func makeTldEnv(t *testing.T, kp *crypto.Keypair, alias string, delegation []byte) *SignedEnvelope {
	tldID := mustTldID(t, kp.Public())
	name := mustWireName(t, nil, alias, tldID)
	rec := mustRecord(t, name, kp.Public(), 1, 1000, 2000)
	if delegation != nil {
		rec.Delegation = delegation
	}
	return mustSign(t, rec, kp)
}

// makeNameEnv builds a record for `labels.alias` owned by ownerKP and signed by
// signerKP. delegation optionally sets field 8.
func makeNameEnv(t *testing.T, ownerKP, signerKP *crypto.Keypair, labels []string, alias string, tldID, delegation []byte) *SignedEnvelope {
	name := mustWireName(t, labels, alias, tldID)
	rec := mustRecord(t, name, ownerKP.Public(), 1, 1000, 2000)
	if delegation != nil {
		rec.Delegation = delegation
	}
	return mustSign(t, rec, signerKP)
}

func TestVerifyAuthorityChain(t *testing.T) {
	tldKP := mustKeypair(t)
	tldID := mustTldID(t, tldKP.Public())

	// 1-hop self-certifying TLD.
	tldEnv := makeTldEnv(t, tldKP, "foo", nil)
	if !VerifyAuthorityChain([]*SignedEnvelope{tldEnv}) {
		t.Error("1-hop TLD chain should verify")
	}
	// Forged signer.
	forged := forgeSigner(tldEnv, mustKeypair(t).Public())
	if VerifyAuthorityChain([]*SignedEnvelope{forged}) {
		t.Error("forged-signer TLD chain should fail")
	}

	// 2-hop: TLD delegates to alice; alice.foo signed by alice.
	aliceKP := mustKeypair(t)
	aliceEnv := makeNameEnv(t, aliceKP, aliceKP, []string{"alice"}, "foo", tldID, nil)
	tldDel := makeTldEnv(t, tldKP, "foo", aliceKP.Public())
	if !VerifyAuthorityChain([]*SignedEnvelope{tldDel, aliceEnv}) {
		t.Error("2-hop delegation chain should verify")
	}
	// 2-hop with child signed by an unauthorized key.
	eveKP := mustKeypair(t)
	aliceByEve := makeNameEnv(t, aliceKP, eveKP, []string{"alice"}, "foo", tldID, nil)
	if VerifyAuthorityChain([]*SignedEnvelope{tldDel, aliceByEve}) {
		t.Error("unauthorized child signer should fail")
	}

	// 3-hop: alice delegates to bob; www.alice.foo signed by bob.
	bobKP := mustKeypair(t)
	aliceDel := makeNameEnv(t, aliceKP, aliceKP, []string{"alice"}, "foo", tldID, bobKP.Public())
	bobEnv := makeNameEnv(t, bobKP, bobKP, []string{"www", "alice"}, "foo", tldID, nil)
	if !VerifyAuthorityChain([]*SignedEnvelope{tldDel, aliceDel, bobEnv}) {
		t.Error("3-hop delegation chain should verify")
	}

	// Chain too long (>MaxLabels+1).
	tooLong := make([]*SignedEnvelope, constants.MaxLabels+2)
	if VerifyAuthorityChain(tooLong) {
		t.Error("oversized chain should fail")
	}
	// Empty chain.
	if VerifyAuthorityChain(nil) {
		t.Error("empty chain should fail")
	}

	// Direct-sign path (no delegation): TLD owner signs alice.foo directly.
	tldDirect := makeTldEnv(t, tldKP, "foo", nil)
	aliceDirect := makeNameEnv(t, tldKP, tldKP, []string{"alice"}, "foo", tldID, nil)
	if !VerifyAuthorityChain([]*SignedEnvelope{tldDirect, aliceDirect}) {
		t.Error("direct-sign chain should verify")
	}

	// Wrong-TLD child (different tld_id).
	otherKP := mustKeypair(t)
	otherTldID := mustTldID(t, otherKP.Public())
	wrongTldChild := makeNameEnv(t, aliceKP, aliceKP, []string{"alice"}, "foo", otherTldID, nil)
	if VerifyAuthorityChain([]*SignedEnvelope{tldDel, wrongTldChild}) {
		t.Error("cross-TLD child should fail")
	}
}

// TestVerifyAuthorityChainDescent exercises the strict-descendant / label-suffix
// branch of VerifyAuthorityChain (wire.go:653-666), which the original
// TestVerifyAuthorityChain only covered on the happy path. These cases pin the
// intended behavior of the descent check: a child must be STRICTLY DEEPER than
// its parent AND share the parent's display-order label suffix.
func TestVerifyAuthorityChainDescent(t *testing.T) {
	tldKP := mustKeypair(t)
	tldID := mustTldID(t, tldKP.Public())
	aliceKP := mustKeypair(t)

	// TLD root delegates its whole subtree to alice_pk.
	tldDel := makeTldEnv(t, tldKP, "foo", aliceKP.Public())

	// POSITIVE: skip-level delegation. TLD root delegates to alice_pk; alice
	// signs www.alice.foo directly, skipping the intermediate alice.foo hop.
	// R3 documents that a delegation covers the whole subtree, so the chain
	// [tld, www] must verify even though no alice.foo envelope is present.
	wwwAliceEnv := makeNameEnv(t, aliceKP, aliceKP, []string{"www", "alice"}, "foo", tldID, nil)
	if !VerifyAuthorityChain([]*SignedEnvelope{tldDel, wwwAliceEnv}) {
		t.Error("skip-level chain [tld, www.alice.foo] should verify (delegation covers subtree)")
	}

	// NEGATIVE 1: child NOT under parent (label-suffix mismatch).
	// Chain: [tld, alice.foo, www.bob.foo]. Authorization holds at every hop
	// (tld delegates to alice_pk; alice signs both records), so the only
	// failing check is descent: child suffix ["bob"] != parent labels ["alice"].
	aliceEnv := makeNameEnv(t, aliceKP, aliceKP, []string{"alice"}, "foo", tldID, nil)
	wwwBobEnv := makeNameEnv(t, aliceKP, aliceKP, []string{"www", "bob"}, "foo", tldID, nil)
	if VerifyAuthorityChain([]*SignedEnvelope{tldDel, aliceEnv, wwwBobEnv}) {
		t.Error("chain with non-descendant child (www.bob.foo under alice.foo) should fail descent check")
	}

	// NEGATIVE 2: child shallower than parent.
	// Chain: [tld, www.alice.foo, alice.foo]. The hop alice.foo under
	// www.alice.foo fails the len(c) > len(p) guard (child has fewer labels
	// than its alleged parent).
	tldDirect := makeTldEnv(t, tldKP, "foo", nil)
	wwwAliceShallowParent := makeNameEnv(t, tldKP, tldKP, []string{"www", "alice"}, "foo", tldID, nil)
	aliceShallower := makeNameEnv(t, tldKP, tldKP, []string{"alice"}, "foo", tldID, nil)
	if VerifyAuthorityChain([]*SignedEnvelope{tldDirect, wwwAliceShallowParent, aliceShallower}) {
		t.Error("chain with shallower child (alice.foo under www.alice.foo) should fail descent check")
	}
}

// ---------------------------------------------------------------------------
// Message (§6.3 / Appendix B.1)
// ---------------------------------------------------------------------------

func mustA(t *testing.T) *RR { t.Helper(); r, _ := A([]byte{10, 0, 0, 1}, 300); return r }
func mustAAAA(t *testing.T) *RR {
	t.Helper()
	r, _ := AAAA(bytes.Repeat([]byte{0x20}, 16), 300)
	return r
}

func testMessageCommon(t *testing.T, msg *Message, recipientID []byte) {
	t.Helper()
	if !msg.Verify(recipientID) {
		t.Error("Verify failed")
	}
	// ID == NodeID(PK).
	nid := mustNodeID(t, msg.PK)
	if !bytes.Equal(nid, msg.ID) {
		t.Error("constructed message ID != NodeID(PK)")
	}
	// Round-trip.
	dec, err := DecodeMessage(mustBytes(t, msg))
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if !dec.Verify(recipientID) {
		t.Error("decoded message Verify failed")
	}
	// Tamper args -> Verify false.
	saved := msg.A
	msg.A = map[string]any{"x": "y"}
	if msg.Verify(recipientID) {
		t.Error("tampered A should fail Verify")
	}
	msg.A = saved
	// Wrong recipient -> Verify false.
	if msg.Verify(bytes.Repeat([]byte{0xFF}, 32)) {
		t.Error("wrong recipient should fail Verify")
	}
}

func mustBytes(t *testing.T, m *Message) []byte {
	t.Helper()
	b, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNewQuery(t *testing.T) {
	kp := mustKeypair(t)
	recipientID := bytes.Repeat([]byte{0xCC}, 32)
	txid := []byte("tx1")
	msg, err := NewQuery("ping", map[string]any{}, kp, recipientID, txid)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Y != MsgTypeQuery || msg.Q != "ping" {
		t.Errorf("query fields wrong: y=%q q=%q", msg.Y, msg.Q)
	}
	testMessageCommon(t, msg, recipientID)
}

func TestNewResponse(t *testing.T) {
	kp := mustKeypair(t)
	recipientID := bytes.Repeat([]byte{0xCC}, 32)
	msg, err := NewResponse(map[string]any{"id": []byte("node")}, kp, recipientID, []byte("t2"))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Y != MsgTypeResponse {
		t.Errorf("y=%q, want r", msg.Y)
	}
	if msg.Q != "" {
		t.Errorf("response Q should be empty, got %q", msg.Q)
	}
	testMessageCommon(t, msg, recipientID)
}

func TestNewError(t *testing.T) {
	kp := mustKeypair(t)
	recipientID := bytes.Repeat([]byte{0xCC}, 32)
	msg, err := NewError(map[string]any{"code": int64(201)}, kp, recipientID, []byte("t3"))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Y != MsgTypeError {
		t.Errorf("y=%q, want e", msg.Y)
	}
	testMessageCommon(t, msg, recipientID)
}

// SigningInput == canonicalEM.Marshal([t, id, recipientID, a]).
func TestMessageSigningInputGolden(t *testing.T) {
	kp := mustKeypair(t)
	recipientID := bytes.Repeat([]byte{0xCC}, 32)
	msg, err := NewQuery("ping", map[string]any{"k": "v"}, kp, recipientID, []byte("tx"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := msg.SigningInput(recipientID)
	if err != nil {
		t.Fatal(err)
	}
	want, err := canonicalEM.Marshal([]any{msg.T, msg.ID, recipientID, msg.A})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("SigningInput\n  got  %s\n  want %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestMessageConstructorValidation(t *testing.T) {
	kp := mustKeypair(t)
	recipientID := bytes.Repeat([]byte{0xCC}, 32)
	// Empty method.
	if _, err := NewQuery("", map[string]any{}, kp, recipientID, []byte("t")); err == nil {
		t.Error("NewQuery should reject empty method")
	}
	// txid too short.
	if _, err := NewQuery("ping", map[string]any{}, kp, recipientID, nil); err == nil {
		t.Error("NewQuery should reject empty txid")
	}
	// txid too long.
	if _, err := NewQuery("ping", map[string]any{}, kp, recipientID, bytes.Repeat([]byte{1}, 17)); err == nil {
		t.Error("NewQuery should reject 17-byte txid")
	}
	// Bad recipient.
	if _, err := NewQuery("ping", map[string]any{}, kp, []byte{1, 2}, []byte("t")); err == nil {
		t.Error("NewQuery should reject short recipientID")
	}
}

func TestDecodeMessageRejectsForgedID(t *testing.T) {
	kp := mustKeypair(t)
	recipientID := bytes.Repeat([]byte{0xCC}, 32)
	msg, _ := NewQuery("ping", map[string]any{}, kp, recipientID, []byte("tx"))
	b := mustBytes(t, msg)
	// Mutate ID to a forged value and re-encode.
	msg.ID = bytes.Repeat([]byte{0xEE}, 32)
	forged, err := msg.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeMessage(forged); err == nil {
		t.Error("DecodeMessage should reject forged ID (id != NodeID(pk))")
	}
	// Positive control: b (the original, unmutated message) must decode
	// cleanly, confirming the forged rejection above is specifically due to
	// the id != SHA-256(pk) check and not a general decode failure.
	if _, err := DecodeMessage(b); err != nil {
		t.Errorf("positive control: DecodeMessage(original) failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RecoveryPolicyWire + Claim (RawMessage) round-trip through a Record
// ---------------------------------------------------------------------------

func TestRecoveryPolicyRoundTrip(t *testing.T) {
	k1, k2, k3 := mustKeypair(t), mustKeypair(t), mustKeypair(t)
	rp, err := NewRecoveryPolicyWire(2, [][]byte{k1.Public(), k2.Public(), k3.Public()}, 3600)
	if err != nil {
		t.Fatal(err)
	}
	kp := mustKeypair(t)
	tldID := mustTldID(t, kp.Public())
	name := mustWireName(t, nil, "foo", tldID)
	rec := mustRecord(t, name, kp.Public(), 1, 0, 1)
	rec.Recovery = rp
	env := mustSign(t, rec, kp)
	envBytes, err := env.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeEnvelope(envBytes)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Record.Recovery == nil {
		t.Fatal("decoded recovery nil")
	}
	if dec.Record.Recovery.Threshold != 2 || dec.Record.Recovery.Timelock != 3600 || len(dec.Record.Recovery.Keys) != 3 {
		t.Errorf("decoded recovery mismatch: %+v", dec.Record.Recovery)
	}
}

func TestClaimRawMessageRoundTrip(t *testing.T) {
	// The claims package encodes an AliasClaim to canonical CBOR and sets
	// Record.Claim to those raw bytes; wire embeds them verbatim.
	claimInner := map[uint64]any{1: uint64(7), 2: []byte("alias"), 3: uint64(1000)}
	claimBytes, err := canonicalEM.Marshal(claimInner)
	if err != nil {
		t.Fatal(err)
	}
	kp := mustKeypair(t)
	tldID := mustTldID(t, kp.Public())
	name := mustWireName(t, nil, "foo", tldID)
	rec := mustRecord(t, name, kp.Public(), 1, 0, 1)
	rec.Claim = cbor.RawMessage(claimBytes)
	env := mustSign(t, rec, kp)
	envBytes, err := env.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeEnvelope(envBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Record.Claim, claimBytes) {
		t.Errorf("claim raw round-trip mismatch\n  got  %s\n  want %s",
			hex.EncodeToString(dec.Record.Claim), hex.EncodeToString(claimBytes))
	}
}
