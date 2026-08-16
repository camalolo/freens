// Package wire implements the freens central wire format: records, signed
// envelopes, authority chains, and the DHT KRPC message envelope.
//
// This is the Go port of archive/python-v0.1/freens/wire.py and implements the
// protocol-critical structures defined in specifications.md:
//
//   - §4 (lines 232-338) — FREENS_Record, SignedEnvelope, canonical encoding &
//     signing (§4.2), resource records (§4.3), validity rules (§4.4).
//   - §3.4 (lines 203-224) — delegation and authority-chain verification.
//   - §6.3 / Appendix B (lines 1010-1051) — the KRPC-like signed Message
//     envelope and its signature input.
//
// Every byte that crosses the wire or feeds a signature is produced by the
// deterministic CBOR codec (fxamacker/cbor v2 configured with
// CoreDetEncOptions(), i.e. RFC 8949 §4.2). Encoding is therefore byte-stable:
//
//	DecodeEnvelope(env.Bytes()).Bytes() == env.Bytes()
//
// Import-cycle avoidance: the Record's field 11 (AliasClaim) is carried as a
// [cbor.RawMessage]. The claims package encodes an AliasClaim to canonical CBOR
// and assigns those raw bytes to Record.Claim; wire marshals them verbatim as
// the value of map key 11 (embedded-map semantics, design decision 1 of the
// Python reference). wire never imports internal/claims.
package wire

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/fxamacker/cbor/v2"
)

// canonicalEM is the RFC 8949 §4.2 "Core Deterministic" encoding mode used for
// every byte that is signed or hashed. Map keys are sorted into canonical CBOR
// order (ascending numeric for this schema's integer keys 1-12) and integers
// use minimum-length encoding.
//
// NilContainers is set to NilContainerAsEmpty so that a nil slice/map encodes
// as the EMPTY container — e.g. a nil []byte becomes empty bstr (0x40), not
// CBOR null (0xf6). This matches the Python reference (which emits b""/[] and
// never null) and keeps RR.Rdata, Record.RRset, etc. wire-stable when callers
// reach a nil via TXT(""), NewRR(typ,ttl,nil), etc.
var canonicalEM = func() cbor.EncMode {
	opts := cbor.CoreDetEncOptions()
	opts.NilContainers = cbor.NilContainerAsEmpty // nil []byte -> empty bstr (0x40), nil slice/map -> empty container
	em, _ := opts.EncMode()
	return em
}()

// RR type codes (IANA DNS parameters; §4.3 table).
const (
	RRTypeA     = 1   // rdata = 4 raw bytes
	RRTypeNS    = 2   // rdata = wire_name / DNS name
	RRTypeCNAME = 5   // rdata = wire_name / DNS name
	RRTypeMX    = 15  // rdata = uint16 preference || wire_name/DNS name
	RRTypeTXT   = 16  // rdata = opaque bytes (RECOMMENDED UTF-8, <=4096 bytes)
	RRTypeAAAA  = 28  // rdata = 16 raw bytes
	RRTypeSRV   = 33  // rdata = uint16 prio, uint16 weight, uint16 port, target
	RRTypeSSHFP = 44  // rdata = algorithm, fingerprint-type, fingerprint
	RRTypeTLSA  = 52  // rdata = usage, selector, matching-type, certificate data
	RRTypeCAA   = 257 // rdata = flags, tag, value
)

// KRPC message-type markers (Message field 1, "y").
const (
	MsgTypeQuery    = "q"
	MsgTypeResponse = "r"
	MsgTypeError    = "e"
)

var errRecipientID = fmt.Errorf("wire: recipient_id must be %d bytes", constants.NodeIDLen)

// ---------------------------------------------------------------------------
// §4.3 — Resource record
// ---------------------------------------------------------------------------

// RR is a single resource record (§4.3): RR = [type:uint, ttl:uint, rdata:bstr].
//
// On the wire an RR is a definite 3-element CBOR *array* (NOT a map); this is
// implemented via MarshalCBOR/UnmarshalCBOR. The cbor struct tags below document
// the logical field numbers but are not used for (de)serialization — the array
// position is what matters on the wire.
//
// Constraints (enforced by [NewRR]):
//   - Type is any IANA DNS type code (unknown codes are preserved verbatim for
//     opaque forwarding, as in DNS);
//   - TTL is in 1..[constants.RecordMaxTTL] seconds;
//   - Rdata is an opaque byte string.
type RR struct {
	Type  uint64 `cbor:"1,keyasint"`
	TTL   uint64 `cbor:"2,keyasint"`
	Rdata []byte `cbor:"3,keyasint"`
}

// MarshalCBOR encodes the RR as the §4.3 3-element array [type, ttl, rdata].
// rdata is normalized to a non-nil empty byte string when nil so the array
// element is always a bstr (matching the Python reference, which emits b""
// rather than CBOR null).
func (r *RR) MarshalCBOR() ([]byte, error) {
	rd := r.Rdata
	if rd == nil {
		rd = []byte{}
	}
	return canonicalEM.Marshal([]any{r.Type, r.TTL, rd})
}

// UnmarshalCBOR decodes a §4.3 RR array. A non-3-element array is rejected.
func (r *RR) UnmarshalCBOR(data []byte) error {
	var elems []cbor.RawMessage
	if err := cbor.Unmarshal(data, &elems); err != nil {
		return fmt.Errorf("wire: RR must be a CBOR array: %w", err)
	}
	if len(elems) != 3 {
		return fmt.Errorf("wire: RR must be a 3-element array, got %d", len(elems))
	}
	if err := cbor.Unmarshal(elems[0], &r.Type); err != nil {
		return fmt.Errorf("wire: RR.type: %w", err)
	}
	if err := cbor.Unmarshal(elems[1], &r.TTL); err != nil {
		return fmt.Errorf("wire: RR.ttl: %w", err)
	}
	var rd []byte
	if err := cbor.Unmarshal(elems[2], &rd); err != nil {
		return fmt.Errorf("wire: RR.rdata: %w", err)
	}
	r.Rdata = rd
	return nil
}

// NewRR constructs and validates an RR. typ may be any uint; ttl must be in
// 1..[constants.RecordMaxTTL]; rdata is any byte string (copied).
func NewRR(typ, ttl uint64, rdata []byte) (*RR, error) {
	if ttl == 0 || ttl > constants.RecordMaxTTL {
		return nil, fmt.Errorf("wire: ttl must be in 1..%d, got %d", constants.RecordMaxTTL, ttl)
	}
	rd := append([]byte(nil), rdata...)
	return &RR{Type: typ, TTL: ttl, Rdata: rd}, nil
}

// A builds an A record whose rdata is exactly 4 bytes.
func A(ip4 []byte, ttl uint64) (*RR, error) {
	if len(ip4) != 4 {
		return nil, fmt.Errorf("wire: A rdata must be exactly 4 bytes, got %d", len(ip4))
	}
	return NewRR(RRTypeA, ttl, ip4)
}

// AAAA builds an AAAA record whose rdata is exactly 16 bytes.
func AAAA(ip6 []byte, ttl uint64) (*RR, error) {
	if len(ip6) != 16 {
		return nil, fmt.Errorf("wire: AAAA rdata must be exactly 16 bytes, got %d", len(ip6))
	}
	return NewRR(RRTypeAAAA, ttl, ip6)
}

// TXT builds a TXT record whose rdata is the UTF-8 bytes of text.
//
// The spec RECOMMENDS NFC normalization of human-supplied text; the Go port
// does not perform NFC normalization (it would require golang.org/x/text, which
// is outside this package's import budget). Callers that need canonical
// normalization should normalize before calling TXT.
func TXT(text string, ttl uint64) (*RR, error) {
	return NewRR(RRTypeTXT, ttl, []byte(text))
}

// ---------------------------------------------------------------------------
// §5.4 — Recovery policy (wire representation)
// ---------------------------------------------------------------------------

// RecoveryPolicyWire is the wire form of the §5.4 RecoveryPolicy:
//
//	RecoveryPolicy = { 1: threshold, 2: keys, 3: timelock }
//
// where threshold is a uint >= 1 (and <= len(Keys)), Keys is an array of
// 32-byte recovery public keys, and Timelock is a uint (seconds before a
// recovery takes effect).
type RecoveryPolicyWire struct {
	Threshold uint64   `cbor:"1,keyasint"`
	Keys      [][]byte `cbor:"2,keyasint"`
	Timelock  uint64   `cbor:"3,keyasint"`
}

// NewRecoveryPolicyWire validates and constructs a recovery policy.
func NewRecoveryPolicyWire(threshold uint64, keys [][]byte, timelock uint64) (*RecoveryPolicyWire, error) {
	if threshold < 1 {
		return nil, errors.New("wire: threshold must be >= 1")
	}
	for i, k := range keys {
		if len(k) != constants.Ed25519PublicKeyLen {
			return nil, fmt.Errorf("wire: recovery key %d must be %d bytes, got %d", i, constants.Ed25519PublicKeyLen, len(k))
		}
	}
	if threshold > uint64(len(keys)) {
		return nil, errors.New("wire: threshold must be <= len(keys)")
	}
	cp := make([][]byte, len(keys))
	for i, k := range keys {
		cp[i] = append([]byte(nil), k...)
	}
	return &RecoveryPolicyWire{Threshold: threshold, Keys: cp, Timelock: timelock}, nil
}

// ---------------------------------------------------------------------------
// §4.1 — FREENS_Record
// ---------------------------------------------------------------------------

// Record is a freens record (§4.1). Fields 1-12.
//
// Required fields (always present in the CBOR map): Version, Name, Owner,
// Sequence, Created, Expires, RRset. Optional fields (omitted from the CBOR map
// when absent — design decision 3): Delegation, PrevHash, Recovery, Claim,
// Revoke. Revoke is included ONLY when it points at true.
//
// (De)serialization is via MarshalCBOR/UnmarshalCBOR so that:
//   - a nil RRset is normalized to an empty array (matching the Python
//     reference, which always emits field 7);
//   - the optional fields are omitted when absent;
//   - Revoke is emitted only when true;
//   - Claim (a [cbor.RawMessage]) is embedded verbatim, giving the
//     embedded-map semantics of design decision 1 without importing
//     internal/claims.
//
// The cbor struct tags document the field numbers but, because MarshalCBOR and
// UnmarshalCBOR are implemented, are not used directly by the codec.
type Record struct {
	Version    uint64              `cbor:"1,keyasint"`           // always ProtoVersion
	Name       []byte              `cbor:"2,keyasint"`           // wire_name (TLD-adjacent-first)
	Owner      []byte              `cbor:"3,keyasint"`           // 32-byte Ed25519 public key
	Sequence   uint64              `cbor:"4,keyasint"`           // strictly increasing per name, >= 1
	Created    uint64              `cbor:"5,keyasint"`           // unix seconds
	Expires    uint64              `cbor:"6,keyasint"`           // unix seconds; Created <= Expires
	RRset      []*RR               `cbor:"7,keyasint"`           // array of RR; MAY be empty
	Delegation []byte              `cbor:"8,keyasint,omitempty"` // 32-byte pk or nil
	PrevHash   []byte              `cbor:"9,keyasint,omitempty"` // 32-byte hash or nil
	Recovery   *RecoveryPolicyWire `cbor:"10,keyasint,omitempty"`
	Claim      cbor.RawMessage     `cbor:"11,keyasint,omitempty"` // canonical CBOR of AliasClaim (set by claims pkg); nil when absent
	Revoke     *bool               `cbor:"12,keyasint,omitempty"` // include only when &true
}

// MarshalCBOR builds the §4.1 map with the omission rules described above.
func (r *Record) MarshalCBOR() ([]byte, error) {
	m := map[uint64]any{
		1: r.Version,
		2: r.Name,
		3: r.Owner,
		4: r.Sequence,
		5: r.Created,
		6: r.Expires,
	}
	rrset := r.RRset
	if rrset == nil {
		rrset = []*RR{}
	}
	m[7] = rrset
	if len(r.Delegation) > 0 {
		m[8] = r.Delegation
	}
	if len(r.PrevHash) > 0 {
		m[9] = r.PrevHash
	}
	if r.Recovery != nil {
		m[10] = r.Recovery
	}
	if len(r.Claim) > 0 {
		m[11] = r.Claim // cbor.RawMessage marshals as opaque embedded CBOR
	}
	if r.Revoke != nil && *r.Revoke {
		m[12] = true
	}
	return canonicalEM.Marshal(m)
}

// UnmarshalCBOR decodes a §4.1 map. Required keys 1-7 must be present;
// optional 8-12 are read if present. Field 11 is captured as raw CBOR bytes.
func (r *Record) UnmarshalCBOR(data []byte) error {
	var m map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("wire: record must be a CBOR map: %w", err)
	}
	for _, k := range []uint64{1, 2, 3, 4, 5, 6, 7} {
		if _, ok := m[k]; !ok {
			return fmt.Errorf("wire: record missing required key %d", k)
		}
	}
	if err := cbor.Unmarshal(m[1], &r.Version); err != nil {
		return fmt.Errorf("wire: record.version: %w", err)
	}
	var name []byte
	if err := cbor.Unmarshal(m[2], &name); err != nil {
		return fmt.Errorf("wire: record.name: %w", err)
	}
	r.Name = name
	var owner []byte
	if err := cbor.Unmarshal(m[3], &owner); err != nil {
		return fmt.Errorf("wire: record.owner: %w", err)
	}
	r.Owner = owner
	if err := cbor.Unmarshal(m[4], &r.Sequence); err != nil {
		return fmt.Errorf("wire: record.sequence: %w", err)
	}
	if err := cbor.Unmarshal(m[5], &r.Created); err != nil {
		return fmt.Errorf("wire: record.created: %w", err)
	}
	if err := cbor.Unmarshal(m[6], &r.Expires); err != nil {
		return fmt.Errorf("wire: record.expires: %w", err)
	}
	var rrset []*RR
	if err := cbor.Unmarshal(m[7], &rrset); err != nil {
		return fmt.Errorf("wire: record.rrset: %w", err)
	}
	r.RRset = rrset
	if v, ok := m[8]; ok {
		var d []byte
		if err := cbor.Unmarshal(v, &d); err != nil {
			return fmt.Errorf("wire: record.delegation: %w", err)
		}
		r.Delegation = d
	}
	if v, ok := m[9]; ok {
		var p []byte
		if err := cbor.Unmarshal(v, &p); err != nil {
			return fmt.Errorf("wire: record.prev_hash: %w", err)
		}
		r.PrevHash = p
	}
	if v, ok := m[10]; ok {
		var rec RecoveryPolicyWire
		if err := cbor.Unmarshal(v, &rec); err != nil {
			return fmt.Errorf("wire: record.recovery: %w", err)
		}
		r.Recovery = &rec
	}
	if v, ok := m[11]; ok {
		r.Claim = append(cbor.RawMessage(nil), v...)
	}
	if v, ok := m[12]; ok {
		var b bool
		if err := cbor.Unmarshal(v, &b); err != nil {
			return fmt.Errorf("wire: record.revoke: %w", err)
		}
		r.Revoke = &b
	}
	return nil
}

// NewRecord validates the required fields and returns a Record with the
// optional fields zeroed. Callers populate RRset/Delegation/etc directly and
// may then call [Record.Validate] to re-check.
func NewRecord(name, owner []byte, sequence, created, expires uint64) (*Record, error) {
	r := &Record{
		Version:  constants.ProtoVersion,
		Name:     append([]byte(nil), name...),
		Owner:    append([]byte(nil), owner...),
		Sequence: sequence,
		Created:  created,
		Expires:  expires,
		RRset:    []*RR{},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate re-runs all structural checks (§4.1/§4.3/§4.4 rule 1). It is called
// by [NewRecord] and [DecodeEnvelope] and is safe to call on a decoded record.
func (r *Record) Validate() error {
	if r.Version != constants.ProtoVersion {
		return fmt.Errorf("wire: version must be %d, got %d", constants.ProtoVersion, r.Version)
	}
	if len(r.Name) == 0 {
		return errors.New("wire: name (field 2) must be a non-empty byte string")
	}
	if len(r.Owner) != constants.Ed25519PublicKeyLen {
		return fmt.Errorf("wire: owner (field 3) must be %d bytes, got %d", constants.Ed25519PublicKeyLen, len(r.Owner))
	}
	if r.Sequence < 1 {
		return errors.New("wire: sequence (field 4) must be a uint >= 1")
	}
	if r.Created > r.Expires {
		return errors.New("wire: created (field 5) must be <= expires (field 6)")
	}
	if len(r.RRset) > constants.MaxRRsPerRecord {
		return fmt.Errorf("wire: rrset (field 7) exceeds %d RRs", constants.MaxRRsPerRecord)
	}
	for i, rr := range r.RRset {
		if rr == nil {
			return fmt.Errorf("wire: rrset[%d] is nil", i)
		}
	}
	if r.Delegation != nil && len(r.Delegation) != constants.Ed25519PublicKeyLen {
		return fmt.Errorf("wire: delegation (field 8) must be %d bytes or nil", constants.Ed25519PublicKeyLen)
	}
	if r.PrevHash != nil && len(r.PrevHash) != constants.SHA256Len {
		return fmt.Errorf("wire: prev_hash (field 9) must be %d bytes or nil", constants.SHA256Len)
	}
	return nil
}

// CanonicalBytes returns the deterministic CBOR bytes of the record — the bytes
// that are signed and (by design decision 1) byte-identical to the embedded
// record serialization inside a [SignedEnvelope].
func (r *Record) CanonicalBytes() ([]byte, error) {
	return canonicalEM.Marshal(r)
}

// ---------------------------------------------------------------------------
// §4.1 — SignedEnvelope
// ---------------------------------------------------------------------------

// SignedEnvelope is §4.1 SignedEnvelope = { 1: record, 2: sig, 3: signer }.
//
// Field 1 is the FREENS_Record as an EMBEDDED canonical CBOR map (design
// decision 1); field 2 is a 64-byte Ed25519 signature over
// [SignedEnvelope.CanonicalRecordBytes]; field 3 is the 32-byte signer public
// key. This is the object stored in and served from the DHT.
//
// Immutability contract: a SignedEnvelope (and its Record) must not be
// mutated after it is signed ([SignRecord]) or decoded ([DecodeEnvelope]) —
// the signature covers the canonical record bytes, so any mutation invalid
// -ates it by definition. The lazily-cached canonical serializations below
// rely on (and enforce) that contract; the unexported fields are ignored by
// the CBOR codec and never appear on the wire.
type SignedEnvelope struct {
	Record *Record `cbor:"1,keyasint"`
	Sig    []byte  `cbor:"2,keyasint"`
	Signer []byte  `cbor:"3,keyasint"`

	// canonRecord caches Record.CanonicalBytes (the signature-covered
	// bytes); canonFull caches the whole-envelope canonical CBOR (Bytes).
	// Both are populated lazily and atomically — concurrent first uses may
	// each compute the (deterministic, identical) bytes and race to store;
	// readers always see either nil or a complete, valid slice.
	//
	// Why (profiling, Aug 2026): after signature-verify memoization, the
	// re-maining CPU hotspot was Record.MarshalCBOR — every VerifySignature
	// and RecordHash re-serialized the same envelope, and one cold resolve
	// re-marshaled each envelope 3-4 times across layer boundaries
	// (collect → verify → chain walk → store tie-break).
	canonRecord atomic.Pointer[[]byte]
	canonFull   atomic.Pointer[[]byte]
}

// CanonicalRecordBytes returns the bytes the signature covers — identical to
// [Record.CanonicalBytes] and, by determinism, byte-identical to the embedded
// record serialization in [SignedEnvelope.Bytes]. The result is cached on the
// envelope (see the struct's immutability contract).
func (e *SignedEnvelope) CanonicalRecordBytes() ([]byte, error) {
	if e.Record == nil {
		return nil, errors.New("wire: envelope has no record")
	}
	if b := e.canonRecord.Load(); b != nil {
		return *b, nil
	}
	b, err := e.Record.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	e.canonRecord.Store(&b)
	return b, nil
}

// Bytes returns the canonical CBOR of the whole envelope — what is stored and
// transmitted in the DHT and what [SignedEnvelope.RecordHash] hashes. The
// result is cached on the envelope (see the struct's immutability contract).
func (e *SignedEnvelope) Bytes() ([]byte, error) {
	if b := e.canonFull.Load(); b != nil {
		return *b, nil
	}
	b, err := canonicalEM.Marshal(e)
	if err != nil {
		return nil, err
	}
	e.canonFull.Store(&b)
	return b, nil
}

// RecordHash returns H_record = SHA-256(canonical_cbor(SignedEnvelope)) (§4.2).
// It covers the WHOLE envelope (record + sig + signer) and is used for
// prev_hash chaining (§8.3) and the §6.4 DHT store tie-break.
func (e *SignedEnvelope) RecordHash() ([]byte, error) {
	b, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

// VerifySignature reports whether Sig verifies under Signer against
// CanonicalRecordBytes. It is non-raising: any length mismatch or verification
// failure yields false.
func (e *SignedEnvelope) VerifySignature() bool {
	if e.Record == nil {
		return false
	}
	if len(e.Sig) != constants.Ed25519SignatureLen {
		return false
	}
	if len(e.Signer) != constants.Ed25519PublicKeyLen {
		return false
	}
	cb, err := e.CanonicalRecordBytes()
	if err != nil {
		return false
	}
	return crypto.Verify(e.Signer, e.Sig, cb)
}

// IsRevoked reports whether field 12 (revoke) is set to true (§8.5).
func (e *SignedEnvelope) IsRevoked() bool {
	return e.Record != nil && e.Record.Revoke != nil && *e.Record.Revoke
}

// SignRecord builds a SignedEnvelope over rec signed by kp. The returned
// envelope's VerifySignature is true by construction.
func SignRecord(rec *Record, kp *crypto.Keypair) (*SignedEnvelope, error) {
	if rec == nil {
		return nil, errors.New("wire: record must be non-nil")
	}
	if kp == nil {
		return nil, errors.New("wire: keypair must be non-nil")
	}
	cb, err := rec.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	env := &SignedEnvelope{
		Record: rec,
		Sig:    kp.Sign(cb),
		Signer: kp.Public(),
	}
	env.canonRecord.Store(&cb) // pre-populate: the just-computed signing bytes
	return env, nil
}

// DecodeEnvelope decodes canonical CBOR envelope bytes (the DHT store payload)
// and validates the result. It rejects malformed CBOR, missing keys, and bad
// sig/signer lengths.
func DecodeEnvelope(data []byte) (*SignedEnvelope, error) {
	var env SignedEnvelope
	if err := cbor.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("wire: invalid envelope CBOR: %w", err)
	}
	if env.Record == nil {
		return nil, errors.New("wire: envelope missing record (field 1)")
	}
	if err := env.Record.Validate(); err != nil {
		return nil, err
	}
	if len(env.Sig) != constants.Ed25519SignatureLen {
		return nil, fmt.Errorf("wire: sig (field 2) must be %d bytes, got %d", constants.Ed25519SignatureLen, len(env.Sig))
	}
	if len(env.Signer) != constants.Ed25519PublicKeyLen {
		return nil, fmt.Errorf("wire: signer (field 3) must be %d bytes, got %d", constants.Ed25519PublicKeyLen, len(env.Signer))
	}
	return &env, nil
}

// ---------------------------------------------------------------------------
// §6.4 PUT step 3 — DHT store winner rule
// ---------------------------------------------------------------------------

// EnvelopeWins reports whether newer strictly wins over older per §6.4 step 3:
//
//	newer.sequence > older.sequence, OR
//	(newer.sequence == older.sequence AND bytes.Compare(newerHash, olderHash) > 0)
//
// The bytewise tie-break makes idempotent concurrent republication convergent:
// two identical envelopes have identical hashes (neither wins), while two
// different same-sequence records are resolved deterministically by hash. Any
// hash error yields false.
func EnvelopeWins(newer, older *SignedEnvelope) bool {
	if newer == nil || older == nil || newer.Record == nil || older.Record == nil {
		return false
	}
	ns := newer.Record.Sequence
	os := older.Record.Sequence
	if ns > os {
		return true
	}
	if ns == os {
		nh, err1 := newer.RecordHash()
		oh, err2 := older.RecordHash()
		if err1 != nil || err2 != nil {
			return false
		}
		return bytes.Compare(nh, oh) > 0
	}
	return false
}

// ---------------------------------------------------------------------------
// §4.4 — basic validity (structural + signature + time window)
// ---------------------------------------------------------------------------

// IsBasicValid reports whether env satisfies §4.4 rules 1, 2, 4(partial), 5:
// version==1, structural validity, a valid signature, sequence>=1, and
// created <= now < expires. It does NOT check the authority chain (§3.4 — use
// [VerifyAuthorityChain]) nor sequence history (§4.4 rule 4, which requires
// DHT state). Non-raising: any failure yields false.
func IsBasicValid(env *SignedEnvelope, now uint64) bool {
	if env == nil || env.Record == nil {
		return false
	}
	r := env.Record
	if r.Version != constants.ProtoVersion {
		return false
	}
	if err := r.Validate(); err != nil {
		return false
	}
	if !env.VerifySignature() {
		return false
	}
	if r.Sequence < 1 {
		return false
	}
	if r.Created > now || now >= r.Expires {
		return false
	}
	return true
}

// VerifyChainLink reports whether newer correctly chains to older per §4.4
// rule 4 (lines 324-338) and §8.3 (lines 666-688).
//
// A newcomer that carries prev_hash (field 9) ASSERTS a link to its
// predecessor, so the assertion is enforced: prev_hash must equal
// H_record(older) = SHA-256(canonical_cbor(older)) (§4.2, the hash used for
// prev_hash chaining) AND newer.Sequence must be strictly greater than
// older.Sequence (§4.4 rule 4; a §8.3 transfer carries sequence = prev + 1).
// Any mismatch — wrong hash, missing predecessor, non-increasing sequence —
// yields false.
//
// A newcomer with a nil/empty prev_hash asserts nothing: per the spec
// prev_hash is OPTIONAL on the wire (§8.2 ordinary updates need not carry it;
// §8.3 requires it only for transfers). Such a newcomer is chain-valid iff
//
//   - there is no predecessor (older == nil) and it is a FIRST PUBLICATION
//     (Sequence == 1, matching §8.2's "sequence resets to 1" for a fresh or
//     re-created name), or
//   - a predecessor exists and Sequence still strictly increases (an ordinary
//     §8.2 update: sequence = old + 1, prev_hash optional).
//
// This keeps existing publishers backward compatible: records published
// without prev_hash (Sequence 1, or Sequence > old with no prev_hash) remain
// valid, which is exactly the pre-prev_hash behavior of the §6.4 winner rule.
//
// Non-raising: any nil envelope/record or hash error yields false.
func VerifyChainLink(newer, older *SignedEnvelope) bool {
	if newer == nil || newer.Record == nil {
		return false
	}
	if len(newer.Record.PrevHash) == 0 {
		// No chain assertion: first publication, or an ordinary update whose
		// sequence strictly increases (§8.2).
		if older == nil || older.Record == nil {
			return newer.Record.Sequence == 1
		}
		return newer.Record.Sequence > older.Record.Sequence
	}
	// prev_hash is set: it must point at the predecessor's H_record and the
	// sequence must increase (§8.3).
	if older == nil || older.Record == nil {
		return false
	}
	h, err := older.RecordHash()
	if err != nil {
		return false
	}
	return bytes.Equal(newer.Record.PrevHash, h) && newer.Record.Sequence > older.Record.Sequence
}

// ---------------------------------------------------------------------------
// §3.4 — authority chain
// ---------------------------------------------------------------------------

// VerifyAuthorityChain walks a chain of SignedEnvelopes from the TLD record
// down to a name record (§3.4) and reports whether every hop verifies.
//
// chain is ordered TLD-first: chain[0] is the TLD record, chain[-1] is the
// target. Rules (ported from wire.py):
//
//   - len(chain) in [1, MaxLabels+1]; every env.VerifySignature() holds.
//   - chain[0] (TLD root): signer == owner; the name decodes to ZERO labels;
//     crypto.TldID(owner) == tld_id embedded in the name (self-certifying).
//   - chain[i>0]: authorized by parent chain[i-1] iff
//     (parent.Delegation != nil && parent.Delegation == child.Signer) OR
//     (parent.Owner == child.Signer); AND the child name is a STRICT DESCENDANT
//     of the parent name (same tld_id, more labels, parent's display-order
//     labels are the suffix of the child's).
//
// Non-raising: any decode/structural failure yields false.
func VerifyAuthorityChain(chain []*SignedEnvelope) bool {
	if len(chain) == 0 {
		return false
	}
	if len(chain) > constants.MaxLabels+1 {
		return false
	}
	for _, env := range chain {
		if env == nil || env.Record == nil {
			return false
		}
		if !env.VerifySignature() {
			return false
		}
	}

	// chain[0]: self-certifying TLD root.
	root := chain[0]
	if !bytes.Equal(root.Signer, root.Record.Owner) {
		return false
	}
	rootLabels, rootTldID, err := naming.DecodeWireName(root.Record.Name)
	if err != nil {
		return false
	}
	if len(rootLabels) != 0 {
		return false
	}
	ownerTldID, err := crypto.TldID(root.Record.Owner)
	if err != nil {
		return false
	}
	if !bytes.Equal(ownerTldID, rootTldID) {
		return false
	}

	// Each subsequent hop: authorized by parent AND a strict descendant.
	for i := 1; i < len(chain); i++ {
		parent := chain[i-1]
		child := chain[i]

		authorized := false
		if len(parent.Record.Delegation) > 0 && bytes.Equal(parent.Record.Delegation, child.Signer) {
			authorized = true
		} else if bytes.Equal(parent.Record.Owner, child.Signer) {
			authorized = true
		}
		if !authorized {
			return false
		}

		pLabels, pTldID, err := naming.DecodeWireName(parent.Record.Name)
		if err != nil {
			return false
		}
		cLabels, cTldID, err := naming.DecodeWireName(child.Record.Name)
		if err != nil {
			return false
		}
		if !bytes.Equal(cTldID, pTldID) {
			return false
		}
		if len(cLabels) <= len(pLabels) {
			return false
		}
		// Parent's display-order labels are the shared TLD-adjacent suffix of
		// the child's labels (display order is most-specific-first). When the
		// parent is the TLD (pLabels empty) every same-TLD child qualifies.
		if len(pLabels) > 0 {
			off := len(cLabels) - len(pLabels)
			for j := 0; j < len(pLabels); j++ {
				if cLabels[off+j] != pLabels[j] {
					return false
				}
			}
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// §6.3 / Appendix B.1 — DHT KRPC Message
// ---------------------------------------------------------------------------

// Message is the §6.3 / Appendix B.1 KRPC-like signed CBOR message envelope.
//
//	Message = {
//	  1: y    "q"|"r"|"e"            query / response / error
//	  2: t    bstr(1..16)            transaction id
//	  3: q    text                   method name (queries only)
//	  4: a    map                    arguments / return values
//	  5: id   bstr(32)               sender Node ID = SHA-256(pk)
//	  6: pk   bstr(32)               sender public key
//	  7: sig  bstr(64)               Ed25519 over SigningInput
//	}
//
// Node identity is verified on receipt (id == SHA-256(pk), §6.2). The signature
// covers the canonical CBOR array [t, id, recipient_id, a] (§6.3 line 437);
// recipient_id is the receiving node's 32-byte ID (transport context), supplied
// to Sign/Verify rather than carried in the message body.
type Message struct {
	Y   string         `cbor:"1,keyasint"`
	T   []byte         `cbor:"2,keyasint"`
	Q   string         `cbor:"3,keyasint,omitempty"`
	A   map[string]any `cbor:"4,keyasint"`
	ID  []byte         `cbor:"5,keyasint"`
	PK  []byte         `cbor:"6,keyasint"`
	Sig []byte         `cbor:"7,keyasint"`
}

// SigningInput returns the bytes the signature covers: the canonical CBOR of
// the 4-element array [t, id, recipient_id, a] (§6.3 line 437). recipient_id
// must be 32 bytes.
func (m *Message) SigningInput(recipientID []byte) ([]byte, error) {
	if len(recipientID) != constants.NodeIDLen {
		return nil, errRecipientID
	}
	return canonicalEM.Marshal([]any{m.T, m.ID, recipientID, m.A})
}

// Sign sets PK from kp, refreshes ID = NodeID(PK) (so the id == NodeID(pk)
// invariant always holds post-sign), and sets Sig = kp.Sign(SigningInput).
func (m *Message) Sign(kp *crypto.Keypair, recipientID []byte) error {
	if kp == nil {
		return errors.New("wire: keypair must be non-nil")
	}
	if len(recipientID) != constants.NodeIDLen {
		return errRecipientID
	}
	m.PK = kp.Public()
	id, err := crypto.NodeID(m.PK)
	if err != nil {
		return err
	}
	m.ID = id
	input, err := m.SigningInput(recipientID)
	if err != nil {
		return err
	}
	m.Sig = kp.Sign(input)
	return nil
}

// Verify reports whether id == NodeID(PK) AND Sig verifies under PK against
// SigningInput(recipientID). Non-raising.
func (m *Message) Verify(recipientID []byte) bool {
	if len(recipientID) != constants.NodeIDLen {
		return false
	}
	if len(m.Sig) != constants.Ed25519SignatureLen {
		return false
	}
	id, err := crypto.NodeID(m.PK)
	if err != nil || !bytes.Equal(id, m.ID) {
		return false
	}
	input, err := m.SigningInput(recipientID)
	if err != nil {
		return false
	}
	return crypto.Verify(m.PK, m.Sig, input)
}

// Bytes returns the canonical CBOR of the whole message.
func (m *Message) Bytes() ([]byte, error) {
	return canonicalEM.Marshal(m)
}

// validate checks the structural invariants a Message must satisfy. It is run
// by DecodeMessage and is satisfied by construction in the New* helpers.
func (m *Message) validate() error {
	switch m.Y {
	case MsgTypeQuery, MsgTypeResponse, MsgTypeError:
	default:
		return fmt.Errorf("wire: y (field 1) must be 'q', 'r', or 'e', got %q", m.Y)
	}
	if len(m.T) < 1 || len(m.T) > 16 {
		return fmt.Errorf("wire: t (field 2) must be 1..16 bytes, got %d", len(m.T))
	}
	if m.Y == MsgTypeQuery && m.Q == "" {
		return errors.New("wire: query message requires a non-empty method name (field 3 'q')")
	}
	if len(m.ID) != constants.NodeIDLen {
		return fmt.Errorf("wire: id (field 5) must be %d bytes", constants.NodeIDLen)
	}
	if len(m.PK) != constants.Ed25519PublicKeyLen {
		return fmt.Errorf("wire: pk (field 6) must be %d bytes", constants.Ed25519PublicKeyLen)
	}
	id, err := crypto.NodeID(m.PK)
	if err != nil || !bytes.Equal(id, m.ID) {
		return errors.New("wire: id (field 5) must equal SHA-256(pk) (field 6)")
	}
	if len(m.Sig) != 0 && len(m.Sig) != constants.Ed25519SignatureLen {
		return fmt.Errorf("wire: sig (field 7) must be 0 or %d bytes, got %d", constants.Ed25519SignatureLen, len(m.Sig))
	}
	return nil
}

// DecodeMessage decodes canonical CBOR message bytes and validates the result
// (including the id == SHA-256(pk) check, so a forged-ID message is rejected).
func DecodeMessage(data []byte) (*Message, error) {
	var m Message
	if err := cbor.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("wire: invalid message CBOR: %w", err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// NewQuery builds and signs a query message (y == "q"). method becomes field 3;
// txid is the 1..16-byte transaction id; id/pk are derived from kp.
func NewQuery(method string, args map[string]any, kp *crypto.Keypair, recipientID, txid []byte) (*Message, error) {
	if method == "" {
		return nil, errors.New("wire: method must be a non-empty string")
	}
	if len(txid) < 1 || len(txid) > 16 {
		return nil, fmt.Errorf("wire: txid must be 1..16 bytes, got %d", len(txid))
	}
	if len(recipientID) != constants.NodeIDLen {
		return nil, errRecipientID
	}
	m := &Message{Y: MsgTypeQuery, T: append([]byte(nil), txid...), A: args, Q: method}
	if err := m.Sign(kp, recipientID); err != nil {
		return nil, err
	}
	return m, nil
}

// NewResponse builds and signs a response message (y == "r").
func NewResponse(args map[string]any, kp *crypto.Keypair, recipientID, txid []byte) (*Message, error) {
	return newNonQuery(MsgTypeResponse, args, kp, recipientID, txid)
}

// NewError builds and signs an error message (y == "e").
func NewError(args map[string]any, kp *crypto.Keypair, recipientID, txid []byte) (*Message, error) {
	return newNonQuery(MsgTypeError, args, kp, recipientID, txid)
}

func newNonQuery(y string, args map[string]any, kp *crypto.Keypair, recipientID, txid []byte) (*Message, error) {
	if len(txid) < 1 || len(txid) > 16 {
		return nil, fmt.Errorf("wire: txid must be 1..16 bytes, got %d", len(txid))
	}
	if len(recipientID) != constants.NodeIDLen {
		return nil, errRecipientID
	}
	m := &Message{Y: y, T: append([]byte(nil), txid...), A: args}
	if err := m.Sign(kp, recipientID); err != nil {
		return nil, err
	}
	return m, nil
}
