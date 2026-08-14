package dht

import (
	"bytes"
	"context"
	"testing"

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/naming"
	"github.com/laurent/freens/internal/wire"
)

// TestStoreLookup builds a TLD-root record and a descendant `www.foo` A record,
// stores each at the key the daemon would use (K_tld for the TLD root, K_name
// for the name), and verifies StoreLookup.Lookup routes each wire_name to the
// right envelope — and returns (nil, nil) for an absent name. This is the
// contract the 3 copy-pasted `storeLookup` types rely on, now covered in the
// adapter's own package.
func TestStoreLookup(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const now int64 = 2_000_000
	store := NewEnvelopeStore(0, func() int64 { return now })

	// --- setup: a self-certifying TLD keypair ---------------------------
	alice, err := crypto.Generate()
	if err != nil {
		t.Fatalf("crypto.Generate: %v", err)
	}
	aliceTID, err := crypto.TldID(alice.Public())
	if err != nil {
		t.Fatalf("crypto.TldID: %v", err)
	}

	// --- TLD-root record at K_tld = tld_id ------------------------------
	// EncodeWireName(nil, alias, tldID) yields the 0x00 || tld_id TLD-root form.
	tldWire, err := naming.EncodeWireName(nil, "foo", aliceTID)
	if err != nil {
		t.Fatalf("EncodeWireName(tld): %v", err)
	}
	tldRec, err := wire.NewRecord(tldWire, alice.Public(), 1,
		uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		t.Fatalf("NewRecord(tld): %v", err)
	}
	tldEnv, err := wire.SignRecord(tldRec, alice)
	if err != nil {
		t.Fatalf("SignRecord(tld): %v", err)
	}
	if !tldEnv.VerifySignature() {
		t.Fatal("TLD envelope signature invalid")
	}
	kTld, err := naming.DHTKeyTld(aliceTID) // == tld_id
	if err != nil {
		t.Fatalf("DHTKeyTld: %v", err)
	}
	if ok, err := store.Put(kTld, tldEnv, now, true); err != nil || !ok {
		t.Fatalf("Put(K_tld): ok=%v err=%v", ok, err)
	}

	// --- www.foo A record at K_name -------------------------------------
	wwwWire, err := naming.EncodeWireName([]string{"www"}, "foo", aliceTID)
	if err != nil {
		t.Fatalf("EncodeWireName(www): %v", err)
	}
	wwwRec, err := wire.NewRecord(wwwWire, alice.Public(), 1,
		uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		t.Fatalf("NewRecord(www): %v", err)
	}
	aRR, err := wire.A([]byte{203, 0, 113, 42}, 300)
	if err != nil {
		t.Fatalf("wire.A: %v", err)
	}
	wwwRec.RRset = []*wire.RR{aRR}
	wwwEnv, err := wire.SignRecord(wwwRec, alice)
	if err != nil {
		t.Fatalf("SignRecord(www): %v", err)
	}
	if !wwwEnv.VerifySignature() {
		t.Fatal("www envelope signature invalid")
	}
	kName := naming.DHTKeyName(wwwWire)
	if ok, err := store.Put(kName, wwwEnv, now, true); err != nil || !ok {
		t.Fatalf("Put(K_name): ok=%v err=%v", ok, err)
	}

	// --- an absent name (valid wire form, never stored) -----------------
	absentWire, err := naming.EncodeWireName([]string{"mail"}, "foo", aliceTID)
	if err != nil {
		t.Fatalf("EncodeWireName(absent): %v", err)
	}

	lookup := NewStoreLookup(store)

	// --- TLD-root lookup resolves at K_tld ------------------------------
	gotTLD, err := lookup.Lookup(ctx, tldWire, now)
	if err != nil {
		t.Fatalf("Lookup(tldWire): unexpected error: %v", err)
	}
	if gotTLD == nil {
		t.Fatal("Lookup(tldWire) returned nil, want the TLD envelope")
	}
	if !bytes.Equal(gotTLD.Record.Name, tldWire) {
		t.Fatalf("Lookup(tldWire).Record.Name = %x, want %x", gotTLD.Record.Name, tldWire)
	}
	// Stored under the tld_id key, so it must be the exact envelope we Put.
	if gotTLD != tldEnv {
		t.Fatal("Lookup(tldWire) returned a different envelope than the one stored at K_tld")
	}

	// --- name lookup resolves at K_name ---------------------------------
	gotWWW, err := lookup.Lookup(ctx, wwwWire, now)
	if err != nil {
		t.Fatalf("Lookup(wwwWire): unexpected error: %v", err)
	}
	if gotWWW == nil {
		t.Fatal("Lookup(wwwWire) returned nil, want the www envelope")
	}
	if !bytes.Equal(gotWWW.Record.Name, wwwWire) {
		t.Fatalf("Lookup(wwwWire).Record.Name = %x, want %x", gotWWW.Record.Name, wwwWire)
	}
	if gotWWW != wwwEnv {
		t.Fatal("Lookup(wwwWire) returned a different envelope than the one stored at K_name")
	}

	// --- absent name returns (nil, nil) ---------------------------------
	gotAbsent, err := lookup.Lookup(ctx, absentWire, now)
	if err != nil {
		t.Fatalf("Lookup(absentWire): unexpected error: %v", err)
	}
	if gotAbsent != nil {
		t.Fatalf("Lookup(absentWire) = %v, want nil (not stored)", gotAbsent)
	}
}

// TestStoreLookupDecodingError verifies the adapter surfaces a malformed
// wire_name (no 0x00 terminator) as an error rather than silently returning nil.
func TestStoreLookupDecodingError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const now int64 = 2_000_000
	store := NewEnvelopeStore(0, func() int64 { return now })
	lookup := NewStoreLookup(store)

	// A wire_name missing the 0x00 terminator fails naming.DecodeWireName.
	if _, err := lookup.Lookup(ctx, []byte{0x01, 0x03, 'f', 'o', 'o'}, now); err == nil {
		t.Fatal("Lookup(malformed wire_name) want error, got nil")
	}
}
