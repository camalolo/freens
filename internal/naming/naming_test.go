package naming

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestValidateAlias(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"Foo", "foo", false},
		{"FOO", "foo", false},
		{"a", "a", false},
		{"a-b", "a-b", false},
		{"a1", "a1", false},
		{"foo", "foo", false},
		{"123", "", true}, // all-numeric
		{"-a", "", true},  // leading -
		{"a-", "", true},  // trailing -
		{"", "", true},    // empty
		{"a_b", "", true}, // bad char
		{"abé", "", true}, // non-ASCII (no IDNA)
		{"a.b", "", true}, // dot not allowed
	}
	for _, c := range cases {
		got, err := ValidateAlias(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ValidateAlias(%q): want error, got %q", c.in, got)
				continue
			}
			if !errors.Is(err, ErrNaming) {
				t.Errorf("ValidateAlias(%q): error does not wrap ErrNaming: %v", c.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("ValidateAlias(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ValidateAlias(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if !IsValidAlias("foo") {
		t.Error("IsValidAlias(foo) = false, want true")
	}
	if IsValidAlias("123") {
		t.Error("IsValidAlias(123) = true, want false")
	}
}

func TestValidateLabel(t *testing.T) {
	got, err := ValidateLabel("WWW")
	if err != nil || got != "www" {
		t.Errorf("ValidateLabel(WWW) = %q,%v, want www,nil", got, err)
	}
	// numeric labels allowed
	if _, err := ValidateLabel("123"); err != nil {
		t.Errorf("ValidateLabel(123): unexpected error %v", err)
	}
	for _, bad := range []string{"-x", "x-", "", "x_y"} {
		if _, err := ValidateLabel(bad); err == nil {
			t.Errorf("ValidateLabel(%q): want error", bad)
		} else if !errors.Is(err, ErrNaming) {
			t.Errorf("ValidateLabel(%q): error does not wrap ErrNaming: %v", bad, err)
		}
	}
}

func TestDecomposeName(t *testing.T) {
	cases := []struct {
		in      string
		labels  []string
		alias   string
		wantErr bool
	}{
		{"foo", []string{}, "foo", false},
		{"alice.foo", []string{"alice"}, "foo", false},
		{"www.alice.foo", []string{"www", "alice"}, "foo", false},
		{"foo.", []string{}, "foo", false},                        // trailing dot stripped
		{"WWW.Alice.FOO", []string{"www", "alice"}, "foo", false}, // normalized
		{".foo", nil, "", true},
		{"a..b.foo", nil, "", true},
		{"foo..", nil, "", true},
		// 8 labels under TLD OK, 9 not.
		{"a.b.c.d.e.f.g.h.foo", []string{"a", "b", "c", "d", "e", "f", "g", "h"}, "foo", false},
		{"a.b.c.d.e.f.g.h.i.foo", nil, "", true},
	}
	for _, c := range cases {
		labels, alias, err := DecomposeName(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("DecomposeName(%q): want error", c.in)
				continue
			}
			if !errors.Is(err, ErrNaming) {
				t.Errorf("DecomposeName(%q): error does not wrap ErrNaming: %v", c.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("DecomposeName(%q): unexpected error %v", c.in, err)
			continue
		}
		if alias != c.alias || !sliceEq(labels, c.labels) {
			t.Errorf("DecomposeName(%q) = %v,%q, want %v,%q", c.in, labels, alias, c.labels, c.alias)
		}
	}
}

func sliceEq(a, b []string) bool {
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

func TestEncodeWireNameWorkedExample(t *testing.T) {
	tldID := make([]byte, 32)
	for i := range tldID {
		tldID[i] = byte(i)
	}
	wire, err := EncodeWireName([]string{"www", "alice"}, "foo", tldID)
	if err != nil {
		t.Fatal(err)
	}
	// Spec line 192: 0x01 05 "alice" 0x01 03 "www" 0x00 <tld_id>
	wantPrefix := []byte{0x01, 5, 'a', 'l', 'i', 'c', 'e', 0x01, 3, 'w', 'w', 'w', 0x00}
	want := append(append([]byte{}, wantPrefix...), tldID...)
	if !bytes.Equal(wire, want) {
		t.Errorf("wire = %x, want %x", wire, want)
	}
	// Round-trip.
	labels, tid, err := DecodeWireName(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !sliceEq(labels, []string{"www", "alice"}) || !bytes.Equal(tid, tldID) {
		t.Errorf("decode = %v,%x want [www alice],%x", labels, tid, tldID)
	}
}

func TestEncodeWireNameVariants(t *testing.T) {
	tid := bytes.Repeat([]byte{1}, 32)
	// Empty labels (TLD itself).
	w, err := EncodeWireName(nil, "foo", tid)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0x00}, tid...)
	if !bytes.Equal(w, want) {
		t.Errorf("empty-labels wire = %x, want %x", w, want)
	}
	// Single label.
	w, err = EncodeWireName([]string{"alice"}, "foo", tid)
	if err != nil {
		t.Fatal(err)
	}
	want = append([]byte{0x01, 5, 'a', 'l', 'i', 'c', 'e', 0x00}, tid...)
	if !bytes.Equal(w, want) {
		t.Errorf("single-label wire = %x, want %x", w, want)
	}
}

func TestEncodeWireNameErrors(t *testing.T) {
	tid := bytes.Repeat([]byte{1}, 32)
	if _, err := EncodeWireName(nil, "foo", tid[:31]); err == nil {
		t.Error("expected error for 31-byte tld_id")
	} else if !errors.Is(err, ErrNaming) {
		t.Errorf("EncodeWireName(31-byte tld_id): error does not wrap ErrNaming: %v", err)
	}
	if _, err := EncodeWireName(nil, "123", tid); err == nil {
		t.Error("expected error for invalid alias")
	} else if !errors.Is(err, ErrNaming) {
		t.Errorf("EncodeWireName(123): error does not wrap ErrNaming: %v", err)
	}
}

func TestDecodeWireNameMalformed(t *testing.T) {
	tid := bytes.Repeat([]byte{1}, 32)
	cases := [][]byte{
		{0x00},                             // truncated (no tld_id)
		append([]byte{0x02}, tid...),       // bad marker
		{0x01, 5, 'a', 'l', 'i', 'c', 'e'}, // missing terminator
		append([]byte{0x00}, tid[:31]...),  // wrong tld_id length
	}
	for i, c := range cases {
		_, _, err := DecodeWireName(c)
		if err == nil {
			t.Errorf("expected error decoding %x", c)
			continue
		}
		if !errors.Is(err, ErrNaming) {
			t.Errorf("cases[%d] (%x): error does not wrap ErrNaming: %v", i, c, err)
		}
	}
}

func TestDHTKeys(t *testing.T) {
	tid := make([]byte, 32)
	for i := range tid {
		tid[i] = byte(i)
	}
	wire, _ := EncodeWireName(nil, "foo", tid)

	// K_tld == tld_id
	kt, err := DHTKeyTld(tid)
	if err != nil || !bytes.Equal(kt, tid) {
		t.Errorf("DHTKeyTld = %x, want %x", kt, tid)
	}
	if _, err := DHTKeyTld(tid[:31]); err == nil {
		t.Error("DHTKeyTld should reject 31-byte id")
	} else if !errors.Is(err, ErrNaming) {
		t.Errorf("DHTKeyTld(31-byte): error does not wrap ErrNaming: %v", err)
	}

	// K_name == SHA-256(0x02 || wire)
	h := sha256.New()
	h.Write([]byte{0x02})
	h.Write(wire)
	want := h.Sum(nil)
	if got := DHTKeyName(wire); !bytes.Equal(got, want) {
		t.Errorf("DHTKeyName = %x, want %x", got, want)
	}

	// K_claim == SHA-256(0x03 || "claim:foo")
	h2 := sha256.New()
	h2.Write([]byte{0x03})
	h2.Write([]byte("claim:"))
	h2.Write([]byte("foo"))
	wantClaim := h2.Sum(nil)
	gotClaim, err := DHTKeyClaim("foo")
	if err != nil || !bytes.Equal(gotClaim, wantClaim) {
		t.Errorf("DHTKeyClaim(foo) = %x, want %x", gotClaim, wantClaim)
	}
	// Case-insensitive.
	gotUpper, _ := DHTKeyClaim("FOO")
	if !bytes.Equal(gotUpper, wantClaim) {
		t.Error("DHTKeyClaim should be case-insensitive")
	}
	if _, err := DHTKeyClaim("123"); err == nil {
		t.Error("DHTKeyClaim should reject all-numeric alias")
	}

	// Sanity: ErrNaming is the base error type (errors.Is).
	_, err = DHTKeyClaim("123")
	if err == nil {
		t.Fatalf("DHTKeyClaim(123): want error")
	}
	if !errors.Is(err, ErrNaming) {
		t.Errorf("DHTKeyClaim(123): error does not wrap ErrNaming: %v", err)
	}
}
