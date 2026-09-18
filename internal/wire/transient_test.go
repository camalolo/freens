package wire

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestMessageTransientFlagRoundtrip: the v0.19.7 transient flag (field 8)
// survives encode/decode and stays OMITTED when false — nodes that never
// set it emit byte-identical packets to the pre-v0.19.7 encoding.
func TestMessageTransientFlagRoundtrip(t *testing.T) {
	pk := bytes.Repeat([]byte{9}, 32)
	id := sha256.Sum256(pk)
	m := &Message{Y: MsgTypeQuery, T: []byte("tx"), Q: "ping", A: map[string]any{"x": 1}, ID: id[:], PK: pk}
	plain, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain, []byte{0x08}) && cborKey8Present(plain) {
		t.Error("unset flag must be omitted from the encoding (wire compat with pre-v0.19.7 peers)")
	}
	back, err := DecodeMessage(plain)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if back.X {
		t.Error("X = true on a message that never set it")
	}

	m.X = true
	flagged, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	back, err = DecodeMessage(flagged)
	if err != nil {
		t.Fatalf("decode flagged: %v", err)
	}
	if !back.X {
		t.Error("X lost in encode/decode")
	}
}

// cborKey8Present does a structural check: decode into a generic map and see
// whether key 8 (0x08 as a positive integer inside the map) exists.
func cborKey8Present(data []byte) bool {
	var raw map[interface{}]interface{}
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return false
	}
	for k := range raw {
		if i, ok := k.(uint64); ok && i == 8 {
			return true
		}
		if i, ok := k.(int64); ok && i == 8 {
			return true
		}
	}
	return false
}

// TestMessageTransientOldPeerCompat: a PRE-v0.19.7 peer encodes messages
// without key 8 and decodes with a struct that has no X field — both
// directions must keep working when the fleets roll asymmetrically. The
// old-encoder direction is simulated by hand-building the 7-key CBOR map;
// the old-decoder direction by unmarshalling a key-8 message into a struct
// without X (fxamacker ignores unknown keys by default).
func TestMessageTransientOldPeerCompat(t *testing.T) {
	// A validate()-consistent identity: id must equal SHA-256(pk).
	pk := bytes.Repeat([]byte{7}, 32)
	id := sha256.Sum256(pk)

	// Old encoder: no key 8 in the map (integer keys, the keyasint shape).
	oldShape := map[uint]any{
		1: MsgTypeQuery,
		2: []byte("tx"),
		3: "ping",
		4: map[string]any{},
		5: id[:],
		6: pk,
		7: make([]byte, 64),
	}
	encoded, err := cbor.Marshal(oldShape)
	if err != nil {
		t.Fatal(err)
	}
	m, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("old-encoder message rejected by new decoder: %v", err)
	}
	if m.X {
		t.Error("X = true on an old-encoded message")
	}

	// New encoder → old decoder shape: unknown key 8 must not error.
	newer := map[uint]any{
		1: MsgTypeQuery,
		2: []byte("tx"),
		3: "ping",
		4: map[string]any{},
		5: id[:],
		6: pk,
		7: make([]byte, 64),
		8: true,
	}
	encoded, err = cbor.Marshal(newer)
	if err != nil {
		t.Fatal(err)
	}
	var strict struct {
		Y   string         `cbor:"1,keyasint"`
		T   []byte         `cbor:"2,keyasint"`
		Q   string         `cbor:"3,keyasint,omitempty"`
		A   map[string]any `cbor:"4,keyasint"`
		ID  []byte         `cbor:"5,keyasint"`
		PK  []byte         `cbor:"6,keyasint"`
		Sig []byte         `cbor:"7,keyasint"`
	}
	if err := cbor.Unmarshal(encoded, &strict); err != nil {
		t.Fatalf("old-style struct must ignore the unknown key-8 field: %v", err)
	}
}
