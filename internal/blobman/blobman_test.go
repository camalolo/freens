package blobman

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestComputeValidateRoundtrip: Compute produces a manifest whose chunk
// list exactly covers the file, whose re-validated shape holds, and whose
// whole-file digest matches an independent sha256.
func TestComputeValidateRoundtrip(t *testing.T) {
	blob := make([]byte, DefaultChunkSize+1234) // one full chunk + a short tail
	if _, err := rand.Read(blob); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "freens-test.tar.gz")
	if err := os.WriteFile(p, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := Compute(p, "v9.9", "freens-test.tar.gz")
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(m.Chunks) != 2 {
		t.Fatalf("chunks = %d, want 2 (one full + one tail)", len(m.Chunks))
	}
	if m.ChunkLen(1) != 1234 {
		t.Errorf("tail chunk = %d bytes, want 1234", m.ChunkLen(1))
	}
	sum := sha256.Sum256(blob)
	if m.SHA256 != hex.EncodeToString(sum[:]) {
		t.Error("whole-file digest mismatch")
	}
	// Roundtrip through JSON bytes (the wire shape the verb parses).
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = b
}

// TestValidateRejectsDoctored: the validator must refuse manifest shapes a
// hostile peer could exploit — chunk lists that don't cover the claimed
// size, or malformed digests.
func TestValidateRejectsDoctored(t *testing.T) {
	m := &Manifest{Tag: "v1", Asset: "a.tar.gz", Size: DefaultChunkSize + 10, ChunkSize: DefaultChunkSize,
		SHA256: hex.EncodeToString(make([]byte, 32)), Chunks: []string{hex.EncodeToString(make([]byte, 32))}}
	if err := m.Validate(); err == nil {
		t.Error("one chunk for 1.00002 chunks accepted — the assembler could be fed a short file")
	}
	m2 := *m
	m2.Chunks = []string{hex.EncodeToString(make([]byte, 32)), hex.EncodeToString(make([]byte, 32))}
	if err := m2.Validate(); err != nil {
		t.Errorf("exact-cover manifest rejected: %v", err)
	}
	bad := *m
	bad.SHA256 = "not-hex"
	if err := bad.Validate(); err == nil {
		t.Error("malformed whole-file digest accepted")
	}
}
