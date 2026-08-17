// lifecycle_seedfile_test.go — the @keyfile seed spec behind every seed
// flag (audit F5): "@/path" and the same hex typed inline must resolve to
// the SAME keypair, so the ps-safe file form is a drop-in everywhere
// (-signer-seed, -new-owner-seed, -new-seed, -recovery-seeds entries).
package cli

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestSeedKeypairAtFileMatchesHex(t *testing.T) {
	kp := mustTestKeypair(t)
	hexSeed := hex.EncodeToString(kp.Seed())

	p := filepath.Join(t.TempDir(), "owner.key")
	if err := os.WriteFile(p, []byte(hexSeed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := seedKeypair("@"+p, "-test")
	if err != nil {
		t.Fatalf("@file spec: %v", err)
	}
	direct, err := seedKeypair(hexSeed, "-test")
	if err != nil {
		t.Fatalf("hex spec: %v", err)
	}
	if !bytes.Equal(fromFile.Public(), kp.Public()) {
		t.Error("@file spec resolved to a different key than the seed file holds")
	}
	if !bytes.Equal(direct.Public(), kp.Public()) {
		t.Error("hex spec resolved to a different key")
	}
	msg := []byte("spec equivalence probe")
	if !bytes.Equal(fromFile.Sign(msg), direct.Sign(msg)) {
		t.Error("@file and hex specs must yield identical keypairs (signatures differ)")
	}
}
