// save_atomic_test.go — locks Save's durability invariants (audit F2/F3):
// the write is temp+rename, so a pre-existing keyfile with loose
// permissions is REPLACED by a fresh 0600 file (an in-place os.WriteFile
// would keep the old mode), no temp files survive a save, and both
// on-disk forms still round-trip through Load.
package keychain

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestSaveReplacesLoosePermissions: overwriting a 0644 keyfile must end
// at 0600 — os.WriteFile's mode applies only at creation, the atomic
// rename sidesteps that by always installing the fresh 0600 temp file.
func TestSaveReplacesLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "alice.key")
	if err := os.WriteFile(p, []byte("stale-bytes-that-must-not-survive\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	kp := mustKP(t)
	if err := Save(p, kp, ""); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("overwritten keyfile mode = %o, want 0600", st.Mode().Perm())
	}
	got, err := Load(p, "")
	if err != nil || !bytes.Equal(got.Public(), kp.Public()) {
		t.Fatalf("reload after overwrite: %v (key preserved: %v)", err, bytes.Equal(got.Public(), kp.Public()))
	}
	if b := mustReadFile(t, p); string(b) == "stale-bytes-that-must-not-survive\n" {
		t.Fatal("stale content survived the save")
	}
}

// TestSaveLeavesNoTempFiles: after successful saves (fresh and overwrite,
// both on-disk forms) the directory holds exactly the keyfile — no *.tmp
// litter from the atomic dance.
func TestSaveLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "alice.key")
	if err := Save(p, mustKP(t), ""); err != nil {
		t.Fatal(err)
	}
	if err := Save(p, mustKP(t), "a passphrase"); err != nil { // overwrite path too
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "alice.key" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("dir after save = %v, want exactly [alice.key] (no temp leftovers)", names)
	}
}

// TestSaveAtomicRoundTripBothForms: content written over an existing file
// stays readable back through Load in the plaintext AND the FREENSK1
// encrypted form.
func TestSaveAtomicRoundTripBothForms(t *testing.T) {
	dir := t.TempDir()
	kp := mustKP(t)

	plain := filepath.Join(dir, "plain.key")
	if err := os.WriteFile(plain, []byte("old contents\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Save(plain, kp, ""); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(plain, ""); err != nil || !bytes.Equal(got.Public(), kp.Public()) {
		t.Fatalf("plaintext round trip: %v", err)
	}
	if IsEncryptedPath(plain) {
		t.Error("plaintext save reported encrypted")
	}

	enc := filepath.Join(dir, "enc.key")
	if err := os.WriteFile(enc, []byte("old contents\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Save(enc, kp, "hunter2"); err != nil {
		t.Fatal(err)
	}
	if !IsEncryptedPath(enc) {
		t.Fatal("encrypted save reported plaintext")
	}
	if got, err := Load(enc, "hunter2"); err != nil || !bytes.Equal(got.Public(), kp.Public()) {
		t.Fatalf("encrypted round trip: %v", err)
	}
	if _, err := Load(enc, ""); !os.IsNotExist(err) && err == nil {
		t.Error("encrypted file loaded with an empty passphrase")
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
