package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReplacesAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := Write(path, []byte("v1"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "v1" {
		t.Fatalf("read back: %q, %v", got, err)
	}

	// Replace: new bytes win, mode is enforced even over a looser file.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("v2"), 0o600); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, err = os.ReadFile(path)
	if err != nil || string(got) != "v2" {
		t.Fatalf("read back: %q, %v", got, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %v, want 0600 (enforced over looser existing file)", fi.Mode().Perm())
	}

	// Creates missing parent dirs; no temp litter left behind.
	nested := filepath.Join(dir, "a", "b", "c.bin")
	if err := Write(nested, []byte("x"), 0o600); err != nil {
		t.Fatalf("nested write: %v", err)
	}
	ents, err := os.ReadDir(filepath.Dir(nested))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("temp litter left behind: %s", e.Name())
		}
	}
}

func TestWriteEmptyPath(t *testing.T) {
	if err := Write("", []byte("x"), 0o600); err == nil {
		t.Fatal("empty path: want error")
	}
}
