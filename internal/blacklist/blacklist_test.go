package blacklist

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecordFlagsImmediatelyAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blacklist.json")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	id[0] = 7
	if flagged := l.Flagged(id); flagged {
		t.Fatal("stranger flagged before any violation")
	}
	ok, err := l.Record(id, ClassWrongSlice, "chunk 12 hash mismatch", []byte("bad bytes"))
	if err != nil || !ok {
		t.Fatalf("Record = %v, %v", ok, err)
	}
	if !l.Flagged(id) {
		t.Fatal("proven violation did not flag")
	}
	// Proof hash is recorded, not the bytes.
	entries := l.Entries()
	if len(entries) != 1 || entries[0].Violations[0].Proof == "" {
		t.Fatalf("entries = %+v", entries)
	}
	if entries[0].Violations[0].Proof == "bad bytes" {
		t.Fatal("proof stored raw — must be a hash")
	}
	// Persistence: a fresh ledger over the same file keeps the flag.
	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !l2.Flagged(id) {
		t.Fatal("flag did not survive reopen")
	}
}

func TestTTLDecayAndRearm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blacklist.json")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	id[1] = 9
	if _, err := l.Record(id, ClassBadPoW, "nonce fails verify", nil); err != nil {
		t.Fatal(err)
	}
	// Age the entry past the TTL directly (24 h is not a test timescale).
	l.mu.Lock()
	e := l.entries[stringOrID(id)]
	e.ExpiresAt = time.Now().Add(-time.Second)
	l.mu.Unlock()
	if l.Flagged(id) {
		t.Fatal("expired flag still enforced")
	}
	if entries := l.Entries(); len(entries) != 0 {
		t.Fatalf("expired entry survived Entries(): %+v", entries)
	}
	// Re-violation re-arms.
	if _, err := l.Record(id, ClassBadPoW, "again", nil); err != nil {
		t.Fatal(err)
	}
	if !l.Flagged(id) {
		t.Fatal("re-violation did not re-arm")
	}
}

func TestRemove(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "blacklist.json"))
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	id[2] = 1
	_, _ = l.Record(id, ClassReservedClaim, "com", nil)
	if !l.Remove(hexOf(t, id)) || l.Flagged(id) {
		t.Fatal("Remove did not clear the flag")
	}
	if l.Remove(hexOf(t, id)) {
		t.Fatal("Remove twice reported success")
	}
}

func TestNilLedgerIsInert(t *testing.T) {
	var l *Ledger
	id := make([]byte, 32)
	if ok, _ := l.Record(id, ClassWrongSlice, "x", nil); ok {
		t.Fatal("nil ledger recorded")
	}
	if l.Flagged(id) || len(l.Entries()) != 0 || l.Remove("x") {
		t.Fatal("nil ledger not inert")
	}
}

func TestShortIDRefused(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "blacklist.json"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := l.Record([]byte("short"), ClassWrongSlice, "x", nil); ok || err == nil {
		t.Fatal("short node id accepted")
	}
}

// stringOrID adapts the test's []byte key to the map key used by Record
// (hex string).
func stringOrID(id []byte) string { return hexKey(id) }

func hexOf(t *testing.T, id []byte) string {
	t.Helper()
	return hexKey(id)
}

func hexKey(id []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(id)*2)
	for _, b := range id {
		out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(out)
}

// guard: the ledger file must not be world-readable (it names accused peers).
func TestFilePerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blacklist.json")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := l.Record(id, ClassBadEnvelope, "x", []byte("env")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("ledger perms too open: %v", info.Mode().Perm())
	}
}
