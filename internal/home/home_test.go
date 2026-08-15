package home

// home_test.go — state-directory tests: seeds.conf parsing/creation and the
// learned-peerbook round trip (including the 32-entry cap). Every test
// redirects FREENS_HOME to a throwaway directory so nothing touches the
// developer's real ~/.freens.

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/laurent/freens/internal/dht"
)

// testPK returns a deterministic 32-byte public key for index i (hex chars
// '0'+i are valid hex; the exact value is irrelevant to the round trip).
func testPK(i int) []byte {
	pk := make([]byte, 32)
	for j := range pk {
		pk[j] = byte('a' + (i+j)%26)
	}
	return pk
}

func TestParseSeedsGoodBadAndComments(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FREENS_HOME", dir)
	path := filepath.Join(dir, "seeds.conf")
	content := `# full-line comment

freens.camalolo.com:15353#780494a338d831d94b371c9a1d9351885753df071ba4e60e23283282d33fe2c7
203.0.113.7:15353#0000000000000000000000000000000000000000000000000000000000000000

no-hash-separator.example:15353
203.0.113.8#not-hex!
203.0.113.9:15353#deadbeef
:no-port#` + strings.Repeat("ab", 32) + `
203.0.113.10:0#` + strings.Repeat("cd", 32) + `
  203.0.113.11:15354#` + strings.Repeat("ef", 32) + `  ` + "\n" +
		"#trailing comment\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write seeds: %v", err)
	}
	peers := ParseSeeds(path)
	if len(peers) != 3 {
		t.Fatalf("ParseSeeds returned %d peers, want 3: %+v", len(peers), peers)
	}
	// The pinned seed, byte for byte.
	seedPK, err := hex.DecodeString("780494a338d831d94b371c9a1d9351885753df071ba4e60e23283282d33fe2c7")
	if err != nil {
		t.Fatalf("decode pinned seed pk: %v", err)
	}
	if peers[0].Addr != "freens.camalolo.com:15353" || !bytes.Equal(peers[0].PublicKey, seedPK) {
		t.Errorf("peers[0] = %+v, want the pinned seed entry", peers[0])
	}
	if peers[1].Addr != "203.0.113.7:15353" {
		t.Errorf("peers[1].Addr = %q, want 203.0.113.7:15353", peers[1].Addr)
	}
	// The padded/space-wrapped line must have been TrimSpace'd into shape.
	if peers[2].Addr != "203.0.113.11:15354" {
		t.Errorf("peers[2].Addr = %q, want 203.0.113.11:15354", peers[2].Addr)
	}
}

func TestParseSeedsAbsentFile(t *testing.T) {
	t.Setenv("FREENS_HOME", t.TempDir())
	if peers := ParseSeeds(SeedsPath()); peers != nil {
		t.Fatalf("ParseSeeds on missing file = %+v, want nil", peers)
	}
}

func TestEnsureSeedsIdempotent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FREENS_HOME", dir)

	if err := EnsureSeeds(); err != nil {
		t.Fatalf("EnsureSeeds (first): %v", err)
	}
	b, err := os.ReadFile(SeedsPath())
	if err != nil {
		t.Fatalf("read seeds.conf: %v", err)
	}
	if string(b) != DefaultSeeds() {
		t.Fatalf("first EnsureSeeds wrote %q, want DefaultSeeds()", string(b))
	}
	fi, err := os.Stat(SeedsPath())
	if err != nil {
		t.Fatalf("stat seeds.conf: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("seeds.conf mode = %o, want 0600", fi.Mode().Perm())
	}

	// Operator edit: the second call must NOT overwrite an existing file.
	custom := "# my network only\n203.0.113.1:15353#" + strings.Repeat("11", 32) + "\n"
	if err := os.WriteFile(SeedsPath(), []byte(custom), 0o600); err != nil {
		t.Fatalf("write custom seeds: %v", err)
	}
	if err := EnsureSeeds(); err != nil {
		t.Fatalf("EnsureSeeds (second): %v", err)
	}
	b, _ = os.ReadFile(SeedsPath())
	if string(b) != custom {
		t.Fatalf("EnsureSeeds overwrote an existing seeds.conf (%q)", string(b))
	}
}

func TestPeerbookRoundTripAndTruncation(t *testing.T) {
	t.Setenv("FREENS_HOME", t.TempDir())

	// 40 peers: SavePeerbook must cap at 32, LoadPeerbook must return
	// exactly those 32 with addr+pk intact (first 32 in input order).
	var in []dht.Peer
	for i := 0; i < 40; i++ {
		in = append(in, dht.Peer{
			Addr:      "10.1." + strconv.Itoa(i/10) + "." + strconv.Itoa(1+i%9) + ":15353",
			PublicKey: testPK(i),
		})
	}
	if err := SavePeerbook(in, time.Now().Unix()); err != nil {
		t.Fatalf("SavePeerbook: %v", err)
	}
	out := LoadPeerbook()
	if len(out) != 32 {
		t.Fatalf("LoadPeerbook returned %d peers, want 32 (cap)", len(out))
	}
	for i := range out {
		if out[i].Addr != in[i].Addr {
			t.Errorf("out[%d].Addr = %q, want %q", i, out[i].Addr, in[i].Addr)
		}
		if string(out[i].PublicKey) != string(in[i].PublicKey) {
			t.Errorf("out[%d].PublicKey mismatch", i)
		}
	}
}

func TestPeerbookBestEffort(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FREENS_HOME", dir)

	if peers := LoadPeerbook(); peers != nil {
		t.Fatalf("LoadPeerbook on missing file = %+v, want nil", peers)
	}

	// Corrupt JSON: nil, not an error (callers fall back to seeds).
	book := filepath.Join(PeersDir(), "book.json")
	if err := os.MkdirAll(PeersDir(), 0o700); err != nil {
		t.Fatalf("mkdir peers: %v", err)
	}
	if err := os.WriteFile(book, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt book: %v", err)
	}
	if peers := LoadPeerbook(); peers != nil {
		t.Fatalf("LoadPeerbook on corrupt file = %+v, want nil", peers)
	}
}

func TestContactsToPeers(t *testing.T) {
	t.Setenv("FREENS_HOME", t.TempDir())

	goodPK := testPK(3)
	contacts := []*dht.NodeContact{
		{NodeID: testPK(1), PublicKey: append([]byte(nil), goodPK...), Addr: "203.0.113.2:15353", LastSeen: 1},
		nil, // skipped
		{NodeID: testPK(2), PublicKey: nil, Addr: "x:1"},             // bad key: skipped
		{NodeID: testPK(3), PublicKey: goodPK, Addr: ""},             // no addr: skipped
		{NodeID: testPK(4), PublicKey: []byte("short"), Addr: "y:2"}, // bad key: skipped
	}
	peers := ContactsToPeers(contacts)
	if len(peers) != 1 {
		t.Fatalf("ContactsToPeers returned %d peers, want 1: %+v", len(peers), peers)
	}
	if peers[0].Addr != "203.0.113.2:15353" || string(peers[0].PublicKey) != string(goodPK) {
		t.Fatalf("ContactsToPeers = %+v, want the one well-formed contact", peers[0])
	}
	// Copy semantics: mutating the source contact's key must not affect it.
	contacts[0].PublicKey[0] ^= 0xff
	if peers[0].PublicKey[0] == contacts[0].PublicKey[0] {
		t.Fatal("ContactsToPeers aliased the contact's key bytes")
	}

	// End-to-end: contacts -> peers -> SavePeerbook -> LoadPeerbook keeps
	// the PUBLIC KEY (what AddPeer needs), not the Node ID.
	if err := SavePeerbook(peers, 1); err != nil {
		t.Fatalf("SavePeerbook: %v", err)
	}
	back := LoadPeerbook()
	if len(back) != 1 || string(back[0].PublicKey) != string(goodPK) || back[0].Addr != "203.0.113.2:15353" {
		t.Fatalf("round trip = %+v, want addr+public key preserved", back)
	}
}
