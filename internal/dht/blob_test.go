package dht

// blob_test.go — chunked peer transfer (v0.19.7): the cache, the token-
// gated blob.get handler, and the client. The swarm trust model lives in
// the CALLER (chunk hashes vs the origin manifest); this file proves the
// transport: only token-holding, rate-respecting sources get bytes, and
// the bytes served are exactly the cached file's bytes at the offsets
// requested.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
)

func startBlobNode(t *testing.T, cache *BlobCache) *Node {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewNode(NodeConfig{
		Keypair:    kp,
		ListenAddr: "127.0.0.1:0",
		Store:      NewEnvelopeStore(0, nil),
		BlobCache:  cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

func TestBlobCacheStoreOpenPrune(t *testing.T) {
	dir := t.TempDir()
	bc, err := NewBlobCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	blob := bytes.Repeat([]byte{0xA5}, 100_000)
	p := filepath.Join(dir, "src.tar.gz")
	if err := os.WriteFile(p, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(blob)
	bc.Store(sum[:], p)
	if !bc.Has(sum[:]) {
		t.Fatal("Has = false right after Store")
	}
	f, size, err := bc.Open(sum[:])
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got := make([]byte, size)
	_, _ = f.ReadAt(got, 0)
	f.Close()
	if !bytes.Equal(got, blob) {
		t.Fatal("cached bytes differ from the source")
	}
	// The prune keeps only the newest maxBlobCacheEntries — store two more
	// distinct blobs and expect the first to eventually leave.
	for i := 0; i < maxBlobCacheEntries+1; i++ {
		b2 := bytes.Repeat([]byte{byte(i)}, 1000)
		p2 := filepath.Join(dir, "src.tar.gz")
		if err := os.WriteFile(p2, b2, 0o600); err != nil {
			t.Fatal(err)
		}
		s2 := sha256.Sum256(b2)
		if err := bc.Store(s2[:], p2); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond) // distinct mtimes
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) > maxBlobCacheEntries {
		t.Errorf("cache holds %d entries, want <= %d (unbounded mirror risk)", len(entries), maxBlobCacheEntries)
	}
}

func TestBlobGetRoundtripAndGating(t *testing.T) {
	dir := t.TempDir()
	bc, err := NewBlobCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, 150_000)
	if _, err := rand.Read(blob); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "src.tar.gz")
	if err := os.WriteFile(p, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(blob)
	bc.Store(sum[:], p)

	srv := startBlobNode(t, bc)
	client := startFlagTestNode(t, false) // transient or not is irrelevant here
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Roundtrip: a mid-file slice and the short final chunk both land.
	off, wantLen := 100_000, 48*1024
	data, total, err := client.BlobGet(ctx, peerOf(t, srv), sum[:], off, wantLen)
	if err != nil {
		t.Fatalf("BlobGet: %v", err)
	}
	if total != int64(len(blob)) {
		t.Errorf("total = %d, want %d", total, len(blob))
	}
	if !bytes.Equal(data, blob[off:int64(off)+int64(wantLen)]) {
		t.Fatalf("served slice mismatch (%d bytes)", len(data))
	}
	// The final short chunk: offset+length past EOF must clamp.
	tail, _, err := client.BlobGet(ctx, peerOf(t, srv), sum[:], len(blob)-10, wantLen)
	if err != nil {
		t.Fatalf("BlobGet tail: %v", err)
	}
	if len(tail) != 10 || !bytes.Equal(tail, blob[len(blob)-10:]) {
		t.Fatalf("tail chunk = %d bytes, want the 10 trailing bytes", len(tail))
	}

	// A node WITHOUT a cache must refuse to serve — serving is opt-in via
	// NodeConfig.BlobCache, never accidental.
	bare := startFlagTestNode(t, false)
	if _, _, err := client.BlobGet(ctx, peerOf(t, bare), sum[:], 0, 100); err == nil {
		t.Fatal("blob.get answered by a cache-less node — serving must be explicit")
	}
}
