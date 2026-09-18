package dht

// blobtcp_test.go — the TCP blob channel: whole-file streaming with the
// token gate, range clamping, and the abuse ceilings (per-IP/global conn
// caps are enforced at accept; here we prove the protocol + auth).

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"os"
	"testing"
	"time"
)

func TestBlobTCPRoundtripAndGate(t *testing.T) {
	dir := t.TempDir()
	bc, err := NewBlobCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, 300_000) // spans multiple 48 KiB reads
	if _, err := rand.Read(blob); err != nil {
		t.Fatal(err)
	}
	p := dir + "/src.tar.gz"
	if err := writeFile(p, blob); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(blob)
	bc.Store(sum[:], p)

	srv := startBlobNode(t, bc)
	tcpCtx, tcpCancel := context.WithCancel(context.Background())
	defer tcpCancel()
	if err := srv.StartBlobTCP(tcpCtx, "127.0.0.1:0"); err != nil {
		t.Fatalf("StartBlobTCP: %v", err)
	}
	tcpPort := srv.BlobTCPAddr() // the TCP channel binds its own ephemeral port
	client := startFlagTestNode(t, false)

	// A token minted for the CLIENT's address (the UDP path does this).
	token := srv.tokens.Issue([]byte{127, 0, 0, 1})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Whole-blob stream.
	r, total, err := client.BlobTCPGet(ctx, tcpPeerOf(t, srv, tcpPort), token, sum[:], 0, uint64(len(blob)))
	if err != nil {
		t.Fatalf("BlobTCPGet: %v", err)
	}
	got, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if total != int64(len(blob)) || len(got) != len(blob) || !bytes.Equal(got, blob) {
		t.Fatalf("streamed %d/%d bytes, mismatch=%v", len(got), total, !bytes.Equal(got, blob))
	}

	// Mid-file range with clamping (range past EOF).
	r, total, err = client.BlobTCPGet(ctx, tcpPeerOf(t, srv, tcpPort), token, sum[:], uint64(len(blob)-100), 1<<20)
	if err != nil {
		t.Fatalf("BlobGet range: %v", err)
	}
	got, err = io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatalf("read range: %v", err)
	}
	if len(got) != 100 || !bytes.Equal(got, blob[len(blob)-100:]) {
		t.Fatalf("range = %d bytes, want the 100-byte tail", len(got))
	}

	// Token gate: a bogus token gets refused (no bytes).
	bad := append([]byte("x"), token[1:]...)
	if _, _, err := client.BlobTCPGet(ctx, tcpPeerOf(t, srv, tcpPort), bad, sum[:], 0, 10); err == nil {
		t.Fatal("bogus token accepted — the bulk channel must stay gated")
	}
}

func writeFile(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }

// tcpPeerOf builds a Peer pointing at srv's TCP blob listener (the
// production client dials the DHT port number over TCP; the test binds :0
// and uses the listener's actual port).
func tcpPeerOf(t *testing.T, srv *Node, tcpAddr string) Peer {
	t.Helper()
	p := peerOf(t, srv)
	p.Addr = tcpAddr
	return p
}
