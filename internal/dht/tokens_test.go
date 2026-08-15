package dht

import (
	"bytes"
	"testing"

	"github.com/camalolo/freens/internal/constants"
)

// newTestTokenStore builds a TokenStore whose clock reads `initial` seconds,
// returning the store and a mutator that advances the clock.
func newTestTokenStore(t *testing.T, rootSecret []byte, initial int64) (*TokenStore, *int64) {
	t.Helper()
	clock := initial
	ts, err := NewTokenStore(constants.TokenRotation, rootSecret, func() int64 { return clock })
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	return ts, &clock
}

func TestNewTokenStoreValidation(t *testing.T) {
	t.Parallel()

	secret := bytes.Repeat([]byte{0x01}, 32)

	if _, err := NewTokenStore(0, secret, nil); err == nil {
		t.Fatal("NewTokenStore(rotation=0) want error, got nil")
	}
	if _, err := NewTokenStore(-1, secret, nil); err == nil {
		t.Fatal("NewTokenStore(rotation=-1) want error, got nil")
	}
	if _, err := NewTokenStore(300, make([]byte, 15), nil); err == nil {
		t.Fatal("NewTokenStore(root_secret=15 bytes) want error, got nil")
	}
	// nil nowFn is allowed (defaults to time.Now().Unix()).
	ts, err := NewTokenStore(300, secret, nil)
	if err != nil {
		t.Fatalf("NewTokenStore(nil nowFn) unexpected error: %v", err)
	}
	if ts == nil {
		t.Fatal("NewTokenStore(nil nowFn) returned nil store")
	}
}

func TestEpoch(t *testing.T) {
	t.Parallel()

	ts, _ := newTestTokenStore(t, bytes.Repeat([]byte{'k'}, 32), 0)
	if got := ts.Epoch(1000); got != 3 {
		t.Fatalf("Epoch(1000) = %d, want 3", got)
	}
	if got := ts.Epoch(0); got != 0 {
		t.Fatalf("Epoch(0) = %d, want 0", got)
	}
	if got := ts.Epoch(299); got != 0 {
		t.Fatalf("Epoch(299) = %d, want 0", got)
	}
	if got := ts.Epoch(300); got != 1 {
		t.Fatalf("Epoch(300) = %d, want 1", got)
	}
	if got := ts.Epoch(1199); got != 3 {
		t.Fatalf("Epoch(1199) = %d, want 3", got)
	}
	if got := ts.Epoch(1200); got != 4 {
		t.Fatalf("Epoch(1200) = %d, want 4", got)
	}
}

func TestIssueShapeAndDeterminism(t *testing.T) {
	t.Parallel()

	root := bytes.Repeat([]byte{'k'}, 32)
	peer := []byte("1.2.3.4")

	ts1, c1 := newTestTokenStore(t, root, 1000)
	ts2, _ := newTestTokenStore(t, root, 1000)

	tok1 := ts1.Issue(peer)
	tok2 := ts2.Issue(peer)

	// Every issued token is exactly 32 bytes (SHA-256 digest length).
	if len(tok1) != constants.SHA256Len {
		t.Fatalf("Issue returned %d bytes, want %d", len(tok1), constants.SHA256Len)
	}
	// Deterministic: same root + same peer + same time => same token.
	if !bytes.Equal(tok1, tok2) {
		t.Fatalf("Issue not deterministic: %x vs %x", tok1, tok2)
	}

	// Different peer => different token.
	otherPeer := []byte("5.6.7.8")
	tokOther := ts1.Issue(otherPeer)
	if bytes.Equal(tok1, tokOther) {
		t.Fatal("Issue produced identical tokens for different peers")
	}

	// Different root secret => different token.
	ts3, _ := newTestTokenStore(t, bytes.Repeat([]byte{'z'}, 32), 1000)
	tokOtherSecret := ts3.Issue(peer)
	if bytes.Equal(tok1, tokOtherSecret) {
		t.Fatal("Issue produced identical tokens under different root secrets")
	}

	// Sanity: changing the clock to a new epoch changes the issued token.
	*c1 = 1300 // epoch 4
	tokEpoch4 := ts1.Issue(peer)
	if bytes.Equal(tok1, tokEpoch4) {
		t.Fatal("Issue produced identical tokens across different epochs")
	}
}

func TestVerifyWindow(t *testing.T) {
	t.Parallel()

	root := bytes.Repeat([]byte{'k'}, 32)
	peer := []byte("10.0.0.1")

	// Issue at clock=1000 (rotation 300 => epoch 3).
	ts, clock := newTestTokenStore(t, root, 1000)
	token := ts.Issue(peer)
	if len(token) != constants.SHA256Len {
		t.Fatalf("Issue returned %d bytes, want %d", len(token), constants.SHA256Len)
	}

	// Verifies at the issue time (epoch 3).
	*clock = 1000
	if !ts.Verify(peer, token, 1) {
		t.Fatal("Verify at 1000 (current epoch) want true, got false")
	}

	// Verifies at 1199 (still epoch 3, current).
	*clock = 1199
	if !ts.Verify(peer, token, 1) {
		t.Fatal("Verify at 1199 (current epoch) want true, got false")
	}

	// Verifies at 1300 (epoch 4; tolerance 1 covers epoch 3 as previous).
	*clock = 1300
	if !ts.Verify(peer, token, 1) {
		t.Fatal("Verify at 1300 (previous epoch, tolerance=1) want true, got false")
	}

	// Does NOT verify at 1600 (epoch 5; tolerance 1 covers only 5 and 4).
	*clock = 1600
	if ts.Verify(peer, token, 1) {
		t.Fatal("Verify at 1600 (epoch 5, tolerance=1) want false, got true")
	}
}

func TestVerifyToleranceZero(t *testing.T) {
	t.Parallel()

	root := bytes.Repeat([]byte{'k'}, 32)
	peer := []byte("10.0.0.2")

	ts, clock := newTestTokenStore(t, root, 1000) // epoch 3
	token := ts.Issue(peer)

	// tolerance=0: only the current epoch is honoured.
	*clock = 1000
	if !ts.Verify(peer, token, 0) {
		t.Fatal("Verify at 1000 tolerance=0 (current epoch) want true, got false")
	}

	// One epoch later (epoch 4), tolerance=0 must reject the epoch-3 token.
	*clock = 1300
	if ts.Verify(peer, token, 0) {
		t.Fatal("Verify at 1300 tolerance=0 want false, got true")
	}
}

func TestVerifyRejectsBadInput(t *testing.T) {
	t.Parallel()

	root := bytes.Repeat([]byte{'k'}, 32)
	peer := []byte("10.0.0.3")
	ts, clock := newTestTokenStore(t, root, 1000)
	token := ts.Issue(peer)

	*clock = 1000

	// Wrong peer => false.
	if ts.Verify([]byte("99.99.99.99"), token, 1) {
		t.Fatal("Verify(wrong peer) want false, got true")
	}

	// Bad token bytes (right length, wrong content) => false.
	bad := make([]byte, constants.SHA256Len)
	bad[0] = 0xff
	if ts.Verify(peer, bad, 1) {
		t.Fatal("Verify(bad token) want false, got true")
	}

	// Wrong token length => false.
	if ts.Verify(peer, make([]byte, 31), 1) {
		t.Fatal("Verify(31-byte token) want false, got true")
	}
	if ts.Verify(peer, make([]byte, 33), 1) {
		t.Fatal("Verify(33-byte token) want false, got true")
	}

	// Negative tolerance => false.
	if ts.Verify(peer, token, -1) {
		t.Fatal("Verify(tolerance=-1) want false, got true")
	}
}

func TestCurrentAndPreviousSecret(t *testing.T) {
	t.Parallel()

	root := bytes.Repeat([]byte{'k'}, 32)
	ts, _ := newTestTokenStore(t, root, 0)

	cur := ts.CurrentSecret(1300)     // epoch 4
	prev := ts.PreviousSecret(1300)   // epoch 3
	earlier := ts.CurrentSecret(1000) // epoch 3
	if bytes.Equal(cur, prev) {
		t.Fatal("CurrentSecret(1300) == PreviousSecret(1300); want distinct")
	}
	if !bytes.Equal(prev, earlier) {
		t.Fatal("PreviousSecret(1300) != CurrentSecret(1000); want equal (both epoch 3)")
	}
	// Secrets are 32 bytes.
	if len(cur) != constants.SHA256Len || len(prev) != constants.SHA256Len {
		t.Fatalf("secret length = %d/%d, want %d", len(cur), len(prev), constants.SHA256Len)
	}
}
