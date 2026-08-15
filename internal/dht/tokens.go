// Package dht — tokens.go implements the rotating HMAC-SHA256 write-token
// issuer/verifier described in specifications.md §6.3 ("Write tokens",
// spec lines 453-458): before a peer may put a record onto this node it must
// first obtain a write token via a prior get/ping exchange. A token is
//
//	token = HMAC-SHA256(secret_for_epoch, peer_ip)
//
// where secret_for_epoch is derived per-epoch from a long-lived root secret
// and the current epoch number (HMAC-SHA256(root_secret, str(epoch))). Epochs
// advance every rotationSeconds seconds (constants.TokenRotation = 300s). A
// token remains valid for the current epoch and the previous
// toleranceEpochs epochs, so a token minted moments before an epoch boundary
// is still honoured after the rotation.
//
// This file ports archive/python-v0.1/freens/dht/tokens.py. Only the Go
// standard library is used (crypto/hmac, crypto/sha256, strconv, time).
package dht

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/camalolo/freens/internal/constants"
)

// minRootSecretLen is the minimum acceptable root-secret length. The Python
// reference requires >= 16 bytes; shorter secrets are rejected at construction
// time.
const minRootSecretLen = 16

// TokenStore is the rotating HMAC-SHA256 write-token issuer/verifier. The
// root secret never appears directly in any issued token; only per-epoch
// derived secrets are used, so leaking one epoch's tokens does not compromise
// other epochs.
type TokenStore struct {
	rotationSeconds int
	rootSecret      []byte // copied; never aliased to caller memory
	nowFn           func() int64
}

// NewTokenStore constructs a TokenStore. rotationSeconds must be > 0;
// rootSecret must be at least minRootSecretLen (16) bytes; nowFn supplies the
// clock used by Issue/Verify (default time.Now().Unix() when nil).
func NewTokenStore(rotationSeconds int, rootSecret []byte, nowFn func() int64) (*TokenStore, error) {
	if rotationSeconds <= 0 {
		return nil, errors.New("dht: rotation must be > 0")
	}
	if len(rootSecret) < minRootSecretLen {
		return nil, fmt.Errorf("dht: root_secret too short (min %d bytes, got %d)", minRootSecretLen, len(rootSecret))
	}
	clock := nowFn
	if clock == nil {
		clock = func() int64 { return time.Now().Unix() }
	}
	secret := make([]byte, len(rootSecret))
	copy(secret, rootSecret)
	return &TokenStore{
		rotationSeconds: rotationSeconds,
		rootSecret:      secret,
		nowFn:           clock,
	}, nil
}

// Epoch returns the rotation epoch number floor(now / rotation). For the
// default rotation of 300 and now=1000 this is floor(1000/300) == 3 (epoch 3
// spans the half-open interval [900, 1200)).
func (ts *TokenStore) Epoch(now int64) int {
	return int(now / int64(ts.rotationSeconds))
}

// secretForEpoch derives the per-epoch HMAC key:
// HMAC-SHA256(rootSecret, strconv.Itoa(epoch)). It is the Go analogue of
// tokens._secret_for_epoch in the Python reference.
func (ts *TokenStore) secretForEpoch(epoch int) []byte {
	mac := hmac.New(sha256.New, ts.rootSecret)
	mac.Write([]byte(strconv.Itoa(epoch)))
	return mac.Sum(nil)
}

// CurrentSecret returns the active epoch's secret (diagnostic; do not
// transmit).
func (ts *TokenStore) CurrentSecret(now int64) []byte {
	return ts.secretForEpoch(ts.Epoch(now))
}

// PreviousSecret returns the previous epoch's secret (diagnostic; do not
// transmit).
func (ts *TokenStore) PreviousSecret(now int64) []byte {
	return ts.secretForEpoch(ts.Epoch(now) - 1)
}

// Issue returns token = HMAC-SHA256(secretForCurrentEpoch, peerIP) — exactly
// constants.SHA256Len (32) bytes. The current epoch is read from the injected
// clock. Issue is strict about the epoch derivation but lenient about an
// empty/nil peerIP (it simply mints a token over the empty byte slice); the
// caller is expected to supply a real peer identity.
func (ts *TokenStore) Issue(peerIP []byte) []byte {
	secret := ts.secretForEpoch(ts.Epoch(ts.nowFn()))
	mac := hmac.New(sha256.New, secret)
	mac.Write(peerIP)
	return mac.Sum(nil)
}

// Verify reports whether token matches the HMAC under the current epoch's
// secret or any of the previous toleranceEpochs epochs' secrets. Comparison
// is constant-time (crypto/hmac.Equal). Verify is deliberately lenient: any
// malformed input (wrong token length, negative tolerance) yields false
// rather than an error, since verification handles untrusted wire data.
//
// With the default tolerance of 1 this honours exactly the spec's "current
// and previous rotation" rule: off=0 tests the current epoch, off=1 the
// previous one.
func (ts *TokenStore) Verify(peerIP, token []byte, toleranceEpochs int) bool {
	if len(token) != constants.SHA256Len {
		return false
	}
	if toleranceEpochs < 0 {
		return false
	}
	currentEpoch := ts.Epoch(ts.nowFn())
	for off := 0; off <= toleranceEpochs; off++ {
		candEpoch := currentEpoch - off
		secret := ts.secretForEpoch(candEpoch)
		candidate := hmac.New(sha256.New, secret)
		candidate.Write(peerIP)
		if hmac.Equal(candidate.Sum(nil), token) {
			return true
		}
	}
	return false
}
