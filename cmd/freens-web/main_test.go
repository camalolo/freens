// main_test.go — locks the leaf-SAN cap: the SAN list is fed from the
// daemon's envelope store (attacker-influenceable in size), so leafSANs
// must emit at most leafSANCap entries, chosen deterministically (sorted,
// first N) — the same store always mints the same certificate.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"testing"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/wire"
)

// storeFake is a Daemon that answers Store (everything else fails loudly —
// leafSANs only uses Store and the nil-daemon fast path).
type storeFake struct {
	entries []admin.StoreEntry
}

func (f *storeFake) Status(context.Context) (*admin.Status, error) {
	return nil, errors.New("not implemented")
}
func (f *storeFake) Peers(context.Context) ([]dht.Peer, error) {
	return nil, errors.New("not implemented")
}
func (f *storeFake) Resolve(context.Context, string) (*admin.Resolved, error) {
	return nil, errors.New("not implemented")
}
func (f *storeFake) Publish(context.Context, *wire.SignedEnvelope) (int, error) {
	return 0, errors.New("not implemented")
}
func (f *storeFake) PublishClaim(context.Context, *wire.SignedEnvelope) error {
	return errors.New("not implemented")
}
func (f *storeFake) Get(context.Context, []byte) (*wire.SignedEnvelope, error) {
	return nil, errors.New("not implemented")
}
func (f *storeFake) Witness(context.Context, string, []byte, []byte, uint64, []byte, []byte) ([][]byte, error) {
	return nil, errors.New("not implemented")
}
func (f *storeFake) Store(context.Context) (*admin.StoreResponse, error) {
	return &admin.StoreResponse{Entries: f.entries, Count: len(f.entries)}, nil
}
func (f *storeFake) Difficulty(context.Context) (*admin.Difficulty, error) {
	return nil, errors.New("not implemented")
}

// tldB32 encodes a public key the way the daemon's store rows carry it.
func tldB32(pk []byte) string {
	id, err := crypto.TldID(pk)
	if err != nil {
		panic(err)
	}
	return strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(id), "="))
}

func testKeypair(t *testing.T) *crypto.Keypair {
	t.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	kp, err := crypto.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func TestLeafSANsCapIsDeterministic(t *testing.T) {
	kp := testKeypair(t)
	want := tldB32(kp.Public())

	// leafSANCap + 30 subnames of OUR namespace (out of order on purpose),
	// plus 5 entries of a FOREIGN namespace that must never appear.
	fake := &storeFake{}
	for i := 0; i < leafSANCap+30; i++ {
		fake.entries = append(fake.entries, admin.StoreEntry{
			Labels:   []string{"host" + itoa(i)},
			TldIDB32: want,
		})
	}
	for i := 0; i < 5; i++ {
		fake.entries = append(fake.entries, admin.StoreEntry{
			Labels:   []string{"foreign" + itoa(i)},
			TldIDB32: tldB32(testKeypair(t).Public()),
		})
	}

	log := slog.Default()
	sans := leafSANs(fake, kp, "myalias", log)

	// Exactly apex + wildcard + leafSANCap subnames — the cap holds and the
	// foreign namespace never leaks in.
	if len(sans) != 2+leafSANCap {
		t.Fatalf("got %d SANs, want 2 + cap %d", len(sans), leafSANCap)
	}
	if sans[0] != "myalias" || sans[1] != "*.myalias" {
		t.Fatalf("first SANs = %q %q, want apex + wildcard", sans[0], sans[1])
	}
	subs := sans[2:]
	if !sort.StringsAreSorted(subs) {
		t.Error("subname SANs are not sorted (the cap pick must be deterministic)")
	}
	for _, s := range subs {
		if strings.Contains(s, "foreign") {
			t.Fatalf("foreign namespace leaked into the SAN list: %q", s)
		}
		if !strings.HasSuffix(s, ".myalias") {
			t.Fatalf("SAN %q does not belong to the namespace", s)
		}
	}

	// Determinism: the same store yields the identical list on re-mint.
	again := leafSANs(fake, kp, "myalias", log)
	if strings.Join(again, ",") != strings.Join(sans, ",") {
		t.Error("leafSANs not deterministic across calls on the same store")
	}
}

// TestLeafSANsSmallStoreAndNilDaemon: a modest store passes through in
// full; nil degrades to apex+wildcard.
func TestLeafSANsSmallStoreAndNilDaemon(t *testing.T) {
	kp := testKeypair(t)
	want := tldB32(kp.Public())
	fake := &storeFake{entries: []admin.StoreEntry{
		{Labels: []string{"b"}, TldIDB32: want},
		{Labels: []string{"a"}, TldIDB32: want},
		{Labels: []string{}, TldIDB32: want}, // apex row: no labels, skipped
	}}
	sans := leafSANs(fake, kp, "myalias", slog.Default())
	if len(sans) != 4 || sans[0] != "myalias" || sans[1] != "*.myalias" ||
		sans[2] != "a.myalias" || sans[3] != "b.myalias" {
		t.Fatalf("sans = %v, want apex+wildcard+2 sorted subnames", sans)
	}

	bare := leafSANs(nil, kp, "myalias", slog.Default())
	if len(bare) != 2 || bare[0] != "myalias" || bare[1] != "*.myalias" {
		t.Fatalf("sans(nil daemon) = %v, want apex+wildcard only", bare)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
