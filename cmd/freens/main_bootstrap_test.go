package main

// main_bootstrap_test.go — the pure bootstrap-source selection logic
// (peersFromSources) behind the zero-config bootstrap: explicit sources
// (-peers / -peers-file) win, otherwise home's seeds.conf + learned
// peerbook take over, and everything dedupes by (addr, public key). No
// daemon is spun up here — run() only delegates to this function.

import (
	"testing"

	"github.com/laurent/freens/internal/dht"
)

// mkPeer builds a bootstrap peer whose 32-byte key is the repeated key
// byte (distinct key byte ⇒ distinct peer for dedupe purposes).
func mkPeer(addr string, key byte) dht.Peer {
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = key
	}
	return dht.Peer{Addr: addr, PublicKey: pk}
}

func TestPeersFromSourcesExplicitWins(t *testing.T) {
	flag := []dht.Peer{mkPeer("203.0.113.1:15353", 0x01)}
	file := []dht.Peer{mkPeer("203.0.113.2:15353", 0x02)}
	seeds := []dht.Peer{mkPeer("198.51.100.1:15353", 0x03)}
	book := []dht.Peer{mkPeer("198.51.100.2:15353", 0x04)}

	got := peersFromSources(flag, file, seeds, book)
	if len(got) != 2 || got[0].Addr != "203.0.113.1:15353" || got[1].Addr != "203.0.113.2:15353" {
		t.Fatalf("explicit sources must win over home sources, got %+v", got)
	}

	// File alone also counts as "explicit".
	got = peersFromSources(nil, file, seeds, book)
	if len(got) != 1 || got[0].Addr != "203.0.113.2:15353" {
		t.Fatalf("file-only explicit selection = %+v", got)
	}
}

func TestPeersFromSourcesFallsBackToHome(t *testing.T) {
	seeds := []dht.Peer{mkPeer("freens.camalolo.com:15353", 0x01)}
	book := []dht.Peer{mkPeer("203.0.113.9:15353", 0x02)}

	got := peersFromSources(nil, nil, seeds, book)
	if len(got) != 2 || got[0].Addr != "freens.camalolo.com:15353" || got[1].Addr != "203.0.113.9:15353" {
		t.Fatalf("seeds+book fallback = %+v", got)
	}
}

func TestPeersFromSourcesDedupe(t *testing.T) {
	dup := mkPeer("203.0.113.1:15353", 0x07)
	sameAddrOtherKey := mkPeer("203.0.113.1:15353", 0x08)

	// Same (addr, pk) in seeds and book: kept once.
	if got := peersFromSources(nil, nil, []dht.Peer{dup}, []dht.Peer{dup}); len(got) != 1 {
		t.Fatalf("duplicate (addr,pk) across seeds/book kept %d copies, want 1", len(got))
	}
	// Same addr with a DIFFERENT key is a different node: both kept.
	got := peersFromSources(nil, nil, []dht.Peer{dup}, []dht.Peer{sameAddrOtherKey})
	if len(got) != 2 {
		t.Fatalf("same-addr/different-key peers = %d, want 2", len(got))
	}
	// Dedupe also applies across the explicit sources.
	if got := peersFromSources([]dht.Peer{dup}, []dht.Peer{dup, sameAddrOtherKey}, nil, nil); len(got) != 2 {
		t.Fatalf("explicit dedupe = %d, want 2", len(got))
	}
}

func TestPeersFromSourcesAllEmpty(t *testing.T) {
	if got := peersFromSources(nil, nil, nil, nil); got != nil {
		t.Fatalf("all sources empty = %+v, want nil (island)", got)
	}
}
