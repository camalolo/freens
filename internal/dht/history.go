// Package dht — history.go adds the get-by-hash lookup path that §8.3
// (specifications.md lines 666-688) requires for verifying transferred names.
//
// A §8.3 transfer record carries prev_hash = H_record(previous signed
// envelope), and "the network accepts [it] because the previous owner — whose
// key the current authority chain names — signed it" (lines 680-681).
// Verifying the resulting chain therefore means fetching PREDECESSOR
// envelopes by their H_record — envelopes that are no longer the live winner
// under any DHT key (the single-winner §6.4 slot now holds the successor).
// EnvelopeStore retains those predecessors in its bounded superseded-envelope
// history, and this file exposes the lookup over them: local history first,
// then an iterative DHT get with h ITSELF as the key (the serving side's
// get-by-hash history fallback lives in the transport's get handler).
package dht

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/wire"
)

// hashLookup pins the LookupByHash shape other packages type-assert
// DHTLookup against (the resolver's §8.3 transfer verification side channel).
var _ interface {
	LookupByHash(ctx context.Context, h []byte) (*wire.SignedEnvelope, error)
} = (*DHTLookup)(nil)

// LookupByHash returns the superseded envelope whose H_record (§4.2) equals
// h: the local store's §8.3 history first (EnvelopeStore.GetHistory), then a
// live entry stored AT key h (a fetched-by-hash envelope cached under its own
// H_record — e.g. re-seeded from <persist> at start-up; the hash is verified
// before returning, so a colliding mis-keyed entry can never masquerade),
// then — when the lookup has a node — an iterative DHT get on h AS the DHT
// key, mirroring [DHTLookup.Lookup]'s network path (§6.4 GET; peers serving
// get-by-hash answer from their own history). A nil node degrades to local
// only. Returns (nil, nil) when the predecessor is available neither locally
// nor across the reachable network — an auditable chain that cannot be
// reassembled is unverifiable. A network envelope whose H_record does not
// equal h is discarded (treated as a miss): h IS the content hash, so a
// mismatching answer is a routing artifact or spam, never the predecessor.
//
// Fetched predecessors are NOT cached into the live store: the live map is
// keyed by DHT keys (K_tld/K_name/K_claim), h is a content hash, and history
// entries are immutable audit data with no freshness window to revalidate.
func (l *DHTLookup) LookupByHash(ctx context.Context, h []byte) (*wire.SignedEnvelope, error) {
	if len(h) != constants.SHA256Len {
		return nil, fmt.Errorf("dht: hash must be %d bytes, got %d", constants.SHA256Len, len(h))
	}
	if env := l.store.GetHistory(h); env != nil {
		return env, nil
	}
	// Hash-keyed live entry (fetch cache / re-seed artifact): the entry's own
	// H_record must equal the key it is stored under, or it is not the
	// predecessor being asked for. Get applies the liveness window; a
	// superseded predecessor retrieved this way is normally well within it,
	// and an expired one is servable by some peer's history instead.
	if env, _ := l.store.Get(h, time.Now().Unix()); env != nil {
		if got, err := env.RecordHash(); err == nil && bytes.Equal(got, h) {
			return env, nil
		}
	}
	if l.node == nil {
		return nil, nil // island: local history only.
	}
	c, cancel := context.WithTimeout(ctx, dhtLookupTimeout)
	defer cancel()
	env, err := l.node.IterativeGet(c, h)
	if err != nil {
		return nil, err
	}
	if env == nil {
		return nil, nil
	}
	got, err := env.RecordHash()
	if err != nil || !bytes.Equal(got, h) {
		return nil, nil // not the requested predecessor: a miss, not an error.
	}
	return env, nil
}
