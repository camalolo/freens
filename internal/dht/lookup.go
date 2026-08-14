// Package dht — lookup.go provides StoreLookup, a thin adapter from
// *EnvelopeStore to the resolver.RecordLookup interface (structural — it does
// NOT import internal/resolver, so the dht → resolver edge never appears and
// the import graph stays acyclic). It is the single canonical home for the
// store-backed record-lookup routing previously copy-pasted as private
// `storeLookup` types in cmd/freens, cmd/freens-cli, and internal/integration.
//
// Routing rule (mirrors how the daemon seeds/reads records, §6.4): for a
// wire_name that decodes to zero labels (the TLD-root form 0x00 || tld_id) the
// record lives at K_tld = tld_id; every other wire_name lives at
// K_name = SHA-256(0x02 || wire_name). The resolver walks the authority chain
// hop-by-hop, calling Lookup with each hop's wire_name, so this routing makes
// both the TLD record and descendant name records resolve correctly.
package dht

import (
	"context"

	"github.com/laurent/freens/internal/naming"
	"github.com/laurent/freens/internal/wire"
)

// StoreLookup adapts an *EnvelopeStore to the resolver.RecordLookup interface
// (structurally — it does not import resolver). See the file doc for the
// K_tld / K_name routing rule.
type StoreLookup struct {
	store *EnvelopeStore
}

// NewStoreLookup wraps s so it can be passed anywhere a
// resolver.RecordLookup is expected.
func NewStoreLookup(s *EnvelopeStore) *StoreLookup { return &StoreLookup{store: s} }

// KeyForWireName derives the DHT storage key for a wire_name (spec §3.3 / §6.4):
//
//   - A TLD-root wire_name (0x00 || tld_id, zero labels) is stored at
//     K_tld = tld_id (the self-certifying TLD identifier itself).
//   - Every other wire_name is stored at K_name = SHA-256(0x02 || wire_name).
//
// This is the single canonical keying rule shared by the store-backed lookup,
// the -load seeder in cmd/freens, and the put/get RPC handlers.
func KeyForWireName(wireName []byte) ([]byte, error) {
	labels, tldID, err := naming.DecodeWireName(wireName)
	if err != nil {
		return nil, err
	}
	if len(labels) == 0 {
		return tldID, nil // K_tld = tld_id
	}
	return naming.DHTKeyName(wireName), nil // K_name
}

// KeyForClaim derives K_claim = SHA-256(0x03 || "claim:" || alias) (§3.3) —
// the key under which the §7.4/C.1 claim envelope (the TLD record carrying the
// AliasClaim in field 11) is stored. It is the thin exported alias of
// naming.DHTKeyClaim, kept here so the dht package exposes one canonical
// key-derivation surface (KeyForWireName / KeyForClaim) for Publish /
// PublishClaim and the put/get handlers.
func KeyForClaim(alias string) ([]byte, error) {
	return naming.DHTKeyClaim(alias)
}

// Lookup returns the winning SignedEnvelope stored for wireName at time now,
// or (nil, nil) if no live record is stored under the corresponding key.
//
// For a wire_name that decodes to zero labels (a TLD root) it looks up
// K_tld = tld_id; otherwise it looks up K_name = SHA-256(0x02 || wire_name).
func (l *StoreLookup) Lookup(ctx context.Context, wireName []byte, now int64) (*wire.SignedEnvelope, error) {
	key, err := KeyForWireName(wireName)
	if err != nil {
		return nil, err
	}
	return l.store.Get(key, now)
}
