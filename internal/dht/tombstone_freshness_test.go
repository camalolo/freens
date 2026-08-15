// tombstone_freshness_test.go — a §9.5 tombstone must be re-checked
// SHORT (60 s), not treated as a day-fresh delegation: found live when an
// un-revoke stalled behind a day-fresh tombstone cache (revocation
// propagated in one TTL; the un-revoke would have taken 24 h).
package dht

import (
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

func TestTombstoneCacheFreshnessIsShort(t *testing.T) {
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	name, err := naming.EncodeWireName(nil, "fresh-test", tldID)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())
	rev := true
	rec, err := wire.NewRecord(name, kp.Public(), 2, now, now+86400)
	if err != nil {
		t.Fatal(err)
	}
	rec.Revoke = &rev // the tombstone: empty RRset + revoke=true
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}

	if got := cacheFreshness(env); got != 60 {
		t.Errorf("tombstone cacheFreshness = %d, want 60 (short re-check)", got)
	}

	// Sanity: a normal A record keeps its TTL window (delegation fallback
	// path still applies to non-revoked empty RRsets).
	rec2, err := wire.NewRecord(name, kp.Public(), 3, now, now+86400)
	if err != nil {
		t.Fatal(err)
	}
	env2, err := wire.SignRecord(rec2, kp)
	if err != nil {
		t.Fatal(err)
	}
	if got := cacheFreshness(env2); got != int64(constants.RecordDefaultTTL) {
		t.Errorf("empty-RRset non-revoked freshness = %d, want RecordDefaultTTL", got)
	}
}
