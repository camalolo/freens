// Package renewal implements the record-lease renewal (spec §6.4 step 4
// / §4.4): a freens record's expires is fixed INSIDE its signature, so
// "keep the name alive" means re-signing the same content at sequence+1
// with a fresh validity window — pure key-holder privilege, no PoW, no
// witnesses, milliseconds of work.
//
// It exists as a package because two front-ends need the identical
// semantics: `freens renew` (the CLI button) and the daemon's auto-renew
// loop (which makes the README's "records renew automatically while the
// daemon runs" literally true).
package renewal

import (
	"bytes"
	"fmt"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/wire"
)

// RenewThreshold: a record is renewed once its remaining lifetime drops
// below this fraction of RecordDefaultTTL (80% elapsed — the same cadence
// as the §6.4 step-4 republish timer, which re-copies at 80% but cannot
// extend the signed expiry; this is the extension it cannot do).
const RenewThreshold = 0.8

// ShouldRenew reports whether a record expiring at `expires` needs a
// renewal now (inside the final 20% of RecordDefaultTTL, or already
// expired — renewal inside the §12 grace window re-lights the name).
func ShouldRenew(now, expires int64) bool {
	remaining := expires - now
	if remaining <= 0 {
		return true // already expired: renew on sight (grace window)
	}
	return remaining < int64(float64(constants.RecordDefaultTTL)*(1-RenewThreshold))
}

// RenewEnvelope re-signs prev's content as a fresh lease: same name, owner,
// RRset, delegation, recovery policy, and embedded claim; sequence+1;
// created=now, expires=now+RecordDefaultTTL; revoke is NOT carried (a
// renewal un-revokes only in the sense that it re-points the name — but
// callers are expected to refuse revoking records entirely; see the CLI).
//
// The signer must be the current owner's key (same rule as every update:
// the authority chain names this key). The envelope is signed by kp.
func RenewEnvelope(prev *wire.SignedEnvelope, kp *crypto.Keypair, now int64) (*wire.SignedEnvelope, error) {
	if prev == nil || prev.Record == nil {
		return nil, fmt.Errorf("renewal: no previous record")
	}
	if !bytes.Equal(kp.Public(), prev.Record.Owner) {
		return nil, fmt.Errorf("renewal: signer is not the current owner (spec 8.3/9.2: updates are owner-signed)")
	}
	if prev.IsRevoked() {
		return nil, fmt.Errorf("renewal: record is revoked (deliberate death; un-revoke with register/name, not renew)")
	}
	rec, err := wire.NewRecord(prev.Record.Name, prev.Record.Owner, prev.Record.Sequence+1, uint64(now), uint64(now+int64(constants.RecordDefaultTTL)))
	if err != nil {
		return nil, err
	}
	if len(prev.Record.RRset) > 0 {
		rec.RRset = append([]*wire.RR(nil), prev.Record.RRset...)
	}
	if len(prev.Record.Delegation) > 0 {
		rec.Delegation = append([]byte(nil), prev.Record.Delegation...)
	}
	rec.Recovery = prev.Record.Recovery
	rec.Claim = prev.Record.Claim
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		return nil, err
	}
	if !env.VerifySignature() {
		return nil, fmt.Errorf("renewal: self-check failed")
	}
	return env, nil
}

// FreshWindow is the human-readable validity a renewal grants.
func FreshWindow() time.Duration { return time.Duration(constants.RecordDefaultTTL) * time.Second }
