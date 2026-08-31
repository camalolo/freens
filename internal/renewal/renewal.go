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

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/tlsca"
	"github.com/camalolo/freens/internal/wire"
)

// RenewThreshold: a record is renewed once the elapsed share of its OWN
// lifetime passes this fraction (80% — the same cadence as the §6.4 step-4
// republish timer, which re-copies at 80% but cannot extend the signed
// expiry; this is the extension it cannot do). v0.8.0: the threshold was
// anchored at RecordDefaultTTL, so a record published with a longer
// lifetime (up to RecordMaxTTL, 30 d) was re-signed every ~19 h — harmless
// but needlessly churning sequence numbers; the anchor is now the record's
// actual created..expires window, matching republishDue exactly.
const RenewThreshold = 0.8

// ShouldRenew reports whether a record created at `created` and expiring at
// `expires` needs a renewal now (inside the final 1-RenewThreshold of its
// own lifetime, or already expired — renewal inside the §12 grace window
// re-lights the name). A non-positive or degenerate window falls back to the
// default-TTL cadence.
func ShouldRenew(now, created, expires int64) bool {
	remaining := expires - now
	if remaining <= 0 {
		return true // already expired: renew on sight (grace window)
	}
	lifetime := expires - created
	if lifetime <= 0 {
		lifetime = int64(constants.RecordDefaultTTL)
	}
	return remaining < int64(float64(lifetime)*(1-RenewThreshold))
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
	EnsureTLSCA(rec, kp, uint64(now))
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		return nil, err
	}
	if !env.VerifySignature() {
		return nil, fmt.Errorf("renewal: self-check failed")
	}
	return env, nil
}

// EnsureTLSCA implements the §9.5 apex-RRset rule for every publish path:
// an APEX record (zero-label wire name) carries the owner-CA binding. An
// existing TLSCA is kept verbatim only when it is the SAME CA the current
// derivation produces — same public key AND same subject (ECDSA signature
// randomness makes byte equality impossible, but key+subject identity is
// deterministic; a template upgrade that changes the subject therefore
// swaps the binding at the next renewal instead of leaving the record
// authorizing a cert no server presents). Missing, foreign, or near-expiry
// bindings are replaced with a fresh §9.5.1 derivation. The alias comes
// from the record's embedded §7 claim (apexes carry it); no claim, no TLSCA.
//
// Best-effort BY CONTRACT: every problem — non-apex name, undecodable
// claim, derivation failure, rrset at the §4.3 cap — silently leaves the
// record untouched. The TLS layer must never be the reason a renewal or a
// registration fails.
func EnsureTLSCA(rec *wire.Record, kp *crypto.Keypair, now uint64) {
	if rec == nil || kp == nil || len(rec.Name) == 0 {
		return
	}
	labels, _, err := naming.DecodeWireName(rec.Name)
	if err != nil || len(labels) != 0 {
		return // only the apex carries the binding (§9.5.2)
	}
	nowT := time.Unix(int64(now), 0)
	alias := ""
	if len(rec.Claim) > 0 {
		if c, derr := claims.DecodeAliasClaim(rec.Claim); derr == nil {
			alias = c.Alias
		}
	}
	if alias == "" {
		return
	}
	wantDER, _, cerr := tlsca.OwnerCA(kp.Seed(), alias, nowT)
	if cerr != nil {
		return
	}
	wantCert, perr := tlsca.ParseCertDER(wantDER)
	if perr != nil {
		return
	}
	kept := false
	swap := -1
	for i, rr := range rec.RRset {
		if rr == nil || rr.Type != wire.RRTypeTLSCA {
			continue
		}
		c, perr := tlsca.ParseCertDER(rr.Rdata)
		switch {
		case perr != nil:
			swap = i // garbage slot: replace
		case tlsca.SameCA(c, wantCert, nowT):
			kept = true
		default:
			swap = i // a different CA: replace (identity or lifetime)
		}
	}
	if kept || (swap < 0 && len(rec.RRset) >= constants.MaxRRsPerRecord) {
		return
	}
	rr, rerr := wire.NewRR(wire.RRTypeTLSCA, constants.TLSCAResponseTTL, wantDER)
	if rerr != nil {
		return
	}
	if swap >= 0 {
		rec.RRset[swap] = rr
		return
	}
	rec.RRset = append(rec.RRset, rr)
}

// FreshWindow is the human-readable validity a renewal grants.
func FreshWindow() time.Duration { return time.Duration(constants.RecordDefaultTTL) * time.Second }
