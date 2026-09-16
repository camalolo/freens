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
	"github.com/fxamacker/cbor/v2"
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
	// Recovery and Claim are deep-copied too: they are byte slices behind
	// pointers/raw messages owned by prev, and the renewed envelope is
	// SIGNED over them — a later mutation of prev (a caller reusing or
	// re-signing the old envelope) must not corrupt the new signature.
	if prev.Record.Recovery != nil {
		rec.Recovery = &wire.RecoveryPolicyWire{
			Threshold: prev.Record.Recovery.Threshold,
			Timelock:  prev.Record.Recovery.Timelock,
			Keys:      make([][]byte, len(prev.Record.Recovery.Keys)),
		}
		for i, k := range prev.Record.Recovery.Keys {
			rec.Recovery.Keys[i] = append([]byte(nil), k...)
		}
	}
	rec.Claim = append(cbor.RawMessage(nil), prev.Record.Claim...)
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
// an APEX record (zero-label wire name) carries the owner-CA binding — and
// EXACTLY ONE binding: an existing TLSCA is kept verbatim only when it is
// the SAME CA the current derivation produces (same public key AND same
// subject — ECDSA signature randomness makes byte equality impossible, but
// key+subject identity is deterministic; a template upgrade that changes
// the subject therefore swaps the binding at the next renewal instead of
// leaving the record authorizing a cert no server presents), and EVERY
// other TLSCA slot — missing, foreign, near-expiry, or garbage — is
// replaced by the fresh §9.5.1 derivation, even when a good SameCA slot
// exists elsewhere in the set (a foreign RR must never survive beside the
// binding). The alias comes from the record's embedded §7 claim (apexes
// carry it); no claim, no TLSCA.
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
	var bad []int // indices of TLSCA slots that are NOT the current CA
	for i, rr := range rec.RRset {
		if rr == nil || rr.Type != wire.RRTypeTLSCA {
			continue
		}
		if c, perr := tlsca.ParseCertDER(rr.Rdata); perr == nil && tlsca.SameCA(c, wantCert, nowT) {
			kept = true
			continue
		}
		bad = append(bad, i) // garbage slot, a different CA, or a redundant non-kept copy
	}
	if kept && len(bad) == 0 {
		return // the record already carries exactly the right binding
	}
	fresh, rerr := wire.NewRR(wire.RRTypeTLSCA, constants.TLSCAResponseTTL, wantDER)
	if rerr != nil {
		return
	}
	// Rebuild the rrset: every non-TLSCA RR and the SameCA binding survive
	// in place; of the bad slots the FIRST is reused for the fresh binding
	// (position-stable) and the rest are dropped; with no bad slots and no
	// kept binding, the fresh RR is appended (§4.3 cap respected).
	bi := 0
	placed := false
	out := rec.RRset[:0:0] // fresh backing array — never aliases the caller's slice
	for i, rr := range rec.RRset {
		isBad := bi < len(bad) && bad[bi] == i
		if isBad {
			bi++
		}
		switch {
		case !isBad:
			out = append(out, rr)
		case kept:
			// the SameCA binding is present: foreign/garbage slots drop
		case !placed:
			out = append(out, fresh)
			placed = true
		}
	}
	if !kept && !placed {
		if len(rec.RRset) >= constants.MaxRRsPerRecord {
			return // rrset at the §4.3 cap: leave the record untouched
		}
		out = append(out, fresh)
	}
	rec.RRset = out
}
