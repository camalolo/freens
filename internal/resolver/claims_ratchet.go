package resolver

// claims_ratchet.go — the resolver-side half of the #8 backdated-claim
// defense (v0.15.3). Companion to the §7.3 witness exclusivity check
// (dht.liveClaimConflict); see that function and verifyClaimContents for the
// full threat model.
//
// # The hole in one paragraph
//
// §6.4 orders competing claims EARLIEST-ASSERTED-TIMESTAMP-first, and a
// claim's timestamp is self-asserted. Witnesses fence the FRONT (the §6.3
// ts gate refuses claims older than WITNESS_PRESENT_WINDOW, so no honest
// node ever signs a backdated claim), but a FORGED claim carries only the
// attacker's own attestations — self-consistent, band-satisfying, signed by
// witness keypairs the attacker generated. The §7.5 finality horizon then
// drops the WITNESS_SET membership restriction for any claim older than 48 h
// (it must: registration-time witnesses churn away from the current
// closest-8, and enforcing membership forever killed every mature name —
// found live fleet-wide 2026-09-01). A claim minted ALREADY-backdated is
// therefore born past the horizon: it never faces the membership check, and
// its self-attestations are indistinguishable from honest history. Content
// alone cannot detect it.
//
// # What the ratchet adds: an observation anchor
//
// The one thing a backdated forgery cannot fake is having been seen
// resolving this alias BEFORE the forgery existed. Each Resolver keeps a
// bounded per-alias ledger of the past-horizon claim identities it has
// itself observed surviving verification ("established" identities). When a
// resolution offers a past-horizon identity the resolver has NEVER seen for
// an alias where it HAS an established one, the newcomer is dropped before
// the §6.4 ordering — it cannot displace (or outrank-then-own) an identity
// this resolver watched resolve, no matter how ancient its asserted
// timestamp. In-window claims are unaffected (they proved membership against
// the resolver's own converged walk, the strong path).
//
// Properties, honestly stated:
//
//   - Hijack of a name this resolver resolves (fleet reality: every daemon
//     resolves every fleet name hourly — auto-renew verification, doctor,
//     DNS traffic): defeated. The forged newcomer is dropped; during the
//     incumbent's replication gaps the alias answers NXDOMAIN rather than
//     handing the name to the forgery — strictly safer than serving it.
//   - Squatting a name NO resolver has observed before: NOT defeated. A
//     forgery observed before the victim ever registers becomes the
//     established identity; when the victim's honest claim itself ages past
//     the horizon, both identities are established and the resolver cannot
//     adjudicate between them (content-identical profiles). This bound
//     needs the protocol amendment (renewals re-collect FRESH witness
//     attestations, which the §6.3 ts gate guarantees honest witnesses will
//     only ever sign for genuinely-recent claims — a past-horizon claim
//     with fresh attestations becomes self-authenticating). Until then the
//     squat bound is the §12 sybil economics of REGISTERING the name
//     normally — the forgery adds nothing the plain registration path
//     doesn't already allow.
//   - Legitimate flows never trip it: a mature owner's identity is
//     immutable (same PoW, same attestations, same prefix hash forever), so
//     it is recorded once and survives every check; a post-window
//     re-registration mints a FRESH timestamp and rides the in-window path;
//     a resolver's very first sight of any alias accepts (bootstrap) and
//     then locks in what it saw.
//   - State: bounded (maxRatchetAliases, wholesale drop like the admin
//     witnessCache), in-memory only (restart = amnesia = fail-open: the
//     next resolution re-learns whatever identity currently wins), and
//     never negative-cached (a dropped newcomer is a per-resolution filter,
//     not a network fact).

import (
	"encoding/hex"
	"sync"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
)

// liveClaim is one envelope that survived verifyClaimEnvelope: the decoded
// claim, its carrier's created time (§8.4 continuity), and its identity
// (claim prefix hash). Package-level since v0.15.3 — the ratchet filter
// consumes it.
type liveClaim struct {
	claim   *claims.AliasClaim
	created int64
	ph      []byte
}

// maxRatchetAliases bounds the per-alias ledger. Fleet-scale namespaces sit
// in the hundreds; past this, the whole ledger drops (a resolver that
// resolved >4096 aliases re-bootstraps its trust anchors — acceptable and
// bounded, vs unbounded growth per alias ever seen).
const maxRatchetAliases = 4096

// pastHorizonLedger records, per alias, the past-horizon claim identities
// (hex prefix hash → last observed surviving) this resolver has established.
type pastHorizonLedger struct {
	mu     sync.Mutex
	bySeen map[string]map[string]int64
}

func newPastHorizonLedger() *pastHorizonLedger {
	return &pastHorizonLedger{bySeen: make(map[string]map[string]int64)}
}

// established reports whether phHex is a recorded past-horizon identity of
// alias, refreshing its last-seen stamp when it is.
func (l *pastHorizonLedger) established(alias, phHex string, now int64) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ids, ok := l.bySeen[alias]
	if !ok {
		return false
	}
	if _, seen := ids[phHex]; !seen {
		return false
	}
	ids[phHex] = now
	return true
}

// hasAny reports whether alias has ANY recorded past-horizon identity —
// including ones not visible in the current resolution (the incumbent's
// replication gap: the forgery must not win just because the honest
// envelope is momentarily unreachable).
func (l *pastHorizonLedger) hasAny(alias string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.bySeen[alias]) > 0
}

// observe records phHex as an established past-horizon identity of alias.
func (l *pastHorizonLedger) observe(alias, phHex string, now int64) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.bySeen) >= maxRatchetAliases {
		// Wholesale drop (the admin witnessCache pattern): identity ledgers
		// have no natural expiry — a forged identity must not be forgotten
		// before an honest one — so growth is answered by a clean slate,
		// not selective pruning.
		l.bySeen = make(map[string]map[string]int64)
	}
	ids, ok := l.bySeen[alias]
	if !ok {
		ids = make(map[string]int64, 2)
		l.bySeen[alias] = ids
	}
	ids[phHex] = now
}

// filterPastHorizonNewcomers applies the ratchet to the live claim set
// before §6.4 ordering: past-horizon identities never before observed for
// this alias are dropped when the alias HAS at least one established
// identity in the same resolution. Returns the filtered slice (in place —
// callers have not aliased it yet).
func (r *Resolver) filterPastHorizonNewcomers(alias string, lives []liveClaim, now int64) []liveClaim {
	if len(lives) == 0 {
		return lives
	}
	horizon := now - int64(constants.ContestWindow)
	past := 0
	for _, lc := range lives {
		if int64(lc.claim.Timestamp) <= horizon {
			past++
		}
	}
	if past == 0 {
		return lives // nothing past-horizon: the ratchet has nothing to say
	}
	// Which past-horizon identities are established here?
	phHexes := make([]string, len(lives))
	est := make([]bool, len(lives))
	anyEstablishedVisible := false
	for i, lc := range lives {
		if int64(lc.claim.Timestamp) > horizon {
			continue // in-window: rides the membership-checked path
		}
		phHexes[i] = hex.EncodeToString(lc.ph)
		est[i] = r.pastHorizon.established(alias, phHexes[i], now)
		if est[i] {
			anyEstablishedVisible = true
		}
	}
	// A ledger entry for an identity NOT visible this round (replication
	// gap) defends the alias exactly as a visible one would.
	defended := anyEstablishedVisible || r.pastHorizon.hasAny(alias)
	kept := lives[:0]
	for i, lc := range lives {
		switch {
		case phHexes[i] == "":
			kept = append(kept, lc) // in-window
		case est[i] || !defended:
			// This identity IS the established one, or the alias has no
			// established identity at all (fresh resolver bootstrap —
			// everything is new, keep all and learn).
			kept = append(kept, lc)
			r.pastHorizon.observe(alias, phHexes[i], now)
		default:
			// A past-horizon NEWCOMER against a defended alias: drop. It
			// cannot prove history — its attestations are self-consistent
			// by construction — and the alias demonstrably resolved as
			// someone else here before.
			if r.Logger != nil {
				r.Logger.Warn("dropping unproven past-horizon claim newcomer",
					"alias", alias, "identity", phHexes[i])
			}
		}
	}
	return kept
}
