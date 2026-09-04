// reserved.go — the §7.7 reserved-alias policy: an alias that equals a
// delegated ICANN TLD (com, net, de, xn--… — see reserved_tlds.go for the
// full data and its rationale) or an IANA special-use name (localhost,
// onion, …) must not become a freens TLD claim.
//
// Why (spec §7.7, prompted by the "what if someone registers com?" audit):
// the alias IS the TLD in freens, so a claim on "com" makes the claimant the
// owner of the whole freens .com namespace — including every name that
// reaches freens through the §9.3 NXDOMAIN fallthrough (typos, expired
// domains, filter-NXDOMAINed names) WITH a §9.5 owner CA, i.e. a phishing
// site with a green padlock. The default dns-first route keeps the claim
// inert against live domains, but the abuse window alone justifies refusing
// to mint, witness, or resolve such claims by default.
//
// Enforcement points (all local policy, never protocol law — a modified
// client can still do what it likes; §7.7 is what honest reference-
// implementation nodes do):
//
//   - `freens register` / webui register: refuse to MINT the claim
//     (-allow-reserved overrides on the CLI; the web UI never overrides).
//   - the DHT witness RPC: nodes refuse to CO-SIGN claims for reserved
//     aliases (NodeConfig.AllowReserved overrides) — no quorum, no claim.
//   - the resolver: freensResolve treats a reserved alias as claim-less
//     ([options] allow-reserved overrides; [alias-pins] still win — local
//     policy always beats the network), so even a rogue-published claim is
//     never accepted for resolution.
//
// Deliberately NOT gated: renewals, re-publishes, recovery and revocation of
// an alias a node already holds — the gate protects new registrations only
// and must never strand an existing holder (the list can only grow).
package naming

import "fmt"

// ReservedReason returns a human-readable reason string when alias is
// reserved per §7.7, or "" when it is not. The input should be the
// normalized (lowercase) alias; validation is the caller's prerequisite
// (ValidateAlias). Reasons distinguish the data kinds only for messaging;
// the policy is identical for all of them.
//
// Two kinds of entry, deliberately COMBINED into one lookup (IsReservedTLD):
//
//   - TLD-shaped collisions: every delegated ICANN TLD and every IANA
//     special-use name — claiming one would let a freens TLD masquerade as
//     part of real DNS (reserved_tlds.go).
//   - The project's own namespace: the "freens" alias itself — it is not a
//     TLD, but it is the name this software, its docs, its setup tooling
//     (the Windows connection-specific suffix "freens" behind the §9.4
//     suffix rescue) and every user's muscle memory already mean. A claim
//     on it would own `www.freens`, `mail.freens`, … — the first names a
//     new user tries, served by a stranger with a green padlock.
func ReservedReason(alias string) string {
	if _, ok := projectReserved[alias]; ok {
		return "the freens project's own namespace (the alias this software, its docs and its tooling already mean — spec §7.7)"
	}
	if _, ok := reservedTLDs[alias]; ok {
		return "a reserved TLD name (delegated ICANN TLD, IANA root-zone snapshot " + ReservedTLDsSnapshot + ", or IANA special-use name)"
	}
	return ""
}

// IsReservedTLD reports whether alias is reserved per §7.7 (TLD-shaped
// collisions or the project's own namespace).
func IsReservedTLD(alias string) bool {
	if _, ok := projectReserved[alias]; ok {
		return true
	}
	_, ok := reservedTLDs[alias]
	return ok
}

// ErrReserved is wrapped by every §7.7 gate error (errors.Is-compatible).
var ErrReserved = fmt.Errorf("reserved alias")

// CheckRegisterable validates alias per §3.2 and then applies the §7.7
// reserved-alias gate. It is the single funnel for every claim-MINTING path
// (`freens register`, the web UI register form). Resolution/witness gates
// use IsReservedTLD directly — they run on already-normalized aliases and
// must not re-report §3.2 syntax errors as reserved-alias failures.
func CheckRegisterable(alias string) (string, error) {
	norm, err := ValidateAlias(alias)
	if err != nil {
		return "", err
	}
	if reason := ReservedReason(norm); reason != "" {
		return "", fmt.Errorf("%w: %q is %s — freens refuses to claim it so freens names can never be mistaken for real DNS (spec §7.7); pick a different alias, or pass -allow-reserved to override", ErrReserved, norm, reason)
	}
	return norm, nil
}
