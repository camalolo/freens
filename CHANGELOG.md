# Changelog

## Unreleased — v0.16.2: the fleet-log pass — false renewal confirms, the hollowed rescue, rotation-gate day-roll false alarms, re-mint churn, bounded installer execs

The 2026-09-05 morning fleet-log review caught a real outage chain and
the code that let it happen (all fixed; fleet-verified before commit):

- **cli/daemon: the pending-renewal confirm checked only K_tld.**
  `retryPendingPuts` verified the network held `keys[0]` — so when the
  K_tld leg landed (3/8) while the K_claim leg was refused by every
  store it reached (0/8, ghost-polluted claim keyspace), the confirm
  matched, the pending entry was dropped, and the network kept serving
  the LAPSED predecessor claim. Hours later the predecessor's lease ran
  out and the namespace went NXDOMAIN fleet-wide (minipc 08:59–10:09,
  nanopi from ~10:00) while both owners' local bookkeeping said
  "fresh" — the phantom-freshness class again, this time with a
  false-confirm instead of a silent put. Every key must now confirm.
- **dht: the publish walk-rescue runs under its own 60 s budget.**
  The rescue reused the caller's ctx — which the round-1 ghost timeouts
  had just consumed, exactly when the rescue was needed most — so the
  walk answered nothing and `targets` stayed 8. Fresh bounded deadline.
- **tlsca+trustsync: CA dedup and the rotation gate key on the CA
  IDENTITY (subject-public-key hash), not whole-cert bytes.** The owner
  CA's cert bytes change with every derivation DAY (the §9.5.1 window
  truncates to the UTC day) while the key stays deterministic — so the
  byte comparison read every UTC-midnight renewal as a CA rotation:
  minipc's routine 10:10 renewal tripped the gate with a WARN and a
  needless 1 h grace. Day-window re-mints now dedupe silently; the gate
  fires only on a real key change. Pre-v0.16.2 state files adopt the
  identity from the first notification (the installed cross-cert
  anchored the same key).
- **trustsync: re-mints throttled to one per hour per alias.** The
  cross-cert's life is capped by the apex RECORD's expiry, so the final
  ~6 h of every lease made the refresh test permanently true — the
  server re-minted (and re-ran its certutil NSS installs) on EVERY
  resolution for the whole window, soaking the box.
- **trustsync: every installer exec is bounded (30 s)** —
  update-ca-certificates and certutil had no deadline; concurrent
  instances serialized for minutes at a time on the box that runs
  certutil. (The boxes without certutil never wedged — which is what
  pinned the correlation.)

## Unreleased — v0.16.1: the walk returns only candidates that ANSWERED (the rescue's missing half)

- **dht: `IterativeFindNode` excludes failed probes from its result.**
  The walk queried dead candidates correctly (§6.2 eviction, progress via
  the queried-map) but its RETURN VALUE was the top-want **by distance**
  over everything it knew — so a dense cluster of dead contacts could
  occupy the entire result and hide the live nodes the walk actually
  reached deeper in the list. The v0.15.5 walk-rescue documented its
  contract as "the closest REACHED contacts" and filtered the result
  against its already-tried set — with a ghost-dominated `reached` it
  added nothing and the publish still reported "accepted by 0 of 8"
  while the storing peers sat one round away. Failed probes are now
  dropped from the result (they were already evicted/demoted in the
  table), so put targets and witness candidates come only from nodes
  that answered. Found chasing the `TestPublishRescuesGhostTableWithWalk`
  CI failure (which had failed on BOTH the v0.15.5 and v0.16.0 commits —
  born flaky): the fixture also stamped no `LastSeen` on its synthetic
  ghosts, making them instantly eligible for the idle sweep — a second,
  independent coin flip. Both layers fixed; the test is now deterministic
  across repeated runs.

## Unreleased — v0.16.0: §9.5.4 trust hardening (quarantine, rotation gate, liveness sweep), §7.7 project namespace, `freens trust ls/remove`

The malicious-use hardening pass on the TLS trust layer, each piece
fleet-verified before commit:

- **§9.5.4 young-claim quarantine.** A resolution whose winning claim is
  still inside the §7.5 `CONTEST_WINDOW` records the namespace's owner CA
  but installs NO cross-cert: DNS answers serve, TLS trust waits until the
  claim matures. A Sybil-witnessed fresh claim now gets zero green-padlock
  window — the padlock has to be earned by surviving the contest period.
  The signal rides the existing `contested` computation (resolver →
  `OnOwnerCA`); pin-resolved aliases skip the quarantine by construction
  (explicit operator policy).
- **§9.5.4 rotation observation gate.** The owner CA key is derived
  deterministically from `SK_tld` with a 10-year certificate, so a TLSCA
  change under a LIVE installed binding is never routine: the daemon keeps
  the old cross-cert authoritative, journals a loud WARN, shows
  `rotating (→<fp> since <ts>)` in `trust ls` and admin `/tls`, and
  completes the swap only after the new CA persists across the 1-hour
  observation grace. Flip-backs abort the rotation. An installed CA that
  already EXPIRED swaps immediately (the legitimate decade-cycle re-mint
  gains nothing from a grace on a dead anchor).
- **§9.5.4 liveness sweep.** Expired cross-certs now purge engine state
  AND direct system-bundle / NSS installs — not just the spool file —
  driven both by traffic and by a new daemon-side 30-minute timer
  (`RunSweeper`): a box that stops resolving a namespace still converges
  its trust stores when the namespace's lease lapses. Also fixes a
  latent dedup hole: a fresh state entry whose spool file vanished
  re-mints instead of silently trusting nothing.
- **§7.7 project-namespace reservation.** `freens` itself is now a
  reserved alias (refused at mint, witness co-sign and resolution, same
  as the TLD list): it is not a TLD, but it is the name the software, its
  docs, its tooling and the Windows suffix-rescue suffix already mean —
  a stranger must never own `www.freens` with a green padlock.
- **`freens trust ls` / `freens trust remove <alias>`.** First-class
  operator inventory of every cross-certified namespace on the box
  (status, CA fingerprint, expiry, system/spool) and the one-command
  purge of a poisoned or unwanted namespace (-json for scripts; admin
  `/tls` carries the same status fields).
- **cli: a RETRIED register with a passphrase-encrypted keychain no
  longer dies on its own recovery keyfiles.** On the "owner key reused"
  path the passphrase never reached the recovery-plan reload, so every
  retry of an interrupted registration failed with "keyfile is
  passphrase-encrypted (passphrase required)" even with
  FREENS_PASSPHRASE set — found live during this release's fleet test
  (the retry flow the docs call free-to-retry was unreachable for
  encrypted keys). The unlock passphrase is now fetched lazily (env
  wins, else prompt) exactly when the recovery keyfiles need it.

## Unreleased — v0.15.5: the register-page render fix, the publish walk-rescue, and the daemon-path re-attest hook

Three fixes straight from live-fleet testing of v0.15.4:

- **webui: registering a name no longer 500s at the progress card.**
  The register page inlines the jobfragment template with the PAGE's
  data — but jobfragment evaluates fields the page struct does not
  carry, and a missing struct field is a template EXECUTION error. The
  page had 500'd ("render error") on every re-attached progress card
  since v0.6.0, hiding the actual outcome of every webui registration —
  found live when the first real browser registration attempt (a §7.7
  "com" refusal on desktop) surfaced it. The page now renders the
  attached job's VIEW data (shared with the polled fragment endpoint),
  so a refused registration shows its clean refusal message. (The §7.7
  gate itself was never involved — it refused correctly before any key
  was generated.)
- **dht: a publish that accepts nothing from its local table rescues
  itself with a real walk.** The live incident this fixes: standalone
  `renew -force -peers` reported "publish (K_claim): accepted by 0 of 8
  peers" while the fleet was healthy — the put targets came from
  rt.Closest over a bootstrap table polluted with ghost one-shot
  contacts, so every put timed out. When the table round yields zero
  acceptances, the publish now runs IterativeFindNode once and puts to
  the closest REACHED contacts — the targets it should have used in the
  first place — and reports the honest count. Bounded: the rescue only
  runs on the total-failure path.
- **admin: daemon-path renewals now drive §8.3 re-attestation.** The
  v0.15.4 collection hook lived in the auto-renew tick and the
  standalone CLI path — but the standalone path's K_claim leg is
  exactly what the ghost pollution breaks, so in practice re-attests
  only fired on the tick. /publish's claim leg now triggers the
  collection fire-and-forget from the daemon (whose routing view is
  warm), so every daemon-transport renewal keeps the fleet's freshness
  evidence alive.

## Unreleased — v0.15.4: the v2 renewal amendment (§8.3 re-attestation — network-transferable freshness evidence)

The designated v2 path from the backdated-claim defense, implemented:

- **The witness RPC gains a re-attest mode (§7.3).** A request whose
  claim ts is older than the present window is no longer refused
  outright when it carries `reattest: true` — it is the owner asking
  the witness to RE-NOTARIZE a claim it holds. Eligibility: the exact
  claim identity is pooled here (a witness re-attests only what it
  holds, screened by the full §7.4 content filter), held for at least
  `RE_ATTEST_HOLD` (24 h — fresh forgeries cannot farm signatures
  between their put and their re-attest round), and no live conflicting
  identity competes (the exclusivity rule on the re-attest channel: a
  disputed alias is re-attested for NEITHER side). The witness signs a
  NOW-dated attestation over the unchanged claim identity — the ts gate
  guarantees honest witnesses never put their current clock under a
  claim whose asserted ts is not genuinely recent — and keeps what it
  signed.
- **Renewals drive it (§8.3).** After a successful publish, the daemon's
  auto-renew and `freens renew` walk the converged witness set and
  collect re-attestations — best-effort by design: a short haul is
  "this cycle gathered nothing", never a renewal failure. Holding
  periods mean each witness signs from its second renewal cycle onward,
  so fleet evidence accumulates in the background.
- **Verifiers consume it.** hGet serves the holder's stored fresh
  re-attestations alongside the envelopes (flat
  [identity, attestation] pairs — no nested maps on the wire, graceful
  with pre-amendment peers); the collect path merges and re-verifies
  them into the local pool; and in the resolver, among PAST-HORIZON
  claims, one whose fresh attestations reach the W quorum —
  membership-checked whenever the walk names the witness set — PREEMPTS
  past-horizon claims without such evidence. Evidence outranks both
  asserted age and the v0.15.3 ratchet's own observation. The ratchet
  remains the fallback for names without evidence yet, and in-window
  claims are untouched (ordering rules).
- **Pool state**: per claim-identity firstSeen stamps (the holding
  period is per IDENTITY, so renewal generations never re-arm it) and
  stored re-attestation sets, both persisted in a claims-meta.json
  sidecar (the holding period must survive restarts, or every upgrade
  re-arms it fleet-wide), bounded (16 per identity, swept with the pool,
  re-verified on load — a hand-edited meta file cannot manufacture
  evidence).
- **Spec**: §7.3 re-attest mode + updated residual (the remaining bound
  is §12 economics); §8.3 the renewal amendment + the verifier's
  preference rule; §7.5 evidence-outranks-observation. A future release
  MAY flip the preference into a hard requirement for past-horizon
  claims once fleet coverage is demonstrated for a full renewal cycle.

## Unreleased — v0.15.3: the backdated-claim defense (witness exclusivity + the resolver ratchet) and four audit P1/P2s

The remaining open findings from the 2026-09-04 audit:

- **#8, the backdated-claim hole — designed, then closed where content
  can close it.** The audit's sharpest find: §6.4 orders claims
  earliest-ASSERTED-timestamp-first, the §6.3 witness ts gate fences the
  front (no honest node signs a claim older than 5 min), but a claim
  minted ALREADY-backdated carries only the attacker's self-signed
  attestations — and because it is born past the §7.5 contest horizon,
  it NEVER faces the WITNESS_SET membership check. Content alone cannot
  detect it: a forged old-ts claim is byte-for-byte what a
  legitimately-old claim looks like (renewals keep the original claim
  immutable forever). Two mitigations carry the gap:
  - **§7.3 witness exclusivity** (dht `liveClaimConflict`): a witness
    refuses to co-sign a different-identity claim for an alias on which
    it holds a LIVE, fully content-valid claim. Until now exclusivity
    emerged only from the resolver's ordering — the witness set would
    happily mint a second claim over a live name. The refusing witness
    set IS the storing set around K_claim, so a live name can no longer
    gather a fresh-claim quorum from honest witnesses; same identity
    (renewals, parked-claim retries) is exempt; quorum-less pooled
    fabrications still lock nothing (the DoS-safety bar).
  - **The past-horizon ratchet** (resolver `claims_ratchet.go`): every
    resolver keeps a bounded per-alias ledger of the past-horizon claim
    identities it has observed resolving. An UNOBSERVED past-horizon
    identity cannot displace an established one — and is refused even
    during the incumbent's replication gaps (NXDOMAIN, not the forgery).
    Fail-open on a verifier's first sight (the documented residual:
    first-sight squatting and two-established-identity disputes need the
    renewal-fresh-attestation protocol amendment, now written into the
    spec as the designated v2 path).
  - The v0.14.1 comment claiming the residual was "48 h of sybil
    presence" was wrong (a backdated claim need not hold anything for
    48 h — it is never in the window); rewritten with the honest model.
  - Spec: §7.3 gains the exclusivity rule + updated residual; §7.5
    documents the horizon's ratchet; §8.4 documents the shared screen.
- **The dual §8.4 tombstone screens unified.** The resolver carried a
  second hand-rolled copy of the tombstone evidence screen that had
  ALREADY drifted from the dht's (it checked record version/sequence/
  validation, the witness/storer side did not). One shared screen
  (`dht.ClaimEvidence`) now backs every §8.4 enforcement point — witness
  gate, put gate, resolver continuity — verifying identically, in the
  stronger direction.
- **EDNS both directions.** Upstream: `Forward` advertises a 1232-byte
  UDP payload on queries with no OPT (the classic 512 advertisement
  forced TC + a TCP retry per large answer, on a copy — the caller's
  message is never mutated). Client-facing: the resolver echoes an OPT
  advertising the requester's declared payload (clamped 512-4096) and
  `writeReply` truncates against THAT budget — an EDNS-capable stub no
  longer gets 512-byte truncation and needless TCP fallback.
- **Cache case-folding (RFC 1035 §2.3.3).** Cache keys fold the qname to
  lowercase: `Example.COM` and `example.com` were two independent
  entries (a miss for one, a separately-expiring copy for the other).
  The persistence-reload path folds too.
- **Routing `Closest` stops cloning the world.** It runs on every walk
  step, RPC reply, and put target pick; it used to deep-clone EVERY
  contact before sorting, then return a slice. It now gathers pointers,
  sorts under the read lock, and clones only the n survivors.

## Unreleased — v0.15.2: the audit batch (webui CSRF, silent-data-loss paths, bounded state, dead code)

The 2026-09-04 full-tree audit (staticcheck + four parallel deep reads,
every P0 re-verified by hand) landed its fixes:

- **webui: every browser mutation works again.** The CSRF gate demanded
  `X-Requested-With: XMLHttpRequest`, which htmx never sends (it stamps
  `HX-Request: true`) — all ten `hx-post` flows 400'd from any real
  browser since the guard shipped, while the Go tests (which set the
  header by hand) stayed green. The gate now accepts either custom
  header; the CSRF property is unchanged (cross-site posts cannot set
  custom headers at all).
- **revoke/forget stop lying about network failures.** A failed
  discovery walk used to be treated as "nothing published": revoke then
  minted a sequence-1 tombstone that silently lost the §6.4 winner race
  (name stayed live while the CLI printed REVOKED), and forget DELETED
  the keys anyway — live name, keyless user. Walk errors now abort both
  verbs; forget's nothing-published branch also prompts before pruning
  interactively (it was the one destructive path with no confirmation);
  the un-revoke hint now names `register` for apexes (`name` refuses
  them).
- **passphrase prompt failures abort.** A `term.ReadPassword` error
  returned `("", nil)` and the owner key was silently written in
  PLAINTEXT. Now the error propagates; nothing is written.
- **resolver: a TC'd upstream answer is no longer served as final** when
  its TCP retry fails (partial answers silently dropped records) — the
  truncation is treated as a failed exchange, SERVFAIL if no upstream
  succeeds.
- **Bounded state (four leaks):** dht `deadUntil` and `witnessLast` now
  sweep expired entries on insert past a floor (previously one
  permanent map entry per probed corpse / per alias ever co-signed);
  the admin `witnessCache` drops its memo past 4096 entries; the webui
  retires each per-connection one-shot listener when the connection
  closes (previously a parked goroutine + map entry leaked per served
  connection on the always-on UI).
- **Races:** the webui job fragment read `j.Result` outside the job
  mutex (racing the runner's final write on every completion poll); the
  nginx toolchain's lazy init raced across concurrent cert handlers
  (now once-guarded).
- **`freens name` (the phantom-sequence class, last member):** the
  standalone discovery get is now preceded by `IterativeFindNode`
  warm-up toward the name and apex keys, and a failed walk aborts the
  publish instead of silently minting sequence 1.
- **Wire-visible spec reference fix:** every v0.15.0 reserved-alias
  comment AND the witness refusal string cited "spec §7.6"; the policy
  lives in §7.7. All references corrected.
- **Dead code purged** (all repo-verified): cli `netIP`, `reusableClaim`,
  `claimStatePath`, `difficultyOf`, `base32Decode`, `publishEnv`,
  `backupReadmeTemplate` (keychain's copy is the live one),
  `systemctlActive`; webui `errDenied`, `wantsHTML`, the ops.go
  import-keeper block, dead `ttl`/`_ = d` locals in mutations.go; dht
  `(*Node).currentDifficulty`; claims `corroboratingWitnesses` and the
  `OrderKey` type/method — with the claims-pool's field-by-field
  duplicate of the §7.4 ordering deleted in favor of the now-exported
  `claims.LessOrderKey` (one ordering, two packages, no drift);
  resolver `ValidateServeBool`; renewal `FreshWindow`; upnp Gateway
  diagnostics getters; constants.R; certmgr `ErrServeFilesNotFound`.
  certmgr `runWithTimeout` was dead because NOTHING used it — nginx
  `-t`/`reload` execs ran without any timeout, wedging the certs page
  on a hung nginx; all certmgr nginx/systemctl execs are now bounded at
  30 s (`runBounded`).
- **dht `putToPeer`** no longer dereferences `putResp` inside the branch
  guarded by its own nil check.

## Unreleased — the phantom-sequence class dies: claim caches revalidate, standalone renew walks the true closest-set

Second half of the minipc-incident findings (2026-09-04; the first half
shipped in v0.15.0's §7.7):

- **`DHTLookup.LookupClaim` now actually mirrors `Lookup`** — including
  stale-cache revalidation. A fetched claim cache is served only while
  fresh (fetchedAt + min-TTL); past freshness the next lookup re-walks
  the network and adopts what it finds (adopted copies are cached and
  their fetch time restamped). Before: local hit → serve, forever — so a
  node that cached a claim envelope which then LAPSED served the dead
  copy for the whole §6.4 ExpiryGrace day while the network moved on;
  the resolver's §7.4 checklist rightly rejected the expired envelope
  and the name NXDOMAINed locally while every fresher vantage resolved
  (nanopi vs minipc, ~1 h observed, 24 h possible). Authoritative local
  seeds (no fetchedAt) keep the eternal fast path — owner-local and
  `-load`-seeded views are unchanged. One claim-specific refinement
  beyond Lookup: a DEGRADED walk (probes failed) with a LAPSED cached
  copy returns ErrDegradedMiss (SERVFAIL upstream, never negative-
  cached) instead of an authoritative-looking NXDOMAIN — issue #1's
  contract extended to the claim hop.
- **Standalone `renew` runs ONE warmed node for the whole flow.** The
  fetch leg now warms the table with `IterativeFindNode` toward BOTH
  keys (K_tld and K_claim — find_node responses always carry {nodes},
  immune to the store-hit blindness) before the discovery get, so
  §6.4's EnvelopeWins bases the new sequence on the max-sequence copy
  the network actually holds. Before: the discovery get behind a single
  stale bootstrap peer saw only that peer's store copy (store hits omit
  {nodes} — the walk never learns the true closest-set) and minted a
  globally-losing sequence ("phantom 21": seq-21 minted while the
  network held 23). The publish now reuses the same warmed node — the
  old second, cold node could under-replicate the renewed envelope
  past the very peer that blinded discovery (caught by the regression
  test). `register`'s standalone sequence discovery gets the same K_tld
  warm-up.

## Unreleased — §7.7 reserved-alias policy: freens can never become ".com"

Prompted by the "what happens if someone registers `com`?" audit. The
alias IS the TLD in freens, so a claim on a real TLD string would make
the claimant the owner of the whole freens `.com` namespace — and every
name under it that upstream DNS answers NXDOMAIN for (typos, expired
domains, filter-NXDOMAINed names) falls through the §9.3 default route
straight to the claimant, **with a §9.5 owner CA**: a phishing site with
a green padlock. The old §9.3 answer (default dns-first never silently
shadows live domains) closed the accidental-collision hole but not the
deliberate-abuse one, and the flat PoW gave squatters zero per-alias
friction.

The reference implementation now refuses at all three enforcement
points, so a first-time user cannot be misled onto a spoofed site even
if malicious nodes fully self-witness a claim (5 rogue nodes):

- **Mint**: `freens register` and the web UI register form refuse an
  alias equal to a delegated ICANN TLD (IANA root-zone snapshot
  2026090300, embedded — 1445 entries incl. IDN A-labels) or an IANA
  special-use name (`localhost`, `onion`, `test`, `example`, `invalid`,
  `local`, `arpa`, `home` — enumerated by hand; no DNS-based check can
  see them). The gate fires before any keygen/PoW/network work. The CLI
  has `-allow-reserved` (with a loud warning); the web UI has NO
  override — its error points at the CLI. The list is a compiled-in
  snapshot on purpose (a runtime "ask upstream DNS" gate was rejected:
  spoofable exactly when it matters, fails on upstream-less networks,
  and leaves witnesses disagreeing on a policy that must be
  deterministic); it only ever grows, refreshed at release time.
- **Witness**: the §6.3 witness RPC refuses to co-sign reserved-alias
  claims before any crypto work (error 305). No quorum, no claim.
- **Resolve**: `freensResolve` treats a reserved alias as claim-less —
  NXDOMAIN, no network walk — even if a fully-witnessed claim exists in
  the network; the admin `/resolve` face behaves identically.
  `[alias-pins]` win over the gate (operator policy), checked first.

Escapes and non-goals: `-allow-reserved` (CLI flag + daemon flag +
`[options] allow-reserved = true`) is the single deliberate local
override for all three gates. Existing holders are NEVER gated —
renewal/re-publish/recovery/revoke keep working regardless of the list,
so a future snapshot change cannot strand a name. Spec: new §7.7;
§9.3's collision policy remains as the second line of defense. Found
while testing: the resolver suite's canonical test alias `foo` is ITSELF
a delegated gTLD in the 2026 snapshot — the fixtures now use `footld`
(and the integration test's `foo` sails through on its alias-pin,
proving the pin exemption live).

## Unreleased — "confirmed" now names the address that carried it

Found live on the fleet: a friend's box reached us only through EPHEMERAL
one-shot CLI ports (:1908, :1025, …), so a peers-table row read
"confirmed · 1m ago" next to a headline address no daemon ever answered,
while its real daemon port sat at "never confirmed" (its restrictive NAT
drops unsolicited sources — only its own outbound traffic confirms).
Both the webui peers table and `freens peers` now show, per row:

- **"at <address>"** under the last-direct-exchange cell — the address
  the confirmation actually rode (dht.ConfirmedAddr: the freshest
  per-address confirmation, which for multi-homed contacts need not be
  the displayed headline).
- **"· never confirmed" markers** on alternates, shown only when the
  contact IS confirmed elsewhere — the asymmetry an operator needs to
  see. On an advertised contact every address is unconfirmed and the
  badge already says so. `freens peers` lists them compactly as
  `never confirmed: :1025 :1024` (same-host ports shortened).

`freens peers -json` gains `confirmed_addr` and per-alt `confirmed`
flags; the alts list follows the display rules (non-literals dropped).

## Unreleased — `freens peers`, `freens keys`, `freens store`: the CLI catches up with the web UI's read surfaces

The web UI's Network/Keys/Store pages had no `freens` verb behind them —
the operator asked where the peers listing went (2026-09-02):

- **`freens peers`** prints the running daemon's routing table: one block
  per multi-homed contact with display-ordered addresses (public first,
  LAN after — the SAME dht.DisplayAddrs helper the webui table uses, so
  the two surfaces can never diverge again), the node-key prefix the web
  UI shows, last direct exchange, and the honest confirmed/advertised
  state. `-v` adds full keys + node IDs; `-json` for scripts. Rows sort
  confirmed-first. Refusing to run against `-peers` standalone: the
  routing table is daemon state.
- **`freens keys`** lists the local keychain inventory (owner/recovery
  keyfiles, sizes, mod times, passphrase-encryption flag) —
  keychain.Inventory, the Keys page's source.
- **`freens store`** lists the daemon's live envelope store (GET /store):
  decoded names, sequences, live/lapsed/REVOKED lease state, §7.4 claim
  flags, expiry and size — the Store page's source, lapsed entries last.

## Unreleased — the phantom-fresh lease is dead: auto-renew verifies the network, publishes report acceptance, doctor checks the lease cross-box, and ghosts stop circulating

Four follow-ups to the 2026-09-02 camalolo incident (the local keychain
said "fresh until 12:17" while the network had lost the envelope; every
non-owner resolver NXDOMAINed the name for ~7 h and nothing on the owner
noticed):

- **daemon: the auto-renew pass verifies "fresh" leases against the
  NETWORK.** Once an hour per name (the pass runs every 10 min) a lease
  that ShouldRenew considers fresh is re-fetched by a network walk that
  EXCLUDES the daemon's own store — an owner counting its own copy
  would have "confirmed" itself forever. A missing or older-generation
  answer re-publishes the exact local envelope (no re-sign, the
  sequence does not move) and queues it for the existing
  network-confirmed retry loop. Degraded walks are skipped as
  inconclusive, never treated as evidence.
- **dht: walks no longer probe the walker itself.** A peer advertising
  the walker back (normal Kademlia) used to add the walker's own node
  to the shortlist, so a "network" GET could be answered by the local
  store one UDP hop away — poisoning exactly the verification above
  and, before it, any walk-statistics view. Self is now excluded at
  batch-pick time in the GET, find_node, and claim-collection walks.
- **dht+admin: publishes report per-key storing-peer acceptance.**
  PublishStats carries {key, targets, accepted}; the admin /publish
  response adds a `keys` array beside the historical `accepted` count,
  the daemon logs "accepted k of R" (WARN on 0 and on partial), and the
  auto-renew loop logs the same for every renewal put. "RENEWED" can no
  longer mean "the puts went nowhere".
- **dht: ghost one-shot contacts stop circulating in {nodes}.** A
  contact the node never directly confirmed is advertised only while
  its learn is fresh (10 min); confirmed contacts keep the 1 h idle
  sweep as their bound. One-shot CLI ephemeral contacts used to hop
  across the fleet forever — every re-learn started a fresh clock, and
  they polluted the closest-8 views around contested keys.
- **admin+cli: doctor checks the alias's lease as a FOREIGN resolver
  sees it.** POST /resolve accepts {"network": true}: both fetches walk
  peers with the daemon's own store/pool excluded and the response
  carries the network record/claim sequence+expiry. `freens doctor`
  runs it on the first keychain alias and FAILS with
  `freens renew -force <alias>` when the network's copy is missing or
  expired while the local one resolves — the exact signal the incident
  hid for hours. Degraded walks are reported inconclusive, never
  failed.

## v0.14.2 — the peers table stops showing "<nil>:15353" and lists public addresses before LAN ones

Two fleet-visible cleanups around the multi-homed contacts table (each
peer row shows every address a node is known at, added v0.13.3):

- **dht: hostname-shaped contacts no longer ride `{nodes}`
  advertisements.** seeds.conf pins the community seed by HOSTNAME
  (`freens.camalolo.com:15353#…`), so every node's routing table holds a
  contact whose address is not an IP literal. That is fine for dialing
  (ResolveUDPAddr resolves at ping time) but was poison on the wire:
  `encodeNodeEntry` emitted EMPTY ip bytes for it, and every receiver's
  `parseNodes` stringified those bytes as the literal text `<nil>` —
  teaching the whole fleet an undialable `<nil>:15353` "address" for the
  seed (node 38c5d5b3…, visible in every webUI peers table since the
  multi-homing rollout). encodeNodes now skips addresses whose host does
  not parse as an IP (preferred or alt — the entry is simply not
  advertised; the contact stays dialable locally), and parseNodes skips
  entries with empty/garbage/unspecified ip bytes so old peers cannot
  reintroduce the artifact. Spec §6.2 amended (advertised addresses are
  literals; malformed entries are skipped).
- **webui: the peers table orders each node's addresses public-first.**
  The row lists the public/global addresses first, then LAN/private/
  link-local ones (stored recency order kept within each class), and
  drops addresses that are not IP literals — so a pre-fix `<nil>` alt
  still hiding in a running table renders nowhere until the daemon
  restart clears it. Display-only: the daemon's preferred (probe)
  address and Alts bookkeeping are untouched. IPv6 addresses order as
  public (a global v6 sorts first; fe80::/10 and fc00::/7 sort as LAN).

## v0.14.1 — names stopped resolving when their witnesses moved (§7.3 membership), the seed could not resolve the names it witnessed, renewals stop dying silently, and the §9.5.4 trust chain stops aging out

Four fleet-found fixes, all of the "works until the network has run long
enough to matter" class. The headline symptom, live on the fleet since
~19:17 on Sep 1: the server NXDOMAINed `minipc`/`nanopi`/`desktop`
while `admin /resolve` (which skips §7.4 screening) found them all, and
reproduced on stock v0.13.16. Root causes stacked three deep:

- **dht: the converged witness set includes the walking node's own ID.**
  §7.3 membership ("the witness is among the WITNESS_SET = 8 closest
  nodes to K_claim as the verifier's converged lookup observed them")
  was built from the walk's REACHED contacts — and a walk never reaches
  itself. The seed had witnessed every registration in the community,
  so every claim but its own carried its attestation, which counted 0/5
  forever on the seed. Self's ID now joins the candidate set (it is
  definitionally up — it is running the walk — and its offer already
  joins the merge); a far-away self still never displaces a real
  member, and sparse views still yield nil/unenforced.
- **resolver: membership has a §7.5 finality horizon.** A claim carries
  exactly W = 5 witnesses, so pre-fix membership demanded ALL FIVE sit
  in the verifier's CURRENT closest-8 forever — any churn (a witness
  departing in the Aug-31 name cleanup, or lucasvps/camalolo-box
  joining and shifting the keyspace boundary) killed every mature name
  it touched, against §8's "ownership = liveness of the OWNER".
  Membership is now enforced only while the claim is inside its §7.5
  contest window (`now - ts < CONTEST_WINDOW`); past it the claim is
  FINAL and verifies on its timeless evidence (signatures, corroboration
  band, distinctness). The anti-fabrication value is concentrated in
  that window (a fabricated backdated claim must displace a LIVE
  registration there, with its sybils still in the verifier's view);
  the residual — backdate past the horizon with a self-consistent
  quorum — is the §12 Sybil bound, now documented in the spec's §7.3
  and pinned by tests (backdate_test.go: the young fabricated quorum is
  still rejected; the mature honest claim survives churn; both
  residuals assert loudly so a re-tightening cannot happen silently).
  Spec §7.3 amended in the same release.
- **daemon: failed renewal publishes are retried with network
  confirmation.** The renewal pass renews BOTH carriers of a name
  (K_tld + K_claim); when minipc's 14:36 publish hit "accepted by 0 of
  7 peers" on one key while the sibling succeeded, the fresh local copy
  reset ShouldRenew — the failed leg waited a full lease before anyone
  re-signed it, peers served the expired predecessor, and the resolvers
  (correctly) refused it. Unconfirmed puts now land in a retry queue
  that re-publishes (no re-sign) every tick until the network's own
  §6.4 GET returns the exact envelope, or 12 attempts (≈2 h) end in a
  loud operator-directed warning.
- **cli/trustsync: the §9.5.4 system-trust chain stops silently aging
  out.** Three compounding defects, all found the same day: (1) the
  trust bridge's systemd oneshot tripped the default start limit (5
  starts / 10 s) — the daemon touches the spool on every TLSCA
  re-verification — and the path unit went `failed (start-limit-hit)`
  forever, freezing the system CA store while the spool moved on. The
  unit sets `StartLimitIntervalSec=0` and caps path triggers. (2)
  `trust-install`/setup skipped existing unit files, so the boxes with
  BROKEN units could never receive the fix; install is repair-shaped
  now (rewrite on content drift, reset-failed + restart, and
  `trust-install` ensures the bridge too). (3) the spool held expired
  cross-certs (lifetime-capped by the apex record's 24 h lease) and an
  expired copy in the system store POISONS verification — it shares the
  owner CA's subject and deterministic key with the live one, so
  OpenSSL anchors on it and reports "certificate expired" for a name
  whose entire presented chain was valid (found live: minipc curling
  its own webui). The daemon sweeps expired/unparsable spool entries at
  startup and per notification; the bridge copies only certs passing
  `openssl x509 -checkend 0`.

## v0.14.0 — DoH both ways: encrypted upstream + serving /dns-query (spec §9.6)

DNS-over-HTTPS as a first-class switch in each direction, each one line
of config (or one webui toggle), both default OFF:

- **Encrypted upstream** (`[upstream] doh = …`): RFC 8484 POSTs to the
  configured endpoint with the plain `servers` list kept as fallback —
  a DoH outage degrades to exactly today's behavior, never to errors.
  The `[upstream] doh` key existed since pre-v0.7.1 but was parsed and
  never wired; it is now the real thing.
- **Bootstrap-loop fix (the bug under the feature)**: with the standard
  wiring (`resolv.conf → 127.0.0.1`) a HOSTNAME DoH URL deadlock-looped
  through this very daemon — the endpoint's name resolved via the OS
  resolver, which is us, which resolves it via DoH, which needs the
  endpoint's name … Now the endpoint hostname is resolved via the
  plaintext servers and pinned onto the dialer (TLS still verifies the
  URL hostname), and the shipped presets are IP-form URLs
  (`https://9.9.9.9/dns-query`, `https://1.1.1.1/dns-query`) that need
  no bootstrap at all.
- **Serving DoH** (`[doh] serve = true`): the freens-web listener
  answers `/dns-query` for LAN devices — same §9.5 certificate, same
  CIDR gate, same port, no new firewall rules. The HTTPS face relays to
  the daemon's resolver over the admin socket (`POST /dns-query`), and
  a down daemon answers SERVFAIL as a DNS message, never a bare HTTP
  error. `GET /api/doh/root.pem` serves the owner CA for one-click
  device import.
- **Applied live, not at restart**: `POST admin /reload` hot-swaps the
  upstream (a `resolver.UpstreamRef`; in-flight queries finish on the
  upstream they started with). `freens doh upstream quad9` or the
  webui Settings page save + apply in one step; the `[doh] serve` face
  re-reads its switch with a ~2 s cache, so toggling costs nothing.
  The reload re-applies the implicit `9.9.9.9, 1.1.1.1` fallback fill —
  the first fleet run skipped it and silently downgraded the fallback
  to "no servers" on confs (like the fleet's own) that never spell one
  out; the reload response's trailing "fallback )" was the tell.
- **freens-web's home default now matches the platform** (found live on
  the desktop box in the same test): the UI resolved its default home as
  `~/.freens` while the Windows platform default is
  `%ProgramData%\freens` — under LocalSystem that meant the UI read a
  stale keychain, a nonexistent admin socket, and the WRONG freens.conf,
  so its `/dns-query` stayed 404 no matter what the conf said. The
  default is `internal/home.Dir()` now, same as every other component.
- **The controls**: new Settings page in the webui (upstream preset
  picker + serve toggle + device client-URL + self-Test button), new
  `freens doh` verb (`status` / `upstream <preset|URL|off>` / `serve
  on|off` / `test [name]`), and warn-only `doctor` checks (a DoH
  problem never fails the health unit). Config edits go through the new
  `internal/confedit`: comment-preserving line surgery, atomic rename,
  original mode kept, one `.pre-doh` undo generation.

Fleet-verified (server, laurent-minipc, nanopi, desktop): tcpdump shows
upstream traffic is TLS-only (:443) with DoH on; GET+POST DoH queries
verified against the fetched owner CA work from Linux and Windows
clients to Linux and Windows servers; serve off → 404 and back on
without restarting anything; the switch survives daemon restarts.

## v0.13.16 — a slow upstream stops being fatal (upstream retries, upgrade retries, refresh-failure visibility)

Field report from camalolo-box (a fresh box's very first `freens
upgrade`): `lookup github.com on 127.0.0.1:53: server misbehaving` —
three times in a row; the fourth attempt worked. The per-name pattern
(each name failed exactly once, its first-ever query) pinned it: a
COLD upstream resolver took longer than one attempt's budget on a
cache miss, the daemon SERVFAILed the whole box, and the upstream —
which had received the query and cached the answer — was never asked
again. The user's three manual retries were doing what the software
should have.

- **DNSUpstream retries each server (2 attempts, glibc-style) before
  moving to the next** — the retry lands on the upstream's now-warm
  answer. One packet lost or one slow cache-miss no longer SERVFAILs
  every lookup on the machine.
- **`freens upgrade` retries its GitHub fetches once on transport
  errors** (dial/DNS/timeout) — the release API call and the tarball
  download both. HTTP-level errors (404 etc.) stay un-retried: an
  answer is not a hiccup.
- **Namespace refresh failures are now VISIBLE** (the operator-facing
  gap in the stale-serving design): a background refresh that starts
  failing logs ONE WARN ("names not re-verifiable are answered from
  cache until it recovers") and its recovery logs one INFO — transitions
  only, never per kick, so an outage is a single line instead of log
  spam. This also documents the deliberate choice: an UNREACHABLE
  namespace keeps stale answers flowing (better an old address than
  none); only an AUTHORITATIVE negative flushes the address.

## v0.13.15 — the warm set: names in recurring use are cached forever

Operator question, and they were right: "could the daemon look up in
the background all the hosts approaching the window and re-cache them,
so from a client perspective it's always fresh?" The one nuance is
that the background sweep must do REAL revalidations through the
screened path — resetting a timer would serve un-revalidated data
indefinitely and never learn revocations. With real lookups, always-
cached and always-true arrive together:

- **Proactive refresh sweeper**: every 60 s the daemon revalidates the
  WARM SET — positive entries whose last CLIENT hit is within 24 h and
  whose data is expired or about to expire (≤60 s). Any name queried
  at least once a day is answered from cache forever: daemon restarts
  (v0.13.13 persistence), idle gaps (6 h stale window), and now the
  gap beyond both. Each warm entry costs ~one walk per TTL (300 s
  default), batched to ≤16 kicks/tick with most-recently-hit priority.
- **Refreshes do NOT count as hits**: a name abandoned for 24 h drops
  out of the warm set and ages out within the stale window — its next
  query walks once (the pre-sweeper behavior) and it is warm again.
  No ghost set grows forever.
- A side benefit: warm names are re-verified continuously even with no
  client queries, so a revocation or address change is learned
  proactively within minutes rather than at the next client query.

## v0.13.13 — the cache survives restarts; active names never go cold

Field report (desktop, the box this fleet upgrades most): first browse
to `desktop:8090` after the v0.13.12 restart failed, the retry worked —
from the client POV "no caching". Three real gaps, three fixes:

- **The response cache now persists across daemon restarts**
  (`<persist>/dns-cache.json`, saved every 60 s when dirty, restored at
  boot). The entries are §10.4 VALIDATION RESULTS — restoring one
  carries exactly the trust of keeping it in memory — so the restarts
  every upgrade performs stop being a cold-cache walk for the first
  client query afterwards. Entries that EXPIRED while the daemon was
  down restore into the §10.4 stale window (served stale while the
  background refresh revalidates — restart invisible); negatives
  restore but never serve stale, unchanged.
- **The stale window is 6 h** (was 30 min — found live: an idle evening
  still cost the first morning query a walk). The window only ever
  matters while the namespace is unreachable, where the last known
  good address beats none; reachable namespaces self-correct within
  one refresh regardless of window size. Spec §10.4 reference updated.
- **Prefetch (unbound-style)**: a fresh cache hit with ≤60 s of TTL
  left refreshes in the background on THAT hit, so a name in active
  use never reaches expiry at all — the stale path stays reserved for
  genuinely idle names and outages.

## v0.13.9 — setup fixes the nsswitch shadowing (the last mile of first contact)

The closing fix of the fresh-VPS bootstrap saga: on a stock
systemd-resolved system, `/etc/nsswitch.conf`'s hosts line — `files
myhostname resolve [!UNAVAIL=return] dns` — lets systemd-resolved answer
single-label lookups with NXDOMAIN and TERMINATE the glibc chain before
`dns` is ever consulted. resolv.conf and the port-53 redirect were
perfect; `dig <name>` worked; `ping <name>` said "Name or service not
known". The user's verdict was the product requirement: "absolutely
terrible experience — they would probably give up before getting it to
work."

`setup` now runs the fix on every path (including the already-wired
early return): the hosts line drops `resolve` and its attached action
and gains `dns`, the original is backed up to
`/etc/nsswitch.conf.freens-pre`, and a failed privileged write prints
the manual sed with a loud warning instead of a green checkbox over an
armed trap. `uninstall` restores the original. Idempotent; no-op
without nsswitch.conf or without `resolve`.


## v0.13.8 — register's two post-success papercuts (one was real)

Found live 2026-09-01 immediately after the fresh VPS's successful
`lucasvps` registration.

- **REAL: recovery keyfiles were regenerated on every register
  invocation.** Retries re-invoke the recovery plan, and each invocation
  minted fresh keypairs over `<alias>.rec1-3.key` — silently invalidating
  any backup made from an earlier attempt while the banner kept saying
  "keyfiles generated". The plan now **reuses existing keyfiles** (same
  policy, banner: "reused — your earlier backups are still valid"),
  **refuses loudly on a partial set** (restore from backup or delete all
  to start a new set), and generates only on a clean slate.
- **COSMETIC-BUT-SCARY: the K_claim publish poll reported failure for a
  completed publish.** The async replication job can outlive the CLI's
  poll deadline (it grinds through replicas unreachable from this
  vantage while enough others accept). Publish failures now verify
  before failing — four resolve attempts through the daemon; if the name
  is found and not revoked, register prints "publish complete" and exits
  zero.


## v0.13.7 — the witness cooldown stops punishing re-registrations

The final defect in the fresh-VPS bootstrap saga (2026-09-01): the §7.3
`WITNESS_COOLDOWN` keyed on the **alias alone** — one signature per alias
per hour unless the claim hash was byte-identical. But `register` mints a
fresh claim timestamp whenever an attempt's 5-minute present-window lapses
or the daemon restarts, and a new timestamp means a new claim hash — so
**every witness that signed an earlier attempt refused the next one**.
The quorum shuffled itself 3 → 2 → 0 across the friend's retries while
the seed's journal proved the network was answering fine each time.

The cooldown now records the **claimant key** and refuses only when the
claimant *differs*: a claimant re-mining their own pending registration
is not a competing claim — the anti-fraud purpose (a second claimant
racing for the same alias within the hour) is unchanged, and the
existing different-claimant refusal test passes untouched.

## v0.13.6 — a newcomer's bootstrap works by itself, over the internet

Three coordinated defects kept a fresh node at "8 known / 0 confirmed
peers" with a registration that could never collect its 5 witnesses
(found live 2026-09-01 on a brand-new VPS with nothing but the built-in
seed line; the operator's call: fix the code, no hand-patching — "I want
it to work by itself over the internet").

- **Confirm-on-learn**: nothing probed what a newcomer learned. The
  seed's multi-addr advertisement taught it the whole fleet, but
  confirmation only happened if some walk happened to touch a contact —
  so the table sat LAN-preferred (the seed's vantage) and unconfirmed
  forever. Now `learnContact` fires an async probe for every newly
  learned, never-confirmed contact: preferred address first, then recent
  alternates, **promoting the first alternate when the preferred
  misses** — the stored address follows to wherever the peer is actually
  reachable (the seed's table said the LAN address; the internet says
  the WAN mapping; both are learned, the probe settles it).
- **Witness collection survives its client**: `/witness` ran on the
  request's context — the CLI's 15 s admin timeout fired before the
  endpoint's 30 s server cap and the disconnect *cancelled the walk
  mid-flight*. Every retry re-died at the same 15 s mark while the fleet
  was actively witnessing each attempt (the seed's journal shows
  co-signatures landing for all three failed tries). The collection now
  runs detached (own 30 s budget) and the finished quorum is memoized —
  a retry returns it instantly.
- **The CLI's witness call carries its own 45 s timeout** with headroom
  over the server cap, instead of inheriting the shared 15 s.

Tests: learned contacts get probed and confirmed end-to-end; the
dead-preferred + reachable-alternate shape fails over and confirms.

## v0.13.12 — the walk stops landing on the client (serve-stale-while-revalidate) + /certs page completion

Operator-reported (and reproduced live): DNS answers were instant while
cached (§10.4, positive = record TTL, default 300 s) but every expiry
put the FULL screened walk back on the answering path — measured
~100 ms on the warm LAN, 2.1 s when a WAN hop was involved, seconds on
a VPS behind restrictive NAT. The data doesn't change at TTL expiry;
the latency shouldn't either.

- **Serve-stale-while-revalidate (§10.4 amended)**: an expired
  POSITIVE answer inside a bounded window (30 min) is answered
  immediately — it carries exactly the validation the fresh answer
  had — while the resolver revalidates in the background
  (single-flighted via the existing flight table, semaphore-bounded,
  one kick per 5 s per name so an unreachable namespace can't spin).
  The fresh outcome — positive OR negative — replaces the entry, so
  revocations/rotations still propagate within TTL + one refresh; a
  failed refresh never poisons the cache (the last known good address
  keeps being answered until the window closes — better an old address
  than none during an outage). Negative answers NEVER serve stale, and
  the contested-alias re-consultation cadence (§7.5) is preserved by
  the same background refresh. Stale answers carry a short DNS TTL
  (30 s) so client stubs re-ask soon. New metric:
  `freens_resolver_cache_stale_total`.
- **/certs page completion** (the "is it ergonomic" review): the flow
  publish → issue → clone → renew now lives on ONE page — an inline
  "publish a sub-name" form (reusing the name endpoint, auto-reload on
  success) starts it; expiry shows the absolute UTC stamp under the
  countdown; cloned vhost files wear a "freens-managed" badge so
  operators can tell our output from hand-written configs at a glance.
- **CLI: names can lead**. `freens cert nginx www.camalolo -clone
  camalolo.com` now parses as typed — Go's flag package stops at the
  first positional, and every cert verb needed its flags first (found
  live during the rollout). `flagsFirst` reorders with value-flags
  kept attached; applied to all cert subcommands.

## v0.13.11 — certmgr CI hotfix (hermetic binary-resolution test)

One line on top of v0.13.10, no behavior change: the
TestResolveBinarySbinCandidates added with certmgr assumed nginx is
never on PATH, but GitHub's Ubuntu runner images preinstall it — the
test now stubs the LookPath seam so it passes on any image. Everything
below is v0.13.10 verbatim.

## v0.13.10 — certmgr: letsencrypt-like certificate management, nginx included

The §9.5 layer proved the trust model works (fleet-tested since
v0.9.3-tls); what it lacked was the certbot half: certificates were
issued once by hand, expired silently after their 7-day TTL, and
non-daemon servers (nginx!) had no path from "here is a PEM" to "this
vhost serves it". `internal/certmgr` closes that gap — issuance,
renewal state, nginx deployment, reload — as ONE package so the CLI and
the web UI cannot drift (the keychain lesson, applied to certs).

- **Renewal tracking** (`<home>/tls/renewal/<name>.json`): every
  `freens cert <name>` now records its file paths + expiry + deployment
  targets (one-shot exports opt out with `-no-track`). `freens cert
  renew [name…]` re-mints every certificate with < 48 h left IN PLACE
  (same paths, fresh key per §9.5.3 — atomic renames, servers never see
  a half-written file), reloads nginx for deployed certs, and runs
  per-cert deploy hooks (`-deploy-hook`). Exit code non-zero on any
  failure — cron/timer friendly with `-quiet`.
- **`freens cert nginx <name>`** (the certbot --nginx shape): scans the
  config tree (conf.d, sites-enabled, symlinks resolved so a vhost is
  seen exactly once; backup litter like `*.freens-pre`/`*.dpkg-*` never
  matches), finds the server block by server_name, backs the file up as
  `*.freens-pre`, injects `listen 443 ssl` + the certificate pair at the
  block's own indentation (or REPLACES a foreign certificate with
  `-force`), validates with `nginx -t` — restoring the backup if the
  test fails — and only then reloads. `cert list` / `cert forget` round
  out the table management.
- **`-clone <existing-server-name>`** (the case the edit path can't
  serve): the site already lives at a vhost with its own VALID
  certificate (camalolo.com under Let's Encrypt) — editing that block
  would swap a perfectly good third-party cert. Clone instead: every
  block mentioning the source name is copied into a NEW
  `freens-<name>` file (sites-available + enabled symlink on Debian,
  sibling `*.conf` in conf.d trees), with server_name → the freens
  name, the certificate pair → ours, and the non-transferables stripped
  (`default_server` would collide; `ssl_stapling(_verify)` expects an
  OCSP endpoint a §9.5 leaf deliberately lacks). Everything else —
  locations, proxies, PHP, includes, even `return 301
  https://$server_name…` redirects, which resolve to the new name —
  passes through byte-for-byte, and the SOURCE file is never opened for
  writing. A failed `nginx -t` removes the clone, leaving the tree
  byte-identical. The webui's nginx table grew the same affordance:
  blocks that already serve a freens name get "Use this certificate",
  foreign ones get "Clone this vhost for a freens name".
- **nginx discovery now finds /usr/sbin/nginx** (found on this very
  box: the binary lives outside a normal user's PATH, so every
  discovery call from the user-owned CLI and daemon-user webui failed
  before ever reaching `nginx -V` — PATH is tried first, then the sbin
  candidates).
- **The Certificates page in freens-web** (`/certs`): every owned name
  (apexes + the store's sub-names) with cert status/expiry, Issue and
  Renew buttons (passphrase field appears when the owner key is
  encrypted), "Renew all due", and the nginx half: every server block
  on the box with its TLS state and a "Use this certificate" button.
  Same code path as the CLI (certmgr), including the automatic
  passwordless-`sudo -n` fallback for root-owned config dirs (never
  interactive — a web handler cannot hang on a prompt).
- **doctor** grew a tracked-certificate section (warn-only by design:
  the daily timer self-heals a lagging cert, so "due" must not paint
  the health unit red — EXPIRED and file-missing are loud warnings).
- **`contrib/systemd/freens-cert-renew.{service,timer}`**: the daily
  `freens cert renew -quiet` unit, freens-health's shape (hardcode
  FREENS_HOME on XDG-layout installs — the %h gotcha again).

Trust is NOT part of this: visitors still validate through the TLSCA
RR + cross-cert chain exactly as before (§9.5.4). certmgr only answers
"which certificates exist, where do they live, when do they expire,
and which server blocks serve them". WebPKI comparison note: LE's
domain-validation challenge exists because the CA doesn't own the
namespace — freens' owner key IS the authorization, so issuance needs
no network at all.

## v0.13.5 — the seed's first answer carries the whole fleet

Operator idea, prompted by a friend's lab box reporting itself an
"offline island" with the seed "down" (the seed was fine — the lab's
probes never left its own network — but the report exposed the real
weakness): `{nodes}` advertisements now carry **one entry per known
address** per peer, not one entry per peer.

A newcomer's very first `find_node` against the seed therefore returns
the entire community at LAN+WAN: every peer's every address. Concretely:

- **Wire format unchanged** — same `[ip, port, nodeID, pk]` CBOR
  entries, just more of them. v0.13.3+ receivers merge same-NodeID
  entries into one multi-homed contact (their v0.13.3 `Alts`);
  pre-v0.13.3 receivers re-learn them the old overwrite way (transient).
- **No single point of failure**: the seed dying an hour after bootstrap
  strands nobody — every node a newcomer ever talked to is a redundant
  anchor with every address it knows, and each newcomer forwards the
  same richness to the next.
- **The anti-ghost invariant holds**: advertisement never confirms —
  learned addresses still need a direct verified exchange before they
  count as alive (pinned by test).

## v0.13.4 — the UI can no longer lie about its own version

Two hardening fixes straight out of the desktop box's stale-UI ghost
(2026-09-01: the freens-web process served pre-upgrade templates through
two "successful" upgrades while every version surface showed fresh
stamps — the page footer renders the DAEMON's version, so nothing ever
asked the UI what IT was).

- **`/healthz` reports the webui's own build stamp**:
  `{"status":"ok","version":"v0.13.4"}` from the binary itself, not the
  daemon. The one version surface that cannot lie about the UI process.
- **The upgrade verifies it**: after restarting services, the health
  check polls the webui's `/healthz` (port from `[webui] listen`,
  default 8090; redirect-following, TLS-skipping — the §9.5 chain is
  self-certified, reaching the process is the point) and prints
  `webui back: version X` — or a warning naming the exact remedy when
  the stamp predates the installed release. Best-effort, like the daemon
  check: warns, never fails the upgrade.
- **HTML responses are `Cache-Control: no-store`**: a browser page
  cached across an upgrade renders the OLD template skeleton around the
  NEW 30-second polling fragments — the peers heading drew twice exactly
  this way, and the mixture looks exactly like a server bug. Assets keep
  their 1-hour public cache.

## v0.13.3 — multi-homed contacts + the Windows webui-service restart fix

Diagnosed by the operator, found live on the desktop box (2026-09-01):
"maybe the same id for 2 IPs is the issue? camalolo is actually on LAN and
WAN at the same time." Exactly. The routing table kept one slot per node
and **overwrote the address** on every re-learn, so a node reachable at
two addresses (the seed: public IP on ppp0 + the operator's LAN) made the
stored address flip-flop between them depending on who taught us last —
and a probe timeout against whichever was stored at the moment evicted the
node whole. The peers table then showed the seed's address "coming and
going".

- **Routing table**: `NodeContact` now carries `Alts` — other known
  addresses with their own last-seen/confirmed stamps, LRU-capped (4 per
  node). A re-learn at a different address accumulates instead of
  clobbering. The preferred address is the freshest *confirmed* one
  (strict comparison, so same-second ties keep the incumbent — no
  ping-pong).
- **Probe failure failover**: a missed probe first switches the preferred
  address to a recent alternate (clearing the failed address's
  confirmation per the anti-ghost invariant) before demoting the node;
  the §6.2 bucket-pressure quiz also pings the alternates and promotes
  the answering one. A node is only "dead" when **every** known address
  is — and a laptop that leaves the LAN fails over to the WAN address on
  its own.
- **Surfaces**: admin `/peers` and the webui peers table carry and render
  the alternates ("also <addr>" under the preferred).
- **Snapshots**: the persisted peerbook gains an optional `alts` field —
  old binaries ignore it, new binaries read old snapshots.
- **Windows upgrade fix**: the upgrade stopped/restarted only the `freens`
  SCM service around the binary swap, so `freens-web` kept running its
  renamed-aside image — the UI reported the old version and served old
  embedded templates (the doubled "Peers (N)" heading) until a manual
  restart. The upgrade now stops both services first and restarts both
  after (absent web service on pre-v0.13.0 installs handled).

## v0.13.2 — one missed probe no longer evicts a confirmed peer

Found live on the desktop box (2026-09-01): its only non-LAN anchor — the
community seed, reachable solely through a NAT'd public path — was being
hard-evicted from the routing table whenever a single 2 s lookup probe
tripped (NAT mapping churn / PPPoE jitter), the 30 s dead penalty then
suppressed re-probing, and the peers table showed the seed gone until some
walk happened to re-learn and re-confirm it. Visible in the UI as the
seed's address "coming and going", and in the daemon log as a `dht:
bootstrapped peer` line at every re-add.

All four walk failure paths (iterative get, find_node round, claims
lookup, evidence walk) now share one `probeFailed` handler: a contact
with a direct confirmation on record **keeps its slot**, demoted back to
probation (`ConfirmedAt` cleared — the peers surface shows it as
advertised until the next successful exchange re-stamps it, typically
within one 30 s dead-penalty window). A never-confirmed contact — or one
already demoted by an earlier miss — is still removed exactly as before,
so genuinely dead peers converge within a probe round rather than
zombie-ing for the full idle TTL. Bucket-pressure eviction (§6.4 step 3)
and the idle sweep are untouched.

Also: the Network page no longer renders its "Peers (N)" heading twice
(the static page and the polling fragment each drew one).

## v0.13.1 — honest warm-up states + the peers-table fix

Three fixes for the post-restart window where a freshly booted daemon has
a loaded peerbook but zero *confirmed* contacts, so lookups fail and every
surface showed a misleading ✗ (found live three times on 2026-09-01: the
post-wake upgrade restart on the desktop box). Plus the one-line decode
bug behind the webui's eternal "never confirmed":

- **Startup ping sweep**: the daemon pings every learned peerbook contact
  immediately at boot (2 s budget each, parallel) instead of waiting for
  the first refresh tick — the routing table carries CONFIRMED contacts
  within seconds of a restart.
- **`/status` gained `confirmed_peers`**: routing-table size says nothing
  about reachability (the peerbook fills it instantly); consumers can now
  distinguish "warming up" from "broken".
- **Doctor**: the peer check reports the confirmed count, and the
  no-contacts-yet state renders as the ✱ warning "WARMING UP" instead of
  a bare count; alias-resolution failures during warm-up say "still
  warming up".
- **Webui peers table fix** (the one-line decode bug): the /peers handler
  has emitted each contact's confirmed-since timestamp since the issue-#2
  machinery, but the admin client decoded only addr+pk — so every webui
  peers table rendered "never confirmed" + the "advertised" badge for
  LIVE, ping-verified peers, on every platform, forever. The client now
  decodes and propagates the field; the table also polls every 30 s and
  the Dashboard health card shows "✱ resolver warming up (peers not
  confirmed yet — a moment after a restart)" during the window, with
  auto-refresh so states clear themselves.

## v0.13.0 — the web UI is always there (service on every OS) + automatic http→https

"Setup installs the daemon but the UI needs hand-standing-up" was true on
one platform and half-true on the rest. Now setup keeps the LAN management
UI running everywhere — and the one UI port speaks both dialects: typing
`http://<name>:8090` gets a 308 upgrade to the encrypted UI instead of a
connection reset (found live on the desktop box, where a plain-typing
visitor saw ERR_CONNECTION_RESET with zero guidance). The auto-upgrade is
the Caddy trick: each accepted connection is sniffed on its first byte
(0x16 = TLS ClientHello, ASCII = plaintext HTTP), TLS serves the UI as
before, plaintext gets `308 → https://<typed-host>:8090/…` with HSTS set
so the browser upgrades itself from then on. No-leaf installs keep the
plain-HTTP fallback unchanged (nothing to upgrade to). Shutdown drains
both dialects (accept loop, TLS server, redirect server, per-conn
one-shot listeners) — tested against a real §9.5-minted leaf on ephemeral
ports via the new `BoundAddr` accessor.

Service story, per platform:

- **Windows**: freens-web gains the SCM service handler the daemon has
  (v0.11.0 pattern — the SCM hands Execute the service name; the real
  command line is os.Args; Stop drains the server bounded, then Stopped;
  service logs to <home>\webui.log with 8 MiB rotate). setup installs it
  as the second service "freens-web" (automatic start, restart-on-
  failure, same recovery ladder) and adds the inbound firewall rule
  "freens-web UI" (TCP 8090, port-scoped); `freens uninstall` (and
  `setup -uninstall`) remove both. webui.Server grew a real Shutdown
  (the SCM stop path waits for the listener race, then drains) — the
  console binary's SIGTERM handling now uses the same graceful path
  instead of os.Exit.
- **Linux**: setup writes and enables freens-web.service next to the
  daemon unit (same user + FREENS_HOME env conventions, Restart=on-
  failure, After=freens.service). Idempotent: an existing unit is left
  untouched (hand-tuned fleet units survive re-setups); a hand-built
  freens without a freens-web binary beside it silently skips the UI.
  `freens uninstall` already removed the unit — now setup is its mirror.
- **macOS**: setup (darwin branch) installs the com.freens.webui
  LaunchAgent (RunAtLoad + KeepAlive, FREENS_HOME carried) and loads it;
  `freens uninstall` unloads+removes it. Flagged fleet-untested (no mac
  in the 3-box LAN fleet); the daemon story on macOS remains a manual
  run and setup says so.

## v0.12.0 — self-healing renewals, async admin publishes, `forget` + `uninstall`

Four operations findings from the 2026-08-31/09-01 cleanup session, plus
the two verbs the cleanup runbook was missing:

- **Auto-renewal sequence stall (found live on the seed box):** the
  daemon's `renewOnce` published a renewal at seq N+1 to the peers but
  never installed it in its OWN store, so every later tick re-read the
  stale N, re-signed a *different* envelope at the same N+1 (fresh
  timestamps), and was refused everywhere — `accepted by 0 of 7 peers`
  every ten minutes while the network record starved toward its lease
  end. The same stall silently explains pre-upgrade records never
  gaining their §9.5 TLSCA binding (camalolo needed `renew -force` by
  hand). `renewOnce` now feeds the fresh envelope back into the local
  store (K_tld/K_name + K_claim, mirroring the admin handler's
  storeLocally), so the sequence advances exactly once per lease.
- **Idempotent puts are no longer refusals:** an envelope carrying the
  ALREADY-STORED record (identical §6.4 H_record — replica refreshes,
  duplicate renewals) now returns success from the store instead of
  losing the winner check. Republish loops read honest acceptance
  counts; "accepted by 0 of N" regains its meaning as genuine refusal.
  A stale-sequence re-put still cannot resurrect over a live higher
  sequence (the identical-check compares against the CURRENT incumbent).
- **Async admin publishes:** POST /publish accepts {"async":true} →
  202 {"job": id} with the outcome at GET /job/{id} (registry: done /
  accepted-count / error, pruned after an hour). The CLI's
  Publish/PublishClaim always ride the job under a 2-minute budget —
  the keyed K_claim leg walks its own keyspace and can outrun any sane
  HTTP budget (found live: the client died at 15 s while the
  daemon-side publish completed a minute later). Wire-compatible both
  ways: a pre-async daemon ignores the field and answers the old
  synchronous shape, which the client treats as the final result.
- **`freens forget <name>`:** the cleanup verb the runbook was doing by
  hand — revoke (the §9.5 tombstone, signed while the key still exists)
  THEN prune the key material (owner key, §8.4 recovery keys, parked
  claim state) in that order; a failed revoke keeps the keys. Names
  that are absent or already revoked skip straight to pruning.
  `-keep-keys` is plain revoke; `-yes` is required in non-interactive
  sessions (deleting key material is the one-way part). Sub-names under
  the apex are separate records and are called out in the output.
- **`freens uninstall`:** the one-command removal matching what setup and
  the ecosystem put on the machine: stop + disable every ACTIVE freens*
  systemd unit (discovered — daemon, freens-web, comm chairs — plus
  timers like freens-health), remove the unit files (globbed, regular
  files only, legacy --user unit included), reverse the OS resolver
  wiring (shared code with `setup -uninstall`), then the optional
  extras: `-trust` removes the §9.5 local root + cross-cert anchors
  from the system CA bundle and the spool tree (NSS profiles get the
  exact certutil commands printed — they are per-user databases);
  `-purge` deletes the ENTIRE state dir (keys!) and is gated by -yes in
  scripts. Windows routes through the SCM uninstall core under one UAC
  gate with the flags preserved through the relaunch.
- **setup writes the relocated-state env into the unit** (found live
  during the fleet deploy of this very build): re-running `freens setup`
  on a XDG-relocated install wrote a freens.service WITHOUT
  `Environment=FREENS_HOME` (the line had only ever been hand-patched),
  forking a second daemon at the default ~/.freens — admin socket and
  keychain scanning (auto-renew) misdirected while the -config path
  still looked right. setup now emits `Environment=FREENS_HOME=…` into
  the unit whenever the variable is set at install time.

## v0.11.0 — Windows 10/11: SCM service + automatic setup

Windows goes from "unsupported" to the same one-command story as Linux:
`freens start <name>` (or `setup` step by step) installs the daemon as a
real Windows **service**, wires the OS resolver, and survives reboot —
with UAC doing what sudo does on Linux.

- **State model**: `home.Dir()` on Windows defaults to
  `%ProgramData%\freens` instead of a per-user profile. The daemon is
  machine infrastructure there — the SCM service runs as LocalSystem
  while every user's CLI and freens-web must find the SAME keychain and
  admin socket, which separate profiles would split. `FREENS_HOME`
  still overrides for everything.
- **Admin socket**: the `\\.\pipe\…` placeholder is gone — Windows has
  AF_UNIX since Windows 10 1803 (and Go supports it since 1.17), so the
  same `<home>\admin.sock` filesystem path serves daemon + CLI on both
  ends with zero new code.
- **`freens setup` (setupwin.go)**: self-elevates via UAC
  (`Start-Process -Verb RunAs`, `-console-wait` keeps the elevated
  child's window readable), then: state layout → `freens.conf` with the
  resolver DIRECTLY on `127.0.0.1:53` (Windows has no privileged-port
  concept — the whole Linux redirect scheme does not apply) → seeds →
  SCM service `freens` (LocalSystem, automatic start, restart-on-failure
  recovery via x/sys `svc/mgr`, internal/winsvc) → program-scoped
  inbound firewall rule for UDP 15353 (Windows Defender silently drops
  DHT inbound otherwise) → adapter DNS wiring.
- **OS resolver wiring**: every adapter that CARRIES DNS servers is
  pointed at 127.0.0.1 via PowerShell
  (`Get-DnsClientServerAddress | Set-DnsClientServerAddress` — blank
  slates are never touched), with the captured per-adapter lists saved
  to `<home>\dns-backup.json` so `-uninstall` restores exactly what was
  there (the resolv.conf backup convention, per-adapter). Conventional
  names forward to the upstream servers captured from those same
  adapters at setup time (`[upstream]` in freens.conf — public
  resolvers as fallback). Single-label freens names work through the
  OS resolver's suffix-devolution: the suffixed query NXDOMAINs at the
  daemon, the bare-name retry then hits the alias.
- **Service plumbing** (cmd/freens service_windows.go): when launched
  by the SCM, the binary answers the service control protocol while the
  ordinary daemon runs unchanged in a goroutine; Stop/Shutdown close a
  channel that run()'s signal select treats exactly like SIGTERM (one
  shutdown sequence for console and service alike). A service has no
  console, so slog goes to `<home>\daemon.log` (8 MiB rotate-on-start
  to daemon.log.1).
- **`freens upgrade` on Windows**: the release asset is
  freens-windows-amd64.tar.gz with .exe-named binaries (staging
  normalizes the suffix, so all downstream naming stays GOOS-agnostic);
  Windows refuses rename-over a RUNNING image but allows renaming it —
  installBinary moves the old image aside (.freens-old) and slides the
  new one in; the service is stopped before the swap and restarted
  after (a non-elevated run refuses early with the reason instead of
  half-failing on a locked binary).
- **doctor/status/start** learned the Windows wiring model
  ("resolver points at daemon" = an adapter carries 127.0.0.1;
  ":53 path complete" = the daemon's port IS 53) and the `net start
  freens` fix-it hint.
- **§9.5 trust on Windows**: `freens trust-install` imports the local
  root into the WINDOWS certificate store via certutil (machine store
  when elevated/per-service, per-user fallback), and cross-certs land
  in the intermediate (CA) store — Chrome/Edge verify against the
  Windows store, not NSS; Firefox manages its own. trustsync's unix
  plumbing (system bundle + NSS) moved to store_unix.go, the Windows
  counterpart lives in store_windows.go.
- **Release/CI**: release.yml builds windows/amd64 (4→5 platforms);
  ci.yml adds a windows vet+build job (unit tests stay linux-run:
  several suites lean on unix sockets/paths the Windows port
  deliberately does not emulate).
- **Field fixes from the first live run (desktop, Win11 26200, same day)**:
  - **SCM arg delivery**: the service manager hands `Execute` the SERVICE
    NAME, not the ImagePath arguments — the daemon flag-parsed nothing and
    silently ran config-less (DNS up, DHT + admin socket dead). The handler
    now takes the real command line from `os.Args`, and `run()` REFUSES
    unexpected positionals so "started with defaults by accident" can
    never happen quietly again.
  - **Windows has no directory-fsync**: keychain writes ended with the
    Linux durability idiom `open(dir)+Sync()`, which fails with
    ERROR_ACCESS_DENIED there (first `setup` died writing node.key). The
    dir-sync is now skipped on windows (the rename's durability falls to
    NTFS journaling; the write itself was always durable).
  - **Hardened machines run BlockOutbound** (desktop does, all profiles):
    every unsigned binary's connect() fails with WSAEACCES while signed
    tools work — invisible until a real daemon ran. setup now adds a
    program-scoped OUTBOUND allow rule for the freens binary (upstream
    DNS, DHT peers, `upgrade` downloads) next to the inbound DHT rule,
    and netsh rules are delete-then-add so re-runs don't duplicate.
  - Verified end to end on the box: setup (via UAC-elevated run), service
    install + SCM stop/start, AF_UNIX admin socket, adapter DNS wiring,
    conventional-name forwarding, cross-box freens name resolution, and a
    live `register` (passphrase-protected key, PoW, 5 witnesses) whose
    name propagates to the Linux fleet boxes.
- **§9.2 suffix rescue** (`[options] suffix-rescue`, v0.11.0, found
  necessary live): the Windows resolver NEVER resolves single-label
  freens names — it appends a DNS suffix ("desktop.lan") and never
  retries the bare form (NRPT "." rules don't help; traced via the DNS
  Client operational log). With the option on, a name whose last label
  has no explicit route that upstream NXDOMAINs falls back to a freens
  lookup of the name minus that label. Real domains answer upstream
  before the rescue can run, explicit routes never rescue, and the
  rescued answer echoes the ORIGINAL qname. Windows setup pairs it with
  a "freens" connection suffix on every wired adapter — the freens-first
  route's own miss borrows the bare name, so `desktop.freens` just reads
  as `desktop`.

- **Toolchain note for Windows builds from source**: Go 1.26.0/1.26.1
  carry a known Windows runtime regression (golang/go#77975, fixed in
  1.26.2 via #78041) that intermittently hard-faults the claims-verify
  path during heavy concurrent use — observed during this release's
  field testing, confirmed against 20 clean runs on 1.26.2. Build with
  Go 1.25.x (CI/release default) or 1.26.2+; release binaries are
  unaffected (built on 1.25).
- **Fixed on the way**: internal/upnp did not compile on Windows at
  all (a raw-fd `IP_MULTICAST_IF` setsockopt with the linux fd type) —
  the multicast interface pinning now has a windows twin using
  syscall.Handle, keeping the identical {INADDR_ANY, interface} layout.

## v0.10.0 — `freens upgrade`: one-command self-update from GitHub releases

The fleet's deploy procedure until now was scp-tarball-then-systemctl per
box (see the release checklist); this replaces it with the verb the
daemon has always wanted:

    freens upgrade            # latest release: download, verify, install, restart
    freens upgrade -check     # read-only comparison against api.github.com
    freens upgrade -yes       # the non-interactive form (scripts, fleet ssh)
    freens upgrade -version v0.9.1   # pin a tag (a plain number gets the v)

The flow, end to end on the target machine:

- **Fetch**: `releases/latest` (or `releases/tags/<vX.Y.Z>`) via the REST
  API; the platform asset is picked by the CI naming scheme
  (`freens-<goos>-<goarch>.tar.gz`, release.yml). `GITHUB_TOKEN` is
  honored for the API budget.
- **Verify before touching anything**: the tarball is unpacked member by
  member (only the three release binaries, size-capped) into a staging
  dir, and the staged `freens` is EXECUTED: it must run and report
  exactly the target tag via `freens version`. CI ships no checksums, so
  "does the binary identify as the release?" is the download-integrity
  check — a truncated or cross-arch tarball dies here, before a single
  byte of the live install changes.
- **Config migrations run through the NEW binary**: `upgrade` execs
  `<staged>/freens upgrade-migrate -from <old>` before installing. This
  ordering is the whole point — a migration for a (v0.9.1 → v0.9.3-tls)
  transition can only be known by v0.9.3-tls' code, which the running
  old binary cannot contain. `upgrade-migrate` is a real (internal)
  dispatch verb, applies the idempotent `configPatches` table, and backs
  the config up once as `freens.conf.pre-upgrade` (setup's
  resolv.conf-backup convention). First patch: `webui-name` (since
  v0.9.3) pins `[webui] name` to the keychain's single owner alias when
  the section lacks a name — freens-web's alphabetical fallback is the
  wrong name for multi-alias owners (found live on the v0.9.3-tls
  deploy; AGENTS.md says SET IT — now the upgrader sets it).
- **Install in place, atomically**: each binary lands as
  `<target>.freens-new` in the SAME directory (rename(2), no gap where
  no binary exists) and renames over the running image — legal on
  Linux, the open inode keeps executing the old code through the rest
  of the verb. Privileged install dirs go through setup's
  sudoRun sequence (passwordless → interactive on a TTY → manual
  commands printed); user-writable dirs skip sudo entirely. The
  previous binary is kept as `<target>.freens-prev` — copy back +
  restart to roll back.
- **Restart + health**: every ACTIVE `freens*` systemd unit is
  discovered (`systemctl list-units 'freens*'` — daemon + freens-web +
  comm chairs), daemon first and webui last, restarted via the same
  sudo path; if the admin socket answered before the upgrade, the verb
  polls it for 20 s afterwards and reports the daemon's version and
  peer count.

Safety rails: `-check` touches nothing; a dev/unstamped build, an
up-to-date install, or a downgrade each refuse without `-force`; a
non-TTY run without `-yes` refuses (no surprise rewrites from cron);
identical binaries (sha256) are skipped. The freens-cli shim now
stamps its ldflags version into the shared CLI so `freens-cli upgrade`
compares correctly too.

Tests: version parse/compare (numeric triples, repo-style `-suffix`
ordering, dev stamps), asset selection, staging + verification against
a built tarball, the migration table (apply/skip/no-op/idempotence),
unit discovery ordering (daemon first, web last, failed units
excluded), and the full download→verify→migrate→install→restart
flow against a fake GitHub and a fake install dir.

## v0.9.3-tls — §9.5 self-certifying TLS: spec + implementation (fleet-tested)

HTTPS for freens names in stock browsers, between freens users, with no
central CA. Spec §9.5 written first (see the design entry further down),
then implemented and verified on the 3-box LAN fleet.

Implementation (this pass):

- `internal/tlsca`: §9.5.1 owner-CA derivation (P-256 from SK_tld via
  HKDF, self-signed, CN=alias + OU "freens owner ca"), local roots,
  constrained cross-certs, leaves. stdlib x509 + x/crypto/hkdf only.
- `internal/trustsync`: §9.5.4 visitor-side engine wired to the resolver's
  screened answer path — mint cross-certs on verified TLSCA RRs, install
  into spool/NSS/system stores, purge on rotation (tld_id change) and
  §8.5 tombstones. Admin `GET /tls` reports state; `freens doctor` checks
  it.
- Resolver: `TLSTrustSync` hook (async, screened-path-only, dead-alias
  notifications at the apex hop).
- Renewal: `EnsureTLSCA` — every apex publish/renew/auto-renew carries the
  binding; same-CA detection compares the full TBS identity (subject, key,
  serial, validity, constraints) so template upgrades migrate at the next
  renewal instead of leaving records authorizing certs no server presents.
- CLI: `freens cert <name>` (leaf+CA PEM export), `freens trust-install`
  (one-time per-device root import: system bundle + NSS).
- freens-web: HTTPS by default with the leaf of `[webui] name` (default:
  first keychain alias), plain-HTTP fallback when no key is issuable;
  `[webui] tls = false` opts out.
- Fleet results: server↔minipc↔nanopi HTTPS all verify (ssl_verify 0,
  cross-namespace included); Chromium + curl + NSS all accept the chain
  and REJECT a rogue leaf for bank.com signed by the same owner CA
  (nameConstraints enforced: OpenSSL err 47, NSS -8080). Live purge and
  re-mint verified via revoke/un-revoke of a test name.

Bugs found live during the fleet test (all fixed):

- Leaf/CA subject collision made OpenSSL treat the leaf as self-signed
  (leaf now carries no OU).
- 20-byte serials with the high bit set DER-encode to 21 octets; NSS
  rejects the cert outright. Serial top bit now masked.
- Chromium's Chrome-Root-Store verifier ignores NSS non-anchor
  intermediates — cross-certs install as trusted-but-name-constrained
  anchors (`certutil -t C,,`).
- `%h` in systemd unit ExecStart expands to /root regardless of User= —
  freens-web's `-config %h/...` silently read a nonexistent file;
  contrib unit fixed (no -config; FREENS_HOME drives it) and deployed.
- trustsync unit tests could touch the real user NSS DB (installer not
  gated by options); now isolated.

Known warts (documented in spec): first-visit retry (§9.5.5); the
resolver's response cache can delay purge/refresh by up to the cached
TTL; un-revoking an apex needs a same-identity carrier (register
re-mines and hits the §8.4 reuse window — scratch path proven on the
fleet, a proper `freens un-revoke` verb is the follow-up; atlantic was
recovered this way).

## v0.9.3-tls (spec design entry) — self-certifying TLS: HTTPS for freens names in stock browsers

Design addition, no code yet (per decision: spec first, implementation
follows). Answers the cross-user case: MY browser must trust a FRIEND's
certificate for HIS machine, transparently, with no per-friend imports.

Mechanism (spec §9.5, + §9.4 stage 2, §10.6, §4.3 RR, Appendix A/D):

- The CA for a namespace is the name OWNER: CA key derived
  deterministically from SK_tld (HKDF, "freens-tls-ca-v1") — no new
  secret to back up; transfer/rotate re-keys TLS for free.
- The CA binding is published INSIDE the signed apex record (new
  TLSCA RR, type 65280, DER cert) — resolution is the distribution
  and authentication mechanism.
- Visitors' daemons cross-certify the owner CA into a name-constrained
  intermediate (dNSName { alias, *.alias }, lifetime capped by record
  expiry) under a once-generated local root installed at setup.
  Stock browsers then verify a normal chain; a stolen owner CA can
  only misrepresent its own namespace; WebPKI names unreachable.
- Leaf certs: SNI-issued, ≤ 7 d, P-256, no CRL/OCSP (short-lived +
  rotation is the revocation story); PEM export for non-daemon TLS
  endpoints.
- Known wart, documented: first https:// visit to a never-seen
  namespace may fail once (trust sync races the handshake); retry
  succeeds (§9.5.5).

Mechanism details as implemented are in the entry above.
## v0.9.2 — DDoS hardening: global pre-verify packet budget + walk caps

From a resilience review of the flood paths (the v0.7.1 audit covered
memory bounds and per-source-IP throttling; this pass asked what a
*DISTRIBUTED* attacker gets). Two structural gaps, both now closed:

1. **Pre-auth CPU exhaustion.** Everything inbound — canonical-CBOR
   decode and the Ed25519 verify — runs on the single `readLoop`
   goroutine, and an *invalid* signature costs the same verify as a
   valid one. The per-source-IP buckets (50 get/s, 10 put/s) bound one
   source's share, but a botnet or a spoofed-source flood draws a
   fresh bucket per source: the aggregate was unbounded. A
   well-formed-CBOR, garbage-signature flood pinned one core at full
   verify cost with no gate in front of it.
2. **Work amplification.** Every distinct inbound DNS/DHT question can
   fan out into a multi-second iterative walk (rounds × ≤K probes).
   Single-flight collapses *identical* questions, but a distinct-name
   query flood — always a cache miss by construction — opened unbounded
   concurrent walks; the inbound packet budget can't see it (each
   question is one cheap packet).

Changes (all Go-level `NodeConfig`/`Resolver` knobs, defaults far above
honest traffic; negative disables each):

- **`NodeConfig.PacketRateLimit`/`PacketBurst` (default 1000/s, burst
  2000)** — one GLOBAL token bucket consulted at the very top of
  `handle()`, before decode and verify. Excess datagrams drop silently
  (never answered — answering an unverified source would aid
  amplification). Two fields behind one mutex; no map, no sweep,
  nothing an attacker can grow. Bounds the aggregate decode+verify CPU
  whatever the source distribution.
- **Stray-response pre-verify filter** — a `y="r"/"e"` message whose
  txid matches no in-flight `sendQuery` is dropped *before* the
  Ed25519 verify: one map lookup instead of one signature check.
  Legitimate replies always pass (`sendQuery` registers the txid
  before its query leaves the socket); a benign race with a
  just-timed-out query drops a reply nobody is waiting for.
- **`NodeConfig.WalkConcurrency` (default 64)** — a non-blocking
  semaphore held for the whole walk in `IterativeGetDetailed`,
  `CollectClaims` and the §8.4 evidence walk. A saturated budget
  refuses immediately with the new `ErrWalkBusy` (never queues —
  queueing would pile one goroutine per waiting query onto the flood).
  Islands (empty routing table) never consume a slot;
  `IterativeFindNode` (the registration client's self-initiated
  table-population walk) is deliberately not gated.
- **`ErrWalkBusy` maps to SERVFAIL, never NXDOMAIN, never cached** —
  on both resolver claim paths (ClaimSetResolver and legacy
  ClaimResolver), exactly like `ErrDegradedMiss`: an overloaded
  resolver must not let "busy" masquerade as "does not exist", or a
  flood would park 60 s negative TTLs on arbitrary names.
  `DHTLookup.CollectClaimsWithWitnesses` likewise serves a LOCAL claim
  under `ErrWalkBusy` (a saturated walk does not invalidate what this
  node already holds); only an empty-everywhere overload propagates.
- **`Resolver.MaxConcurrentResolutions` (default 64)** — the LEADER of
  each distinct resolution needs a slot (lazily built semaphore;
  followers of an in-flight question join free, preserving the
  v0.7.1 single-flight semantics). Refusal is an immediate
  SERVFAIL-class error, which `ServeDNS` never caches.

Documented residual: the §8.4 evidence fetch inside the resolver's
chain verification folds fetch errors into a boolean, so an
`ErrWalkBusy` there degrades to an ordinary verification failure
(NXDOMAIN) rather than SERVFAIL — reachable only for recovery-root
names while simultaneously walk-saturated; the resolver-level cap
rejects most overload before that walk starts.

Tests: `internal/dht/flood_hardening_test.go` (packet budget caps
single-source AND 5-source floods at exactly the shared burst, refills,
disables; stray-response flood ignored with the node provably healthy
afterwards; walk cap refuses a second walk fast with `ErrWalkBusy`,
releases the slot on completion, `CollectClaims` shares the budget,
uncapped negative knob; local claim served under walk refusal) and
`internal/resolver/overload_test.go` (`ErrWalkBusy` → SERVFAIL on both
claim paths, uncached through the full `ServeDNS` path; distinct
questions refused fast while identical followers share the flight;
disabled cap runs concurrently; capped query SERVFAILs and caches
nothing).

Remaining hardening backlog from the same review (not in this release):
negative caching of freens NXDOMAINs (random-name cache-bypass floods),
a per-source QPS limit on the DNS server sockets themselves,
source-routability cookies for unknown DHT sources (replay
amplification, needs a spec note), and the deployment layer — nftables
`hashlimit` in front of the UDP/DNS ports and systemd `CPUQuota`/
`MemoryMax` on the freens units.

## v0.9.1 — §8.4 hotfix: same-identity resurrection is ownership continuity

Found live on the LAN fleet (2026-08-22): every freens name on the
3-box/7-node network resolved NXDOMAIN through the DNS path while
`freens status`/`doctor` stayed green — the resolver's §7.4 claim
filter and the K_claim put path were refusing the fleet's own renewed
claims as "resurrections".

What happened, end to end:

1. Claim carriers live 24 h; the daemon's auto-renew loop re-signs and
   republishes them at 80% of lifetime. The v0.9.0 fleet restarted
   daily (deploys), so the first daemon that ran > 24 h hit its first
   in-place renewal — which the storing nodes REFUSED (below), the
   carriers expired, and the aliases entered the §8.4 30-day reuse
   window against their own tombstones.
2. The refusal itself: v0.8.0's "renewal vs re-claim" rule rejected a
   same-identity carrier created at/after the predecessor's `expires`
   ("a resurrection — re-claiming through the back door by re-wrapping
   the old identity"). But the §7.4 pools retain EVERY generation of a
   claim's carriers, so once the FIRST generation died, every later
   renewal was compared against that older tombstone and refused — an
   unbroken renewal chain was indistinguishable from a resurrection
   under the per-candidate check. The fleet was structurally doomed
   from its first late renewal tick.
3. Diagnosis was slowed by `PublishKeyedAt` collapsing every failure —
   including "accepted by 0 of N peers" (peers *refusing* the put) —
   into `ErrNoPeers` ("dht: no peers known"), which read as a phantom
   connectivity problem while the routing table held 6 confirmed
   peers.

The fix (spec §8.4 amended to match):

- A carrier of a tombstone's OWN claim identity is always accepted —
  at the K_claim put, and as an exemption from the resolver's
  no-winner-inside-the-window rule. Only the claimant key can sign
  such a carrier, and it embeds the exact claim (same PoW, same
  attestations) that registered the alias: renewal and resurrection
  are both ownership continuity, never re-claims. The window now
  refuses only DIFFERENT-identity claims — the anti-squat property it
  was designed for, fully preserved.
- `PublishKeyedAt` returns the last underlying error on total failure
  (`ErrNoPeers` only when no peer was even attempted).
- Regression tests: wire-level hPut accepts a same-identity carrier
  created after the death (the fleet's exact state); the resolver
  resolves a tombstone's own identity on a fresh post-death carrier;
  the different-identity refusals (put, witness, resolver lock) are
  re-pinned unchanged.

## v0.9.0 — anti-sniping: the witness present window

From a front-running question ("should the name stay hidden until
minted, like some blockchain name systems?"): freens claims already
hide the alias from the storage layer (`K_claim` is a hash of it), but
the `witness` RPC necessarily discloses it — the alias is inside the
PoW prefix a witness must re-verify before signing. Combined with §7.4's
earliest-timestamp-first ordering and a witness age gate of
`WITNESS_COOLDOWN` (1 h), a listener on a victim's witness round could
mine a competing claim backdated up to an hour and out-order the
victim's — a steal feasible whenever the accepted age exceeds the
victim's mine-plus-witness latency. Full commit–reveal registration
(hiding the name even from witnesses until minted) was weighed and
deferred (§7.1 options table); the cheap fix below removes the
realistic attack instead.

Protocol fixes:

- **`WITNESS_PRESENT_WINDOW = 300 s` (spec amendment, §7.3 + Appendix
  A)** — witnesses now refuse claims whose asserted ts is older than 5
  minutes (was `WITNESS_COOLDOWN`, 1 h): an honest registration (mining
  at the initial difficulty plus the 3×10 s retry cycle) completes well
  inside the window, so nothing legitimate is lost, while a sniper's
  backdate margin shrinks twelvefold. The verifier-side corroboration
  band tracks the same window (`[claim.ts - skew, claim.ts + window +
  skew]`) so resolvers accept exactly what witnesses would sign — band
  and gate must agree, or attestations no honest witness produces would
  still corroborate. §7.3 also now states explicitly that conservatively
  refusing a second claim inside the cooldown (what the implementation
  always did) is conformant, and §7.1 records hidden-name commit–reveal
  as considered/deferred with the disclosure analysis.

Implementation:

- **Witness RPC age gate** (`hWitness`) enforces the window with the
  same uint64-safe comparisons as before; the parked-claim reuse in
  `freens register` and the web UI discards claims older than the
  window and re-mines (previously the staleness threshold was the 1 h
  cooldown — a parked claim between 5 min and 1 h old would otherwise
  dead-loop against "claim ts too old" refusals). Parked-claim reuse
  remains free for prompt retries; witnesses' 1 h per-alias signature
  cooldown is unchanged.

Tests: `TestWitnessRefusesSniperBackdate` and
`TestWitnessAcceptsPresentWindowAgedRetry` pin the new gate edges;
`TestCorroborationBandEdges` gains the 1-h-late-attestation (=
pre-v0.9.0 band edge) rejection.

## v0.8.0 — protocol audit: retarget correction, §8.4 reuse window

From a protocol-semantics audit (expiry, anti-squatting economics,
alias re-claim): the Appendix A.4 difficulty retarget had its control
direction inverted and its units wrong, and the spec's §8.4
ALIAS_REUSE_DELAY was declared but unenforceable — nothing alias-keyed
survived a claim's expiry. Both are fixed at the SPEC level first, then
implemented.

Protocol fixes:

- **A.4 difficulty retarget: direction + units + cadence (spec
  amendment)** — the rule compared a whole retarget block's wall-clock
  span against the *per-claim* target (600 s), and the ratio ran
  backwards: a registration flood LOWERED the difficulty to the 24-bit
  floor (the mass-squatting scenario got cheaper the more it was used)
  while a quiet network ratcheted D up +2 per block. Corrected form:
  `D += clamp(round(log2(target_block_span / actual_block_span)), ±2)`
  with `target_block_span = POW_RETARGET_BLOCK × 600 s` — fast blocks
  raise D, slow blocks lower it (floor 24); `round` (was `ceil`)
  removes the upward drift from span jitter at equilibrium.
  `POW_RETARGET_BLOCK` lowered 2016 → 256 (≈ 42.7 h at target rate) so
  a retarget can actually fire on a sub-Bitcoin-scale network.
- **§8.4 ALIAS_REUSE_DELAY: the 30-day reuse window is now enforced
  (spec amendment)** — the tombstone is the EXPIRED CLAIM ENVELOPE
  ITSELF (signature, PoW and witness attestations are timeless), so no
  new wire format: storing nodes retain dead claim envelopes in the
  §7.4 pool until `expires + 30 d` and re-offer them to collectors;
  witnesses refuse to co-sign a different claim for a windowed alias
  (error 301 "alias in reuse window", classified apart from
  "network too small"); storing nodes refuse K_claim puts of carriers
  created after the tombstone's expiry (a same-identity carrier
  OVERLAPPING the dead lease is a renewal and passes — a resurrection
  via still-attached old attestations does not); resolvers select no
  winner while the window is open. Revoked carriers (§8.5) are not
  tombstones. Full content re-verification everywhere — a rogue node
  pooling PoW-valid/quorum-less fabrications cannot lock an alias.

Daemon:

- **Difficulty + claim-pool persistence** — the A.4 difficulty state
  (own D, block counter, observed ring) was RAM-only: a restart reset a
  raised difficulty to 24 (dodgeable by reboot) and dropped every
  in-window tombstone (the reuse window evaporated on restart). Both
  now persist beside the store snapshots (`difficulty.json`,
  `claims-pool/*.cbor`) on the 60 s tick and at shutdown, and reload at
  boot.
- **Auto-renew anchors at the record's OWN lifetime** —
  `renewal.ShouldRenew` computed its 80% threshold against
  RecordDefaultTTL, so a record published with a longer lease (up to
  30 d) was re-signed every ~19 h; the threshold now uses the record's
  actual created..expires window, matching the §6.4 republish timer.

CLI / UX:

- **`freens register` consults the difficulty oracle** — the -difficulty
  help always said "the network difficulty" while the CLI mined at a
  static 24 (only the web UI consulted the daemon's gossiped median).
  In daemon mode register now raises its mining target to the gossiped
  difficulty; standalone `-peers` mode keeps the flag value and says
  so. A witness's §8.4 reuse-window refusal surfaces as "retry after
  the window", not as "the network is too small".

Documentation:

- The deliberate stale-serve-on-clean-miss in DHTLookup.Lookup (a
  deleted name resolving locally until its SIGNED expires — lease
  semantics, bounded by the resolver's per-serve validity gate) is now
  documented at the code site.

## v0.7.1 — security & performance hardening (application audit)

A full application audit (untrusted-input handling, at-rest secrets,
web/admin surfaces, resource bounds, hot-path performance) produced this
release: every HIGH finding fixed, the cheap performance wins landed,
and the remaining accepted-risk items documented below.

Security fixes:

- **ClaimPool bounds + PoW gate (§7.4 storing side)** — the top-2 claim
  pool grew one key per distinct alias FOREVER, and the collect path
  (DHTLookup.CollectClaims → Offer) admitted envelopes on
  envelope-signature alone, so a malicious peer could pool zero-PoW
  claims for unlimited aliases at no mint cost (memory exhaustion).
  Offer now enforces the §7.4 claim screen (claimant consistency +
  recomputed PoW) and the pool is bounded by key count (4096, FIFO
  whole-key eviction) and total bytes (16 MiB).
- **Per-source-IP put throttle** — a put is the costliest CPU a peer can
  induce (decode + signature + PoW + witness verifies, inline on the
  readLoop) and write tokens are minted by every ping/get, so they gated
  authorization, not rate. New NodeConfig.PutRateLimit/PutBurst
  (default 10/s burst 20 per source IP; error 301 "throttled").
- **Witness verification cap** — claims.ValidWitnesses evaluates at most
  16 deduplicated attestations (2× WITNESS_SET); a ≤64 KB claim
  previously cost ~400 Ed25519 verifies on the storing node.
- **§8.4 timelock bound** — VerifyRecovery now enforces
  `NotBefore >= prev_created + policy.Timelock`: a compromised quorum
  can no longer backdate execute_not_before to 0 and take effect with no
  cancellation window (the CLI's verify-recovery reports the same
  BACKDATED status). prevCreated == 0 keeps the legacy check for
  callers that cannot know it.
- **Witness claim-ts gate vs huge uint64** — ts ≥ 2^63 wrapped both
  int64 sanity gates negative and got co-signed; the comparisons are
  uint64-native now.
- **History/evidence byte budgets** — the §8.3 history and §8.4
  evidence tables were count-capped (4096) but byte-uncapped (~256 MB
  of network-sourced data each beyond the documented store budget).
  Both now carry 16 MiB byte budgets (oldest-first/FIFO eviction) and
  evidence blobs over 64 KiB are rejected outright.
- **rateLimiter hard cap** — >10k distinct live sources no longer grow
  the per-IP bucket map unbounded (least-recently-touched entries are
  evicted at the ceiling).
- **freens namespace never leaks upstream first** — the shipped default
  configs (builtin + `freens setup`) now route `freens = freens-first`:
  the community TLD is not an ICANN TLD, so dns-first only leaked every
  freens name to public plaintext upstreams and let a spoofed upstream
  NOERROR shadow the DHT answer. Existing freens.conf files need the
  route line added (or re-run setup).
- **DoH wired** — `[upstream] doh` was parsed but never used; it now
  drives an RFC 8484 DoH upstream (resolver.DoHUpstream) with the
  plaintext servers as automatic fallback.
- **webui**: bootstrap is atomic under a lock (first-visitor TOCTOU),
  login lockout counts failures per IPv4 /24 · IPv6 /64 (source-address
  rotation defeated the per-IP counters), Register rejects empty
  passphrases (no more silent plaintext keyfiles), and Status results
  are cached 1 s per render (the login page no longer amplifies daemon
  round-trips pre-auth).
- **keys at rest**: keychain.Save is atomic (temp + fsync + rename +
  dir fsync; a torn write can no longer destroy the only owner key) and
  always lands 0600 even over a pre-existing loose-perms file. CLI
  passphrase policy: a MISMATCH now aborts (it used to proceed with NO
  passphrase), and non-interactive plaintext keys require the explicit
  FREENS_ALLOW_PLAINTEXT_KEY=1 opt-in. gen-key/lifecycle flag help now
  documents the @keyfile form everywhere (avoids ps/proc exposure of
  raw seeds).
- **setup**: /etc writes (resolv.conf, unit) are staged
  (`<dest>.freens.new` → `mv -f`): the box always has either the old or
  the new file — the rm-then-cp window that could leave no resolv.conf
  is gone. The pristine resolv.conf backup is never overwritten on
  re-setup.
- **TURN**: total allocation cap (DefaultMaxTotalAllocs = 128, error
  508; spoofed-source Allocate floods can no longer exhaust the
  daemon's FDs) and the per-IP allocation map is garbage-collected on
  expiry/release.

Performance fixes:

- **CompareDistance is allocation-free** (byte-wise stack XOR-compare;
  was 2 heap slices per comparison inside every walk sort — thousands of
  allocations per lookup).
- **RecordHash cached per envelope** (atomic, like the canonical-byte
  caches; the claim-collection sort comparator re-hashed full envelopes
  O(n log n) per collect).
- **VerifyFull builds the PoW prefix once** and shares it between the
  PoW and witness stages (was 2 canonical-CBOR encodes per claim).
- **Resolver single-flight**: concurrent identical questions share one
  resolution and DHT walk (the cache-expiry stampede ran N walks and
  could self-trip peers' §12 throttle into SERVFAIL bursts).
- **ResponseCache**: full expired-sweeps run every 64 inserts (was every
  insert, O(4096) under the shared mutex) and hit/miss counters moved
  outside the lock.
- **DNS correctness along the way**: >255 B TXT rdata maps to
  multi-string character-strings (an un-packable answer used to be
  silently dropped) and UDP answers over 512 B truncate with TC set
  instead of vanishing as oversized datagrams.

Known accepted risks (documented, not fixed here): webui serves plain
HTTP on the LAN by design (TLS would need a PKI story for LAN boxes);
the recovery declaration instant remains unattestable without trusted
timestamps (the new bound removes the zero-window forgery; a
predecessor older than the timelock still admits a past-dated
NotBefore); TURN auth remains "any freens node key" (opt-in community
relay, now allocation-capped).

## v0.7.0 — witness attestations v2: the backdating hole closed (security)

Found by an external security review of the §7 alias layer, confirmed by
a proof-of-concept through the real resolver path: **a claim re-mined
with an artificially old timestamp, carrying five witness attestations
fabricated from thin air, passed the full §7.4 filter and won the
(timestamp, pow_hash, tld_id) ordering against every honest claim** —
at zero network presence, zero witnesses contacted, and (worse) as
*final* rather than contested, since a backdated ts is outside the 48 h
contest window. Root causes: the v1 attestation signed the claim
identity fields but not through a timestamp-binding commitment, so
attestations were transplantable across re-mined claims; the resolver
never used witness timestamps; and the §7.3 witness-set membership was
never enforced anywhere.

Four layers, one release (BREAKING for attestations — the fleet
re-registers; see the runbook note at the end):

- **Witness attestations v2 (`freens-witness-v2`)**: the signed message
  is now `"freens-witness-v2" || claim_prefix_hash(32) || witness_ts`,
  where claim_prefix_hash = SHA-256 of the PoW prefix — a commitment to
  the full claim identity {alias, tld_id, timestamp, claimant_pk}. An
  attestation now verifies against exactly the claim it was issued for:
  transplanting fresh attestations onto a backdated re-mined claim fails
  cryptographically. `crypto.WitnessSigningMessage`,
  `claims.NewWitnessAttestation`, `WitnessAttestation.Verify` and the
  §6.3 witness RPC all moved; v1 attestations fail verification by
  construction.
- **Corroboration band (§7.3)**: a witness counts toward the quorum
  only if its own attestation timestamp lies within
  `[claim.ts − 60 s, claim.ts + 1 h + 60 s]` — the honest witnessing
  window. Modern-dated attestations no longer corroborate an old-dated
  claim, whatever keys signed them.
- **Witness-set membership at resolve (§7.3/§7.4)**: the resolver's
  claim-collecting walk now returns the CONVERGED witness set — the 8
  closest nodes it actually reached — and the quorum counts only
  witnesses among them. Five keys minted out of thin air are not among
  the network's witness nodes, so a fully self-consistent fabricated
  quorum (own keys, backdated clocks) fails too. Gated: a sparse view
  (< 8 reachable nodes — the 3-box beta fleet qualifies) names no set
  and skips the restriction rather than enforce it against a partial
  view. `CollectWitnesses` now runs the §7.4 "iteratively find" walk
  (plus self-exclusion) so registrants and verifiers agree on the set.
- **Documented residual**: against a verifier that cannot name the
  witness set, a self-consistent fabricated quorum on a backdated claim
  still resolves (as final). The attack cost moved from zero to a Sybil
  attack priced by NodeID grinding against the real witness set;
  tripwire test `TestBackdatedSparseViewResidualDocumentsSybilBound`
  pins the behavior so a future tightening updates this note loudly.
  Full closure needs a network dense enough to always name the set.

Hardening riding along (same review):

- **The witness RPC verifies the PoW before signing** (§7.3 always said
  MUST; the implementation couldn't — the nonce/pow_hash weren't in the
  args). `witness` now carries `nonce` + `pow_hash`; the recomputation
  and difficulty inference run before the cooldown bucket is touched.
- **`witness` shares the §12 per-IP throttle** with get/find_node (50
  req/s, burst 100): it was the most expensive *unauthenticated* work a
  stranger could induce (PoW hash + Ed25519 signature per call).
- **Retarget integrity**: only a node's FIRST co-sign of an alias counts
  as an "accepted claim" for Appendix A.4 difficulty retargeting —
  re-sign floods (or honest retry traffic) no longer drive the network
  difficulty up through the gossiped median.
- **K_claim put screen (§6.4/§7.4)**: a put landing at K_claim now
  passes the full §7.4 claim filter (claimant binding, PoW, corroborating
  quorum) before entering the store or the top-2 claim pool — seeding
  garbage claims into claim space was otherwise free DHT pollution.
- **Store anti-censorship rule (§6.4)**: a no-prev_hash newcomer signed
  by a key other than the live incumbent's owner can no longer win the
  slot on sequence alone (the `sequence = MAX_UINT64` eviction DoS);
  accepted only when the store's live PARENT record authorizes the key
  (§8.3 delegated re-publication keeps working — verified by the
  transferred-chain integration tests). TLD-root hand-offs must use
  prev_hash + §8.3/§8.4 as before.
- **Spec updated** (§6.3 witness args, §6.4 displacement rules, §7.3
  attestation/quorum/band/membership + residual, §7.4, §10 threat
  matrix, §10.2.1 convergence-model note, §12 throttle note).

witness-round + publish, PoW not re-mined... except when the parked
claim is older than WITNESS_COOLDOWN — found live during the v0.7.0
fleet deploy: such a claim is un-witnessable (the anti-forgery gate
refuses it) and register now re-mines instead of dead-looping retries).
Test coverage: the PoC regressions (`internal/resolver/backdate_test.go`,
`internal/claims/band_test.go`), witness-RPC PoW/throttle/cooldown
paths, store impostor + delegation-exception + recycling, and the full
existing suite (530 tests, 9 fuzz targets) green — plus a live
3-box/7-node fleet deploy: all 8 unlocked names re-registered through
the v2 witness path in one pass each (~20 s: mine → 5 co-signs →
publish), full cross-box dig matrix green before AND after a
simultaneous 9-unit restart (acid test), `freens doctor` clean
everywhere (vaulttest, the passphrase-encrypted test name, still needs
its owner to re-register interactively).

## v0.6.2 — /login redirect loop fixed
- **GET /login no longer redirects to itself** ("too many redirects",
  found live from a LAN browser minutes after deploying v0.6.0): the
  auth pages (/login, /bootstrap) were wrapped in the session check, so
  an unauthenticated login page bounced to itself forever. They now sit
  outside requireAuth — their handlers already guard their own states
  (no password yet → /login redirects once to /bootstrap; password set →
  /bootstrap redirects once to /login). Regression-tested for both
  states.

## v0.6.1 — web UI fix
- **Register-job progress polling fixed**: the live progress card 500'd
  ("no such fragment") — the jobfragment template was parsed into every
  page's base set but never registered for standalone /api/job
  execution. The register flow itself worked (mining, witnesses,
  publish — verified live, resolving cross-box); the card just froze at
  its first render until refresh. Found during v0.6.0 fleet verification.

## v0.6.0 — freens-web: the LAN management UI; un-revoke fixed
- **freens-web** — a web UI for the whole system, served on the LAN:
  dashboard (daemon, peers, store, difficulty, your names' health), names
  (records, expiry, address changes, sub-names), full register flow with
  LIVE progress (PoW mining → witness collection → publish, as an async
  job), renew, revoke (typed confirmation), the DHT store browser, a DNS
  lookup playground, the network page (peers + confirmation state), and
  keys with one-click backup download. Server-rendered Go (html/template
  + htmx, everything embedded — no CDN, no build step), dark/light, a
  separate optional systemd unit (`contrib/systemd/freens-web.service`)
  so the daemon never depends on it. Security: binds 0.0.0.0 but serves
  ONLY the machine's private subnets (auto-detected allowlist — a WAN
  address like ppp0 gets 403, verified live), first-visit password
  bootstrap (bcrypt, 0600), 24 h HttpOnly sessions, per-IP login lockout,
  CSRF header on mutations, typed-alias confirm for revocation.
  Encrypted owner keys prompt per operation; passphrases never persist.
- **Un-revoke fixed (found by the web UI's integration tests):** sequence
  discovery used /resolve, which reports a revoked name as found:false
  with NO sequence — so publishing after a revocation (the documented
  un-revoke: `freens name <alias>`, or re-`register`) reset the sequence
  to 1 and SILENTLY LOST the §6.4 winner race against the tombstone (0
  peer acceptances). register/name/revoke (daemon mode) now fetch the
  envelope by key — tombstones included — before computing sequence+1.
- **internal/keychain**: the keyfile/alias/backup/recovery/claim-parking
  logic extracted from the CLI into one library shared with the web UI
  (no behavior change; CLI delegates). Sentinels ErrNeedsPassphrase /
  ErrWrongPassphrase let UIs ask precisely.
- **Admin socket: GET /store and GET /difficulty** (read-only, like every
  admin endpoint): the live envelope listing (decoded names, RRsets,
  lease state, claim keys flagged) and the A.4 difficulty oracle.
- **`freens backup` output unchanged** but the bundle builder now lives
  in keychain.BuildBackup (one implementation for CLI + web).

## v0.5.2 — hot-path performance; throttled gets stop negative-caching
- **44× faster cold resolves (1.6 ms → 37 µs on the test N200).** Profiling
  the live paths (new loopback benchmark suite: resolve cold/cached/network,
  envelope verify, store ops, ping, iterative get) showed ~60% of all CPU in
  Ed25519 verification — the SAME envelope re-verified at every layer
  boundary (collect → §7.4 filter → chain walk → store cache-back), each
  check re-serializing the record to canonical CBOR. Two changes:
  `crypto.Verify` memoizes verdicts in a bounded lock-free table (key =
  SHA-256 over all inputs, so mutation of any byte misses and re-verifies;
  positive AND negative results cache), and `SignedEnvelope` lazily caches
  its canonical record/envelope bytes (an explicit immutability-after-signing
  contract — the signature covers exactly those bytes). Verified store put
  112 µs → 0.75 µs; envelope decode+verify 222 µs → 17 µs; network-cold
  resolve 4.8 ms → 2.3 ms (UDP-bound).
- **§12-throttled gets degrade instead of negative-caching** (found live
  while benchmarking): a get answered with error 301 "throttled" was treated
  as a clean miss — an over-limit client (burst 100 @ 50/s per source IP)
  got NXDOMAIN that sat out the 60 s negative TTL, exactly the issue-#1
  failure mode. The walks now classify it as `ErrDegradedMiss` (SERVFAIL,
  retried, never cached) and the throttling peer is neither evicted nor
  penalized (it answered; it just declined to serve). `LookupStats` counts
  `ProbesThrottled`.

## v0.5.1 — the two nits, fixed
- **Revoked names no longer count as "resolves".** `/resolve` reports a
  §9.5 tombstone as `found:false, revoked:true` (mirroring the DNS
  face's NXDOMAIN); doctor flags revoked keychain aliases as warnings
  ("deliberate; un-revoke or drop the key"), `status` shows
  "revoked (dead by owner choice)", and `start` no longer treats a
  tombstoned alias as "already ours and published".
- **Ghost probation survives restarts.** The peerbook now carries each
  contact's last-direct-exchange timestamp (`confirmed`), and bootstrap
  reloads it via `AddPeerConfirmed` — a restart resumes the anti-ghost
  clock instead of resetting it, closing the "restart short-cycling
  defeats the idle sweep" residual from v0.5.0.

## v0.5.0 — ghost contacts, IPv6 names, clock doctor, chair alerting
- **Issue #2 fixed — advertisement can no longer launder dead contacts.**
  A contact's liveness now requires DIRECT exchange: `ConfirmedAt` is
  advanced only by verified inbound messages / successful RPCs; {nodes}
  re-teaching keeps the original LastSeen and bucket position (an
  advertised ghost never looks fresh), a 1-minute idle sweep (default
  TTL 1 h, `NodeConfig.ContactIdleTTL`) evicts unconfirmed- and
  silent-ages contacts no matter how enthusiastically peers re-advertise
  them, and the peerbook persists ONLY directly-confirmed contacts.
  Found live: a day of one-shot CLI probes left ~10 ephemeral-port
  ghosts per table; witness collection degraded to 2/5.
- **IPv6 names: `-ip` accepts v6 in `register` and `name`** (IPv6
  literal → AAAA record; dotted quad → A as before). `name`'s apex
  inheritance falls back A → AAAA.
- **doctor checks the clock** (warn-only): freens crypto is wall-clock
  dependent (validity windows, §7.4 ordering, witness ts bounds);
  skew measured against HTTP Date headers, NTP-fix advice at 2 min/1 h
  thresholds, offline = skip not fail.
- **Chair alerting**: `contrib/systemd/freens-health.{service,timer}` —
  doctor every 15 min, failures in the journal, `OnFailure=` hook for
  your notifier; plus an acceptable-use section for node operators in
  the runbook.

## v0.4.0 — passphrase-protected keyfiles
- **Owner and recovery keys can now be encrypted at rest.** At
  registration a passphrase is prompted: Enter twice = the plaintext
  legacy form (fully compatible), anything else typed twice = a
  scrypt(N=2¹⁵)+AES-256-GCM envelope (`FREENSK1` magic). Unlocking
  prompts on a terminal or reads `FREENS_PASSPHRASE` (scripts/services).
  Detection is by magic; plaintext files load unchanged. Hostile scrypt
  parameters in a planted keyfile are refused. New `internal/securekey`
  (+ `golang.org/x/crypto`, `x/term`).
- **Honest auto-renew trade-off, stated up front**: the daemon cannot
  prompt, so passphrase-protected names are skipped by the auto-renew
  loop (logged with the `freens renew` / `FREENS_PASSPHRASE hints) and
  register warns at generation time.
- `freens backup` inherits the protection automatically (files copied
  verbatim); RESTORE.txt documents both forms.

## v0.3.8 — publisher-local store on admin publish
- **The publishing box's own resolver now serves the new sequence
  immediately.** The admin `/publish` path published to peers only; the
  daemon's own store kept the previous sequence and DHTLookup served it
  until freshness lapsed (found live verifying v0.3.7: post-renewal the
  publishing box answered sequence N−1 while peers served N). Publish
  now also installs the envelope at every `dht.StorageKeys` slot locally
  (the §6.4 winner rule makes it harmless).

## v0.3.7 — names stay alive: renewal + the community seed is back
- **`freens renew [name…]`** — the lease-extension button: re-signs at
  sequence+1 with a fresh 24 h window (owner-only, no PoW, no witnesses,
  milliseconds). No arguments renews every keychain alias; fresh records
  are skipped unless -force; revoked records are refused (deliberate
  death). New `internal/renewal` package carries the semantics.
- **The daemon auto-renews keychain names every 10 minutes** (store scan:
  every envelope signed by a keychain key inside the final-20% window is
  re-signed and republished at all its legitimate keys — K_tld/K_name +
  K_claim). "Keep the daemon running and your names stay alive" is now
  literally true; the §6.4 republish loop alone cannot extend an expiry
  baked into a signature. Passive nodes and relay-only boxes (empty
  keychain) skip it.
- **Community seed promoted**: the shipped `defaultSeedLine` pointed at
  the morning's uninstalled production node (right hostname, dead key —
  every fresh install bootstrapped against nothing). Now pinned to the
  current fleet identity on freens.camalolo.com (that machine holds its
  public IP directly on ppp0 — no NAT in the path).
- `dht.Node.PublishKeyedAt`: publish an envelope at an explicit key set
  (the auto-renew path; same best-effort semantics as Publish).

## v0.3.6 — §7.4 anti-forgery: claim timestamps are bounded
- **A forged "ancient" claim could permanently out-order every honest
  claim** (§7.4 orders earliest-timestamp-first) and steal an alias once
  cooldowns lapsed — without breaking a single key. Witnesses now refuse
  claims dated outside [now − WITNESS_COOLDOWN, now + SKEW_TOLERANCE]:
  the window that covers both mining-time signing and register's
  cooldown-safe retry re-presentation. The resolver additionally drops
  future-dated claims at verification (defense in depth). Found
  auditing what becomes of a revoked alias.

## v0.3.5 — tombstones re-check fast (un-revoke unstalled, found live)
- **A §9.5 tombstone's cache window is now 60 s, not 24 h.** The generic
  freshness rule treated a revoked record's (by-definition empty) RRset
  as a delegation → day-fresh caching: revocation propagated within the
  victim's TTL, but an un-revoke could stall behind a day-fresh
  tombstone for up to 24 h per node. Found live revoking and
  re-registering `atlantic` on the LAN.

## v0.3.4 — `freens revoke <name>`: §9.5's tombstone as an easy button
- **Revocation had every layer except the button**: the wire (field 12),
  the store (winner rule), the resolver (NXDOMAIN at any revoked hop) —
  but no CLI could create one. `freens revoke <name>` builds the §9.5
  tombstone from live state (owner key from the keychain, sequence =
  current+1 fetched from the network, empty RRset, revoke=true) and
  publishes it; confirmation prompt on a TTY (-yes skips). Un-revoke =
  publish a newer sequence.
- **register is now sequence-aware**: it hardcoded sequence 1, so
  re-registering a revoked apex (the natural un-revoke path) would have
  LOST the §6.4 winner rule and been silently ignored. It now fetches
  the current sequence like `name` does.

## v0.3.3 — fresh-install fix (found on the cross-internet test node)
- **First boot with a fresh `persist` dir no longer fails.** The v0.3.2
  load→persist defaulting errored on a not-yet-existing store dir
  (`load: open …/store: no such file or directory`) — every LAN box had a
  store already, so it only surfaced on a genuinely fresh remote node. A
  defaulted load on a missing dir is now skipped (the first persist tick
  creates it); an explicit `-load` still errors loudly.

## v0.3.2 — persistence actually round-trips (found live, fleet-wide)
- **A restart no longer empties the store.** `-persist` wrote snapshots
  but nothing reloaded them — records lived only in RAM, so restarting
  the whole fleet at once lost every record network-wide while the
  .cbor files sat on disk unread (observed: all stores at 0, names
  NXDOMAIN, minutes of head-scratching). With `-load` unset the daemon
  now defaults its seed dir to the persist dir (explicit `-load` still
  wins); the §6.4 winner rule makes the reload idempotent.
- **Shutdown persist paths used the flag, not the effective value**:
  with `persist` set only in the `[dht]` config section, the final
  snapshot's sidecars (`fetched.json`, `history/`, `evidence/`) went to
  RELATIVE paths — under a system unit (CWD=/) that is `mkdir /history`,
  permission denied. All final-persist paths now use the effective dir.

## v0.3.1 — churn-proof lookups (fixes #1)
Field-observed 3× on the 7-node LAN: while some nodes are down (reboots,
crash-looping units), lookups for some names time out or NXDOMAIN for
minutes although surviving nodes hold the records the whole time. Three
layers fixed:
- **Walk layer** (`IterativeGet` + the claims walk): probe-failed contacts
  are PENALIZED for 30 s (eviction alone did not stop re-probing — live
  peers keep re-advertising corpses in their {nodes} lists); a round in
  which no probe answered doubles the next round's batch (ALPHA → … ≤ K)
  so the walk reaches live holders past a cluster of dead closest
  candidates in one extra round instead of rounds × 2 s of serial
  timeouts.
- **Classification**: a miss with probe failures is a DEGRADED miss
  (`dht.ErrDegradedMiss`), distinct from a clean "every reachable holder
  answered not-held" miss. `DHTLookup` still serves stale cached copies
  first (offline resilience unchanged).
- **Resolver layer**: a degraded miss answers SERVFAIL — which §10.4 never
  caches — so the next query retries immediately; previously one failed
  walk during churn negative-cached NXDOMAIN for 60 s, outlasting the
  outage itself.

## v0.3.0 — system service: the daemon is machine infrastructure
- **setup installs a systemd SYSTEM unit** (`/etc/systemd/system/
  freens.service`, `WantedBy=multi-user.target`, `User=` the unprivileged
  installer). A DNS resolver must come up at power-on — the `--user` model
  needed `loginctl enable-linger` (which setup never set: fresh machines
  rebooted into no daemon until first login) and raced the user session.
  Found live on the 3-box LAN; system units were already what
  contrib/seed-node.md prescribed for servers. There is exactly one mode
  now — no flags, no user/system split.
- **Automatic migration**: setup detects a pre-v0.3.0 `--user` unit,
  disables + removes it, and installs the system unit in its place
  (same state dir, same ports, one daemon).
- Uninstall removes the system unit (and any legacy user unit); the
  community-node runbook shrank accordingly (`freens setup` does it all).

## v0.2.1 — OS-resolver wiring that actually works (found live on 3 boxes)
- **setup: the one true wiring is resolv.conf → 127.0.0.1 + a loopback
  :53 → daemon-port NAT redirect.** The v0.2.0 paths were both broken in
  the field: `nameserver 127.0.0.1:5300` is invalid resolv.conf syntax
  (dig rejects the whole file; glibc silently skips the line), and the
  systemd-resolved drop-in can never resolve freens names because
  resolved does not forward single-label queries — and every freens name
  IS a single-label TLD. setup now installs daddr-scoped nft rules
  (iptables fallback) and rewrites resolv.conf as a plain file (not
  through resolved's stub symlink, which restarts would regenerate).
- **port53-redirect.sh: daddr-scoped rules** — the old uid-exclusion
  (a) used nft syntax real parsers reject, and (b) excluded EVERY app on
  single-user machines where apps share the daemon's uid, making the
  redirect a no-op. Only loopback-destined :53 matches now; the daemon's
  upstream queries (external addresses) never do.
- **doctor: checks the real wiring** — resolv.conf at 127.0.0.1 AND the
  redirect present; warns precisely when only half is wired.
- **register: the "network too small" error now points at
  contrib/seed-node.md** (found live: 3 boxes < W=5 witnesses; the
  honest error, plus how to help).
- Uninstall removes the NAT table and legacy v0.2.0 artifacts (drop-in,
  `:5300` resolv.conf lines).

## v0.2.0 — the friends release
Everything below plus the "chairs" kit: `contrib/seed-node.md` (run a
community node on any Linux box in ~5 minutes — a system service, public
DHT listener, persist, and the one-line seed exchange) and a
friends'-eye "what to expect" note in the README (network needs ~5 live
nodes; keep the daemon running for renewals; back up keys on day one).
First release shipping the one-command UX: `freens start`, `backup`,
`doctor --fix`, plain-language `status`, interactive sudo, cooldown-safe
witness retries, configured-port awareness.

## v0.1.x (unreleased-to-v0.2.0)
- **register: cooldown-safe witness retries (fix found live)** — the daemon
  transport passed a fresh timestamp to the witness RPC, so every retry of
  a REUSED claim minted a new prefix hash and §7.3's witness cooldown
  refused exactly the nodes that had already helped (observed signer counts
  degrading 4→2→0). Both transports now present `claim.Timestamp`. On top,
  witness collection retries on a cold routing table (3 attempts, 10 s
  pause; each walk warms the table) instead of failing "network too small"
  on a just-started daemon.
- **doctor/setup honor a configured DNS port** — the DNS check, the OS
  resolver wiring, and the uninstall cleanup used the hardcoded
  127.0.0.1:5300; a user-edited `[listen] udp` port produced false ✔s and
  wired the OS at a dead port. All paths now read the configured address
  (fallback to the default when absent/malformed).
- **Module path matches the repo** — `github.com/camalolo/freens`
  (was `github.com/laurent/freens`; import-path sweep + import re-sorting,
  no behavior change). `go install github.com/camalolo/freens/cmd/freens@…`
  now works.
- **Non-technical UX pass** — `freens start <name>` is the whole onboarding
  as one verb (setup if needed → register → plain summary; prompts for the
  name interactively; idempotent; positional `register <alias>` accepted
  too). Bare `freens` now prints a first-timer card instead of the full
  subcommand dump, and typos get "did you mean" suggestions. `setup`
  prompts for the admin password itself when sudo needs one on a terminal
  (never in scripts; manual commands remain the no-TTY fallback).
  `doctor --fix` repairs what it diagnoses: missing daemon → idempotent
  setup + wait, unwired OS resolver → the setup wiring. `status` speaks
  plain language (`alice → 203.0.113.42 · healthy`; raw fields behind
  `-v`). `freens backup` bundles owner + recovery keys (+ claim state)
  into one dated file with a RESTORE.txt inside; `backup -restore`
  unpacks it (bare filenames only — hostile archives are rejected, no
  clobbering without -force).
- **Single binary + zero-config UX** — `freens setup` (state dir, config,
  node key, seeds.conf, systemd --user service, OS resolver wiring via
  systemd-resolved drop-in or resolv.conf, `--uninstall`), `freens register`
  (defaults: outbound IP, running daemon via the admin socket, default-on
  2-of-3 recovery keyfiles, cooldown-safe claim REUSE across retries),
  `freens name`, `freens status`, `freens doctor`. `~/.freens` state dir
  (FREENS_HOME); learned peerbook persists across restarts; pinned default
  seed (freens.camalolo.com) with hostname re-resolve every 5 min. The
  local admin socket (unix, 0600) exposes publish/get/resolve/witness/
  peers/status to the CLI; `freens-cli` is now a thin compat shim (all
  subcommands moved to `internal/cli`, admin-aware, standalone fallback).
- **Fixes found live**: IterativeFindNode early-break starved walks on
  tables with stale contacts; register now reuses the owner key AND mined
  claim on retry (witness-cooldown cascade); setup template wrote a
  freens-only route (NXDOMAINing the internet) — now dns-first; doctor's
  seed check TCP-dialed a UDP protocol.
- **`freens-cli register`** — one-command alias onboarding (§7): owner key
  (generated to a 0600 keyfile) → claim PoW → W live witness co-signatures
  from the DHT → TLD record published at K_tld + K_claim. Every seed flag
  accepts `@keyfile` (CLI and daemon `-node-seed`); `gen-key -out`.
- **CI** — gofmt/vet/race gates, linux+darwin build matrix, tag-driven
  releases, and native fuzzing (9 targets; smoke on push, 2m/nightly).
- **IPv6** — DHT/STUN/TURN verified family-agnostic end-to-end (loopback v6
  tests for all three); UPnP stays IPv4 by protocol design.
- **Daemon `[dht]` config section** — the network side (listen, node-seed,
  peers, peers-file, advertise, stun, turn, turn-relay, persist, passive,
  upnp) in the same `-config` file as the resolver sections; per-setting
  precedence flag > config > default. `freens version` / `freens-cli
  version`, stamped in CI builds.
- **UPnP renewal** — mappings re-asserted every 5 minutes; router reboots
  self-heal, external-address changes are followed at runtime
  (`Node.UpdateAdvertise`). Fixed discovery against real firmware (LOCATION
  parse bug; multicast pinned per LAN interface + gateway unicast fallback).
- **TURN client + server** (RFC 8656 subset) — community relay tier:
  `-turn` donates bandwidth, `-turn-relay` escapes symmetric NAT; freens
  node-key auth, per-IP caps, permission lists, STUN-on-the-same-port.
- **§8.4 recovery execution** — evidence-aware acceptance end to end:
  resolver-side hand-off walk (transfer + recovery mixed), evidence store +
  transport + persistence (survives restarts), `recover -out-envelope`,
  `publish -evidence`, `verify-recovery`; fail-closed during the timelock.
- **Ops** — `/metrics` + `/healthz` (Prometheus text), `-peers-file` +
  SIGHUP reload, `-dns` override, `contrib/testnet.sh [N] [direct|relay]`.

## v0.1.0
- Initial implementation of the freens naming protocol: wire format (§4),
  Kademlia DHT with signed RPCs (§6), alias claims with witnessing and
  contests (§7), resolver with caching/upstream fallback (§9-10), ownership
  lifecycle (§8), STUN discovery, systemd integration, IDNA (§3.2).
