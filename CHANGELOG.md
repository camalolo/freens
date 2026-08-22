# Changelog

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
