# Changelog

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
