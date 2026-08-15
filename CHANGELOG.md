# Changelog

## unreleased
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
