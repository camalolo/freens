# contrib/ — OS integration recipes (spec §9.4 stage 1, §9.1)

The spec's deployment model (§9.1) is a resolver on `127.0.0.1:53` (UDP+TCP)
so existing applications need zero changes; §9.4 stage 1 normatively defines
only this "local resolver" path. Port 53 is privileged, so pick one of the
recipes below (high-port + redirect is recommended — no elevated privileges
for the daemon itself).

| Recipe | Files | Privileges needed |
|---|---|---|
| High port + redirect (recommended) | `port53-redirect.sh` | root once, to install firewall rules |
| Bind :53 directly | — (setcap one-liner) | root once, to set the file capability |
| User systemd service | inline unit below | none |
| systemd-resolved coexistence | `systemd/freens-resolved.conf` | root once |

Nothing here is executed by the build or tests; these are contributed
examples — read before running.

## 1. High port + port-53 redirect (recommended)

Run the daemon unprivileged on a high port, then redirect the host's outgoing
port-53 traffic to it, so stub resolvers keep working unmodified:

```bash
freens -listen 127.0.0.1:5300 -upstream 9.9.9.9,1.1.1.1 ...   # your user
sudo ./port53-redirect.sh add          # iptables or nftables, auto-detected
./port53-redirect.sh status            # inspect
sudo ./port53-redirect.sh remove       # revert
```

The script is idempotent (check-before-add) and excludes the daemon user's
own packets from the redirect — without that exclusion the daemon's upstream
forwards to `9.9.9.9:53` would loop back into itself. Configure with
`TO_PORT` / `UID_EXCL` / `BACKEND` env vars (see the header comment). Rules
are not persistent across reboots; persist them via your distro's firewall
service.

Alternatively point clients at the high port directly
(`resolv.conf` does not support ports, but `dig -p 5300` and most
stub-resolver configs do).

## 2. Binding :53 directly — CAP_NET_BIND_SERVICE

Grant the binary the capability instead of running it as root (§9.1
"documented forwarding recipes" alternative):

```bash
setcap 'cap_net_bind_service=+ep' "$(command -v freens)"
freens -listen 127.0.0.1:53 ...
```

Revert with `setcap -r "$(command -v freens)"`. Note: capabilities on a file
are lost when the binary is replaced (re-run after upgrades), and some
filesystems mounted `nosuid` ignore them. Then use
`resolv.conf.example` / the resolved drop-in below.

## 3. Running as the user's systemd service

Run the daemon under your own uid with a user unit
(`~/.config/systemd/user/freens.service`) — no root at all when combined
with recipe 1 (root is only needed once to install the redirect, which can
also be done from a system unit):

```ini
[Unit]
Description=freens local DNS resolver (spec §9.1)
After=network-online.target

[Service]
ExecStart=%h/bin/freens -listen 127.0.0.1:5300 -load %h/.local/share/freens/records
Restart=on-failure

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now freens.service
journalctl --user -u freens.service -f      # watch the startup log
```

Adjust `ExecStart` (add `-dht`/`-peers`/`-turn`/`-config`/`-idna` as
needed — the startup log line reports whether IDNA is on).

## 4. systemd-resolved coexistence

On distros using systemd-resolved, its stub listener owns `127.0.0.53:53`
and its own upstream configuration. Install the drop-in
`systemd/freens-resolved.conf` as
`/etc/systemd/resolved.conf.d/freens.conf` to make resolved forward
everything to the daemon (`DNS=127.0.0.1`) and to disable its stub listener
(`DNSStubListener=no`, which also frees the name for the redirect path):

```bash
sudo mkdir -p /etc/systemd/resolved.conf.d
sudo cp contrib/systemd/freens-resolved.conf /etc/systemd/resolved.conf.d/freens.conf
sudo systemctl restart systemd-resolved
resolvectl status     # verify: "Current DNS Server: 127.0.0.1"
```

Revert by deleting the file and restarting systemd-resolved. For
NetworkManager-managed `/etc/resolv.conf` instead, see the notes in
`resolv.conf.example`.

## 5. NAT traversal — the connectivity ladder

The DHT speaks UDP (default port 15353). What a peer dials is the address
the node advertises, and the daemon picks the first rung of this ladder
that applies — precedence: explicit `-advertise` > UPnP router mapping >
relayed address from `-turn-relay` > `-stun`-discovered reflexive address >
observed source — falling back to direct when a rung is unavailable:

1. **Direct — observed source.** On a host with a dialable address, do
   nothing: peers learn the working source address from your packets.
   IPv6 prefix delegation counts here — a routed /64 gives the host a
   global address, no forward needed. Behind IPv4 NAT this rung fails:
   peers learn your RFC1918 source address instead, which is undialable.
2. **`-advertise` — port forward / known public address.** Forward
   external UDP 15353 to the machine and tell the daemon what the world
   sees:

   ```bash
   freens -dht :15353 -advertise 203.0.113.7:15353 ...
   ```

   `-advertise` publishes that address in `find_node`/`get` contact
   lists (§6.2 "nodes advertise (ip, port, node_pubkey)") instead of the
   observed source, and always wins over any discovered or relayed
   address below.
3. **`-upnp` — router-requested port mapping (default ON).** The daemon
   SSDP-discovers the LAN's router (UPnP IGD), asks it to forward the
   DHT's UDP port (`AddAnyPortMapping`, with the older `AddPortMapping`
   as fallback), and advertises the resulting external address exactly
   like `-advertise` — zero configuration on the most common NAT there
   is, the home router. The mapping is labeled and UDP-only, points
   solely at this host, is released at shutdown, and is re-asserted every
   5 minutes — a router reboot self-heals (probe `GetSpecificPortMappingEntry`,
   re-map on loss) and external-address changes are followed at runtime via
   the node's live advertised-address update, no restart needed; the rung silently
   stands down whenever it does not apply (an explicit `-advertise` or
   `-turn-relay`, no IGD answering SSDP, the router refusing the
   mapping, or a CGNAT-fronted gateway reporting a 0.0.0.0 external
   address — a mapping behind carrier NAT is meaningless). Disable with
   `-upnp=false`. Exposed as the `freens_upnp_mapping` gauge.
4. **`-stun` — discovered reflexive address.** `-stun <server>` (RFC
   5389 Binding request, e.g. `-stun stun.example.net:3478`) makes the
   DHT node periodically ask a STUN server what its public reflexive
   address is and advertise THAT to peers — exactly like a hand-set
   `-advertise`, but discovered. This resolves the common full-cone /
   restricted-cone NAT with no port forward; it does NOT resolve
   symmetric NAT (the NAT assigns a different external port per
   destination, so the reflexive address one STUN server reports is
   useless to other peers). A freens `-turn` relay also answers STUN
   Binding, so one instance can serve as your `-stun` server too (next
   section).
5. **`-turn-relay` — symmetric NAT, via a community relay.** The node
   opens an allocation on a freens TURN relay (RFC 8656 subset) and
   tunnels ALL peer DHT traffic through it, advertising the RELAYED
   address. Every packet rides an allocation that already punched the
   NAT it needs, so this works even when both sides are behind
   symmetric NATs — no inbound dialability required. If the relay is
   unreachable, the node falls back to direct. Server side + trust
   caveats: next section.
6. **External generic options.** A WireGuard tunnel or a cheap VPS
   fronting the node gives a stable dialable address — then `-advertise`
   it (rung 2). Works everywhere; costs a box.

Without a relay, at least one side of each peer pair needs a directly
dialable address — that limitation is inherent to UDP. The community
relay tier is what removes it.

## 6. Running a community TURN relay (`-turn`)

`freens -turn 0.0.0.0:3478 …` runs a relay for nodes stuck on rung 4: a
public UDP address other freens nodes tunnel through with `-turn-relay`
(3478 is the conventional TURN port; any free port works). The same
listener answers STUN Binding requests, so one instance also serves
`-stun` (rung 3) — point both flags at it:

```bash
# on the public host (the relay operator):
freens -turn 0.0.0.0:3478 ...
# on each symmetric-NAT node:
freens -dht :15353 -turn-relay relay.example.net:3478 \
    -stun relay.example.net:3478 ...
```

**Cost.** Bandwidth ≈ the sum of the relayed nodes' DHT traffic —
keepalives, lookups, record fetches. That is small (the DHT is a control
plane, not media streaming), but it is your uplink doing other nodes'
work; the `freens_turn_allocations` gauge on the `-metrics` endpoint
shows how many allocations are riding you.

**Auth model.** freens-turn is an RFC 8656 subset with freens-native
auth, not a generic TURN server: every allocation must carry a valid
freens node-key signature over
`"freens-turn-v1" || txid || key || lifetime`. Stock TURN clients (coturn
& co.) will not interop, and neither will random non-freens UDP
senders. The signature binds usage to a freens node key, but any freens
node can mint one — it is an identity, not an ACL. The real gates are
operational:

- **per-IP allocation cap** — at most 8 concurrent allocations per
  source IP (default);
- **bounded lifetimes, mandatory refresh** — an allocation lives 600 s
  by default (hard max 3600 s) and is freed unless refreshed;
- **per-allocation permissions** — at most 64 peer addresses (default)
  may send through one allocation.

No relay-tuning flags exist yet; those caps are internal defaults (as of
this writing — check the daemon `-h` output once the flags land).

**Trust caveat.** DHT RPCs are signed (§6.3) but NOT encrypted: a relay
operator can read every relayed byte — lookups, records, who talks to
whom. Relaying fixes dialability, not confidentiality. Use a relay you
trust, or wrap the relay path in a tunnel you control (rung 5).

## 7. N-node interop testnet (`testnet.sh`)

`testnet.sh` is the ops-hardening / spec-§D interop harness: it builds the
daemon + CLI, launches N nodes on localhost (DHT `127.0.0.1:15354…`, DNS
`127.0.0.1:5301…`), publishes a TLD + `www` record through node 1's DHT
port, and asserts with `dig` that EVERY node serves the record — then
republishes a `sequence+1` update and asserts every node converges on the
new IP within 30 s:

```bash
./contrib/testnet.sh               # 5 nodes, direct mode, workdir = mktemp -d
./contrib/testnet.sh 3             # 3 nodes
./contrib/testnet.sh 3 relay       # 3 nodes, relay mode (below)
./contrib/testnet.sh 5 /tmp/tn     # 5 nodes, keep the workdir for inspection
# last line on success: "PASS: 5 nodes converged"
#                    (or "PASS: 5 nodes converged via TURN relay")
```

**Relay mode** simulates symmetric NAT: node 1 additionally runs the
community relay (`-turn 127.0.0.1:3470` — the port is FIXED, not `:0`,
so nodes 2..N can aim `-turn-relay` at it by flag; 3470 rather than the
conventional 3478 leaves that port free for a real relay on the host),
while nodes 2..N drop
`-advertise` and get `-turn-relay 127.0.0.1:3470` instead: all their
peer DHT traffic rides an allocation on node 1, and peers see only the
relayed address (`-advertise` must be dropped for them — it takes
precedence over `-turn-relay` and keeping it would short-circuit the
test). The same publish/update/`dig` assertions must pass, proving the
relayed transport end to end — relayed-address advertising, allocations
that stay alive, convergence on every node — with only node 1 directly
dialable.

Requirements: `go`, `dig` (bind9 dnsutils); run it from the repo root. Each
node's state lives under `<workdir>/n<i>/` (`log`, `records/`,
`resolver.conf`); on any failure the script tails every node log and exits
non-zero. All daemons are killed on exit. The test alias is routed
freens-side and pinned per node (`[alias-pins]`, §9.3) — the §7 witness-
quorum claim path needs a live witness-collecting publisher, so this harness
proves DHT data convergence + DNS serving (§D interop), not claim races.

## 8. Recovery runbook (§8.4)

The lost-primary-key flow, end to end with the CLI (the spec's Appendix C.4
walkthrough):

```bash
# 0) beforehand: embed a 2-of-3 recovery policy in the record (§5.4 field 10)
freens-cli make-record -name www.alice.foo -owner-seed $K -ip 203.0.113.42 \
    -pin $PIN -recovery-keys $RK1,$RK2,$RK3 -recovery-threshold 2 -out r1.cbor

# 1) the primary key is lost: threshold recovery keys sign a declaration
#    naming a fresh primary key; -out is the evidence, -out-envelope the
#    recovered record R2 (owner = the new key, sequence+1, prev_hash-linked,
#    signed by the NEW owner — the opposite of transfer)
freens-cli recover -prev-envelope r1.cbor -new-owner-seed $FRESH \
    -recovery-seeds $RK1SEED,$RK2SEED -out evidence.cbor -out-envelope r2.cbor

# 2) anyone can audit the declaration (pure wire checks, no network)
freens-cli verify-recovery -prev-envelope r1.cbor -evidence evidence.cbor
#   -> status=quorum 2/2 OK, timelock expires <iso>     (exit 0 once elapsed)
#   or the failure reason (below threshold / timelock pending; exit 2)

# 3) after the 72 h timelock (no cancellation by the old key), publish R2
#    WITH its evidence — the evidence rides along in the PUT so peers can
#    police the quorum + timelock on the acceptance side (§8.4 step 3)
freens-cli publish -files r2.cbor -evidence evidence.cbor -peers ...

# 4) the new owner SHOULD rotate the recovery keys (§8.4 step 2: "this
#    defeats a single stolen recovery key")
freens-cli rotate -prev-envelope r2.cbor -new-seed $K2 -signer-seed $FRESH \
    -out r3.cbor && freens-cli publish -files r3.cbor -peers ...
```

Note: `recover` carries the previous recovery policy over into R2 UNCHANGED
— rotating it is deliberately the post-recovery `rotate` step, because
changing the quorum needs the control this recovery establishes.

## 9. Daemon operational flags (`-dns`, `-metrics`, `-peers-file` + SIGHUP)

Quick operational knobs that override/extend the config file (all optional):

- `freens -dns 127.0.0.1:5300 …` — override the DNS listen address (UDP and
  TCP) without editing a config; the high-port recipes above apply verbatim.
- `freens -metrics 127.0.0.1:9153 …` — serve operational metrics and a
  health endpoint over HTTP on that address:

  ```bash
  curl -s http://127.0.0.1:9153/metrics   # scrape (Prometheus text format)
  curl -s -f http://127.0.0.1:9153/healthz && echo healthy
  ```

  `/healthz` returns 200 while the daemon is up (use it for systemd
  `ExecStartPre`/orchestrator readiness probes); port 9153 avoids colliding
  with common Prometheus targets.
- `freens -peers-file /etc/freens/peers.conf …` — bootstrap peers from a
  file (same `addr#pk` comma/newline-separated format as `-peers`). Send the
  daemon `SIGHUP` to reload it without a restart:

  ```bash
  kill -HUP $(pidof freens)   # re-reads -peers-file
  ```

  Useful when the bootstrap set is managed by config management and must not
  touch the long-lived `-node-seed` identity or the persisted store.

## 6b. Daemon `[dht]` config section

The `-config` file carries the whole daemon, not just the resolver. The
`[dht]` section holds the network side — same keys as the flags:

```ini
[tld-routes]
mytld = freens

[dht]
listen = 0.0.0.0:15353
node-seed = /etc/freens/node.key   ; or 64-hex
peers = 192.0.2.10:15353#<64-hex-node-pk>
peers-file = /etc/freens/peers.txt
advertise = 203.0.113.7:15353      ; or stun = ... / turn-relay = ...
turn = :3478                       ; optional community relay
persist = /var/lib/freens
; passive = true
; upnp = false                     ; only the off switch exists in-file
```

Precedence per setting: an explicitly-passed flag wins over the config,
which wins over the default (same rule as `-listen`/`-upstream`).
`node-seed` accepts a bare path or `@path` keyfile form (hex otherwise);
full-line `;`/`#` comments only. `freens version` / `freens-cli version`
print the build (CI builds stamp the commit / tag).

## 10. Seed node: hostname advertise

A node with a stable public address seeds the network: point a DNS name
at it (e.g. `freens.example.com`), open the DHT port (15353/udp) and the
public resolver port if desired, and run the daemon with
`-advertise freens.example.com:15353`. Hostnames are resolved at startup
and re-resolved every 5 minutes at runtime (`Node.StartAdvertiseResolve`)
— peers learn the current address from the advertise stamp on every
outbound query, so DNS-side changes propagate without daemon restarts.
New nodes bootstrap from the seed via `~/.freens/seeds.conf`
(`freens setup` writes the default pin; edit the file to point at any
seed you prefer — or your own).

## Files

- `testnet.sh` — N-node localhost interop testnet, `direct` or `relay`
  mode: build, launch N daemons, publish once, `dig` every node, publish
  an update, `dig` every node again (kills everything on exit; needs `go`
  + `dig`; relay mode additionally runs `-turn`/`-turn-relay` through
  node 1, see §7).
- `ddns-cloudflare.sh` — Cloudflare DDNS keep-A-record-current for
  dynamic-IP seed nodes (§10): WAN IP from the interface, PATCH on drift,
  `--check` dry-run, token from env or certbot's `cloudflare.ini` (never
  printed; needs `curl` + `jq` + iproute2; validated with `bash -n` only).
- `systemd/freens-ddns.service` + `systemd/freens-ddns.timer` — system
  units driving the script every 5 minutes (`Persistent=true`; install
  instructions in the unit headers; validated with `bash -n`/`systemd-analyze verify` only).
- `port53-redirect.sh` — iptables/nftables REDIRECT :53 → :5300 (UDP+TCP),
  idempotent, with `remove`/`status` actions (needs root to *run*; validated
  with `bash -n` only).
- `resolv.conf.example` — the classic `nameserver 127.0.0.1` line, with
  backup/revert instructions and managed-resolv.conf caveats.
- `systemd/freens-resolved.conf` — systemd-resolved drop-in example.
