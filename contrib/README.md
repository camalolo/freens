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

Adjust `ExecStart` (add `-dht`/`-peers`/`-config`/`-idna` as needed — the
startup log line reports whether IDNA is on).

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

## 5. NAT / port forwarding (DHT dialability)

The DHT speaks UDP (default port 15353). Behind NAT, peers learn your RFC1918
source address from packets — undialable. Forward external UDP 15353 to the
machine and tell the daemon what the world sees:

```bash
freens -dht :15353 -advertise 203.0.113.7:15353 ...
```

`-advertise` publishes that address in `find_node`/`get` contact lists
(§6.2 "nodes advertise (ip, port, node_pubkey)") instead of the observed
source. Caveat: two peers behind different NATs, both without forwards, still
cannot reach each other directly — hole-punching/STUN/TURN is future work;
today at least one side needs a reachable address (the same assumption
`-peers` bootstrapping makes). Alternative: IPv6 prefix delegation — a routed
/64 gives the host a global address, no forward needed.

## Files

- `port53-redirect.sh` — iptables/nftables REDIRECT :53 → :5300 (UDP+TCP),
  idempotent, with `remove`/`status` actions (needs root to *run*; validated
  with `bash -n` only).
- `resolv.conf.example` — the classic `nameserver 127.0.0.1` line, with
  backup/revert instructions and managed-resolv.conf caveats.
- `systemd/freens-resolved.conf` — systemd-resolved drop-in example.
