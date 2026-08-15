# Run a community node (be a chair)

freens needs a handful of reliably-on nodes for the network to work:
alias registration (§7.3) asks W=5 **distinct live nodes** to co-sign a
claim, and records live only where nodes store and republish them
(§6.4). Every always-on node — a VPS, a home server, a Raspberry Pi
behind UPnP — is a chair at the table. This is the copy-paste runbook.

What a community node is NOT: a registrar, an authority, or a holder of
anyone's keys. It stores signed records, answers `get`, co-signs
timestamped witness requests, and forwards what it is asked to forward.
It sees no secrets and can forge nothing.

## 1. The one-time setup (any Linux box, ~5 minutes)

```bash
# as root or with sudo — the installer handles everything since v0.3.0:
# config, node key, seeds, AND a systemd SYSTEM unit (boots at power-on,
# no login needed — right for a headless node)
curl -L -o freens.tar.gz https://github.com/camalolo/freens/releases/latest/download/freens-linux-amd64.tar.gz
tar xzf freens.tar.gz && sudo install -m755 freens-linux-amd64/freens /usr/local/bin/freens

freens setup          # writes ~/.freens + /etc/systemd/system/freens.service
                       # and enables it (runs as YOU, unprivileged — keys
                       # stay in your home; sudo is only for the unit file
                       # and the resolver wiring)
```

Then edit `~/.freens/freens.conf`'s `[dht]` section for a public node:

```ini
[dht]
listen = 0.0.0.0:15353            ; the community port (UDP)
advertise = YOUR.PUBLIC.IP:15353  ; or a hostname; omit behind UPnP
persist = ~/.freens/store        ; records survive restarts (setup made it)
upnp = true                       ; home servers: router maps the port
```

Open UDP 15353 in any firewall (`ufw allow 15353/udp`).

## 2. The service

Already done — `freens setup` (step 1) wrote and enabled the systemd
system unit. If you disabled it, `sudo systemctl enable --now freens`
brings it back. The daemon runs as the unprivileged user who ran setup;
the admin socket stays a 0600 unix socket in `~/.freens` — local CLI
only, nothing remote.

## 3. Tell the community (and join everyone else)

```bash
freens status -v        # your node's public key is the node_pk= line
```

Share one line — `your.host:15353#<node_pk-hex>` — with whoever keeps
the seed list, and add the existing community seeds to your own
`~/.freens/seeds.conf` so everyone interconnects. That file is the whole
coordination mechanism.

## 4. What good looks like

```bash
freens doctor           # all ✔: socket, DNS path, peers, seeds
journalctl -u freens -f # quiet is healthy; witness lines appear as
                        # people register names
```

Optional extras: run a TURN relay too (`-turn`, see contrib/README §6)
so symmetric-NAT users can join; expose `-metrics` locally.

## Hardware/bandwidth

A node is kilobytes of signed records and occasional witness signatures —
the smallest VPS or a Pi is far more than enough. Disk use is bounded by
the record store; `persist` can be dropped if you prefer memory-only.

## Staying awake (alerting)

A dead chair shrinks the witness pool silently. `contrib/systemd/`
ships a `freens-health.timer` + service pair: `freens doctor` every
15 minutes, failures in the journal under `freens-health.service` —
wire `OnFailure=` to whatever notifies you (mail, ntfy, your pager).

## Acceptable use

Your node stores and serves whatever correctly-signed records the
network publishes — you cannot see or pre-approve content (it is
end-to-end signed, not encrypted). As an operator you retain the
ultimate control: stopping the daemon, or firewalling specific
records' keys is impractical, but shutting the node down is always one
command. If your jurisdiction or hosting provider has rules about
carrying third-party content, factor them in before joining; the
network has no builtin takedown path (by design — only a record's
owner key can revoke it).
