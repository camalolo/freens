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
# as root or with sudo — a server has no user session, so we install a
# SYSTEM service instead of the desktop `freens setup` path
curl -L -o freens.tar.gz https://github.com/camalolo/freens/releases/latest/download/freens-linux-amd64.tar.gz
tar xzf freens.tar.gz && install -m755 freens-linux-amd64/freens /usr/local/bin/freens

freens setup          # writes ~/.freens: freens.conf, node key, seeds.conf
                      # (the systemd --user service step will no-op on a
                      # headless box; ignore it — step 2 installs the system
                      # service instead)
```

Then edit `~/.freens/freens.conf`'s `[dht]` section for a public node:

```ini
[dht]
listen = 0.0.0.0:15353            ; the community port (UDP)
advertise = YOUR.PUBLIC.IP:15353  ; or a hostname; omit behind UPnP
persist = /var/lib/freens/store   ; records survive restarts (mkdir -p it)
upnp = true                       ; home servers: router maps the port
```

Open UDP 15353 in any firewall (`ufw allow 15353/udp`).

## 2. The system service

```bash
sudo mkdir -p /var/lib/freens/store /etc/systemd/system
sudo tee /etc/systemd/system/freens.service >/dev/null <<EOF
[Unit]
Description=freens community node (self-certifying DNS)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/freens daemon -config $HOME/.freens/freens.conf
Restart=on-failure
RestartSec=2
User=YOURUSER

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now freens
```

> `$HOME` expands when the heredoc is written, so the unit gets the
> absolute path — check `ExecStart` if your home is elsewhere. The
> daemon's admin socket stays a 0600 unix socket in `~/.freens` — local
> CLI only, nothing remote.

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
