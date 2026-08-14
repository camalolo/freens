package dht

// stun_loop.go — §6.2 NAT traversal via STUN (RFC 5389 Binding).
//
// A node behind NAT that knows no dialable address sets NodeConfig.Stun to a
// STUN server; startSTUN then discovers the server-reflexive address and
// advertises it to peers (exactly like an explicit NodeConfig.Advertise):
// the discovered "ip:port" is written via setAdvertise and therefore stamped
// on every outbound query's "advertise" arg, so peers learnPeer this node at
// its public address instead of the NAT'd private observed source.
//
// Lifecycle note (why the monitor is NOT registered in n.bgWg): Close()
// runs stopBackground() — which WAITS on n.bgWg — BEFORE storing n.closed,
// and this monitor's only shutdown signal is n.closed. Registering it in
// bgWg would therefore deadlock Close (stopBackground would wait for a
// goroutine that cannot observe the flag until stopBackground returns).
// Instead the monitor polls n.closed once per second and exits on its own:
// each discovery attempt is capped at 3 s by the stun client, so the
// goroutine terminates within ~4 s of Close while holding no Node resources
// (every attempt dials its own throwaway UDP socket, and advertise writes
// are mutex-guarded).

import (
	"context"
	"net"
	"time"

	"github.com/laurent/freens/internal/stun"
)

// stunRefreshInterval is the period between STUN reflexive-address
// re-discoveries (NodeConfig.Stun: "Refreshed periodically so address
// changes are picked up"). A daemon-level knob, not a spec constant — the
// spec fixes the mechanism (§6.2 advertise + STUN), not the refresh cadence.
const stunRefreshInterval = 60 * time.Second

// startSTUN launches the STUN reflexive-address monitor when configured.
// No-op unless NodeConfig.Stun is set AND no explicit Advertise was given
// (an explicit address always wins over a discovered one — §6.2 line 422:
// the advertised (ip, port) is operator policy, not a best guess).
func (n *Node) startSTUN() {
	if n.stun == "" {
		return // monitor off: nothing to discover from
	}
	if adv := n.advertised(); adv != "" {
		n.log.Info("dht: explicit Advertise set; STUN discovery disabled (explicit address wins)",
			"advertise", adv, "stun", n.stun)
		return
	}
	// Resolve the server ONCE (net.ResolveUDPAddr, so hostnames are fine).
	// An unresolvable server disables the monitor with a warning rather
	// than failing Start — a broken STUN config must not brick the node,
	// mirroring the invalid-Advertise fallback in Start().
	server, err := net.ResolveUDPAddr("udp", n.stun)
	if err != nil {
		n.log.Warn("dht: cannot resolve STUN server; NAT discovery disabled",
			"stun", n.stun, "err", err)
		return
	}
	go n.stunMonitor(server)
}

// stunMonitor is the §6.2 monitor loop: discover, advertise, sleep, repeat.
// Each iteration uses a fresh stun.Client (fresh UDP socket per discovery —
// a reflexive address is only valid for the 5-tuple it was observed on).
// Discovery failures never clear an established advertisement; they log one
// Warn at the start of each consecutive-failure streak so a down server
// cannot spam the log every refresh.
func (n *Node) stunMonitor(server *net.UDPAddr) {
	warned := false // Warn-once-per-streak latch
	for !n.closed.Load() {
		reflex, err := (&stun.Client{Server: server.String()}).Discover(context.Background())
		switch {
		case err != nil:
			if !warned {
				n.log.Warn("dht: STUN discovery failed; keeping current advertisement",
					"stun", n.stun, "err", err)
				warned = true
			}
		default:
			warned = false
			n.advertiseReflexive(reflex)
		}
		if !n.stunNap() {
			return // node closed mid-sleep
		}
	}
}

// advertiseReflexive adopts a freshly discovered reflexive address when it
// differs from the current advertisement.
//
// Address sanity: the unspecified address (0.0.0.0 / ::) is never
// advertised — it names no host. Private and loopback reflexive addresses
// ARE advertised (with the normal Info log): advertising a private address
// is pointless behind NAT but harmless — and correct — on LAN-only testnets,
// and a loopback discovery (e.g. this node's STUN server on the same host)
// is exactly what LAN/lab deployments and the transport tests observe.
func (n *Node) advertiseReflexive(a *net.UDPAddr) {
	if a == nil || a.IP == nil || a.IP.IsUnspecified() {
		return // nothing dialable to advertise
	}
	addr := a.String()
	if addr == n.advertised() {
		return // unchanged since the last refresh: no churn, no log spam
	}
	n.setAdvertise(addr)
	n.log.Info("dht: STUN discovered reflexive address, advertising", "addr", addr)
}

// stunNap sleeps stunRefreshInterval in one-second slices so the monitor
// notices n.closed promptly (it has no context to select on — see the file
// header). Returns false when the node is closed and the caller must exit.
func (n *Node) stunNap() bool {
	for i := 0; i < int(stunRefreshInterval/time.Second); i++ {
		if n.closed.Load() {
			return false
		}
		time.Sleep(time.Second)
	}
	return !n.closed.Load()
}
