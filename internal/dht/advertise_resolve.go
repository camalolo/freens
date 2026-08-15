package dht

// advertise_resolve.go — hostname-shaped NodeConfig.Advertise re-resolution
// (§6.2 "nodes advertise (ip, port, node_pubkey)").
//
// WHY. Start resolves NodeConfig.Advertise ONCE and stamps the resulting
// literal "ip:port" on every outbound query. That is wrong for the seed-node
// pattern this file exists for: a PPPoE/dynDNS seed advertises a HOSTNAME
// (-advertise freens.camalolo.com:15353, kept current by the Cloudflare
// DDNS timer in contrib/) whose underlying IP drifts on every re-dial. The
// peers' learnPeer only ever trusts literal addresses (parseAdvertisedAddr
// rejects hostnames on the read-loop hot path — no DNS there), so the seed
// itself must re-resolve and re-advertise: when the hostname's IP changes,
// this monitor calls UpdateAdvertise(newIP:samePort) and the next outbound
// query teaches every peer the fresh address.
//
// MONITOR. Every interval (5 minutes by default) the ORIGINAL hostname
// (captured at Start, never the resolved literal) is re-resolved; only an
// actual IP change updates the advertisement (no churn, no log spam on a
// stable line). A resolution failure keeps the current advertisement — the
// hostname may be briefly unresolvable mid-re-dial — logging one Warn per
// consecutive-failure streak, mirroring the STUN monitor.
//
// Lifecycle note (why the monitor is NOT registered in n.bgWg — same
// reasoning as stun_loop.go): Close() runs stopBackground() — which WAITS
// on n.bgWg — BEFORE storing n.closed, and this monitor's only shutdown
// signal is n.closed. Registering it in bgWg would deadlock Close. It
// instead polls n.closed at nap granularity and exits on its own, holding
// no Node resources (every iteration is one resolver call plus a
// mutex-guarded advertise write).
//
// Wiring deviation (documented): Start() itself never launches this
// monitor — Node.Start lives in transport.go, which is frozen to changes
// beyond the Advertised() getter. The daemon opts in right after Start:
//
//	n, _ := dht.NewNode(dht.NodeConfig{Advertise: "seed.example.net:15353", ...})
//	n.Start()
//	n.StartAdvertiseResolve("seed.example.net:15353")
//
// The monitor owns the advertisement from then on: explicit Advertise
// already outranks STUN/TURN/UPnP discovery (precedence Advertise >
// TurnRelay > Stun), and those paths only run when Advertise is empty, so
// no other writer competes for n.advertise while it is alive.

import (
	"net"
	"strconv"
	"sync"
	"time"
)

// advResolve holds the monitor's two knobs: the resolver it re-resolves
// hostnames through and the re-check interval. They live behind an RW
// mutex (not as bare package vars) because tests INJECT them while the
// monitor goroutine is running — flipping an unguarded package var would
// be a data race by definition, and the race detector rightly flags it
// even against an already-finished goroutine (no happens-before edge).
type advResolveKnobs struct {
	sync.RWMutex
	resolve  func(network, addr string) (*net.UDPAddr, error) // default net.ResolveUDPAddr
	interval time.Duration                                    // default 5 minutes
}

var advResolve = advResolveKnobs{
	resolve:  net.ResolveUDPAddr,
	interval: 5 * time.Minute,
}

// advertiseResolveInterval returns the current re-check interval. Five
// minutes: the same cadence as the DDNS timer and the UPnP renewal loop,
// so a PPPoE re-dial is picked up within one DNS TTL window on both the
// DNS side and the advertise side. A daemon-level knob, not a spec
// constant — the spec fixes the advertise mechanism (§6.2), not the
// refresh cadence.
func advertiseResolveInterval() time.Duration {
	advResolve.RLock()
	defer advResolve.RUnlock()
	return advResolve.interval
}

// resolveAdvertiseHost resolves host:port through the injected resolver.
func resolveAdvertiseHost(host string, port int) (*net.UDPAddr, error) {
	advResolve.RLock()
	fn := advResolve.resolve
	advResolve.RUnlock()
	return fn("udp", net.JoinHostPort(host, strconv.Itoa(port)))
}

// setAdvertiseResolveKnobs installs test knobs (fake resolver, shortened
// interval) and returns a restore func. Production code never calls it.
func setAdvertiseResolveKnobs(resolve func(network, addr string) (*net.UDPAddr, error), interval time.Duration) (restore func()) {
	advResolve.Lock()
	oldResolve, oldInterval := advResolve.resolve, advResolve.interval
	advResolve.resolve, advResolve.interval = resolve, interval
	advResolve.Unlock()
	return func() {
		advResolve.Lock()
		advResolve.resolve, advResolve.interval = oldResolve, oldInterval
		advResolve.Unlock()
	}
}

// StartAdvertiseResolve launches the hostname re-resolve monitor for orig
// (the ORIGINAL NodeConfig.Advertise value, hostname form). No-op unless
// orig is hostname-shaped: an IP literal needs no re-resolution, and a
// value without host:port shape was already rejected by Start's
// validateAdvertise. The monitor is a goroutine closed over (host, port,
// last-applied address) — nothing is stored on Node beyond what Close()
// already owns (the closed flag it polls).
func (n *Node) StartAdvertiseResolve(orig string) {
	if n.closed.Load() {
		return // raced a shutdown: nothing to watch
	}
	host, portStr, err := net.SplitHostPort(orig)
	if err != nil || host == "" || portStr == "" {
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return
	}
	if net.ParseIP(host) != nil {
		return // IP literal: static by construction, nothing to re-resolve
	}
	// Seed "last applied" with whatever Start validated ("" when the
	// hostname was UNRESOLVABLE at Start — the monitor then self-heals the
	// advertisement on its first successful resolve instead of leaving the
	// node on observed-source mode forever).
	go n.advertiseResolveMonitor(host, port, n.advertised())
}

// advertiseResolveMonitor is the watch loop: nap, re-resolve the ORIGINAL
// hostname, adopt the address when its IP changed. current is the last
// address THIS monitor applied (its own bookkeeping, not live node state —
// the monitor owns the advertisement for the lifetime of the hostname
// advertise, per the precedence rules in the file header).
func (n *Node) advertiseResolveMonitor(host string, port int, current string) {
	warned := false // Warn-once-per-streak latch, mirroring stunMonitor
	for !n.closed.Load() {
		if !n.advertiseResolveNap() {
			return // node closed mid-sleep
		}
		a, err := resolveAdvertiseHost(host, port)
		if err != nil || a == nil || a.IP == nil || a.IP.IsUnspecified() {
			if !warned {
				n.log.Warn("dht: advertise hostname re-resolve failed; keeping current advertisement",
					"advertise_host", host, "err", err)
				warned = true
			}
			continue
		}
		warned = false
		addr := net.JoinHostPort(a.IP.String(), strconv.Itoa(port))
		if addr == current {
			continue // unchanged since the last refresh: no churn
		}
		if uerr := n.UpdateAdvertise(addr); uerr != nil {
			// Cannot happen for the literal ip:port built above; kept for
			// defense (a resolver returning a zone'd address, say).
			n.log.Warn("dht: advertise re-resolve produced an invalid address; keeping current",
				"addr", addr, "err", uerr)
			continue
		}
		current = addr
		n.log.Info("dht: advertise hostname re-resolved; advertising new address",
			"advertise_host", host, "addr", addr)
	}
}

// advertiseResolveNap sleeps the re-check interval in slices of at most
// one second so the monitor notices n.closed promptly (it has no context
// to select on — see the file header). Returns false when the node is
// closed and the caller must exit.
func (n *Node) advertiseResolveNap() bool {
	interval := advertiseResolveInterval()
	slice := time.Second
	if interval < slice {
		slice = interval
	}
	for slept := time.Duration(0); slept < interval; slept += slice {
		if n.closed.Load() {
			return false
		}
		time.Sleep(slice)
	}
	return !n.closed.Load()
}
