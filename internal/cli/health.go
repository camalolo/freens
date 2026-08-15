// health.go — `status` and `doctor`: the "is my freens working" pair.
//
//	status  pretty-print the running daemon's admin status + a dig-free
//	        self-check (admin.Resolve of the user's first keychain alias)
//	doctor  ✔/✘ health checks; exit 1 when any ✘ fails:
//	        admin socket, daemon version, DNS fallback path via
//	        127.0.0.1:5300, each keychain alias's apex, peers > 0,
//	        seeds.conf parse + first-seen dial, and (warn-only ✱) the OS
//	        resolver pointing at the daemon.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/laurent/freens/internal/home"
)

// daemonDNSCheckTimeout bounds the doctor DNS self-check.
const daemonDNSCheckTimeout = 3 * time.Second

// errDaemonNotRunning is status' not-running outcome (exit 1, with the
// fix-it hint printed to stdout).
var errDaemonNotRunning = errors.New("daemon not running")

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("status takes no positional arguments")
	}
	c := maybeAdmin()
	if c == nil {
		fmt.Println("daemon not running — freens setup")
		return errDaemonNotRunning
	}
	ctx, cancel := adminCtx()
	defer cancel()
	st, err := c.Status(ctx)
	if err != nil {
		return fmt.Errorf("daemon status (admin socket %s): %w", home.AdminSock(), err)
	}
	fmt.Printf("daemon=running (admin socket %s)\n", home.AdminSock())
	fmt.Printf("version=%v\n", st.Version)
	fmt.Printf("node_id=%v\n", st.NodeID)
	fmt.Printf("node_pk=%v\n", st.NodePK)
	fmt.Printf("dht_listen=%v\n", st.DHTListen)
	fmt.Printf("advertise=%v\n", st.Advertise)
	fmt.Printf("peers=%v\n", st.Peers)
	fmt.Printf("store_envs=%v\n", st.StoreEnvs)
	fmt.Printf("history_envs=%v\n", st.HistoryEnvs)
	fmt.Printf("relay_mode=%v\n", st.RelayMode)
	fmt.Printf("turn_allocs=%v\n", st.TURNAllocs)
	fmt.Printf("network_claims=%v\n", st.NetworkClaims)

	// Dig-free self-check: resolve the user's first keychain alias apex.
	if aliases := keychainAliases(); len(aliases) > 0 {
		a := aliases[0]
		r, err := c.Resolve(ctx, a)
		switch {
		case err != nil:
			fmt.Printf("self-check: alias %s: error: %v\n", a, err)
		case r == nil || !r.Found:
			fmt.Printf("self-check: alias %s: not found (did `register` finish?)\n", a)
		default:
			ip := firstAdminAIP(r.RRset)
			fmt.Printf("self-check: alias %s: found, sequence=%v apex_a=%s\n", a, r.Sequence, ip)
		}
	} else {
		fmt.Println("self-check: no keychain aliases yet — register one with `register -alias <you>`")
	}
	return nil
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("doctor takes no positional arguments")
	}
	failed := 0
	check := func(ok bool, format string, args ...any) {
		mark := "✔"
		if !ok {
			mark = "✘"
			failed++
		}
		fmt.Printf("%s %s\n", mark, fmt.Sprintf(format, args...))
	}
	warn := func(format string, args ...any) {
		fmt.Printf("✱ %s\n", fmt.Sprintf(format, args...))
	}

	// 1. admin socket.
	sock := home.AdminSock()
	c := maybeAdmin()
	check(c != nil, "admin socket alive (%s)", sock)

	// 2. daemon version (needs the socket).
	var peers int
	if c != nil {
		ctx, cancel := adminCtx()
		st, err := c.Status(ctx)
		cancel()
		if err != nil || st == nil {
			check(false, "daemon version: status RPC failed (%v)", err)
		} else {
			check(true, "daemon version %v", st.Version)
			peers = int(st.Peers)
		}
	} else {
		check(false, "daemon version: no daemon (start one with: freens setup)")
	}

	// 3. DNS path through the daemon: a known upstream name resolves via
	//    127.0.0.1:5300 — exercising the conventional-DNS fallback.
	check(checkDNSFallback(), "DNS: example.com resolves via %s (fallback path)", daemonDNSAddr)

	// 4. freens path: each keychain alias's apex resolves via the daemon.
	aliases := keychainAliases()
	if len(aliases) == 0 {
		warn("no keychain aliases (~/.freens/keys) — nothing to resolve; register one")
	} else if c != nil {
		ctx, cancel := adminCtx()
		for _, a := range aliases {
			r, err := c.Resolve(ctx, a)
			check(err == nil && r != nil && r.Found, "alias %s resolves (apex)", a)
		}
		cancel()
	}

	// 5. peers.
	if c != nil {
		check(peers > 0, "DHT peers connected (%d)", peers)
	}

	// 6. seeds.conf parses + the first seed answers a dial.
	check(checkSeeds(), "seeds.conf parses and the first seed is dialable")

	// 7. OS resolver (warn-only).
	if osResolverPointsAtDaemon() {
		fmt.Printf("✔ OS resolver points at the daemon\n")
	} else {
		warn("OS resolver does not point at %s yet (setup wires it; DNS still works via the daemon port)", daemonDNSAddr)
	}

	if failed > 0 {
		return fmt.Errorf("doctor: %d check(s) failed", failed)
	}
	fmt.Println("doctor: all checks passed")
	return nil
}

// checkDNSFallback resolves a known upstream name through the daemon's DNS
// listener (127.0.0.1:5300) with a Go net.Resolver pinned to that address.
func checkDNSFallback() bool {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: daemonDNSCheckTimeout}
			return d.DialContext(ctx, "udp", daemonDNSAddr)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), daemonDNSCheckTimeout)
	defer cancel()
	_, err := r.LookupHost(ctx, "example.com")
	return err == nil
}

// checkSeeds verifies seeds.conf parses with the daemon's own
// home.ParseSeeds and the first entry is well-formed. Liveness is
// deliberately NOT dialed here: the DHT is UDP (a TCP probe would
// false-negative every healthy seed), and seed reachability is already
// covered by the peers-connected check — a node with peers got them from
// somewhere.
func checkSeeds() bool {
	peers := home.ParseSeeds(home.SeedsPath())
	return len(peers) > 0
}

// osResolverPointsAtDaemon reports whether /etc/resolv.conf names the daemon
// (the systemd-resolved drop-in path funnels into resolv.conf's stub too).
func osResolverPointsAtDaemon() bool {
	data, err := os.ReadFile(pathResolvConf)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), daemonDNSAddr)
}
