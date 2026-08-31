// health.go — `status` and `doctor`: the "is my freens working" pair.
//
//	status  plain-language health: daemon up?, each name -> IP, backup
//	        reminder; the raw daemon fields (node ids, hex) live behind -v
//	doctor  ✔/✘ health checks; exit 1 when any ✘ fails:
//	        admin socket, daemon version, DNS fallback path via
//	        127.0.0.1:5300, each keychain alias's apex, peers > 0,
//	        seeds.conf parse, and (warn-only ✱) the OS resolver pointing
//	        at the daemon. --fix repairs what it can BEFORE checking:
//	        missing daemon -> freens setup (idempotent) + wait, unwired
//	        OS resolver -> the same wiring setup performs (interactive
//	        sudo when a password is needed).
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/home"
)

// daemonDNSCheckTimeout bounds the doctor DNS self-check.
const daemonDNSCheckTimeout = 3 * time.Second

// doctorFixWait bounds how long --fix/start wait for a just-started
// daemon to answer on the admin socket (vars so tests shrink them).
var (
	doctorFixWaitAttempts = 20
	doctorFixWaitSleep    = 500 * time.Millisecond
)

// effectiveDNSAddr returns the DNS address the daemon actually listens on:
// the EXPLICIT [listen] "udp =" value from freens.conf, else the
// 127.0.0.1:5300 default setup writes. doctor and the OS-resolver wiring
// must use THIS address — checking the built-in default against a
// user-configured port produces false ✔s (or wires the OS at a dead port).
// The resolver package's parser cannot be used here: it defaults
// ListenUDP to 127.0.0.1:53, which would make "no explicit udp" (setup's
// own 5300 layout, or a malformed file) look like a :53 config.
func effectiveDNSAddr() string {
	b, err := os.ReadFile(home.ConfPath())
	if err != nil {
		return daemonDNSAddr
	}
	inListen := false
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inListen = line == "[listen]"
			continue
		}
		if !inListen {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "udp" {
			if v = strings.TrimSpace(v); v != "" {
				return v
			}
		}
	}
	return daemonDNSAddr
}

// errDaemonNotRunning is status' not-running outcome (exit 1, with the
// fix-it hint printed to stdout).
var errDaemonNotRunning = errors.New("daemon not running")

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	verbose := fs.Bool("v", false, "also print the daemon's raw status fields (node ids, counters)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("status takes no positional arguments")
	}
	c := maybeAdmin()
	if c == nil {
		fmt.Println("daemon not running — start everything with: freens start <name>   (or: freens setup)")
		return errDaemonNotRunning
	}
	ctx, cancel := adminCtx()
	defer cancel()
	st, err := c.Status(ctx)
	if err != nil {
		return fmt.Errorf("daemon status (admin socket %s): %w", home.AdminSock(), err)
	}

	// Plain-language summary first: is it working, and whose names answer.
	peers := int(st.Peers)
	net := fmt.Sprintf("%d peers", peers)
	if peers == 0 {
		net = "no peers yet (offline island)"
	}
	fmt.Printf("daemon: running · version %v · %s\n", st.Version, net)

	aliases := keychainAliases()
	switch {
	case len(aliases) == 0:
		fmt.Printf("names: none yet — claim one with: %s register <name>\n", ProgName)
	default:
		for _, a := range aliases {
			r, err := c.Resolve(ctx, a)
			switch {
			case err != nil:
				fmt.Printf("%s → error: %v\n", a, err)
			case r != nil && r.Revoked:
				fmt.Printf("%s → revoked (dead by owner choice)\n", a)
			case r == nil || !r.Found:
				fmt.Printf("%s → not published yet (did `register` finish?)\n", a)
			default:
				ip := firstAdminIP(r.RRset)
				if ip == "" {
					ip = "no address record"
				}
				fmt.Printf("%s → %s · healthy\n", a, ip)
			}
		}
		if hasRecoveryKeys(aliases[0]) {
			fmt.Printf("backup: recovery keys exist — run `%s backup` and store the file off this machine\n", ProgName)
		}
	}

	// Raw fields for operators (and doctor debugging).
	if *verbose {
		fmt.Printf("admin_socket=%s\n", home.AdminSock())
		fmt.Printf("node_id=%v\n", st.NodeID)
		fmt.Printf("node_pk=%v\n", st.NodePK)
		fmt.Printf("dht_listen=%v\n", st.DHTListen)
		fmt.Printf("advertise=%v\n", st.Advertise)
		fmt.Printf("store_envs=%v\n", st.StoreEnvs)
		fmt.Printf("history_envs=%v\n", st.HistoryEnvs)
		fmt.Printf("relay_mode=%v\n", st.RelayMode)
		fmt.Printf("turn_allocs=%v\n", st.TURNAllocs)
		fmt.Printf("network_claims=%v\n", st.NetworkClaims)
	}
	return nil
}

// hasRecoveryKeys reports whether alias' default register recovery keyfiles
// exist in the keychain — the "a backup is possible (and wise)" signal.
func hasRecoveryKeys(alias string) bool {
	_, err := os.Stat(filepath.Join(home.KeysDir(), alias+".rec1.key"))
	return err == nil
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fix := fs.Bool("fix", false, "repair what doctor would flag: start the daemon if down (runs `setup`, idempotent), wire the OS resolver if unwired")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("doctor takes no positional arguments")
	}
	if *fix {
		runDoctorFixes()
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
	//    the daemon's CONFIGURED listen address — exercising the
	//    conventional-DNS fallback.
	dnsAddr := effectiveDNSAddr()
	check(checkDNSFallback(dnsAddr), "DNS: example.com resolves via %s (fallback path)", dnsAddr)

	// 4. freens path: each keychain alias's apex resolves via the daemon.
	aliases := keychainAliases()
	if len(aliases) == 0 {
		warn("no keychain aliases (~/.freens/keys) — nothing to resolve; register one")
	} else if c != nil {
		ctx, cancel := adminCtx()
		for _, a := range aliases {
			r, err := c.Resolve(ctx, a)
			switch {
			case err != nil:
				check(false, "alias %s resolves (apex): %v", a, err)
			case r != nil && r.Revoked:
				warn("alias %s is REVOKED (deliberate; un-revoke with register/name or drop the key)", a)
			default:
				check(err == nil && r != nil && r.Found, "alias %s resolves (apex)", a)
			}
		}
		cancel()
	}

	// 5. peers.
	if c != nil {
		check(peers > 0, "DHT peers connected (%d)", peers)
	}

	// 6. seeds.conf parses.
	check(checkSeeds(), "seeds.conf parses and has at least one seed")

	// 7. OS resolver + the :53 redirect that makes the wiring complete.
	if points, redirect := osResolverPointsAtDaemon(); points && redirect {
		fmt.Printf("✔ OS resolver points at the daemon (127.0.0.1 + :53 -> %s redirect)\n", effectiveDNSAddr())
	} else if points {
		warn("resolv.conf points at 127.0.0.1 but the :53 -> %s redirect is MISSING — re-run `freens setup` (or freens doctor --fix)", effectiveDNSAddr())
	} else {
		warn("OS resolver does not point at the daemon yet (setup wires it; DNS still works via the daemon port)")
	}

	// 8. Clock sanity (warn-only): freens cryptography is wall-clock
	//    dependent (record validity windows, §7.4 claim ordering, witness
	//    timestamp bounds) — a badly skewed clock registers badly and
	//    resolves badly. Measured against an HTTP Date header; offline or
	//    unreachable is a skip, not a failure.
	if skew, ok := clockSkew(); ok {
		switch {
		case skew < 2*time.Minute:
			fmt.Printf("✔ clock sane (skew %s against internet time)\n", skew.Round(time.Second))
		case skew < 1*time.Hour:
			warn("clock is %s off internet time — fix NTP (records/claims misbehave under skew)", skew.Round(time.Second))
		default:
			warn("clock is %s off internet time — registrations from this machine will misbehave; fix NTP NOW", skew.Round(time.Minute))
		}
	} else {
		warn("could not check clock skew (no internet time source reachable)")
	}

	// 9. §9.5 TLS trust sync: local root present, and (daemon permitting)
	//    which namespaces are cross-certified.
	rootPath := filepath.Join(home.Dir(), "tls", "root.crt")
	rootOK := sysStatExists(rootPath)
	if !rootOK {
		check(false, "TLS local trust root missing (%s) — run `freens trust-install`", rootPath)
	} else if c == nil {
		warn("TLS local trust root present (daemon down: cross-cert state unknown)")
	} else {
		ctx, cancel := adminCtx()
		fp, cross, terr := c.TLSSnapshot(ctx)
		cancel()
		switch {
		case terr != nil:
			warn("TLS trust sync state unavailable (older daemon or disabled: %v)", terr)
		default:
			check(true, "TLS trust root %s…", fp[:16])
			if len(cross) == 0 {
				warn("TLS: no namespaces cross-certified yet — resolve a freens name with a TLSCA record (§9.5.5: first https visit may need one retry)")
			} else {
				names := make([]string, 0, len(cross))
				for _, x := range cross {
					names = append(names, x.Alias)
				}
				fmt.Printf("✔ TLS: %d namespace(s) cross-certified: %s\n", len(cross), strings.Join(names, ", "))
			}
		}
	}

	if failed > 0 {
		return fmt.Errorf("doctor: %d check(s) failed", failed)
	}
	fmt.Println("doctor: all checks passed")
	return nil
}

// runDoctorFixes is doctor --fix: repair the two things a user can't fix
// wrong — the daemon not running (re-run setup: idempotent, ends with
// systemctl enable --now) and the OS resolver not pointing at the daemon
// (the same wiring setup performs, interactive sudo on a TTY). Everything
// else doctor checks is network state only time/peers can fix.
func runDoctorFixes() {
	c := maybeAdmin()
	if c == nil || !sysStatExists(home.ConfPath()) || !checkSeeds() {
		fmt.Println("fix: daemon down or install incomplete — running `freens setup` (safe to re-run)")
		if err := setupInstall(); err != nil {
			fmt.Printf("fix: setup failed: %v\n", err)
		}
		if waitForAdminSocket() {
			fmt.Println("fix: ✔ daemon is answering on the admin socket")
		} else if goosWindows {
			fmt.Println("fix: ✘ daemon still not answering — start it manually: `net start freens` (elevated) or re-run `freens setup`")
		} else {
			fmt.Println("fix: ✘ daemon still not answering — start it manually: sudo systemctl start freens.service")
		}
	}
	if points, redirect := osResolverPointsAtDaemon(); !points || !redirect {
		fmt.Println("fix: OS resolver wiring incomplete — wiring it now")
		fmt.Println(wireOSResolver())
	}
}

// waitForAdminSocket polls for a daemon answer (used after a service
// start): true once maybeAdmin() returns a client.
func waitForAdminSocket() bool {
	for i := 0; i < doctorFixWaitAttempts; i++ {
		if maybeAdmin() != nil {
			return true
		}
		time.Sleep(doctorFixWaitSleep)
	}
	return maybeAdmin() != nil
}

// clockSkew measures |local clock − internet time| via HTTP Date headers
// (second-granularity, plenty for the minutes-level sanity we need).
// ok=false means "could not measure" (offline / filtered), never an error.
// The endpoint set is swapped in tests.
var clockSkewProbes = []string{"https://1.1.1.1/", "https://www.google.com/"}

func clockSkew() (time.Duration, bool) {
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, url := range clockSkewProbes {
		resp, err := client.Head(url)
		if err != nil {
			continue
		}
		resp.Body.Close()
		d := resp.Header.Get("Date")
		if d == "" {
			continue
		}
		remote, err := http.ParseTime(d)
		if err != nil {
			continue
		}
		skew := time.Since(remote)
		if skew < 0 {
			skew = -skew
		}
		return skew, true
	}
	return 0, false
}

// checkDNSFallback resolves a known upstream name through the daemon's DNS
// listener (its configured address) with a Go net.Resolver pinned to it.
func checkDNSFallback(addr string) bool {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: daemonDNSCheckTimeout}
			return d.DialContext(ctx, "udp", addr)
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

// osResolverPointsAtDaemon reports (points, redirectComplete): whether the
// OS resolver sends queries to the daemon AND the :53 traffic path is
// complete. On Linux that is /etc/resolv.conf -> 127.0.0.1 (the working
// freens wiring — a bare loopback nameserver; the v0.2.0 "127.0.0.1:5300"
// form was invalid resolv.conf syntax and is treated as legacy) plus the
// port-53 redirect in the firewall. On Windows the daemon LISTENS on :53
// directly (no privileged-port concept, no redirect), so "redirect" just
// means the daemon's port IS 53 and "points" means an adapter carries the
// daemon loopback in its DNS server list.
func osResolverPointsAtDaemon() (points, redirect bool) {
	if goosWindows {
		return windowsAdapterDNSWired("127.0.0.1"), portOfAddr(effectiveDNSAddr()) == "53"
	}
	data, err := os.ReadFile(pathResolvConf)
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "nameserver 127.0.0.1" || line == "nameserver 127.0.0.1:5300" {
				points = true
				break
			}
		}
	}
	redirect = port53RedirectInstalled()
	return points, redirect
}

// port53RedirectInstalled reports whether an active :53 redirect exists
// (our nft table, an nft ruleset redirect to the daemon port, or iptables
// REDIRECT rules). Swappable probe for tests.
var port53RedirectInstalled = func() bool {
	if out, err := exec.Command("sudo", "-n", "nft", "list", "ruleset").Output(); err == nil {
		s := string(out)
		if strings.Contains(s, "redirect to :"+portOfAddr(effectiveDNSAddr())) ||
			strings.Contains(s, "redirect to 127.0.0.1:"+portOfAddr(effectiveDNSAddr())) ||
			strings.Contains(s, "chain "+nftTableName) {
			return true
		}
	}
	if out, err := exec.Command("sudo", "-n", "iptables", "-t", "nat", "-S", "OUTPUT").Output(); err == nil {
		return strings.Contains(string(out), "--to-ports "+portOfAddr(effectiveDNSAddr()))
	}
	return false
}

// portOfAddr splits "host:port" ("" when malformed).
func portOfAddr(addr string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return p
	}
	return ""
}
