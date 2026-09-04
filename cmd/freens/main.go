// Command freens runs the freens local DNS resolver daemon (spec §9.1
// deployment model).
//
// The daemon serves freens records from an in-process [dht.EnvelopeStore] and,
// when the DHT transport is enabled (-dht), participates as a full Kademlia
// node (§6.2-§6.4): it answers ping/find_node/get/put RPCs over UDP and fetches
// records from peers on a local-store miss, so records published on (or seeded
// into) one node resolve from any peered node. Records may also be seeded into
// the local store on startup via the -load flag (a directory of *.cbor envelope
// files as produced by freens-cli make-record). Conventional DNS questions
// outside the freens namespace are forwarded to upstream recursive resolvers.
//
// Usage:
//
//	freens [-config <path>] [-listen <addr>] [-dns <addr>] [-upstream <csv>]
//	       [-load <dir>] [-dht <addr>] [-node-seed <hex>] [-peers <addr#pk>,...]
//	       [-peers-file <path>] [-passive] [-advertise <addr>] [-stun <addr>]
//	       [-turn <addr>] [-turn-relay <addr>] [-persist <dir>] [-metrics <addr>] [-idna]
//
// If -config is absent a built-in default config is used (127.0.0.1:53,
// upstreams 9.9.9.9 / 1.1.1.1, "* = dns-first"). If binding UDP/TCP port 53 is
// forbidden by the OS, the daemon logs guidance (spec §9.1) — use a high port
// with a redirect, or grant CAP_NET_BIND_SERVICE.
//
// DHT transport (-dht): binds the Kademlia UDP socket (spec default port
// 15353). Because every RPC is signed over the recipient's Node ID, a node can
// only address a peer whose public key it knows, so -peers takes entries of the
// form "ip:port#<64-hex-pubkey>". The node's own public key (needed by peers) is
// logged at startup. With -dht empty, the daemon is a single-node island.
//
// -passive (spec §6.1 "clients MAY disable participation"): the DHT node still
// answers ping/find_node/get from its store but refuses put and never
// republishes others' records.
//
// -idna / [options] "idna = true" (spec §3.2 MAY: IDNA2008 U-labels): calls
// naming.EnableIDNA() before any name parsing happens (it flips a
// package-global normalizer, so it must precede config parsing and server
// start). See the flag help for exactly what it changes on the wire.
//
// -persist <dir> (requires -dht): snapshots the envelope store to <dir> as
// <keyhex>.cbor every 60s and once at shutdown, so records fetched over the
// DHT survive restarts; point -load at the same dir to re-seed them (the §6.4
// winner rule makes this idempotent).
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/cli"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/metrics"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/renewal"
	"github.com/camalolo/freens/internal/resolver"
	"github.com/camalolo/freens/internal/securekey"
	"github.com/camalolo/freens/internal/trustsync"
	"github.com/camalolo/freens/internal/turn"
	"github.com/camalolo/freens/internal/upnp"
	"github.com/camalolo/freens/internal/wire"
	"github.com/miekg/dns"
)

// builtinDefaultConfig is used when -config is absent: a safe "* = dns-first"
// resolver listening on 127.0.0.1:53 with public upstreams (spec §9.1). The
// freens community namespace gets an explicit freens-first route: it is not
// an ICANN TLD, so asking public upstreams for it first only leaks every
// freens name (and lets a spoofed upstream NOERROR shadow the DHT answer —
// found in the v0.7.1 security audit); freens-first still falls through to
// DNS on a miss, preserving the non-surprising default for ordinary names.
const builtinDefaultConfig = `[listen]
udp = 127.0.0.1:53
tcp = 127.0.0.1:53
[upstream]
servers = 9.9.9.9, 1.1.1.1
[tld-routes]
freens = freens-first
* = dns-first
`

func main() {
	// Launched by the Windows service manager: enter the SCM control loop
	// (it runs the daemon; this never returns). Must be the FIRST check —
	// a service has no usable argv and must answer the SCM promptly.
	if windowsServiceRequested() {
		os.Exit(windowsRunService())
	}
	// Single-binary front: `freens <verb>` (register, setup, name, doctor,
	// gen-key, publish, … — the full internal/cli dispatch) runs the CLI;
	// `freens daemon [flags…]` or bare flags run the resolver daemon
	// (bare-flag form is the historical one and stays). A BARE `freens`
	// with no arguments at all prints the first-timer quickstart instead
	// of helplessly trying privileged port 53 (the daemon path stays
	// reachable via the explicit `daemon` verb, which the systemd unit
	// uses).
	if len(os.Args) > 1 {
		sub := os.Args[1]
		if sub != "daemon" && sub != "version" && sub != "-version" && sub != "--version" &&
			!strings.HasPrefix(sub, "-") {
			cli.ProgName = "freens"
			cli.Version = version
			os.Exit(cli.Main(os.Args[1:]))
		}
	} else {
		fmt.Println("to run the resolver daemon itself: freens daemon   (see contrib/ for OS integration)")
		fmt.Println()
		os.Exit(cli.Main(nil))
	}
	if err := run(daemonArgs(os.Args[1:])); err != nil {
		fmt.Fprintf(os.Stderr, "freens: %v\n", err)
		os.Exit(1)
	}
}

// daemonArgs strips the optional literal "daemon" subcommand so both
// `freens daemon -dht :15353` and `freens -dht :15353` parse identically.
func daemonArgs(args []string) []string {
	if len(args) > 0 && args[0] == "daemon" {
		return args[1:]
	}
	return args
}

// version is stamped at build time (-ldflags "-X main.version=vX.Y.Z");
// "dev" marks a locally built binary.
var version = "dev"

// serviceStop is closed by the Windows service control handler when the
// SCM asks the service to stop (Always nil elsewhere — a select on a nil
// channel never fires). run() watches it alongside SIGINT/SIGTERM so the
// same shutdown sequence serves the console and the service.
var serviceStop chan struct{}

// daemonLogSink is where the daemon's slog output goes: os.Stderr by
// default; the Windows service (which has no console at all) points it at
// <home>/daemon.log before entering the SCM handler.
var daemonLogSink io.Writer

// systemStoreWritable reports whether the process may install directly
// into the OS trust store (root on unix). On Windows the plumbing in
// internal/trustsync degrades to the per-user store by itself, so the
// attempt is always worth making (the service runs as LocalSystem = the
// machine store).
var systemStoreWritable = func() bool { return os.Geteuid() == 0 }

func run(args []string) error {
	if len(args) > 0 && (args[0] == "version" || args[0] == "-version" || args[0] == "--version") {
		fmt.Println("freens", version)
		return nil
	}
	fs := flag.NewFlagSet("freens", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: freens [-config <path>] [-listen <addr>] [-dns <addr>] [-upstream <csv>]")
		fmt.Fprintln(fs.Output(), "             [-load <dir>] [-dht <addr>] [-node-seed <hex>] [-peers <addr#pk>,...]")
		fmt.Fprintln(fs.Output(), "             [-peers-file <path>] [-passive] [-advertise <addr>] [-stun <addr>]")
		fmt.Fprintln(fs.Output(), "             [-turn <addr>] [-turn-relay <addr>] [-upnp] [-persist <dir>] [-metrics <addr>] [-idna]")
		fs.PrintDefaults()
	}
	f := defineFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Unexpected positionals are an ERROR, not an accident to run past:
	// `freens daemon foo` must never silently start on built-in defaults
	// (found live: the SCM delivered the service NAME as an argument, the
	// daemon flag-parsed nothing and ran config-less — DNS up, DHT and
	// admin socket dead — with no complaint anywhere).
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument(s) after the daemon flags: %s (see -h)", strings.Join(fs.Args(), " "))
	}
	configPath, listenAddr, dnsAddr, upstreamCSV, loadDir := f.configPath, f.listenAddr, f.dnsAddr, f.upstreamCSV, f.loadDir
	dhtAddr, nodeSeedHex, peersCSV, peersFile, metricsAddr := f.dhtAddr, f.nodeSeedHex, f.peersCSV, f.peersFile, f.metricsAddr
	passive, advertiseAddr, stunAddr := f.passive, f.advertiseAddr, f.stunAddr
	turnAddr, turnRelayAddr, persistDir, idnaFlag := f.turnAddr, f.turnRelayAddr, f.persistDir, f.idna
	allowReservedFlag := f.allowReserved
	upnpEnabled := f.upnpEnabled

	// Per-setting precedence everywhere below: an explicitly-passed flag
	// wins; otherwise the -config file ([dht] section for the network side,
	// [options]/[tld-routes] for the resolver side); otherwise the default.
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	// The Windows service has no console: slog goes to <home>/daemon.log
	// (daemonLogSink is set before the SCM handler starts). Everywhere else
	// this is os.Stderr, as always.
	sink := io.Writer(os.Stderr)
	if daemonLogSink != nil {
		sink = daemonLogSink
	}
	logger := slog.New(slog.NewTextHandler(sink, nil))
	slog.SetDefault(logger)

	// Enable IDNA BEFORE any name parsing: ParseConfig validates [tld-routes]
	// and [alias-pins] keys through naming, and the servers below parse query
	// names through naming too — it is package-global state (spec §3.2).
	if *idnaFlag {
		naming.EnableIDNA()
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if !set["idna"] && cfg.EnableIDNA {
		naming.EnableIDNA()
	}
	// [dht] section: the network side of the same file (flag > config >
	// default, per setting — see dhtconfig.go).
	dhtCfg, err := loadDHTConfig(*configPath)
	if err != nil {
		return fmt.Errorf("config [dht]: %w", err)
	}
	dhtEffective := pickString(set["dht"], *dhtAddr, dhtCfg.Listen, "")
	nodeSeedEffective := pickString(set["node-seed"], *nodeSeedHex, dhtCfg.NodeSeed, "")
	peersCSVEffective := pickString(set["peers"], *peersCSV, dhtCfg.Peers, "")
	peersFileEffective := pickString(set["peers-file"], *peersFile, dhtCfg.PeersFile, "")
	advertiseEffective := pickString(set["advertise"], *advertiseAddr, dhtCfg.Advertise, "")
	stunEffective := pickString(set["stun"], *stunAddr, dhtCfg.Stun, "")
	turnEffective := pickString(set["turn"], *turnAddr, dhtCfg.Turn, "")
	turnRelayEffective := pickString(set["turn-relay"], *turnRelayAddr, dhtCfg.TurnRelay, "")
	persistEffective := pickString(set["persist"], *persistDir, dhtCfg.Persist, "")
	passiveEffective := pickBool(set["passive"], *passive, dhtCfg.Passive, false)
	// -upnp defaults ON; only an explicit -upnp=false flag or upnp = false
	// in [dht] turns it off (upnp = true in the file is a no-op).
	upnpEffective := !(set["upnp"] && !*upnpEnabled) && !dhtCfg.UPnPOff

	// Persistence ROUND TRIP (found live on the 7-node LAN): -persist
	// writes snapshots, but nothing reloaded them — records lived only in
	// RAM, so restarting the whole fleet at once emptied every store
	// simultaneously while the .cbor files sat on disk unread. When -load
	// is unset, default it to the persist dir so a restart re-seeds the
	// store from its own snapshots (idempotent under the §6.4 winner rule;
	// an explicit -load still wins). A defaulted load on a NOT-YET-EXISTING
	// dir (fresh install: the first persist tick creates it) is skipped —
	// only an EXPLICIT -load errors on a missing dir (found live on the
	// cross-internet test node: first boot with persist=/fresh/path).
	loadEffective := resolveLoadForBoot(*loadDir, persistEffective)

	// Apply CLI overrides.
	if *listenAddr != "" {
		cfg.ListenUDP = *listenAddr
	}
	if *dnsAddr != "" {
		cfg.ListenUDP = *dnsAddr
		cfg.ListenTCP = *dnsAddr
	}
	if *upstreamCSV != "" {
		cfg.UpstreamServers = splitCSV(*upstreamCSV)
	}
	// §7.7 reserved-alias override: flag > config [options] > default (off).
	// One effective value drives BOTH gates — the witness side (NodeConfig.
	// AllowReserved) and the resolver/admin side (cfg.AllowReserved + the
	// admin Server mirror) — so a node cannot end up with split policy.
	cfg.AllowReserved = pickBool(set["allow-reserved"], *allowReservedFlag, cfg.AllowReserved, false)
	applyUpstreamDefault(cfg)

	logger.Info("freens daemon starting",
		"listen_udp", cfg.ListenUDP,
		"listen_tcp", cfg.ListenTCP,
		"upstream", cfg.UpstreamServers,
		"load_dir", loadEffective,
		"idna", naming.IDNANormalizer != nil, // §3.2 U-labels accepted?
		"allow_reserved", cfg.AllowReserved, // §7.7 override active?
	)

	// -peers-file: validated and parsed AFTER config/flag validation but
	// BEFORE the DHT node starts; the entries bootstrap alongside -peers.
	// (Re-read on SIGHUP below.)
	var filePeers []dht.Peer
	if peersFileEffective != "" {
		data, err := os.ReadFile(peersFileEffective)
		if err != nil {
			return fmt.Errorf("peers-file: %w", err)
		}
		filePeers = parsePeersFile(string(data))
		logger.Info("loaded -peers-file", "file", peersFileEffective, "peers", len(filePeers))
	}

	// In-process envelope store: the freens record source. When the DHT
	// transport is enabled this same store backs both the local resolver lookups
	// and the get/put RPCs, and caches records fetched from peers (spec §6.4).
	store := dht.NewEnvelopeStore(0, nil)

	// Seed the store from the load dir: an explicit -load, else the persist
	// dir (the persistence round trip — snapshots reload on restart).
	if loadEffective != "" {
		count, err := seedFromDir(store, loadEffective, logger)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
		logger.Info("seeded envelopes from store dir", "dir", loadEffective, "count", count)
	}

	// Wire the freens record source. With the DHT transport off this is the
	// store-only adapter (an island). With it on, DHTLookup consults the local
	// store first and falls back to an iterative network GET on a miss.
	var dhtNode *dht.Node
	var dhtLookup *dht.DHTLookup
	var adminSrv *admin.Server
	var tlsSnapshot func() any // §9.5 /tls provider (nil = trust sync off)
	// upnpMapping is the live router port mapping (released at shutdown);
	// the renewal goroutine may replace it, and the metrics ticker reads it,
	// so access goes through upnpMu.
	var upnpMapping *upnp.Mapping
	var upnpMu sync.Mutex
	var freens resolver.RecordLookup = dht.NewStoreLookup(store)
	// -turn / -turn-relay both require the DHT transport; warn-and-ignore
	// mirrors -persist (a relay server without a node serves no one; a node
	// without the DHT transport has no peer UDP to tunnel).
	if dhtEffective == "" {
		if turnEffective != "" {
			logger.Warn("-turn requires -dht; ignoring", "turn", turnEffective)
		}
		if turnRelayEffective != "" {
			logger.Warn("-turn-relay requires -dht; ignoring", "turn-relay", turnRelayEffective)
		}
	}
	if dhtEffective != "" {
		nodeKP, err := loadNodeKey(nodeSeedEffective)
		if err != nil {
			return fmt.Errorf("node key: %w", err)
		}
		// -upnp (default ON "when convenient"): map the DHT port on the
		// LAN's router and advertise the external address — BEFORE the node
		// starts, feeding NodeConfig.Advertise the same way an explicit
		// -advertise would. Skipped when a better rung is already set; any
		// failure falls to the rest of the ladder (-stun, observed source)
		// with at most a Debug line.
		advertise := advertiseEffective
		if upnpEffective && advertise == "" && turnRelayEffective == "" {
			port := dhtPort(dhtEffective)
			mctx, mcancel := context.WithTimeout(context.Background(), 6*time.Second)
			m, merr := upnp.Map(mctx, port, "freens", logger)
			mcancel()
			if merr == nil {
				upnpMu.Lock()
				upnpMapping = m
				upnpMu.Unlock()
				advertise = m.Addr()
				logger.Info("upnp: router port mapping active",
					"advertise", m.Addr(),
					"internal_port", port,
					"external_port", m.ExternalPort())
			} else {
				logger.Debug("upnp: no mapping; continuing down the NAT ladder", "reason", merr)
			}
		}
		// -turn: co-located community relay server. Zero values for every
		// knob except ListenAddr/Log let internal/turn's defaults apply
		// (MaxAllocsPerIP, DefaultLifetime/MaxLifetime, MaxPermissions —
		// see the flag help).
		var turnSrvCfg *turn.ServerConfig
		if turnEffective != "" {
			turnSrvCfg = &turn.ServerConfig{ListenAddr: turnEffective, Log: logger}
		}
		node, err := dht.NewNode(dht.NodeConfig{
			Keypair:       nodeKP,
			ListenAddr:    dhtEffective,
			Store:         store,
			Logger:        logger,
			Passive:       passiveEffective,
			Advertise:     advertise,
			Stun:          stunEffective,
			TurnRelay:     turnRelayEffective,
			TurnServer:    turnSrvCfg,
			AllowReserved: cfg.AllowReserved,
		})
		if err != nil {
			return fmt.Errorf("dht node: %w", err)
		}
		if err := node.Start(); err != nil {
			return fmt.Errorf("dht start: %w", err)
		}
		dhtNode = node
		dhtLookup = dht.NewDHTLookup(store, node)
		// v0.8.0: restore the Appendix A.4 difficulty state and the §7.4
		// claim pool (live claims + §8.4 tombstones) from the load/persist
		// dir — without this, every restart reset the node's difficulty to
		// PoWDifficultyInit (a raised difficulty was dodgeable by reboot)
		// and dropped every in-window tombstone (the §8.4 reuse window
		// evaporated on restart).
		if loadEffective != "" {
			if err := node.LoadDifficultyState(filepath.Join(loadEffective, difficultyStateFile)); err != nil {
				logger.Warn("could not restore difficulty state", "error", err)
			}
			if pc, perr := node.LoadClaimPoolDir(filepath.Join(loadEffective, claimsPoolDir)); perr != nil {
				logger.Warn("could not restore claim pool", "error", perr)
			} else if pc > 0 {
				logger.Info("restored pooled claims (incl. §8.4 tombstones)", "count", pc)
			}
		}
		// Local control socket (internal/admin): the single-binary CLI's
		// admin-aware commands (publish/resolve/register/name/…) talk to
		// THIS daemon through it instead of spinning their own DHT nodes —
		// the "no -peers needed" path. Node-less daemons still serve
		// status-only.
		adminSrv = admin.New(node, dhtLookup, version, logger)
		adminSrv.SetAllowReserved(cfg.AllowReserved) // §7.7: keep the admin face in step with the resolver face
		go func() {
			if err := adminSrv.ListenAndServe(home.AdminSock()); err != nil {
				logger.Warn("admin socket failed", "sock", home.AdminSock(), "error", err)
			}
		}()
		freens = dhtLookup
		// Restore the network-cache metadata (which envelopes were FETCHED,
		// vs authoritative -load seeds) so a restart does not launder cached
		// copies into always-fresh local data (§6.4 cache freshness).
		if loadEffective != "" {
			if meta, err := os.ReadFile(filepath.Join(loadEffective, fetchMetaFile)); err == nil {
				if err := dhtLookup.LoadFetchMetaJSON(meta); err != nil {
					logger.Warn("could not restore cache metadata", "file", fetchMetaFile, "error", err)
				} else {
					logger.Info("restored network-cache metadata", "file", fetchMetaFile)
				}
			}
		}
		// DHTLookup also implements the resolver's optional ClaimResolver, so
		// network alias claims (spec §7) resolve automatically from here on —
		// no further wiring needed; the resolver type-asserts it.
		logger.Info("claim resolution via DHT enabled (network alias claims, spec §7)")
		logger.Info("DHT transport started",
			"listen", dhtEffective,
			"node_id", hex.EncodeToString(node.ID()),
			"node_pk", hex.EncodeToString(node.PublicKey()),
			"passive", *passive,
			// §6.2 advertised address: explicit -advertise, the UPnP mapping,
			// or empty (peers learn the observed source; Node.Start logs a
			// warning if a passed address could not be honored).
			"advertise", advertise,
			"turn_server", turnEffective,
			"turn_relay", turnRelayEffective,
		)
		// TURN startup verdicts, mirroring the -advertise/-stun style logs:
		// the relay outcome is known right after Start (the allocation dials
		// inside it — dht logged the relayed address on success); the TURN
		// server's concrete bound address (e.g. for :0) only exists now.
		if *turnRelayAddr != "" {
			if node.RelayedMode() {
				logger.Info("TURN relay mode active; advertising the relayed address", "relay", *turnRelayAddr)
			} else {
				logger.Warn("TURN relay mode inactive; using direct UDP + observed source", "relay", *turnRelayAddr)
			}
		}
		if ts := node.TURNServer(); ts != nil {
			if a, aerr := ts.Addr(); aerr == nil {
				logger.Info("TURN server listening (also answers STUN Binding; usable as a -stun target)",
					"addr", a.String())
			}
		}
		// Hostname-shaped -advertise (e.g. a DDNS-fronted seed): Start
		// resolved it once; the monitor re-resolves the ORIGINAL hostname
		// every 5 minutes and UpdateAdvertise's peers onto a fresh IP
		// after a PPPoE/dynDNS drift (internal/dht/advertise_resolve.go).
		// No-op for IP literals (the common case) and for UPnP-derived
		// addresses (those are literals too; the renewal loop owns them).
		if advertise != "" {
			node.StartAdvertiseResolve(advertise)
		}
		if peers := parsePeers(peersCSVEffective); len(peers) > 0 {
			logger.Info("bootstrapping DHT peers", "count", len(peers))
			node.Bootstrap(context.Background(), peers)
		}
		if len(filePeers) > 0 {
			logger.Info("bootstrapping -peers-file peers", "count", len(filePeers))
			node.Bootstrap(context.Background(), filePeers)
		}
		// Zero-config bootstrap (home state directory): when NO peers were
		// provided at all — neither -peers nor -peers-file, flag or [dht]
		// config — fall back to <home>/seeds.conf (written with the pinned
		// seed on first boot below, operator-editable) plus the learned
		// peerbook (<home>/peers/book.json, refreshed every 60s by the
		// loop under "Learned-peerbook persistence"). The book always
		// lives in home.Dir() ($FREENS_HOME, default ~/.freens) even when
		// -config points elsewhere: it is learned state, not config.
		if peersCSVEffective == "" && peersFileEffective == "" {
			if err := home.EnsureSeeds(); err != nil {
				logger.Debug("could not ensure seeds.conf in home dir", "error", err)
			}
			seeds := home.ParseSeeds(home.SeedsPath())
			book := home.LoadPeerbook()
			peers := peersFromSources(nil, nil, seeds, book)
			switch {
			case len(seeds) > 0 && len(book) > 0:
				logger.Info("bootstrapping from seeds.conf + peerbook (no -peers given)",
					"seeds", len(seeds), "peerbook", len(book), "peers", len(peers))
			case len(seeds) > 0:
				logger.Info("bootstrapping from seeds.conf (no -peers given)",
					"seeds", len(seeds), "peers", len(peers))
			case len(book) > 0:
				logger.Info("bootstrapping from peerbook (no -peers given)",
					"peerbook", len(book), "peers", len(peers))
			default:
				logger.Info("no peers configured — using seeds.conf/peerbook when available; " +
					"this node is an island until peered (-peers, seeds.conf, or UPnP-discovered contacts)")
			}
			if len(peers) > 0 {
				node.Bootstrap(context.Background(), peers)
				// Warm-up sweep: ping the learned contacts RIGHT NOW
				// instead of waiting for the first refresh tick. Without
				// this a restart has a minutes-long window where the
				// peerbook is loaded but nothing is confirmed — every
				// freens-name lookup degrades, doctor's resolution check
				// fails, and the dashboard shows a red resolver (found
				// live 2026-09-01 on the desktop box after its overnight
				// sleep + upgrade restart).
				go warmupPingSweep(node, book, logger)
			}
		}
	}

	// -persist: snapshot the store to disk every 60s (and once at shutdown
	// below) so records fetched over the DHT survive restarts. Pointing -load
	// at the same directory re-seeds them on the next start; the §6.4 winner
	// rule makes the round trip idempotent.
	var persistStop chan struct{}
	if persistEffective != "" {
		if dhtNode == nil {
			logger.Warn("-persist requires -dht; ignoring", "dir", persistEffective)
		} else {
			persistStop = make(chan struct{})
			go persistLoop(store, dhtLookup, dhtNode, persistEffective, persistStop, logger)
		}
	}

	// Learned-peerbook persistence (home): every 60s save the routing
	// table's contacts (cap 32) to <home>/peers/book.json so the NEXT boot
	// does not depend on seeds being reachable — the zero-config
	// bootstrap above re-reads it. Runs alongside the -persist loop with
	// the same stop-channel pattern (a final snapshot happens at
	// shutdown, after the DHT node stopped, so the book reflects every
	// contact learned during shutdown handshakes). Best-effort like the
	// book itself: errors are logged, never fatal.
	var bookStop chan struct{}
	if dhtNode != nil {
		bookStop = make(chan struct{})
		go peerbookLoop(dhtNode, bookStop, logger)
	}

	// Auto-renewal (the lease half of "ownership = liveness"): every 10
	// minutes, scan the store for envelopes signed by a KEYCHAIN key (the
	// user's own names — apexes, sub-names, claim copies) whose remaining
	// lifetime is inside the renewal threshold, and re-sign + republish
	// them at sequence+1 with a fresh window. This is what makes "keep
	// the daemon running and your names stay alive" literally true: the
	// §6.4 republish loop alone cannot extend an expiry baked into a
	// signature. Skipped in passive mode (§6.1: no put) and when no
	// keychain keys exist (a pure relay/witness node owns nothing).
	var renewStop chan struct{}
	if dhtNode != nil && !passiveEffective {
		renewStop = make(chan struct{})
		go renewLoop(dhtNode, store, logger, renewStop)
	}

	// Upstream wiring: plaintext UDP/TCP to the configured servers, or —
	// when [upstream] doh is set — RFC 8484 DoH with the plaintext servers
	// as fallback (the doh key was parsed-but-ignored before v0.7.1). The
	// value goes into an UpstreamRef so POST admin /reload can hot-swap it
	// (v0.14.0 §9.6: `freens doh upstream …` / the webui Settings page apply
	// without a daemon restart).
	plain := &resolver.DNSUpstream{Servers: cfg.UpstreamServers}
	var upstream resolver.Upstream = plain
	if cfg.UpstreamDoH != "" {
		upstream = &resolver.DoHUpstream{URL: cfg.UpstreamDoH, Fallback: plain}
	}
	upRef := resolver.NewUpstreamRef(upstream)
	res := resolver.New(cfg, freens, upRef)

	// §9.5.4 trust sync: cross-certify DHT-verified owner CAs into the local
	// trust stores (spool for the privileged bridge + direct system store
	// when writable + NSS user DBs when certutil exists). [tls] trust-sync =
	// false disables the hook entirely.
	tlsCfg, err := loadTLSConfig(*configPath)
	if err != nil {
		logger.Warn("tls config ignored", "error", err)
		tlsCfg = &tlsConfig{}
	}
	if !tlsCfg.TrustSyncOff {
		if tsEngine, terr := trustsync.New(trustsync.Options{
			HomeDir:     home.Dir(),
			Logger:      logger,
			NSSInstall:  true,
			SystemStore: systemStoreWritable(),
		}); terr != nil {
			logger.Warn("tls trust sync disabled", "error", terr)
		} else {
			res.TLSSync = tsEngine
			tlsSnapshot = func() any {
				return map[string]any{
					"root_fingerprint": tsEngine.RootFingerprint(),
					"cross_certs":      tsEngine.Snapshot(),
				}
			}
			if adminSrv != nil {
				adminSrv.SetTLSProvider(tlsSnapshot)
			}
			logger.Info("tls trust sync enabled (§9.5)", "root_fingerprint", tsEngine.RootFingerprint())
		}
	}

	// §9.6 DoH wiring (v0.14.0): the admin socket gains the wire-DNS relay
	// the webui's DoH face forwards to, plus the config hot-reload the
	// `freens doh` verb and the Settings page use to apply an upstream
	// change without a restart. Late-wired like the TLS provider above:
	// adminSrv (and its goroutine) exist only under -dht, and the resolver
	// was built after them. Both endpoints 503 until this block runs.
	if adminSrv != nil {
		adminSrv.SetDNSHandler(func(ctx context.Context, query []byte) ([]byte, error) {
			q := new(dns.Msg)
			if err := q.Unpack(query); err != nil {
				return nil, fmt.Errorf("bad DNS query: %w", err)
			}
			resp := res.ResolveMsg(ctx, q)
			return resp.Pack()
		})
		adminSrv.SetReloader(func() (string, error) {
			cfg2, err := loadConfig(*configPath)
			if err != nil {
				return "", fmt.Errorf("config re-read failed: %w", err)
			}
			// Flags keep their priority on a reload: the -upstream override
			// won the initial wiring, so it wins here too. And the empty-list
			// default MUST apply again — the reload that skips it silently
			// downgrades the fallback to "no servers" on confs (like this
			// fleet's own) that never spell one out (found live in the
			// v0.14.0 fleet test: "applied live: … fallback )" was the tell).
			if *upstreamCSV != "" {
				cfg2.UpstreamServers = splitCSV(*upstreamCSV)
			}
			applyUpstreamDefault(cfg2)
			plain2 := &resolver.DNSUpstream{Servers: cfg2.UpstreamServers}
			var up2 resolver.Upstream = plain2
			if cfg2.UpstreamDoH != "" {
				up2 = &resolver.DoHUpstream{URL: cfg2.UpstreamDoH, Fallback: plain2}
			}
			upRef.Set(up2)
			if cfg2.UpstreamDoH != "" {
				logger.Info("config reloaded: upstream is now DoH", "url", cfg2.UpstreamDoH,
					"fallback", strings.Join(cfg2.UpstreamServers, ","))
				return "upstream: DoH " + cfg2.UpstreamDoH + " (fallback " +
					strings.Join(cfg2.UpstreamServers, ",") + ")", nil
			}
			logger.Info("config reloaded: upstream is now plain DNS",
				"servers", strings.Join(cfg2.UpstreamServers, ","))
			return "upstream: plain " + strings.Join(cfg2.UpstreamServers, ","), nil
		})
	}

	// Operational metrics (hardening part 1): the registry always exists —
	// counters/gauges are near-free when -metrics is off; only the HTTP
	// endpoint below is optional. Gauges are refreshed by a 15s goroutine;
	// freens_dns_queries_total is incremented in the DNS server path and the
	// cache hit/miss counters in ResponseCache.get.
	reg := metrics.New()
	processStart := time.Now()
	uptimeGauge := reg.NewGauge("freens_uptime_seconds", "Seconds since the daemon process started.")
	dhtPeersGauge := reg.NewGauge("freens_dht_peers", "Entries in this node's Kademlia routing table.")
	storeEnvGauge := reg.NewGauge("freens_dht_store_envelopes", "Live envelopes in the local DHT envelope store.")
	histEnvGauge := reg.NewGauge("freens_dht_history_envelopes", "Superseded envelopes retained as §8.3 audit history.")
	gossipDiffGauge := reg.NewGauge("freens_dht_gossip_difficulty", "Network PoW difficulty in bits: median of peers' advertised witness difficulties (Appendix A.4).")
	cacheEntriesGauge := reg.NewGauge("freens_resolver_cache_entries", "Entries currently held in the §10.4 response cache.")
	turnAllocGauge := reg.NewGauge("freens_turn_allocations",
		"Active TURN allocations on this node's co-located TURN server (-turn; absent when the server is off).")
	upnpGauge := reg.NewGauge("freens_upnp_mapping",
		"1 when this daemon holds a live UPnP IGD port mapping for its DHT port (0/absent otherwise).")
	turnRelayGauge := reg.NewGauge("freens_turn_relay",
		"1 when this node routes its peer UDP through a TURN allocation (-turn-relay), 0 otherwise.")
	dnsQueriesCounter := reg.NewCounter("freens_dns_queries_total",
		"DNS queries answered, by question type and response status (noerror/nxdomain/servfail).", "qtype", "status")

	// The §10.4 response cache: enabled here (it only short-circuits the DNS
	// server path; direct ResolveQuestion callers are unaffected) so the
	// cache metrics are live from the first query. State persists across
	// restarts (dns-cache.json): the entries are §10.4 VALIDATION RESULTS,
	// so restoring one carries the same trust as keeping it in memory — and
	// a daemon restart (every upgrade!) stops being a cold-cache walk for
	// the first client query afterwards.
	res.Logger = logger
	cache := resolver.NewResponseCache(0, nil)
	cache.SetMetrics(reg)
	res.Cache = cache
	if persistEffective != "" {
		dnsCachePath := filepath.Join(persistEffective, "dns-cache.json")
		if err := cache.LoadFrom(dnsCachePath); err != nil {
			if !os.IsNotExist(err) {
				logger.Warn("dns cache restore skipped", "error", err)
			}
		} else if cache.Len() > 0 {
			logger.Info("dns cache restored", "entries", cache.Len())
		}
		go persistDNSCacheLoop(cache, dnsCachePath, logger)
	}

	udpSrv := resolver.NewServer(cfg.ListenUDP, "udp", res)
	tcpSrv := resolver.NewServer(cfg.ListenTCP, "tcp", res)
	// One shared counter for both transports: the label set is {qtype,status}
	// (no transport dimension), so a duplicate registration per server would
	// panic — hence the setter takes the counter, not the registry.
	udpSrv.SetQueryCounter(dnsQueriesCounter)
	tcpSrv.SetQueryCounter(dnsQueriesCounter)

	// Start both servers concurrently; both get a chance to bind even if one
	// fails (spec §9.1: "still attempt"). A bind failure surfaces immediately.
	errCh := make(chan error, 2) // buffered so goroutines never block on send
	go func() { errCh <- udpSrv.ListenAndServe() }()
	go func() { errCh <- tcpSrv.ListenAndServe() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Gauge refresh loop: populate immediately, then every 15s. Gauges read
	// only exported APIs (RoutingTable().Size, EnvelopeStore.Count/
	// HistoryCount, DHTLookup.NetworkDifficulty — nil-receiver-safe, so the
	// island case reports PoWDifficultyInit, and ResponseCache.Len).
	updateGauges := func() {
		uptimeGauge.With().Set(time.Since(processStart).Seconds())
		if dhtNode != nil {
			dhtPeersGauge.With().Set(float64(dhtNode.RoutingTable().Size()))
			if ts := dhtNode.TURNServer(); ts != nil {
				turnAllocGauge.With().Set(float64(ts.Allocations()))
			}
			turnRelayGauge.With().Set(boolGauge(dhtNode.RelayedMode()))
			upnpMu.Lock()
			upnpGauge.With().Set(boolGauge(upnpMapping != nil))
			upnpMu.Unlock()
		}
		storeEnvGauge.With().Set(float64(store.Count()))
		histEnvGauge.With().Set(float64(store.HistoryCount()))
		gossipDiffGauge.With().Set(float64(dhtLookup.NetworkDifficulty()))
		cacheEntriesGauge.With().Set(float64(cache.Len()))
	}
	updateGauges()

	// bgStop ends the background goroutines (gauge refresh, SIGHUP reload)
	// during shutdown so no reload ever races the teardown below.
	bgStop := make(chan struct{})
	// Proactive refresh sweeper: names hit in the last 24 h keep being
	// revalidated in the background even with zero client queries — from
	// the client POV a name in recurring use is answered from cache
	// forever (restarts covered by the persisted cache, idle gaps by the
	// §10.4 stale window, and this closes the gap beyond both).
	go res.RunRefreshSweeper(bgStop)
	// UPnP renewal: routers forget mappings across reboots/resets, and
	// external addresses change (dynamic PPPoE). Probe every 5 minutes,
	// re-map when the entry vanished, follow address changes — the node's
	// advertised address updates at runtime (Node.UpdateAdvertise), no
	// restart. A confirmed-lost mapping that cannot be re-established keeps
	// the old advertised address (better stale than flapping); the next
	// tick retries.
	go func() {
		t := time.NewTicker(upnpRenewInterval)
		defer t.Stop()
		for {
			select {
			case <-bgStop:
				return
			case <-t.C:
			}
			upnpMu.Lock()
			m := upnpMapping
			upnpMu.Unlock()
			if m == nil || dhtNode == nil {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			nm, changed, err := m.EnsureFresh(ctx)
			cancel()
			if err != nil {
				logger.Debug("upnp: renewal probe failed; keeping mapping", "error", err)
				continue
			}
			if nm == nil {
				logger.Warn("upnp: router lost the mapping and re-mapping failed; will retry")
				continue
			}
			upnpMu.Lock()
			upnpMapping = nm
			upnpMu.Unlock()
			if changed {
				if uerr := dhtNode.UpdateAdvertise(nm.Addr()); uerr != nil {
					logger.Warn("upnp: renewed mapping address rejected; keeping previous", "addr", nm.Addr(), "error", uerr)
				} else {
					logger.Info("upnp: mapping renewed; advertising updated address", "addr", nm.Addr(), "external_port", nm.ExternalPort())
				}
			}
		}
	}()
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				updateGauges()
			case <-bgStop:
				return
			}
		}
	}()

	// SIGHUP: re-read -peers-file and AddPeer each entry (idempotent). With
	// no -peers-file configured the handler just logs that fact.
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	go func() {
		defer signal.Stop(hupCh)
		for {
			select {
			case <-bgStop:
				return
			case <-hupCh:
				reloadPeersFile(dhtNode, peersFileEffective, logger)
			}
		}
	}()

	// -metrics HTTP endpoint: /metrics (Prometheus text format 0.0.4) and
	// /healthz, started after the DHT node, stopped with everything else. A
	// listen failure is logged but does NOT take the resolver down.
	var metricsSrv *http.Server
	if *metricsAddr != "" {
		metricsSrv = &http.Server{
			Addr:              *metricsAddr,
			Handler:           newMetricsHandler(reg),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("metrics endpoint failed", "addr", *metricsAddr, "error", err)
			}
		}()
		logger.Info("metrics endpoint listening", "addr", *metricsAddr)
	}

	var firstErr error
	select {
	case firstErr = <-errCh:
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", "signal", sig)
	case <-serviceStop: // SCM stop/shutdown (Windows service only)
		logger.Info("received service stop request, shutting down")
	}

	if firstErr != nil {
		logger.Error("a DNS server failed to start", "error", firstErr)
		if isPort53(cfg.ListenUDP) || isPort53(cfg.ListenTCP) {
			logger.Error("hint: binding port 53 may require privileges; use a high port " +
				"(-listen 127.0.0.1:5300) with an iptables/systemd redirect, or grant " +
				"CAP_NET_BIND_SERVICE (setcap) / run as root (spec §9.1)")
		}
	}

	// Idempotent shutdown of both servers (one may already be stopped). Log
	// non-nil shutdown errors but do NOT override firstErr: a server-shutdown
	// failure is informational and must not mask an earlier bind/serve failure.
	if err := udpSrv.Shutdown(); err != nil {
		logger.Error("udp server shutdown error", "error", err)
	}
	if err := tcpSrv.Shutdown(); err != nil {
		logger.Error("tcp server shutdown error", "error", err)
	}
	// Stop the background goroutines (gauge refresh, SIGHUP reload) and the
	// metrics endpoint alongside the servers.
	close(bgStop)
	if metricsSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := metricsSrv.Shutdown(ctx); err != nil {
			logger.Error("metrics server shutdown error", "error", err)
		}
		cancel()
	}
	if adminSrv != nil {
		if err := adminSrv.Close(); err != nil {
			logger.Error("admin socket shutdown error", "error", err)
		}
	}
	if dhtNode != nil {
		if err := dhtNode.Close(); err != nil {
			logger.Error("dht node shutdown error", "error", err)
		}
	}
	// Release the UPnP port mapping after the DHT transport has stopped
	// (best-effort; a router that forgot it is not an error worth failing
	// the shutdown over).
	upnpMu.Lock()
	mapping := upnpMapping
	upnpMu.Unlock()
	if mapping != nil {
		if err := mapping.Release(); err != nil {
			logger.Warn("upnp: port mapping release failed", "error", err)
		} else {
			logger.Info("upnp: port mapping released")
		}
	}
	// Final peerbook snapshot AFTER the DHT node stopped (mirrors the
	// final -persist below): the book reflects every contact learned
	// during shutdown handshakes, then the loop is retired.
	if bookStop != nil {
		close(bookStop)
	}
	if renewStop != nil {
		close(renewStop)
	}
	// Final persistence AFTER the servers (and the DHT node) have stopped, so
	// the snapshot reflects every record the resolver cached during shutdown.
	if persistStop != nil {
		close(persistStop)
		if count, err := store.PersistTo(persistEffective); err != nil {
			logger.Error("final persist failed", "dir", persistEffective, "error", err)
		} else {
			logger.Info("persisted envelopes at shutdown", "dir", persistEffective, "count", count)
		}
		persistFetchMeta(dhtLookup, persistEffective, logger)
		if hc, herr := store.PersistHistoryTo(filepath.Join(persistEffective, "history")); herr != nil {
			logger.Error("final persist history failed", "error", herr)
		} else if hc > 0 {
			logger.Info("persisted audit history at shutdown", "count", hc)
		}
		if ec, eerr := store.PersistEvidenceTo(filepath.Join(persistEffective, "evidence")); eerr != nil {
			logger.Error("final persist evidence failed", "error", eerr)
		} else if ec > 0 {
			logger.Info("persisted recovery evidence at shutdown", "count", ec)
		}
		persistAuxState(dhtNode, persistEffective, logger)
	}
	return firstErr
}

// fetchMetaFile is the sidecar (next to the *.cbor envelopes) recording which
// persisted envelopes are network caches and when they were fetched.
const fetchMetaFile = "fetched.json"

// difficultyStateFile is the persisted Appendix A.4 difficulty state (own D,
// retarget-block counter/start, observed ring) — v0.8.0: a restart must not
// reset a raised difficulty.
const difficultyStateFile = "difficulty.json"

// claimsPoolDir holds the persisted §7.4 claim pool (live claims + §8.4
// tombstones), one <H_record hex>.cbor per envelope.
const claimsPoolDir = "claims-pool"

// effectiveLoadDir resolves the startup seed directory: an explicit -load
// always wins; otherwise, when persistence is configured, the persist dir
// (the snapshots reload on restart — the round trip that was missing until
// v0.3.1, found live when a fleet-wide restart emptied every store).
func effectiveLoadDir(loadFlag, persistEffective string) string {
	if loadFlag != "" {
		return loadFlag
	}
	return persistEffective
}

// resolveLoadForBoot is effectiveLoadDir plus the fresh-install tolerance:
// a DEFAULTED load dir that does not exist yet (first boot — the first
// persist tick creates it) is dropped so startup proceeds; an explicit
// -load is returned verbatim (a missing explicit dir is a loud error).
func resolveLoadForBoot(loadFlag, persistEffective string) string {
	dir := effectiveLoadDir(loadFlag, persistEffective)
	if loadFlag == "" && dir != "" {
		if _, err := os.Stat(dir); err != nil {
			return "" // nothing to reload yet: fine
		}
	}
	return dir
}

// persistFetchMeta best-effort-writes the DHTLookup fetch metadata into dir.
func persistFetchMeta(l *dht.DHTLookup, dir string, logger *slog.Logger) {
	if l == nil {
		return
	}
	meta, err := l.FetchMetaJSON()
	if err != nil {
		logger.Error("encode cache metadata failed", "error", err)
		return
	}
	if err := os.WriteFile(filepath.Join(dir, fetchMetaFile), meta, 0o644); err != nil {
		logger.Error("write cache metadata failed", "error", err)
	}
}

// persistAuxState persists the non-envelope daemon state that must survive a
// restart alongside the store snapshots: the Appendix A.4 difficulty state
// (v0.8.0) and the §7.4 claim pool (live claims + §8.4 tombstones). Both are
// best-effort — logged, never fatal — like every persist here.
func persistAuxState(node *dht.Node, dir string, logger *slog.Logger) {
	if node == nil {
		return
	}
	if err := node.SaveDifficultyState(filepath.Join(dir, difficultyStateFile)); err != nil {
		logger.Error("persist difficulty state failed", "error", err)
	}
	if pc, perr := node.PersistClaimPoolDir(filepath.Join(dir, claimsPoolDir)); perr != nil {
		logger.Error("persist claim pool failed", "error", perr)
	} else if pc > 0 {
		logger.Info("persisted pooled claims (incl. §8.4 tombstones)", "count", pc)
	}
}

// persistLoop snapshots the envelope store into dir every 60s until stop is
// closed. Errors are logged, never fatal: the next tick (or the final
// shutdown-time PersistTo) retries.
func persistLoop(store *dht.EnvelopeStore, lookup *dht.DHTLookup, node *dht.Node, dir string, stop <-chan struct{}, logger *slog.Logger) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			count, err := store.PersistTo(dir)
			if err != nil {
				logger.Error("persist failed", "dir", dir, "error", err)
				continue
			}
			logger.Info("persisted envelopes", "dir", dir, "count", count)
			persistFetchMeta(lookup, dir, logger)
			if hc, herr := store.PersistHistoryTo(filepath.Join(dir, "history")); herr != nil {
				logger.Error("persist history failed", "error", herr)
			} else if hc > 0 {
				logger.Info("persisted audit history", "dir", filepath.Join(dir, "history"), "count", hc)
			}
			if ec, eerr := store.PersistEvidenceTo(filepath.Join(dir, "evidence")); eerr != nil {
				logger.Error("persist evidence failed", "error", eerr)
			} else if ec > 0 {
				logger.Info("persisted recovery evidence", "dir", filepath.Join(dir, "evidence"), "count", ec)
			}
			persistAuxState(node, dir, logger)
		case <-stop:
			return
		}
	}
}

// peersFromSources selects and merges the bootstrap-peer sources in
// precedence order, deduplicating by (addr, public key): the explicit
// sources (-peers CSV, then -peers-file) when EITHER provided an entry,
// otherwise the zero-config home sources (seeds.conf, then the learned
// peerbook). Later duplicates of an earlier (addr, pk) pair are dropped.
// Pure — unit-tested without a daemon (the run() caller passes nil explicit
// sources precisely when neither flag nor [dht] config provided peers).
func peersFromSources(flagPeers, filePeers, seeds, book []dht.Peer) []dht.Peer {
	var out []dht.Peer
	seen := make(map[string]bool)
	add := func(ps []dht.Peer) {
		for _, p := range ps {
			key := p.Addr + "#" + hex.EncodeToString(p.PublicKey)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, p)
		}
	}
	if len(flagPeers) > 0 || len(filePeers) > 0 {
		add(flagPeers)
		add(filePeers)
		return out
	}
	add(seeds)
	add(book)
	return out
}

// peerbookLoop snapshots the node's routing-table contacts to
// <home>/peers/book.json every 60s until stop is closed (same pattern as
// persistLoop). Errors are logged, never fatal: the book is an
// optimization, not state.
func peerbookLoop(node *dht.Node, stop <-chan struct{}, logger *slog.Logger) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			savePeerbook(node, logger)
		case <-stop:
			return
		}
	}
}

// savePeerbook persists the node's current routing-table contacts (the
// best dialable peers this node knows — AllContacts order, capped at 32 by
// home.SavePeerbook) as one best-effort atomic write. Only DIRECTLY
// CONFIRMED contacts are persisted (issue #2: advertisement-learned
// ephemeral-port ghosts must not survive a restart). No-op without a node
// or without contacts (an empty book would erase nothing but also teach
// nothing; keeping the last non-empty book is strictly better).
func savePeerbook(node *dht.Node, logger *slog.Logger) {
	if node == nil {
		return
	}
	peers := confirmedPeers(node.RoutingTable().AllContacts(), time.Now().Unix())
	if len(peers) == 0 {
		return
	}
	if err := home.SavePeerbook(peers, time.Now().Unix()); err != nil {
		logger.Debug("peerbook save failed", "error", err)
		return
	}
	logger.Info("peerbook saved", "peers", len(peers))
}

// confirmedPeers filters contacts to those with at least one DIRECT
// exchange (ConfirmedAt > 0 — the routing table's anti-ghost invariant) and
// converts them to the persistence form, CARRYING the confirmation age so
// a restart resumes probation instead of resetting it (issue #2).
func confirmedPeers(contacts []*dht.NodeContact, now int64) []dht.Peer {
	var out []dht.Peer
	for _, c := range contacts {
		if c.ConfirmedAt <= 0 {
			continue // never directly confirmed: do not persist
		}
		out = append(out, dht.Peer{Addr: c.Addr, PublicKey: c.PublicKey, Confirmed: c.ConfirmedAt})
	}
	return out
}

// renewLoop keeps the user's own names alive: every 10 minutes it scans the
// store for envelopes SIGNED BY A KEYCHAIN KEY whose remaining lifetime is
// inside renewal.ShouldRenew, re-signs them (sequence+1, fresh 24 h window)
// and republishes at every legitimate key (dht.StorageKeys: K_tld/K_name
// plus K_claim for claim-carrying records). Owner-private keys live in
// ~/.freens/keys (0600, same user as the daemon) — the loop reads them to
// sign, exactly like the CLI would, and never exposes them further.
//
// Two conservatisms: a record that is REVOKED is never renewed (deliberate
// death), and a renewal that fails to publish anywhere is retried on the
// next tick. The retry is not left to ShouldRenew alone: a renewal renews
// BOTH carriers of a name (K_tld + K_claim), and when only one key's put
// fails while the other succeeds, the fresh local copy resets ShouldRenew —
// the failed leg would silently wait a full lease before anyone re-signed
// it (v0.14.0 fleet incident: "accepted by 0 of 7 peers" at one tick, then
// 24 h of NXDOMAIN while peers served the expired predecessor). Unconfirmed
// puts therefore land in renewPending and are re-published — no re-sign,
// the envelope is already good — until the network's own GET confirms them.
type renewPendingPut struct {
	env      *wire.SignedEnvelope
	keys     [][]byte
	attempts int
}

// renewPendingMaxAttempts bounds the retry loop: 12 ticks ≈ 2 h of retries
// per envelope. A network that cannot accept a put in 2 h needs the operator
// (doctor), not an infinite background hammer.
const renewPendingMaxAttempts = 12

var renewPending = struct {
	sync.Mutex
	m map[string]*renewPendingPut // hex(key) -> pending put
}{m: map[string]*renewPendingPut{}}

func renewLoop(node *dht.Node, store *dht.EnvelopeStore, logger *slog.Logger, stop <-chan struct{}) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			retryPendingPuts(node, logger)
			renewOnce(node, store, logger)
		case <-stop:
			return
		}
	}
}

// retryPendingPuts re-publishes unconfirmed renewals and drops the entries
// the network now reflects (the §6.4 GET returns the exact envelope).
func retryPendingPuts(node *dht.Node, logger *slog.Logger) {
	renewPending.Lock()
	defer renewPending.Unlock()
	if len(renewPending.m) == 0 {
		return
	}
	for kHex, p := range renewPending.m {
		p.attempts++
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := node.PublishKeyedAt(ctx, p.keys, p.env)
		var confirmed bool
		if err == nil {
			// Confirm from the NETWORK's view, not the local store: the
			// incident was precisely "local thinks it's done, network
			// disagrees". IterativeGet walks the real holders.
			gctx, gcancel := context.WithTimeout(context.Background(), 30*time.Second)
			env, gerr := node.IterativeGet(gctx, p.keys[0])
			gcancel()
			if gerr == nil && env != nil && p.env.Record != nil && env.Record != nil {
				nh, e1 := env.RecordHash()
				ph, e2 := p.env.RecordHash()
				confirmed = e1 == nil && e2 == nil && bytes.Equal(nh, ph)
			}
		}
		cancel()
		switch {
		case confirmed:
			delete(renewPending.m, kHex)
			logger.Info("auto-renew: pending publish confirmed by the network", "sequence", p.env.Record.Sequence)
		case p.attempts >= renewPendingMaxAttempts:
			delete(renewPending.m, kHex)
			logger.Warn("auto-renew: publish unconfirmed after repeated retries — run `freens renew -force <name>` (or check connectivity)",
				"sequence", p.env.Record.Sequence, "attempts", p.attempts)
		default:
			logger.Warn("auto-renew: publish not yet confirmed network-wide; will retry",
				"sequence", p.env.Record.Sequence, "attempt", p.attempts, "err", err)
		}
	}
}

// warmupPingSweep pings the learned peerbook contacts right after boot so
// the routing table carries CONFIRMED contacts within seconds, not after
// the first bucket-refresh tick. Per-peer timeout is short on purpose:
// a peer that cannot answer a ping in 2 s is not useful for the first
// lookup anyway; the normal refresh/repair machinery takes over from
// there. Best-effort — failures are just logged at debug level.
func warmupPingSweep(node *dht.Node, book []dht.Peer, logger *slog.Logger) {
	var wg sync.WaitGroup
	for _, p := range book {
		wg.Add(1)
		go func(p dht.Peer) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := node.Ping(ctx, p); err != nil {
				logger.Debug("warmup ping failed", "peer", p.Addr, "error", err)
			}
		}(p)
	}
	wg.Wait()
	logger.Info("warmup ping sweep complete", "contacts", len(book))
}

// renewOnce is one auto-renewal pass (split out so a future -renew-now flag
// or admin RPC can trigger it on demand).
func renewOnce(node *dht.Node, store *dht.EnvelopeStore, logger *slog.Logger) {
	// The keychain map: owner public key -> keypair (skip .recN recovery
	// keyfiles — they recover, they do not renew).
	entries, err := os.ReadDir(home.KeysDir())
	if err != nil {
		return // no keychain: a relay node, nothing to renew
	}
	owners := make(map[string]*crypto.Keypair)
	encrypted := 0
	envPass, envOK := os.LookupEnv("FREENS_PASSPHRASE")
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".key") || strings.Contains(name, ".rec") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(home.KeysDir(), name))
		if err != nil {
			continue
		}
		var seed []byte
		if securekey.IsEncrypted(b) {
			if !envOK {
				encrypted++
				continue // cannot prompt from a service; renew manually
			}
			seed, err = securekey.DecryptSeed(b, envPass)
			if err != nil {
				logger.Warn("auto-renew: wrong passphrase for keyfile (check FREENS_PASSPHRASE)", "file", name)
				continue
			}
		} else {
			seed, err = hex.DecodeString(strings.TrimSpace(string(b)))
			if err != nil {
				logger.Debug("auto-renew: keyfile is not hex", "file", name)
				continue
			}
		}
		kp, err := crypto.FromSeed(seed)
		if err != nil {
			logger.Debug("auto-renew: unparseable keyfile", "file", name)
			continue
		}
		owners[hex.EncodeToString(kp.Public())] = kp
	}
	if encrypted > 0 {
		logger.Info("auto-renew: skipping passphrase-protected key(s) (the daemon cannot prompt)",
			"count", encrypted,
			"hint", "renew manually or set FREENS_PASSPHRASE for the service")
	}
	if len(owners) == 0 {
		return
	}

	now := store.Now()
	renewed := 0
	for _, ent := range store.Entries(now) {
		env := ent.Env
		if env == nil || env.Record == nil || env.IsRevoked() {
			continue
		}
		signerHex := hex.EncodeToString(env.Signer)
		kp, mine := owners[signerHex]
		if !mine {
			continue // not ours: cached/relayed records are their owners' business
		}
		if !renewal.ShouldRenew(now, int64(env.Record.Created), int64(env.Record.Expires)) {
			renewVerifyFresh(node, logger, env)
			continue
		}
		fresh, err := renewal.RenewEnvelope(env, kp, now)
		if err != nil {
			logger.Warn("auto-renew: re-sign failed", "error", err)
			continue
		}
		keys, err := dht.StorageKeys(fresh)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		stats, err := node.PublishKeyedAtStats(ctx, keys, fresh)
		cancel()
		logPublishStats(logger, "auto-renew", stats, err)
		if err != nil {
			logger.Warn("auto-renew: publish failed (queued for network-confirmed retry)", "error", err)
			renewPending.Lock()
			for _, k := range keys {
				renewPending.m[hex.EncodeToString(k)] = &renewPendingPut{env: fresh, keys: keys}
			}
			renewPending.Unlock()
			continue
		}
		// The publish reporting success does not mean every holder has it —
		// the K_tld put can land while the K_claim put silently reaches
		// nobody until the next lease (the incident above). Queue the keys
		// for NETWORK-CONFIRMED retry; confirmation drops them within a
		// tick or two when propagation is healthy.
		renewPending.Lock()
		for _, k := range keys {
			renewPending.m[hex.EncodeToString(k)] = &renewPendingPut{env: fresh, keys: keys}
		}
		renewPending.Unlock()
		// The renewal must BELIEVE what it told the network: install the
		// fresh envelope in the local store too. Without this the next
		// tick re-reads the stale sequence here, re-signs the SAME
		// sequence+1 (new timestamps — a different envelope the peers
		// rightly refuse), and the name's sequence stalls at N+1 until
		// the local copy ages out — "accepted by 0 of 7 peers" every
		// ten minutes while the network record slowly starves toward
		// expiry (found live 2026-08-31 on the seed box; a TLSCA-less
		// pre-upgrade record renewed this way never gains the binding).
		for _, k := range keys {
			_, _ = store.Put(k, fresh, now, false) // signed above
		}
		renewed++
		logger.Info("auto-renewed record", "sequence", fresh.Record.Sequence,
			"expires", fresh.Record.Expires)
	}
	if renewed > 0 {
		logger.Info("auto-renew pass complete", "renewed", renewed)
	}
}

// renewVerifyInterval: how often the pass re-verifies that the NETWORK
// still holds each apparently-fresh lease (a var so tests can shrink it).
// The 2026-09-02 camalolo incident: the local bookkeeping said "fresh
// until 12:17" while the network had lost the envelope entirely — every
// non-owner resolver NXDOMAINed the name for hours and nothing on the
// owner noticed, because ShouldRenew only looks at the LOCAL store. One
// network GET per own name per interval is the cheap antidote.
var renewVerifyInterval = 60 * time.Minute

// renewVerifyLast rate-limits the per-name verification: name (hex wire
// name) -> unix second of the last attempt.
var renewVerifyLast sync.Map

// renewVerifyFresh re-checks an own record that ShouldRenew considers
// fresh: the network's walk (local store EXCLUDED — an owner counting its
// own copy would "confirm" itself forever) must offer the same envelope,
// or the lease is re-published on the spot and queued for the
// network-confirmed retry loop. Degraded walks are skipped (inconclusive,
// not evidence) — the next window re-checks.
func renewVerifyFresh(node *dht.Node, logger *slog.Logger, env *wire.SignedEnvelope) {
	if env == nil || env.Record == nil {
		return
	}
	nameKey := hex.EncodeToString(env.Record.Name)
	nowS := time.Now().Unix()
	if v, ok := renewVerifyLast.Load(nameKey); ok &&
		nowS-v.(int64) < int64(renewVerifyInterval/time.Second) {
		return
	}
	renewVerifyLast.Store(nameKey, nowS)

	keys, err := dht.StorageKeys(env)
	if err != nil || len(keys) == 0 {
		return
	}
	gctx, gcancel := context.WithTimeout(context.Background(), 30*time.Second)
	netEnv, err := node.IterativeGet(gctx, keys[0])
	gcancel()
	if errors.Is(err, dht.ErrDegradedMiss) || errors.Is(err, dht.ErrWalkBusy) {
		logger.Debug("auto-renew: lease verification inconclusive (degraded walk)",
			"sequence", env.Record.Sequence)
		return
	}
	healthy := err == nil && netEnv != nil && netEnv.Record != nil
	if healthy {
		nh, e1 := netEnv.RecordHash()
		lh, e2 := env.RecordHash()
		healthy = e1 == nil && e2 == nil && bytes.Equal(nh, lh)
	}
	if healthy {
		logger.Debug("auto-renew: fresh lease verified on the network",
			"sequence", env.Record.Sequence)
		return
	}
	// The network is missing the lease or holds an older/different
	// generation: re-publish the EXISTING local envelope (no re-sign — it
	// is still valid and sequence-correct) and let the confirmed-retry
	// loop finish the job.
	netSeq := int64(-1)
	if netEnv != nil && netEnv.Record != nil {
		netSeq = int64(netEnv.Record.Sequence)
	}
	logger.Warn("auto-renew: network lost a supposedly-fresh lease; re-publishing",
		"sequence", env.Record.Sequence, "network_sequence", netSeq, "get_err", err)
	pctx, pcancel := context.WithTimeout(context.Background(), 30*time.Second)
	stats, perr := node.PublishKeyedAtStats(pctx, keys, env)
	pcancel()
	logPublishStats(logger, "auto-renew verify", stats, perr)
	renewPending.Lock()
	for _, k := range keys {
		renewPending.m[hex.EncodeToString(k)] = &renewPendingPut{env: env, keys: keys}
	}
	renewPending.Unlock()
}

// logPublishStats turns dht.PublishStats into one log line per key — the
// per-target acceptance the bare error/nil used to swallow ("RENEWED" while
// the puts went nowhere, found live 2026-09-02).
func logPublishStats(logger *slog.Logger, what string, stats []dht.PublishStats, err error) {
	for _, s := range stats {
		if s.Targets == 0 {
			continue // ErrNoPeers case; the error already says so
		}
		if s.Accepted == 0 {
			logger.Warn(what+": key accepted by 0 peers", "key", s.KeyHex, "targets", s.Targets)
		} else if s.Accepted < s.Targets {
			logger.Info(what+": key partially accepted", "key", s.KeyHex,
				"accepted", s.Accepted, "targets", s.Targets)
		} else {
			logger.Debug(what+": key accepted", "key", s.KeyHex, "targets", s.Targets)
		}
	}
	_ = err // the caller reports it in its own terms
}

// loadNodeKey returns the DHT node identity: from seedHex (a 32-byte hex Ed25519
// seed) when provided, or freshly generated otherwise. A stable identity across
// restarts (a pinned -node-seed) keeps a node's Node ID / routing-table entry
// stable for its peers.
func loadNodeKey(seedSpec string) (*crypto.Keypair, error) {
	if seedSpec == "" {
		return crypto.Generate()
	}
	// "@/path/to/keyfile": keep raw node seeds off unit files and command
	// lines (same convention as freens-cli's @keyfile specs).
	if strings.HasPrefix(seedSpec, "@") {
		b, err := os.ReadFile(strings.TrimPrefix(seedSpec, "@"))
		if err != nil {
			return nil, fmt.Errorf("read node keyfile: %w", err)
		}
		seedSpec = strings.TrimSpace(string(b))
	}
	seed, err := hex.DecodeString(seedSpec)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	if len(seed) != constants.Ed25519PrivateKeyLen {
		return nil, fmt.Errorf("seed must be %d bytes, got %d", constants.Ed25519PrivateKeyLen, len(seed))
	}
	return crypto.FromSeed(seed)
}

// parsePeers parses a comma-separated list of "addr#<64-hex-pubkey>" bootstrap
// peers into dht.Peer values. Malformed entries are skipped (with no error) so a
// single bad entry does not prevent startup.
func parsePeers(csv string) []dht.Peer {
	var peers []dht.Peer
	for _, p := range splitCSV(csv) {
		if peer, ok := parsePeerEntry(p); ok {
			peers = append(peers, peer)
		}
	}
	return peers
}

// parsePeerEntry parses a single "addr#<64-hex-pubkey>" peer entry. ok is
// false for malformed entries (no "#", empty halves, bad hex, wrong length).
func parsePeerEntry(s string) (dht.Peer, bool) {
	idx := strings.Index(s, "#")
	if idx <= 0 || idx == len(s)-1 {
		return dht.Peer{}, false
	}
	addr := s[:idx]
	pk, err := hex.DecodeString(s[idx+1:])
	if err != nil || len(pk) != constants.Ed25519PublicKeyLen {
		return dht.Peer{}, false
	}
	return dht.Peer{Addr: addr, PublicKey: pk}, true
}

// parsePeersFile parses the newline-separated contents of a -peers-file: one
// "addr#<64-hex-pubkey>" peer per line. Blank lines and lines whose first
// non-blank character is "#" (comments) are skipped; other malformed lines are
// skipped silently, matching parsePeers' tolerance.
func parsePeersFile(content string) []dht.Peer {
	var peers []dht.Peer
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if peer, ok := parsePeerEntry(line); ok {
			peers = append(peers, peer)
		}
	}
	return peers
}

// reloadPeersFile implements the SIGHUP behavior: with no -peers-file
// configured it just says so; otherwise it re-reads and re-parses the file and
// AddPeer's every entry into the running DHT node (AddPeer is idempotent).
// Failures are logged, never fatal.
func reloadPeersFile(node *dht.Node, path string, logger *slog.Logger) {
	if path == "" {
		logger.Info("SIGHUP: no -peers-file configured")
		return
	}
	if node == nil {
		logger.Warn("SIGHUP: -peers-file reload ignored: no DHT node running (-dht empty)")
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		logger.Error("SIGHUP: read -peers-file failed", "file", path, "error", err)
		return
	}
	peers := parsePeersFile(string(data))
	added, failed := 0, 0
	for _, p := range peers {
		if err := node.AddPeer(p.PublicKey, p.Addr); err != nil {
			failed++
			logger.Warn("SIGHUP: AddPeer failed", "addr", p.Addr, "error", err)
			continue
		}
		added++
	}
	logger.Info("SIGHUP: reloaded -peers-file",
		"file", path, "entries", len(peers), "added", added, "failed", failed)
}

// newMetricsHandler builds the -metrics HTTP endpoint: /metrics (Prometheus
// text-exposition 0.0.4) and /healthz (liveness). Factored out for tests.
func newMetricsHandler(reg *metrics.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if _, err := reg.WriteTo(w); err != nil {
			slog.Error("metrics: write exposition failed", "error", err)
		}
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// storeLookup used to be defined locally here; it now lives once in
// internal/dht as dht.StoreLookup (NewStoreLookup wraps an *EnvelopeStore and
// structurally satisfies resolver.RecordLookup). The canonical TLD-root →
// K_tld / else → K_name routing rule lives in dht.KeyForWireName; the daemon's
// -load seeding below uses the same rule when keying envelopes.

// flags bundles the command-line flag pointers returned by defineFlags. It
// exists so tests can exercise the flag definitions (names, defaults, help)
// without spinning up the daemon; run() unpacks them into the same local
// variables it always used.
type flags struct {
	configPath, listenAddr, dnsAddr, upstreamCSV, loadDir        *string
	dhtAddr, nodeSeedHex, peersCSV, peersFile, metricsAddr       *string
	advertiseAddr, stunAddr, turnAddr, turnRelayAddr, persistDir *string
	passive, idna, upnpEnabled, allowReserved                    *bool
}

// defineFlags registers every freens flag on fs and returns their value
// pointers (flag.Parse must be called by the caller).
func defineFlags(fs *flag.FlagSet) *flags {
	f := &flags{}
	f.configPath = fs.String("config", "", "path to resolver config file (optional; built-in default if absent)")
	f.listenAddr = fs.String("listen", "", "override UDP listen address (default from config)")
	f.dnsAddr = fs.String("dns", "", "override BOTH the UDP and TCP DNS listen addresses, e.g. 127.0.0.1:5300 "+
		"(default from config; empty leaves the config addresses untouched)")
	f.upstreamCSV = fs.String("upstream", "", "override upstream DNS servers (comma/space separated)")
	f.loadDir = fs.String("load", "", "directory of *.cbor envelope files to seed the in-process store on startup")
	f.dhtAddr = fs.String("dht", "", "UDP address for the DHT transport (e.g. :15353); empty disables the DHT node")
	f.nodeSeedHex = fs.String("node-seed", "", "hex Ed25519 seed (32 bytes) for this node's DHT identity; generated if empty")
	f.peersCSV = fs.String("peers", "", "comma-separated bootstrap peers as addr#<64-hex-pubkey>")
	f.peersFile = fs.String("peers-file", "", "newline-separated peers file (one addr#<64-hex-pubkey> per line; blank lines\n"+
		"and lines starting with # are skipped), loaded at startup and re-loaded on SIGHUP\n"+
		"(re-parse + AddPeer each entry, idempotent)")
	f.metricsAddr = fs.String("metrics", "", "listen address for the operational HTTP endpoint exposing /metrics\n"+
		"(Prometheus text format) and /healthz, e.g. :9153; empty disables the endpoint")
	f.upnpEnabled = fs.Bool("upnp", true, "ask the LAN's router (UPnP IGD) to forward the DHT UDP port and "+
		"advertise the external address (spec 6.2) — the zero-config NAT rung; best-effort "+
		"and silently skipped when -advertise/-turn-relay is set, no gateway answers (SSDP), "+
		"the router refuses, or the edge is CGNAT-fronted (0.0.0.0 external address). "+
		"The mapping is labeled, UDP-only, released at shutdown, and re-asserted every 5 minutes (router reboots self-heal; external-address changes are followed at runtime) (requires -dht)")
	f.passive = fs.Bool("passive", false, "passive DHT mode (spec §6.1): answer ping/find_node/get but refuse put and skip republishing (requires -dht)")
	f.advertiseAddr = fs.String("advertise", "", "address peers should dial to reach this node's DHT transport, host:port "+
		"(spec §6.2 \"nodes advertise (ip, port, node_pubkey)\") — for NAT/port-forward setups where the observed UDP "+
		"source is a private address peers cannot dial back; validated at startup, empty = peers learn the observed source "+
		"(requires -dht)")
	f.stunAddr = fs.String("stun", "", "STUN server host:port (RFC 5389 Binding) used to discover this node's "+
		"server-reflexive public address and advertise it to peers exactly like -advertise (spec §6.2); refreshed "+
		"every 60s so address changes are picked up. Ignored when -advertise is set (an explicit address always "+
		"wins over a discovered one) and in -turn-relay mode (the relayed address is advertised instead; STUN "+
		"remains the fallback when the allocation fails). For symmetric NAT — no usable reflexive mapping — "+
		"prefer -turn-relay (requires -dht)")
	f.turnAddr = fs.String("turn", "", "run a freens TURN server (RFC 8656 subset) alongside the DHT node so\n"+
		"symmetric-NAT peers can relay through this daemon's spare bandwidth (community\n"+
		"relay tier): host:port to bind, e.g. :3478 (requires -dht). Auth is freens-\n"+
		"native node-key signatures; the socket also answers STUN Binding requests,\n"+
		"so it doubles as a -stun target. Server knobs — MaxAllocsPerIP (allocations\n"+
		"per source IP), DefaultLifetime / MaxLifetime of allocations, and\n"+
		"MaxPermissions per allocation — are left at zero here so internal/turn's\n"+
		"defaults apply")
	f.turnRelayAddr = fs.String("turn-relay", "", "route ALL of this node's peer UDP through a TURN allocation on the\n"+
		"given freens TURN server (host:port) and advertise the RELAYED address to\n"+
		"peers (spec §6.2) — the dialable address for nodes behind symmetric NAT\n"+
		"(requires -dht). Precedence: -advertise > -turn-relay > -stun (an explicit\n"+
		"address always wins; STUN is skipped in relay mode and remains the fallback).\n"+
		"If the allocation fails the node logs a warning and falls back to direct\n"+
		"UDP + observed source")
	f.persistDir = fs.String("persist", "", "directory to persist the envelope store to (<keyhex>.cbor files) every 60s and at shutdown (requires -dht)")
	f.idna = fs.Bool("idna", false, "accept IDNA2008 U-label aliases (spec §3.2): normalize non-ASCII (raw\n"+
		"UTF-8) alias/TLD components of query names to punycode A-labels via UTS #46\n"+
		"(transitional=false, useSTD3Rules=true). NOTE: this only affects queries that\n"+
		"carry a raw U-label as bytes — real stub resolvers and browsers already send\n"+
		"punycode (xn--…) ASCII, which strict LDH accepts either way; subdomain labels\n"+
		"(the part before the alias) stay strict ASCII LDH regardless. Equivalent to\n"+
		"[options] \"idna = true\" in the config file; an explicit -idna=false overrides it.")
	f.allowReserved = fs.Bool("allow-reserved", false, "override the §7.7 reserved-alias policy: this daemon may WITNESS (co-sign\n"+
		"claims for) and RESOLVE freens aliases that equal delegated ICANN TLDs or IANA\n"+
		"special-use names (com, net, localhost, …). Default OFF: register refuses to mint\n"+
		"such claims, the node refuses to witness them, and the resolver + admin faces\n"+
		"treat them as claim-less (NXDOMAIN) even if rogue-witnessed claims exist — so a\n"+
		"first-time user can never be routed to a spoofed site under a real-TLD-shaped\n"+
		"freens name. Deliberately local: other nodes keep the default. Equivalent to\n"+
		"[options] \"allow-reserved = true\"; an explicit -allow-reserved=false overrides it.")
	return f
}

// loadConfig parses the config file at path, or the built-in default if path is
// empty.
// applyUpstreamDefault fills an empty upstream server list with the §9.1
// defaults (9.9.9.9, 1.1.1.1). BOTH the initial wiring and the /reload
// re-read go through this — a reload that skips it would downgrade the
// DoH fallback to an empty list on confs that never spell one out.
func applyUpstreamDefault(cfg *resolver.Config) {
	if len(cfg.UpstreamServers) == 0 {
		cfg.UpstreamServers = resolver.DefaultUpstreamServers
	}
}

func loadConfig(path string) (*resolver.Config, error) {
	if path == "" {
		return resolver.ParseConfig(builtinDefaultConfig)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return resolver.ParseConfig(string(data))
}

// seedFromDir reads every *.cbor envelope file in dir, decodes it, and Puts it
// at the appropriate DHT key (K_tld for TLD-root records, K_name otherwise).
// Verification is enabled (verifySignature=true); a malformed file is logged
// and skipped rather than aborting startup.
func seedFromDir(store *dht.EnvelopeStore, dir string, logger *slog.Logger) (int, error) {
	// §8.4 evidence seeding FIRST: <dir>/evidence/*.cbor are recovery
	// declarations persisted by PersistEvidenceTo, one file per
	// H_record-named blob. The FILENAME is the hex record hash (the
	// evidence-table key); each is decode-validated and retained via
	// PutEvidenceRaw BEFORE any envelope is (re-)Put, so a recovery record
	// R2 re-seeded from <persist> can displace its incumbent R1 through the
	// store's §8.4 gate (the gate falls back to this table when the Put
	// carries no in-band evidence bytes — the restart path).
	evDir := filepath.Join(dir, "evidence")
	if eentries, err := os.ReadDir(evDir); err == nil {
		for _, e := range eentries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".cbor") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(evDir, e.Name()))
			if err != nil {
				return 0, err
			}
			h, err := hex.DecodeString(strings.TrimSuffix(e.Name(), ".cbor"))
			if err != nil || len(h) != constants.SHA256Len {
				logger.Warn("skipping misnamed recovery evidence file", "file", e.Name())
				continue
			}
			if err := store.PutEvidenceRaw(h, data); err != nil {
				logger.Warn("skipping malformed recovery evidence", "file", e.Name(), "error", err)
				continue
			}
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	now := store.Now()
	count := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cbor") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return count, err
		}
		env, err := wire.DecodeEnvelope(data)
		if err != nil {
			logger.Warn("skipping malformed envelope file", "file", path, "error", err)
			continue
		}
		// Canonical keys (dht.StorageKeys): K_tld/K_name from the record name,
		// PLUS K_claim for claim-bearing TLD records — the claim envelope is
		// published at both keys (§7.4/C.1), and PersistTo writes one file per
		// key, so seeding by name alone would drop K_claim on reload.
		keys, err := dht.StorageKeys(env)
		if err != nil {
			logger.Warn("skipping envelope with undecodable name", "file", path, "error", err)
			continue
		}
		put := false
		for _, key := range keys {
			accepted, err := store.Put(key, env, now, true)
			if err != nil {
				return count, fmt.Errorf("put %s: %w", path, err)
			}
			put = put || accepted
		}
		if !put {
			// Every key already held this exact (or a strictly newer) envelope —
			// the normal idempotent case when -load points at the -persist dir.
			logger.Debug("envelope already seeded or superseded", "file", path)
			continue
		}
		count++
	}
	// §8.3 audit-history seeding: <dir>/history/*.cbor are superseded
	// predecessors persisted by PersistHistoryTo. They must land in HISTORY,
	// not the live map — Put would reject them as stale losers of the winner
	// rule (their successor is the live winner), so they are force-retained;
	// this is what makes transferred-TLD verification survive restarts.
	histDir := filepath.Join(dir, "history")
	if hentries, err := os.ReadDir(histDir); err == nil {
		for _, e := range hentries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".cbor") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(histDir, e.Name()))
			if err != nil {
				return count, err
			}
			env, err := wire.DecodeEnvelope(data)
			if err != nil {
				logger.Warn("skipping malformed history envelope", "file", e.Name(), "error", err)
				continue
			}
			store.RetainHistory(env)
		}
	}
	return count, nil
}

// boolGauge renders a bool as a gauge value (1/0).
func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// upnpRenewInterval is how often the daemon re-asserts its UPnP port
// mapping (probe GetSpecificPortMappingEntry; re-map on loss; follow
// external-address changes). Five minutes bounds router-reboot downtime
// without meaningful SOAP chatter.
const upnpRenewInterval = 5 * time.Minute

// dhtPort extracts the UDP port of a -dht listen address (":15353",
// "0.0.0.0:15353"); the protocol default when absent.
func dhtPort(addr string) int {
	if _, p, err := net.SplitHostPort(addr); err == nil && p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	return 15353 // FREENS_PORT (spec Appendix A)
}

// splitCSV splits a comma/space/tab-separated list, dropping empties.
func splitCSV(s string) []string {
	out := []string{}
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	}) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// isPort53 reports whether addr is a port-53 listen address (so we can emit
// spec §9.1 privileged-port guidance on bind failure).
func isPort53(addr string) bool {
	return strings.HasSuffix(addr, ":53") || addr == ":53"
}

// persistDNSCacheLoop saves the response cache every 60 s (dirty caches
// only) until the process exits — the same cadence and never-fatal shape as
// the envelope/peerbook persist loops. Restored at boot by LoadFrom, this
// is what makes daemon restarts (upgrades, the 05:00 pppd dance, crash
// recovery) invisible to DNS clients: the first query after a restart is
// answered from the restored validation results while the background
// refresh revalidates.
func persistDNSCacheLoop(cache *resolver.ResponseCache, path string, logger *slog.Logger) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for range t.C {
		saved, err := cache.SaveIfDirty(path)
		if err != nil {
			logger.Error("dns cache persist failed", "error", err)
		} else if saved {
			logger.Info("persisted dns cache", "path", path)
		}
	}
}
