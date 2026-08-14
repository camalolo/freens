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
//	freens [-config <path>] [-listen <addr>] [-upstream <csv>] [-load <dir>]
//	       [-dht <addr>] [-node-seed <hex>] [-peers <addr#pk>,...]
//	       [-passive] [-advertise <addr>] [-persist <dir>] [-idna]
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
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/dht"
	"github.com/laurent/freens/internal/naming"
	"github.com/laurent/freens/internal/resolver"
	"github.com/laurent/freens/internal/wire"
)

// builtinDefaultConfig is used when -config is absent: a safe "* = dns-first"
// resolver listening on 127.0.0.1:53 with public upstreams (spec §9.1).
const builtinDefaultConfig = `[listen]
udp = 127.0.0.1:53
tcp = 127.0.0.1:53
[upstream]
servers = 9.9.9.9, 1.1.1.1
[tld-routes]
* = dns-first
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "freens: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("freens", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: freens [-config <path>] [-listen <addr>] [-upstream <csv>] [-load <dir>]")
		fmt.Fprintln(fs.Output(), "             [-dht <addr>] [-node-seed <hex>] [-peers <addr#pk>,...]")
		fmt.Fprintln(fs.Output(), "             [-passive] [-advertise <addr>] [-persist <dir>] [-idna]")
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "path to resolver config file (optional; built-in default if absent)")
	listenAddr := fs.String("listen", "", "override UDP listen address (default from config)")
	upstreamCSV := fs.String("upstream", "", "override upstream DNS servers (comma/space separated)")
	loadDir := fs.String("load", "", "directory of *.cbor envelope files to seed the in-process store on startup")
	dhtAddr := fs.String("dht", "", "UDP address for the DHT transport (e.g. :15353); empty disables the DHT node")
	nodeSeedHex := fs.String("node-seed", "", "hex Ed25519 seed (32 bytes) for this node's DHT identity; generated if empty")
	peersCSV := fs.String("peers", "", "comma-separated bootstrap peers as addr#<64-hex-pubkey>")
	passive := fs.Bool("passive", false, "passive DHT mode (spec §6.1): answer ping/find_node/get but refuse put and skip republishing (requires -dht)")
	advertiseAddr := fs.String("advertise", "", "address peers should dial to reach this node's DHT transport, host:port "+
		"(spec §6.2 \"nodes advertise (ip, port, node_pubkey)\") — for NAT/port-forward setups where the observed UDP "+
		"source is a private address peers cannot dial back; validated at startup, empty = peers learn the observed source "+
		"(requires -dht)")
	persistDir := fs.String("persist", "", "directory to persist the envelope store to (<keyhex>.cbor files) every 60s and at shutdown (requires -dht)")
	idnaFlag := fs.Bool("idna", false, "accept IDNA2008 U-label aliases (spec §3.2): normalize non-ASCII (raw\n"+
		"UTF-8) alias/TLD components of query names to punycode A-labels via UTS #46\n"+
		"(transitional=false, useSTD3Rules=true). NOTE: this only affects queries that\n"+
		"carry a raw U-label as bytes — real stub resolvers and browsers already send\n"+
		"punycode (xn--…) ASCII, which strict LDH accepts either way; subdomain labels\n"+
		"(the part before the alias) stay strict ASCII LDH regardless. Equivalent to\n"+
		"[options] \"idna = true\" in the config file; an explicit -idna=false overrides it.")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// -idna override semantics (mirroring -listen/-upstream): an explicitly
	// passed flag wins; otherwise the config file's [options] idna decides;
	// otherwise IDNA stays off.
	idnaFlagSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "idna" {
			idnaFlagSet = true
		}
	})

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
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
	if !idnaFlagSet && cfg.EnableIDNA {
		naming.EnableIDNA()
	}

	// Apply CLI overrides.
	if *listenAddr != "" {
		cfg.ListenUDP = *listenAddr
	}
	if *upstreamCSV != "" {
		cfg.UpstreamServers = splitCSV(*upstreamCSV)
	}
	if len(cfg.UpstreamServers) == 0 {
		cfg.UpstreamServers = []string{"9.9.9.9", "1.1.1.1"}
	}

	logger.Info("freens daemon starting",
		"listen_udp", cfg.ListenUDP,
		"listen_tcp", cfg.ListenTCP,
		"upstream", cfg.UpstreamServers,
		"load_dir", *loadDir,
		"idna", naming.IDNANormalizer != nil, // §3.2 U-labels accepted?
	)

	// In-process envelope store: the freens record source. When the DHT
	// transport is enabled this same store backs both the local resolver lookups
	// and the get/put RPCs, and caches records fetched from peers (spec §6.4).
	store := dht.NewEnvelopeStore(0, nil)

	// Seed the store from -load dir, if provided.
	if *loadDir != "" {
		count, err := seedFromDir(store, *loadDir, logger)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
		logger.Info("seeded envelopes from -load dir", "dir", *loadDir, "count", count)
	}

	// Wire the freens record source. With the DHT transport off this is the
	// store-only adapter (an island). With it on, DHTLookup consults the local
	// store first and falls back to an iterative network GET on a miss.
	var dhtNode *dht.Node
	var dhtLookup *dht.DHTLookup
	var freens resolver.RecordLookup = dht.NewStoreLookup(store)
	if *dhtAddr != "" {
		nodeKP, err := loadNodeKey(*nodeSeedHex)
		if err != nil {
			return fmt.Errorf("node key: %w", err)
		}
		node, err := dht.NewNode(dht.NodeConfig{
			Keypair:    nodeKP,
			ListenAddr: *dhtAddr,
			Store:      store,
			Logger:     logger,
			Passive:    *passive,
			Advertise:  *advertiseAddr,
		})
		if err != nil {
			return fmt.Errorf("dht node: %w", err)
		}
		if err := node.Start(); err != nil {
			return fmt.Errorf("dht start: %w", err)
		}
		dhtNode = node
		dhtLookup = dht.NewDHTLookup(store, node)
		freens = dhtLookup
		// Restore the network-cache metadata (which envelopes were FETCHED,
		// vs authoritative -load seeds) so a restart does not launder cached
		// copies into always-fresh local data (§6.4 cache freshness).
		if *loadDir != "" {
			if meta, err := os.ReadFile(filepath.Join(*loadDir, fetchMetaFile)); err == nil {
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
			"listen", *dhtAddr,
			"node_id", hex.EncodeToString(node.ID()),
			"node_pk", hex.EncodeToString(node.PublicKey()),
			"passive", *passive,
			// §6.2 advertised address: empty means peers learn the observed
			// source (Node.Start logs a warning if a passed -advertise was
			// invalid and could not be honored).
			"advertise", *advertiseAddr,
		)
		if peers := parsePeers(*peersCSV); len(peers) > 0 {
			logger.Info("bootstrapping DHT peers", "count", len(peers))
			node.Bootstrap(context.Background(), peers)
		}
	}

	// -persist: snapshot the store to disk every 60s (and once at shutdown
	// below) so records fetched over the DHT survive restarts. Pointing -load
	// at the same directory re-seeds them on the next start; the §6.4 winner
	// rule makes the round trip idempotent.
	var persistStop chan struct{}
	if *persistDir != "" {
		if dhtNode == nil {
			logger.Warn("-persist requires -dht; ignoring", "dir", *persistDir)
		} else {
			persistStop = make(chan struct{})
			go persistLoop(store, dhtLookup, *persistDir, persistStop, logger)
		}
	}

	upstream := &resolver.DNSUpstream{Servers: cfg.UpstreamServers}
	res := resolver.New(cfg, freens, upstream)

	udpSrv := resolver.NewServer(cfg.ListenUDP, "udp", res)
	tcpSrv := resolver.NewServer(cfg.ListenTCP, "tcp", res)

	// Start both servers concurrently; both get a chance to bind even if one
	// fails (spec §9.1: "still attempt"). A bind failure surfaces immediately.
	errCh := make(chan error, 2) // buffered so goroutines never block on send
	go func() { errCh <- udpSrv.ListenAndServe() }()
	go func() { errCh <- tcpSrv.ListenAndServe() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var firstErr error
	select {
	case firstErr = <-errCh:
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", "signal", sig)
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
	if dhtNode != nil {
		if err := dhtNode.Close(); err != nil {
			logger.Error("dht node shutdown error", "error", err)
		}
	}
	// Final persistence AFTER the servers (and the DHT node) have stopped, so
	// the snapshot reflects every record the resolver cached during shutdown.
	if persistStop != nil {
		close(persistStop)
		if count, err := store.PersistTo(*persistDir); err != nil {
			logger.Error("final persist failed", "dir", *persistDir, "error", err)
		} else {
			logger.Info("persisted envelopes at shutdown", "dir", *persistDir, "count", count)
		}
		persistFetchMeta(dhtLookup, *persistDir, logger)
		if hc, herr := store.PersistHistoryTo(filepath.Join(*persistDir, "history")); herr != nil {
			logger.Error("final persist history failed", "error", herr)
		} else if hc > 0 {
			logger.Info("persisted audit history at shutdown", "count", hc)
		}
	}
	return firstErr
}

// fetchMetaFile is the sidecar (next to the *.cbor envelopes) recording which
// persisted envelopes are network caches and when they were fetched.
const fetchMetaFile = "fetched.json"

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

// persistLoop snapshots the envelope store into dir every 60s until stop is
// closed. Errors are logged, never fatal: the next tick (or the final
// shutdown-time PersistTo) retries.
func persistLoop(store *dht.EnvelopeStore, lookup *dht.DHTLookup, dir string, stop <-chan struct{}, logger *slog.Logger) {
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
		case <-stop:
			return
		}
	}
}

// loadNodeKey returns the DHT node identity: from seedHex (a 32-byte hex Ed25519
// seed) when provided, or freshly generated otherwise. A stable identity across
// restarts (a pinned -node-seed) keeps a node's Node ID / routing-table entry
// stable for its peers.
func loadNodeKey(seedHex string) (*crypto.Keypair, error) {
	if seedHex == "" {
		return crypto.Generate()
	}
	seed, err := hex.DecodeString(seedHex)
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
		idx := strings.Index(p, "#")
		if idx <= 0 || idx == len(p)-1 {
			continue
		}
		addr := p[:idx]
		pkHex := p[idx+1:]
		pk, err := hex.DecodeString(pkHex)
		if err != nil || len(pk) != constants.Ed25519PublicKeyLen {
			continue
		}
		peers = append(peers, dht.Peer{Addr: addr, PublicKey: pk})
	}
	return peers
}

// storeLookup used to be defined locally here; it now lives once in
// internal/dht as dht.StoreLookup (NewStoreLookup wraps an *EnvelopeStore and
// structurally satisfies resolver.RecordLookup). The canonical TLD-root →
// K_tld / else → K_name routing rule lives in dht.KeyForWireName; the daemon's
// -load seeding below uses the same rule when keying envelopes.

// loadConfig parses the config file at path, or the built-in default if path is
// empty.
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
