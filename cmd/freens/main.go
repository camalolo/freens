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

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/dht"
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
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "path to resolver config file (optional; built-in default if absent)")
	listenAddr := fs.String("listen", "", "override UDP listen address (default from config)")
	upstreamCSV := fs.String("upstream", "", "override upstream DNS servers (comma/space separated)")
	loadDir := fs.String("load", "", "directory of *.cbor envelope files to seed the in-process store on startup")
	dhtAddr := fs.String("dht", "", "UDP address for the DHT transport (e.g. :15353); empty disables the DHT node")
	nodeSeedHex := fs.String("node-seed", "", "hex Ed25519 seed (32 bytes) for this node's DHT identity; generated if empty")
	peersCSV := fs.String("peers", "", "comma-separated bootstrap peers as addr#<64-hex-pubkey>")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
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
		})
		if err != nil {
			return fmt.Errorf("dht node: %w", err)
		}
		if err := node.Start(); err != nil {
			return fmt.Errorf("dht start: %w", err)
		}
		dhtNode = node
		freens = dht.NewDHTLookup(store, node)
		logger.Info("DHT transport started",
			"listen", *dhtAddr,
			"node_id", hex.EncodeToString(node.ID()),
			"node_pk", hex.EncodeToString(node.PublicKey()),
		)
		if peers := parsePeers(*peersCSV); len(peers) > 0 {
			logger.Info("bootstrapping DHT peers", "count", len(peers))
			node.Bootstrap(context.Background(), peers)
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
	return firstErr
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
		// Canonical key (K_tld for TLD-root records, K_name otherwise) is the
		// single rule shared with the store lookup and the get/put handlers.
		key, err := dht.KeyForWireName(env.Record.Name)
		if err != nil {
			logger.Warn("skipping envelope with undecodable name", "file", path, "error", err)
			continue
		}
		accepted, err := store.Put(key, env, now, true)
		if err != nil {
			return count, fmt.Errorf("put %s: %w", path, err)
		}
		if !accepted {
			logger.Warn("envelope not accepted (signature invalid or lost the winner rule)",
				"file", path)
			continue
		}
		count++
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
