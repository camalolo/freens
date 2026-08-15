// dht.go — the live-network subcommands, now admin-aware:
//
//	publish   §6.4 PUT — push signed-envelope .cbor files to the R peers
//	          closest to each record's key. With -evidence (spec 8.4) the
//	          single -file is instead carried by the evidence-aware PUT
//	          (Node.PublishWithEvidence). Via the daemon (admin socket) when
//	          no -peers is given.
//	resolve   §6.4 GET — iterative lookup of a name's terminal record and a
//	          human-readable display of it (chain verification is NOT
//	          attempted here; the daemon does it when serving DNS).
//	get       raw §6.4 GET by 32-byte key — the debugging escape hatch.
//
// They share the -peers/startCLINode plumbing (a one-shot DHT node with a
// synchronous bootstrap ping round), printEnvelope (the record
// pretty-printer), and pickTransport (admin.go's daemon-vs-standalone rule).
package cli

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/dht"
	"github.com/laurent/freens/internal/naming"
	"github.com/laurent/freens/internal/wire"
)

// cliTimeout bounds every live-network subcommand (publish / resolve / get):
// a one-shot CLI run must terminate even against a black-holed network.
const cliTimeout = 30 * time.Second

// ---------------------------------------------------------------------------
// shared plumbing: -peers parsing + the one-shot CLI node
// ---------------------------------------------------------------------------

// parsePeerList parses a comma-separated -peers list of "ip:port#<64-hex-pk>"
// bootstrap peers — the same format as the daemon's -peers (recipient_id is
// part of every DHT message signature, §6.3, so a peer's public key is
// mandatory). Unlike the long-running daemon, which silently skips malformed
// entries, a one-shot CLI run has nothing to gain from ignoring typos, so a
// malformed entry is a usage error.
func parsePeerList(csv string) ([]dht.Peer, error) {
	if strings.TrimSpace(csv) == "" {
		return nil, usageErr("no -peers given (format: ip:port#<64-hex-node-pk>, comma-separated)")
	}
	var peers []dht.Peer
	for _, p := range strings.Split(csv, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		idx := strings.Index(p, "#")
		if idx <= 0 || idx == len(p)-1 {
			return nil, usageErr("bad peer %q (want ip:port#<64-hex-pk>)", p)
		}
		addr := p[:idx]
		if _, err := net.ResolveUDPAddr("udp", addr); err != nil {
			return nil, usageErr("bad peer address %q: %v", addr, err)
		}
		pk, err := hex.DecodeString(p[idx+1:])
		if err != nil || len(pk) != constants.Ed25519PublicKeyLen {
			return nil, usageErr("bad peer public key %q (want %d hex chars)", p[idx+1:], 2*constants.Ed25519PublicKeyLen)
		}
		peers = append(peers, dht.Peer{Addr: addr, PublicKey: pk})
	}
	return peers, nil
}

// startCLINode builds and starts the one-shot DHT node shared by publish /
// resolve / get: an ephemeral UDP socket (-listen, default ":0"), an identity
// from -node-seed (hex; random when empty, §6.2), and an in-memory envelope
// store that caches whatever the lookup path fetches (§6.4 "nodes along the
// lookup path MAY cache"). Bootstrap reachability is verified synchronously —
// one ping per peer within RPC_TIMEOUT — so an unreachable network fails fast
// with a clear error instead of degrading into a misleading "not found".
//
// The caller must Close the returned node. Node diagnostics are discarded:
// CLI stdout is data, one line per item.
func startCLINode(ctx context.Context, nodeSeedHex, listenAddr string, peers []dht.Peer) (*dht.Node, error) {
	kp, err := nodeKeypair(nodeSeedHex)
	if err != nil {
		return nil, usageErr("invalid -node-seed: %v", err)
	}
	if listenAddr == "" {
		listenAddr = ":0"
	}
	node, err := dht.NewNode(dht.NodeConfig{
		Keypair:    kp,
		ListenAddr: listenAddr,
		Store:      dht.NewEnvelopeStore(0, nil),
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		// A one-shot CLI node neither refreshes buckets (§6.2) nor
		// republishes (§6.4 step 4 — the daemon's job); both background
		// loops are disabled.
		BucketRefreshInterval: -1,
		RepublishInterval:     -1,
	})
	if err != nil {
		return nil, err
	}
	if err := node.Start(); err != nil {
		return nil, err
	}
	fail := func(e error) (*dht.Node, error) {
		_ = node.Close()
		return nil, e
	}
	reachable := 0
	for _, p := range peers {
		if err := node.AddPeer(p.PublicKey, p.Addr); err != nil {
			return fail(err)
		}
		c, cancel := context.WithTimeout(ctx, time.Duration(constants.RPCTimeoutSec)*time.Second)
		err = node.Ping(c, p)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: warning: peer %s unreachable (%v)\n", ProgName, p.Addr, err)
			continue
		}
		reachable++
	}
	if reachable == 0 {
		return fail(fmt.Errorf("no peers reachable (checked %d)", len(peers)))
	}
	return node, nil
}

// nodeKeypair returns the CLI node's identity: from seedHex (a 32-byte hex
// Ed25519 seed) when provided, or freshly generated otherwise. Mirrors the
// daemon's loadNodeKey.
func nodeKeypair(seedSpec string) (*crypto.Keypair, error) {
	if seedSpec == "" {
		return crypto.Generate()
	}
	// hex or @keyfile (seedKeypair does the parsing).
	return seedKeypair(seedSpec, "-node-seed")
}

// ---------------------------------------------------------------------------
// shared plumbing: envelope pretty-printing
// ---------------------------------------------------------------------------

// nameSummary renders a wire_name for one-line reports (publish's per-file
// line, get/resolve headers): display-order labels plus the pinned tld_id in
// lowercase base32. The alias itself is not carried in the wire name (§3.3
// stores only tld_id), so the TLD position is shown as the base32 id.
func nameSummary(wireName []byte) string {
	labels, tldID, err := naming.DecodeWireName(wireName)
	if err != nil {
		return "<undecodable wire_name>"
	}
	b32 := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(tldID), "="))
	if len(labels) == 0 {
		return "<tld-root> tld_id_b32=" + b32
	}
	return strings.Join(labels, ".") + ".<tld> tld_id_b32=" + b32
}

// printEnvelope pretty-prints a fetched *wire.SignedEnvelope: H_record (§4.2),
// name, owner/signer, sequence, validity window (human UTC plus
// seconds-remaining relative to now), revoke flag, delegation/claim presence,
// and the RRset with type number, TTL, rdata hex, and a readable rendering
// for A/AAAA/TXT (§4.3). Shared by resolve and get.
func printEnvelope(env *wire.SignedEnvelope, now int64) {
	r := env.Record
	if rh, err := env.RecordHash(); err == nil {
		fmt.Printf("record_hash=%s\n", hex.EncodeToString(rh))
	}
	fmt.Printf("name_summary=%s\n", nameSummary(r.Name))
	if labels, tldID, err := naming.DecodeWireName(r.Name); err == nil {
		fmt.Printf("labels=[%s]\n", strings.Join(labels, " "))
		fmt.Printf("tld_id_b32=%s\n", strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(tldID), "=")))
	}
	fmt.Printf("owner=%s\n", hex.EncodeToString(r.Owner))
	fmt.Printf("signer=%s\n", hex.EncodeToString(env.Signer))
	fmt.Printf("signature_valid=%v\n", env.VerifySignature())
	fmt.Printf("sequence=%d\n", r.Sequence)
	fmt.Printf("created=%s (unix %d)\n", time.Unix(int64(r.Created), 0).UTC().Format(time.RFC3339), r.Created)
	fmt.Printf("expires=%s (unix %d, %d seconds remaining)\n",
		time.Unix(int64(r.Expires), 0).UTC().Format(time.RFC3339), r.Expires, int64(r.Expires)-now)
	fmt.Printf("revoked=%v\n", env.IsRevoked())
	if len(r.Delegation) == constants.Ed25519PublicKeyLen {
		fmt.Printf("delegation=%s\n", hex.EncodeToString(r.Delegation))
	}
	if len(r.Claim) > 0 {
		fmt.Printf("claim=embedded (%d bytes)\n", len(r.Claim))
	}
	fmt.Printf("rrset=%d\n", len(r.RRset))
	for i, rr := range r.RRset {
		line := fmt.Sprintf("  [%d] type=%d ttl=%d rdata=%s", i, rr.Type, rr.TTL, hex.EncodeToString(rr.Rdata))
		if s := readableRdata(rr); s != "" {
			line += "  " + s
		}
		fmt.Println(line)
	}
}

// readableRdata renders the §4.3 rdata of A / AAAA / TXT RRs in a
// human-readable form; other types (and wrong-length rdata) return "" — the
// hex form is already printed by printEnvelope.
func readableRdata(rr *wire.RR) string {
	switch rr.Type {
	case wire.RRTypeA:
		if len(rr.Rdata) == net.IPv4len {
			return "a=" + net.IP(rr.Rdata).String()
		}
	case wire.RRTypeAAAA:
		if len(rr.Rdata) == net.IPv6len {
			return "aaaa=" + net.IP(rr.Rdata).String()
		}
	case wire.RRTypeTXT:
		return "txt=" + strconv.Quote(string(rr.Rdata))
	}
	return ""
}

// ---------------------------------------------------------------------------
// publish — §6.4 PUT
// ---------------------------------------------------------------------------

// publishWithEvidence PUTs env with its §8.4 evidence attached via
// Node.PublishWithEvidence (internal/dht: the evidence rides along on every
// put so storing peers retain it next to the envelope). It never falls back
// to a plain Publish: a recovery record that silently lost its proof would
// be indistinguishable from an unsigned-key takeover (§8.4 step 2's
// cancellation race exists precisely because acceptance REQUIRES the
// evidence).
func publishWithEvidence(ctx context.Context, n *dht.Node, env *wire.SignedEnvelope, evidence []byte) error {
	return n.PublishWithEvidence(ctx, env, evidence)
}

// cmdPublish implements `publish`: decode each -files envelope, then PUT it
// to the R closest peers (§6.4 PUT — the node obtains a write token from
// each peer via a prior get, §6.3) or hand it to the running daemon (no
// -peers). One line per file is printed ("name-summary -> accepted/
// rejected"); the exit is non-zero only when ALL files fail, and a warning
// is emitted when only some fail.
//
// -evidence <path> switches the single -file into §8.4 evidence transport:
// the RecoveryEvidence CBOR is read, decoded (fail fast), and carried in the
// PUT via [publishWithEvidence] instead of a plain Publish — the output line
// then notes the attached signature count. It requires exactly ONE -file
// (the recovered record R2 the evidence proves). Evidence transport is
// standalone-only: the admin socket does not carry recovery evidence.
func cmdPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	filesCSV := fs.String("files", "", "comma-separated paths of signed-envelope .cbor files to PUT onto the DHT (§6.4)")
	nodeSeedHex := fs.String("node-seed", "", "hex Ed25519 seed (32 bytes) for this CLI node's DHT identity; random if empty (standalone mode only)")
	peersCSV := fs.String("peers", "", "comma-separated bootstrap peers as ip:port#<64-hex-pubkey> (standalone mode; default: the running daemon)")
	listenAddr := fs.String("listen", "", "UDP address for the CLI DHT node (default: ephemeral :0; standalone mode only)")
	evidencePath := fs.String("evidence", "", "path to a RecoveryEvidence CBOR (spec 8.4, recover -out): publish the single -file WITH the evidence (Node.PublishWithEvidence) instead of a plain PUT; requires exactly ONE -file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("publish takes no positional arguments")
	}
	var files []string
	for _, f := range strings.Split(*filesCSV, ",") {
		if f = strings.TrimSpace(f); f != "" {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return usageErr("publish requires -files <csv of .cbor paths>")
	}
	// §8.4 evidence transport: read + decode BEFORE touching the network so a
	// bad path/bytes is a fast local error, and pin the one-file shape (the
	// evidence proves exactly one recovered record R2).
	var evidence []byte
	var evidenceSigs int
	if *evidencePath != "" {
		if len(files) != 1 {
			return usageErr("publish -evidence requires exactly ONE -file (the spec 8.4 recovered record R2 it proves), got %d", len(files))
		}
		data, err := os.ReadFile(*evidencePath)
		if err != nil {
			return fmt.Errorf("read %q: %w", *evidencePath, err)
		}
		ev, err := wire.DecodeRecoveryEvidence(data)
		if err != nil {
			return fmt.Errorf("decode evidence %q: %w", *evidencePath, err)
		}
		evidence, evidenceSigs = data, len(ev.Signatures)
	}
	tr, err := pickTransport(*peersCSV)
	if err != nil {
		return err
	}
	if evidence != nil && tr.daemon() {
		return usageErr("publish -evidence requires standalone mode: pass -peers (the admin socket does not carry spec 8.4 recovery evidence)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	defer cancel()
	var node *dht.Node
	if !tr.daemon() {
		node, err = startCLINode(ctx, *nodeSeedHex, *listenAddr, tr.peers)
		if err != nil {
			return err
		}
		defer node.Close()
	}

	accepted, failed := 0, 0
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			failed++
			fmt.Printf("%s: <unreadable> -> rejected (%v)\n", path, err)
			continue
		}
		env, err := wire.DecodeEnvelope(data)
		if err != nil {
			failed++
			fmt.Printf("%s: <undecodable> -> rejected (%v)\n", path, err)
			continue
		}
		if !env.VerifySignature() {
			failed++
			fmt.Printf("%s: %s -> rejected (envelope signature invalid)\n", path, nameSummary(env.Record.Name))
			continue
		}
		if evidence != nil {
			// §8.4 path — evidence attached; a failure here is final (no
			// silent plain-publish fallback, see publishWithEvidence).
			if err := publishWithEvidence(ctx, node, env, evidence); err != nil {
				failed++
				fmt.Printf("%s: %s -> rejected (evidence transport: %v)\n", path, nameSummary(env.Record.Name), err)
				continue
			}
			accepted++
			fmt.Printf("%s: %s -> accepted (spec 8.4 evidence attached: %s, %d signature(s))\n",
				path, nameSummary(env.Record.Name), *evidencePath, evidenceSigs)
			continue
		}
		stored := 0
		if tr.daemon() {
			stored, err = tr.client.Publish(ctx, env)
		} else {
			err = node.Publish(ctx, env)
		}
		if err != nil {
			failed++
			fmt.Printf("%s: %s -> rejected (%v)\n", path, nameSummary(env.Record.Name), err)
			continue
		}
		accepted++
		if tr.daemon() && stored > 0 {
			fmt.Printf("%s: %s -> accepted (daemon, %d storing peers)\n", path, nameSummary(env.Record.Name), stored)
		} else {
			fmt.Printf("%s: %s -> accepted\n", path, nameSummary(env.Record.Name))
		}
	}
	switch {
	case accepted == 0:
		return fmt.Errorf("publish: all %d file(s) failed", failed)
	case failed > 0:
		fmt.Fprintf(os.Stderr, "%s: warning: %d of %d file(s) failed\n", ProgName, failed, accepted+failed)
	}
	return nil
}

// ---------------------------------------------------------------------------
// resolve — §6.4 GET by name
// ---------------------------------------------------------------------------

// cmdResolve implements `resolve`: derive the wire_name from -name +
// -tld-id-b32, look it up with an iterative §6.4 GET (or via the daemon when
// no -peers is given), and display the terminal record. Only the TERMINAL
// record is displayed: cryptographic authority-chain verification (§3.4) is
// the daemon's job when serving DNS answers — this subcommand is a
// fetch/display/debug tool, not a validating resolver.
func cmdResolve(args []string) error {
	fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
	name := fs.String("name", "", "display name to fetch (labels.alias, e.g. www.alice.foo; bare alias = TLD root). Chain verification is NOT performed — the daemon does it when serving DNS.")
	tldIDB32 := fs.String("tld-id-b32", "", "base32 tld_id pin of the TLD (gen-key's tld_id_b32; RFC 4648, padding optional)")
	nodeSeedHex := fs.String("node-seed", "", "hex Ed25519 seed (32 bytes) for this CLI node's DHT identity; random if empty (standalone mode only)")
	peersCSV := fs.String("peers", "", "comma-separated bootstrap peers as ip:port#<64-hex-pubkey> (standalone mode; default: the running daemon)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("resolve takes no positional arguments")
	}
	if *name == "" || *tldIDB32 == "" {
		return usageErr("resolve requires -name and -tld-id-b32")
	}
	tldID, err := decodePin(*tldIDB32, "-tld-id-b32")
	if err != nil {
		return err
	}
	labels, alias, err := naming.DecomposeName(*name)
	if err != nil {
		return usageErr("invalid name %q: %v", *name, err)
	}
	tr, err := pickTransport(*peersCSV)
	if err != nil {
		return err
	}
	wireName, err := naming.EncodeWireName(labels, alias, tldID)
	if err != nil {
		return err
	}

	if tr.daemon() {
		ctx, cancel := adminCtx()
		defer cancel()
		r, err := tr.client.Resolve(ctx, *name)
		if err != nil {
			return err
		}
		if r == nil || !r.Found {
			fmt.Println("not found")
			return nil
		}
		printResolved(r, alias)
		return nil
	}

	key, err := dht.KeyForWireName(wireName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	defer cancel()
	node, err := startCLINode(ctx, *nodeSeedHex, "", tr.peers)
	if err != nil {
		return err
	}
	defer node.Close()

	env, err := node.IterativeGet(ctx, key)
	if err != nil {
		return err
	}
	if env == nil {
		fmt.Println("not found")
		return nil
	}
	fmt.Println("found")
	fmt.Printf("alias=%s\n", alias)
	fmt.Printf("key=%s\n", hex.EncodeToString(key))
	printEnvelope(env, time.Now().Unix())
	return nil
}

// printResolved pretty-prints an admin.Resolve answer in the same spirit as
// printEnvelope (the daemon has already chain-verified what it serves).
// RR.Rdata arrives base64-encoded ("rdata_b64"), with a human rendering in
// Text ("rdata_text") when one exists.
func printResolved(r *adminResolved, alias string) {
	fmt.Println("found")
	fmt.Printf("alias=%s\n", alias)
	fmt.Printf("name=%s\n", r.Name)
	fmt.Printf("tld_id_b32=%s\n", r.TldIDB32)
	fmt.Printf("owner=%s\n", r.Owner)
	fmt.Printf("sequence=%d\n", r.Sequence)
	fmt.Printf("rrset=%d\n", len(r.RRset))
	for i, rr := range r.RRset {
		line := fmt.Sprintf("  [%d] type=%d ttl=%d rdata_b64=%s", i, rr.Type, rr.TTL, rr.Rdata)
		if rr.Text != "" {
			line += "  " + rr.Text
		}
		fmt.Println(line)
	}
}

// ---------------------------------------------------------------------------
// get — raw §6.4 GET by key
// ---------------------------------------------------------------------------

// cmdGet implements `get`: a raw iterative GET of an arbitrary 32-byte DHT
// key (K_tld, K_name, or K_claim — whatever produced the key), printing the
// envelope's H_record plus the record summary, or "not found". Daemon-backed
// when no -peers is given.
func cmdGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	keyHex := fs.String("key", "", "32-byte DHT key as 64 hex chars")
	nodeSeedHex := fs.String("node-seed", "", "hex Ed25519 seed (32 bytes) for this CLI node's DHT identity; random if empty (standalone mode only)")
	peersCSV := fs.String("peers", "", "comma-separated bootstrap peers as ip:port#<64-hex-pubkey> (standalone mode; default: the running daemon)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("get takes no positional arguments")
	}
	if *keyHex == "" {
		return usageErr("get requires -key <64-hex>")
	}
	key, err := hex.DecodeString(strings.TrimSpace(*keyHex))
	if err != nil {
		return usageErr("invalid key hex: %v", err)
	}
	if len(key) != constants.SHA256Len {
		return usageErr("key must be %d bytes (%d hex chars), got %d bytes", constants.SHA256Len, 2*constants.SHA256Len, len(key))
	}
	tr, err := pickTransport(*peersCSV)
	if err != nil {
		return err
	}

	if tr.daemon() {
		ctx, cancel := adminCtx()
		defer cancel()
		env, err := tr.client.Get(ctx, key)
		if err != nil {
			return err
		}
		if env == nil {
			fmt.Println("not found")
			return nil
		}
		fmt.Println("found")
		fmt.Printf("key=%s\n", hex.EncodeToString(key))
		printEnvelope(env, time.Now().Unix())
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	defer cancel()
	node, err := startCLINode(ctx, *nodeSeedHex, "", tr.peers)
	if err != nil {
		return err
	}
	defer node.Close()

	env, err := node.IterativeGet(ctx, key)
	if err != nil {
		return err
	}
	if env == nil {
		fmt.Println("not found")
		return nil
	}
	fmt.Println("found")
	fmt.Printf("key=%s\n", hex.EncodeToString(key))
	printEnvelope(env, time.Now().Unix())
	return nil
}
