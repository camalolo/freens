// register.go — `register`: the §7 end-to-end alias onboarding in ONE
// command. Before register, creating a network alias meant chaining
// gen-key → mine-claim → (somehow collecting W=5 witness attestations from
// live nodes) → make-record → publish — with the witness step having no
// client path at all outside test drivers. register is the product flow:
//
//	owner key (loaded or generated, saved 0600 in the keychain)
//	  → §7.3 claim PoW at the network difficulty
//	  → 2-of-3 recovery keyfiles + a spec 5.4 policy embedded in the apex
//	    record (default ON — the "user never loses their name" decision;
//	    -no-recovery opts out)
//	  → §7.3 witness collection: W distinct live nodes co-sign the claim —
//	    via the RUNNING DAEMON's routing table (admin socket) when no
//	    -peers is given, else via a one-shot CLI node's §6.2
//	    IterativeFindNode walk toward K_claim + CollectWitnesses
//	  → claims.VerifyFull (PoW + witness quorum + claimant binding)
//	  → TLD record v1 with the claim embedded, published at K_tld AND
//	    K_claim (daemon Publish/PublishClaim or Node.Publish/PublishClaim)
//
// Every seed flag in this CLI also accepts "@/path/to/keyfile" in place of
// hex (seedFromSpec) — register writes such a file for a generated key, so
// the follow-up name/make-record/publish round trips never need the raw
// seed on a command line (ps/history exposure).
package cli

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/keychain"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
	"github.com/fxamacker/cbor/v2"
)

// recoveryKeyfileCount / recoveryThreshold / recoveryTimelockDefault are the
// register recovery defaults (user decision, default ON): 3 keyfiles, any 2
// recover, 72 h timelock (constants.RecoveryTimelock, spec 5.4/8.4).
const (
	recoveryKeyfileCount = 3
	recoveryThreshold    = 2
)

func cmdRegister(args []string) error {
	// The README form is positional (`freens register alice`); -alias stays
	// for scripts and muscle memory. stdlib flag stops at the first
	// positional, so a LEADING alias is lifted out before Parse and a
	// TRAILING one is read from fs.Args() — `register alice -ip x` and
	// `register -ip x alice` both work.
	var lead string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		lead, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	alias := fs.String("alias", "", "alias to claim (e.g. alice); becomes the TLD of your namespace (positional form: register alice)")
	ip := fs.String("ip", "", "IPv4 address for the apex A record (default: this machine's outbound IPv4)")
	ttl := fs.Uint64("ttl", 300, "apex A record TTL in seconds")
	peersCSV := fs.String("peers", "", "comma-separated bootstrap peers as ip:port#<64-hex-node-pk> (standalone mode; default: the running daemon)")
	difficulty := fs.Int("difficulty", constants.PoWDifficultyInit, "PoW difficulty in bits (default: the network difficulty, 24 bits)")
	maxIters := fs.Int("max-iters", 500_000_000, "max PoW search iterations (~4s at 24 bits on a modern core)")
	ownerKey := fs.String("owner-key", "", "owner key: 64-hex-char seed or @keyfile (default: generate a fresh key)")
	outKey := fs.String("out-key", "", "where to write a GENERATED owner key (default <home>/keys/<alias>.key; 0600)")
	outDir := fs.String("out-dir", ".", "directory for the artifacts (<alias>.tld.cbor)")
	noRecovery := fs.Bool("no-recovery", false, "do NOT generate the default 2-of-3 recovery keyfiles / embed a spec 5.4 policy in the apex record")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// The README form is positional (`freens register alice`); -alias stays
	// for scripts and muscle memory.
	pos := fs.Args()
	if lead != "" {
		pos = append([]string{lead}, pos...)
	}
	switch {
	case len(pos) > 1:
		return usageErr("register takes one alias (%s register <alias>); got %d arguments", ProgName, len(pos))
	case len(pos) == 1 && *alias != "" && pos[0] != *alias:
		return usageErr("alias given twice: %q and -alias %s — pass it once", pos[0], *alias)
	case *alias == "" && len(pos) == 1:
		*alias = pos[0]
	}
	if *alias == "" {
		return usageErr("register needs an alias: %s register <alias>  (e.g. %s register alice; -ip and -peers default to this machine's outbound IPv4 and the running daemon)", ProgName, ProgName)
	}
	if *difficulty < constants.PoWDifficultyInit {
		return usageErr("-difficulty must be >= %d (the network default, Appendix A.4)", constants.PoWDifficultyInit)
	}

	// --- IP: explicit or the machine's outbound IPv4 -----------------------
	apexIP := *ip
	if apexIP == "" {
		out, err := outboundIPv4()
		if err != nil {
			return err
		}
		apexIP = out.String()
		fmt.Printf("ip=%s (this machine's outbound IPv4; override with -ip)\n", apexIP)
	}
	if ip := net.ParseIP(apexIP); ip == nil || (ip.To4() == nil && !strings.Contains(apexIP, ":")) {
		return usageErr("invalid -ip %q (want an IPv4 dotted quad or an IPv6 literal)", apexIP)
	}

	// --- owner key ---------------------------------------------------------
	var kp *crypto.Keypair
	keyPassphrase := ""
	keyPath := ""
	if *ownerKey != "" {
		var err error
		kp, err = seedKeypair(*ownerKey, "-owner-key")
		if err != nil {
			return err
		}
		fmt.Printf("owner key loaded (%d-byte policy-free Ed25519)\n", 32)
	} else if def := filepath.Join(home.KeysDir(), *alias+".key"); fileExists(def) {
		// RETRIES REUSE THE IDENTITY: a second `register -alias x` continues
		// the first attempt's claim (cooldown-safe, same keychain entry,
		// same recovery policy) instead of minting a new identity whose
		// claim the witness cooldown would refuse.
		var err error
		kp, err = seedKeypair("@"+def, "-owner-key")
		if err != nil {
			return err
		}
		keyPath = def
		fmt.Printf("owner key reused: %s (continuing the previous attempt)\n", def)
	} else {
		var err error
		kp, err = crypto.Generate()
		if err != nil {
			return err
		}
		keyPath = *outKey
		if keyPath == "" {
			keyPath = ownerKeyPath(*alias) // <home>/keys/<alias>.key
		}
		// Passphrase policy (interactive default: ask; empty twice, or
		// the explicit FREENS_ALLOW_PLAINTEXT_KEY=1 non-terminal opt-in,
		// = plaintext legacy form). One passphrase covers the owner key
		// AND the recovery keyfiles below.
		var perr error
		keyPassphrase, perr = promptNewPassphrase()
		if perr != nil {
			return perr
		}
		if err := writeKeyFileEnc(keyPath, kp, keyPassphrase); err != nil {
			return fmt.Errorf("writing owner key: %w", err)
		}
		if keyPassphrase != "" {
			fmt.Printf("owner key generated and saved (0600, passphrase-encrypted): %s\n", keyPath)
			fmt.Printf("*** the daemon CANNOT auto-renew passphrase-protected names (it cannot prompt) — renew manually (`%s renew %s`) or provide %s to the service\n", ProgName, *alias, EnvPassphrase)
			fmt.Println("BACK THIS UP; losing it without a recovery policy loses the name")
		} else {
			fmt.Printf("owner key generated and saved (0600): %s  — BACK THIS UP; losing it without a recovery policy loses the name\n", keyPath)
		}
	}
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		return err
	}
	pin := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(tldID), "="))
	fmt.Printf("alias=%s tld_id_b32=%s\n", *alias, pin)

	// --- default-on recovery (spec 5.4; user decision) ---------------------
	recPaths, recPolicy, err := recoveryPlan(*noRecovery, home.KeysDir(), *alias, keyPassphrase)
	if err != nil {
		return err
	}
	if recPolicy != nil {
		fmt.Printf("recovery: %d-of-%d keyfiles generated (0600), %d s timelock embedded in the apex record (spec 5.4)\n",
			recPolicy.Threshold, len(recPolicy.Keys), recPolicy.Timelock)
		fmt.Println("*** BACK THESE UP on separate media — any", recPolicy.Threshold, "of", len(recPolicy.Keys), "recover the name if the owner key is lost; losing them all loses the name FOREVER:")
		for _, p := range recPaths {
			fmt.Printf("    %s\n", p)
		}
	} else {
		fmt.Println("recovery: NONE (-no-recovery) — if the owner key is lost the name cannot be re-pointered (spec 8.4)")
	}

	// --- §7.3 PoW (REUSED across retries with the same owner key) -----------
	// A failed attempt (e.g. not enough witnesses yet) must not burn the
	// alias: §7.3's WITNESS_COOLDOWN lets each witness re-sign the SAME
	// claim (identical prefix hash) inside the window, but a re-mined claim
	// carries a fresh timestamp = a new prefix hash = cooldown-refused. So
	// the mined claim persists next to the owner key and every retry with
	// that key reuses it verbatim; -difficulty changes invalidate it.
	fmt.Printf("mining claim (difficulty %d bits)...\n", *difficulty)
	ts := uint64(time.Now().Unix())
	claim := loadReusableClaim(*alias, kp, *difficulty)
	if claim == nil {
		var err error
		claim, err = claims.MineAliasClaim(*alias, kp, ts, *difficulty, *maxIters, 16)
		if err != nil {
			return err
		}
		saveReusableClaim(*alias, claim)
	} else {
		fmt.Println("  reusing the previously mined claim (same owner key — cooldown-safe)")
	}
	fmt.Printf("  PoW found: pow_hash=%s\n", hex.EncodeToString(claim.PowHash[:8]))

	// --- transport: daemon (admin socket) or standalone -peers --------------
	tr, err := pickTransport(*peersCSV)
	if err != nil {
		return err
	}

	// --- witness collection (§7.3) -------------------------------------------
	// Both paths pass claim.Timestamp — NOT a fresh now — so every retry
	// presents the SAME claim prefix hash. §7.3's cooldown lets a witness
	// re-sign an identical claim inside the window but REFUSES a different
	// one; a per-run ts on a reused claim would mint a new prefix each
	// attempt and cooldown-lock out exactly the witnesses that already
	// helped (observed live: attempts degrading 4→2→0 signers).
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var atts []*claims.WitnessAttestation
	var node *dht.Node
	if tr.daemon() {
		fmt.Printf("witnesses: collecting %d co-signatures via the running daemon (admin socket)\n", constants.W)
		atts, err = collectWitnessesRetried(constants.W, func(int) ([]*claims.WitnessAttestation, error) {
			return collectWitnessesViaAdmin(ctx, tr.client, *alias, tldID, kp.Public(), claim.Timestamp, claim.Nonce, claim.PowHash)
		})
		if err != nil {
			return err
		}
	} else {
		node, err = startCLINode(ctx, "", ":0", tr.peers)
		if err != nil {
			return err
		}
		defer node.Close()

		kClaim, err := dht.KeyForClaim(*alias)
		if err != nil {
			return err
		}
		atts, err = collectWitnessesRetried(constants.W, func(int) ([]*claims.WitnessAttestation, error) {
			// §6.2 walk toward K_claim: bootstrap peers alone would cap the
			// witness candidates at the -peers list; the WITNESS_SET is
			// defined over the W closest nodes to K_claim, so fill the
			// routing table first. Each attempt's walk also WARMS the
			// table (responses seed it), which is what makes retries
			// converge on a cold node.
			found := node.IterativeFindNode(ctx, kClaim, constants.WitnessSet)
			fmt.Printf("witness candidates (closest to K_claim): %d\n", len(found))
			return node.CollectWitnesses(ctx, *alias, tldID, kp.Public(), claim.Timestamp, claim.Nonce, claim.PowHash, constants.WitnessSet)
		})
		if err != nil {
			return err
		}
	}
	if len(atts) < constants.W {
		return fmt.Errorf("only %d of %d required witnesses responded — the network is too small from this vantage point; add more -peers and retry (the claim PoW is reusable: rerun with the same -owner-key and -difficulty). Help the network grow: run a community node (see contrib/seed-node.md) — every always-on node is one more witness", len(atts), constants.W)
	}
	claim.Witnesses = atts[:constants.W]
	if !claims.VerifyFull(claim, claims.InferDifficulty, nil, constants.W) {
		return cryptoErr("assembled claim failed VerifyFull (PoW + %d distinct witnesses)", constants.W)
	}
	fmt.Printf("  witnesses: %d distinct nodes co-signed\n", len(claim.Witnesses))

	// --- publish (§6.4 PUT at BOTH keys) ------------------------------------
	// §7.4/C.1: the claim envelope lives at K_tld (the name's record) AND
	// K_claim (the contest set) — resolvers consult both.
	name, err := naming.EncodeWireName(nil, *alias, tldID)
	if err != nil {
		return err
	}
	now := uint64(time.Now().Unix())
	// Sequence: the network's current + 1 when the name exists (a RETRY
	// after a revocation, or any prior publication, must out-sequence it —
	// §6.4 winner rule — or the re-publish is silently ignored); 1 for a
	// genuinely fresh name. Sequence discovery fetches the ENVELOPE by key
	// (tombstones included): /resolve does not report a revoked name's
	// sequence, so a revoke-then-re-register via Resolve alone would reset
	// to 1 and silently lose the winner race against the tombstone (found
	// live by the webui ops tests; the same fix as the web UI's engine).
	seq := uint64(1)
	if tr.daemon() {
		sctx, scancel := adminCtx()
		if cur, gerr := tr.client.Get(sctx, tldID); gerr == nil && cur != nil && cur.Record != nil {
			seq = cur.Record.Sequence + 1
		}
		scancel()
	} else {
		kTld, kerr := dht.KeyForWireName(name)
		if kerr != nil {
			return kerr
		}
		if cur, cerr := node.IterativeGet(ctx, kTld); cerr == nil && cur != nil {
			seq = cur.Record.Sequence + 1
		}
	}
	rec, err := wire.NewRecord(name, kp.Public(), seq, now, now+86400)
	if err != nil {
		return err
	}
	a, err := addrRR(apexIP, *ttl)
	if err != nil {
		return usageErr("invalid -ip: %v", err)
	}
	rec.RRset = []*wire.RR{a}
	rec.Recovery = recPolicy
	cb, err := claim.CanonicalBytes()
	if err != nil {
		return err
	}
	rec.Claim = cbor.RawMessage(cb)
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		return err
	}

	if tr.daemon() {
		if _, err := tr.client.Publish(ctx, env); err != nil {
			return fmt.Errorf("publish (K_tld, daemon): %w", err)
		}
		if err := tr.client.PublishClaim(ctx, env); err != nil {
			return fmt.Errorf("publish (K_claim, daemon): %w", err)
		}
	} else {
		// Walk toward K_tld first so the R closest storers are in the routing
		// table (the witness walk filled it toward K_claim, a different key).
		kTld, err := dht.KeyForWireName(name)
		if err != nil {
			return err
		}
		node.IterativeFindNode(ctx, kTld, constants.RReplication)
		if err := node.Publish(ctx, env); err != nil {
			return fmt.Errorf("publish (K_tld): %w", err)
		}
		if err := node.PublishClaim(ctx, env); err != nil {
			return fmt.Errorf("publish (K_claim): %w", err)
		}
	}
	envPath := filepath.Join(*outDir, *alias+".tld.cbor")
	if b, err := env.Bytes(); err == nil {
		if werr := os.WriteFile(envPath, b, 0o644); werr != nil {
			fmt.Fprintf(os.Stderr, "%s: warning: could not write %s (%v)\n", ProgName, envPath, werr)
		}
	}

	fmt.Println("PUBLISHED (K_tld + K_claim). Your namespace:")
	fmt.Printf("  %s.            -> %s   (apex, live now)\n", *alias, apexIP)
	fmt.Println("next steps:")
	fmt.Printf("  add names:  %s name www.%s            (IP defaults to the apex A record)\n", ProgName, *alias)
	if recPolicy == nil {
		fmt.Printf("  (consider a spec 5.4 recovery policy: make-record -recovery-keys on the apex's next sequence)\n")
	}
	fmt.Printf("artifacts: %s", envPath)
	if keyPath != "" {
		fmt.Printf(" %s", keyPath)
	}
	for _, p := range recPaths {
		fmt.Printf(" %s", p)
	}
	fmt.Println()
	return nil
}

// ---------------------------------------------------------------------------
// register helpers
// ---------------------------------------------------------------------------

// outboundIPv4 discovers this machine's outbound IPv4 address by "dialing" a
// public DNS resolver over UDP — no packet is sent; the kernel only picks a
// route and a source address, which is exactly the address the wider
// internet would see as ours.
func outboundIPv4() (net.IP, error) {
	conn, err := net.DialTimeout("udp4", "9.9.9.9:53", 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("could not determine this machine's outbound IPv4 (pass -ip explicitly): %w", err)
	}
	defer conn.Close()
	ua, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || ua.IP == nil || ua.IP.To4() == nil {
		return nil, fmt.Errorf("could not determine this machine's outbound IPv4 (pass -ip explicitly)")
	}
	return ua.IP.To4(), nil
}

// recoveryPlan is register's default-on recovery decision (spec 5.4):
//
//	with noRecovery: no files, no policy (nil, nil, nil)
//	otherwise:       <alias>.rec1/2/3.key fresh keyfiles (0600) in keysDir
//	                 + a 2-of-3 policy with a constants.RecoveryTimelock
//	                 (72 h) timelock, ready to embed in the apex record
//
// Split out so the defaults are unit-testable without a live network.
// recoveryPlan generates this alias's default-on spec 5.4 recovery policy
// (3 keys, threshold 2) — delegated to internal/keychain, shared with the
// web UI.
func recoveryPlan(noRecovery bool, keysDir, alias, passphrase string) ([]string, *wire.RecoveryPolicyWire, error) {
	return keychain.RecoveryPlan(noRecovery, keysDir, alias, passphrase,
		recoveryKeyfileCount, recoveryThreshold, constants.RecoveryTimelock)
}

// witnessRetryAttempts / witnessRetrySleep are the cold-routing-table
// self-heal knobs (vars so tests shrink them): a freshly started daemon or
// one-shot node may reach too few witnesses on the FIRST walk even on a
// healthy network; each walk warms the table, so pause + retry converges.
var (
	witnessRetryAttempts = 3
	witnessRetrySleep    = 10 * time.Second
)

// collectWitnessesRetried wraps one witness-collection attempt (a closure
// that returns the verified, de-duplicated attestations it gathered) with
// the cold-table self-heal: keep the best haul across attempts, pausing
// between them so the routing table fills. Returns the last error only
// when the attempt itself failed (transport errors are not wait-fixable);
// a short haul is returned to the caller, whose W-quorum check produces
// the actionable "network too small" message.
func collectWitnessesRetried(needed int, collect func(attempt int) ([]*claims.WitnessAttestation, error)) ([]*claims.WitnessAttestation, error) {
	var best []*claims.WitnessAttestation
	for attempt := 1; attempt <= witnessRetryAttempts; attempt++ {
		atts, err := collect(attempt)
		if err != nil {
			return nil, err
		}
		if len(atts) > len(best) {
			best = atts
		}
		if len(best) >= needed {
			return best, nil
		}
		if attempt < witnessRetryAttempts {
			fmt.Printf("  only %d of %d witnesses so far — waiting %s for the routing table to warm up (retry %d/%d)…\n",
				len(best), needed, witnessRetrySleep, attempt+1, witnessRetryAttempts)
			time.Sleep(witnessRetrySleep)
		}
	}
	return best, nil
}

// collectWitnessesViaAdmin asks the running daemon to collect the witness
// quorum on our behalf: the daemon's routing table is already warm, and its
// admin Witness RPC walks to the WITNESS_SET itself. Each returned raw CBOR
// attestation is decoded, verified against the claim's prefix hash (v2
// binding), and de-duplicated by node public key.
func collectWitnessesViaAdmin(ctx context.Context, c adminWitnesser, alias string, tldID, claimantPK []byte, ts uint64, nonce, powHash []byte) ([]*claims.WitnessAttestation, error) {
	raw, err := c.Witness(ctx, alias, tldID, claimantPK, ts, nonce, powHash)
	if err != nil {
		return nil, fmt.Errorf("witness collection (daemon): %w", err)
	}
	// The v2 attestations bind the claim prefix hash; recompute it here so
	// verification is local, not trusted from the daemon.
	prefixHash, err := (&claims.AliasClaim{
		Alias: alias, TldID: tldID, Timestamp: ts, ClaimantPK: claimantPK,
	}).PrefixHash()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(raw))
	var atts []*claims.WitnessAttestation
	for _, b := range raw {
		w, err := claims.DecodeWitnessAttestation(b)
		if err != nil {
			continue // malformed attestation: skip, the quorum decides
		}
		if !w.Verify(prefixHash) {
			continue
		}
		if seen[string(w.NodePK)] {
			continue
		}
		seen[string(w.NodePK)] = true
		atts = append(atts, w)
	}
	return atts, nil
}

// adminWitnesser is the admin-client slice collectWitnessesViaAdmin needs
// (kept as an interface so tests can drive it without a socket).
type adminWitnesser interface {
	Witness(ctx context.Context, alias string, tldID, claimant []byte, ts uint64, nonce, powHash []byte) ([][]byte, error)
}

// writeKeyFileEnc persists the seed (passphrase-encrypted FREENSK1 when
// passphrase != "", else the legacy plaintext form) — delegated to
// internal/keychain, shared with the web UI.
func writeKeyFileEnc(path string, kp *crypto.Keypair, passphrase string) error {
	return keychain.Save(path, kp, passphrase)
}

// netIP parses a dotted-quad IPv4 (the CLI's A-record convention); nil on
// anything else.
func netIP(s string) []byte {
	if ip := net.ParseIP(s); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return append([]byte(nil), ip4...)
		}
	}
	return nil
}

// reusableClaim is the persisted mined claim (cooldown-safe retries): the
// JSON mirrors the AliasClaim fields the witness prefix hash covers.
type reusableClaim struct {
	Alias       string `json:"alias"`
	TldIDB32    string `json:"tld_id_b32"`
	ClaimantB64 string `json:"claimant_b64"`
	Timestamp   uint64 `json:"timestamp"`
	Difficulty  int    `json:"difficulty"`
	NonceB64    string `json:"nonce_b64"`
}

func claimStatePath(alias string) string {
	return filepath.Join(home.KeysDir(), alias+".claim.json")
}

// loadReusableClaim returns the persisted claim when it matches alias, owner
// key, difficulty AND is still witnessable (v0.7.0: the §6.3 witness RPC
// refuses claims whose timestamp is older than WITNESS_COOLDOWN, so a parked
// claim past that age can never gather a quorum — re-mine instead of
// dead-looping retries against refusals). Delegated to internal/keychain,
// shared with the web UI.
func loadReusableClaim(alias string, kp *crypto.Keypair, difficulty int) *claims.AliasClaim {
	c := keychain.LoadReusableClaim(home.KeysDir(), alias, kp, difficulty)
	if c != nil && time.Now().Unix()-int64(c.Timestamp) >= int64(constants.WitnessCooldown) {
		return nil // stale: older than any witness will sign — re-mine
	}
	return c
}

// saveReusableClaim persists the claim for cooldown-safe retries (0600).
func saveReusableClaim(alias string, c *claims.AliasClaim) {
	keychain.SaveReusableClaim(home.KeysDir(), alias, c)
}

// difficultyOf reads the difficulty from the nonce[0] convention (Appendix
// A.4); falls back to the network default.
func difficultyOf(c *claims.AliasClaim) int {
	if len(c.Nonce) > 0 && int(c.Nonce[0]) >= constants.PoWDifficultyInit {
		return int(c.Nonce[0])
	}
	return constants.PoWDifficultyInit
}

func base32Decode(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(s))
}

// fileExists reports whether path is a regular file.
func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
