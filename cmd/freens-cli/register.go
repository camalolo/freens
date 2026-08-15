package main

// register.go — `freens-cli register`: the §7 end-to-end alias onboarding in
// ONE command. Before register, creating a network alias meant chaining
// gen-key → mine-claim → (somehow collecting W=5 witness attestations from
// live nodes) → make-record → publish — with the witness step having no
// client path at all outside test drivers. register is the product flow:
//
//	owner key (loaded or generated, saved 0600)
//	  → §7.3 claim PoW at the network difficulty
//	  → §6.2 IterativeFindNode toward K_claim (fills the routing table past
//	    the bootstrap peers — the WITNESS_SET are the W nodes closest to
//	    K_claim, discoverable only by walking)
//	  → §7.3 CollectWitnesses (distinct live nodes co-sign via the witness
//	    RPC; Appendix A.4 difficulty gossip rides the responses)
//	  → claims.VerifyFull (PoW + witness quorum + claimant binding)
//	  → TLD record v1 with the claim embedded, published at K_tld AND
//	    K_claim (PublishClaim)
//
// Every seed flag in this CLI also accepts "@/path/to/keyfile" in place of
// hex (seedFromSpec) — register writes such a file for a generated key, so
// the follow-up make-record/publish round trips never need the raw seed on
// a command line (ps/history exposure).

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

	"github.com/fxamacker/cbor/v2"
	"github.com/laurent/freens/internal/claims"
	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/dht"
	"github.com/laurent/freens/internal/naming"
	"github.com/laurent/freens/internal/wire"
)

func cmdRegister(args []string) error {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	alias := fs.String("alias", "", "alias to claim (e.g. alice); becomes the TLD of your namespace")
	ip := fs.String("ip", "", "IPv4 address for the apex A record (e.g. 1.2.3.4)")
	ttl := fs.Uint64("ttl", 300, "apex A record TTL in seconds")
	peersCSV := fs.String("peers", "", "comma-separated bootstrap peers as ip:port#<64-hex-node-pubkey> (required)")
	difficulty := fs.Int("difficulty", constants.PoWDifficultyInit, "PoW difficulty in bits (default: the network difficulty, 24 bits)")
	maxIters := fs.Int("max-iters", 500_000_000, "max PoW search iterations (~4s at 24 bits on a modern core)")
	ownerKey := fs.String("owner-key", "", "owner key: 64-hex-char seed or @keyfile (default: generate a fresh key)")
	outKey := fs.String("out-key", "", "where to write a GENERATED owner key (default ~/.freens/keys/<alias>.key; 0600)")
	outDir := fs.String("out-dir", ".", "directory for the artifacts (<alias>.tld.cbor)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *alias == "" || *ip == "" || *peersCSV == "" {
		return usageErr("register requires -alias, -ip and -peers")
	}
	peers, err := parsePeerList(*peersCSV)
	if err != nil {
		return err
	}
	if *difficulty < constants.PoWDifficultyInit {
		return usageErr("-difficulty must be >= %d (the network default, Appendix A.4)", constants.PoWDifficultyInit)
	}

	// --- owner key ---------------------------------------------------------
	var kp *crypto.Keypair
	keyPath := ""
	switch {
	case *ownerKey != "":
		kp, err = seedKeypair(*ownerKey, "-owner-key")
		if err != nil {
			return err
		}
		fmt.Printf("owner key loaded (%d-byte policy-free Ed25519)\n", 32)
	default:
		kp, err = crypto.Generate()
		if err != nil {
			return err
		}
		keyPath = *outKey
		if keyPath == "" {
			home, _ := os.UserHomeDir()
			if home == "" {
				keyPath = *alias + ".key"
			} else {
				keyPath = filepath.Join(home, ".freens", "keys", *alias+".key")
			}
		}
		if err := writeKeyFile(keyPath, kp); err != nil {
			return fmt.Errorf("writing owner key: %w", err)
		}
		fmt.Printf("owner key generated and saved (0600): %s  — BACK THIS UP; losing it without a recovery policy loses the name\n", keyPath)
	}
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		return err
	}
	pin := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(tldID), "="))
	fmt.Printf("alias=%s tld_id_b32=%s\n", *alias, pin)

	// --- §7.3 PoW ------------------------------------------------------------
	ts := uint64(time.Now().Unix())
	fmt.Printf("mining claim (difficulty %d bits)...\n", *difficulty)
	claim, err := claims.MineAliasClaim(*alias, kp, ts, *difficulty, *maxIters, 16)
	if err != nil {
		return err
	}
	fmt.Printf("  PoW found: pow_hash=%s\n", hex.EncodeToString(claim.PowHash[:8]))

	// --- network: table walk + witness collection ---------------------------
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	node, err := startCLINode(ctx, "", ":0", peers)
	if err != nil {
		return err
	}
	defer node.Close()

	kClaim, err := dht.KeyForClaim(*alias)
	if err != nil {
		return err
	}
	// §6.2 walk toward K_claim: bootstrap peers alone would cap the witness
	// candidates at the -peers list; the WITNESS_SET is defined over the W
	// closest nodes to K_claim, so fill the routing table first.
	found := node.IterativeFindNode(ctx, kClaim, constants.WitnessSet)
	fmt.Printf("witness candidates (closest to K_claim): %d\n", len(found))

	atts, err := node.CollectWitnesses(ctx, *alias, tldID, kp.Public(), ts, constants.WitnessSet)
	if err != nil {
		return fmt.Errorf("witness collection: %w", err)
	}
	if len(atts) < constants.W {
		return fmt.Errorf("only %d of %d required witnesses responded — the network is too small from this vantage point; add more -peers and retry (the claim PoW is reusable: rerun with the same -owner-key and -difficulty)", len(atts), constants.W)
	}
	claim.Witnesses = atts[:constants.W]
	if !claims.VerifyFull(claim, claims.InferDifficulty, nil, constants.W) {
		return cryptoErr("assembled claim failed VerifyFull (PoW + %d distinct witnesses)", constants.W)
	}
	fmt.Printf("  witnesses: %d distinct nodes co-signed\n", len(claim.Witnesses))

	// --- publish (§6.4 PUT at BOTH keys) ------------------------------------
	// §7.4/C.1: the claim envelope lives at K_tld (the name's record) AND
	// K_claim (the contest set) — resolvers consult both. Walk toward K_tld
	// first so the R closest storers are in the routing table (the witness
	// walk filled it toward K_claim, a different key).
	name, err := naming.EncodeWireName(nil, *alias, tldID)
	if err != nil {
		return err
	}
	kTld, err := dht.KeyForWireName(name)
	if err != nil {
		return err
	}
	node.IterativeFindNode(ctx, kTld, constants.RReplication)
	now := uint64(time.Now().Unix())
	rec, err := wire.NewRecord(name, kp.Public(), 1, now, now+86400)
	if err != nil {
		return err
	}
	ip4 := netIP(*ip)
	if ip4 == nil {
		return usageErr("invalid -ip %q (want dotted quad)", *ip)
	}
	a, err := wire.A(ip4, *ttl)
	if err != nil {
		return usageErr("invalid -ip: %v", err)
	}
	rec.RRset = []*wire.RR{a}
	cb, err := claim.CanonicalBytes()
	if err != nil {
		return err
	}
	rec.Claim = cbor.RawMessage(cb)
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		return err
	}

	if err := node.Publish(ctx, env); err != nil {
		return fmt.Errorf("publish (K_tld): %w", err)
	}
	if err := node.PublishClaim(ctx, env); err != nil {
		return fmt.Errorf("publish (K_claim): %w", err)
	}
	envPath := filepath.Join(*outDir, *alias+".tld.cbor")
	if b, err := env.Bytes(); err == nil {
		if werr := os.WriteFile(envPath, b, 0o644); werr != nil {
			fmt.Fprintf(os.Stderr, "freens-cli: warning: could not write %s (%v)\n", envPath, werr)
		}
	}

	fmt.Println("PUBLISHED (K_tld + K_claim). Your namespace:")
	fmt.Printf("  %s.            -> %s   (apex, live now)\n", *alias, *ip)
	fmt.Println("next steps:")
	fmt.Printf("  add names:  freens-cli make-record -name www.%s -pin %s -owner-seed @%s -ip <ip> -out www.cbor\n", *alias, pin, keyPathOrSeed(keyPath, kp))
	fmt.Printf("              freens-cli publish -files www.cbor -peers %s\n", *peersCSV)
	fmt.Println("  (consider a spec 5.4 recovery policy: make-record -recovery-keys on the apex's next sequence)")
	if keyPath != "" {
		fmt.Printf("artifacts: %s %s\n", keyPath, envPath)
	} else {
		fmt.Printf("artifacts: %s\n", envPath)
	}
	return nil
}

// keyPathOrSeed prints the key-file reference when one exists (the ergonomic
// next step), else the raw hex (loaded-key case: no file was written).
func keyPathOrSeed(path string, kp *crypto.Keypair) string {
	if path != "" {
		return path
	}
	return hex.EncodeToString(kp.Seed())
}

// writeKeyFile persists a hex seed at path with 0600 (mkdir -p the parent).
func writeKeyFile(path string, kp *crypto.Keypair) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(hex.EncodeToString(kp.Seed())+"\n"), 0o600)
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
