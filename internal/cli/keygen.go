// keygen.go — the key/claim primitives: gen-key (Ed25519 keypair) and
// mine-claim (§7.3 AliasClaim PoW). Moved verbatim from the freens-cli
// front-end into the shared cli package.
package cli

import (
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/crypto"
)

// ---------------------------------------------------------------------------
// gen-key
// ---------------------------------------------------------------------------

func cmdGenKey(args []string) error {
	fs := flag.NewFlagSet("gen-key", flag.ContinueOnError)
	out := fs.String("out", "", "write the seed as a 0600 keyfile (64 hex chars + newline) for use as -owner-key @<path> etc.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("gen-key takes no positional arguments")
	}
	kp, err := crypto.Generate()
	if err != nil {
		return err
	}
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		return err
	}
	fmt.Printf("seed=%s\n", hex.EncodeToString(kp.Seed()))
	fmt.Printf("public=%s\n", hex.EncodeToString(kp.Public()))
	fmt.Printf("tld_id=%s\n", hex.EncodeToString(tldID))
	fmt.Printf("tld_id_b32=%s\n", base32.StdEncoding.EncodeToString(tldID))
	if *out != "" {
		if err := writeKeyFile(*out, kp); err != nil {
			return fmt.Errorf("writing keyfile: %w", err)
		}
		fmt.Printf("keyfile=%s (0600; use as -owner-key @%s on other subcommands)\n", *out, *out)
	}
	return nil
}

// ---------------------------------------------------------------------------
// mine-claim
// ---------------------------------------------------------------------------

func cmdMineClaim(args []string) error {
	fs := flag.NewFlagSet("mine-claim", flag.ContinueOnError)
	alias := fs.String("alias", "", "alias to claim (e.g. foo)")
	seedHex := fs.String("seed", "", "claimant Ed25519 seed (hex)")
	difficulty := fs.Int("difficulty", 12, "PoW difficulty in bits (12 = quick demo; 24 = network default)")
	maxIters := fs.Int("max-iters", 2_000_000, "max PoW search iterations")
	nonceSize := fs.Int("nonce-size", 16, "nonce byte length (nonce[0] records the difficulty per Appendix A.4)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *alias == "" || *seedHex == "" {
		return usageErr("mine-claim requires -alias and -seed")
	}
	// -seed accepts hex or @keyfile (seedKeypair).
	kp, err := seedKeypair(*seedHex, "-seed")
	if err != nil {
		return err
	}
	now := uint64(time.Now().Unix())
	claim, err := claims.MineAliasClaim(*alias, kp, now, *difficulty, *maxIters, *nonceSize)
	if err != nil {
		return err
	}
	// Self-check the mined claim before printing it.
	if !claim.VerifyPoW(*difficulty) {
		return cryptoErr("mined claim failed VerifyPoW at difficulty %d", *difficulty)
	}
	if !claim.VerifyClaimantConsistency() {
		return cryptoErr("mined claim failed VerifyClaimantConsistency (tld_id != SHA-256(pk))")
	}
	cb, err := claim.CanonicalBytes()
	if err != nil {
		return err
	}
	fmt.Printf("alias=%s\n", claim.Alias)
	fmt.Printf("tld_id=%s\n", hex.EncodeToString(claim.TldID))
	fmt.Printf("nonce=%s\n", hex.EncodeToString(claim.Nonce))
	fmt.Printf("pow_hash=%s\n", hex.EncodeToString(claim.PowHash))
	fmt.Printf("timestamp=%d\n", claim.Timestamp)
	fmt.Printf("claim_cbor=%s\n", hex.EncodeToString(cb))
	return nil
}
