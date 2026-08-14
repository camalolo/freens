// Command freens-cli is the developer front-end for freens: Ed25519 key
// generation, alias-claim mining, record construction/signing, and a
// self-contained end-to-end demo of the full create → claim → delegate →
// publish → resolve lifecycle (no daemon required).
//
// Subcommands:
//
//	gen-key                      Generate an Ed25519 keypair; print seed/public/tld_id.
//	mine-claim                   Mine an AliasClaim PoW; print nonce/pow_hash/claim CBOR.
//	make-record                  Build + sign a freens record (A RR); print envelope CBOR + DHT key.
//	publish                      PUT signed-envelope .cbor files onto the DHT (§6.4 PUT).
//	resolve                      Fetch + display a name's terminal record (§6.4 GET; no chain walk).
//	get                          Raw DHT get by 64-hex key (§6.4 GET).
//	demo                         Self-contained end-to-end showcase (the headline demo).
//
// Exit codes: 0 success, 1 usage/error, 2 crypto/validation failure.
//
// publish/resolve/get are the live-network subcommands; they take -peers
// (addr#pk bootstrap peers, same format as the daemon's -peers) and talk real
// §6.3 UDP RPC. resolve/get DISPLAY the stored record only — cryptographic
// authority-chain verification (§3.4) is the daemon's job when serving DNS.
//
// PoW difficulty: -difficulty defaults to 12 for a quick demo. The network
// default is constants.PoWDifficultyInit (24, Appendix A); lower it only for
// local testing. The `demo` subcommand lowers claims.PoWDifficultyInit to 8
// in-process so the showcase runs in well under a second.
package main

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/laurent/freens/internal/claims"
	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/dht"
	"github.com/laurent/freens/internal/naming"
	"github.com/laurent/freens/internal/resolver"
	"github.com/laurent/freens/internal/wire"
	"github.com/miekg/dns"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(1)
	}
	sub := os.Args[1]
	args := os.Args[2:]
	var err error
	switch sub {
	case "gen-key":
		err = cmdGenKey(args)
	case "mine-claim":
		err = cmdMineClaim(args)
	case "make-record":
		err = cmdMakeRecord(args)
	case "transfer":
		err = cmdTransfer(args)
	case "rotate":
		err = cmdRotate(args)
	case "recover":
		err = cmdRecover(args)
	case "publish":
		err = cmdPublish(args)
	case "resolve":
		err = cmdResolve(args)
	case "get":
		err = cmdGet(args)
	case "demo":
		err = cmdDemo(args)
	case "-h", "--help", "help":
		usage(os.Stdout)
		return
	default:
		fmt.Fprintf(os.Stderr, "freens-cli: unknown subcommand %q\n", sub)
		usage(os.Stderr)
		os.Exit(1)
	}
	if err != nil {
		// crypto/validation failures exit 2; everything else (usage, IO) exits 1.
		code := 1
		if errors.Is(err, crypto.ErrCrypto) {
			code = 2
		}
		fmt.Fprintf(os.Stderr, "freens-cli: %v\n", err)
		os.Exit(code)
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, "usage: freens-cli <subcommand> [flags]")
	fmt.Fprintln(w, "subcommands:")
	fmt.Fprintln(w, "  gen-key               generate an Ed25519 keypair")
	fmt.Fprintln(w, "  mine-claim            mine an AliasClaim PoW")
	fmt.Fprintln(w, "  make-record           build + sign a freens record")
	fmt.Fprintln(w, "  transfer              hand a name to a new owner key (spec 8.3; -prev-envelope, -new-owner-seed, -signer-seed)")
	fmt.Fprintln(w, "  rotate                key hygiene: transfer to a fresh key (spec 8.6 = 8.3 hand-off)")
	fmt.Fprintln(w, "  recover               gather threshold recovery-key signatures (spec 8.4; -prev-envelope, -new-owner-seed, -recovery-seeds)")
	fmt.Fprintln(w, "  publish               put envelope .cbor files onto the DHT (-files, -peers)")
	fmt.Fprintln(w, "  resolve               fetch + display a record from the DHT (-name, -tld-id-b32, -peers)")
	fmt.Fprintln(w, "  get                   raw DHT get by key (-key, -peers)")
	fmt.Fprintln(w, "  demo                  self-contained end-to-end showcase")
	fmt.Fprintln(w, "resolve/get display the stored record only; authority-chain verification (§3.4)")
	fmt.Fprintln(w, "is the daemon's job when serving DNS answers.")
}

// errUsage signals a usage error (exit code 1).
type errUsage struct{ msg string }

func (e *errUsage) Error() string { return e.msg }

func usageErr(format string, args ...any) error {
	return &errUsage{msg: fmt.Sprintf(format, args...)}
}

// cryptoErr wraps a crypto/validation failure as crypto.ErrCrypto (exit code 2).
func cryptoErr(format string, args ...any) error {
	return fmt.Errorf("crypto: %s: %w", fmt.Sprintf(format, args...), crypto.ErrCrypto)
}

// ---------------------------------------------------------------------------
// gen-key
// ---------------------------------------------------------------------------

func cmdGenKey(args []string) error {
	fs := flag.NewFlagSet("gen-key", flag.ContinueOnError)
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
	seed, err := hex.DecodeString(strings.TrimSpace(*seedHex))
	if err != nil {
		return usageErr("invalid seed hex: %v", err)
	}
	kp, err := crypto.FromSeed(seed)
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

// ---------------------------------------------------------------------------
// make-record
// ---------------------------------------------------------------------------

func cmdMakeRecord(args []string) error {
	fs := flag.NewFlagSet("make-record", flag.ContinueOnError)
	name := fs.String("name", "", "display name (e.g. www.alice.foo)")
	ownerSeedHex := fs.String("owner-seed", "", "owner Ed25519 seed (hex)")
	ip := fs.String("ip", "", "IPv4 address for the A record (e.g. 1.2.3.4)")
	pin := fs.String("pin", "", "base32 tld_id of the alias owner (the TLD)")
	signerSeedHex := fs.String("signer-seed", "", "optional signer seed (hex); defaults to owner-seed (for delegation scenarios)")
	expiresStr := fs.String("expires", "", "expires unix timestamp (default: now+86400)")
	seq := fs.Uint64("seq", 1, "record sequence number")
	ttl := fs.Uint64("ttl", 300, "A record TTL in seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *ownerSeedHex == "" || *ip == "" || *pin == "" {
		return usageErr("make-record requires -name, -owner-seed, -ip, -pin")
	}
	labels, alias, err := naming.DecomposeName(*name)
	if err != nil {
		return usageErr("invalid name %q: %v", *name, err)
	}
	tldID, err := decodePin(*pin, "-pin")
	if err != nil {
		return err
	}
	ownerSeed, err := hex.DecodeString(strings.TrimSpace(*ownerSeedHex))
	if err != nil {
		return usageErr("invalid owner seed hex: %v", err)
	}
	ownerKP, err := crypto.FromSeed(ownerSeed)
	if err != nil {
		return err
	}
	signerKP := ownerKP
	if *signerSeedHex != "" {
		sseed, err := hex.DecodeString(strings.TrimSpace(*signerSeedHex))
		if err != nil {
			return usageErr("invalid signer seed hex: %v", err)
		}
		signerKP, err = crypto.FromSeed(sseed)
		if err != nil {
			return err
		}
	}
	ip4 := net.ParseIP(*ip).To4()
	if ip4 == nil {
		return usageErr("invalid IPv4 address %q", *ip)
	}
	now := uint64(time.Now().Unix())
	expires := now + uint64(constants.RecordDefaultTTL)
	if *expiresStr != "" {
		e, err := strconv.ParseUint(*expiresStr, 10, 64)
		if err != nil {
			return usageErr("invalid -expires: %v", err)
		}
		expires = e
	}
	wireName, err := naming.EncodeWireName(labels, alias, tldID)
	if err != nil {
		return err
	}
	rec, err := wire.NewRecord(wireName, ownerKP.Public(), *seq, now, expires)
	if err != nil {
		return err
	}
	aRR, err := wire.A(ip4, *ttl)
	if err != nil {
		return err
	}
	rec.RRset = []*wire.RR{aRR}
	env, err := wire.SignRecord(rec, signerKP)
	if err != nil {
		return err
	}
	envBytes, err := env.Bytes()
	if err != nil {
		return err
	}
	fmt.Printf("envelope_cbor=%s\n", hex.EncodeToString(envBytes))
	fmt.Printf("wire_name=%s\n", hex.EncodeToString(wireName))
	if len(labels) == 0 {
		fmt.Printf("k_tld=%s\n", hex.EncodeToString(tldID))
	} else {
		fmt.Printf("k_name=%s\n", hex.EncodeToString(naming.DHTKeyName(wireName)))
	}
	return nil
}

// decodePin decodes a base32 tld_id pin (RFC 4648; case-insensitive, padding
// optional) to exactly 32 bytes, mirroring resolver.decodeBase32TLDID. flagName
// names the calling flag for error messages ("-pin", "-tld-id-b32").
func decodePin(s, flagName string) ([]byte, error) {
	s2 := strings.ToUpper(strings.TrimSpace(s))
	if s2 == "" {
		return nil, usageErr("empty %s", flagName)
	}
	pad := (-len(s2)) % 8
	if pad < 0 {
		pad += 8
	}
	s2 += strings.Repeat("=", pad)
	decoded, err := base32.StdEncoding.DecodeString(s2)
	if err != nil {
		return nil, usageErr("invalid base32 %s %q: %v", flagName, s, err)
	}
	if len(decoded) != constants.SHA256Len {
		return nil, usageErr("decoded %s is %d bytes, expected %d", flagName, len(decoded), constants.SHA256Len)
	}
	return decoded, nil
}

// ---------------------------------------------------------------------------
// demo — the self-contained end-to-end showcase
// ---------------------------------------------------------------------------

func cmdDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Lower the PoW difficulty in-process for a fast, deterministic demo. The
	// library reads PoWDifficultyInit at call time, so the default
	// difficulty-inference path is exercised exactly as in production (just at
	// 8 bits instead of 24).
	savedDiff := claims.PoWDifficultyInit
	claims.PoWDifficultyInit = 8
	defer func() { claims.PoWDifficultyInit = savedDiff }()

	const (
		now   int64  = 2_000_000
		alias string = "foo"
	)
	wantIP := net.IPv4(203, 0, 113, 42)

	step := func(n int, format string, args ...any) {
		fmt.Printf("\n=== Step %d: %s ===\n", n, fmt.Sprintf(format, args...))
	}
	nl := func() { fmt.Println() }

	// 1. Alice generates a self-certifying TLD keypair.
	step(1, "Alice generates a self-certifying TLD keypair")
	alice, err := crypto.Generate()
	if err != nil {
		return err
	}
	aliceTID, err := crypto.TldID(alice.Public())
	if err != nil {
		return err
	}
	fmt.Printf("    PK_tld (hex)  = %s\n", hex.EncodeToString(alice.Public()))
	fmt.Printf("    tld_id (hex)  = %s\n", hex.EncodeToString(aliceTID))
	fmt.Printf("    tld_id (b32)  = %s\n", base32.StdEncoding.EncodeToString(aliceTID))
	fmt.Println("    (tld_id = SHA-256(PK_tld); self-certifying — no registrar needed)")

	// 2. Mine the "foo" alias claim at low difficulty.
	step(2, "Alice mines an AliasClaim PoW for %q at difficulty 8", alias)
	claim, err := claims.MineAliasClaim(alias, alice, uint64(now), 8, 2_000_000, 16)
	if err != nil {
		return err
	}
	fmt.Printf("    nonce         = %s\n", hex.EncodeToString(claim.Nonce))
	fmt.Printf("    pow_hash      = %s\n", hex.EncodeToString(claim.PowHash))
	fmt.Printf("    PoW valid     = %v\n", claim.VerifyPoW(8))
	fmt.Printf("    claimant bind = %v  (tld_id == SHA-256(claimant_pk))\n", claim.VerifyClaimantConsistency())

	// 3. Assemble W witnesses.
	step(3, "%d witness nodes (WITNESS_SET closest to K_claim) co-sign the claim", constants.W)
	witnesses := make([]*claims.WitnessAttestation, 0, constants.W)
	for i := 0; i < constants.W; i++ {
		nkp, err := crypto.Generate()
		if err != nil {
			return err
		}
		w, err := claims.NewWitnessAttestation(nkp, uint64(now)+uint64(i), alias, aliceTID, alice.Public())
		if err != nil {
			return err
		}
		witnesses = append(witnesses, w)
	}
	claim.Witnesses = witnesses
	full := claims.VerifyFull(claim, claims.InferDifficulty, nil, constants.W)
	fmt.Printf("    VerifyFull    = %v  (claimant binds + PoW + %d distinct witness sigs)\n", full, constants.W)

	// 4. Publish the authority chain into the in-process DHT store.
	step(4, "Publish the authority chain into the in-process DHT store")
	store := dht.NewEnvelopeStore(0, func() int64 { return now })

	// 4a. TLD record at K_tld, with the claim embedded in field 11.
	tldName, err := naming.EncodeWireName(nil, alias, aliceTID)
	if err != nil {
		return err
	}
	tldRec, err := wire.NewRecord(tldName, alice.Public(), 1, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		return err
	}
	cb, err := claim.CanonicalBytes()
	if err != nil {
		return err
	}
	tldRec.Claim = cb
	tldEnv, err := wire.SignRecord(tldRec, alice)
	if err != nil {
		return err
	}
	kTld, err := naming.DHTKeyTld(aliceTID)
	if err != nil {
		return err
	}
	if ok, err := store.Put(kTld, tldEnv, now, true); err != nil {
		return cryptoErr("store put K_tld: %v", err)
	} else if !ok {
		return cryptoErr("TLD record not accepted by store")
	}
	fmt.Printf("    K_tld         = %s   <- TLD record (claim embedded)\n", hex.EncodeToString(kTld))

	// 4b. Delegate alice.foo to a fresh sub-key (Delegation field).
	aliceSub, err := crypto.Generate()
	if err != nil {
		return err
	}
	aliceName, err := naming.EncodeWireName([]string{"alice"}, alias, aliceTID)
	if err != nil {
		return err
	}
	aliceRec, err := wire.NewRecord(aliceName, aliceSub.Public(), 1, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		return err
	}
	aliceRec.Delegation = aliceSub.Public()
	aliceEnv, err := wire.SignRecord(aliceRec, alice) // signed by the TLD key
	if err != nil {
		return err
	}
	kAlice := naming.DHTKeyName(aliceName)
	if ok, err := store.Put(kAlice, aliceEnv, now, true); err != nil {
		return cryptoErr("store put K_name(alice): %v", err)
	} else if !ok {
		return cryptoErr("alice.foo record not accepted by store")
	}
	fmt.Printf("    K_name(alice) = %s   <- delegates alice.foo to alice_sub_pk\n", hex.EncodeToString(kAlice))

	// 4c. www.alice.foo with A=203.0.113.42, signed by the delegated alice_sub.
	wwwName, err := naming.EncodeWireName([]string{"www", "alice"}, alias, aliceTID)
	if err != nil {
		return err
	}
	wwwRec, err := wire.NewRecord(wwwName, aliceSub.Public(), 1, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		return err
	}
	aRR, err := wire.A([]byte{203, 0, 113, 42}, 300)
	if err != nil {
		return err
	}
	wwwRec.RRset = []*wire.RR{aRR}
	wwwEnv, err := wire.SignRecord(wwwRec, aliceSub)
	if err != nil {
		return err
	}
	kWWW := naming.DHTKeyName(wwwName)
	if ok, err := store.Put(kWWW, wwwEnv, now, true); err != nil {
		return cryptoErr("store put K_name(www): %v", err)
	} else if !ok {
		return cryptoErr("www record not accepted by store")
	}
	fmt.Printf("    K_name(www)   = %s   <- A=203.0.113.42, signed by alice_sub\n", hex.EncodeToString(kWWW))

	// 5. Resolve www.alice.foo type A through the freens resolver.
	step(5, "Resolve www.alice.foo type A via the freens resolver")
	lookup := dht.NewStoreLookup(store)
	cfg := &resolver.Config{
		ListenUDP: "127.0.0.1:0",
		ListenTCP: "127.0.0.1:0",
		TLDRoutes: map[string]resolver.Route{alias: resolver.RouteFREENS, "*": resolver.RouteDNSFirst},
		AliasPins: map[string][]byte{alias: append([]byte(nil), aliceTID...)},
	}
	res := resolver.New(cfg, lookup, nil)
	res.Now = func() int64 { return now }

	q := dns.Question{Name: "www.alice.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, _, err := res.ResolveQuestion(context.Background(), q)
	if err != nil {
		return err
	}
	fmt.Printf("    rcode         = %d  (NOERROR = %d)\n", rcode, dns.RcodeSuccess)
	if len(rrs) != 1 {
		return cryptoErr("expected 1 answer RR, got %d", len(rrs))
	}
	a, ok := rrs[0].(*dns.A)
	if !ok {
		return cryptoErr("expected *dns.A, got %T", rrs[0])
	}
	fmt.Printf("    answer        = %s  %d  IN  A  %s\n", q.Name, a.Header().Ttl, a.A)
	fmt.Printf("    matches spec  = %v  (Appendix C.2: 203.0.113.42)\n", a.A.Equal(wantIP))

	// 6. Collision resolution: two claimants, deterministic winner.
	step(6, "Collision resolution (§7.4): two claimants, deterministic winner")
	alice2, err := crypto.FromSeed(bytes.Repeat([]byte{0xa1}, 32))
	if err != nil {
		return err
	}
	bob2, err := crypto.FromSeed(bytes.Repeat([]byte{0xb0}, 32))
	if err != nil {
		return err
	}
	cA, err := claims.MineAliasClaim(alias, alice2, uint64(now)+100, 8, 2_000_000, 16)
	if err != nil {
		return err
	}
	cB, err := claims.MineAliasClaim(alias, bob2, uint64(now)+50, 8, 2_000_000, 16)
	if err != nil {
		return err
	}
	w1 := claims.SelectWinner([]*claims.AliasClaim{cA, cB})
	w2 := claims.SelectWinner([]*claims.AliasClaim{cB, cA})
	// SelectWinner is documented to return nil when no claim survives the
	// structural/PoW filter; guard the dereference below (mirrors the
	// defensive check already in internal/integration).
	if w1 == nil || w2 == nil {
		return cryptoErr("select_winner returned nil")
	}
	nl()
	fmt.Printf("    Alice claim   ts=%d\n", cA.Timestamp)
	fmt.Printf("    Bob   claim   ts=%d  (earlier)\n", cB.Timestamp)
	fmt.Printf("    SelectWinner[Alice,Bob] picks Bob = %v\n", bytes.Equal(w1.ClaimantPK, bob2.Public()))
	fmt.Printf("    SelectWinner[Bob,Alice] picks Bob = %v  (input-order independent)\n", bytes.Equal(w2.ClaimantPK, bob2.Public()))
	fmt.Println("    => §7.4 total order (timestamp, pow_hash, tld_id): earliest assertion wins")

	nl()
	fmt.Println("Demo complete: full create -> claim -> delegate -> publish -> resolve flow verified.")
	fmt.Println("Run `freens -load <dir>` to serve records like these from the daemon.")
	return nil
}

// storeLookup used to be defined locally here; it now lives once in
// internal/dht as dht.NewStoreLookup(store), which structurally satisfies
// resolver.RecordLookup. See internal/dht/lookup.go for the canonical
// TLD-root → K_tld / else K_name routing rule.
