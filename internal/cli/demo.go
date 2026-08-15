// demo.go — the self-contained end-to-end showcase (moved verbatim from the
// freens-cli front-end): create → claim → delegate → publish → resolve, all
// in-process, no daemon or network required.
package cli

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"net"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/resolver"
	"github.com/camalolo/freens/internal/wire"
	"github.com/miekg/dns"
)

// cmdDemo is the headline demo. It lowers claims.PoWDifficultyInit to 8
// in-process so the showcase runs in well under a second.
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
