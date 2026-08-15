// lifecycle.go — the §8 ownership lifecycle subcommands:
//
//	transfer   §8.3 (lines 666-688) — re-point a name's authority to a new
//	           owner key. The hand-off record keeps the name, sets
//	           owner = new key, sequence = prev + 1, and prev_hash =
//	           H_record(previous signed envelope); per §8.3 line 677
//	           ("signature: by A7C91... (current owner key)") and lines
//	           680-681 ("The network accepts the new record because the
//	           previous owner — whose key the current authority chain
//	           names — signed it"), it is signed by the CURRENT (previous)
//	           owner key, not the transferee. After the transfer only the
//	           new key can sign further updates.
//	rotate     §8.6 (lines 714-720) — "Rotation = transfer to a fresh key
//	           (Section 8.3)": a thin variant of transfer with identical
//	           semantics (new owner = the fresh hygiene key, signer = the
//	           current owner).
//	recover    §8.4 (lines 689-707) — assemble the recovery-declaration
//	           evidence: threshold-many recovery keys (validated against the
//	           previous record's field-10 policy) sign
//	           wire.RecoverySigningMessage over (prev H_record, new primary
//	           pk, execute_not_before = now + timelock). -out writes the
//	           evidence CBOR; -out-envelope ADDITIONALLY writes the §8.4
//	           recovered record R2 (owner = the new key, sequence = prev+1,
//	           prev_hash = H(prev), signed by the NEW owner — the opposite
//	           signer convention of §8.3 transfer) for `publish -files
//	           <r2.cbor> -evidence <evidence.cbor>`.
//	verify-recovery §8.4 verifier side — check a RecoveryEvidence against
//	           the previous record's field-10 policy (pure wire calls, no
//	           network): quorum count, threshold, and timelock status,
//	           human-readable.
//
// The produced envelopes follow make-record's output conventions
// (envelope_cbor=<hex> plus wire_name/k_name lines) so they can be piped
// around, and -out additionally writes the raw .cbor file that
// `publish -files` consumes.
//
// Resolver interaction (documented, NOT changed here): wire.VerifyAuthorityChain
// requires the TLD-root signer == owner and tld_id == SHA-256(owner), so a
// transferred TLD record (owner = new key, signer = old key) does not verify
// under the current chain walker — accepting §8.3 hand-offs resolver-side
// (by following the prev_hash chain, which §8.3 line 682-684 provides for
// offline hand-off-history verification) is future work outside this scope.
// Sub-name transfers keep verifying against their unchanged parent record
// (the parent's owner/delegation still names the old child key that signed
// the hand-off), but descendants of a transferred name must re-sign with the
// new key once the delegation follows it.
package cli

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/securekey"
	"github.com/camalolo/freens/internal/wire"
)

// ---------------------------------------------------------------------------
// shared plumbing
// ---------------------------------------------------------------------------

// loadEnvelope reads and decodes a signed-envelope .cbor file — the same
// format publish consumes and the daemon's -load seeding produces.
func loadEnvelope(path string) (*wire.SignedEnvelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	env, err := wire.DecodeEnvelope(data)
	if err != nil {
		return nil, fmt.Errorf("decode envelope %q: %w", path, err)
	}
	return env, nil
}

// seedKeypair resolves a seed SPEC into a Keypair; flagName names the
// calling flag for error messages. A spec is either 64 hex characters or
// "@/path/to/keyfile" — a file containing the hex seed (as written by
// gen-key -out / register) or a passphrase-encrypted envelope (the
// FREENSK1 format; unlocked via prompt or FREENS_PASSPHRASE). The @file
// form keeps raw seeds off command lines (ps, shell history).
func seedKeypair(spec, flagName string) (*crypto.Keypair, error) {
	raw := spec
	if strings.HasPrefix(spec, "@") {
		b, err := os.ReadFile(strings.TrimPrefix(spec, "@"))
		if err != nil {
			return nil, usageErr("read %s keyfile %q: %v", flagName, spec, err)
		}
		if securekey.IsEncrypted(b) {
			pass, perr := passphraseForUnlock()
			if perr != nil {
				return nil, perr
			}
			seed, derr := securekey.DecryptSeed(b, pass)
			if derr != nil {
				return nil, usageErr("unlock %s keyfile: %v", flagName, derr)
			}
			kp, kerr := crypto.FromSeed(seed)
			if kerr != nil {
				return nil, usageErr("%s: %v", flagName, kerr)
			}
			return kp, nil
		}
		raw = strings.TrimSpace(string(b))
	}
	seed, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, usageErr("invalid %s hex: %v", flagName, err)
	}
	kp, err := crypto.FromSeed(seed)
	if err != nil {
		return nil, usageErr("%s: %v", flagName, err)
	}
	return kp, nil
}

// handoffFlags is the shared flag set of transfer (§8.3) and rotate (§8.6):
// both build a "transfer to a fresh key" record over a previous envelope.
type handoffFlags struct {
	prevPath    string
	newSeedHex  string
	signerHex   string
	ip          string
	expiresStr  string
	ttl         uint64
	out         string
	subcommand  string
	newSeedFlag string // "-new-owner-seed" (transfer) / "-new-seed" (rotate)
}

// parseHandoffFlags builds the shared flag set under subcommand's name.
func parseHandoffFlags(subcommand, newSeedFlag string, args []string) (*handoffFlags, error) {
	fs := flag.NewFlagSet(subcommand, flag.ContinueOnError)
	hf := &handoffFlags{
		subcommand:  subcommand,
		newSeedFlag: newSeedFlag,
	}
	fs.StringVar(&hf.prevPath, "prev-envelope", "", "path to the previous signed envelope .cbor (the record whose name is being handed off)")
	fs.StringVar(&hf.newSeedHex, strings.TrimPrefix(newSeedFlag, "-"), "", "hex Ed25519 seed of the fresh key that will own the name after the hand-off")
	fs.StringVar(&hf.signerHex, "signer-seed", "", "hex Ed25519 seed of the CURRENT owner key — §8.3: the hand-off is signed by the previous owner")
	fs.StringVar(&hf.ip, "ip", "", "optional IPv4 for a replacement A record (omit to carry over the previous RRset)")
	fs.StringVar(&hf.expiresStr, "expires", "", "expires unix timestamp (default: now+"+strconv.Itoa(constants.RecordDefaultTTL)+"s)")
	fs.Uint64Var(&hf.ttl, "ttl", 300, "A record TTL in seconds (only used with -ip)")
	fs.StringVar(&hf.out, "out", "", "write the new envelope's canonical CBOR to this .cbor path (for publish -files)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if len(fs.Args()) != 0 {
		return nil, usageErr("%s takes no positional arguments", subcommand)
	}
	if hf.prevPath == "" || hf.newSeedHex == "" || hf.signerHex == "" {
		return nil, usageErr("%s requires -prev-envelope, %s and -signer-seed", subcommand, newSeedFlag)
	}
	return hf, nil
}

// runHandoff implements §8.3's transfer (and §8.6's rotation, which the spec
// defines as "transfer to a fresh key"): build the hand-off envelope, print
// make-record-style output lines, and optionally write the .cbor file.
func runHandoff(hf *handoffFlags) error {
	prev, err := loadEnvelope(hf.prevPath)
	if err != nil {
		return err
	}
	newKP, err := seedKeypair(hf.newSeedHex, hf.newSeedFlag)
	if err != nil {
		return err
	}
	signerKP, err := seedKeypair(hf.signerHex, "-signer-seed")
	if err != nil {
		return err
	}
	env, err := buildHandoffEnvelope(prev, newKP.Public(), signerKP, hf.ip, hf.expiresStr, hf.ttl)
	if err != nil {
		return err
	}
	envBytes, err := env.Bytes()
	if err != nil {
		return err
	}

	r := env.Record
	fmt.Printf("envelope_cbor=%s\n", hex.EncodeToString(envBytes))
	fmt.Printf("wire_name=%s\n", hex.EncodeToString(r.Name))
	if labels, tldID, derr := naming.DecodeWireName(r.Name); derr == nil && len(labels) == 0 {
		k, kerr := naming.DHTKeyTld(tldID)
		if kerr != nil {
			return kerr
		}
		fmt.Printf("k_tld=%s\n", hex.EncodeToString(k))
	} else {
		fmt.Printf("k_name=%s\n", hex.EncodeToString(naming.DHTKeyName(r.Name)))
	}
	fmt.Printf("handoff=%s\n", hf.subcommand)
	fmt.Printf("name_summary=%s\n", nameSummary(r.Name))
	fmt.Printf("new_owner=%s\n", hex.EncodeToString(r.Owner))
	fmt.Printf("signer=%s (previous owner, spec 8.3)\n", hex.EncodeToString(env.Signer))
	fmt.Printf("sequence=%d\n", r.Sequence)
	if ph, herr := prev.RecordHash(); herr == nil {
		fmt.Printf("prev_hash=%s\n", hex.EncodeToString(ph))
	}
	fmt.Printf("rrset=%d\n", len(r.RRset))
	if hf.out != "" {
		if err := os.WriteFile(hf.out, envBytes, 0o644); err != nil {
			return fmt.Errorf("write %q: %w", hf.out, err)
		}
		fmt.Printf("wrote=%s\n", hf.out)
	}
	return nil
}

// buildHandoffEnvelope builds the §8.3 transfer record from prev:
//
//   - Name: carried over verbatim (the name — and therefore K_name/K_tld —
//     is unchanged; only the authority re-points).
//   - Owner: newOwnerPK ("owner: B82F1... (new owner key)").
//   - Sequence: prev.Sequence + 1 ("sequence: prev + 1").
//   - PrevHash: H_record(previous signed envelope) (§4.2; "prev_hash:
//     H_record(previous signed envelope)"), so wire.VerifyChainLink(new,
//     prev) holds and the DHT store's §4.4-rule-4 path accepts the newcomer
//     over the alive incumbent.
//   - Created/Expires: fresh window (now..now+RecordDefaultTTL, or -expires).
//   - RRset: carried over unless ip is given, in which case a single A
//     record replaces it ("optionally in the same record as a normal
//     update", §8.6).
//   - Delegation: when the previous record's subtree authority followed the
//     previous owner (delegation empty or equal to the previous owner — the
//     §8.3 example's "delegation: B82F1... (subtree authority follows)"),
//     it is re-pointed at the new owner; a third-party delegation survives
//     the hand-off unchanged.
//   - Recovery policy and embedded alias claim: carried over (§8.3: "For a
//     whole-TLD transfer, the same operation on the TLD record transfers the
//     alias and all undelegated names at once" — the claim anchors the
//     alias). Revoke is NOT carried: a hand-off at a higher sequence
//     un-revokes per §8.5.
//
// Per §8.3 line 677 the envelope is signed by signerKP, which MUST be the
// current owner's key ("signature: by A7C91... (current owner key)");
// lines 680-681: "The network accepts the new record because the previous
// owner — whose key the current authority chain names — signed it."
func buildHandoffEnvelope(prev *wire.SignedEnvelope, newOwnerPK []byte, signerKP *crypto.Keypair, ip, expiresStr string, ttl uint64) (*wire.SignedEnvelope, error) {
	if prev == nil || prev.Record == nil {
		return nil, cryptoErr("previous envelope has no record")
	}
	if !bytes.Equal(signerKP.Public(), prev.Record.Owner) {
		return nil, cryptoErr(
			"spec 8.3: the hand-off must be signed by the CURRENT owner %s, got %s",
			hex.EncodeToString(prev.Record.Owner), hex.EncodeToString(signerKP.Public()))
	}
	now := uint64(time.Now().Unix())
	expires := now + uint64(constants.RecordDefaultTTL)
	if expiresStr != "" {
		e, err := strconv.ParseUint(expiresStr, 10, 64)
		if err != nil {
			return nil, usageErr("invalid -expires: %v", err)
		}
		expires = e
	}
	prevHash, err := prev.RecordHash()
	if err != nil {
		return nil, err
	}
	rec, err := wire.NewRecord(prev.Record.Name, newOwnerPK, prev.Record.Sequence+1, now, expires)
	if err != nil {
		return nil, err
	}
	rec.PrevHash = prevHash
	if ip != "" {
		ip4 := net.ParseIP(ip).To4()
		if ip4 == nil {
			return nil, usageErr("invalid IPv4 address %q", ip)
		}
		aRR, err := wire.A(ip4, ttl)
		if err != nil {
			return nil, err
		}
		rec.RRset = []*wire.RR{aRR}
	} else if len(prev.Record.RRset) > 0 {
		rec.RRset = append([]*wire.RR(nil), prev.Record.RRset...)
	}
	if len(prev.Record.Delegation) == 0 || bytes.Equal(prev.Record.Delegation, prev.Record.Owner) {
		// Subtree authority follows the hand-off (§8.3 example).
		rec.Delegation = append([]byte(nil), newOwnerPK...)
	} else {
		rec.Delegation = append([]byte(nil), prev.Record.Delegation...)
	}
	rec.Recovery = prev.Record.Recovery
	rec.Claim = prev.Record.Claim
	return wire.SignRecord(rec, signerKP)
}

// ---------------------------------------------------------------------------
// transfer — §8.3
// ---------------------------------------------------------------------------

// cmdTransfer implements `transfer`: build the §8.3 hand-off
// envelope from -prev-envelope, signed by the current owner (-signer-seed),
// re-pointing the name to -new-owner-seed's public key.
func cmdTransfer(args []string) error {
	hf, err := parseHandoffFlags("transfer", "-new-owner-seed", args)
	if err != nil {
		return err
	}
	return runHandoff(hf)
}

// ---------------------------------------------------------------------------
// rotate — §8.6
// ---------------------------------------------------------------------------

// cmdRotate implements `rotate`. §8.6 (lines 714-720): "Rotation =
// transfer to a fresh key (Section 8.3), optionally in the same record as a
// normal update." — rotation is exactly transfer semantics with the fresh
// hygiene key as the new owner, so this is a thin variant of cmdTransfer
// (shared builder; only the flag spelling differs).
func cmdRotate(args []string) error {
	hf, err := parseHandoffFlags("rotate", "-new-seed", args)
	if err != nil {
		return err
	}
	return runHandoff(hf)
}

// ---------------------------------------------------------------------------
// recover — §8.4 evidence assembly
// ---------------------------------------------------------------------------

// cmdRecover implements `recover`: read the previous record's
// field-10 recovery policy, sign wire.RecoverySigningMessage(prev H_record,
// new owner pk, execute_not_before = now + timelock) with each -recovery-seeds
// key (validated to be a subset of the policy's keys), and write the
// RecoveryEvidence CBOR to -out. With -out-envelope it ADDITIONALLY writes the
// §8.4 recovered record R2 — the make-record-style signed envelope that, once
// the timelock elapses and the evidence is published alongside it, re-points
// the name at the new primary key. The recovery POLICY is carried over
// unchanged (see buildRecoveryEnvelope); operators SHOULD follow up with
// `rotate` after regaining control to rotate the recovery keys
// (§8.4 step 2: "SHOULD also rotate the recovery keys — this defeats a single
// stolen recovery key").
func cmdRecover(args []string) error {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	prevPath := fs.String("prev-envelope", "", "path to the previous signed envelope .cbor (whose field-10 recovery policy is used)")
	newOwnerSeedHex := fs.String("new-owner-seed", "", "hex Ed25519 seed of the fresh primary key that will own the name after recovery")
	recoverySeedsCSV := fs.String("recovery-seeds", "", "comma-separated hex seeds of the recovery keys (must be a subset of the policy's field-10 keys)")
	out := fs.String("out", "", "path to write the RecoveryEvidence CBOR")
	outEnvelope := fs.String("out-envelope", "", "additionally write the spec 8.4 recovered record R2 as a signed envelope .cbor here "+
		"(owner = the NEW key, sequence = prev+1, prev_hash = H(prev), signed by the NEW owner — the opposite of transfer). "+
		"The recovery policy is carried over unchanged; after regaining control, follow up with `rotate` to rotate the recovery keys (spec 8.4 step 2)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("recover takes no positional arguments")
	}
	if *prevPath == "" || *newOwnerSeedHex == "" || *recoverySeedsCSV == "" || *out == "" {
		return usageErr("recover requires -prev-envelope, -new-owner-seed, -recovery-seeds and -out")
	}

	prev, err := loadEnvelope(*prevPath)
	if err != nil {
		return err
	}
	policy := prev.Record.Recovery
	if policy == nil {
		return cryptoErr("%v — the name cannot be re-pointered (spec 8.4: losing the primary key with no recovery policy means the name cannot be re-pointered)", wire.ErrNoRecoveryPolicy)
	}
	newKP, err := seedKeypair(*newOwnerSeedHex, "-new-owner-seed")
	if err != nil {
		return err
	}

	// Each recovery seed must correspond to a key in the policy, and no key
	// may be counted twice.
	seen := make(map[string]bool)
	var signers []*crypto.Keypair
	for i, seedHex := range strings.Split(*recoverySeedsCSV, ",") {
		if seedHex = strings.TrimSpace(seedHex); seedHex == "" {
			continue
		}
		kp, err := seedKeypair(seedHex, fmt.Sprintf("-recovery-seeds[%d]", i))
		if err != nil {
			return err
		}
		if seen[string(kp.Public())] {
			return usageErr("duplicate recovery seed %d — a key signs the declaration once", i)
		}
		inPolicy := false
		for _, k := range policy.Keys {
			if bytes.Equal(k, kp.Public()) {
				inPolicy = true
				break
			}
		}
		if !inPolicy {
			return cryptoErr("recovery seed %d yields key %s which is NOT one of the policy's %d keys (spec 8.4: any threshold-of-keys sign the declaration)",
				i, hex.EncodeToString(kp.Public()), len(policy.Keys))
		}
		seen[string(kp.Public())] = true
		signers = append(signers, kp)
	}

	prevHash, err := prev.RecordHash()
	if err != nil {
		return err
	}
	now := uint64(time.Now().Unix())
	// §8.4 line 694: execute_not_before = now + timelock.
	notBefore := now + policy.Timelock
	msg, err := wire.RecoverySigningMessage(prevHash, newKP.Public(), notBefore)
	if err != nil {
		return err
	}
	sigs := make([][]byte, 0, len(signers))
	for _, kp := range signers {
		sigs = append(sigs, kp.Sign(msg))
	}
	ev := &wire.RecoveryEvidence{
		NewOwnerPK: newKP.Public(),
		Signatures: sigs,
		NotBefore:  notBefore,
	}
	// Self-check: with the assembled quorum the evidence must already verify
	// once the timelock elapses (or, if fewer than threshold keys signed,
	// provably not — warn, the caller may still be gathering signatures).
	// The same check covers the optional R2 envelope below: it pairs R2 with
	// exactly this evidence, so verifying the evidence at now=NotBefore is
	// verifying the envelope's acceptance precondition (§8.4 step 3).
	if ok := wire.VerifyRecovery(policy, ev, prevHash, notBefore); !ok && len(sigs) >= int(policy.Threshold) {
		return cryptoErr("assembled recovery evidence failed self-verification")
	}
	evBytes, err := ev.Bytes()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, evBytes, 0o644); err != nil {
		return fmt.Errorf("write %q: %w", *out, err)
	}

	// Optional §8.4 recovered record R2 (the envelope `publish -files
	// <r2.cbor> -evidence <evidence.cbor>` pushes once the timelock elapses).
	var r2 *wire.SignedEnvelope
	if *outEnvelope != "" {
		r2, err = buildRecoveryEnvelope(prev, newKP, now)
		if err != nil {
			return err
		}
	}

	fmt.Printf("evidence_file=%s\n", *out)
	fmt.Printf("prev_hash=%s\n", hex.EncodeToString(prevHash))
	fmt.Printf("new_owner=%s\n", hex.EncodeToString(newKP.Public()))
	fmt.Printf("threshold=%d of %d policy keys\n", policy.Threshold, len(policy.Keys))
	fmt.Printf("signed=%d\n", len(sigs))
	fmt.Printf("timelock=%d seconds (spec 8.4 default 72 h)\n", policy.Timelock)
	fmt.Printf("execute_not_before=%d (%s)\n", notBefore, time.Unix(int64(notBefore), 0).UTC().Format(time.RFC3339))
	if len(sigs) < int(policy.Threshold) {
		fmt.Fprintf(os.Stderr, "%s: warning: %d of %d required signatures gathered — the declaration does not verify until the threshold is reached\n", ProgName, len(sigs), policy.Threshold)
	}
	if r2 != nil {
		r2Bytes, err := r2.Bytes()
		if err != nil {
			return err
		}
		if err := os.WriteFile(*outEnvelope, r2Bytes, 0o644); err != nil {
			return fmt.Errorf("write %q: %w", *outEnvelope, err)
		}
		r := r2.Record
		fmt.Printf("envelope_file=%s\n", *outEnvelope)
		fmt.Printf("envelope_cbor=%s\n", hex.EncodeToString(r2Bytes))
		fmt.Printf("wire_name=%s\n", hex.EncodeToString(r.Name))
		if labels, tldID, derr := naming.DecodeWireName(r.Name); derr == nil && len(labels) == 0 {
			k, kerr := naming.DHTKeyTld(tldID)
			if kerr != nil {
				return kerr
			}
			fmt.Printf("k_tld=%s\n", hex.EncodeToString(k))
		} else {
			fmt.Printf("k_name=%s\n", hex.EncodeToString(naming.DHTKeyName(r.Name)))
		}
		fmt.Printf("name_summary=%s\n", nameSummary(r.Name))
		fmt.Printf("recovered_owner=%s\n", hex.EncodeToString(r.Owner))
		fmt.Printf("signer=%s (NEW owner, spec 8.4 — the opposite of transfer)\n", hex.EncodeToString(r2.Signer))
		fmt.Printf("sequence=%d\n", r.Sequence)
		fmt.Printf("created=%d\n", r.Created)
		fmt.Printf("expires=%d (%d seconds remaining, min %d)\n", r.Expires, int64(r.Expires)-int64(now), constants.ResponseTTLCap)
		fmt.Printf("rrset=%d\n", len(r.RRset))
		fmt.Printf("recovery_policy=carried over unchanged (threshold %d of %d)\n", r.Recovery.Threshold, len(r.Recovery.Keys))
		fmt.Printf("wrote=%s\n", *outEnvelope)
	}
	fmt.Printf("note: publish the recovered record after the timelock with `publish -files <r2.cbor> -evidence %s`; rotate the recovery keys afterwards (spec 8.4 step 2: `rotate`)\n", *out)
	return nil
}

// buildRecoveryEnvelope builds the §8.4 recovered record R2 from prev (R1).
// The declaration itself (the quorum's proof) lives in the RecoveryEvidence;
// R2 is the record that, published WITH that evidence once the timelock
// elapses, re-points the name:
//
//   - Name: carried over verbatim (K_name/K_tld unchanged).
//   - Owner: the NEW primary key (§8.4 "the new primary key owns the name").
//   - Sequence: prev.Sequence + 1 (§8.4 "published like any record
//     (sequence +1 ...)").
//   - Created/Expires: fresh window — now .. now + (R1's remaining lifetime,
//     floored at constants.ResponseTTLCap = 3600 s so a nearly-expired or
//     already-expired R1 still yields a usable R2).
//   - PrevHash: H_record(R1) (§4.2), chaining R2 to the recovered record the
//     evidence's signatures name.
//   - RRset: carried over; an RR without a TTL (0) defaults to 3600.
//   - Delegation: like a §8.3 hand-off, subtree authority that followed the
//     previous owner (empty or == prev owner) is re-pointed at the new
//     owner; a third-party delegation survives unchanged.
//   - Recovery policy: carried over UNCHANGED (§8.4 step 1's "recovery
//     fields updated" is the operator's follow-up decision, not the
//     recovery's: rotating recovery keys requires the regained control this
//     record establishes — §8.4 step 2 says the owner SHOULD rotate them
//     right after, i.e. `rotate` / make-record -recovery-*).
//   - Claim: carried over (a TLD-root recovery keeps the alias anchored).
//     Revoke is NOT carried: a higher-sequence record un-revokes (§8.5).
//
// Signer convention — the OPPOSITE of §8.3 transfer: the NEW owner key signs
// R2. In a transfer the previous owner is available and proves consent by
// signing; in a recovery the previous key is BY DEFINITION unavailable, so
// the quorum's evidence (verified against R1's policy and H_record) is the
// consent proof, and the new key signs the record it will own.
func buildRecoveryEnvelope(prev *wire.SignedEnvelope, newKP *crypto.Keypair, now uint64) (*wire.SignedEnvelope, error) {
	if prev == nil || prev.Record == nil {
		return nil, cryptoErr("previous envelope has no record")
	}
	if prev.Record.Recovery == nil {
		return nil, cryptoErr("%v — there is no policy to carry over into the recovered record", wire.ErrNoRecoveryPolicy)
	}
	prevHash, err := prev.RecordHash()
	if err != nil {
		return nil, err
	}
	// Fresh validity window: carry over R1's remaining lifetime, floored at
	// one hour (constants.ResponseTTLCap) so R2 is always usable.
	remaining := int64(prev.Record.Expires) - int64(now)
	if remaining < int64(constants.ResponseTTLCap) {
		remaining = int64(constants.ResponseTTLCap)
	}
	rec, err := wire.NewRecord(prev.Record.Name, newKP.Public(), prev.Record.Sequence+1, now, uint64(int64(now)+remaining))
	if err != nil {
		return nil, err
	}
	rec.PrevHash = prevHash
	if len(prev.Record.RRset) > 0 {
		rec.RRset = make([]*wire.RR, len(prev.Record.RRset))
		for i, rr := range prev.Record.RRset {
			cp := *rr
			if cp.TTL == 0 {
				cp.TTL = constants.ResponseTTLCap // "TTLs (default 3600 if absent)"
			}
			rec.RRset[i] = &cp
		}
	}
	if len(prev.Record.Delegation) == 0 || bytes.Equal(prev.Record.Delegation, prev.Record.Owner) {
		// Subtree authority follows the new primary (§8.3-style).
		rec.Delegation = append([]byte(nil), newKP.Public()...)
	} else {
		rec.Delegation = append([]byte(nil), prev.Record.Delegation...)
	}
	rec.Recovery = prev.Record.Recovery
	rec.Claim = prev.Record.Claim
	env, err := wire.SignRecord(rec, newKP) // §8.4: the NEW owner signs
	if err != nil {
		return nil, err
	}
	if !env.VerifySignature() {
		return nil, cryptoErr("recovered record R2 failed its signature self-check")
	}
	return env, nil
}

// ---------------------------------------------------------------------------
// verify-recovery — §8.4 verifier side (pure wire calls, no network)
// ---------------------------------------------------------------------------

// cmdVerifyRecovery implements `verify-recovery`: decode the
// previous record and a RecoveryEvidence, and report whether the declaration
// satisfies R1's field-10 policy at -now (default: the current time) — the
// same predicate wire.VerifyRecovery applies on the acceptance side, plus a
// human-readable quorum/threshold/timelock breakdown. A failing verification
// is a validation failure (exit code 2), not a usage error.
func cmdVerifyRecovery(args []string) error {
	fs := flag.NewFlagSet("verify-recovery", flag.ContinueOnError)
	prevPath := fs.String("prev-envelope", "", "path to the previous signed envelope .cbor (whose field-10 recovery policy and H_record anchor the declaration)")
	evidencePath := fs.String("evidence", "", "path to the RecoveryEvidence CBOR (recover -out)")
	nowFlag := fs.Int64("now", 0, "verification instant as unix seconds (default: now; spec 8.4 step 3 needs now >= execute_not_before)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("verify-recovery takes no positional arguments")
	}
	if *prevPath == "" || *evidencePath == "" {
		return usageErr("verify-recovery requires -prev-envelope and -evidence")
	}
	prev, err := loadEnvelope(*prevPath)
	if err != nil {
		return err
	}
	policy := prev.Record.Recovery
	if policy == nil {
		return cryptoErr("%v — the previous record names no recovery quorum", wire.ErrNoRecoveryPolicy)
	}
	evData, err := os.ReadFile(*evidencePath)
	if err != nil {
		return fmt.Errorf("read %q: %w", *evidencePath, err)
	}
	ev, err := wire.DecodeRecoveryEvidence(evData)
	if err != nil {
		return fmt.Errorf("decode evidence %q: %w", *evidencePath, err)
	}
	prevHash, err := prev.RecordHash()
	if err != nil {
		return err
	}
	now := uint64(time.Now().Unix())
	if *nowFlag != 0 {
		now = uint64(*nowFlag)
	}

	quorum := countRecoveryQuorum(policy, ev, prevHash)
	notBefore := time.Unix(int64(ev.NotBefore), 0).UTC().Format(time.RFC3339)
	nowStr := time.Unix(int64(now), 0).UTC().Format(time.RFC3339)

	fmt.Printf("prev_hash=%s\n", hex.EncodeToString(prevHash))
	fmt.Printf("new_owner=%s\n", hex.EncodeToString(ev.NewOwnerPK))
	fmt.Printf("quorum=%d\n", quorum)
	fmt.Printf("threshold=%d\n", policy.Threshold)
	fmt.Printf("keys=%d\n", len(policy.Keys))
	fmt.Printf("timelock_expires=%s (unix %d)\n", notBefore, ev.NotBefore)
	fmt.Printf("now=%s (unix %d)\n", nowStr, now)

	switch {
	case quorum < int(policy.Threshold):
		return cryptoErr("status=quorum %d/%d BELOW THRESHOLD — only %d of the required %d distinct policy keys produced valid signatures",
			quorum, len(policy.Keys), quorum, policy.Threshold)
	case now < ev.NotBefore:
		return cryptoErr("status=quorum %d/%d OK, timelock not elapsed — executable at %s (%d s remaining, spec 8.4 step 3)",
			quorum, len(policy.Keys), notBefore, int64(ev.NotBefore)-int64(now))
	default:
		fmt.Printf("status=quorum %d/%d OK, timelock expires %s\n", quorum, len(policy.Keys), notBefore)
		return nil
	}
}

// countRecoveryQuorum returns the number of DISTINCT policy keys that each
// produced a valid signature over the §8.4 message — the same counting rule
// wire.VerifyRecovery applies internally (duplicated here because the wire
// API exposes only the boolean verdict, and verify-recovery wants the count
// for its human-readable report).
func countRecoveryQuorum(policy *wire.RecoveryPolicyWire, ev *wire.RecoveryEvidence, prevHash []byte) int {
	if policy == nil || ev == nil {
		return 0
	}
	msg, err := wire.RecoverySigningMessage(prevHash, ev.NewOwnerPK, ev.NotBefore)
	if err != nil {
		return 0
	}
	verified := 0
	seen := make(map[string]bool, len(policy.Keys))
	for _, k := range policy.Keys {
		if len(k) != constants.Ed25519PublicKeyLen || seen[string(k)] {
			continue
		}
		for _, sig := range ev.Signatures {
			if crypto.Verify(k, sig, msg) {
				seen[string(k)] = true
				verified++
				break
			}
		}
	}
	return verified
}
