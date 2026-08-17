// ops.go — the web UI's mutation engine: the same daemon-mode flows the
// CLI runs (register / name / renew / revoke), as library functions over
// the Daemon interface and the keychain, with structured progress reporting
// for the async register job. The CLI remains the reference
// implementation; these are its shapes, minus flags and terminal prompts.
package webui

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/keychain"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
	"github.com/fxamacker/cbor/v2"
)

// opsKeychain bundles where keys live for the operations (the freens home's
// keys dir; configurable for tests).
type opsEnv struct {
	keysDir string
	d       Daemon
}

// RegisterInput is the register form.
type RegisterInput struct {
	Alias      string
	IP         string // IPv4 dotted quad or IPv6 literal ("" = outbound default)
	TTL        uint64 // A/AAAA TTL seconds (0 = 300)
	NoRecovery bool   // skip the default-on 3-of-2 recovery policy
	Passphrase string // REQUIRED in the web UI: keys are always encrypted at rest
}

// RegisterResult reports what a successful register did.
type RegisterResult struct {
	Alias       string
	TldIDB32    string
	Sequence    uint64
	IP          string
	Witnesses   int
	ClaimReused bool
	KeyPath     string
	RecPaths    []string
}

// registerError carries a user-facing message (safe to render raw).
type registerError struct{ msg string }

func (e *registerError) Error() string { return e.msg }

func userErr(format string, a ...any) error {
	return &registerError{msg: fmt.Sprintf(format, a...)}
}

// Register runs the full §7.4/C.1 flow: load-or-generate the owner key,
// load-or-mine the claim (reusing the parked one on retries), collect W
// witnesses via the daemon, sign the TLD record with the embedded claim +
// recovery policy, and publish at K_tld AND K_claim. progress (may be nil)
// receives human-readable step updates for the job page.
func (e *opsEnv) Register(ctx context.Context, in RegisterInput, progress func(string)) (RegisterResult, error) {
	tell := func(format string, a ...any) {
		if progress != nil {
			progress(fmt.Sprintf(format, a...))
		}
	}
	// The web UI never writes unencrypted keyfiles. An empty passphrase
	// used to fall through to keychain.Save's plaintext mode (the CLI's
	// default) and silently leave raw secret keys on disk — audit F3 —
	// so it is rejected FIRST, before any key is generated, parked, or
	// written (the form sends a single passphrase field, so emptiness is
	// the only mismatch possible).
	if strings.TrimSpace(in.Passphrase) == "" {
		return RegisterResult{}, userErr("a passphrase is required — the web UI does not write unencrypted keyfiles")
	}
	alias, err := naming.ValidateAlias(in.Alias)
	if err != nil {
		return RegisterResult{}, userErr("invalid alias: %v", err)
	}
	ip := strings.TrimSpace(in.IP)
	if ip == "" {
		ip, err = outboundIPv4()
		if err != nil {
			return RegisterResult{}, userErr("could not determine this machine's address — set one explicitly")
		}
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = 300
	}

	// Difficulty: the daemon's oracle (baseline floor inside MineAliasClaim
	// semantics; the CLI passes the same value).
	diff := constants.PoWDifficultyInit
	if d, err := e.d.Difficulty(ctx); err == nil && d.Difficulty > diff {
		diff = d.Difficulty
	}

	// Owner key: reuse the parked one for cooldown-safe retries.
	keyPath := keychain.OwnerKeyPath(e.keysDir, alias)
	kp, err := keychain.Load(keyPath, in.Passphrase)
	var keyEnc bool
	switch {
	case err == nil:
		tell("reusing the existing owner key for %s", alias)
	case errors.Is(err, keychain.ErrNeedsPassphrase), errors.Is(err, keychain.ErrWrongPassphrase):
		return RegisterResult{}, userErr("the owner key for %s is passphrase-encrypted — supply its passphrase", alias)
	default:
		kp, err = crypto.Generate()
		if err != nil {
			return RegisterResult{}, err
		}
		if err := keychain.Save(keyPath, kp, in.Passphrase); err != nil {
			return RegisterResult{}, userErr("writing the owner key: %v", err)
		}
		keyEnc = in.Passphrase != ""
	}
	_ = keyEnc
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		return RegisterResult{}, err
	}
	pin := tldB32Display(tldID)

	// Recovery plan (default on), reusing nothing (a re-register of the
	// same alias keeps its existing recovery files — regenerating would
	// strand the old policy's keys; matching the CLI, which only generates
	// when the owner key is fresh is NOT its behavior — it always
	// overwrites; we keep parity and regenerate only on fresh keys to avoid
	// surprising an existing owner. Documented divergence, see docs.md).
	var recPaths []string
	var recPol *wire.RecoveryPolicyWire
	if !in.NoRecovery {
		recPaths, recPol, err = keychain.RecoveryPlan(false, e.keysDir, alias, in.Passphrase,
			3, 2, constants.RecoveryTimelock)
		if err != nil {
			return RegisterResult{}, userErr("generating recovery keys: %v", err)
		}
	}

	// Claim: parked first (cooldown-safe retries), else mine. A parked
	// claim older than WITNESS_COOLDOWN is un-witnessable (the §6.3 gate)
	// and is discarded — re-mine rather than dead-loop refusals.
	now := time.Now().Unix()
	claim := keychain.LoadReusableClaim(e.keysDir, alias, kp, diff)
	if claim != nil && now-int64(claim.Timestamp) >= int64(constants.WitnessCooldown) {
		claim = nil // stale: older than any witness will sign
	}
	reused := claim != nil
	if !reused {
		tell("mining the claim (difficulty %d)…", diff)
		claim, err = claims.MineAliasClaim(alias, kp, uint64(now), diff, 500_000_000, 16)
		if err != nil {
			return RegisterResult{}, userErr("PoW mining failed: %v", err)
		}
		keychain.SaveReusableClaim(e.keysDir, alias, claim)
	} else {
		tell("reusing the parked claim for %s", alias)
	}

	// Witnesses via the daemon (the §7.3 cooldown-safe retry loop; the
	// claim.Timestamp stays fixed across retries).
	tell("collecting %d witness signatures…", constants.W)
	atts, err := e.collectWitnesses(ctx, alias, tldID, kp.Public(), claim.Timestamp, claim.Nonce, claim.PowHash)
	if err != nil {
		return RegisterResult{}, err
	}
	if len(atts) < constants.W {
		return RegisterResult{}, userErr("only %d of %d witnesses responded — the network is too small from this vantage point; retry in a minute (the claim is reused, nothing is lost)", len(atts), constants.W)
	}
	claim.Witnesses = atts[:constants.W]
	if !claims.VerifyFull(claim, claims.InferDifficulty, nil, constants.W) {
		return RegisterResult{}, userErr("assembled claim failed verification")
	}
	tell("witnesses: %d distinct nodes co-signed", len(claim.Witnesses))

	// Sequence: the network's current + 1 (tombstones included — see
	// currentSequence; retries/revocations must out-sequence, §6.4).
	seq := uint64(1)
	if wn, werr := naming.EncodeWireName(nil, alias, tldID); werr == nil {
		seq = e.currentSequence(wn)
	}

	// Build + sign the TLD record.
	wireName, err := naming.EncodeWireName(nil, alias, tldID)
	if err != nil {
		return RegisterResult{}, err
	}
	ipRR, err := addrRR(ip, ttl)
	if err != nil {
		return RegisterResult{}, userErr("invalid IP %q", ip)
	}
	rec, err := wire.NewRecord(wireName, kp.Public(), seq, uint64(now), uint64(now)+86400)
	if err != nil {
		return RegisterResult{}, err
	}
	rec.RRset = []*wire.RR{ipRR}
	rec.Recovery = recPol
	cb, err := claim.CanonicalBytes()
	if err != nil {
		return RegisterResult{}, err
	}
	rec.Claim = cbor.RawMessage(cb)
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		return RegisterResult{}, err
	}

	// Publish at BOTH keys (§7.4/C.1).
	tell("publishing (K_tld + K_claim)…")
	if _, err := e.d.Publish(ctx, env); err != nil {
		return RegisterResult{}, userErr("publish (K_tld): %v", err)
	}
	if err := e.d.PublishClaim(ctx, env); err != nil {
		return RegisterResult{}, userErr("publish (K_claim): %v", err)
	}
	return RegisterResult{
		Alias: alias, TldIDB32: pin, Sequence: seq, IP: ip,
		Witnesses: len(claim.Witnesses), ClaimReused: reused,
		KeyPath: keyPath, RecPaths: recPaths,
	}, nil
}

// collectWitnesses is the daemon-mode §7.3 loop: ask the daemon's node to
// co-sign, keep the best haul across 3 attempts (10 s apart — the CLI's
// cold-table self-heal), verify + dedupe each haul. The mined PoW pair rides
// along: witnesses verify the PoW before signing (§7.3).
func (e *opsEnv) collectWitnesses(ctx context.Context, alias string, tldID, claimantPK []byte, ts uint64, nonce, powHash []byte) ([]*claims.WitnessAttestation, error) {
	// The v2 attestations bind the claim prefix hash; recompute it so
	// verification is local, not trusted from the daemon.
	prefixHash, perr := (&claims.AliasClaim{
		Alias: alias, TldID: tldID, Timestamp: ts, ClaimantPK: claimantPK,
	}).PrefixHash()
	if perr != nil {
		return nil, userErr("claim identity: %v", perr)
	}
	var best []*claims.WitnessAttestation
	for attempt := 1; attempt <= 3; attempt++ {
		raw, err := e.d.Witness(ctx, alias, tldID, claimantPK, ts, nonce, powHash)
		if err != nil {
			return nil, userErr("witness collection (daemon): %v", err)
		}
		seen := map[string]bool{}
		var atts []*claims.WitnessAttestation
		for _, b := range raw {
			w, derr := claims.DecodeWitnessAttestation(b)
			if derr != nil || !w.Verify(prefixHash) || seen[string(w.NodePK)] {
				continue
			}
			seen[string(w.NodePK)] = true
			atts = append(atts, w)
		}
		if len(atts) > len(best) {
			best = atts
		}
		if len(best) >= constants.W {
			return best, nil
		}
		if attempt < 3 {
			select {
			case <-time.After(10 * time.Second):
			case <-ctx.Done():
				return best, nil
			}
		}
	}
	return best, nil
}

// currentSequence returns the sequence the NEXT publication of wireName
// must carry (the network's current + 1, tombstones included — /resolve
// does NOT report a revoked name's sequence, so sequence discovery via
// Resolve after a revocation would reset to 1 and silently LOSE the §6.4
// winner race against the tombstone; found live by the webui ops tests,
// the same flaw the CLI's un-revoke path had).
func (e *opsEnv) currentSequence(wireName []byte) uint64 {
	key, err := dht.KeyForWireName(wireName)
	if err != nil {
		return 1
	}
	if env, gerr := e.d.Get(context.Background(), key); gerr == nil && env != nil && env.Record != nil {
		return env.Record.Sequence + 1
	}
	return 1
}

// SetName publishes <label>.<alias> (or the apex when label is empty) at
// sequence+1 with the given IP — `freens name`. Passphrase unlocks an
// encrypted owner key when needed.
func (e *opsEnv) SetName(ctx context.Context, displayName, ip string, ttl uint64, passphrase string) (seq uint64, err error) {
	labels, alias, err := naming.DecomposeName(displayName)
	if err != nil {
		return 0, userErr("invalid name: %v", err)
	}
	kp, err := e.loadOwner(alias, passphrase)
	if err != nil {
		return 0, err
	}
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		return 0, err
	}
	if ttl == 0 {
		ttl = 300
	}
	if strings.TrimSpace(ip) == "" {
		// Inherit the apex's current address (A first, AAAA fallback).
		if r, rerr := e.d.Resolve(ctx, alias); rerr == nil && r != nil {
			if v := firstIP(r.RRset); v != "" {
				ip = v
			}
		}
		if ip == "" {
			return 0, userErr("no address given and the apex has none to inherit")
		}
	}
	wireName, err := naming.EncodeWireName(labels, alias, tldID)
	if err != nil {
		return 0, err
	}
	seq = e.currentSequence(wireName)
	ipRR, err := addrRR(strings.TrimSpace(ip), ttl)
	if err != nil {
		return 0, userErr("invalid IP %q", ip)
	}
	now := uint64(time.Now().Unix())
	rec, err := wire.NewRecord(wireName, kp.Public(), seq, now, now+uint64(constants.RecordDefaultTTL))
	if err != nil {
		return 0, err
	}
	rec.RRset = []*wire.RR{ipRR}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		return 0, err
	}
	if _, err := e.d.Publish(ctx, env); err != nil {
		return 0, userErr("publish: %v", err)
	}
	return seq, nil
}

// Revoke publishes the §9.5 tombstone for displayName at sequence+1.
func (e *opsEnv) Revoke(ctx context.Context, displayName, passphrase string) (seq uint64, err error) {
	labels, alias, err := naming.DecomposeName(displayName)
	if err != nil {
		return 0, userErr("invalid name: %v", err)
	}
	kp, err := e.loadOwner(alias, passphrase)
	if err != nil {
		return 0, err
	}
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		return 0, err
	}
	wireName, err := naming.EncodeWireName(labels, alias, tldID)
	if err != nil {
		return 0, err
	}
	seq = e.currentSequence(wireName)
	now := uint64(time.Now().Unix())
	rec, err := wire.NewRecord(wireName, kp.Public(), seq, now, now+uint64(constants.RecordDefaultTTL))
	if err != nil {
		return 0, err
	}
	rec.RRset = nil
	rec.Revoke = boolPtr(true)
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		return 0, err
	}
	if _, err := e.d.Publish(ctx, env); err != nil {
		return 0, userErr("publish: %v", err)
	}
	return seq, nil
}

// Renew extends one name's lease at sequence+1 (the CLI's renewOne shape,
// daemon mode only). Force skips the freshness check.
func (e *opsEnv) Renew(ctx context.Context, displayName, passphrase string, force bool) (seq uint64, err error) {
	labels, alias, err := naming.DecomposeName(displayName)
	if err != nil {
		return 0, userErr("invalid name: %v", err)
	}
	kp, err := e.loadOwner(alias, passphrase)
	if err != nil {
		return 0, err
	}
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		return 0, err
	}
	wireName, err := naming.EncodeWireName(labels, alias, tldID)
	if err != nil {
		return 0, err
	}
	key, err := dht.KeyForWireName(wireName)
	if err != nil {
		return 0, err
	}
	prev, _ := e.d.Get(ctx, key)
	if prev == nil || prev.Record == nil {
		return 0, userErr("no live record on the network — nothing to renew")
	}
	if !force && !staleEnough(prev, time.Now().Unix()) {
		return 0, userErr("still comfortably fresh (renew anyway with the force option)")
	}
	now := uint64(time.Now().Unix())
	rec, err := wire.NewRecord(wireName, kp.Public(), prev.Record.Sequence+1, now, now+uint64(constants.RecordDefaultTTL))
	if err != nil {
		return 0, err
	}
	rec.RRset = prev.Record.RRset
	rec.Recovery = prev.Record.Recovery
	if len(prev.Record.Claim) > 0 {
		rec.Claim = prev.Record.Claim
	}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		return 0, err
	}
	if _, err := e.d.Publish(ctx, env); err != nil {
		return 0, userErr("publish: %v", err)
	}
	return rec.Sequence, nil
}

// staleEnough mirrors the CLI's renew freshness gate: renew when the lease
// has less than 25% left (the renewal package's rule).
func staleEnough(env *wire.SignedEnvelope, now int64) bool {
	r := env.Record
	remaining := int64(r.Expires) - now
	span := int64(r.Expires) - int64(r.Created)
	return span <= 0 || remaining*4 <= span
}

// loadOwner loads alias' owner key, mapping the keychain sentinels to
// user-facing messages.
func (e *opsEnv) loadOwner(alias, passphrase string) (*crypto.Keypair, error) {
	kp, err := keychain.Load(keychain.OwnerKeyPath(e.keysDir, alias), passphrase)
	switch {
	case errors.Is(err, keychain.ErrNotFound):
		return nil, userErr("no owner key for %s on this machine", alias)
	case errors.Is(err, keychain.ErrNeedsPassphrase):
		return nil, errEncryptedKey{alias: alias}
	case errors.Is(err, keychain.ErrWrongPassphrase):
		return nil, userErr("wrong passphrase for the %s owner key", alias)
	case err != nil:
		return nil, userErr("%v", err)
	}
	return kp, nil
}

// errEncryptedKey tells the handler to re-ask for the passphrase.
type errEncryptedKey struct{ alias string }

func (errEncryptedKey) Error() string { return "key is passphrase-encrypted" }

// ---------------------------------------------------------------------------
// small shared helpers
// ---------------------------------------------------------------------------

func tldB32Display(tldID []byte) string {
	return strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(tldID), "="))
}

// addrRR is the CLI's addrrr.addrRR (IPv4 → A, IPv6 literal → AAAA).
func addrRR(ipStr string, ttl uint64) (*wire.RR, error) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	switch {
	case ip == nil:
		return nil, fmt.Errorf("invalid IP address %q", ipStr)
	case ip.To4() != nil:
		return wire.A(ip.To4(), ttl)
	case strings.Contains(ipStr, ":"):
		return wire.AAAA(ip.To16(), ttl)
	default:
		return nil, fmt.Errorf("invalid IP address %q", ipStr)
	}
}

// firstIP renders the first A (or AAAA) rdata of an admin RRset.
func firstIP(rrs []admin.RR) string {
	v6 := ""
	for _, rr := range rrs {
		if rr.Type == wire.RRTypeA && rr.Text != "" {
			return rr.Text
		}
		if rr.Type == wire.RRTypeAAAA && rr.Text != "" && v6 == "" {
			v6 = rr.Text
		}
	}
	return v6
}

func boolPtr(b bool) *bool { return &b }

// outboundIPv4 discovers the machine's outbound IPv4 (no packet sent — the
// kernel picks a route; the CLI's trick).
func outboundIPv4() (string, error) {
	c, err := net.Dial("udp", "9.9.9.9:53")
	if err != nil {
		return "", err
	}
	defer c.Close()
	addr := c.LocalAddr().(*net.UDPAddr)
	return addr.IP.String(), nil
}

var (
	_ = base64.StdEncoding
	_ = bytes.Equal
	_ = sort.Strings
)

// ---------------------------------------------------------------------------
// naming / display helpers shared across files
// ---------------------------------------------------------------------------

// validAlias validates an alias via naming (returns the error or nil).
func validAlias(alias string) (string, error) {
	return naming.ValidateAlias(alias)
}

// validAliasOrDNSName accepts anything decomposable (freens name or an
// upstream DNS name — the lookup page forwards both to the daemon).
func validAliasOrDNSName(name string) (string, error) {
	_, _, err := naming.DecomposeName(name)
	return name, err
}

// tldIDOf derives a keypair's TLD ID.
func tldIDOf(kp *crypto.Keypair) ([]byte, error) {
	return crypto.TldID(kp.Public())
}

// buildBackup streams the keychain bundle (keychain.BuildBackup).
func buildBackup(w io.Writer, keysDir string) (int, error) {
	files, err := keychain.BuildBackup(w, keysDir)
	return len(files), err
}
