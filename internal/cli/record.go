// record.go — make-record (§4 record construction + signing) and the record
// builder shared with `name`/`register`, plus the pin/recovery-key decoding
// helpers. Moved from the freens-cli front-end; behavior is byte-compatible.
package cli

import (
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// ---------------------------------------------------------------------------
// the shared A-record builder (make-record + name + register)
// ---------------------------------------------------------------------------

// buildARecord builds the UNSIGNED §4.1 record for displayName (labels.alias,
// e.g. "www.alice.foo") carrying exactly one A RR. It is the shared core of
// make-record, name, and register: decompose + encode the wire name (§3.3)
// under the given tldID pin, NewRecord with a fresh created stamp and the
// given expiry window. Callers attach their extras (recovery policy, claim)
// and sign (wire.SignRecord). Returns the record plus the wire_name (callers
// print it and derive K_tld/K_name from it).
func buildARecord(displayName string, tldID, ownerPK []byte, ip4 net.IP, seq, ttl, expires uint64) (*wire.Record, []byte, error) {
	labels, alias, err := naming.DecomposeName(displayName)
	if err != nil {
		return nil, nil, usageErr("invalid name %q: %v", displayName, err)
	}
	wireName, err := naming.EncodeWireName(labels, alias, tldID)
	if err != nil {
		return nil, nil, err
	}
	now := uint64(time.Now().Unix())
	rec, err := wire.NewRecord(wireName, ownerPK, seq, now, expires)
	if err != nil {
		return nil, nil, err
	}
	aRR, err := wire.A(ip4, ttl)
	if err != nil {
		return nil, nil, err
	}
	rec.RRset = []*wire.RR{aRR}
	return rec, wireName, nil
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
	out := fs.String("out", "", "write the envelope's canonical CBOR to this .cbor path (for publish -files)")
	recoveryKeysCSV := fs.String("recovery-keys", "", "comma-separated hex Ed25519 public keys (64 hex chars each) embedding a spec 5.4 recovery policy (field 10); empty = no policy")
	recoveryThreshold := fs.Uint64("recovery-threshold", 0, "recovery quorum size (spec 5.4 threshold); required with -recovery-keys, must be 1..len(keys)")
	recoveryTimelock := fs.Uint64("recovery-timelock", 0, "seconds a recovery waits before taking effect (spec 5.4 timelock; 0 = default 259200 = 72 h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *ownerSeedHex == "" || *ip == "" || *pin == "" {
		return usageErr("make-record requires -name, -owner-seed, -ip, -pin")
	}
	labels, _, err := naming.DecomposeName(*name)
	if err != nil {
		return usageErr("invalid name %q: %v", *name, err)
	}
	tldID, err := decodePin(*pin, "-pin")
	if err != nil {
		return err
	}
	// -owner-seed / -signer-seed accept hex or @keyfile (seedKeypair).
	ownerKP, err := seedKeypair(*ownerSeedHex, "-owner-seed")
	if err != nil {
		return err
	}
	signerKP := ownerKP
	if *signerSeedHex != "" {
		signerKP, err = seedKeypair(*signerSeedHex, "-signer-seed")
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
	rec, wireName, err := buildARecord(*name, tldID, ownerKP.Public(), ip4, *seq, *ttl, expires)
	if err != nil {
		return err
	}
	// Spec 5.4 (lines 373-394): a record MAY embed a recovery policy
	// (field 10) so that threshold-of-keys can later re-point the name per
	// §8.4 — only when -recovery-keys is given; absent flags leave Recovery
	// nil (field 10 omitted from the CBOR map).
	if *recoveryKeysCSV != "" {
		keys, err := decodeRecoveryKeys(*recoveryKeysCSV)
		if err != nil {
			return err
		}
		if *recoveryThreshold < 1 || *recoveryThreshold > uint64(len(keys)) {
			return usageErr("invalid -recovery-threshold %d: must be 1..%d (the size of -recovery-keys, spec 5.4)", *recoveryThreshold, len(keys))
		}
		timelock := *recoveryTimelock
		if timelock == 0 {
			timelock = constants.RecoveryTimelock
		}
		policy, err := wire.NewRecoveryPolicyWire(*recoveryThreshold, keys, timelock)
		if err != nil {
			return err
		}
		rec.Recovery = policy
	}
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
	if rec.Recovery != nil {
		// Policy summary lines (spec 5.4), styled like the other extras.
		fmt.Printf("recovery_threshold=%d\n", rec.Recovery.Threshold)
		fmt.Printf("recovery_keys=%d\n", len(rec.Recovery.Keys))
		fmt.Printf("recovery_timelock=%d\n", rec.Recovery.Timelock)
	}
	if *out != "" {
		if err := os.WriteFile(*out, envBytes, 0o644); err != nil {
			return fmt.Errorf("write %q: %w", *out, err)
		}
		fmt.Printf("wrote=%s\n", *out)
	}
	return nil
}

// ---------------------------------------------------------------------------
// decoding helpers
// ---------------------------------------------------------------------------

// decodeRecoveryKeys parses the -recovery-keys CSV into 32-byte Ed25519
// public keys (spec 5.4 field 2: "array of bstr(32)"); each CSV entry must
// be exactly 64 hex chars. Empty entries (stray commas) are skipped.
func decodeRecoveryKeys(csv string) ([][]byte, error) {
	var keys [][]byte
	for i, field := range strings.Split(csv, ",") {
		if field = strings.TrimSpace(field); field == "" {
			continue
		}
		k, err := hex.DecodeString(field)
		if err != nil {
			return nil, usageErr("invalid -recovery-keys[%d] hex: %v", i, err)
		}
		if len(k) != constants.Ed25519PublicKeyLen {
			return nil, usageErr("-recovery-keys[%d] is %d bytes, expected %d (64 hex chars)", i, len(k), constants.Ed25519PublicKeyLen)
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, usageErr("-recovery-keys must name at least one public key")
	}
	return keys, nil
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
