// Package keychain is the one library for the on-disk freens keychain
// (~/.freens/keys): owner keys, recovery keyfiles, the parked reusable claim
// state, and the backup bundle. It exists so the CLI and the web UI share
// EXACTLY the same keyfile semantics (the FREENSK1 encrypted form, the
// legacy plaintext hex form, alias discovery, backup contents) instead of
// drifting — a format bug fixed here is fixed everywhere.
//
// The package never prompts: callers decide where a passphrase comes from
// (terminal, environment variable, web form). Encrypted keys surface
// ErrNeedsPassphrase (no passphrase given) and ErrWrongPassphrase (unlock
// failed) as distinct sentinel errors so UIs can ask precisely.
package keychain

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/securekey"
	"github.com/camalolo/freens/internal/wire"
)

// Sentinel errors for the unlock path (see package doc).
var (
	// ErrNeedsPassphrase: the keyfile is encrypted and no passphrase was
	// supplied — ask for one and retry.
	ErrNeedsPassphrase = errors.New("keyfile is passphrase-encrypted (passphrase required)")
	// ErrWrongPassphrase: a passphrase was supplied but the unlock failed
	// (GCM authentication or malformed envelope).
	ErrWrongPassphrase = securekey.ErrWrongPassphrase
	// ErrNotFound: no keyfile at the requested path.
	ErrNotFound = errors.New("no keyfile at that path")
)

// keyFileRe matches an owner keyfile name: <alias>.key. Recovery keyfiles
// (<alias>.rec1.key etc.) never match because the stem must be a plain
// valid alias.
var keyFileRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)\.key$`)

// recFileRe matches a recovery keyfile: <alias>.recN.key (N ≥ 1, no leading
// zero — matching register's generation).
var recFileRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)\.rec([1-9][0-9]*)\.key$`)

// Aliases lists the aliases that have an owner key in keysDir (sorted) —
// the "which namespaces can I manage" answer.
func Aliases(keysDir string) []string {
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return nil
	}
	var aliases []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if m := keyFileRe.FindStringSubmatch(e.Name()); m != nil {
			aliases = append(aliases, m[1])
		}
	}
	sort.Strings(aliases)
	return aliases
}

// OwnerKeyPath is the keychain location of alias' owner key.
func OwnerKeyPath(keysDir, alias string) string {
	return filepath.Join(keysDir, alias+".key")
}

// Load reads and unlocks a keyfile. passphrase may be empty for legacy
// plaintext keyfiles; an encrypted keyfile with an empty passphrase returns
// ErrNeedsPassphrase, and a wrong passphrase returns ErrWrongPassphrase.
func Load(path, passphrase string) (*crypto.Keypair, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		return nil, err
	}
	if securekey.IsEncrypted(b) {
		if passphrase == "" {
			return nil, ErrNeedsPassphrase
		}
		seed, derr := securekey.DecryptSeed(b, passphrase)
		if derr != nil {
			return nil, ErrWrongPassphrase
		}
		return crypto.FromSeed(seed)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("invalid plaintext keyfile %s: %v", path, err)
	}
	return crypto.FromSeed(seed)
}

// Save persists kp at path (0600, parent dirs 0700); passphrase "" writes
// the legacy plaintext hex form, non-empty writes the FREENSK1 envelope.
func Save(path string, kp *crypto.Keypair, passphrase string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var data []byte
	if passphrase == "" {
		data = []byte(hex.EncodeToString(kp.Seed()) + "\n")
	} else {
		var err error
		data, err = securekey.EncryptSeed(kp.Seed(), passphrase)
		if err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o600)
}

// IsEncryptedPath reports whether the keyfile at path carries the FREENSK1
// envelope (missing files report false).
func IsEncryptedPath(path string) bool {
	b, err := os.ReadFile(path)
	return err == nil && securekey.IsEncrypted(b)
}

// KeyInfo is one keyfile inventory row (the web UI's Keys page).
type KeyInfo struct {
	Path      string    `json:"path"`
	Name      string    `json:"name"`      // file base name
	Alias     string    `json:"alias"`     // owning alias ("" for node.key etc.)
	Kind      string    `json:"kind"`      // "owner" | "recovery"
	Encrypted bool      `json:"encrypted"` // FREENSK1 at rest
	Size      int64     `json:"size"`
	ModTime   time.Time `json:"mod_time"`
}

// Inventory lists every keyfile in keysDir (owner + recovery), sorted by
// alias then kind. Files that match neither pattern are skipped.
func Inventory(keysDir string) []KeyInfo {
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return nil
	}
	var out []KeyInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info := KeyInfo{Path: filepath.Join(keysDir, e.Name()), Name: e.Name()}
		if fi, err := e.Info(); err == nil {
			info.Size = fi.Size()
			info.ModTime = fi.ModTime()
		}
		switch {
		case keyFileRe.MatchString(e.Name()):
			info.Alias = keyFileRe.FindStringSubmatch(e.Name())[1]
			info.Kind = "owner"
		case recFileRe.MatchString(e.Name()):
			m := recFileRe.FindStringSubmatch(e.Name())
			info.Alias = m[1]
			info.Kind = "recovery"
		default:
			continue
		}
		info.Encrypted = IsEncryptedPath(info.Path)
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Alias != out[j].Alias {
			return out[i].Alias < out[j].Alias
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

// backupEntryRe matches the only filenames a backup (or a restore) may
// carry: owner keys, recovery keyfiles, and the reusable claim state — bare
// names, no directories.
var backupEntryRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.rec[1-9][0-9]*)?(\.key|\.claim\.json)$`)

// backupReadmeTemplate is the RESTORE.txt carried inside every bundle.
const backupReadmeTemplate = `freens key backup
==================

This archive bundles every key of your name(s) so a lost disk does not
lose the namespace. Keep it OFF this machine (USB stick, password
manager attachment, encrypted cloud folder).

Restoring: on the new machine run

  %s backup -restore <this-file.tar.gz>

which copies the keyfiles below into ~/.freens/keys (refuses to
overwrite; -force overrides). Then ` + "`freens status`" + ` confirms the
names are yours again. If a keyfile was passphrase-encrypted, the
passphrase is the one you set when registering — it is NOT in this
archive.

Contents:
  %s

Generated %s by freens backup.
`

// BuildBackup writes the dated keychain bundle (tar.gz) for keysDir into w.
// It is the library core of `freens backup`; the CLI adds the file
// management and printing around it. Returns the bundled file names.
func BuildBackup(w io.Writer, keysDir string) ([]string, error) {
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return nil, fmt.Errorf("nothing to back up (no keychain at %s)", keysDir)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && backupEntryRe.MatchString(e.Name()) {
			files = append(files, e.Name())
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("nothing to back up (no key files in %s)", keysDir)
	}
	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	for _, name := range files {
		b, err := os.ReadFile(filepath.Join(keysDir, name))
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", name, err)
		}
		hdr := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, err
		}
	}
	readme := fmt.Sprintf(backupReadmeTemplate, "freens", strings.Join(files, "\n  "),
		time.Now().Format("2006-01-02 15:04"))
	hdr := &tar.Header{Name: "RESTORE.txt", Mode: 0o644, Size: int64(len(readme)), Format: tar.FormatUSTAR}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}
	if _, err := tw.Write([]byte(readme)); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return files, gz.Close()
}

// ---------------------------------------------------------------------------
// Recovery plan (register's default-on spec 5.4 policy)
// ---------------------------------------------------------------------------

// RecoveryPlan generates count recovery keypairs for alias in keysDir
// (passphrase "" = plaintext files) and returns their paths plus the wire
// policy embedding their public keys at the given threshold. noRecovery
// short-circuits to (nil, nil, nil).
func RecoveryPlan(noRecovery bool, keysDir, alias, passphrase string, count, threshold int, timelock uint64) ([]string, *wire.RecoveryPolicyWire, error) {
	if noRecovery {
		return nil, nil, nil
	}
	if count <= 0 || threshold <= 0 || threshold > count {
		return nil, nil, fmt.Errorf("keychain: recovery plan needs 0 < threshold <= count (got %d/%d)", threshold, count)
	}
	paths := make([]string, 0, count)
	pks := make([][]byte, 0, count)
	for i := 1; i <= count; i++ {
		rkp, err := crypto.Generate()
		if err != nil {
			return nil, nil, err
		}
		p := filepath.Join(keysDir, fmt.Sprintf("%s.rec%d.key", alias, i))
		if err := Save(p, rkp, passphrase); err != nil {
			return nil, nil, fmt.Errorf("writing recovery keyfile: %w", err)
		}
		paths = append(paths, p)
		pks = append(pks, rkp.Public())
	}
	pol, err := wire.NewRecoveryPolicyWire(uint64(threshold), pks, timelock)
	if err != nil {
		return nil, nil, err
	}
	return paths, pol, nil
}

// ---------------------------------------------------------------------------
// Reusable claim state (register's cooldown-safe retry parking)
// ---------------------------------------------------------------------------

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

// ClaimStatePath is where alias' parked claim lives.
func ClaimStatePath(keysDir, alias string) string {
	return filepath.Join(keysDir, alias+".claim.json")
}

// LoadReusableClaim returns the persisted claim when it matches alias,
// owner key, and difficulty (any mismatch or absence => nil: re-mine).
func LoadReusableClaim(keysDir, alias string, kp *crypto.Keypair, difficulty int) *claims.AliasClaim {
	b, err := os.ReadFile(ClaimStatePath(keysDir, alias))
	if err != nil {
		return nil
	}
	var rc reusableClaim
	if json.Unmarshal(b, &rc) != nil || rc.Alias != alias || rc.Difficulty != difficulty {
		return nil
	}
	tldID, err1 := base32Decode(rc.TldIDB32)
	claimant, err2 := base64.StdEncoding.DecodeString(rc.ClaimantB64)
	nonce, err3 := base64.StdEncoding.DecodeString(rc.NonceB64)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil
	}
	if mine, err := crypto.TldID(kp.Public()); err != nil || !bytes.Equal(tldID, mine) {
		return nil
	}
	if !bytes.Equal(claimant, kp.Public()) {
		return nil
	}
	c := &claims.AliasClaim{Alias: alias, TldID: tldID, ClaimantPK: claimant, Timestamp: rc.Timestamp, Nonce: nonce}
	if p, err := c.Prefix(); err == nil {
		c.PowHash = crypto.PoWHash(p, nonce) // VerifyPoW compares against this field
	}
	if !c.VerifyPoW(difficulty) || !c.VerifyClaimantConsistency() {
		return nil // tampered or stale state: never reuse unverifiable claims
	}
	return c
}

// base32Decode is the tld_id_b32 inverse (lowercase RFC 4648, no padding —
// the same decoding the CLI always used).
func base32Decode(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(s))
}

// difficultyOf reads the difficulty from the nonce[0] convention (Appendix
// A.4); falls back to the network default.
func difficultyOf(c *claims.AliasClaim) int {
	if len(c.Nonce) > 0 && int(c.Nonce[0]) >= constants.PoWDifficultyInit {
		return int(c.Nonce[0])
	}
	return constants.PoWDifficultyInit
}

// SaveReusableClaim parks c for alias (best effort — failures are
// non-fatal; the claim simply won't be reused after a retry).
func SaveReusableClaim(keysDir, alias string, c *claims.AliasClaim) {
	tldB32 := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(c.TldID), "="))
	rc := reusableClaim{
		Alias:       alias,
		TldIDB32:    tldB32,
		ClaimantB64: base64.StdEncoding.EncodeToString(c.ClaimantPK),
		Timestamp:   c.Timestamp,
		Difficulty:  difficultyOf(c),
		NonceB64:    base64.StdEncoding.EncodeToString(c.Nonce),
	}
	if b, err := json.MarshalIndent(rc, "", "  "); err == nil {
		_ = os.MkdirAll(filepath.Dir(ClaimStatePath(keysDir, alias)), 0o700)
		_ = os.WriteFile(ClaimStatePath(keysDir, alias), b, 0o600)
	}
}
