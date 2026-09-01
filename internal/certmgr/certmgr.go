// Package certmgr is the letsencrypt-like management layer on top of the
// §9.5 self-certifying TLS machinery (internal/tlsca): issuance, renewal
// state, nginx deployment, and reload — the "certbot" of freens names.
//
// What LE does with ACME + a globally trusted root, freens does with the
// owner key: possession of SK_tld IS the domain validation (no challenge,
// no rate limit), and trust on visitors' devices comes from the TLSCA RR
// riding the signed apex record (§9.5.2) cross-certified into their local
// root — not from this package. certmgr only answers: "which certificates
// exist, where do their files live, when do they expire, and which server
// blocks serve them".
//
// Renewal state lives in <home>/tls/renewal/<name>.json (tracked
// certificates: file paths + expiry + nginx deployment), the default
// export directory is <home>/tls/export. Leaves are short-lived
// (constants.TLSLeafTTLSec, 7 days) and are minted fresh on every renewal —
// short lifetime plus owner-CA rotation is the revocation story (§9.5.3),
// so renewals swap the key too, which is why every renewal re-validates and
// reloads the servers that serve the old files.
package certmgr

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/keychain"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/tlsca"
)

// ErrNotTracked: no renewal state for that name (cert was never issued
// through a tracking flow).
var ErrNotTracked = errors.New("certmgr: no tracked certificate for that name")

// ErrNotDue: the certificate is still comfortably fresh (use Force).
var ErrNotDue = errors.New("certmgr: certificate not due for renewal yet")

// ErrNeedsPassphrase mirrors keychain.ErrNeedsPassphrase so UIs can react
// without importing the keychain sentinels (errors.Is chains through).
var ErrNeedsPassphrase = keychain.ErrNeedsPassphrase

// ErrWrongPassphrase mirrors keychain.ErrWrongPassphrase.
var ErrWrongPassphrase = keychain.ErrWrongPassphrase

// renewBeforeSecs is the certbot-style "renew when less than this is left"
// window. Leaves live 7 days; the daily timer therefore renews at ≤2 days
// left, giving two missed-timer days of slack before anything expires.
const renewBeforeSecs = 2 * 24 * 3600

// Renewal is one tracked certificate's state (the renewal/<name>.json
// file). Paths are absolute and stable: issuance once, renewal forever at
// the same paths — the certbot renewal-config model.
type Renewal struct {
	Name       string   `json:"name"`                  // display name ("camalolo", "www.camalolo")
	Alias      string   `json:"alias"`                 // owning alias (the keychain key)
	Labels     []string `json:"labels,omitempty"`      // sub-labels, display order (nil = apex)
	CertPath   string   `json:"cert_path"`             // serving chain PEM (leaf + owner CA)
	KeyPath    string   `json:"key_path"`              // leaf private key PEM (0600)
	NotAfter   int64    `json:"not_after"`             // leaf expiry, unix seconds
	IssuedAt   int64    `json:"issued_at"`             // last issuance, unix seconds
	NginxFiles []string `json:"nginx_files,omitempty"` // nginx config files serving this cert (renewal reloads after touching them)
	DeployHook string   `json:"deploy_hook,omitempty"` // shell command run after each successful renewal
}

// StateDir is where renewal state lives.
func StateDir(home string) string { return filepath.Join(home, "tls", "renewal") }

// ExportDir is the default directory for issued certificates.
func ExportDir(home string) string { return filepath.Join(home, "tls", "export") }

func statePath(home, name string) string {
	return filepath.Join(StateDir(home), name+".json")
}

// Track writes (or updates) the renewal state for r.Name.
func Track(home string, r *Renewal) error {
	if err := os.MkdirAll(StateDir(home), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(statePath(home, r.Name), b, 0o600)
}

// LoadState reads one tracked certificate. Returns ErrNotTracked (wrapping
// fs.ErrNotExist) when absent.
func LoadState(home, name string) (*Renewal, error) {
	b, err := os.ReadFile(statePath(home, name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotTracked, name)
		}
		return nil, err
	}
	var r Renewal
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("certmgr: corrupt renewal state %s: %v", name, err)
	}
	return &r, nil
}

// ListState returns every tracked certificate (sorted by name; a corrupt
// state file is skipped, not fatal — one bad file must not hide the rest).
func ListState(home string) ([]*Renewal, error) {
	entries, err := os.ReadDir(StateDir(home))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Renewal
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		r, err := LoadState(home, strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// Forget removes the tracking state (the cert files are left alone —
// deleting live key material is uninstall/forget territory, not renewal).
func Forget(home, name string) error {
	err := os.Remove(statePath(home, name))
	if err != nil && os.IsNotExist(err) {
		return fmt.Errorf("%w: %s", ErrNotTracked, name)
	}
	return err
}

// IsDue reports whether r's leaf should be renewed (certbot's
// renew-before-expiry rule, tuned to the 7-day leaf TTL).
func IsDue(r *Renewal, now time.Time) bool {
	return r.NotAfter-now.Unix() < renewBeforeSecs
}

// Issued is the result of one leaf issuance.
type Issued struct {
	Name     string
	Alias    string
	SANs     []string
	NotAfter time.Time
	CertPEM  []byte // chain: leaf + owner CA (the SERVING chain, §9.5.4)
	KeyPEM   []byte
	CertPath string
	KeyPath  string
}

// Issue mints a fresh leaf for displayName (an owned apex or sub-name) and
// writes <outDir>/<name>.{crt,key} atomically. SAN policy matches §9.5.3 /
// `freens cert`: the exact name, plus *.<alias> when it IS the apex (the
// wildcard is advisory — Windows clients ignore it for sub-names, which is
// why sub-name leaves carry their explicit SAN).
func Issue(keysDir, displayName, outDir, passphrase string, now time.Time) (*Issued, error) {
	labels, alias, err := naming.DecomposeName(displayName)
	if err != nil {
		return nil, fmt.Errorf("certmgr: invalid name %q: %v", displayName, err)
	}
	kp, err := keychain.Load(keychain.OwnerKeyPath(keysDir, alias), passphrase)
	if err != nil {
		return nil, err // keychain sentinels pass through for callers to map
	}
	caDER, caKey, err := tlsca.OwnerCA(kp.Seed(), alias, now)
	if err != nil {
		return nil, err
	}
	sans := []string{displayName}
	if len(labels) == 0 {
		sans = append(sans, "*."+alias)
	}
	leafDER, leafKeyDER, err := tlsca.Leaf(caDER, caKey, sans, now)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(outDir, displayName+".crt")
	keyPath := filepath.Join(outDir, displayName+".key")
	chain := append(tlsca.CertPEM(leafDER), tlsca.CertPEM(caDER)...)
	if err := writeFileAtomic(certPath, chain, 0o644); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(keyPath, tlsca.KeyPEM(leafKeyDER), 0o600); err != nil {
		return nil, err
	}
	leaf, err := tlsca.ParseCertDER(leafDER)
	if err != nil {
		return nil, err
	}
	return &Issued{
		Name: displayName, Alias: alias, SANs: sans,
		NotAfter: leaf.NotAfter, CertPEM: chain, KeyPEM: tlsca.KeyPEM(leafKeyDER),
		CertPath: certPath, KeyPath: keyPath,
	}, nil
}

// TrackIssue issues AND records the renewal state in one step — the flow
// every "give me a cert for this name and keep it fresh" entry point uses
// (CLI cert, cert nginx, the web UI). outDir "" means ExportDir(home).
func TrackIssue(home, keysDir, displayName, outDir, passphrase, hook string, now time.Time) (*Renewal, *Issued, error) {
	if outDir == "" {
		outDir = ExportDir(home)
	}
	iss, err := Issue(keysDir, displayName, outDir, passphrase, now)
	if err != nil {
		return nil, nil, err
	}
	r := &Renewal{
		Name:       iss.Name,
		Alias:      iss.Alias,
		Labels:     mustLabels(displayName),
		CertPath:   iss.CertPath,
		KeyPath:    iss.KeyPath,
		NotAfter:   iss.NotAfter.Unix(),
		IssuedAt:   now.Unix(),
		DeployHook: hook,
	}
	if prev, err := LoadState(home, iss.Name); err == nil {
		// Renewal-state continuity: keep the nginx deployment list (and any
		// hook) a re-issue would otherwise silently drop.
		r.NginxFiles = prev.NginxFiles
		if hook == "" {
			r.DeployHook = prev.DeployHook
		}
	}
	if err := Track(home, r); err != nil {
		return nil, nil, err
	}
	return r, iss, nil
}

// EnsureTracked returns the tracked state for displayName, issuing a fresh
// certificate when none is tracked (or its files vanished). The web UI's
// "install into nginx" path runs this so a click on an un-issued name just
// works.
func EnsureTracked(home, keysDir, displayName, passphrase string, now time.Time) (*Renewal, error) {
	if r, err := LoadState(home, displayName); err == nil &&
		fileExists(r.CertPath) && fileExists(r.KeyPath) {
		return r, nil
	}
	r, _, err := TrackIssue(home, keysDir, displayName, "", passphrase, "", now)
	return r, err
}

// RenewOpts tunes RenewOne / RenewDue.
type RenewOpts struct {
	Force    bool   // renew even when not due
	Hook     string // set/override the deploy hook for this name
	NoReload bool   // skip the nginx reload even when nginx serves this cert
}

// RenewOne renews one tracked name: fresh leaf at the SAME paths (servers
// keep serving through the swap — atomic renames), state update, then the
// deploy side (nginx reload when tracked, deploy hook). Returns the updated
// state. ErrNotTracked / ErrNotDue report the boring outcomes.
func RenewOne(home, keysDir, displayName, passphrase string, opts RenewOpts, now time.Time) (*Renewal, error) {
	prev, err := LoadState(home, displayName)
	if err != nil {
		return nil, err
	}
	if !opts.Force && !IsDue(prev, now) {
		return prev, ErrNotDue
	}
	iss, err := Issue(keysDir, displayName, filepath.Dir(prev.CertPath), passphrase, now)
	if err != nil {
		return nil, err
	}
	r := &Renewal{
		Name: prev.Name, Alias: prev.Alias, Labels: prev.Labels,
		CertPath: iss.CertPath, KeyPath: iss.KeyPath,
		NotAfter: iss.NotAfter.Unix(), IssuedAt: now.Unix(),
		NginxFiles: prev.NginxFiles,
		DeployHook: prev.DeployHook,
	}
	if opts.Hook != "" {
		r.DeployHook = opts.Hook
	}
	if err := Track(home, r); err != nil {
		return nil, err
	}
	// Deploy side, best-effort but reported: reload nginx first (the config
	// still references these exact paths), then the operator's hook.
	if !opts.NoReload && len(r.NginxFiles) > 0 {
		if err := ReloadNginx("", ""); err != nil {
			return r, fmt.Errorf("renewed, but the nginx reload failed: %v", err)
		}
	}
	if r.DeployHook != "" {
		if err := RunHook(r.DeployHook); err != nil {
			return r, fmt.Errorf("renewed, but the deploy hook failed: %v", err)
		}
	}
	return r, nil
}

// RenewDue renews every tracked certificate that IsDue (or all with force).
// One encrypted key must not strand the rest: per-name failures are
// collected and the summary reports both. Returns the renewed states and a
// joined error (nil when everything renewed or nothing was due).
func RenewDue(home, keysDir, passphrase string, opts RenewOpts, now time.Time) ([]*Renewal, error) {
	states, err := ListState(home)
	if err != nil {
		return nil, err
	}
	var renewed []*Renewal
	var errs []error
	for _, prev := range states {
		r, rerr := RenewOne(home, keysDir, prev.Name, passphrase, opts, now)
		switch {
		case rerr == nil:
			renewed = append(renewed, r)
		case errors.Is(rerr, ErrNotDue) && !opts.Force:
			// fresh enough — the normal bulk outcome
		default:
			errs = append(errs, fmt.Errorf("%s: %v", prev.Name, rerr))
		}
	}
	return renewed, errors.Join(errs...)
}

// RunHook executes a deploy hook (sh -c on unix, cmd /c on windows) with a
// bounded timeout; output is folded into the error for operator visibility.
func RunHook(hook string) error {
	out, err := runShell(hook, 60*time.Second)
	if err != nil {
		return fmt.Errorf("deploy hook %q: %v: %s", hook, err, strings.TrimSpace(out))
	}
	return nil
}

// mustLabels re-derives display-order labels (TrackIssue convenience).
func mustLabels(displayName string) []string {
	labels, _, err := naming.DecomposeName(displayName)
	if err != nil {
		return nil
	}
	return labels
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// writeFileAtomic replaces path with data: temp file in the SAME directory,
// fsync, rename (the keychain's scheme, minus the Windows dir-sync special
// case which securekey/keychain already documented as best-effort there —
// for cert files the rename itself is the atomicity that matters, and a
// cert re-issued by tomorrow's timer heals any lost rename anyway).
func writeFileAtomic(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ErrServeFilesNotFound is a doctor/UX helper answer.
func ErrServeFilesNotFound(name string) error {
	return fmt.Errorf("%w: run `freens cert %s` (or issue it from the web UI) first", ErrNotTracked, name)
}

// containsName: exact membership (server_name lists, deployed-file lists).
func containsName(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
