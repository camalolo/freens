// Package trustsync implements the visitor side of §9.5 self-certifying
// TLS: cross-certify DHT-verified owner CAs into the local trust stores,
// and purge what died.
//
// Flow (§9.5.4): the resolver's screened answer path notifies OnOwnerCA
// (alias, tld_id, caDER, recordExpires) for every verified apex carrying a
// TLSCA RR. The engine screens the CA, mints a name-constrained cross-cert
// under the installation's LOCAL ROOT (generated once, kept under
// <home>/tls/), verifies the chain locally, and installs it:
//
//   - spool (always):   <home>/tls/spool/freens-cross-<alias>.crt — picked
//     up by the freens-trust systemd path unit (root) which refreshes the
//     system bundle (/usr/local/share/ca-certificates + update-ca-certificates);
//   - system store (when writable — root-mode daemons): direct install;
//   - NSS user DB (when certutil exists): ~/.pki/nssdb + Firefox profiles —
//     this is what makes Chromium/Firefox accept the chain unprivileged.
//
// OnAliasDead removes everything for the alias (rotation keyed by tld_id:
// a stale death signal for a superseded identity is ignored).
package trustsync

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/camalolo/freens/internal/tlsca"
)

// ErrTrustSync marks trustsync failures.
var ErrTrustSync = errors.New("trustsync: error")

// refreshWithin: re-mint a cross-cert when less than this much lifetime
// remains. Cross-certs are capped by the record expiry (≤ 24 h leases), so
// any live traffic keeps them fresh; 6 h of remaining life is comfortably
// above a quiet weekend gap, below any realistic lease.
const refreshWithin = 6 * time.Hour

// Options configures an engine. HomeDir is required; empty optional paths
// disable the corresponding installer.
type Options struct {
	HomeDir string       // FREENS_HOME (root + spool + state live under <home>/tls)
	Logger  *slog.Logger // nil = discard
	Now     func() time.Time

	// NSSInstall enables the certutil-based user-store installs (Chromium's
	// ~/.pki/nssdb and Firefox profile DBs). Default on; auto-skips when
	// certutil is absent.
	NSSInstall bool
	// SystemStore enables the DIRECT system-bundle install attempt (root
	// daemons). Default on; the spool file is ALWAYS written either way.
	SystemStore bool
}

// Engine is the §9.5.4 sink. Safe for concurrent use; deduplicates work.
type Engine struct {
	opts Options
	log  *slog.Logger

	mu        sync.Mutex
	rootDER   []byte
	rootKey   *ecdsa.PrivateKey
	state     map[string]crossState // alias → installed binding
	installed map[string]bool       // alias → directly written to system store
}

type crossState struct {
	TldIDB32 string `json:"tld_id_b32"`
	CASha256 string `json:"ca_sha256"`
	NotAfter int64  `json:"not_after"`
}

// New loads (or generates) the installation's local root and the cross-cert
// state. The root key file is 0600; the root cert is public material.
func New(opts Options) (*Engine, error) {
	if opts.HomeDir == "" {
		return nil, fmt.Errorf("%w: HomeDir required", ErrTrustSync)
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	e := &Engine{
		opts:      opts,
		log:       opts.Logger,
		state:     map[string]crossState{},
		installed: map[string]bool{},
	}
	tlsDir := filepath.Join(opts.HomeDir, "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		return nil, fmt.Errorf("%w: tls dir: %v", ErrTrustSync, err)
	}
	if err := os.MkdirAll(e.spoolDir(), 0o755); err != nil {
		return nil, fmt.Errorf("%w: spool dir: %v", ErrTrustSync, err)
	}
	rootDER, rootKey, err := e.loadOrCreateRoot()
	if err != nil {
		return nil, err
	}
	e.rootDER, e.rootKey = rootDER, rootKey
	e.loadState()
	return e, nil
}

func (e *Engine) tlsDir() string    { return filepath.Join(e.opts.HomeDir, "tls") }
func (e *Engine) spoolDir() string  { return filepath.Join(e.tlsDir(), "spool") }
func (e *Engine) statePath() string { return filepath.Join(e.tlsDir(), "cross.json") }

func (e *Engine) loadOrCreateRoot() ([]byte, *ecdsa.PrivateKey, error) {
	keyPath := filepath.Join(e.tlsDir(), "root.key")
	crtPath := filepath.Join(e.tlsDir(), "root.crt")
	keyPEM, kerr := os.ReadFile(keyPath)
	crtPEM, cerr := os.ReadFile(crtPath)
	if kerr == nil && cerr == nil {
		key, err := decodeECKey(keyPEM)
		if err == nil {
			if cert, perr := tlsca.ParseCertPEM(crtPEM); perr == nil {
				if err := cert.CheckSignatureFrom(cert); err == nil {
					return cert.Raw, key, nil
				}
			}
		}
		e.log.Warn("tls: unreadable local root under <home>/tls — regenerating (previously installed roots in browser stores go stale)")
	}
	der, key, err := tlsca.LocalRoot(e.opts.Now())
	if err != nil {
		return nil, nil, err
	}
	if werr := writeAtomic(keyPath, pemECKey(key), 0o600); werr != nil {
		return nil, nil, fmt.Errorf("%w: write root key: %v", ErrTrustSync, werr)
	}
	if werr := writeAtomic(crtPath, tlsca.CertPEM(der), 0o644); werr != nil {
		return nil, nil, fmt.Errorf("%w: write root cert: %v", ErrTrustSync, werr)
	}
	e.log.Info("tls: generated the local trust root", "fingerprint", tlsca.Fingerprint(der),
		"path", crtPath, "hint", "run `freens trust-install` to import it into this machine's browser/OS stores")
	return der, key, nil
}

// RootFingerprint returns the local root's SHA-256 (doctor / admin status).
func (e *Engine) RootFingerprint() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return tlsca.Fingerprint(e.rootDER)
}

// RootPEM returns the local root certificate (PEM) — the artifact
// `freens trust-install` pushes into the browser/OS stores.
func (e *Engine) RootPEM() []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	return tlsca.CertPEM(e.rootDER)
}

// InstallRoot imports the LOCAL ROOT into this machine's stores — the
// one-time, per-device step of §9.5.4. Idempotent. Returns a human-readable
// report (one line per store). The system-bundle attempt is DIRECT only
// (root-mode); for a user daemon it prints the exact sudo commands instead
// (setup wires the freens-trust bridge so this is normally unnecessary).
func (e *Engine) InstallRoot() []string {
	var report []string
	rootPEM := e.RootPEM()
	root := e.tlsDir() + "/root.crt"

	// 1) System bundle: direct when possible, else print the recipe.
	sysPath := "/usr/local/share/ca-certificates/freens-local-root.crt"
	if err := writeAtomic(sysPath, rootPEM, 0o644); err == nil {
		if err := exec.Command("update-ca-certificates").Run(); err == nil {
			report = append(report, "system: installed ("+sysPath+")")
		} else {
			report = append(report, "system: cert copied — run `sudo update-ca-certificates` to refresh")
		}
	} else {
		report = append(report, "system: NOT installed (needs one command):")
		report = append(report,
			"  sudo cp "+root+" "+sysPath+" && sudo update-ca-certificates")
	}

	// 2) NSS user DBs (Chromium's ~/.pki/nssdb + Firefox profiles).
	cu := certutilPath()
	if cu == "" {
		report = append(report, "nss: certutil not found (libnss3-tools) — skipped; browsers may not trust freens HTTPS")
		return report
	}
	home, herr := os.UserHomeDir()
	if herr == nil {
		pki := filepath.Join(home, ".pki", "nssdb")
		if _, serr := os.Stat(pki); serr != nil {
			if err := exec.Command(cu, "-N", "-d", "sql:"+pki, "--empty-password").Run(); err == nil {
				report = append(report, "nss: created "+pki)
			}
		}
	}
	for _, db := range e.nssDBs() {
		_ = exec.Command(cu, "-d", db, "-D", "-n", "freens-local-root").Run()
		if err := exec.Command(cu, "-d", db, "-A", "-n", "freens-local-root", "-t", "C,,", "-i", root).Run(); err != nil {
			report = append(report, "nss: FAILED for "+db+": "+err.Error())
			continue
		}
		report = append(report, "nss: installed into "+db)
	}
	return report
}

// ---------------------------------------------------------------------------
// The resolver sink (§9.5.4)
// ---------------------------------------------------------------------------

// OnOwnerCA screens the verified CA binding, mints the constrained
// cross-cert when missing or near expiry, and installs it. Never returns an
// error (the resolver calls it asynchronously): problems are logged and the
// next notification retries.
func (e *Engine) OnOwnerCA(alias string, tldID, caDER []byte, recordExpires int64) {
	if len(alias) == 0 || len(caDER) == 0 || recordExpires <= 0 {
		return
	}
	ca, err := tlsca.ParseCertDER(caDER)
	if err != nil {
		e.log.Debug("tls: unparsable owner CA ignored", "alias", alias, "err", err)
		return
	}
	if err := tlsca.ValidateOwnerCA(ca, alias); err != nil {
		e.log.Warn("tls: owner CA failed the §9.5.4 screen", "alias", alias, "err", err)
		return
	}
	now := e.opts.Now()
	caHash := tlsca.Fingerprint(caDER)
	tldB32 := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(tldID), "="))

	e.mu.Lock()
	if st, ok := e.state[alias]; ok && st.TldIDB32 == tldB32 && st.CASha256 == caHash {
		notAfter := time.Unix(st.NotAfter, 0)
		if now.Add(refreshWithin).Before(notAfter) {
			e.mu.Unlock()
			return // healthy, fresh, unchanged
		}
	}
	e.mu.Unlock()

	crossDER, err := tlsca.CrossCert(e.rootDER, e.rootKey, caDER, alias, time.Unix(recordExpires, 0), now)
	if err != nil {
		e.log.Warn("tls: cross-cert mint failed", "alias", alias, "err", err)
		return
	}
	cross, _ := tlsca.ParseCertDER(crossDER)
	crossPEM := tlsca.CertPEM(crossDER)

	// 1) Spool (the privileged bridge's source of truth).
	spool := e.spoolPath(alias)
	if err := writeAtomic(spool, crossPEM, 0o644); err != nil {
		e.log.Warn("tls: spool write failed", "alias", alias, "err", err)
	}

	// 2) System bundle (root-mode daemons; the bridge covers user-mode).
	sysOK := false
	if e.opts.SystemStore {
		sysOK = e.installSystem(alias, crossPEM)
	}

	// 3) NSS user DBs (Chromium/Firefox).
	if e.opts.NSSInstall {
		e.installNSS(alias, crossPEM)
	}
	e.mu.Lock()
	e.state[alias] = crossState{TldIDB32: tldB32, CASha256: caHash, NotAfter: cross.NotAfter.Unix()}
	e.installed[alias] = sysOK
	e.mu.Unlock()
	if werr := e.saveState(); werr != nil {
		e.log.Warn("tls: state save failed", "err", werr)
	}
	e.log.Info("tls: cross-certified namespace", "alias", alias,
		"ca", caHash[:16], "not_after", cross.NotAfter.Format(time.RFC3339),
		"system", sysOK, "spool", spool)
}

// OnAliasDead purges everything the engine installed for alias. A stale
// signal for a superseded identity (tldID mismatch) is ignored.
func (e *Engine) OnAliasDead(alias string, tldID []byte) {
	e.mu.Lock()
	st, ok := e.state[alias]
	if !ok {
		e.mu.Unlock()
		return
	}
	if len(tldID) > 0 {
		b32 := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(tldID), "="))
		if b32 != st.TldIDB32 {
			e.mu.Unlock()
			return // old identity's corpse: the live one stays
		}
	}
	spool := e.spoolPath(alias)
	sysOK := e.installed[alias]
	delete(e.state, alias)
	delete(e.installed, alias)
	e.mu.Unlock()

	_ = os.Remove(spool)
	if sysOK {
		e.uninstallSystem(alias)
	}
	if e.opts.NSSInstall {
		e.uninstallNSS(alias)
	}
	if err := e.saveState(); err != nil {
		e.log.Warn("tls: state save failed", "err", err)
	}
	e.log.Info("tls: purged cross-cert (alias dead)", "alias", alias)
}

// Snapshot lists the installed bindings (admin /tls + doctor).
type Snapshot struct {
	Alias    string `json:"alias"`
	TldIDB32 string `json:"tld_id_b32"`
	CASha256 string `json:"ca_sha256"`
	NotAfter int64  `json:"not_after"`
	System   bool   `json:"system_store"`
}

func (e *Engine) Snapshot() []Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Snapshot, 0, len(e.state))
	for alias, st := range e.state {
		out = append(out, Snapshot{alias, st.TldIDB32, st.CASha256, st.NotAfter, e.installed[alias]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out
}

// ---------------------------------------------------------------------------
// Installers
// ---------------------------------------------------------------------------

func (e *Engine) spoolPath(alias string) string {
	return filepath.Join(e.spoolDir(), "freens-cross-"+alias+".crt")
}

func (e *Engine) sysPath(alias string) string {
	return "/usr/local/share/ca-certificates/freens-cross-" + alias + ".crt"
}

// installSystem writes the system bundle entry directly and refreshes it.
// Fails silently into the spool path when unprivileged (the bridge's job).
func (e *Engine) installSystem(alias string, crossPEM []byte) bool {
	path := e.sysPath(alias)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false
	}
	if err := writeAtomic(path, crossPEM, 0o644); err != nil {
		return false // EACCES for a user daemon: expected, spool covers it
	}
	if err := exec.Command("update-ca-certificates").Run(); err != nil {
		e.log.Debug("tls: update-ca-certificates failed", "alias", alias, "err", err)
		return true // file placed; a later bridge run completes the refresh
	}
	return true
}

func (e *Engine) uninstallSystem(alias string) {
	_ = os.Remove(e.sysPath(alias))
	_ = exec.Command("update-ca-certificates").Run()
}

// nssDBs lists the NSS databases certutil should know about: Chromium's
// user DB plus every Firefox profile with a cert9.db.
func (e *Engine) nssDBs() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var dbs []string
	pki := filepath.Join(home, ".pki", "nssdb")
	if _, err := os.Stat(pki); err == nil {
		dbs = append(dbs, "sql:"+pki)
	}
	prof, err := filepath.Glob(filepath.Join(home, ".mozilla", "firefox", "*.default*"))
	if err == nil {
		for _, p := range prof {
			if _, err := os.Stat(filepath.Join(p, "cert9.db")); err == nil {
				dbs = append(dbs, "sql:"+p)
			}
		}
	}
	return dbs
}

// certutilPath finds certutil (libnss3-tools). Empty = not installed.
func certutilPath() string {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		p := filepath.Join(dir, "certutil")
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

func (e *Engine) installNSS(alias string, crossPEM []byte) {
	cu := certutilPath()
	if cu == "" {
		return
	}
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("freens-nss-%d-%s.crt", os.Getpid(), nssSafe(alias)))
	if err := os.WriteFile(tmp, crossPEM, 0o644); err != nil {
		return
	}
	defer os.Remove(tmp)
	name := "freens-cross-" + nssSafe(alias)
	for _, db := range e.nssDBs() {
		// Replace then add: certutil has no upsert. "C,," (trusted anchor):
		// Chromium's Chrome-Root-Store verifier uses NSS DB entries ONLY as
		// anchors — an "c,," intermediate is invisible to it, breaking the
		// chain. The namespace constraint lives in the cross-cert itself and
		// is enforced by Chrome's verifier (and OpenSSL); NSS-family
		// verifiers anchor here too, so keep the cert minimal and
		// name-constrained (§9.5.4).
		_ = exec.Command(cu, "-d", db, "-D", "-n", name).Run()
		if err := exec.Command(cu, "-d", db, "-A", "-n", name, "-t", "C,,", "-i", tmp).Run(); err != nil {
			e.log.Debug("tls: NSS add failed", "db", db, "alias", alias, "err", err)
		}
	}
}

func (e *Engine) uninstallNSS(alias string) {
	cu := certutilPath()
	if cu == "" {
		return
	}
	name := "freens-cross-" + nssSafe(alias)
	for _, db := range e.nssDBs() {
		_ = exec.Command(cu, "-d", db, "-D", "-n", name).Run()
	}
}

func nssSafe(alias string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return -1
	}, alias)
}

// ---------------------------------------------------------------------------
// Plumbing: state + atomic writes + PEM key codec
// ---------------------------------------------------------------------------

func (e *Engine) loadState() {
	b, err := os.ReadFile(e.statePath())
	if err != nil {
		return
	}
	var st map[string]crossState
	if json.Unmarshal(b, &st) == nil {
		e.state = st
		if e.state == nil {
			e.state = map[string]crossState{}
		}
		e.installed = map[string]bool{}
	}
}

func (e *Engine) saveState() error {
	e.mu.Lock()
	b, err := json.MarshalIndent(e.state, "", "  ")
	e.mu.Unlock()
	if err != nil {
		return err
	}
	return writeAtomic(e.statePath(), b, 0o600)
}

// writeAtomic mirrors the keychain's temp+fsync+rename write.
func writeAtomic(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
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
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return nil
}

// decodeECKey parses a SEC1 EC PRIVATE KEY PEM.
func decodeECKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, fmt.Errorf("%w: no key block", ErrTrustSync)
	}
	return x509.ParseECPrivateKey(blk.Bytes)
}

// pemECKey encodes the root key as SEC1 PEM (stdlib pem.EncodeToMemory).
func pemECKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
