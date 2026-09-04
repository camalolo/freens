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
//
// v0.16 §9.5.4 hardening (this package):
//   - YOUNG-CLAIM QUARANTINE: OnOwnerCA carries the resolver's contested
//     flag; a claim inside the §7.5 contest window gets DNS answers but no
//     cross-cert — no green padlock for Sybil-minted fresh claims.
//   - ROTATION OBSERVATION GATE: a TLSCA change under a live installed
//     binding (deterministic derivation + 10 y CA window ⇒ either the
//     routine post-expiry re-mint or tampered rrset bytes) serves a loud,
//     grace-delayed swap instead of an instant one.
//   - LIVENESS SWEEP: expired cross-certs now purge state + direct system
//     + NSS installs (not just the spool file), on traffic AND on a timer
//     (RunSweeper) — a box that stops resolving a namespace still converges.

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
	"runtime"
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

// rotationGrace is the §9.5.4 CA-rotation observation gate: a TLSCA change
// under a LIVE installed binding is not trusted until the same new CA has
// been observed for this long across resolutions. The owner CA key is
// derived deterministically from SK_tld and its certificate is valid for
// TLSCAValidityDays (10 y), so a same-identity CA change before expiry is
// either the rare routine re-mint or tampered rrset bytes — the gate turns
// the tampered case from a silent instant padlock swap into a LOUD,
// grace-delayed one (the journal WARN fires immediately; `freens trust ls`
// shows the pending state for the whole window). A rotation whose installed
// CA has already EXPIRED skips the grace (the routine re-mint path).
const rotationGrace = time.Hour

// Trust states (crossState.Status; "" loads as installed for state files
// written before the field existed).
const (
	statusInstalled   = "installed"
	statusQuarantined = "quarantined"
	statusRotating    = "rotating"
)

// statusOf normalizes the legacy empty status.
func statusOf(s string) string {
	if s == "" {
		return statusInstalled
	}
	return s
}

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
	// SysCAPath overrides the system CA bundle directory (unix; empty =
	// /usr/local/share/ca-certificates). Test seam.
	SysCAPath string
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
	NotAfter int64  `json:"not_after"` // 0 = nothing installed (quarantine hold)
	// Status is the §9.5.4 trust state ("" = installed, for pre-v0.16 state
	// files): "quarantined" while the winning claim is inside the §7.5
	// contest window, "rotating" while a CA change serves its observation
	// grace.
	Status  string     `json:"status,omitempty"`
	Pending *pendingCA `json:"pending_ca,omitempty"`
}

// pendingCA records a CA change under a live identity that has NOT yet
// served its observation grace (rotationPending).
type pendingCA struct {
	CASha256 string `json:"ca_sha256"`
	Since    int64  `json:"since"`
}

// caAction is the OnOwnerCA decision outcome (decided under the lock,
// acted on outside it). The actions are declared inside OnOwnerCA, which
// is the only consumer.
type caAction int

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
	e.sweepSpool()
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
	if runtime.GOOS == "windows" {
		return e.installRootWindows()
	}
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
//
// claimYoung is the resolver's §7.5 signal: the winning claim is inside the
// CONTEST_WINDOW (a pin-resolved alias is never young). Two gates protect
// the install:
//
//   - the YOUNG-CLAIM QUARANTINE: while the claim is young, the namespace's
//     CA is recorded but NOT trusted — a Sybil-witnessed fresh claim gets
//     DNS answers but no green padlock until the claim has matured past the
//     contest window. The next resolution after maturity installs.
//   - the ROTATION OBSERVATION GATE: a CA change under a LIVE installed
//     binding serves rotationGrace before the swap (loud journal WARN on
//     first sight, Info on completion/abort). Deterministic derivation +
//     the 10-year CA window make a live same-identity CA change either the
//     routine post-expiry re-mint (no grace: the old CA is already dead) or
//     tampered rrset bytes (grace + noise).
func (e *Engine) OnOwnerCA(alias string, tldID, caDER []byte, recordExpires int64, claimYoung bool) {
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
	present := e.sweepSpool()

	// Decide under the lock; act outside it (minting + installers sleep).
	const (
		actNone caAction = iota
		actInstall
		actQuarantine
		actDefer
	)
	act := actNone
	rotateFrom := "" // installed CA the rotation replaces (journal detail)
	e.mu.Lock()
	st, have := e.state[alias]
	switch {
	case !have:
		if claimYoung {
			act = actQuarantine
		} else {
			act = actInstall
		}
	case st.TldIDB32 != tldB32:
		// identity changed under the alias (§8.3 transfer / §8.6 rotation):
		// those paths are protocol-gated upstream — install the new binding.
		act = actInstall
	case st.CASha256 == caHash:
		if st.Pending != nil {
			// The rrset flipped back to the installed CA: rotation aborted.
			st.Pending = nil
			st.Status = statusInstalled
			e.state[alias] = st
			e.mu.Unlock()
			e.saveState()
			e.log.Info("tls: CA rotation aborted (previous CA still authoritative)", "alias", alias)
			return
		}
		switch {
		case statusOf(st.Status) == statusQuarantined:
			if claimYoung {
				act = actNone // still inside the window: hold
			} else {
				act = actInstall // quarantine lifted: the claim matured
			}
		case claimYoung:
			// installed in an earlier, mature era — claims never re-young
			act = actNone
		case st.NotAfter > 0 && now.Add(refreshWithin).Before(time.Unix(st.NotAfter, 0)) && present[alias]:
			act = actNone // healthy, fresh, unchanged, and the spool agrees
		default:
			act = actInstall // near expiry, or the spool file went missing
		}
	default:
		// DIFFERENT CA under the SAME live identity: the rotation gate.
		if statusOf(st.Status) == statusQuarantined {
			if claimYoung {
				// still young: keep holding, note the new bytes
				e.state[alias] = crossState{TldIDB32: tldB32, CASha256: caHash, Status: statusQuarantined}
				e.mu.Unlock()
				e.saveState()
				e.log.Info("tls: quarantined namespace re-advertised a different CA — still holding", "alias", alias, "ca", caHash[:16])
				return
			}
			act = actInstall // matured between notifications
			break
		}
		installedLive := st.NotAfter > now.Unix()
		if !installedLive {
			act = actInstall // the installed CA already expired: routine re-mint
			break
		}
		if st.Pending == nil || st.Pending.CASha256 != caHash {
			rotateFrom = st.CASha256
			st.Pending = &pendingCA{CASha256: caHash, Since: now.Unix()}
			st.Status = statusRotating
			e.state[alias] = st
			act = actDefer
		} else if now.Unix()-st.Pending.Since >= int64(rotationGrace/time.Second) {
			rotateFrom = st.CASha256
			st.Pending = nil
			st.Status = statusInstalled
			e.state[alias] = st
			act = actInstall // observed stable across the grace: complete
		} else {
			act = actNone // pending, grace not elapsed
		}
	}
	e.mu.Unlock()

	switch act {
	case actNone:
		return
	case actQuarantine:
		e.mu.Lock()
		e.state[alias] = crossState{TldIDB32: tldB32, CASha256: caHash, Status: statusQuarantined}
		e.mu.Unlock()
		e.saveState()
		e.log.Info("tls: cross-cert QUARANTINED — claim inside the §7.5 contest window", "alias", alias,
			"ca", caHash[:16],
			"hint", "DNS answers are served but TLS trust waits for the claim to mature; `freens trust ls` shows the hold")
	case actDefer:
		e.saveState()
		e.log.Warn("tls: CA CHANGE under a live identity — rotation deferred (§9.5.4 observation gate)", "alias", alias,
			"installed_ca", rotateFrom[:16], "new_ca", caHash[:16], "grace", rotationGrace.String(),
			"hint", "a rotation of your own completes after the grace; anything else — investigate NOW (`freens trust ls`)")
	default: // actInstall
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
		e.state[alias] = crossState{TldIDB32: tldB32, CASha256: caHash, NotAfter: cross.NotAfter.Unix(), Status: statusInstalled}
		e.installed[alias] = sysOK
		e.mu.Unlock()
		if werr := e.saveState(); werr != nil {
			e.log.Warn("tls: state save failed", "err", werr)
		}
		if rotateFrom != "" {
			e.log.Info("tls: CA rotation completed after observation grace", "alias", alias,
				"old_ca", rotateFrom[:16], "new_ca", caHash[:16], "not_after", cross.NotAfter.Format(time.RFC3339))
		} else {
			e.log.Info("tls: cross-certified namespace", "alias", alias,
				"ca", caHash[:16], "not_after", cross.NotAfter.Format(time.RFC3339),
				"system", sysOK, "spool", spool)
		}
	}
}

// sweepSpool deletes spool cross-certs whose notAfter has passed (or that
// cannot be parsed), and — the v0.16 liveness half — purges the engine's
// state, direct system-bundle entry and NSS entries for those aliases too.
// The spool is the privileged bridge's source of truth, so an expired entry
// there lands in the system CA store — and because a cross-cert shares its
// owner CA's subject AND its (deterministic) key, a stale copy POISONS the
// verification of an otherwise-fresh chain: OpenSSL selects the expired
// same-subject anchor and reports the whole chain expired (found live
// 2026-09-01: minipc curled its own webui and got "certificate expired"
// while every cert in the presented chain was valid; the expired Aug-31
// spool copy sitting in the system store was the culprit). Cross-certs are
// lifetime-capped by the apex RECORD's expiry (a 24 h lease), so an expired
// entry means the alias's lease LAPSED — the resolver refuses the namespace
// until renewal, and a renewal re-mints + reinstalls from the next
// OnOwnerCA notification. Purging on expiry therefore converges the spool,
// the system store and NSS to exactly the live set instead of leaving
// dead-namespace anchors behind for a later resolution to trip over.
// Cheap (a directory of small certs): called at engine start, on every
// OnOwnerCA notification, and from RunSweeper's ticker — expiry cleanup
// never waits for traffic.
//
// Returns the set of aliases with a spool file present AFTER the sweep
// (the OnOwnerCA dedup fast-path requires it: state that is fresh but
// whose spool file vanished re-mints instead of silently trusting nothing).
func (e *Engine) sweepSpool() map[string]bool {
	entries, err := os.ReadDir(e.spoolDir())
	if err != nil {
		return nil
	}
	now := e.opts.Now()
	present := map[string]bool{}
	expired := []string{}
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasPrefix(name, "freens-cross-") || !strings.HasSuffix(name, ".crt") {
			continue
		}
		alias := strings.TrimSuffix(strings.TrimPrefix(name, "freens-cross-"), ".crt")
		path := filepath.Join(e.spoolDir(), name)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		cert, perr := tlsca.ParseCertPEM(b)
		if perr != nil || !cert.NotAfter.After(now) {
			_ = os.Remove(path)
			e.log.Info("tls: swept expired spool cross-cert", "file", name)
			expired = append(expired, alias)
			continue
		}
		present[alias] = true
	}
	for _, alias := range expired {
		e.purgeIfExpired(alias, now)
	}
	return present
}

// purgeIfExpired drops state + direct installs for an alias whose
// installed cross-cert has expired (the spool file is already gone). A
// missing state entry, or one whose NotAfter is still in the future (an
// unparsable spool file from external tinkering — the engine would re-mint
// on the next notification), is left alone.
func (e *Engine) purgeIfExpired(alias string, now time.Time) {
	e.mu.Lock()
	st, ok := e.state[alias]
	if !ok || st.NotAfter == 0 || time.Unix(st.NotAfter, 0).After(now) {
		e.mu.Unlock()
		return
	}
	delete(e.state, alias)
	delete(e.installed, alias)
	e.mu.Unlock()

	// Uninstall unconditionally (best-effort, idempotent): the installed
	// map does not survive a daemon restart, but a stale system/NSS copy
	// poisons verification exactly the same (the minipc expired-anchor
	// lesson, found live 2026-09-01).
	e.uninstallSystem(alias)
	if e.opts.NSSInstall {
		e.uninstallNSS(alias)
	}
	if err := e.saveState(); err != nil {
		e.log.Warn("tls: state save failed", "err", err)
	}
	e.log.Info("tls: purged expired cross-cert (lease lapsed)", "alias", alias)
}

// RunSweeper drives the liveness sweep on a timer until stop closes:
// a box whose users stop resolving a namespace must still converge its
// trust stores when the namespace's lease lapses (the OnOwnerCA-triggered
// sweep only runs while the alias is being resolved — exactly when it is
// NOT dead). Wire with `go tsEngine.RunSweeper(bgStop, 30*time.Minute)` from
// the daemon (bgStop = the daemon's background-goroutine stop channel).
func (e *Engine) RunSweeper(stop <-chan struct{}, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			e.sweepSpool()
		}
	}
}

// RemoveAlias purges everything the engine holds for alias — the operator
// path behind `freens trust remove <alias>` (OnAliasDead with no identity
// check). Reports whether there was anything to remove.
func (e *Engine) RemoveAlias(alias string) bool {
	e.mu.Lock()
	_, ok := e.state[alias]
	spool := e.spoolPath(alias)
	sysOK := e.installed[alias]
	delete(e.state, alias)
	delete(e.installed, alias)
	e.mu.Unlock()
	if !ok {
		return false
	}
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
	e.log.Info("tls: cross-cert removed by operator", "alias", alias)
	return true
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

// Snapshot lists the installed bindings (admin /tls, doctor, `trust ls`).
type Snapshot struct {
	Alias    string `json:"alias"`
	TldIDB32 string `json:"tld_id_b32"`
	CASha256 string `json:"ca_sha256"`
	NotAfter int64  `json:"not_after"`
	System   bool   `json:"system_store"`
	// Status is "installed", "quarantined" (claim inside the §7.5 contest
	// window — DNS answers serve, TLS trust waits) or "rotating" (a CA
	// change is serving its observation grace).
	Status string `json:"status"`
	// PendingCASha256 / PendingSince describe an in-grace rotation.
	PendingCASha256 string `json:"pending_ca_sha256,omitempty"`
	PendingSince    int64  `json:"pending_since,omitempty"`
}

func (e *Engine) Snapshot() []Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Snapshot, 0, len(e.state))
	for alias, st := range e.state {
		snap := Snapshot{
			Alias:    alias,
			TldIDB32: st.TldIDB32,
			CASha256: st.CASha256,
			NotAfter: st.NotAfter,
			System:   e.installed[alias],
			Status:   statusOf(st.Status),
		}
		if st.Pending != nil {
			snap.PendingCASha256 = st.Pending.CASha256
			snap.PendingSince = st.Pending.Since
		}
		out = append(out, snap)
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

// nssSafe reduces an alias to the [a-z0-9-] form used in store entry names.
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
