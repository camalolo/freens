//go:build !windows

// The unix OS-trust plumbing (see store_windows.go for the Windows
// counterpart): the system CA bundle (/usr/local/share/ca-certificates +
// update-ca-certificates) and NSS user DBs (Chromium's ~/.pki/nssdb and
// Firefox profiles).

package trustsync

import (
	"fmt"
	"os"
	"path/filepath"
)

// SystemCertPath reports where the direct system-bundle copy lives for
// alias (empty when the platform has no file-based system bundle — the
// `freens trust remove` verb stats it to print the root-removal recipe).
func (e *Engine) SystemCertPath(alias string) string {
	return e.sysPath(alias)
}

func (e *Engine) sysPath(alias string) string {
	if e.opts.SysCAPath != "" {
		// Test seam (Options.SysCAPath): a private bundle directory.
		return filepath.Join(e.opts.SysCAPath, "freens-cross-"+alias+".crt")
	}
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
	if err := runBounded("update-ca-certificates"); err != nil {
		e.log.Debug("tls: update-ca-certificates failed", "alias", alias, "err", err)
		return true // file placed; a later bridge run completes the refresh
	}
	return true
}

func (e *Engine) uninstallSystem(alias string) {
	_ = os.Remove(e.sysPath(alias))
	_ = runBounded("update-ca-certificates")
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
		_ = runBounded(cu, "-d", db, "-D", "-n", name)
		if err := runBounded(cu, "-d", db, "-A", "-n", name, "-t", "C,,", "-i", tmp); err != nil {
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
		_ = runBounded(cu, "-d", db, "-D", "-n", name)
	}
}

// installRootWindows is unreachable off-windows (InstallRoot branches on
// runtime.GOOS first); it exists so both builds compile.
func (e *Engine) installRootWindows() []string { return nil }
