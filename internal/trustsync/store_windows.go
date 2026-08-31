//go:build windows

// The Windows OS-trust plumbing: Chrome and Edge verify against the
// WINDOWS certificate store (CryptoAPI), not NSS — so the root and every
// cross-cert go in via the built-in certutil.exe. Machine store first
// (all users; the daemon service runs as LocalSystem and setup usually
// runs elevated), per-user store as the unprivileged fallback. Firefox on
// Windows manages its own store — not automated here.
//
// Store choices: Root for the local trust root (the §9.5.4 anchor), CA
// (Intermediate Certification Authorities) for the name-constrained
// cross-certs — exactly the roles they play in chain building.

package trustsync

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// runCertutil shells out to Windows' own certutil (System32; no relation
// to NSS's certutil beyond the name).
func runCertutil(args ...string) error {
	return exec.Command("certutil", args...).Run()
}

// installSystem puts the cross-cert into the intermediate store (machine
// first, per-user fallback). The cert's subject (CN = alias) is what a
// later uninstallSystem matches on.
func (e *Engine) installSystem(alias string, crossPEM []byte) bool {
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("freens-cross-%d-%s.crt", os.Getpid(), nssSafe(alias)))
	if err := os.WriteFile(tmp, crossPEM, 0o644); err != nil {
		return false
	}
	defer os.Remove(tmp)
	if err := runCertutil("-addstore", "CA", tmp); err == nil {
		return true
	}
	e.log.Debug("tls: machine CA store add failed; trying the user store", "alias", alias)
	return runCertutil("-user", "-addstore", "CA", tmp) == nil
}

// uninstallSystem removes the cross-cert from both stores (best effort;
// certutil matches the subject CN).
func (e *Engine) uninstallSystem(alias string) {
	_ = runCertutil("-delstore", "CA", alias)
	_ = runCertutil("-user", "-delstore", "CA", alias)
}

// nssDBs has no Windows meaning (Firefox manages its own store).
func (e *Engine) nssDBs() []string { return nil }

// certutilPath: the NSS certutil never exists on Windows (the name belongs
// to Windows' own tool) — NSS installs are skipped.
func certutilPath() string { return "" }

func (e *Engine) installNSS(string, []byte) {}

func (e *Engine) uninstallNSS(string) {}

// installRootWindows imports the local root: machine Root store when the
// token allows, else the user's Root store (Chrome/Edge honor both for
// that user).
func (e *Engine) installRootWindows() []string {
	root := filepath.Join(e.tlsDir(), "root.crt")
	var report []string
	if err := runCertutil("-addstore", "Root", root); err == nil {
		report = append(report, "system: installed into the MACHINE Root store (all users)")
	} else if err := runCertutil("-user", "-addstore", "Root", root); err == nil {
		report = append(report, "system: installed into the USER Root store (this user's browsers)")
	} else {
		report = append(report, "system: NOT installed — in an elevated PowerShell run:")
		report = append(report, "  certutil -addstore Root "+root)
	}
	report = append(report, "nss: not applicable on windows (Chrome/Edge use the Windows store; Firefox manages its own)")
	return report
}
