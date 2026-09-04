// trust.go — the §9.5 TLS verbs:
//
//	freens trust-install     one-time per-device bootstrap: generate (once)
//	                         the local trust root and import it into the
//	                         system bundle and NSS user DBs (Chromium/Firefox)
//	freens trust ls          every cross-certified namespace this box holds:
//	                         status (installed / quarantined / rotating), CA
//	                         fingerprint, expiry (§9.5.4 v0.16)
//	freens trust remove      purge a namespace's cross-cert from the spool,
//	                         state, system bundle and NSS DBs
//	freens cert <name>       issue + export a leaf certificate (PEM) for any
//	                         name under an owned alias — for nginx/caddy etc.
//	freens cert renew        renew tracked certificates (all due, or the
//	                         named ones) — cron/timer entry point
//	freens cert list         tracked certificates: paths, expiry, deployment
//	freens cert nginx <name> wire an existing nginx server block to the
//	                         certificate (backup → edit → nginx -t →
//	                         reload, restoring the backup if -t fails)
//	freens cert forget       stop tracking a certificate (files are kept)
//
// All are local-only operations: no daemon, no network (they read the same
// <home>/tls state the daemon's trust-sync engine maintains).
package cli

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/certmgr"
	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/keychain"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/trustsync"
)

func cmdTrust(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "install":
			return cmdTrustInstall(args[1:])
		case "ls", "list":
			return cmdTrustList(args[1:])
		case "remove", "rm":
			return cmdTrustRemove(args[1:])
		}
	}
	return usageErr("trust takes a subcommand: trust ls · trust remove <alias> · trust install (= trust-install)")
}

// cmdTrustList implements `freens trust ls`: every cross-certified
// namespace this installation holds, with its §9.5.4 trust status. Local
// read of <home>/tls (the daemon maintains it; no admin socket involved).
func cmdTrustList(args []string) error {
	fs := flag.NewFlagSet("trust ls", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON (scripts)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	engine, err := trustsync.New(trustsync.Options{
		HomeDir:     home.Dir(),
		NSSInstall:  false,
		SystemStore: false,
	})
	if err != nil {
		return err
	}
	snap := engine.Snapshot()
	if *asJSON {
		b, jerr := json.MarshalIndent(map[string]any{
			"root_fingerprint": engine.RootFingerprint(),
			"cross_certs":      snap,
		}, "", "  ")
		if jerr != nil {
			return jerr
		}
		fmt.Println(string(b))
		return nil
	}
	fmt.Printf("local trust root: %s (sha256 %s)\n", rootPathOf(home.Dir()), engine.RootFingerprint())
	if len(snap) == 0 {
		fmt.Println("no cross-certified namespaces (they appear as freens HTTPS names are resolved)")
		return nil
	}
	fmt.Printf("%-20s %-12s %-18s %-21s %s\n", "ALIAS", "STATUS", "CA (sha256/16)", "NOT_AFTER", "SYSTEM")
	for _, s := range snap {
		ca := s.CASha256
		if len(ca) > 16 {
			ca = ca[:16]
		}
		notAfter := "—"
		if s.NotAfter > 0 {
			notAfter = time.Unix(s.NotAfter, 0).UTC().Format(time.RFC3339)
		}
		status := s.Status
		if s.PendingCASha256 != "" {
			status += fmt.Sprintf(" (→%s since %s)", s.PendingCASha256[:16],
				time.Unix(s.PendingSince, 0).UTC().Format("15:04:05"))
		}
		sys := "spool"
		if s.System {
			sys = "direct"
		}
		fmt.Printf("%-20s %-12s %-18s %-21s %s\n", s.Alias, status, ca, notAfter, sys)
	}
	fmt.Println()
	fmt.Println("quarantined = claim inside the §7.5 contest window (DNS answers serve; TLS trust waits)")
	fmt.Println("rotating    = CA change serving its §9.5.4 observation grace (see the daemon journal)")
	return nil
}

// cmdTrustRemove implements `freens trust remove <alias>`: purge a
// namespace's cross-cert from the spool, engine state, direct system-bundle
// entry and NSS DBs. The one command a poisoned or unwanted namespace needs
// on this box (the daemon re-installs ONLY from live network evidence — a
// removed alias stays removed until its namespace resolves again).
func cmdTrustRemove(args []string) error {
	fs := flag.NewFlagSet("trust remove", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 1 {
		return usageErr("trust remove takes exactly one alias (the freens TLD name, e.g. camalolo)")
	}
	alias := strings.ToLower(fs.Args()[0])
	engine, err := trustsync.New(trustsync.Options{
		HomeDir:     home.Dir(),
		NSSInstall:  true,
		SystemStore: os.Geteuid() == 0,
	})
	if err != nil {
		return err
	}
	if !engine.RemoveAlias(alias) {
		fmt.Printf("%s: nothing installed (no cross-cert state for this alias)\n", alias)
		return nil
	}
	fmt.Printf("%s: cross-cert purged (spool + state + NSS)\n", alias)
	// The privileged bridge may have copied the cert into the system bundle
	// under root; a user-mode CLI cannot remove that copy itself.
	if sys := engine.SystemCertPath(alias); sys != "" {
		if _, serr := os.Stat(sys); serr == nil {
			fmt.Println("system bundle still holds a copy (root-owned). Finish with:")
			fmt.Printf("  sudo rm %s && sudo update-ca-certificates\n", sys)
		} else {
			fmt.Println("system bundle: copy already gone")
		}
	}
	return nil
}

func cmdTrustInstall(args []string) error {
	fs := flag.NewFlagSet("trust-install", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	engine, err := trustsync.New(trustsync.Options{
		HomeDir:     home.Dir(),
		NSSInstall:  true,
		SystemStore: os.Geteuid() == 0,
	})
	if err != nil {
		return err
	}
	rootPEM := engine.RootPEM()
	fp := engine.RootFingerprint()
	fmt.Printf("local trust root: %s\n", rootPathOf(home.Dir()))
	fmt.Printf("  sha256: %s\n", fp)
	if blk, _ := pem.Decode(rootPEM); blk == nil {
		return fmt.Errorf("internal: root PEM unreadable")
	}
	// §9.5.4 privileged bridge (systemd boxes): the cross-cert spool ages
	// out of the system CA store within hours unless something re-syncs it
	// — the bridge is that something, and its units (or their start-limit
	// relief) may predate the fix. Ensure them here too, not just in setup:
	// a user re-running trust-install is exactly the person debugging TLS
	// trust. Non-systemd boxes: installTrustBridge prints the manual recipe
	// or no-ops (it never blocks the root install below).
	goosLinux := !goosWindows && !goosDarwin
	if goosLinux {
		installTrustBridge()
	}
	fmt.Println("installing (idempotent):")
	for _, line := range engine.InstallRoot() {
		fmt.Println("  " + line)
	}
	fmt.Println()
	fmt.Println("Devices you browse FROM need this root once; after that every")
	fmt.Println("freens name with a TLSCA record gets HTTPS automatically (§9.5).")
	return nil
}

func rootPathOf(homeDir string) string {
	return filepath.Join(homeDir, "tls", "root.crt")
}

func cmdCert(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "renew":
			return cmdCertRenew(args[1:])
		case "list":
			return cmdCertList(args[1:])
		case "nginx":
			return cmdCertNginx(args[1:])
		case "forget":
			return cmdCertForget(args[1:])
		}
	}
	return cmdCertIssue(args)
}

func cmdCertIssue(args []string) error {
	fs := flag.NewFlagSet("cert", flag.ContinueOnError)
	outDir := fs.String("out-dir", ".", "directory for <name>.crt / <name>.key")
	days := fs.Int("days", 7, "leaf validity in days (capped by the §9.5.3 7-day ceiling for daemon-issued certs)")
	noTrack := fs.Bool("no-track", false, "skip renewal tracking (one-shot export; `cert renew` will not know this cert)")
	if err := fs.Parse(flagsFirst(args, "out-dir", "days")); err != nil {
		return err
	}
	if len(fs.Args()) != 1 {
		return usageErr("cert takes exactly one name: <name> or <label>.<alias> (e.g. www.alice)\n" +
			"  subcommands: cert renew [name…] · cert list · cert nginx <name> · cert forget <name>")
	}
	displayName := fs.Args()[0]
	if _, _, err := naming.DecomposeName(displayName); err != nil {
		return usageErr("invalid name %q: %v", displayName, err)
	}
	_ = days // validity is fixed at the §9.5.3 ceiling inside tlsca.Leaf

	out := *outDir
	if out != "" {
		if abs, aerr := filepath.Abs(out); aerr == nil {
			out = abs
		}
	}
	now := time.Now()
	var iss *certmgr.Issued
	// Encrypted owner keys: certmgr surfaces the sentinel; unlock here the
	// way every other verb does (FREENS_PASSPHRASE or the terminal prompt).
	if err := resolveCertPass(func(pass string) error {
		if *noTrack {
			var ierr error
			iss, ierr = certmgr.Issue(home.KeysDir(), displayName, out, pass, now)
			return ierr
		}
		r, issued, ierr := certmgr.TrackIssue(home.Dir(), home.KeysDir(), displayName, out, pass, "", now)
		if ierr == nil {
			iss = issued
			if r.DeployHook != "" {
				fmt.Printf("deploy hook: %s\n", r.DeployHook)
			}
		}
		return ierr
	}); err != nil {
		return err
	}
	printIssued(iss)
	if !*noTrack {
		fmt.Printf("tracked: renews with `%s cert renew` (or the daily timer)\n", ProgName)
	}
	return nil
}

func printIssued(iss *certmgr.Issued) {
	fmt.Printf("name=%s\n", iss.Name)
	fmt.Printf("sans=%s\n", joinSans(iss.SANs))
	fmt.Printf("not_after=%s\n", iss.NotAfter.UTC().Format(time.RFC3339))
	fmt.Printf("cert=%s\nkey=%s (0600)\n", iss.CertPath, iss.KeyPath)
	fmt.Println("Chain for clients: leaf -> <alias> owner CA (TLSCA in the apex record) -> their trust root (§9.5).")
}

// resolveCertPass runs attempt("") first; when the owner key is encrypted,
// it unlocks via the standard passphrase path and retries. attempt must be
// side-effect-free on the failure path (certmgr.Issue fails at the keyfile
// read, before any file is written).
func resolveCertPass(attempt func(pass string) error) error {
	err := attempt("")
	if err == nil || !errors.Is(err, keychain.ErrNeedsPassphrase) {
		return err
	}
	pass, perr := passphraseForUnlock()
	if perr != nil {
		return perr
	}
	return attempt(pass)
}

func joinSans(sans []string) string {
	out := ""
	for i, s := range sans {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
