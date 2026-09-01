// trust.go — the §9.5 TLS verbs:
//
//	freens trust-install     one-time per-device bootstrap: generate (once)
//	                         the local trust root and import it into the
//	                         system bundle and NSS user DBs (Chromium/Firefox)
//	freens cert <name>       issue + export a leaf certificate (PEM) for any
//	                         name under an owned alias — for nginx/caddy etc.
//	freens cert renew        renew tracked certificates (all due, or the
//	                         named ones) — cron/timer entry point
//	freens cert list         tracked certificates: paths, expiry, deployment
//	freens cert nginx <name> wire an existing nginx server block to the
//	                         name's certificate (backup → edit → nginx -t →
//	                         reload, restoring the backup if -t fails)
//	freens cert forget       stop tracking a certificate (files are kept)
//
// All are local-only operations: no daemon, no network.
package cli

import (
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/camalolo/freens/internal/certmgr"
	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/keychain"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/trustsync"
)

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
	if err := fs.Parse(args); err != nil {
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
