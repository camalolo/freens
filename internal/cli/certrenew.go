// certrenew.go — the renewal/management half of `freens cert`:
//
//	cert renew [name…]   renew every tracked certificate that is due (or the
//	                     named ones; -force overrides the due check) — the
//	                     cron/timer entry point, certbot-renew shaped
//	cert list            the tracked table: paths, expiry, deployment
//	cert nginx <name>    wire an existing nginx server block to the name's
//	                     certificate (backup → edit → nginx -t → reload)
//	cert forget <name>   stop tracking (the cert files are kept)
package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/certmgr"
	"github.com/camalolo/freens/internal/home"
)

func cmdCertRenew(args []string) error {
	fs := flag.NewFlagSet("cert renew", flag.ContinueOnError)
	force := fs.Bool("force", false, "renew even when the certificate is not due yet")
	hook := fs.String("deploy-hook", "", "command to run after each successful renewal (recorded per name)")
	noReload := fs.Bool("no-reload", false, "skip the nginx reload even for deployed certificates")
	quiet := fs.Bool("quiet", false, "print only failures (for cron)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	names := fs.Args()
	if len(names) == 0 {
		states, err := certmgr.ListState(home.Dir())
		if err != nil {
			return err
		}
		if len(states) == 0 {
			if !*quiet {
				fmt.Println("no tracked certificates — issue one with `freens cert <name>` first")
			}
			return nil
		}
		for _, s := range states {
			names = append(names, s.Name)
		}
	}
	now := time.Now()
	var fails []error
	for _, name := range names {
		var r *certmgr.Renewal
		err := resolveCertPass(func(pass string) error {
			var rerr error
			r, rerr = certmgr.RenewOne(home.Dir(), home.KeysDir(), name, pass,
				certmgr.RenewOpts{Force: *force, Hook: *hook, NoReload: *noReload}, now)
			return rerr
		})
		switch {
		case err == nil:
			left := time.Until(time.Unix(r.NotAfter, 0)).Round(time.Hour)
			if !*quiet {
				fmt.Printf("✔ renewed %s (valid %s more)", name, left)
				if len(r.NginxFiles) > 0 {
					fmt.Printf(" — nginx reloaded (%s)", strings.Join(r.NginxFiles, ", "))
				}
				fmt.Println()
			}
		case errors.Is(err, certmgr.ErrNotDue):
			if !*quiet {
				st, _ := certmgr.LoadState(home.Dir(), name)
				left := "unknown"
				if st != nil {
					left = time.Until(time.Unix(st.NotAfter, 0)).Round(time.Hour).String()
				}
				fmt.Printf("• %s still fresh (%s left) — skipped (-force to renew anyway)\n", name, left)
			}
		default:
			fails = append(fails, fmt.Errorf("%s: %v", name, err))
			fmt.Fprintf(os.Stderr, "✘ %s: %v\n", name, err)
		}
	}
	if len(fails) > 0 {
		return errors.Join(fails...)
	}
	return nil
}

func cmdCertList(args []string) error {
	fs := flag.NewFlagSet("cert list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	states, err := certmgr.ListState(home.Dir())
	if err != nil {
		return err
	}
	if len(states) == 0 {
		fmt.Printf("no tracked certificates — issue one with `%s cert <name>`\n", ProgName)
		return nil
	}
	now := time.Now()
	fmt.Printf("%-24s %-16s %-9s %s\n", "NAME", "EXPIRES", "NGINX", "CERT")
	for _, s := range states {
		left := time.Until(time.Unix(s.NotAfter, 0)).Round(time.Hour)
		due := ""
		if certmgr.IsDue(s, now) {
			due = " DUE"
		}
		nginx := "-"
		if len(s.NginxFiles) > 0 {
			nginx = fmt.Sprintf("%d file(s)", len(s.NginxFiles))
		}
		fmt.Printf("%-24s %-16s %-9s %s\n", s.Name, left.String()+due, nginx, s.CertPath)
		if s.DeployHook != "" {
			fmt.Printf("  hook: %s\n", s.DeployHook)
		}
	}
	return nil
}

func cmdCertNginx(args []string) error {
	fs := flag.NewFlagSet("cert nginx", flag.ContinueOnError)
	conf := fs.String("config", "", "path to the main nginx.conf (default: discovered from `nginx -V`)")
	server := fs.String("server", "", "server_name to match (default: the freens name itself)")
	cloneFrom := fs.String("clone", "", "no block carries this name yet? clone the vhost serving THIS server_name into a new file for the freens name (the source vhost is never modified)")
	force := fs.Bool("force", false, "replace a foreign ssl_certificate the block already serves")
	dryRun := fs.Bool("dry-run", false, "show what would change; edit nothing")
	noReload := fs.Bool("no-reload", false, "edit + validate, but do not reload nginx")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 1 {
		return usageErr("cert nginx takes exactly one name: <name> or <label>.<alias> (e.g. www.alice)")
	}
	displayName := fs.Args()[0]
	env := &certmgr.NginxEnv{ConfPath: *conf}
	var res *certmgr.InstallResult
	if err := resolveCertPass(func(pass string) error {
		var ierr error
		res, ierr = env.Install(home.Dir(), home.KeysDir(), displayName, pass,
			certmgr.InstallOpts{
				MatchName: *server, CloneFrom: strings.TrimSpace(*cloneFrom),
				Force: *force, DryRun: *dryRun, NoReload: *noReload,
			}, time.Now())
		return ierr
	}); err != nil {
		return err
	}
	if *dryRun {
		fmt.Printf("dry run for %s — would change:\n", displayName)
	} else if res.Cloned {
		fmt.Printf("cloned the %q vhost for %s\n", res.ClonedSrc, displayName)
	} else {
		fmt.Printf("installed the %s certificate into nginx\n", displayName)
	}
	for _, m := range res.Matched {
		fmt.Printf("  block: %s\n", m)
	}
	for _, f := range res.Edited {
		fmt.Printf("  file: %s\n", f)
		if !res.Cloned {
			fmt.Printf("  backup: %s.freens-pre\n", f)
		}
	}
	switch {
	case res.Already && len(res.Edited) == 0:
		fmt.Println("  already serving this exact certificate — nothing to do")
	case res.Reloaded:
		fmt.Println("  nginx -t ok, reloaded")
	case res.Validated:
		fmt.Println("  nginx -t ok (reload skipped)")
	}
	if res.UsedSudo {
		fmt.Println("  (written via passwordless sudo — the config dir is root-owned)")
	}
	return nil
}

func cmdCertForget(args []string) error {
	fs := flag.NewFlagSet("cert forget", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 1 {
		return usageErr("cert forget takes exactly one name")
	}
	if err := certmgr.Forget(home.Dir(), fs.Args()[0]); err != nil {
		if errors.Is(err, certmgr.ErrNotTracked) {
			return usageErr("no tracked certificate for %q", fs.Args()[0])
		}
		return err
	}
	fmt.Printf("forgot %s (the cert files themselves are kept)\n", fs.Args()[0])
	return nil
}
