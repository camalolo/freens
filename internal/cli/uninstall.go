// uninstall.go — `freens uninstall`: the one-command removal that matches
// what `freens setup` (and the surrounding ecosystem) put on the machine.
// `setup -uninstall` predates it but is buried as a flag and only knew
// about freens.service; a box that ran setup + freens-web + the doctor
// timer needs everything around the daemon gone too:
//
//  1. stop + disable every ACTIVE freens* systemd unit (services and
//     timers: daemon, freens-web, comm chairs, freens-health.timer —
//     discovered, not hardcoded)
//  2. remove the freens* unit files (+ any pre-v0.3.0 --user unit)
//  3. reverse the OS resolver wiring (nft :53 redirect table, legacy
//     resolved drop-in, resolv.conf restore from the pristine backup)
//  4. -trust: remove the §9.5 local trust root and cross-cert copies
//     from this machine's CA stores (the spool directory goes too)
//  5. -purge: delete the ENTIRE state dir — keys, names, store. The
//     one-way step; gated behind -yes in scripts.
//
// Everything but (4) and (5) is reversible by re-running `freens setup`.
package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/camalolo/freens/internal/home"
)

func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	purge := fs.Bool("purge", false, "ALSO delete the state dir — keys, names, store ("+home.Dir()+"); the one-way step")
	trust := fs.Bool("trust", false, "also remove the §9.5 trust root + cross-certs from this machine's CA stores")
	yes := fs.Bool("yes", false, "answer yes to the -purge confirmation (for scripts)")
	// -console-wait: internal — set on the UAC-elevated relaunch (Windows).
	consoleWait := fs.Bool("console-wait", false, "pause before exit (used when uninstall relaunches itself elevated)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("uninstall takes no positional arguments")
	}
	if goosWindows {
		return uninstallWindows(*purge, *trust, *yes, *consoleWait)
	}
	if goosDarwin {
		uninstallWebUIDarwin()
		fmt.Println("note: the freens DAEMON on macOS is a manual process — stop it if it runs.")
		return nil
	}
	return uninstallUnix(*purge, *trust, *yes)
}

// uninstallWindows is `freens uninstall` on Windows: the same core as
// `setup -uninstall` under one elevation gate, then the optional trust /
// purge extras. The gate relaunches THIS verb elevated, flags intact.
func uninstallWindows(purge, trust, yes, consoleWait bool) error {
	if !winSvcElevated() {
		relaunch := []string{"uninstall"}
		if purge {
			relaunch = append(relaunch, "-purge")
		}
		if trust {
			relaunch = append(relaunch, "-trust")
		}
		if yes {
			relaunch = append(relaunch, "-yes")
		}
		return winRunElevatedGate(relaunch...)
	}
	uninstallWindowsCore()
	if trust {
		fmt.Println("§9.5 trust removal on Windows — remove the local root by hand (name it exactly as trust-install printed):")
		fmt.Println("  certutil -delstore Root <freens-local-root-nickname>")
		fmt.Println("  certutil -delstore -user Root <freens-local-root-nickname>")
		_ = os.RemoveAll(filepath.Join(home.Dir(), "tls"))
		fmt.Println("removed: the local trust root + §9.5 cross-cert spool (" + filepath.Join(home.Dir(), "tls") + ")")
	}
	if purge {
		if err := uninstallPurgeState(yes); err != nil {
			return err
		}
	}
	fmt.Println("uninstall complete.")
	windowsConsoleWait(consoleWait)
	return nil
}

// uninstallUnix is the systemd flow.
func uninstallUnix(purge, trust, yes bool) error {
	uninstallServices()
	removeUnitFiles()
	unwireOSResolver()
	if trust {
		uninstallTrustUnix()
	}
	if purge {
		if err := uninstallPurgeState(yes); err != nil {
			return err
		}
	}
	fmt.Println()
	fmt.Println("uninstall complete.")
	if !purge {
		fmt.Printf("KEPT (your keys, names, and store): %s\n", home.Dir())
		fmt.Printf("delete everything with: rm -rf %s   (or re-run with -purge)\n", home.Dir())
	}
	if !trust {
		fmt.Println("the §9.5 trust root is still installed on this machine — remove with: freens uninstall -trust")
	}
	return nil
}

// trustSystemCertGlob is where the system CA bundle picks up the §9.5
// anchors (var so tests point it into a sandbox).
var trustSystemCertGlob = "/usr/local/share/ca-certificates/freens-*.crt"

// uninstallTrustUnix removes the machine's §9.5 trust artifacts: the
// system-bundle copies (local root + bridge-copied cross certs) and the
// state dir's tls/ tree (root.crt, cross-cert spool, mint state). Browser
// NSS profiles are the user's own databases — the exact certutil commands
// are printed instead of guessed at.
func uninstallTrustUnix() {
	files, err := filepath.Glob(trustSystemCertGlob)
	if err == nil {
		for _, f := range files {
			if err := sudoRun("removing the trust anchor", "rm", "-f", f); err != nil {
				printManualCommands("remove trust anchor "+f, []string{"sudo rm -f " + f})
				continue
			}
			fmt.Printf("removed: %s\n", f)
		}
		if len(files) > 0 {
			fmt.Println("running: sudo update-ca-certificates")
			if err := sudoRun("rebuilding the CA bundle", "update-ca-certificates"); err != nil {
				printManualCommands("rebuild the CA bundle", []string{"sudo update-ca-certificates"})
			}
		}
	}
	_ = os.RemoveAll(filepath.Join(home.Dir(), "tls"))
	fmt.Println("removed: the local trust root + §9.5 cross-cert spool (" + filepath.Join(home.Dir(), "tls") + ")")
	fmt.Println("browsers with their own NSS profile still hold a copy — remove per profile with:")
	fmt.Println("  certutil -d sql:$HOME/.pki/nssdb -D -n \"freens\"  (and per Firefox profile, if used)")
}

// uninstallPurgeState deletes the ENTIRE state dir — the one-way step.
func uninstallPurgeState(yes bool) error {
	dir := home.Dir()
	if !yes && !sysIsTerminal() {
		return usageErr("-purge deletes %s (keys! names!) — pass -yes in scripts", dir)
	}
	if !yes && sysIsTerminal() {
		fmt.Printf("purge %s — every key, name, and stored record on this machine is DELETED. Proceed? [y/N] ", dir)
		var answer string
		if _, err := fmt.Scanln(&answer); err != nil || (answer != "y" && answer != "Y" && answer != "yes") {
			return usageErr("purge aborted (state dir kept)")
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("purging %s: %w", dir, err)
	}
	fmt.Printf("purged: %s (keys, names, store — restore from a `freens backup` file if you have one)\n", dir)
	return nil
}
