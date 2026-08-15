// start.go — `freens start [alias]`: the whole onboarding as ONE verb —
// the "non-technical user" entry point. In order:
//
//	1/3 daemon:   if no daemon answers on the admin socket, run setup
//	              (idempotent: config, keys, seeds, systemd --user service,
//	              OS resolver wiring — interactive sudo when needed) and
//	              wait for it to come up
//	2/3 name:     alias from the argument, else the single keychain alias
//	              (idempotent re-run), else an interactive prompt on a TTY;
//	              if the alias is not published yet, `register` runs with
//	              every default filled (its retries reuse the key + claim)
//	3/3 summary:  the plain-language status (name → IP · healthy)
//
// `freens start alice` twice is safe: an existing published alias skips
// straight to the summary.
package cli

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/laurent/freens/internal/naming"
)

func cmdStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	ip := fs.String("ip", "", "IPv4 address for the apex A record (default: this machine's outbound IPv4)")
	peersCSV := fs.String("peers", "", "comma-separated bootstrap peers (standalone mode; default: the running daemon)")
	// Leading positional alias (the README form), like register.
	var lead string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		lead, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	pos := fs.Args()
	if lead != "" {
		pos = append([]string{lead}, pos...)
	}
	if len(pos) > 1 {
		return usageErr("start takes one optional name (%s start <name>); got %d arguments", ProgName, len(pos))
	}

	// 1/3 — daemon.
	fmt.Println("1/3 checking the freens daemon…")
	if maybeAdmin() == nil {
		fmt.Println("    not running — installing/starting it (freens setup, safe to re-run)")
		if err := setupInstall(); err != nil {
			return fmt.Errorf("setup: %w", err)
		}
		if waitForAdminSocket() {
			fmt.Println("    ✔ daemon running")
		} else {
			fmt.Println("    ✘ daemon still not answering (no systemd user session?) — continuing; `freens doctor --fix` says more")
		}
	} else {
		fmt.Println("    ✔ daemon running")
	}

	// 2/3 — the name.
	fmt.Println("2/3 your name…")
	alias := ""
	if len(pos) == 1 {
		alias = pos[0]
	} else if existing := keychainAliases(); len(existing) == 1 {
		alias = existing[0]
		fmt.Printf("    continuing with your existing name: %s\n", alias)
	} else if len(existing) > 1 {
		return usageErr("you own several names (%s) — say which one: %s start <name>", strings.Join(existing, ", "), ProgName)
	} else if sysIsTerminal() {
		fmt.Print("    choose a name (lowercase letters/digits/hyphens, e.g. alice): ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading the name: %w", err)
		}
		alias = strings.TrimSpace(line)
	} else {
		return usageErr("start needs a name: %s start <name> (e.g. %s start alice)", ProgName, ProgName)
	}
	if norm, err := naming.ValidateAlias(alias); err != nil {
		return usageErr("%q is not a valid name: %v (lowercase letters, digits, hyphens; 1-63 chars)", alias, err)
	} else {
		alias = norm
	}

	// "Already ours" = we hold the owner key AND the network resolves it.
	// A found alias WITHOUT our key is somebody else's name — register must
	// run (and will lose or win the §7.4 contest on its merits).
	already := false
	if fileExists(ownerKeyPath(alias)) {
		if c := maybeAdmin(); c != nil {
			ctx, cancel := adminCtx()
			r, err := c.Resolve(ctx, alias)
			cancel()
			already = err == nil && r != nil && r.Found
		}
	}
	if already {
		fmt.Printf("    ✔ %s is already yours and published\n", alias)
	} else {
		regArgs := []string{alias}
		if *ip != "" {
			regArgs = append(regArgs, "-ip", *ip)
		}
		if *peersCSV != "" {
			regArgs = append(regArgs, "-peers", *peersCSV)
		}
		if err := cmdRegister(regArgs); err != nil {
			return fmt.Errorf("register %s: %w", alias, err)
		}
	}

	// 3/3 — summary.
	fmt.Println("3/3 all set:")
	return cmdStatus(nil)
}
