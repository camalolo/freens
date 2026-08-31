// Package cli implements freens' user-facing command line: every subcommand
// of the `freens` binary (and of the freens-cli compat shim) lives here as an
// importable library so both front-ends share one implementation.
//
// Subcommands:
//
//	gen-key                      Generate an Ed25519 keypair; print seed/public/tld_id.
//	mine-claim                   Mine an AliasClaim PoW; print nonce/pow_hash/claim CBOR.
//	make-record                  Build + sign a freens record (A RR); print envelope CBOR + DHT key.
//	publish                      PUT signed-envelope .cbor files onto the DHT (§6.4 PUT);
//	                             -evidence attaches a §8.4 RecoveryEvidence to the single -file.
//	resolve                      Fetch + display a name's terminal record (§6.4 GET; no chain walk).
//	get                          Raw DHT get by 64-hex key (§6.4 GET).
//	name                         Add/update a sub-name under a registered alias (the easy button).
//	transfer                     §8.3 hand-off of a name to a new owner key.
//	rotate                       §8.6 key hygiene (= §8.3 transfer to a fresh key).
//	recover                      Assemble §8.4 recovery evidence (+ the recovered record R2).
//	verify-recovery              Check §8.4 evidence against the previous record's policy.
//	register                     Claim an alias end-to-end (spec 7): key -> PoW -> W witnesses
//	                             -> TLD record published at K_tld+K_claim (recovery on by default).
//	setup                        Install: config, seeds, systemd system service, OS resolver wiring.
//	start                        The one-command onboarding: setup (if needed) -> register ->
//	                             plain-language status. Prompts for the name on a TTY.
//	backup                       Bundle every keychain key into one dated file (RESTORE.txt
//	                             inside); -restore unpacks it back into the keychain.
//	status                       Plain-language health (daemon, name -> IP); -v adds raw fields.
//	doctor                       Health checks (admin socket, DNS path, peers, seeds, OS
//	                             resolver); --fix repairs daemon/resolver-wiring first.
//	upgrade                      Fetch the latest GitHub release, install its binaries
//	                             in place, migrate freens.conf, restart the services
//	                             (-check compares only; -yes for scripts).
//	demo                         Self-contained end-to-end showcase (the headline demo).
//
// Exit codes: 0 success, 1 usage/error, 2 crypto/validation failure.
//
// Admin-awareness: the live-network subcommands (publish/resolve/get/
// register/name) run in one of two transports. With -peers they build a
// standalone one-shot DHT node exactly as the classic CLI did; with NO -peers
// they use the user's RUNNING DAEMON through its admin socket
// (home.AdminSock(), see internal/admin) when one answers — the common,
// zero-flag case. When neither exists the error says exactly what to do:
// "no -peers given and no running freens daemon found (start one with:
// freens setup)".
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/camalolo/freens/internal/crypto"
)

// Version is the cli package's own version, printed by the `version`
// subcommand. The front-end binaries (freens, freens-cli) stamp their OWN
// ldflags version vars and intercept -version before dispatching here, so
// both stamping schemes coexist.
var Version = "dev"

// ProgName prefixes error/usage lines. The freens-cli shim sets it to
// "freens-cli" for byte-compatible output; the freens binary keeps the
// default.
var ProgName = "freens"

// dispatch is the subcommand table: name -> implementation. args carries
// everything AFTER the subcommand word (flags only, except name which takes
// one positional).
var dispatch = map[string]func([]string) error{
	"gen-key":         cmdGenKey,
	"mine-claim":      cmdMineClaim,
	"make-record":     cmdMakeRecord,
	"publish":         cmdPublish,
	"resolve":         cmdResolve,
	"get":             cmdGet,
	"name":            cmdName,
	"cert":            cmdCert,
	"trust-install":   cmdTrustInstall,
	"transfer":        cmdTransfer,
	"rotate":          cmdRotate,
	"recover":         cmdRecover,
	"verify-recovery": cmdVerifyRecovery,
	"register":        cmdRegister,
	"renew":           cmdRenew,
	"revoke":          cmdRevoke,
	"setup":           cmdSetup,
	"start":           cmdStart,
	"backup":          cmdBackup,
	"status":          cmdStatus,
	"doctor":          cmdDoctor,
	"upgrade":         cmdUpgrade,
	"upgrade-migrate": cmdUpgradeMigrate,
	"demo":            cmdDemo,
	"version":         cmdVersion,
}

// Main is the shared CLI entry point: args[0] is the subcommand, args[1:]
// its flags. It returns the process exit code (0 ok, 1 usage/io, 2
// crypto/validation), never panicking on bad input.
func Main(args []string) int {
	if len(args) == 0 {
		quickstart(os.Stderr)
		return 1
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "-h", "--help", "help":
		usage(os.Stdout)
		return 0
	}
	fn, ok := dispatch[sub]
	if !ok {
		fmt.Fprintf(os.Stderr, "%s: unknown subcommand %q\n", ProgName, sub)
		if hits := suggestSubcommands(sub); len(hits) > 0 {
			fmt.Fprintf(os.Stderr, "did you mean: %s\n", strings.Join(hits, ", "))
		}
		fmt.Fprintln(os.Stderr)
		quickstart(os.Stderr)
		return 1
	}
	err := fn(rest)
	if err == nil {
		return 0
	}
	// crypto/validation failures exit 2; everything else (usage, IO) exits 1.
	code := 1
	if errors.Is(err, crypto.ErrCrypto) {
		code = 2
	}
	fmt.Fprintf(os.Stderr, "%s: %v\n", ProgName, err)
	return code
}

// cmdVersion prints the cli package version (the shims intercept
// -version/--version/version themselves to print their ldflags stamps; this
// is the fallback when dispatched explicitly).
func cmdVersion(args []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("version takes no positional arguments")
	}
	fmt.Printf("%s %s\n", ProgName, Version)
	return nil
}

// quickstart writes the first-timer card: the plain-language path a
// non-technical user needs, not the full subcommand table. Bare `freens`
// and unknown verbs print this; `freens help` prints everything.
func quickstart(w io.Writer) {
	fmt.Fprintln(w, "freens — free names: a name that is yours by key, no registrar")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "one command does everything (install + claim your name):")
	fmt.Fprintln(w, "  freens start <name>    e.g.  freens start alice")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "or step by step:")
	fmt.Fprintln(w, "  freens setup            one-time install on this machine")
	fmt.Fprintln(w, "  freens register <name>  claim your name, e.g.  freens register alice")
	fmt.Fprintln(w, "  freens name www.<name>  add a name under it, e.g.  freens name www.alice")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "protect your name:  freens backup     (copy the file it makes off this machine)")
	fmt.Fprintln(w, "is it working?  freens status    something odd?  freens doctor --fix")
	fmt.Fprintln(w, "all commands:   freens help")
}

// suggestSubcommands returns dispatch entries matching want by prefix or
// within edit distance 2 — the typo net under "unknown subcommand". Short
// inputs (a prefix like "na") are prefix-only: distance matching would
// suggest half the table.
func suggestSubcommands(want string) []string {
	lw := strings.ToLower(strings.TrimLeft(want, "-"))
	if lw == "" {
		return nil
	}
	var out []string
	for name := range dispatch {
		if strings.HasPrefix(name, lw) {
			out = append(out, name)
			continue
		}
		if len(lw) >= 4 && editDistance(name, lw) <= 2 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// editDistance is the classic Levenshtein DP over lowercase inputs.
func editDistance(a, b string) int {
	a, b = strings.ToLower(a), strings.ToLower(b)
	d := make([][]int, len(a)+1)
	for i := range d {
		d[i] = make([]int, len(b)+1)
		d[i][0] = i
	}
	for j := 1; j <= len(b); j++ {
		d[0][j] = j
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			m := d[i-1][j] + 1
			if v := d[i][j-1] + 1; v < m {
				m = v
			}
			if v := d[i-1][j-1] + cost; v < m {
				m = v
			}
			d[i][j] = m
		}
	}
	return d[len(a)][len(b)]
}

// usageTo writes the subcommand help to any writer (usage(os.Stderr) is the
// process-level form).
func usageTo(w io.Writer) { usage(w) }

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage:", ProgName, "<subcommand> [flags]")
	fmt.Fprintln(w, "subcommands:")
	fmt.Fprintln(w, "  start <name>           the one-command onboarding: install if needed, claim <name>, show status")
	fmt.Fprintln(w, "                         (prompts for the name when interactive; safe to re-run)")
	fmt.Fprintln(w, "  setup                  install: config, seeds, system systemd service (boots with the machine), OS resolver wiring (--uninstall reverses)")
	fmt.Fprintln(w, "  status                 plain-language health: daemon + name -> IP (-v adds raw daemon fields)")
	fmt.Fprintln(w, "  doctor                 health checks: admin socket, DNS path, aliases, peers, seeds, OS resolver")
	fmt.Fprintln(w, "                         (--fix repairs: starts the daemon, wires the OS resolver)")
	fmt.Fprintln(w, "  upgrade                self-update: fetch the latest GitHub release, verify + install its binaries in")
	fmt.Fprintln(w, "                         place, patch freens.conf, restart the freens* services (-check compares only;")
	fmt.Fprintln(w, "                         -version <tag> pins; -yes for scripts; old binaries kept as *.freens-prev)")
	fmt.Fprintln(w, "  upgrade-migrate        internal: the config-migration half of `upgrade`, run through the NEW binary")
	fmt.Fprintln(w, "  register <alias>       claim an alias end-to-end (spec 7): key -> PoW -> W live witness")
	fmt.Fprintln(w, "                         co-signatures -> TLD record published at K_tld+K_claim (2-of-3 recovery default)")
	fmt.Fprintln(w, "  revoke <name>          tombstone a name you own (spec 9.5): stops resolving everywhere;")
	fmt.Fprintln(w, "                         un-revoke = publish again (`register`/`name` at a newer sequence)")
	fmt.Fprintln(w, "  renew [name…]          extend your names' 24 h leases (sequence+1, fresh window; the")
	fmt.Fprintln(w, "                         daemon also auto-renews keychain names every 10 min)")
	fmt.Fprintln(w, "  backup                 bundle every key of your name(s) into one dated file (-restore unpacks it)")
	fmt.Fprintln(w, "                         — the \"never lose your name\" button; store the file off-machine")
	fmt.Fprintln(w, "  name                   add/update <label>.<alias> (owner key from the keychain; IP inherits the apex A)")
	fmt.Fprintln(w, "  cert <name>            issue + export a TLS leaf certificate (PEM) for a name you own (spec 9.5;")
	fmt.Fprintln(w, "                         for nginx/caddy etc.; the daemon issues for itself automatically)")
	fmt.Fprintln(w, "  trust-install          one-time per device: import your local trust root so https://<name> works (spec 9.5)")
	fmt.Fprintln(w, "  gen-key                generate an Ed25519 keypair (-out writes a 0600 keyfile)")
	fmt.Fprintln(w, "  mine-claim             mine an AliasClaim PoW")
	fmt.Fprintln(w, "  make-record            build + sign a freens record (optional -recovery-* embed a spec 5.4 policy; -out writes the .cbor)")
	fmt.Fprintln(w, "  transfer               hand a name to a new owner key (spec 8.3; -prev-envelope, -new-owner-seed, -signer-seed)")
	fmt.Fprintln(w, "  rotate                 key hygiene: transfer to a fresh key (spec 8.6 = 8.3 hand-off)")
	fmt.Fprintln(w, "  recover                gather threshold recovery-key signatures (spec 8.4; -prev-envelope, -new-owner-seed, -recovery-seeds,")
	fmt.Fprintln(w, "                         -out evidence CBOR; -out-envelope additionally writes the recovered record R2 — signed by the")
	fmt.Fprintln(w, "                         NEW owner; rotate the recovery keys afterwards: `rotate`, spec 8.4 step 2)")
	fmt.Fprintln(w, "  verify-recovery        check spec 8.4 evidence against the previous record's policy (-prev-envelope, -evidence, [-now])")
	fmt.Fprintln(w, "  publish                put envelope .cbor files onto the DHT (-files, -peers; -evidence <path> attaches a spec 8.4")
	fmt.Fprintln(w, "                         RecoveryEvidence to exactly ONE -file, the recovered record R2)")
	fmt.Fprintln(w, "  resolve                fetch + display a record from the DHT (-name, -tld-id-b32, -peers)")
	fmt.Fprintln(w, "  get                    raw DHT get by key (-key, -peers)")
	fmt.Fprintln(w, "  demo                   self-contained end-to-end showcase")
	fmt.Fprintln(w, "  version                print the binary version")
	fmt.Fprintln(w, "network subcommands use the RUNNING daemon (admin socket) when no -peers is")
	fmt.Fprintln(w, "given; resolve/get display the stored record only — authority-chain")
	fmt.Fprintln(w, "verification (spec 3.4) is the daemon's job when serving DNS.")
}

// errUsage signals a usage error (exit code 1).
type errUsage struct{ msg string }

func (e *errUsage) Error() string { return e.msg }

func usageErr(format string, args ...any) error {
	return &errUsage{msg: fmt.Sprintf(format, args...)}
}

// cryptoErr wraps a crypto/validation failure as crypto.ErrCrypto (exit code 2).
func cryptoErr(format string, args ...any) error {
	return fmt.Errorf("crypto: %s: %w", fmt.Sprintf(format, args...), crypto.ErrCrypto)
}
