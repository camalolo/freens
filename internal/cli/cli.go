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
//	setup                        Install: config, seeds, systemd --user service, OS resolver wiring.
//	status                       Pretty-print the running daemon's admin status.
//	doctor                       Health checks (admin socket, DNS path, peers, seeds, OS resolver).
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

	"github.com/laurent/freens/internal/crypto"
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
	"transfer":        cmdTransfer,
	"rotate":          cmdRotate,
	"recover":         cmdRecover,
	"verify-recovery": cmdVerifyRecovery,
	"register":        cmdRegister,
	"setup":           cmdSetup,
	"status":          cmdStatus,
	"doctor":          cmdDoctor,
	"demo":            cmdDemo,
	"version":         cmdVersion,
}

// Main is the shared CLI entry point: args[0] is the subcommand, args[1:]
// its flags. It returns the process exit code (0 ok, 1 usage/io, 2
// crypto/validation), never panicking on bad input.
func Main(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
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
		usage(os.Stderr)
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

// usageTo writes the subcommand help to any writer (usage(os.Stderr) is the
// process-level form).
func usageTo(w io.Writer) { usage(w) }

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage:", ProgName, "<subcommand> [flags]")
	fmt.Fprintln(w, "subcommands:")
	fmt.Fprintln(w, "  setup                  install: config, seeds, systemd --user service, OS resolver wiring (--uninstall reverses)")
	fmt.Fprintln(w, "  status                 daemon status via the admin socket (+ your first alias self-check)")
	fmt.Fprintln(w, "  doctor                 health checks: admin socket, DNS path, aliases, peers, seeds, OS resolver")
	fmt.Fprintln(w, "  register               claim an alias end-to-end (spec 7): key -> PoW -> W live witness")
	fmt.Fprintln(w, "                         co-signatures -> TLD record published at K_tld+K_claim (2-of-3 recovery default)")
	fmt.Fprintln(w, "  name                   add/update <label>.<alias> (owner key from the keychain; IP inherits the apex A)")
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
