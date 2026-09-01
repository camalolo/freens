// Command freens-web runs the freens LAN management web UI (internal/webui):
// a separate, optional process next to the resolver daemon — the daemon's
// availability never depends on the UI.
//
// Configuration: the SAME freens.conf the daemon reads — the [webui] section
// (see internal/webui.Config); flags override.
//
//	freens-web [-config <path>] [-listen <addr>] [-allow <cidrs|any>]
//	           [-home <dir>] [-sock <admin.sock path>] [-version]
//
// Run it as the daemon user (it reads the keychain and the admin socket).
// Linux/macOS: setup installs the service/agent that keeps it running
// (freens-web.service / com.freens.webui LaunchAgent). Windows: setup
// installs it as the "freens-web" SCM service next to the daemon.
package main

import (
	"context"
	"crypto/tls"
	"encoding/base32"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/keychain"
	"github.com/camalolo/freens/internal/tlsca"
	"github.com/camalolo/freens/internal/webui"
)

// cliVersion is stamped at build time like the daemon's version.
var cliVersion = "dev"

// logSink is the process-wide slog writer the windows service mode
// installs (webui.log); console mode leaves it nil (stderr). Declared
// untagged so both platform halves of the service seam can touch it.
var logSink *os.File

func main() {
	// Windows: the SCM launched us as the freens-web service — answer its
	// control protocol while the ordinary UI runs unchanged in a goroutine.
	if windowsServiceRequested() {
		os.Exit(windowsRunService())
	}

	// Console mode: SIGINT/SIGTERM close the stop channel (one shutdown
	// sequence for console and service alike).
	stop := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		close(stop)
	}()
	if err := consoleRun(os.Args[1:], stop); err != nil {
		fmt.Fprintf(os.Stderr, "freens-web: %v\n", err)
		os.Exit(1)
	}
}

// consoleRun is the whole UI: parse args, resolve config, build the
// server, serve until stop closes (or the listener fails).
func consoleRun(args []string, stop <-chan struct{}) error {
	fs := flag.NewFlagSet("freens-web", flag.ContinueOnError)
	configPath := fs.String("config", "", "freens.conf to read the [webui] section from (default: <home>/freens.conf)")
	listen := fs.String("listen", "", "listen address (default 0.0.0.0:8090)")
	allow := fs.String("allow", "", "source allowlist: comma CIDRs, \"\" = auto (LAN), \"any\" = ungated")
	homeDirFlag := fs.String("home", "", "freens home (default ~/.freens)")
	sock := fs.String("sock", "", "daemon admin socket (default <home>/admin.sock)")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println("freens-web", cliVersion)
		return nil
	}

	// Home first (flag > FREENS_HOME > ~/.freens), then config file inside it.
	cfgHome := *homeDirFlag
	if cfgHome == "" {
		cfgHome = home.Dir()
	}
	cfgFile := *configPath
	if cfgFile == "" {
		cfgFile = filepath.Join(cfgHome, "freens.conf")
	}
	cfg := &webui.Config{}
	if b, err := os.ReadFile(cfgFile); err == nil {
		parsed, perr := webui.ParseConfig(string(b))
		if perr != nil {
			return fmt.Errorf("%s: %w", cfgFile, perr)
		}
		cfg = parsed
	}
	// Flag overrides.
	if *listen != "" {
		cfg.Listen = *listen
	}
	cfg.SelfVersion = cliVersion // /healthz reports THIS binary's stamp
	if *allow != "" {
		cfg.Allow = *allow
	}
	if *homeDirFlag != "" {
		cfg.HomeDir = *homeDirFlag
	}
	homeOverride := cfg.HomeDir
	if homeOverride != "" {
		os.Setenv("FREENS_HOME", homeOverride) // for home.Dir() below
	}
	sockPath := *sock
	if sockPath == "" {
		sockPath = home.AdminSock()
	}

	w := os.Stderr
	if logSink != nil {
		w = logSink // service mode: no console, log to <home>\webui.log
	}
	log := slog.New(slog.NewTextHandler(w, nil))
	srv, err := webui.New(cfg, sockPath, log)
	if err != nil {
		return err
	}
	daemon := webui.NewDaemonClient(sockPath)

	cert := webtls(cfg, cfgHome, log, daemon)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServeTLS(cert) }()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-stop:
		// Drain open requests (bounded) and exit cleanly — the SCM path
		// reports Stopped only after this returns.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}

// webtls mints the §9.5 leaf for [webui] name (default: the first keychain
// alias, sorted) and returns it, or nil with the reason logged when TLS is
// off, impossible (no/unusable key), or the certificate would not carry the
// name this instance serves. Best-effort by design: the UI must come up.
//
// The SAN list covers every PUBLISHED subname of the alias (fetched from
// the daemon's store), not just the wildcard: Windows clients (schannel
// AND Chromium) refuse `*.alias` coverage for `<sub>.alias` when `alias`
// is an unknown TLD — `lan.camalolo` under `*.camalolo` verified fine on
// Linux curl and failed WRONG_PRINCIPAL on the desktop box. Explicit SANs
// need no wildcard semantics at all.
func webtls(cfg *webui.Config, homeDir string, log *slog.Logger, daemon webui.Daemon) *tls.Certificate {
	if cfg.TLSOff {
		log.Info("webui: TLS disabled by config ([webui] tls = false)")
		return nil
	}
	aliases := keychain.Aliases(keychainDir(homeDir))
	if len(aliases) == 0 {
		log.Info("webui: TLS off (no names in the keychain yet — plain HTTP until a name is registered)")
		return nil
	}
	alias := cfg.Name
	switch {
	case alias != "":
		found := false
		for _, a := range aliases {
			if a == alias {
				found = true
				break
			}
		}
		if !found {
			log.Warn("webui: [webui] name not in keychain — TLS off", "name", alias, "keychain", strings.Join(aliases, ","))
			return nil
		}
	default:
		alias = aliases[0]
		log.Info("webui: TLS leaf for the first keychain name (set [webui] name to override)", "alias", alias)
	}
	kp, err := keychain.Load(keychain.OwnerKeyPath(keychainDir(homeDir), alias), os.Getenv("FREENS_PASSPHRASE"))
	if err != nil {
		log.Warn("webui: TLS off (owner key unusable)", "alias", alias, "err", err.Error())
		return nil
	}
	now := time.Now()
	caDER, caKey, err := tlsca.OwnerCA(kp.Seed(), alias, now)
	if err != nil {
		log.Warn("webui: TLS off (CA derivation failed)", "err", err.Error())
		return nil
	}
	leafDER, leafKeyDER, err := tlsca.Leaf(caDER, caKey, leafSANs(daemon, kp, alias, log), now)
	if err != nil {
		log.Warn("webui: TLS off (leaf issuance failed)", "err", err.Error())
		return nil
	}
	// §9.5.4 chain: present [leaf, owner CA] — visitors anchor via their
	// constrained cross-cert (in their trust stores) up to their local root.
	cert, err := tls.X509KeyPair(chainPEM(leafDER, caDER), tlsca.KeyPEM(leafKeyDER))
	if err != nil {
		log.Warn("webui: TLS off (leaf pair build failed)", "err", err.Error())
		return nil
	}
	log.Info("webui: TLS enabled (§9.5)", "alias", alias, "leaf_sha256", tlsca.Fingerprint(leafDER))
	return &cert
}

// chainPEM concatenates DER certificates into one PEM chain (leaf first).
func chainPEM(ders ...[]byte) []byte {
	var out []byte
	for _, der := range ders {
		out = append(out, tlsca.CertPEM(der)...)
	}
	return out
}

// leafSANs builds the leaf's SAN list for alias: the apex, the wildcard,
// and — the part Windows clients need — every PUBLISHED subname of the
// namespace, because schannel and Chromium refuse `*.alias` coverage for
// `<sub>.alias` when `alias` is an unknown TLD. Subnames come from the
// daemon's store (the same records a resolver would serve); a store miss
// degrades to apex+wildcard. Best-effort like everything here.
func leafSANs(daemon webui.Daemon, kp *crypto.Keypair, alias string, log *slog.Logger) []string {
	sans := []string{alias, "*." + alias}
	if daemon == nil {
		return sans
	}
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		return sans
	}
	want := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(tldID), "="))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sr, err := daemon.Store(ctx)
	if err != nil {
		return sans
	}
	for _, e := range sr.Entries {
		if len(e.Labels) > 0 && e.TldIDB32 == want {
			sans = append(sans, strings.Join(e.Labels, ".")+"."+alias)
		}
	}
	log.Info("webui: leaf SANs", "count", len(sans), "sans", strings.Join(sans, ", "))
	return sans
}

func keychainDir(homeDir string) string {
	if homeDir == "" {
		homeDir = home.Dir()
	}
	return filepath.Join(homeDir, "keys")
}
