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
// See contrib/systemd/freens-web.service for the recommended unit.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/keychain"
	"github.com/camalolo/freens/internal/tlsca"
	"github.com/camalolo/freens/internal/webui"
)

// cliVersion is stamped at build time like the daemon's version.
var cliVersion = "dev"

func main() {
	fs := flag.NewFlagSet("freens-web", flag.ContinueOnError)
	configPath := fs.String("config", "", "freens.conf to read the [webui] section from (default: <home>/freens.conf)")
	listen := fs.String("listen", "", "listen address (default 0.0.0.0:8090)")
	allow := fs.String("allow", "", "source allowlist: comma CIDRs, \"\" = auto (LAN), \"any\" = ungated")
	homeDirFlag := fs.String("home", "", "freens home (default ~/.freens)")
	sock := fs.String("sock", "", "daemon admin socket (default <home>/admin.sock)")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *showVersion {
		fmt.Println("freens-web", cliVersion)
		return
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
			fmt.Fprintf(os.Stderr, "freens-web: %s: %v\n", cfgFile, perr)
			os.Exit(1)
		}
		cfg = parsed
	}
	// Flag overrides.
	if *listen != "" {
		cfg.Listen = *listen
	}
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

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv, err := webui.New(cfg, sockPath, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "freens-web: %v\n", err)
		os.Exit(1)
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		os.Exit(0)
	}()

	cert := webtls(cfg, cfgHome, log)
	if err := srv.ListenAndServeTLS(cert); err != nil {
		fmt.Fprintf(os.Stderr, "freens-web: %v\n", err)
		os.Exit(1)
	}
}

// webtls mints the §9.5 leaf for [webui] name (default: the first keychain
// alias, sorted) and returns it, or nil with the reason logged when TLS is
// off, impossible (no/unusable key), or the certificate would not carry the
// name this instance serves. Best-effort by design: the UI must come up.
func webtls(cfg *webui.Config, homeDir string, log *slog.Logger) *tls.Certificate {
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
	leafDER, leafKeyDER, err := tlsca.Leaf(caDER, caKey, []string{alias, "*." + alias}, now)
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

func keychainDir(homeDir string) string {
	if homeDir == "" {
		homeDir = home.Dir()
	}
	return filepath.Join(homeDir, "keys")
}
