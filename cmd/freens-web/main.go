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
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/camalolo/freens/internal/home"
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

	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "freens-web: %v\n", err)
		os.Exit(1)
	}
}
