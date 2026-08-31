// trust.go — the §9.5 TLS verbs:
//
//	freens trust-install   one-time per-device bootstrap: generate (once) the
//	                       local trust root and import it into the system
//	                       bundle and NSS user DBs (Chromium/Firefox)
//	freens cert <name>     issue + export a leaf certificate (PEM) for any
//	                       name under an owned alias — for nginx/caddy etc.
//
// Both are local-only operations: no daemon, no network.
package cli

import (
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/tlsca"
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
	fs := flag.NewFlagSet("cert", flag.ContinueOnError)
	outDir := fs.String("out-dir", ".", "directory for <name>.crt / <name>.key")
	days := fs.Int("days", 7, "leaf validity in days (capped by the §9.5.3 7-day ceiling for daemon-issued certs)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 1 {
		return usageErr("cert takes exactly one name: <name> or <label>.<alias> (e.g. www.alice)")
	}
	displayName := fs.Args()[0]
	labels, alias, err := naming.DecomposeName(displayName)
	if err != nil {
		return usageErr("invalid name %q: %v", displayName, err)
	}

	keyPath := ownerKeyPath(alias)
	kp, err := seedKeypair("@"+keyPath, "-owner")
	if err != nil {
		if os.IsNotExist(err) {
			return usageErr("no owner key for alias %q (looked for %s)", alias, keyPath)
		}
		return err
	}

	now := time.Now()
	caDER, caKey, err := tlsca.OwnerCA(kp.Seed(), alias, now)
	if err != nil {
		return err
	}
	sans := []string{displayName}
	if len(labels) == 0 {
		sans = append(sans, "*."+alias)
	}
	leafDER, leafKeyDER, err := tlsca.Leaf(caDER, caKey, sans, now)
	if err != nil {
		return err
	}
	_ = days // validity is fixed at the §9.5.3 ceiling inside tlsca.Leaf

	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		return err
	}
	crtPath := filepath.Join(*outDir, displayName+".crt")
	keyPathOut := filepath.Join(*outDir, displayName+".key")
	// <name>.crt is the SERVING CHAIN: leaf + owner CA (§9.5.4 — visitors
	// anchor the chain at their constrained cross-cert / local root).
	if err := os.WriteFile(crtPath, chainPEM(leafDER, caDER), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPathOut, tlsca.KeyPEM(leafKeyDER), 0o600); err != nil {
		return err
	}
	leaf, err := tlsca.ParseCertDER(leafDER)
	if err != nil {
		return err
	}
	fmt.Printf("name=%s\n", displayName)
	fmt.Printf("sans=%s\n", joinSans(sans))
	fmt.Printf("not_after=%s\n", leaf.NotAfter.UTC().Format(time.RFC3339))
	fmt.Printf("leaf_sha256=%s\n", tlsca.Fingerprint(leafDER))
	fmt.Printf("cert=%s\nkey=%s (0600)\n", crtPath, keyPathOut)
	fmt.Println("Chain for clients: leaf -> <alias> owner CA (TLSCA in the apex record) -> their trust root (§9.5).")
	return nil
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

// chainPEM concatenates DER certificates into one PEM bundle (leaf first).
func chainPEM(ders ...[]byte) []byte {
	var out []byte
	for _, der := range ders {
		out = append(out, tlsca.CertPEM(der)...)
	}
	return out
}
