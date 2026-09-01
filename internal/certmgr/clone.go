// clone.go — the "twin an existing vhost onto a freens name" operation.
// The realistic case: the site already lives at some server_name (often a
// WebPKI one — camalolo.com under Let's Encrypt) with locations, proxies,
// PHP and includes tuned over years. Rebuilding that by hand for the
// freens name is busywork; editing the ORIGINAL block is wrong (it would
// swap a valid third-party certificate). So: copy every block mentioning
// the source name into a NEW freens-owned file, rewrite the server_name,
// swap the certificate lines, strip the directives that cannot transfer
// (default_server would collide; ssl_stapling expects an OCSP endpoint a
// §9.5 leaf deliberately lacks), then validate + reload like any other
// install. The source file is never opened for writing.
package certmgr

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// installCloned creates the freens vhost by cloning every block that
// carries cloneFrom as a server_name, then deploys exactly like the edit
// path (validate → reload → track the new file so renewals reload).
func (n *NginxEnv) installCloned(home, keysDir string, r *Renewal, cloneFrom string, opts InstallOpts, now time.Time) (*InstallResult, error) {
	blocks, err := n.Scan()
	if err != nil {
		return nil, err
	}
	var src []Block
	known := map[string]bool{}
	for _, b := range blocks {
		for _, sn := range b.ServerNames {
			known[sn] = true
		}
		if containsName(b.ServerNames, cloneFrom) {
			src = append(src, b)
		}
	}
	if len(src) == 0 {
		names := make([]string, 0, len(known))
		for k := range known {
			names = append(names, k)
		}
		sortStrings(names)
		return nil, fmt.Errorf("cannot clone: no server block matches %q either (existing: %s)",
			cloneFrom, strings.Join(names, ", "))
	}
	// Group per source file and read each once.
	perFile := map[string][]Block{}
	var order []string
	for _, b := range src {
		if _, seen := perFile[b.File]; !seen {
			order = append(order, b.File)
		}
		perFile[b.File] = append(perFile[b.File], b)
	}

	res := &InstallResult{Name: r.Name, Cloned: true, ClonedSrc: cloneFrom}
	var body strings.Builder
	body.WriteString("# managed by freens (certmgr): serves the " + r.Name +
		" certificate — renewal is `freens cert renew` (contents are never rewritten, only reloaded).\n")
	for _, file := range order {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
		for _, blk := range perFile[file] {
			body.WriteString("\n")
			for _, ln := range transformClonedBlock(lines[blk.Start-1:blk.End], r.Name, r.CertPath, r.KeyPath) {
				body.WriteString(ln)
				body.WriteString("\n")
			}
		}
		res.Matched = append(res.Matched, perFile[file][0].ServerNames...)
	}

	// Placement follows the source: a symlinked sites-enabled entry gets a
	// real file in sites-available + our own enabled symlink (the Debian
	// shape); a plain file (conf.d style) gets a sibling *.conf.
	real, link, err := cloneFileLocation(order[0], r.Name)
	if err != nil {
		return nil, err
	}
	if opts.DryRun {
		res.Edited = append(res.Edited, real+" (planned)")
		return res, nil
	}
	content := []byte(body.String())
	mode := fs.FileMode(0o644)
	sudo, werr := writeConfigFile(real, content, mode)
	if werr != nil {
		return nil, fmt.Errorf("writing %s: %v", real, werr)
	}
	res.UsedSudo = sudo
	res.Edited = append(res.Edited, real)
	if link != "" {
		if serr := ensureSymlink(link, real, sudo || sudoAvailable()); serr != nil {
			return nil, fmt.Errorf("linking %s: %v", link, serr)
		}
	}

	// Validate BEFORE reload; a failed clone leaves only OUR file behind —
	// remove it and the tree is exactly as before.
	if verr := n.Validate(res.UsedSudo); verr != nil {
		os.Remove(real)
		if link != "" {
			_ = os.Remove(link)
		}
		return nil, fmt.Errorf("nginx -t rejected the cloned vhost (removed): %v", verr)
	}
	res.Validated = true

	if !opts.NoReload {
		if rerr := n.Reload(res.UsedSudo); rerr != nil {
			return res, fmt.Errorf("cloned + validated, but the reload failed: %v", rerr)
		}
		res.Reloaded = true
	}

	// Renewal tracking: the REAL file is what nginx serves; record it so
	// every renewal reloads after swapping the leaf.
	if !containsName(r.NginxFiles, real) {
		r.NginxFiles = append(r.NginxFiles, real)
	}
	if err := Track(home, r); err != nil {
		return res, err
	}
	return res, nil
}

// cloneFileLocation picks where the cloned vhost lives. Block files are
// already resolved to their real paths (Scan dedupes symlinks), so the
// Debian layout is detected by name: a source in sites-available/ gets a
// sibling file there plus our own enabled-side symlink. Anything else
// (conf.d style) gets a sibling *.conf next to it — the include globs want
// the suffix.
func cloneFileLocation(srcFile, name string) (real, link string, err error) {
	resolved, err := filepath.EvalSymlinks(srcFile)
	if err != nil {
		return "", "", err
	}
	dir := filepath.Dir(resolved)
	base := "freens-" + name
	if filepath.Base(dir) == "sites-available" {
		enabled := filepath.Join(filepath.Dir(dir), "sites-enabled")
		if info, serr := os.Stat(enabled); serr == nil && info.IsDir() {
			return filepath.Join(dir, base), filepath.Join(enabled, base), nil
		}
	}
	if !strings.HasSuffix(base, ".conf") {
		base += ".conf"
	}
	return filepath.Join(dir, base), "", nil
}

// transformClonedBlock rewrites one block's lines for the freens twin.
// Everything not listed passes through byte-for-byte (locations, proxies,
// includes, redirects — `$server_name` in a redirect even resolves to the
// new name automatically).
func transformClonedBlock(lines []string, displayName, certPath, keyPath string) []string {
	out := make([]string, 0, len(lines))
	certDone := false
	for _, line := range lines {
		stripped := strings.TrimSpace(stripComment(line))
		fields := strings.Fields(strings.TrimSuffix(stripped, ";"))
		indent := leadingSpace(line)
		if len(fields) > 0 {
			switch fields[0] {
			case "server_name":
				// The twin serves exactly the freens name.
				out = append(out, indent+"server_name "+displayName+";")
				continue
			case "ssl_certificate":
				if !certDone {
					out = append(out,
						indent+"ssl_certificate "+certPath+";",
						indent+"ssl_certificate_key "+keyPath+";")
					certDone = true
				}
				continue
			case "ssl_certificate_key":
				continue // emitted alongside the cert line above
			case "ssl_stapling", "ssl_stapling_verify":
				// §9.5 leaves carry no OCSP endpoint (revocation = short
				// TTL); nginx would log stapling warnings forever.
				continue
			case "listen":
				// default_server is per-address and would collide with the
				// source vhost's own flag on the same port.
				line = indent + dropListens(strings.TrimSuffix(stripped, ";")) + ";"
				out = append(out, line)
				continue
			}
		}
		out = append(out, line)
	}
	return out
}

// dropListens removes default_server from a listen directive ("listen 443
// ssl default_server;" → "listen 443 ssl;").
func dropListens(stripped string) string {
	fields := strings.Fields(stripped)
	var kept []string
	for _, f := range fields {
		if f != "default_server" {
			kept = append(kept, f)
		}
	}
	return strings.Join(kept, " ")
}

// ensureSymlink creates dst → target (relative, the Debian convention),
// replacing a previous link of the same name. Needs the same privileges as
// the config write, hence the sudo -n form when the direct one refuses.
func ensureSymlink(dst, target string, allowSudo bool) error {
	rel, err := filepath.Rel(filepath.Dir(dst), target)
	if err != nil {
		rel = target
	}
	if err := os.Symlink(rel, dst); err == nil {
		return nil
	}
	// Replace an existing link (idempotent re-runs) or fall back to sudo.
	os.Remove(dst)
	if err := os.Symlink(rel, dst); err == nil {
		return nil
	}
	if !allowSudo || !sudoAvailable() {
		return fmt.Errorf("cannot create symlink (permission denied and passwordless sudo unavailable)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := execRunner(ctx, "sudo", "-n", "ln", "-sfn", rel, dst)
	if err != nil {
		return fmt.Errorf("sudo ln: %v: %s", err, strings.TrimSpace(res.Stderr))
	}
	return nil
}

func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j] < ss[j-1]; j-- {
			ss[j], ss[j-1] = ss[j-1], ss[j]
		}
	}
}
