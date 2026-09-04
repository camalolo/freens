// nginx.go — make EXISTING nginx server blocks serve freens certificates:
// the certbot --nginx plugin, small. Scan the config tree for `server { }`
// blocks, match one by server_name, back the file up, inject the
// `listen 443 ssl` + certificate directives (or swap foreign ones with
// force), `nginx -t` the result (restoring the backup on failure), and
// reload. Everything a privileged user does directly, a non-root web UI
// does through `sudo -n` when the box allows it — never interactively.
package certmgr

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// NginxEnv is the (testable) nginx toolchain: binary + config paths and the
// process runner. Zero values mean "discover at first use".
type NginxEnv struct {
	Binary   string // "" = "nginx"
	ConfPath string // "" = discover from `nginx -V`
	Runner   func(ctx context.Context, name string, args ...string) (ExecResult, error)
}

func (n *NginxEnv) run(ctx context.Context, name string, args ...string) (ExecResult, error) {
	if n.Runner != nil {
		return n.Runner(ctx, name, args...)
	}
	return execRunner(ctx, name, args...)
}

// nginxExecTimeout bounds every nginx/systemctl exec the certmgr drives.
// Without it a hung `nginx -t`/`systemctl reload` pins the caller forever —
// the webui's http.Server sets no WriteTimeout, so the certs page wedges
// until service restart (found in the 2026-09-04 audit).
const nginxExecTimeout = 30 * time.Second

// runBounded is run with the nginxExecTimeout budget.
func (n *NginxEnv) runBounded(name string, args ...string) (ExecResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nginxExecTimeout)
	defer cancel()
	return n.run(ctx, name, args...)
}

// sudoWrap prefixes args with -n -- and returns "sudo" as the binary when
// escalating; otherwise the bare binary + args.
func sudoWrap(use bool, name string, args ...string) (string, []string) {
	if use {
		return "sudo", append([]string{"-n", "--", name}, args...)
	}
	return name, args
}

// ErrNginxNotFound: no nginx binary/config on this machine.
var ErrNginxNotFound = errors.New("certmgr: nginx not found on this machine (install it, or point -config at the main nginx.conf)")

// ErrNoServerBlock: no server block carries the wanted server_name.
type ErrNoServerBlock struct {
	Name  string
	Known []string // a handful of server_names that DO exist
}

func (e *ErrNoServerBlock) Error() string {
	return fmt.Sprintf("no nginx server block matches server_name %q — clone an existing vhost onto it with -clone <existing-server-name> (existing: %s)",
		e.Name, strings.Join(e.Known, ", "))
}

// ErrForeignCert: the matched block already serves a certificate we did not
// issue (replace with force).
type ErrForeignCert struct {
	ServerName string
	Files      []string
}

func (e *ErrForeignCert) Error() string {
	return fmt.Sprintf("server block %q already serves its own certificate (%s) — replace with the force option",
		e.ServerName, strings.Join(e.Files, ", "))
}

// Locate fills Binary/ConfPath: the binary resolves on PATH, then the
// sbin candidates (nginx lives in /usr/sbin on Debian — NOT on a normal
// user's PATH, which broke every discovery call from a user-owned daemon
// or CLI); the config path comes from `nginx -V`'s --conf-path (stable
// across distros), falling back to /etc/nginx/nginx.conf. Idempotent.
func (n *NginxEnv) Locate() error {
	if n.Binary == "" {
		n.Binary = resolveBinary()
	}
	if n.ConfPath != "" {
		return nil
	}
	res, err := n.run(context.Background(), n.Binary, "-V")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNginxNotFound, err)
	}
	for _, field := range strings.Fields(res.Stderr + " " + res.Stdout) {
		if strings.HasPrefix(field, "--conf-path=") {
			n.ConfPath = strings.TrimPrefix(field, "--conf-path=")
			break
		}
	}
	if n.ConfPath == "" {
		n.ConfPath = "/etc/nginx/nginx.conf"
	}
	return nil
}

// nginxBinaryCandidates is the PATH fallback list (var so tests can point
// it at a fixture binary).
var nginxBinaryCandidates = []string{
	"/usr/sbin/nginx",
	"/usr/local/sbin/nginx",
	"/usr/local/bin/nginx",
	"/usr/bin/nginx",
	"/opt/nginx/sbin/nginx",
}

// resolveBinary returns "nginx" when PATH has it, else the first candidate
// that exists and is executable (so a user-shell CLI and the daemon-user
// webui both find a root-installed nginx), else bare "nginx" — Locate
// turns the eventual exec error into ErrNginxNotFound either way.
func resolveBinary() string {
	if _, err := execLookPath("nginx"); err == nil {
		return "nginx"
	}
	for _, c := range nginxBinaryCandidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return c
		}
	}
	return "nginx"
}

// Block is one parsed `server { ... }` section.
type Block struct {
	File        string
	Start, End  int // 1-based inclusive line range of the whole block
	ServerNames []string
	ListensSSL  bool
	CertPaths   []string
	KeyPaths    []string

	indent string
}

// Scan walks the config tree (the main conf's directory: conf.d,
// sites-enabled, sites-available, everything non-hidden) and returns every
// server block, file order. Backup/litter files are skipped so yesterday's
// *.freens-pre never matches.
func (n *NginxEnv) Scan() ([]Block, error) {
	if err := n.Locate(); err != nil {
		return nil, err
	}
	root := filepath.Dir(n.ConfPath)
	var blocks []Block
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable corner: skip, don't fail the scan
		}
		if rel, rerr := filepath.Rel(root, path); rerr == nil &&
			strings.Count(rel, string(filepath.Separator)) > 4 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && path != root {
				return fs.SkipDir
			}
			return nil
		}
		if skipNginxFile(d.Name()) {
			return nil
		}
		// Symlinked files (Debian's sites-enabled entries) resolve to their
		// REAL path before parsing: the same vhost is then seen exactly
		// once (blocks' File = the sites-available file, which is also the
		// one an edit must rewrite), and a link pointing outside the tree
		// still gets scanned.
		if !d.Type().IsRegular() {
			if d.Type()&fs.ModeSymlink == 0 {
				return nil
			}
			resolved, rerr := filepath.EvalSymlinks(path)
			if rerr != nil {
				return nil
			}
			if info, ierr := os.Stat(resolved); ierr != nil || info.IsDir() {
				return nil
			}
			path = resolved
		}
		if seen[path] {
			return nil
		}
		seen[path] = true
		bs, perr := scanFile(path)
		if perr != nil {
			return nil // unparsable file (binary junk etc.): skip
		}
		blocks = append(blocks, bs...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].File < blocks[j].File })
	return blocks, nil
}

// skipNginxFile filters editor/backup litter that would otherwise shadow a
// live server block.
func skipNginxFile(name string) bool {
	if strings.HasPrefix(name, ".") {
		return true
	}
	for _, suf := range []string{
		".freens-pre", ".bak", ".default", ".dist", "~", ".swp", ".tmp",
		".dpkg-dist", ".dpkg-bak", ".dpkg-new", ".rpmnew", ".rpmsave", ".orig",
	} {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
}

// stripComment removes a # comment (outside quoted strings).
func stripComment(line string) string {
	inS, inD := false, false
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case c == '#' && !inS && !inD:
			return line[:i]
		}
	}
	return line
}

func countBraces(line string) int {
	n := 0
	for _, c := range stripComment(line) {
		switch c {
		case '{':
			n++
		case '}':
			n--
		}
	}
	return n
}

// scanFile parses one config file into its server blocks. A file the
// tokenizer can't bracket (truncated, binary) yields nothing rather than a
// wrong block — editing a misparsed block would corrupt a live config.
func scanFile(path string) ([]Block, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !looksLikeConfig(raw) {
		return nil, fmt.Errorf("not a text config: %s", path)
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	var blocks []Block
	for i := 0; i < len(lines); i++ {
		stripped := strings.TrimSpace(stripComment(lines[i]))
		fields := strings.Fields(stripped)
		if len(fields) == 0 || fields[0] != "server" || !strings.Contains(stripped, "{") {
			continue
		}
		depth := countBraces(lines[i])
		j := i
		for depth > 0 && j+1 < len(lines) {
			j++
			depth += countBraces(lines[j])
		}
		if depth != 0 {
			continue // unbalanced: not a block we can edit safely
		}
		blocks = append(blocks, parseBlock(path, lines, i, j))
		i = j
	}
	return blocks, nil
}

// looksLikeConfig rejects binary junk cheaply (NUL bytes) before parsing.
func looksLikeConfig(b []byte) bool {
	for i, c := range b {
		if c == 0 {
			return false
		}
		if i > 8192 {
			break
		}
	}
	return true
}

// parseBlock extracts the edit-relevant facts from lines[start..end]
// (0-based, inclusive).
func parseBlock(file string, lines []string, start, end int) Block {
	blk := Block{File: file, Start: start + 1, End: end + 1}
	for ln := start; ln <= end && ln < len(lines); ln++ {
		raw := strings.TrimRight(stripComment(lines[ln]), " \t")
		stripped := strings.TrimSpace(raw)
		fields := strings.Fields(strings.TrimSuffix(stripped, ";"))
		if len(fields) == 0 {
			continue
		}
		if blk.indent == "" && (strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t")) {
			blk.indent = leadingSpace(raw)
		}
		switch fields[0] {
		case "server_name":
			for _, f := range fields[1:] {
				f = strings.Trim(f, ";")
				if f != "" && f != "-" {
					blk.ServerNames = append(blk.ServerNames, unquote(f))
				}
			}
		case "listen":
			if listenIsSSL(fields) {
				blk.ListensSSL = true
			}
		case "ssl_certificate":
			if len(fields) > 1 {
				blk.CertPaths = append(blk.CertPaths, unquote(fields[1]))
			}
		case "ssl_certificate_key":
			if len(fields) > 1 {
				blk.KeyPaths = append(blk.KeyPaths, unquote(fields[1]))
			}
		}
	}
	return blk
}

func leadingSpace(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' && s[i] != '\t' {
			return s[:i]
		}
	}
	return ""
}

func unquote(s string) string { return strings.Trim(s, "\"'") }

// listenIsSSL: "listen 443 ssl", "listen [::]:443 ssl http2", "listen
// 8443" (TLS by convention) — enough for deciding whether a listen line is
// needed.
func listenIsSSL(fields []string) bool {
	if len(fields) < 2 {
		return false
	}
	for _, f := range fields[1:] {
		if f == "ssl" {
			return true
		}
		port := strings.TrimPrefix(f, "[::]:")
		if i := strings.LastIndexByte(port, ':'); i >= 0 {
			port = port[i+1:]
		}
		if p, err := strconv.Atoi(port); err == nil && (p == 443 || p == 8443) {
			return true
		}
	}
	return false
}

// pendingEdit is one config file staged for rewrite.
type pendingEdit struct {
	file    string
	lines   []string
	mode    fs.FileMode
	changed bool
}

// InstallOpts tunes Install.
type InstallOpts struct {
	MatchName string // server_name to match ("" = the freens name itself)
	// CloneFrom names an EXISTING vhost (by server_name) to twin into a
	// NEW config file serving the freens name — the path for "this site
	// already lives at <vhost> with its own valid certificate, give the
	// freens name the same site with our cert". Nothing in the source
	// vhost is ever modified. Only used when no block matches the freens
	// name directly.
	CloneFrom string
	Force     bool // replace a foreign ssl_certificate
	DryRun    bool // plan only: report what would change, touch nothing
	NoReload  bool
}

// InstallResult reports what Install did (and lets the web UI show it).
type InstallResult struct {
	Name      string   `json:"name"`
	Matched   []string `json:"matched"` // server_names of the touched block(s)
	Edited    []string `json:"edited"`  // config files rewritten
	Backup    []string `json:"backup"`  // <file>.freens-pre copies made
	Already   bool     `json:"already"` // block already served this exact cert
	Cloned    bool     `json:"cloned"`  // a new vhost file was created (CloneFrom)
	ClonedSrc string   `json:"cloned_src,omitempty"`
	Validated bool     `json:"validated"`
	Reloaded  bool     `json:"reloaded"`
	UsedSudo  bool     `json:"used_sudo"`
}

// Install makes every server block matching matchName (default: the freens
// name) serve the name's tracked certificate — issuing it first when
// needed. Order of operations is the safety story: edit nothing until the
// cert files exist, back up before the first write, validate before any
// reload, restore the backup when validation fails.
func (n *NginxEnv) Install(home, keysDir, displayName, passphrase string, opts InstallOpts, now time.Time) (*InstallResult, error) {
	r, err := EnsureTracked(home, keysDir, displayName, passphrase, now)
	if err != nil {
		return nil, err
	}
	blocks, err := n.Scan()
	if err != nil {
		return nil, err
	}
	want := opts.MatchName
	if want == "" {
		want = displayName
	}
	var matched []Block
	known := map[string]bool{}
	for _, b := range blocks {
		for _, sn := range b.ServerNames {
			known[sn] = true
		}
		if containsName(b.ServerNames, want) {
			matched = append(matched, b)
		}
	}
	if len(matched) == 0 {
		names := make([]string, 0, len(known))
		for k := range known {
			names = append(names, k)
		}
		sort.Strings(names)
		if len(names) > 12 {
			names = append(names[:12], "…")
		}
		if opts.CloneFrom != "" {
			return n.installCloned(home, keysDir, r, opts.CloneFrom, opts, now)
		}
		return nil, &ErrNoServerBlock{Name: want, Known: names}
	}

	res := &InstallResult{Name: r.Name}
	// Group matched blocks per file: one backup + one rewrite covers all of
	// a file's blocks.
	perFile := map[string][]Block{}
	for _, b := range matched {
		perFile[b.File] = append(perFile[b.File], b)
		res.Matched = append(res.Matched, b.ServerNames...)
	}
	files := make([]string, 0, len(perFile))
	for f := range perFile {
		files = append(files, f)
	}
	sort.Strings(files)

	var pendings []pendingEdit
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		mode := fs.FileMode(0o644)
		if info, serr := os.Stat(file); serr == nil {
			mode = info.Mode()
		}
		pd := pendingEdit{
			file:  file,
			lines: strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n"),
			mode:  mode,
		}
		for _, blk := range perFile[file] {
			servesOurs := containsName(blk.CertPaths, r.CertPath)
			if servesOurs && len(blk.CertPaths) == 1 {
				res.Already = true
				continue
			}
			if len(blk.CertPaths) > 0 && !servesOurs && !opts.Force {
				return nil, &ErrForeignCert{ServerName: want, Files: blk.CertPaths}
			}
			applyBlockEdit(&pd, blk, planBlockEdit(blk, r.CertPath, r.KeyPath))
			pd.changed = true
		}
		pendings = append(pendings, pd)
	}
	if res.Already && !anyChanged(pendings) {
		res.Validated = true // nothing to do; not reloading for a no-op
		return res, nil
	}
	if opts.DryRun {
		for _, pd := range pendings {
			if pd.changed {
				res.Edited = append(res.Edited, pd.file)
			}
		}
		return res, nil
	}

	// Write: backup first, then swap; escalate to sudo -n only when the
	// direct write is refused (the web UI's daemon user on root's
	// /etc/nginx).
	usedSudo := false
	for i := range pendings {
		pd := &pendings[i]
		if !pd.changed {
			continue
		}
		backup := pd.file + ".freens-pre"
		if err := copyFile(pd.file, backup); err != nil {
			return nil, err
		}
		res.Backup = append(res.Backup, backup)
		sudo, werr := writeConfigFile(pd.file, []byte(strings.Join(pd.lines, "\n")), pd.mode)
		if werr != nil {
			return nil, fmt.Errorf("writing %s: %v", pd.file, werr)
		}
		usedSudo = usedSudo || sudo
		res.Edited = append(res.Edited, pd.file)
	}
	res.UsedSudo = usedSudo

	// Validate BEFORE reload; restore on failure so nginx never inherits a
	// broken config from us.
	if verr := n.Validate(usedSudo); verr != nil {
		for i := range pendings {
			pd := &pendings[i]
			if !pd.changed {
				continue
			}
			if b, rerr := os.ReadFile(pd.file + ".freens-pre"); rerr == nil {
				_, _ = writeConfigFile(pd.file, b, pd.mode)
			}
		}
		return nil, fmt.Errorf("nginx -t rejected the edit (backup restored): %v", verr)
	}
	res.Validated = true

	if !opts.NoReload {
		if rerr := n.Reload(usedSudo); rerr != nil {
			return res, fmt.Errorf("installed + validated, but the reload failed: %v", rerr)
		}
		res.Reloaded = true
	}

	// Record the deployment so renewals know to reload after swapping keys.
	for _, f := range res.Edited {
		if !containsName(r.NginxFiles, f) {
			r.NginxFiles = append(r.NginxFiles, f)
		}
	}
	if err := Track(home, r); err != nil {
		return res, err
	}
	return res, nil
}

func anyChanged(pendings []pendingEdit) bool {
	for _, pd := range pendings {
		if pd.changed {
			return true
		}
	}
	return false
}

// planBlockEdit returns the directive lines to insert for a block (the
// caller drops the block's stale cert lines separately): a listen when the
// block has no TLS listener, then the certificate pair — indented like the
// block's own directives.
func planBlockEdit(blk Block, certPath, keyPath string) []string {
	var out []string
	if !blk.ListensSSL {
		out = append(out, "listen 443 ssl;")
	}
	out = append(out,
		"ssl_certificate "+certPath+";",
		"ssl_certificate_key "+keyPath+";")
	indent := blk.indent
	if indent == "" {
		indent = "    "
	}
	for i := range out {
		out[i] = indent + out[i]
	}
	return out
}

// applyBlockEdit removes the block's existing ssl_certificate(_key) lines
// and splices the planned lines in after the last server_name anchor (or
// right after the opening brace when there is none).
func applyBlockEdit(pd *pendingEdit, blk Block, insert []string) {
	var drop []int
	anchor := -1 // 0-based line AFTER which we insert
	for ln := blk.Start - 1; ln <= blk.End-1 && ln < len(pd.lines); ln++ {
		stripped := strings.TrimSpace(stripComment(pd.lines[ln]))
		fields := strings.Fields(strings.TrimSuffix(stripped, ";"))
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "ssl_certificate", "ssl_certificate_key":
			drop = append(drop, ln)
		case "server_name":
			anchor = ln
		}
	}
	// Drop from the end so earlier indexes stay valid; keep the anchor
	// pointing at the same logical line.
	for i := len(drop) - 1; i >= 0; i-- {
		pd.lines = append(pd.lines[:drop[i]], pd.lines[drop[i]+1:]...)
		if anchor > drop[i] {
			anchor--
		}
	}
	if anchor < 0 {
		anchor = blk.Start - 1 // the `server {` line itself
	}
	if anchor > len(pd.lines)-1 {
		anchor = len(pd.lines) - 1
	}
	out := make([]string, 0, len(pd.lines)+len(insert))
	out = append(out, pd.lines[:anchor+1]...)
	out = append(out, insert...)
	out = append(out, pd.lines[anchor+1:]...)
	pd.lines = out
}

// writeConfigFile atomically replaces path with data. Direct write first;
// when the OS refuses (root-owned /etc/nginx) and non-interactive sudo
// works, the write goes through `sudo -n install`. Returns whether sudo
// was used (callers need to run nginx -t the same way).
func writeConfigFile(path string, data []byte, mode fs.FileMode) (usedSudo bool, err error) {
	tmp, terr := os.CreateTemp(filepath.Dir(path), ".freens-cert-*.tmp")
	if terr == nil {
		if _, werr := tmp.Write(data); werr == nil &&
			tmp.Sync() == nil && tmp.Close() == nil &&
			os.Chmod(tmp.Name(), mode) == nil {
			if rerr := os.Rename(tmp.Name(), path); rerr == nil {
				return false, nil
			}
		} else {
			tmp.Close()
		}
		os.Remove(tmp.Name())
	}
	// Direct write refused (or impossible) — sudo fallback, non-interactive
	// only so a web handler can never hang on a password prompt.
	if !sudoAvailable() {
		return false, fmt.Errorf("cannot write %s (permission denied and passwordless sudo unavailable)", path)
	}
	staged := filepath.Join(os.TempDir(), fmt.Sprintf("freens-cert-%d.conf", os.Getpid()))
	if err := os.WriteFile(staged, data, mode); err != nil {
		return false, err
	}
	defer os.Remove(staged)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, rerr := execRunner(ctx, "sudo", "-n", "install", "-m", fmt.Sprintf("%o", mode&0o777), staged, path)
	if rerr != nil {
		return false, fmt.Errorf("sudo install: %v: %s", rerr, strings.TrimSpace(res.Stderr))
	}
	return true, nil
}

// copyFile backs src up (best effort on mode preservation).
func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	mode := fs.FileMode(0o644)
	if info, serr := os.Stat(src); serr == nil {
		mode = info.Mode()
	}
	return os.WriteFile(dst, b, mode)
}

// Validate runs `nginx -t`; parser output is folded into the error.
func (n *NginxEnv) Validate(useSudo bool) error {
	if err := n.Locate(); err != nil {
		return err
	}
	bin, args := sudoWrap(useSudo, n.Binary, "-t", "-c", n.ConfPath)
	res, err := n.runBounded(bin, args...)
	if err == nil {
		return nil
	}
	// The direct run is refused and we haven't escalated yet (renewal path
	// on a root-owned config): retry under sudo -n before declaring defeat.
	if !useSudo && sudoAvailable() {
		bin, args := sudoWrap(true, n.Binary, "-t", "-c", n.ConfPath)
		if res2, err2 := n.runBounded(bin, args...); err2 == nil {
			return nil
		} else {
			return fmt.Errorf("%s", strings.TrimSpace(res2.Stdout+" "+res2.Stderr))
		}
	}
	return fmt.Errorf("%s", strings.TrimSpace(res.Stdout+" "+res.Stderr))
}

// Reload reloads nginx: systemctl when the box runs systemd (nginx not
// being a unit falls back to the signal form), `nginx -s reload` otherwise.
// useSudo forces the sudo -n form (the caller knows the config is root's).
func (n *NginxEnv) Reload(useSudo bool) error {
	if err := n.Locate(); err != nil {
		return err
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil && runtime.GOOS != "windows" {
		bin, args := sudoWrap(useSudo, "systemctl", "reload", "nginx")
		if _, err := n.runBounded(bin, args...); err == nil {
			return nil
		}
		// systemd present but nginx not a unit (hand-rolled): signal form.
	}
	bin, args := sudoWrap(useSudo, n.Binary, "-s", "reload", "-c", n.ConfPath)
	res, err := n.runBounded(bin, args...)
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(res.Stdout+" "+res.Stderr))
	}
	return nil
}

// ReloadNginx is the standalone reload (the renewal path): discover
// everything, escalate when the direct form is refused.
func ReloadNginx(binary, conf string) error {
	n := &NginxEnv{Binary: binary, ConfPath: conf}
	if err := n.Locate(); err != nil {
		return err
	}
	if err := n.Reload(false); err == nil {
		return nil
	}
	return n.Reload(true)
}

// sudoAvailable reports whether non-interactive sudo works here (one cheap
// probe; the web UI hits this per click so failures are cached briefly).
var sudoAvailable = func() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := execRunner(ctx, "sudo", "-n", "true")
	return err == nil
}
