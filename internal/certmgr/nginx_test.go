// nginx_test.go — the scan/edit/deploy half of certmgr against synthetic
// config trees and a recording process runner (no real nginx is ever
// spawned; the test box's own nginx state is irrelevant by construction).
package certmgr

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// nginxFixture is a synthetic /etc/nginx tree plus a recording runner.
type nginxFixture struct {
	t    *testing.T
	root string
	env  *NginxEnv

	calls []string // "name arg arg ..." for every runner invocation
	// failOn matches runner invocations whose joined args contain this
	// substring (checked against "nginx -t" etc.); empty = never fail.
	failOn string
}

const mainConf = `user www-data;
worker_processes auto;
events { }
http {
    include /etc/nginx/mime.types;
    access_log off;
    server {
        listen 80 default_server;
        server_name _;
        return 444;
    }
}
`

// sitesEnabled/app mirrors Debian: no .conf suffix, two blocks, one of
// them already TLS with a FOREIGN certificate.
const appConf = `server {
    listen 80;
    server_name www.camalolo app.local;

    location / {
        proxy_pass http://127.0.0.1:8000; # keep the trailing parts
    }
}

server {
    listen 80;
    server_name secure.camalolo;
    listen 443 ssl;
    ssl_certificate /etc/ssl/old.crt;
    ssl_certificate_key /etc/ssl/old.key;
    root /var/www/tls;
}
`

func newNginxFixture(t *testing.T) *nginxFixture {
	t.Helper()
	root := t.TempDir()
	f := &nginxFixture{t: t, root: root}
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("nginx.conf", mainConf)
	write("sites-enabled/app", appConf)
	write("sites-enabled/app.freens-pre", "server { server_name stale; }") // litter: must never match
	f.env = &NginxEnv{
		Binary:   "nginx",
		ConfPath: filepath.Join(root, "nginx.conf"),
		Runner: func(ctx context.Context, name string, args ...string) (ExecResult, error) {
			line := name + " " + strings.Join(args, " ")
			f.calls = append(f.calls, line)
			if f.failOn != "" && strings.Contains(line, f.failOn) {
				return ExecResult{Stderr: "nginx: [emerg] broken by the test"}, errors.New("exit 1")
			}
			return ExecResult{}, nil
		},
	}
	t.Cleanup(func() { f.calls = nil })
	return f
}

func (f *nginxFixture) called(substr string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func TestScanFindsBlocksAndSkipsLitter(t *testing.T) {
	f := newNginxFixture(t)
	blocks, err := f.env.Scan()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(blocks) != 3 {
		t.Fatalf("got %d blocks, want 3 (main catch-all + 2 in sites-enabled): %+v", len(blocks), blocks)
	}
	var www, tls *Block
	for i := range blocks {
		b := blocks[i]
		for _, sn := range b.ServerNames {
			switch sn {
			case "www.camalolo":
				www = &blocks[i]
			case "secure.camalolo":
				tls = &blocks[i]
			}
		}
		if reflect.DeepEqual(b.ServerNames, []string{"stale"}) {
			t.Fatal("the *.freens-pre litter file was scanned — backups must never match")
		}
	}
	if www == nil || tls == nil {
		t.Fatalf("expected blocks missing: %+v", blocks)
	}
	if www.ListensSSL {
		t.Fatal("the plain-HTTP block parsed as SSL")
	}
	if !tls.ListensSSL || len(tls.CertPaths) != 1 || tls.CertPaths[0] != "/etc/ssl/old.crt" {
		t.Fatalf("tls block parse wrong: %+v", tls)
	}
}

func TestInstallIntoHTTPBlock(t *testing.T) {
	f := newNginxFixture(t)
	e := newTestEnv(t)
	now := time.Unix(1_700_000_000, 0)

	res, err := f.env.Install(e.home, e.keysDir, "www.camalolo", "", InstallOpts{}, now)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !res.Validated || !res.Reloaded || res.Already {
		t.Fatalf("install result wrong: %+v", res)
	}
	if !f.called("nginx -t") && !f.called("-t -c") {
		t.Fatalf("validate never ran: %v", f.calls)
	}
	if !f.called("reload") {
		t.Fatalf("reload never ran: %v", f.calls)
	}

	// The edited file: cert lines present, pointing at the tracked export,
	// original directives preserved, indentation consistent.
	app := filepath.Join(f.root, "sites-enabled", "app")
	b, err := os.ReadFile(app)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	certPath := filepath.Join(ExportDir(e.home), "www.camalolo.crt")
	if !strings.Contains(text, "listen 443 ssl;") {
		t.Fatalf("no listen added:\n%s", text)
	}
	if !strings.Contains(text, "ssl_certificate "+certPath+";") {
		t.Fatalf("cert line missing:\n%s", text)
	}
	if !strings.Contains(text, "proxy_pass http://127.0.0.1:8000; # keep the trailing parts") {
		t.Fatalf("existing directives damaged:\n%s", text)
	}
	// Insertion after the server_name anchor, at the block's indent.
	if idx := strings.Index(text, "server_name www.camalolo"); idx >= 0 {
		tail := text[idx:]
		if !strings.Contains(tail[:strings.Index(tail, "location")], "ssl_certificate") {
			t.Fatalf("cert lines not inserted after the server_name anchor:\n%s", text)
		}
	}
	// Backup + tracking side effects.
	if _, err := os.Stat(app + ".freens-pre"); err != nil {
		t.Fatalf("no backup made: %v", err)
	}
	st, err := LoadState(e.home, "www.camalolo")
	if err != nil {
		t.Fatal(err)
	}
	if !containsName(st.NginxFiles, app) {
		t.Fatalf("nginx file not tracked for renewal: %+v", st.NginxFiles)
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	f := newNginxFixture(t)
	e := newTestEnv(t)
	now := time.Unix(1_700_000_000, 0)
	if _, err := f.env.Install(e.home, e.keysDir, "www.camalolo", "", InstallOpts{}, now); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	res, err := f.env.Install(e.home, e.keysDir, "www.camalolo", "", InstallOpts{}, now)
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if !res.Already || res.Reloaded {
		t.Fatalf("second install should be a no-op: %+v", res)
	}
	if f.called("reload") {
		t.Fatalf("no-op must not reload: %v", f.calls)
	}
}

func TestInstallForeignCertRefusedThenForced(t *testing.T) {
	f := newNginxFixture(t)
	e := newTestEnv(t)
	now := time.Unix(1_700_000_000, 0)

	_, err := f.env.Install(e.home, e.keysDir, "secure.camalolo", "", InstallOpts{}, now)
	var foreign *ErrForeignCert
	if !errors.As(err, &foreign) {
		t.Fatalf("err = %v, want ErrForeignCert", err)
	}
	if len(foreign.Files) != 1 || foreign.Files[0] != "/etc/ssl/old.crt" {
		t.Fatalf("foreign cert list wrong: %+v", foreign.Files)
	}

	res, err := f.env.Install(e.home, e.keysDir, "secure.camalolo", "", InstallOpts{Force: true}, now)
	if err != nil {
		t.Fatalf("forced install: %v", err)
	}
	app := filepath.Join(f.root, "sites-enabled", "app")
	b, _ := os.ReadFile(app)
	text := string(b)
	certPath := filepath.Join(ExportDir(e.home), "secure.camalolo.crt")
	if strings.Contains(text, "/etc/ssl/old.crt") || strings.Contains(text, "/etc/ssl/old.key") {
		t.Fatalf("foreign cert lines survived the force install:\n%s", text)
	}
	if !strings.Contains(text, "ssl_certificate "+certPath+";") {
		t.Fatalf("new cert line missing:\n%s", text)
	}
	if !strings.Contains(text, "root /var/www/tls;") {
		t.Fatalf("unrelated directive lost:\n%s", text)
	}
	_ = res
}

func TestInstallNoMatchingBlock(t *testing.T) {
	f := newNginxFixture(t)
	e := newTestEnv(t)
	_, err := f.env.Install(e.home, e.keysDir, "blog.camalolo", "", InstallOpts{}, time.Unix(1_700_000_000, 0))
	var miss *ErrNoServerBlock
	if !errors.As(err, &miss) {
		t.Fatalf("err = %v, want ErrNoServerBlock", err)
	}
	if !containsName(miss.Known, "www.camalolo") {
		t.Fatalf("known names should include the scanned blocks: %+v", miss.Known)
	}
}

func TestValidateFailureRestoresBackup(t *testing.T) {
	f := newNginxFixture(t)
	e := newTestEnv(t)
	now := time.Unix(1_700_000_000, 0)
	app := filepath.Join(f.root, "sites-enabled", "app")
	before, _ := os.ReadFile(app)

	f.failOn = "-t" // every nginx -t fails (direct AND escalated form)
	_, err := f.env.Install(e.home, e.keysDir, "www.camalolo", "", InstallOpts{}, now)
	if err == nil {
		t.Fatal("install should fail when validation fails")
	}
	if !strings.Contains(err.Error(), "config restored") {
		t.Fatalf("error must truthfully report the successful restore: %v", err)
	}
	after, _ := os.ReadFile(app)
	if string(before) != string(after) {
		t.Fatalf("config not restored after failed validation:\n%s", after)
	}
	// The backup itself survives so the operator can diff.
	if _, err := os.Stat(app + ".freens-pre"); err != nil {
		t.Fatalf("backup gone: %v", err)
	}
}

// TestValidateFailureRestoreFailureReported: when the restore itself fails
// (here: the backup vanished mid-flight), the error must say the config is
// left broken instead of claiming a restore that never happened.
func TestValidateFailureRestoreFailureReported(t *testing.T) {
	f := newNginxFixture(t)
	e := newTestEnv(t)
	now := time.Unix(1_700_000_000, 0)
	app := filepath.Join(f.root, "sites-enabled", "app")

	f.failOn = "-t"
	base := f.env.Runner
	f.env.Runner = func(ctx context.Context, name string, args ...string) (ExecResult, error) {
		line := name + " " + strings.Join(args, " ")
		if strings.Contains(line, " -t ") {
			os.Remove(app + ".freens-pre") // the restore has nothing to read
		}
		return base(ctx, name, args...)
	}
	_, err := f.env.Install(e.home, e.keysDir, "www.camalolo", "", InstallOpts{}, now)
	if err == nil {
		t.Fatal("install should fail when validation fails")
	}
	if !strings.Contains(err.Error(), "RESTORE FAILED") || !strings.Contains(err.Error(), app) {
		t.Fatalf("restore failure not reported honestly: %v", err)
	}
	if strings.Contains(err.Error(), "config restored") {
		t.Fatalf("error claims a restore that failed: %v", err)
	}
}

// TestInstallAppliesMultipleBlocksBottomUp: one file, two matching server
// blocks (the common :80 + :443 twin vhost with the same server_name).
// Edits must apply BOTTOM-UP — top-down, the first edit's inserted lines
// shift every later block's recorded range and the next edit splices into
// the wrong place (found live: our ssl_certificate ended up paired with the
// foreign key and a stray `listen 443 ssl` landed in the :80 block).
func TestInstallAppliesMultipleBlocksBottomUp(t *testing.T) {
	f := newNginxFixture(t)
	app := filepath.Join(f.root, "sites-enabled", "app")
	twin := `server {
    listen 80;
    server_name twin.camalolo;

    location / {
        proxy_pass http://127.0.0.1:8000;
    }
}

server {
    listen 443 ssl;
    server_name twin.camalolo;
    ssl_certificate /etc/ssl/old.crt;
    ssl_certificate_key /etc/ssl/old.key;
    root /var/www/tls;
}
`
	if err := os.WriteFile(app, []byte(twin), 0o644); err != nil {
		t.Fatal(err)
	}
	e := newTestEnv(t)
	now := time.Unix(1_700_000_000, 0)

	res, err := f.env.Install(e.home, e.keysDir, "twin.camalolo", "", InstallOpts{Force: true}, now)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if len(res.Matched) != 2 {
		t.Fatalf("matched = %v, want both twin blocks", res.Matched)
	}

	b, err := os.ReadFile(app)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	certPath := filepath.Join(ExportDir(e.home), "twin.camalolo.crt")
	keyPath := filepath.Join(ExportDir(e.home), "twin.camalolo.key")
	if got := strings.Count(text, "ssl_certificate "+certPath+";"); got != 2 {
		t.Fatalf("our ssl_certificate lines = %d, want 2 (one per block):\n%s", got, text)
	}
	if got := strings.Count(text, "ssl_certificate_key "+keyPath+";"); got != 2 {
		t.Fatalf("our ssl_certificate_key lines = %d, want 2:\n%s", got, text)
	}
	if strings.Contains(text, "/etc/ssl/old") {
		t.Fatalf("foreign cert lines survived:\n%s", text)
	}
	// Exactly one listener ADDED (the :80 block needed it); the :443 block
	// keeps its own — a third means an edit spliced outside its block.
	if got := strings.Count(text, "listen 443 ssl;"); got != 2 {
		t.Fatalf("listen 443 ssl lines = %d, want 2:\n%s", got, text)
	}
	// Structural re-scan: each block parses with exactly its own pair.
	blocks, err := scanFile(app)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 2 {
		t.Fatalf("rescan found %d blocks:\n%s", len(blocks), text)
	}
	for i, blk := range blocks {
		if !blk.ListensSSL {
			t.Errorf("block %d lost its TLS listener", i)
		}
		if len(blk.CertPaths) != 1 || blk.CertPaths[0] != certPath {
			t.Errorf("block %d cert paths = %v, want [%s]", i, blk.CertPaths, certPath)
		}
		if len(blk.KeyPaths) != 1 || blk.KeyPaths[0] != keyPath {
			t.Errorf("block %d key paths = %v, want [%s]", i, blk.KeyPaths, keyPath)
		}
	}
	if !f.called("-t") {
		t.Fatalf("validate never ran: %v", f.calls)
	}
}

func TestDryRunTouchesNothing(t *testing.T) {
	f := newNginxFixture(t)
	e := newTestEnv(t)
	now := time.Unix(1_700_000_000, 0)
	app := filepath.Join(f.root, "sites-enabled", "app")
	before, _ := os.ReadFile(app)

	res, err := f.env.Install(e.home, e.keysDir, "www.camalolo", "", InstallOpts{DryRun: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Edited) != 1 || res.Validated || res.Reloaded {
		t.Fatalf("dry-run result wrong: %+v", res)
	}
	after, _ := os.ReadFile(app)
	if string(before) != string(after) {
		t.Fatal("dry run modified the config")
	}
}

func TestListenIsSSL(t *testing.T) {
	cases := []struct {
		listen []string
		want   bool
	}{
		{[]string{"listen", "80;"}, false},
		{[]string{"listen", "[::]:80;"}, false},
		{[]string{"listen", "443", "ssl;"}, true},
		{[]string{"listen", "[::]:443", "ssl", "http2;"}, true},
		{[]string{"listen", "8443", "ssl;"}, true},
		{[]string{"listen", "127.0.0.1:9443;"}, false},
	}
	for _, c := range cases {
		if got := listenIsSSL(c.listen); got != c.want {
			t.Fatalf("listenIsSSL(%v) = %v, want %v", c.listen, got, c.want)
		}
	}
}

func TestStripCommentRespectsQuotes(t *testing.T) {
	if got := stripComment(`log_format main '$remote_addr # not a comment'; # real`); got != `log_format main '$remote_addr # not a comment'; ` {
		t.Fatalf("stripComment broke a quoted #: %q", got)
	}
	if got := countBraces("server { # {"); got != 1 {
		t.Fatalf("countBraces with commented brace = %d, want 1", got)
	}
}

// cloneFixture replicates the real-world Debian shape: a certbot-style
// vhost (HTTP redirect block + TLS block with a Let's Encrypt certificate,
// default_server, stapling) whose enabled entry is a symlink.
func cloneFixture(t *testing.T) (*nginxFixture, string) {
	t.Helper()
	root := t.TempDir()
	avail := filepath.Join(root, "sites-available")
	enabled := filepath.Join(root, "sites-enabled")
	src := `server {
    listen 80;
    server_name camalolo.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl default_server;
    include snippets/block-dotfiles.conf;
    server_name camalolo.com www_alias.camalolo.com;

    ssl_certificate /etc/letsencrypt/live/camalolo.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/camalolo.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_stapling on;
    ssl_stapling_verify on;

    root /home/www/public/camalolo;
    index index.html;

    location /share {
        proxy_pass http://127.0.0.1:3099;
        proxy_set_header Host $host;
    }

    location / {
        try_files $uri $uri/ =404;
    }
}
`
	if err := os.MkdirAll(avail, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(enabled, 0o755); err != nil {
		t.Fatal(err)
	}
	srcFile := filepath.Join(avail, "camalolo.com")
	if err := os.WriteFile(srcFile, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../sites-available/camalolo.com", filepath.Join(enabled, "camalolo.com")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nginx.conf"), []byte("events { }\nhttp {\n    include "+enabled+"/*;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &nginxFixture{t: t, root: root, env: &NginxEnv{
		Binary:   "nginx",
		ConfPath: filepath.Join(root, "nginx.conf"),
	}}
	f.env.Runner = func(ctx context.Context, name string, args ...string) (ExecResult, error) {
		f.calls = append(f.calls, name+" "+strings.Join(args, " "))
		return ExecResult{}, nil
	}
	return f, srcFile
}

func TestInstallClonesForeignVhost(t *testing.T) {
	f, srcFile := cloneFixture(t)
	e := newTestEnv(t)
	now := time.Unix(1_700_000_000, 0)

	res, err := f.env.Install(e.home, e.keysDir, "www.camalolo", "",
		InstallOpts{CloneFrom: "camalolo.com"}, now)
	if err != nil {
		t.Fatalf("clone install: %v", err)
	}
	if !res.Cloned || res.ClonedSrc != "camalolo.com" || !res.Reloaded {
		t.Fatalf("clone result: %+v", res)
	}

	// Placement: real file in sites-available, enabled symlink beside the
	// source's own (relative target, Debian convention).
	real := filepath.Join(f.root, "sites-available", "freens-www.camalolo")
	link := filepath.Join(f.root, "sites-enabled", "freens-www.camalolo")
	b, err := os.ReadFile(real)
	if err != nil {
		t.Fatalf("cloned file missing: %v", err)
	}
	text := string(b)
	if target, lerr := os.Readlink(link); lerr != nil || target != "../sites-available/freens-www.camalolo" {
		t.Fatalf("enabled symlink wrong: %q %v", target, lerr)
	}

	// The SOURCE file is untouched.
	after, _ := os.ReadFile(srcFile)
	if !strings.Contains(string(after), "listen 443 ssl default_server;") {
		t.Fatal("source vhost was modified — clones must never touch it")
	}

	// Transformations: new name, our cert pair exactly once, no foreign
	// paths, no default_server/stapling; everything else survives.
	st, err := LoadState(e.home, "www.camalolo")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(text, "server_name www.camalolo;"); got != 2 {
		t.Fatalf("server_name rewrites = %d, want 2 (both blocks):\n%s", got, text)
	}
	if !strings.Contains(text, "ssl_certificate "+st.CertPath+";") ||
		!strings.Contains(text, "ssl_certificate_key "+st.KeyPath+";") {
		t.Fatalf("freens cert pair missing:\n%s", text)
	}
	for _, banned := range []string{
		"/etc/letsencrypt/live", "default_server", "ssl_stapling", "www_alias",
	} {
		if strings.Contains(text, banned) {
			t.Fatalf("cloned vhost still contains %q:\n%s", banned, text)
		}
	}
	for _, kept := range []string{
		"return 301 https://$server_name$request_uri;",
		"proxy_pass http://127.0.0.1:3099;",
		"try_files $uri $uri/ =404;",
		"include snippets/block-dotfiles.conf;",
		"include /etc/letsencrypt/options-ssl-nginx.conf;",
	} {
		if !strings.Contains(text, kept) {
			t.Fatalf("clone dropped %q:\n%s", kept, text)
		}
	}

	// Renewal tracking points at the real file.
	if len(st.NginxFiles) != 1 || st.NginxFiles[0] != real {
		t.Fatalf("tracked nginx files = %v, want [%s]", st.NginxFiles, real)
	}
	if !f.called("reload") || !f.called("-t") {
		t.Fatalf("validate/reload never ran: %v", f.calls)
	}
}

func TestInstallCloneDryRunAndMissingSource(t *testing.T) {
	f, srcFile := cloneFixture(t)
	e := newTestEnv(t)
	now := time.Unix(1_700_000_000, 0)

	// Dry run: plan only.
	res, err := f.env.Install(e.home, e.keysDir, "www.camalolo", "",
		InstallOpts{CloneFrom: "camalolo.com", DryRun: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Edited) != 1 || res.Reloaded {
		t.Fatalf("dry run result: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(f.root, "sites-available", "freens-www.camalolo")); !os.IsNotExist(err) {
		t.Fatal("dry run created the clone file")
	}

	// Unknown clone source: a precise error, source tree untouched.
	_, err = f.env.Install(e.home, e.keysDir, "www.camalolo", "",
		InstallOpts{CloneFrom: "nosuch.example"}, now)
	if err == nil || !strings.Contains(err.Error(), "nosuch.example") || !strings.Contains(err.Error(), "cannot clone") {
		t.Fatalf("clone-source miss error = %v", err)
	}
	if _, serr := os.Stat(srcFile); serr != nil {
		t.Fatal("source vanished?!")
	}
}

// TestCloneFailedValidateCleansUpThroughSudo: a clone written through the
// sudo path (`sudo -n install` → a root-owned file in a root-owned tree)
// that nginx -t rejects must be removed through the SAME privilege path —
// the daemon user's direct unlink is refused, and a rejected clone left in
// the config tree bricks every nginx reload/restart while the message
// claims "(removed)". Realistic trigger: the transform copies only the
// server{} block, so a vhost depending on http-level directives (map /
// limit_req_zone / upstream) fails validation.
func TestCloneFailedValidateCleansUpThroughSudo(t *testing.T) {
	root := t.TempDir()
	avail := filepath.Join(root, "sites-available")
	enabled := filepath.Join(root, "sites-enabled")
	if err := os.MkdirAll(avail, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(enabled, 0o755); err != nil {
		t.Fatal(err)
	}
	// The source vhost uses a variable defined by an http-level map: the
	// clone cannot carry the map, so a REAL nginx -t would reject it — the
	// exact shape that used to leak rejected clones into the tree.
	src := `server {
    listen 443 ssl;
    server_name camalolo.com;
    ssl_certificate /etc/letsencrypt/live/camalolo.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/camalolo.com/privkey.pem;
    proxy_pass http://$src_backend; # defined by an http-level map
}
`
	srcFile := filepath.Join(avail, "camalolo.com")
	if err := os.WriteFile(srcFile, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../sites-available/camalolo.com", filepath.Join(enabled, "camalolo.com")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nginx.conf"),
		[]byte("events { }\nhttp {\n    include "+enabled+"/*;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Unwritable tree (the root-owned /etc/nginx shape) forces the clone
	// through `sudo -n install` instead of the direct write.
	if err := os.Chmod(avail, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(enabled, 0o555); err != nil {
		t.Fatal(err)
	}
	// Restore BEFORE t.TempDir's own cleanup (LIFO) so it can remove the tree.
	t.Cleanup(func() { os.Chmod(avail, 0o755); os.Chmod(enabled, 0o755) })
	if pf, perr := os.CreateTemp(avail, "probe*"); perr == nil {
		pf.Close()
		os.Remove(pf.Name())
		t.Skip("running as root: cannot simulate an unwritable config tree")
	}

	f := &nginxFixture{t: t, root: root, env: &NginxEnv{
		Binary:   "nginx",
		ConfPath: filepath.Join(root, "nginx.conf"),
	}}
	tCalls := 0
	f.env.Runner = func(ctx context.Context, name string, args ...string) (ExecResult, error) {
		line := name + " " + strings.Join(args, " ")
		f.calls = append(f.calls, line)
		if strings.Contains(line, " -t ") {
			tCalls++
			if tCalls == 1 {
				// The clone is rejected…
				return ExecResult{Stderr: `nginx: [emerg] unknown "src_backend" variable`}, errors.New("exit 1")
			}
			// …the post-cleanup re-validation finds the tree healthy again.
		}
		return ExecResult{}, nil
	}

	// Simulate the privileged helper through the SAME seam the product code
	// uses for sudo (execRunner): install places the file, ln links, rm
	// removes. The stub is not actually root, so each op briefly re-grants
	// the directory permission it is emulating root for.
	realExec := execRunner
	privileged := func(dir string, fn func() error) error {
		os.Chmod(dir, 0o755)
		defer os.Chmod(dir, 0o555)
		return fn()
	}
	execRunner = func(ctx context.Context, name string, args ...string) (ExecResult, error) {
		line := name + " " + strings.Join(args, " ")
		f.calls = append(f.calls, line)
		switch {
		case name == "sudo" && strings.Contains(line, " install "):
			staged, dest := args[len(args)-2], args[len(args)-1]
			b, rerr := os.ReadFile(staged)
			if rerr != nil {
				return ExecResult{}, rerr
			}
			return ExecResult{}, privileged(filepath.Dir(dest), func() error {
				return os.WriteFile(dest, b, 0o644)
			})
		case name == "sudo" && strings.Contains(line, " ln "):
			return ExecResult{}, privileged(filepath.Dir(args[len(args)-1]), func() error {
				return os.Symlink(args[len(args)-2], args[len(args)-1])
			})
		case name == "sudo" && strings.Contains(line, " rm "):
			return ExecResult{}, privileged(filepath.Dir(args[len(args)-1]), func() error {
				return os.Remove(args[len(args)-1])
			})
		}
		return realExec(ctx, name, args...)
	}
	t.Cleanup(func() { execRunner = realExec })
	oldSudo := sudoAvailable
	sudoAvailable = func() bool { return true }
	t.Cleanup(func() { sudoAvailable = oldSudo; resetSudoCache() })

	e := newTestEnv(t)
	_, err := f.env.Install(e.home, e.keysDir, "www.camalolo", "",
		InstallOpts{CloneFrom: "camalolo.com"}, time.Unix(1_700_000_000, 0))
	if err == nil {
		t.Fatal("clone should fail when validation rejects it")
	}
	if !strings.Contains(err.Error(), "removed") {
		t.Fatalf("error should report the clean removal: %v", err)
	}

	real := filepath.Join(avail, "freens-www.camalolo")
	link := filepath.Join(enabled, "freens-www.camalolo")
	for _, p := range []string{real, link} {
		if _, serr := os.Stat(p); !os.IsNotExist(serr) {
			t.Errorf("rejected clone left behind: %s (err=%v)", p, serr)
		}
	}
	// The removal ran through the sudo seam, and the tree was re-validated
	// afterwards (second nginx -t, AFTER the rm).
	rmIdx, lastT := -1, -1
	for i, c := range f.calls {
		if strings.Contains(c, " rm -f -- "+real) {
			rmIdx = i
		}
		if strings.Contains(c, " -t ") {
			lastT = i
		}
	}
	if rmIdx < 0 {
		t.Errorf("removal did not go through sudo rm: %v", f.calls)
	}
	if tCalls != 2 || lastT < rmIdx {
		t.Errorf("nginx -t not re-run after cleanup (t=%d, rm@%d, last -t@%d): %v",
			tCalls, rmIdx, lastT, f.calls)
	}
}

func TestResolveBinarySbinCandidates(t *testing.T) {
	// Hermetic by force: GitHub's Ubuntu runner images PREINSTALL nginx on
	// PATH (found live in the v0.13.10 CI — resolveBinary rightly returned
	// the PATH binary there), so the test stubs the LookPath seam to
	// simulate the "off PATH" box the sbin candidates exist for.
	oldLook, oldCands := execLookPath, nginxBinaryCandidates
	defer func() { execLookPath, nginxBinaryCandidates = oldLook, oldCands }()
	execLookPath = func(string) (string, error) { return "", exec.ErrNotFound }

	// nginx off PATH but present as /usr/sbin-style candidate: found.
	dir := t.TempDir()
	fake := filepath.Join(dir, "nginx")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	nginxBinaryCandidates = []string{"/nonexistent/nginx", fake}
	if got := resolveBinary(); got != fake {
		t.Fatalf("resolveBinary = %q, want %q", got, fake)
	}
	// Nowhere: bare name (Locate turns the exec failure into the sentinel).
	nginxBinaryCandidates = []string{"/nonexistent/nginx"}
	if got := resolveBinary(); got != "nginx" {
		t.Fatalf("resolveBinary fallback = %q, want %q", got, "nginx")
	}
}
