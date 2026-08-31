// upgrade_test.go — `freens upgrade` against a fake GitHub and a fake
// install directory: the whole download → verify → migrate → install →
// restart flow runs in-process with the sys* indirections swapped, and the
// config-migration table is exercised directly (idempotence included).
package cli

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeGitHub is the test double for the releases API: it answers with a
// release object whose assets point at urls the test controls.
type fakeGitHub struct {
	rel  ghRelease
	urls []string // recorded fetch URLs
}

func (g *fakeGitHub) fetch(url string) (*ghRelease, error) {
	g.urls = append(g.urls, url)
	rel := g.rel
	return &rel, nil
}

// installFakeGitHub points upgradeFetchRelease at the double and restores
// it (plus the download seam) when the test ends.
func installFakeGitHub(t *testing.T, rel ghRelease) *fakeGitHub {
	t.Helper()
	g := &fakeGitHub{rel: rel}
	savedFetch, savedDownload := upgradeFetchRelease, upgradeDownload
	upgradeFetchRelease = g.fetch
	upgradeDownload = func(url, dir string) (string, error) {
		t.Errorf("upgradeDownload called: %s (only -check ran — nothing should download)", url)
		return "", fmt.Errorf("no downloads in this test")
	}
	t.Cleanup(func() { upgradeFetchRelease, upgradeDownload = savedFetch, savedDownload })
	return g
}

// writeScript makes path an executable shell script printing its argument
// (the stand-in for a release binary, executable for verifyStaged).
func writeScript(t *testing.T, path, echo string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho "+echo+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// buildReleaseTarball gzips a tar with the three release binaries under the
// CI's directory prefix (release.yml: tar -C dist freens-<goos>-<goarch>),
// each binary being a script reporting its version.
func buildReleaseTarball(t *testing.T, path, tag string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	prefix := "freens-" + runtime.GOOS + "-" + runtime.GOARCH
	for _, bin := range releaseBinaries {
		body := fmt.Sprintf("#!/bin/sh\necho %s %s\n", bin, tag)
		if err := tw.WriteHeader(&tar.Header{
			Name: prefix + "/" + bin,
			Mode: 0o755,
			Size: int64(len(body)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------------
// version comparison
// ---------------------------------------------------------------------------

func TestParseVersion(t *testing.T) {
	good := map[string]versionNumbers{
		"v0.9.3":     {nums: [3]int{0, 9, 3}},
		"0.9.3":      {nums: [3]int{0, 9, 3}},
		"v0.9.3-tls": {nums: [3]int{0, 9, 3}, suffix: "tls"},
		"v0.9":       {nums: [3]int{0, 9, 0}},
		"v1":         {nums: [3]int{1, 0, 0}},
	}
	for in, want := range good {
		got, ok := parseVersion(in)
		if !ok || got != want {
			t.Errorf("parseVersion(%q) = %+v,%v; want %+v,true", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "dev", "vX.Y.Z", "v0.9.3-", "v-1.2.3", "v1.2.x"} {
		if _, ok := parseVersion(in); ok {
			t.Errorf("parseVersion(%q) parsed, want reject", in)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int // sign of a vs b; -2 = not comparable
	}{
		{"v0.9.1", "v0.9.3-tls", -1},
		{"v0.9.1", "v0.9.3", -1},
		{"v0.9.10", "v0.9.9", 1}, // numeric, not lexical
		{"v1.0.0", "v0.9.9", 1},
		{"v0.9.3-tls", "v0.9.3-tls", 0},
		{"v0.9.3", "v0.9.3", 0},
		// Repo convention: a suffixed tag is a follow-up release of the
		// same number, so it sorts above the plain number.
		{"v0.9.3", "v0.9.3-tls", -1},
		{"dev", "v9.9.9", -2},
		{"v0.9.1", "", -2},
	}
	for _, tt := range tests {
		got, ok := compareVersions(tt.a, tt.b)
		want := tt.want
		if want == -2 {
			if ok {
				t.Errorf("compareVersions(%q,%q) = %d,%v; want incomparable", tt.a, tt.b, got, ok)
			}
			continue
		}
		if !ok || sign(got) != want {
			t.Errorf("compareVersions(%q,%q) = %d,%v; want sign %d", tt.a, tt.b, got, ok, want)
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// ---------------------------------------------------------------------------
// release selection + fetch URL
// ---------------------------------------------------------------------------

func TestFetchReleaseURLForms(t *testing.T) {
	g := installFakeGitHub(t, ghRelease{TagName: "v0.9.3-tls"})
	if _, err := fetchRelease(""); err != nil {
		t.Fatal(err)
	}
	if _, err := fetchRelease("0.9.1"); err != nil {
		t.Fatal(err)
	}
	want := []string{upgradeReleaseURL, upgradeTagURLBase + "v0.9.1"}
	if len(g.urls) != 2 || g.urls[0] != want[0] || g.urls[1] != want[1] {
		t.Errorf("fetch URLs = %v; want %v", g.urls, want)
	}
}

func TestAssetForPicksPlatform(t *testing.T) {
	rel := ghRelease{TagName: "v9.9.9", Assets: []ghAsset{
		{Name: "freens-darwin-arm64.tar.gz", Size: 1, BrowserDownload: "https://x/darwin.tar.gz"},
		{Name: releaseAssetName(), Size: 2, BrowserDownload: "https://x/mine.tar.gz"},
	}}
	a, err := assetFor(&rel)
	if err != nil || a.Name != releaseAssetName() || a.BrowserDownload != "https://x/mine.tar.gz" {
		t.Fatalf("assetFor = %+v, %v; want the %s asset", a, err, releaseAssetName())
	}
	if _, err := assetFor(&ghRelease{TagName: "v9.9.9", Assets: []ghAsset{{Name: "freens-darwin-arm64.tar.gz"}}}); err == nil ||
		!strings.Contains(err.Error(), releaseAssetName()) {
		t.Errorf("missing-asset error = %v; want it to name %s", err, releaseAssetName())
	}
}

// ---------------------------------------------------------------------------
// staging + verification
// ---------------------------------------------------------------------------

func TestStageTarballAndVerify(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "release.tar.gz")
	buildReleaseTarball(t, tarPath, "v9.9.9")

	stage := filepath.Join(dir, "stage")
	staged, err := stageTarball(tarPath, stage)
	if err != nil {
		t.Fatal(err)
	}
	if len(staged) != len(releaseBinaries) {
		t.Fatalf("staged %d binaries; want %d", len(staged), len(releaseBinaries))
	}
	for _, bin := range releaseBinaries {
		info, err := os.Stat(staged[bin])
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o755 {
			t.Errorf("%s mode = %v; want 755", bin, info.Mode().Perm())
		}
	}
	if err := verifyStaged(staged["freens"], "v9.9.9"); err != nil {
		t.Errorf("verifyStaged: %v", err)
	}
	if err := verifyStaged(staged["freens"], "v9.9.8"); err == nil ||
		!strings.Contains(err.Error(), "v9.9.8") {
		t.Errorf("verifyStaged with wrong tag: %v; want a mismatch error", err)
	}
	// A non-gzip file must fail loudly (corrupt download).
	junk := filepath.Join(dir, "junk.tar.gz")
	os.WriteFile(junk, []byte("this is not gzip"), 0o644)
	if _, err := stageTarball(junk, filepath.Join(dir, "stage2")); err == nil {
		t.Error("stageTarball accepted a non-gzip file")
	}
}

// ---------------------------------------------------------------------------
// config migrations
// ---------------------------------------------------------------------------

// migrateTempHome wires FREENS_HOME to a temp dir with one keychain alias
// and (optionally) a starting freens.conf; returns the conf path.
func migrateTempHome(t *testing.T, conf string) string {
	t.Helper()
	dir := tempHome(t)
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Any hex-looking seed works: Aliases() only pattern-matches filenames.
	if err := os.WriteFile(filepath.Join(dir, "keys", "laurent.key"), []byte("aabb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(dir, "freens.conf")
	if conf != "" {
		if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	saved := upgradeMigrateConf
	upgradeMigrateConf = func() string { return confPath }
	t.Cleanup(func() { upgradeMigrateConf = saved })
	return confPath
}

func runMigrate(t *testing.T, from string) string {
	t.Helper()
	out, err := captureStdout(t, func() error { return cmdUpgradeMigrate([]string{"-from", from}) })
	if err != nil {
		t.Fatalf("cmdUpgradeMigrate(-from %s): %v", from, err)
	}
	return out
}

func TestUpgradeMigrateAppliesWebUIName(t *testing.T) {
	confPath := migrateTempHome(t, "[listen]\nudp = 127.0.0.1:5300\n\n[webui]\nlisten = :8090\n")
	out := runMigrate(t, "v0.9.1")
	if !strings.Contains(out, "webui-name") {
		t.Errorf("migrate output missing webui-name patch:\n%s", out)
	}
	got := string(mustRead(t, confPath))
	if !strings.Contains(got, "[webui]\nname = laurent\nlisten = :8090\n") {
		t.Errorf("patched config =\n%s\nwant name inserted right after the [webui] header", got)
	}
	// The pre-upgrade backup carries the ORIGINAL content.
	bak := string(mustRead(t, confPath+".pre-upgrade"))
	if !strings.Contains(bak, "listen = :8090") || strings.Contains(bak, "name = laurent") {
		t.Errorf("pre-upgrade backup =\n%s; want the unpatched original", bak)
	}
	// Idempotent: a second run from the same old version no-ops.
	out2 := runMigrate(t, "v0.9.1")
	if !strings.Contains(out2, "no patches needed") {
		t.Errorf("second migrate =\n%s; want a no-op", out2)
	}
	if got != string(mustRead(t, confPath)) {
		t.Error("second migrate changed the config")
	}
}

func TestUpgradeMigrateSkipsRecentFrom(t *testing.T) {
	confPath := migrateTempHome(t, "[webui]\nlisten = :8090\n")
	if out := runMigrate(t, "v0.9.3"); !strings.Contains(out, "no patches needed") {
		t.Errorf("migrate from v0.9.3 =\n%s; want no-op (patch predates the from version)", out)
	}
	if got := string(mustRead(t, confPath)); strings.Contains(got, "name = laurent") {
		t.Errorf("config changed on a no-op migrate:\n%s", got)
	}
}

func TestUpgradeMigrateUnknownFromIsANoOp(t *testing.T) {
	confPath := migrateTempHome(t, "[webui]\n")
	if out := runMigrate(t, "dev"); !strings.Contains(out, "not a release stamp") {
		t.Errorf("migrate from dev =\n%s; want the skip notice", out)
	}
	if got := string(mustRead(t, confPath)); strings.Contains(got, "name = laurent") {
		t.Errorf("config changed on an unknown from-version:\n%s", got)
	}
}

func TestUpgradeMigrateNoConfigFile(t *testing.T) {
	migrateTempHome(t, "")
	if out := runMigrate(t, "v0.9.1"); !strings.Contains(out, "nothing to migrate") {
		t.Errorf("migrate without a config =\n%s; want the fresh-install notice", out)
	}
}

func TestPatchWebUINameShapes(t *testing.T) {
	dir := tempHome(t)
	keys := filepath.Join(dir, "keys")
	os.MkdirAll(keys, 0o700)
	key := filepath.Join(keys, "laurent.key")
	os.WriteFile(key, []byte("aabb\n"), 0o600)

	// No [webui] section at all: the section is appended.
	out, changed, err := patchWebUIName("[listen]\nudp = 127.0.0.1:5300")
	if err != nil || !changed {
		t.Fatalf("patchWebUIName(no section) = changed %v, %v; want applied", changed, err)
	}
	if !strings.HasSuffix(out, "\n[webui]\nname = laurent\n") {
		t.Errorf("appended section =\n%q", out)
	}
	// An existing (commented) name does NOT count as present, but a real
	// key does.
	if !iniKeyPresent(out, "webui", "name") {
		t.Error("iniKeyPresent missed the freshly added name")
	}
	if iniKeyPresent("; name = x\n[webui]\nlisten = :8090\n", "webui", "name") {
		t.Error("iniKeyPresent counted a commented key")
	}
	// Two aliases: nothing to pin — freens-web's choice stays.
	os.WriteFile(filepath.Join(keys, "nanopi.key"), []byte("ccdd\n"), 0o600)
	if _, changed, err := patchWebUIName("[webui]\nlisten = :8090\n"); err != nil || changed {
		t.Errorf("patchWebUIName(two aliases) = changed %v, %v; want no-op", changed, err)
	}
	// Already named: no-op.
	os.Remove(filepath.Join(keys, "nanopi.key"))
	if _, changed, err := patchWebUIName("[webui]\nname = minipc\n"); err != nil || changed {
		t.Errorf("patchWebUIName(already named) = changed %v, %v; want no-op", changed, err)
	}
}

// ---------------------------------------------------------------------------
// restart discovery
// ---------------------------------------------------------------------------

func TestActiveFreensUnitsOrder(t *testing.T) {
	saved := sysOutput
	defer func() { sysOutput = saved }()
	sysOutput = func(name string, args ...string) (string, error) {
		if name != "systemctl" {
			t.Errorf("sysOutput cmd = %s %v; want systemctl list-units", name, args)
		}
		return "freens-web.service      loaded active running freens web\n" +
			"freens-comm1.service   loaded active running freens comm chair\n" +
			"freens.service          loaded active running freens daemon\n" +
			"freens-comm2.service   loaded failed failed freens comm chair\n", nil
	}
	got := activeFreensUnits()
	want := []string{"freens.service", "freens-comm1.service", "freens-web.service"}
	if len(got) != len(want) {
		t.Fatalf("activeFreensUnits = %v; want %v (failed units excluded)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("activeFreensUnits = %v; want %v (daemon first, web last)", got, want)
		}
	}
	sysOutput = func(name string, args ...string) (string, error) {
		return "", fmt.Errorf("systemctl: not found")
	}
	if got := activeFreensUnits(); got != nil {
		t.Errorf("activeFreensUnits without systemctl = %v; want nil", got)
	}
}

// ---------------------------------------------------------------------------
// -check (read-only)
// ---------------------------------------------------------------------------

func TestUpgradeCheckReportsAvailable(t *testing.T) {
	rel := ghRelease{TagName: "v9.9.9", Assets: []ghAsset{
		{Name: releaseAssetName(), Size: 13 << 20, BrowserDownload: "https://x/mine.tar.gz"},
	}}
	installFakeGitHub(t, rel)
	savedVersion := Version
	Version = "v0.9.1"
	defer func() { Version = savedVersion }()

	out, err := captureStdout(t, func() error { return cmdUpgrade([]string{"-check"}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"running: v0.9.1", "latest release: v9.9.9", "upgrade available: v0.9.1 -> v9.9.9", "13.0 MiB"} {
		if !strings.Contains(out, want) {
			t.Errorf("-check output missing %q:\n%s", want, out)
		}
	}

	Version = "v9.9.9"
	out, err = captureStdout(t, func() error { return cmdUpgrade([]string{"-check"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "up to date") {
		t.Errorf("-check at same version =\n%s; want \"up to date\"", out)
	}

	Version = "v9.9.10"
	out, err = captureStdout(t, func() error { return cmdUpgrade([]string{"-check"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "NEWER") {
		t.Errorf("-check when installed is newer =\n%s; want the NEWER note", out)
	}
}

// ---------------------------------------------------------------------------
// end-to-end: download → verify → migrate → install → restart
// ---------------------------------------------------------------------------

func TestUpgradeEndToEnd(t *testing.T) {
	dir := t.TempDir()
	homeDir := tempHome(t)

	// Config as a pre-v0.9.3 install would have it (webui section, no name)
	// plus a single keychain alias for the webui-name patch to pin.
	confPath := filepath.Join(homeDir, "freens.conf")
	os.WriteFile(confPath, []byte("[listen]\nudp = 127.0.0.1:5300\n\n[webui]\nlisten = :8090\n"), 0o600)
	os.MkdirAll(filepath.Join(homeDir, "keys"), 0o700)
	os.WriteFile(filepath.Join(homeDir, "keys", "laurent.key"), []byte("aabb\n"), 0o600)

	// Fake install dir with the three OLD binaries (must exist: installDir
	// resolves symlinks through the executable path).
	binDir := filepath.Join(dir, "bin")
	os.MkdirAll(binDir, 0o755)
	for _, bin := range releaseBinaries {
		writeScript(t, filepath.Join(binDir, bin), bin+" v0.9.1")
	}

	// Release assets served from a real tarball we build on the fly.
	tarPath := filepath.Join(dir, "release.tar.gz")
	buildReleaseTarball(t, tarPath, "v9.9.9")
	tag := "v9.9.9"
	g := &fakeGitHub{rel: ghRelease{TagName: tag, Assets: []ghAsset{
		{Name: releaseAssetName(), Size: mustSize(t, tarPath), BrowserDownload: "file://" + tarPath},
	}}}
	savedFetch, savedDownload := upgradeFetchRelease, upgradeDownload
	upgradeFetchRelease = g.fetch
	upgradeDownload = func(url, work string) (string, error) {
		if url != "file://"+tarPath {
			t.Errorf("download URL = %s; want %s", url, tarPath)
		}
		dst := filepath.Join(work, "release.tar.gz")
		b, err := os.ReadFile(tarPath)
		if err != nil {
			return "", err
		}
		return dst, os.WriteFile(dst, b, 0o644)
	}
	t.Cleanup(func() { upgradeFetchRelease, upgradeDownload = savedFetch, savedDownload })

	// OS seams: the executable lives in the fake bin dir; systemd "sees"
	// the daemon + web units active; sudo and raw commands are recorded.
	savedExe, savedSudo, savedRun, savedOut := sysExecutable, sysSudo, sysRun, sysOutput
	var ranSudo, ranSys [][]string
	sysExecutable = func() (string, error) { return filepath.Join(binDir, "freens"), nil }
	sysSudo = func(args ...string) error { ranSudo = append(ranSudo, args); return nil }
	sysRun = func(name string, args ...string) error {
		ranSys = append(ranSys, append([]string{name}, args...))
		return nil
	}
	sysOutput = func(name string, args ...string) (string, error) {
		return "freens.service loaded active running freens daemon\nfreens-web.service loaded active running freens web\n", nil
	}
	t.Cleanup(func() { sysExecutable, sysSudo, sysRun, sysOutput = savedExe, savedSudo, savedRun, savedOut })

	// Migrations run in-process (the staged "binary" is a script that
	// cannot run the real verb).
	savedMigrate := upgradeRunMigrate
	migrateFrom := ""
	upgradeRunMigrate = func(newBin, from string) error {
		migrateFrom = from
		_, err := captureStdout(t, func() error { return cmdUpgradeMigrate([]string{"-from", from}) })
		return err
	}
	t.Cleanup(func() { upgradeRunMigrate = savedMigrate })

	savedVersion := Version
	Version = "v0.9.1"
	defer func() { Version = savedVersion }()

	out, err := captureStdout(t, func() error {
		return cmdUpgrade([]string{"-yes"})
	})
	if err != nil {
		t.Fatalf("cmdUpgrade: %v\noutput:\n%s", err, out)
	}

	// Binaries replaced in place, 0755, old content kept as .freens-prev.
	for _, bin := range releaseBinaries {
		target := filepath.Join(binDir, bin)
		got, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("#!/bin/sh\necho %s %s\n", bin, tag)
		if string(got) != want {
			t.Errorf("%s content = %q; want %q", target, got, want)
		}
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o755 {
			t.Errorf("%s mode = %v; want 755", target, info.Mode().Perm())
		}
		prev, err := os.ReadFile(target + ".freens-prev")
		if err != nil || string(prev) != fmt.Sprintf("#!/bin/sh\necho %s v0.9.1\n", bin) {
			t.Errorf("%s.freens-prev = %q, %v; want the old script", target, prev, err)
		}
		// No staging leftovers.
		if _, err := os.Stat(target + ".freens-new"); !os.IsNotExist(err) {
			t.Errorf("%s.freens-new still exists", target)
		}
	}

	// Migrations ran through the NEW binary against the OLD from-version,
	// and the webui-name patch landed.
	if migrateFrom != "v0.9.1" {
		t.Errorf("upgrade-migrate -from = %q; want v0.9.1", migrateFrom)
	}
	conf := string(mustRead(t, confPath))
	if !strings.Contains(conf, "[webui]\nname = laurent\nlisten = :8090\n") {
		t.Errorf("post-upgrade config =\n%s; want [webui] name pinned", conf)
	}
	if _, err := os.Stat(confPath + ".pre-upgrade"); err != nil {
		t.Errorf("config backup missing: %v", err)
	}

	// Both active units restarted, daemon first. sysSudo receives its
	// args WITHOUT the "sudo" prefix (it is sudo's argv).
	var restarted []string
	for _, cmd := range ranSudo {
		if len(cmd) == 3 && cmd[0] == "systemctl" && cmd[1] == "restart" {
			restarted = append(restarted, cmd[2])
		}
	}
	if len(restarted) != 2 || restarted[0] != "freens.service" || restarted[1] != "freens-web.service" {
		t.Errorf("restarted = %v; want [freens.service freens-web.service]", restarted)
	}
	if !strings.Contains(out, "restarting: freens.service, freens-web.service") {
		t.Errorf("output missing the restart line:\n%s", out)
	}
	// No daemon was alive on the temp home, so the health check is skipped.
	if strings.Contains(out, "health check") {
		t.Errorf("health check ran although no daemon was alive before the upgrade:\n%s", out)
	}
}

// refuseTerminal gates the interactive prompt off in tests.
func TestUpgradeRefusesWithoutYesOnPipe(t *testing.T) {
	installFakeGitHub(t, ghRelease{TagName: "v9.9.9", Assets: []ghAsset{
		{Name: releaseAssetName(), BrowserDownload: "https://x/mine.tar.gz"},
	}})
	savedVersion := Version
	Version = "v0.9.1"
	defer func() { Version = savedVersion }()
	savedTerm := sysIsTerminal
	sysIsTerminal = func() bool { return false }
	t.Cleanup(func() { sysIsTerminal = savedTerm })

	err := cmdUpgrade([]string{})
	if err == nil || !strings.Contains(err.Error(), "-yes") {
		t.Errorf("non-interactive without -yes: err = %v; want a -yes hint", err)
	}
}

func TestUpgradeRejectsDowngradeWithoutForce(t *testing.T) {
	installFakeGitHub(t, ghRelease{TagName: "v0.1.0", Assets: []ghAsset{
		{Name: releaseAssetName(), BrowserDownload: "https://x/mine.tar.gz"},
	}})
	savedVersion := Version
	Version = "v0.9.1"
	defer func() { Version = savedVersion }()
	savedTerm := sysIsTerminal
	sysIsTerminal = func() bool { return false }
	t.Cleanup(func() { sysIsTerminal = savedTerm })

	err := cmdUpgrade([]string{"-yes"})
	if err == nil || !strings.Contains(err.Error(), "OLDER") {
		t.Errorf("downgrade without -force: err = %v; want the OLDER explanation", err)
	}
}

func TestUpgradeUpToDateShortCircuits(t *testing.T) {
	g := installFakeGitHub(t, ghRelease{TagName: "v0.9.1", Assets: []ghAsset{
		{Name: releaseAssetName(), BrowserDownload: "https://x/mine.tar.gz"},
	}})
	savedVersion := Version
	Version = "v0.9.1"
	defer func() { Version = savedVersion }()

	out, err := captureStdout(t, func() error { return cmdUpgrade([]string{"-yes"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "already up to date") {
		t.Errorf("output =\n%s; want the up-to-date notice", out)
	}
	if len(g.urls) != 1 {
		t.Errorf("up-to-date path hit GitHub %d times; want exactly 1", len(g.urls))
	}
}

func mustSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}
