// upgrade.go — `freens upgrade`: pull the latest GitHub release and install
// it in place, without ssh, without a tarball, without a trip to the dev
// box. The verb runs END TO END on the target machine:
//
//  1. query api.github.com for the latest (or -version-pinned) release
//  2. pick the asset for this platform (freens-<goos>-<goarch>.tar.gz)
//  3. download + unpack the 3 binaries into a staging dir
//  4. VERIFY the staged binary actually runs and reports the release tag
//     (the CI ships no checksums; "does `freens version` disagree?" is the
//     whole download-integrity story)
//  5. run `upgrade-migrate` THROUGH THE NEW binary so config patches are
//     applied with the knowledge cutoff of the version being installed,
//     not the old one — an old binary cannot know the migrations a newer
//     release needs (this is why the patch table lives here and `setup`
//     does not grow a similar hook)
//  6. put the new binaries in place of the running ones (staging file in
//     the SAME directory + rename = atomic; backup each old binary to
//     *.freens-prev first; the process replaces ITS OWN image — renaming
//     over a running executable is legal on Linux, the open inode keeps
//     running the old code through the rest of this verb)
//  7. restart every active freens* systemd unit (daemon + webui + any comm
//     chairs), then poll the admin socket until the daemon answers
//
// The confirmation prompt is the ONLY interaction: -yes skips it for
// scripts, -check is fully read-only ("is there anything newer?").
//
// All OS side effects (systemctl, privileged writes into /usr/local/bin)
// go through the same sys* indirections as setup.go, so the whole flow is
// testable against a fake GitHub server and a fake install directory.
package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/keychain"
)

// githubOwnerRepo is the release source for self-upgrade. Everything else
// about the process (path layout, unit names, tarball names) is keyed off
// the release.yml build matrix or the setup unit, so an org rename touches
// exactly this one line.
const githubOwnerRepo = "camalolo/freens"

// GitHub endpoint bases (vars so tests can fake the API).
var (
	upgradeReleaseURL       = "https://api.github.com/repos/" + githubOwnerRepo + "/releases/latest"
	upgradeTagURLBase       = "https://api.github.com/repos/" + githubOwnerRepo + "/releases/tags/"
	maxBinarySize     int64 = 1 << 28 // 256 MiB per unpacked member — releases are ~13 MiB
)

// releaseBinaries are the three executables every release tarball ships
// (release.yml builds all of them in lockstep). Order matters for output
// and for restart order indirectly (freens daemon = the important one).
var releaseBinaries = []string{"freens", "freens-cli", "freens-web"}

// ---------------------------------------------------------------------------
// GitHub API
// ---------------------------------------------------------------------------

// ghAsset is one file attached to a release (json shape of the REST API).
type ghAsset struct {
	Name            string `json:"name"`
	Size            int64  `json:"size"`
	BrowserDownload string `json:"browser_download_url"`
}

// ghRelease is the slim subset of the release object upgrade needs.
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

// fetchRelease resolves the release to install: the -version tag if given
// (a missing leading "v" is added: the repo tags releases v-prefixed),
// else the newest release/branch-carrying tag (releases/latest, which
// GitHub defines as non-draft, non-prerelease, newest by semver).
func fetchRelease(tag string) (*ghRelease, error) {
	url := upgradeReleaseURL
	if tag != "" {
		if !strings.HasPrefix(tag, "v") {
			tag = "v" + tag
		}
		url = upgradeTagURLBase + tag
	}
	rel, err := upgradeFetchRelease(url)
	if err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("release at %s has no tag_name", url)
	}
	return rel, nil
}

// upgradeFetchRelease GETs one GitHub releases endpoint and decodes the
// subset of the object we use. Swapped by tests.
var upgradeFetchRelease = func(url string) (*ghRelease, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	// Optional token raises the unauthenticated 60 req/h API budget; also
	// the polite thing for release CDNs behind GitHub's rate limits.
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github api: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("github api: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var rel ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("github api: decode release: %w", err)
	}
	return &rel, nil
}

// releaseAssetName is the CI naming scheme (release.yml): one tarball per
// GOOS/GOARCH with the three binaries inside.
func releaseAssetName() string {
	return "freens-" + runtime.GOOS + "-" + runtime.GOARCH + ".tar.gz"
}

// assetFor picks this platform's tarball from the release.
func assetFor(rel *ghRelease) (*ghAsset, error) {
	want := releaseAssetName()
	for i := range rel.Assets {
		if rel.Assets[i].Name == want {
			return &rel.Assets[i], nil
		}
	}
	names := make([]string, 0, len(rel.Assets))
	for _, a := range rel.Assets {
		names = append(names, a.Name)
	}
	return nil, fmt.Errorf("release %s has no %s for this machine (assets: %s)",
		rel.TagName, want, strings.Join(names, ", "))
}

// ---------------------------------------------------------------------------
// download + staging
// ---------------------------------------------------------------------------

// upgradeDownload streams the asset into dir and returns its path. The
// download runs with a generous budget (a v0.x tarball is ~20 MiB; slow
// links are the norm on LAN test boxes). Swapped by tests.
var upgradeDownload = func(url, dir string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: %s", url, resp.Status)
	}
	path := filepath.Join(dir, "release.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	// The GitHub-asset CDs generally don't send a length on redirect
	// chains; the 512 MiB limit guards a malicious/truncated body.
	n, err := io.Copy(f, io.LimitReader(resp.Body, 1<<29))
	if err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	if n >= 1<<29 {
		return "", fmt.Errorf("download %s: body exceeds 512 MiB", url)
	}
	return path, nil
}

// stageTarball unpacks the three release binaries (and ONLY those — the
// tarball is extracted member-by-member, never a blind untar) into stageDir
// as 0755 executables. Returns the staged path of each binary.
func stageTarball(tarPath, stageDir string) (map[string]string, error) {
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.Open(tarPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("release tarball: not gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	staged := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("release tarball: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := filepath.Base(hdr.Name)
		// Windows tarballs ship the binaries with an .exe suffix; match and
		// stage them under the plain release name so every consumer below
		// (staged["freens"], installTargetPath) stays GOOS-agnostic.
		if !sliceContains(releaseBinaries, strings.TrimSuffix(base, ".exe")) || staged[strings.TrimSuffix(base, ".exe")] != "" {
			continue
		}
		base = strings.TrimSuffix(base, ".exe")
		// …but the staged FILE gets the platform's executable name: Windows
		// CreateProcess appends ".exe" to an extensionless path and would
		// never find plain "freens" (verifyStaged / upgradeRunMigrate exec
		// the staged binary before anything is installed).
		dst := filepath.Join(stageDir, releaseBinaryName(base))
		// One member at a time, size-capped: a hostile tarball cannot fill
		// the disk past the 256 MiB gate before we bail.
		w, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
		if err != nil {
			return nil, err
		}
		_, cpErr := io.Copy(w, io.LimitReader(tr, maxBinarySize))
		closeErr := w.Close()
		if cpErr != nil {
			return nil, fmt.Errorf("release tarball: %s: %w", base, cpErr)
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if info, err := os.Stat(dst); err != nil || info.Size() >= maxBinarySize {
			return nil, fmt.Errorf("release tarball: %s exceeds %d bytes", base, maxBinarySize)
		}
		staged[base] = dst
	}
	if staged["freens"] == "" {
		return nil, fmt.Errorf("release tarball has no %s (corrupt download?)", releaseAssetName())
	}
	return staged, nil
}

func sliceContains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

// verifyStaged runs the staged freens binary and requires it to report the
// target tag. CI ships no checksums, so this execution test IS the
// download-integrity check: a truncated/corrupt tarball or a cross-arch
// build fails here, before a single byte of the live install is touched.
// Var for tests (the e2e test's fake payload is a script — executable only
// on unixes; windows stubs the exec, linux exercises it for real).
var verifyStaged = func(binPath, tag string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binPath, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("staged freens does not run (%v) — corrupt download or wrong architecture?", err)
	}
	got := strings.TrimSpace(string(out))
	want := "freens " + tag
	if got != want {
		return fmt.Errorf("staged freens reports %q; expected %q (bad download?)", got, want)
	}
	return nil
}

// ---------------------------------------------------------------------------
// versions
// ---------------------------------------------------------------------------

// versionNumbers is a parseable release tag: numeric triple + optional
// repo-style suffix ("v0.9.3-tls"). Suffixes FOLLOW the number in this
// repo's ordering (v0.9.3-tls shipped after v0.9.1; a hypothetical plain
// v0.9.3 would be indistinguishable — both read as "the same number" and
// upgrade compares like-for-like).
type versionNumbers struct {
	nums   [3]int
	suffix string
}

// parseVersion parses "vX.Y.Z[-suffix]" (X.Y or X accepted). dev/local
// stamps return ok=false.
func parseVersion(s string) (versionNumbers, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return versionNumbers{}, false
	}
	numsPart, suffix, _ := strings.Cut(s, "-")
	if numsPart == "" || (suffix == "" && strings.Contains(s, "-")) {
		return versionNumbers{}, false // "v-1.2.3", "v0.9.3-"
	}
	parts := strings.Split(numsPart, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return versionNumbers{}, false
	}
	var v versionNumbers
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return versionNumbers{}, false
		}
		v.nums[i] = n
	}
	v.suffix = strings.TrimSpace(suffix)
	return v, true
}

// compareVersions orders release tags: numeric triple first, then the
// suffix (plain < suffixed for the same number, repo convention; two
// suffixes order lexically). ok=false when either side is not a release
// tag (dev, garbage).
func compareVersions(a, b string) (int, bool) {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	if !aok || !bok {
		return 0, false
	}
	for i := range av.nums {
		if av.nums[i] != bv.nums[i] {
			if av.nums[i] < bv.nums[i] {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case av.suffix == bv.suffix:
		return 0, true
	case av.suffix == "":
		return -1, true
	case bv.suffix == "":
		return 1, true
	default:
		return strings.Compare(av.suffix, bv.suffix), true
	}
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

// sysExecutable is os.Executable as a var so tests can point the upgrade at
// a fake install directory.
var sysExecutable = os.Executable

// sysOutput captures a command's stdout (unlike sysRun, which streams) —
// used for `systemctl list-units`. Swapped by tests.
var sysOutput = func(name string, args ...string) (string, error) {
	c := exec.Command(name, args...)
	out, err := c.Output()
	return string(out), err
}

// sysDirWritable probes whether the current user may create files in dir
// (the cheap gate for "install without sudo"). Swapped by tests.
var sysDirWritable = func(dir string) bool {
	probe, err := os.CreateTemp(dir, ".freens-write-*")
	if err != nil {
		return false
	}
	name := probe.Name()
	probe.Close()
	os.Remove(name)
	return true
}

// installDir resolves where the new binaries land: the directory of the
// RUNNING executable (symlinks resolved). freens-cli and freens-web go
// next to it regardless of which of the three this process is — the whole
// tool set must stay in lockstep.
func installDir() (string, error) {
	exe, err := sysExecutable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Dir(exe), nil
}

// upgradeRunMigrate executes the migration verb in the STAGED (new) binary:
// config patches arrive with the knowledge cutoff of the version being
// installed. Swapped by tests to run cmdUpgradeMigrate in-process.
var upgradeRunMigrate = func(newBin, from string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, newBin, "upgrade-migrate", "-from", from)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}

// installBinary swaps stagePath into place at target ATOMICALLY and without
// a gap: the new content lands in a staging file in the SAME directory
// (same filesystem => rename(2)), then renames over the target. The
// previous binary is kept as target.freens-prev for a one-command rollback.
// Non-writable directories use the sudo sequence from setup (cp -> chmod ->
// mv), prints manual commands only when even interactive sudo fails.
func installBinary(stagePath, target string) (result string, err error) {
	same, err := filesIdentical(stagePath, target)
	if err != nil {
		return "", err
	}
	if same {
		return "identical — skipped", nil
	}
	writable := sysDirWritable(filepath.Dir(target))
	base := filepath.Base(target)
	staging := target + ".freens-new"

	if !writable && runtime.GOOS == "windows" {
		// No sudo equivalent: an elevated shell is the only way in. The
		// caller stopped the service first, so nothing is half-swapped.
		return "", fmt.Errorf("%s is not writable by this user — re-run `upgrade` from an elevated (Run as administrator) shell", filepath.Dir(target))
	}
	if writable {
		if err := copyFile(stagePath, staging, 0o755); err != nil {
			return "", err
		}
	} else {
		if err := sudoRun("installing "+base, "cp", stagePath, staging); err != nil {
			return "", err
		}
		if err := sudoRun("installing "+base, "chmod", "755", staging); err != nil {
			return "", err
		}
	}
	if sysStatExists(target) {
		bak := target + ".freens-prev"
		if writable {
			_ = copyFile(target, bak, 0o755) // best effort
		} else {
			_ = sudoRun("backing up "+base, "cp", "-p", target, bak)
		}
	}
	// Replacing OUR OWN image: legal on Linux (the executing inode stays
	// alive until this process exits); case-preserving rename on macOS.
	// Windows refuses rename-over a RUNNING image but allows renaming the
	// running file itself — so on refusal, move the old image aside
	// (.freens-old; its last lock dies with the old process), put the new
	// one in place, and drop the aside (best effort: the current process's
	// own old image lingers until it exits).
	if writable {
		if err := os.Rename(staging, target); err != nil {
			aside := target + ".freens-old"
			if moveErr := os.Rename(target, aside); moveErr != nil {
				return "", err // the original refusal is the interesting one
			}
			if err2 := os.Rename(staging, target); err2 != nil {
				_ = os.Rename(aside, target) // put the old image back
				return "", err2
			}
			_ = os.Remove(aside)
		}
	} else if err := sudoRun("installing "+base, "mv", "-f", staging, target); err != nil {
		return "", err
	}
	return "installed", nil
}

// filesIdentical reports whether two files have the same sha256 (target
// missing => different, no error).
func filesIdentical(a, b string) (bool, error) {
	ha, err := fileSHA256(a)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	hb, err := fileSHA256(b)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return ha == hb, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// copyFile copies src to dst (streaming), mode forced.
func copyFile(src, dst string, mode os.FileMode) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()
	d, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, cpErr := io.Copy(d, s)
	closeErr := d.Close()
	if cpErr != nil {
		return cpErr
	}
	return closeErr
}

// ---------------------------------------------------------------------------
// restart + health
// ---------------------------------------------------------------------------

// activeFreensUnits lists the ACTIVE freens* service units (systemd glob
// honoring freens.service, freens-web.service, freens-comm* chairs, …).
// Only units whose ACTIVE state is "active" are listed — a FAILED unit
// stays failed (that is `freens doctor`'s problem, not an upgrade's).
// Starting stopped units is deliberately out of scope. Returns nil when
// systemctl is absent (non-systemd box) or nothing matches.
func activeFreensUnits() []string {
	out, err := sysOutput("systemctl", "list-units", "freens*", "--type=service", "--no-legend", "--plain")
	if err != nil {
		return nil
	}
	var units []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// Columns: UNIT LOAD ACTIVE SUB DESCRIPTION.
		if len(f) > 2 && f[2] == "active" && strings.HasSuffix(f[0], ".service") {
			units = append(units, f[0])
		}
	}
	// The daemon first, the web UI last, anything else between.
	sort.SliceStable(units, func(i, j int) bool { return unitRestartRank(units[i]) < unitRestartRank(units[j]) })
	return units
}

func unitRestartRank(u string) int {
	switch u {
	case "freens.service":
		return 0
	case "freens-web.service":
		return 9
	default:
		return 5
	}
}

// restartFreensUnits restarts the given units via sudoRun (interactive
// sudo on a TTY, manual commands printed when even that fails).
func restartFreensUnits(units []string) {
	for _, u := range units {
		fmt.Println("running: systemctl restart " + u)
		if err := sudoRun("restarting "+u, "systemctl", "restart", u); err != nil {
			fmt.Fprintf(os.Stderr, "%s: warning: restart %s failed (%v) — roll back with:\n", ProgName, u, err)
			for _, b := range releaseBinaries {
				fmt.Fprintf(os.Stderr, "    sudo cp %s %s\n", installBackupPath(b), installTargetPath(b))
			}
		}
	}
}

// installTargetPath / installBackupPath report the in-place / rollback
// paths of a release binary (errors swallowed — they only feed warnings).
// Windows binaries carry an .exe suffix (matching the release tarball).
func installTargetPath(bin string) string {
	dir, err := installDir()
	if err != nil {
		return bin
	}
	return filepath.Join(dir, releaseBinaryName(bin))
}

func installBackupPath(bin string) string {
	return installTargetPath(bin) + ".freens-prev"
}

// releaseBinaryName maps a release binary's plain name to this platform's
// on-disk name (freens.exe on windows).
func releaseBinaryName(bin string) string {
	if runtime.GOOS == "windows" {
		return bin + ".exe"
	}
	return bin
}

// waitDaemonBack polls the admin socket until the daemon answers status
// (up to d), printing what it finds. Only meaningful after a restart where
// a daemon was previously alive.
func waitDaemonBack(d time.Duration) {
	sock := home.AdminSock()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if admin.Alive(sock) {
			c := &admin.Client{Sock: sock, Timeout: 2 * time.Second}
			if st, err := c.Status(context.Background()); err == nil {
				fmt.Printf("daemon back: version %s, %d peers\n", st.Version, st.Peers)
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "%s: warning: daemon did not answer its admin socket within %s\n", ProgName, d)
	if goosWindows {
		fmt.Fprintln(os.Stderr, "  check `freens doctor` (service: `net start freens`); roll back with the *.freens-prev files listed above")
	} else {
		fmt.Fprintln(os.Stderr, "  check `systemctl status freens` or `freens doctor`; roll back with the *.freens-prev files listed above")
	}
}

// ---------------------------------------------------------------------------
// upgrade
// ---------------------------------------------------------------------------

// cmdUpgrade drives the whole self-update. Flags:
//
//	-check     read-only: report the latest release and whether we have it
//	-version   install a specific tag instead of the latest
//	-force     proceed even when already up to date (or pinning a
//	           downgrade, or the current build has no release stamp)
//	-yes       skip the confirmation prompt (scripts, fleet ssh)
func cmdUpgrade(args []string) error {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	check := fs.Bool("check", false, "only compare against the latest GitHub release; touch nothing")
	force := fs.Bool("force", false, "install even when already up to date (or when the current binary has no release stamp)")
	wantTag := fs.String("version", "", "install this exact release tag (default: latest)")
	yes := fs.Bool("yes", false, "answer yes to the confirmation prompt (for scripts)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("upgrade takes no positional arguments")
	}
	if platform != "linux" && platform != "darwin" && platform != "windows" {
		return usageErr("upgrade supports linux, darwin and windows (this is %s)", runtime.GOOS)
	}

	current := Version
	rel, err := fetchRelease(*wantTag)
	if err != nil {
		return err
	}
	asset, err := assetFor(rel)
	if err != nil {
		return err
	}
	tag := rel.TagName

	// Comparison: -1 newer available, 0 same, +1 installed is newer, !ok
	// current is not a release stamp (dev/local build).
	cmp, comparable := compareVersions(current, tag)
	if *check {
		fmt.Printf("running: %s\n", currentStampLine(current, comparable))
		fmt.Printf("latest release: %s (%s, %s)\n", tag, asset.Name, humanBytes(asset.Size))
		switch {
		case !comparable:
		case cmp < 0:
			fmt.Printf("upgrade available: %s -> %s\n", current, tag)
		case cmp == 0:
			fmt.Println("up to date.")
		default:
			fmt.Printf("installed (%s) is NEWER than %s\n", current, tag)
		}
		return nil
	}

	if comparable && cmp == 0 && !*force {
		fmt.Printf("already up to date (%s).\n", current)
		return nil
	}
	if !comparable && !*force {
		return usageErr("this binary has no release version stamp (%q) — pass -force to install %s anyway, or compare first with `freens upgrade -check`", current, tag)
	}
	if comparable && cmp > 0 && !*force {
		return usageErr("%s is OLDER than the running %s (downgrade) — pass -force to pin it anyway", tag, current)
	}

	if !*yes {
		if !sysIsTerminal() {
			return usageErr("this is not an interactive session — re-run with -yes to proceed (or -check to just compare)")
		}
		fmt.Printf("install %s over %s (binaries in %s, then restart the freens* services)? [y/N] ",
			tag, currentStampLine(current, comparable), mustInstallDir())
		var resp string
		if _, err := fmt.Scanln(&resp); err != nil {
			return fmt.Errorf("reading confirmation: %w", err)
		}
		resp = strings.ToLower(strings.TrimSpace(resp))
		if resp != "y" && resp != "yes" {
			fmt.Println("aborted.")
			return nil
		}
	}

	work, err := os.MkdirTemp("", "freens-upgrade-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	fmt.Printf("downloading %s (%s) ...\n", asset.Name, humanBytes(asset.Size))
	tarPath, err := upgradeDownload(asset.BrowserDownload, work)
	if err != nil {
		return err
	}
	staged, err := stageTarball(tarPath, filepath.Join(work, "stage"))
	if err != nil {
		return err
	}
	fmt.Printf("verifying staged %s reports %s ...\n", "freens", tag)
	if err := verifyStaged(staged["freens"], tag); err != nil {
		return err
	}

	wasAlive := admin.Alive(home.AdminSock())

	// Config migrations THROUGH THE NEW BINARY: it knows every patch a
	// (from -> tag) transition needs; the running old binary might not.
	fmt.Println("config migrations:")
	if err := upgradeRunMigrate(staged["freens"], current); err != nil {
		// A staged binary that cannot run its own verb is the same class
		// of failure as verifyStaged — refuse before touching a byte.
		return fmt.Errorf("staged freens could not run its config migrations: %w", err)
	}

	// Windows: the SCM service LOCKS its binary image — stop it before a
	// byte moves and start it again after. (Linux/darwin rename over the
	// running image instead, so systemd needs no dance.)
	winServiceWasRunning := false
	if goosWindows {
		winServiceWasRunning = winSvcRunning()
		if winServiceWasRunning {
			if !winSvcElevated() {
				return usageErr("the freens service is running and `upgrade` needs admin rights to restart it — re-run from an elevated (Run as administrator) shell (or `net stop freens` first)")
			}
			fmt.Println("stopping service freens (Windows locks a running image)…")
			if err := winSvcStop(); err != nil {
				return fmt.Errorf("stopping the freens service: %w", err)
			}
		}
	}

	// Install each binary in place of the running one.
	fmt.Println("installing:")
	var installErr error
	for _, bin := range releaseBinaries {
		target := installTargetPath(bin)
		res, err := installBinary(staged[bin], target)
		if err != nil {
			installErr = fmt.Errorf("installing %s: %w", target, err)
			break
		}
		fmt.Printf("  %s: %s\n", target, res)
	}
	if installErr != nil {
		if goosWindows && winServiceWasRunning {
			// Leave the machine as we found it: the old binaries are all
			// still in place (or restored), so a plain start succeeds.
			_ = winSvcStart()
		}
		return installErr
	}

	// Restart the services around the new binaries.
	if goosWindows {
		restartWindowsService(winServiceWasRunning)
	} else {
		units := activeFreensUnits()
		if len(units) == 0 {
			fmt.Println("no active freens* systemd units found — restart the daemon yourself (systemctl restart freens.service)")
		} else {
			fmt.Printf("restarting: %s\n", strings.Join(units, ", "))
			restartFreensUnits(units)
		}
	}

	if wasAlive {
		fmt.Println("health check:")
		waitDaemonBack(20 * time.Second)
	}

	fmt.Println("upgrade complete. previous binaries kept as <binary>.freens-prev (copy back + restart to roll back).")
	return nil
}

// restartWindowsService brings the SCM service back after an upgrade (or
// reports how to roll back when it refuses to start).
func restartWindowsService(wasRunning bool) {
	if !wasRunning {
		fmt.Println("service freens was not running — leaving it stopped (start with: net start freens)")
		return
	}
	fmt.Println("starting: service freens")
	if err := winSvcStart(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: starting the freens service failed (%v)\n", ProgName, err)
		fmt.Fprintln(os.Stderr, "  start it manually with `net start freens`; roll back with the *.freens-prev files listed above")
	}
}

// currentStampLine renders the installed version for prompts/checks.
func currentStampLine(current string, comparable bool) string {
	if !comparable {
		return current + " (no release stamp)"
	}
	return current
}

// mustInstallDir is the installDir with the error converted to a literal —
// used inside prompt text where failing loudly beats a silent empty string.
func mustInstallDir() string {
	dir, err := installDir()
	if err != nil {
		return "(unknown)"
	}
	return dir
}

// humanBytes renders asset sizes readably.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// ---------------------------------------------------------------------------
// config migrations (upgrade-migrate — internal verb)
// ---------------------------------------------------------------------------

// configPatch is one idempotent freens.conf migration. since is the
// release that introduced the requirement; the patch runs when upgrading
// FROM any version OLDER than since, and no-ops once applied (so re-runs
// are free and the same patch is safe from any from-version).
type configPatch struct {
	id    string
	since string
	desc  string
	apply func(conf string) (string, bool, error)
}

// configPatches is the migration table, applied by the NEW binary. Order
// matters only for output; each patch is independent and idempotent.
var configPatches = []configPatch{
	{
		id:    "webui-name",
		since: "v0.9.3",
		desc:  "[webui] name pinned to the single keychain alias (freens-web's alphabetical default is the wrong name when you own several)",
		apply: patchWebUIName,
	},
}

// upgradeMigrateConf is where cmdUpgradeMigrate reads/writes (var for tests;
// default = home.ConfPath()).
var upgradeMigrateConf = func() string { return home.ConfPath() }

// cmdUpgradeMigrate applies configPatches the NEW binary knows to the
// config of an install upgrading FROM -from. It backs the config up once
// (freens.conf.pre-upgrade, mirroring setup's resolv.conf backup naming)
// and rewrites it 0600, atomically (temp + rename). Runs with an unknown/
// dev -from it applies nothing and says so — a from-version must be a
// release tag for "older than since" to mean anything.
func cmdUpgradeMigrate(args []string) error {
	fs := flag.NewFlagSet("upgrade-migrate", flag.ContinueOnError)
	from := fs.String("from", "", "the version being upgraded FROM (patches with a newer `since` run)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("upgrade-migrate takes no positional arguments")
	}
	confPath := upgradeMigrateConf()
	cur, err := os.ReadFile(confPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("config: none at %s — nothing to migrate\n", confPath)
			return nil
		}
		return err
	}
	fromV, ok := parseVersion(*from)
	if !ok {
		fmt.Printf("config: current version %q is not a release stamp — skipping config migrations\n", *from)
		return nil
	}

	applied := 0
	backupPath := confPath + ".pre-upgrade"
	for _, p := range configPatches {
		sinceV, ok := parseVersion(p.since)
		if !ok {
			continue
		}
		if compareVersionsNumbers(fromV, sinceV) >= 0 {
			continue // from >= since: the requirement predates this install
		}
		out, did, err := p.apply(string(cur))
		if err != nil {
			return fmt.Errorf("config patch %s: %w", p.id, err)
		}
		if !did {
			continue
		}
		if applied == 0 {
			if err := os.WriteFile(backupPath, cur, 0o600); err != nil {
				return fmt.Errorf("config backup %s: %w", backupPath, err)
			}
		}
		cur = []byte(out)
		applied++
		fmt.Printf("config: %s (since %s): %s\n", p.id, p.since, p.desc)
	}

	if applied == 0 {
		fmt.Println("config: no patches needed")
		return nil
	}
	if err := writeFileAtomic0600(confPath, cur); err != nil {
		return fmt.Errorf("writing %s: %w", confPath, err)
	}
	fmt.Printf("config: %d patch(es) applied; previous config kept as %s\n", applied, backupPath)
	return nil
}

// compareVersionsNumbers is the struct-level compare (parseVersion is
// version-string level).
func compareVersionsNumbers(a, b versionNumbers) int {
	for i := range a.nums {
		if a.nums[i] != b.nums[i] {
			if a.nums[i] < b.nums[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case a.suffix == b.suffix:
		return 0
	case a.suffix == "":
		return -1
	case b.suffix == "":
		return 1
	default:
		return strings.Compare(a.suffix, b.suffix)
	}
}

// writeFileAtomic0600 persists config content atomically (temp in the same
// dir + rename), mirroring home.ConfPath's file conventions.
func writeFileAtomic0600(path string, data []byte) error {
	tmp := path + ".freens-new"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// patchWebUIName pins [webui] name to the keychain's alias when there is
// exactly ONE owner alias: freens-web falls back to the FIRST keychain
// alias alphabetically, which for multi-alias owners is a silent surprise
// (found live on the v0.9.3-tls fleet deploy — the default was NOT the
// name people expected). With 0 or >1 aliases there is nothing to pin;
// with a [webui] section that already names someone, leave it alone.
func patchWebUIName(conf string) (string, bool, error) {
	if iniKeyPresent(conf, "webui", "name") {
		return conf, false, nil
	}
	aliases := keychain.Aliases(home.KeysDir())
	if len(aliases) != 1 {
		return conf, false, nil
	}
	line := "name = " + aliases[0]
	if at, ok := iniSectionHeaderEnd(conf, "webui"); ok {
		return conf[:at] + line + "\n" + conf[at:], true, nil
	}
	if !strings.HasSuffix(conf, "\n") {
		conf += "\n"
	}
	return conf + "\n[webui]\n" + line + "\n", true, nil
}

// iniSectionHeaderEnd returns the byte offset right after the FIRST
// "[section]" header line's newline (the insertion point for new keys),
// ok=false when the section is absent.
func iniSectionHeaderEnd(conf, section string) (int, bool) {
	for _, line := range iniLines(conf) {
		s := strings.TrimSpace(line.text)
		if strings.HasPrefix(s, "[") &&
			strings.TrimSuffix(strings.TrimPrefix(s, "["), "]") == section {
			return line.end, true
		}
	}
	return 0, false
}

// iniKeyPresent reports whether section contains `key = ...` (comments and
// other sections are ignored; the key name is matched exactly, case 1:1
// like the webui parser).
func iniKeyPresent(conf, section, key string) bool {
	inSection := false
	for _, line := range iniLines(conf) {
		s := strings.TrimSpace(line.text)
		if s == "" || strings.HasPrefix(s, ";") || strings.HasPrefix(s, "#") {
			continue
		}
		if strings.HasPrefix(s, "[") {
			inSection = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]") == section
			continue
		}
		if !inSection {
			continue
		}
		if eq := strings.IndexByte(s, '='); eq > 0 && strings.TrimSpace(s[:eq]) == key {
			return true
		}
	}
	return false
}

// iniLine is one physical line with its char offsets into conf.
type iniLine struct {
	text  string
	start int
	end   int // index just past the trailing newline (== start for an empty tail line)
}

// iniLines splits conf into lines carrying byte offsets (the insert helper
// needs them to splice without re-scanning).
func iniLines(conf string) []iniLine {
	var out []iniLine
	off := 0
	for off <= len(conf) {
		nl := strings.IndexByte(conf[off:], '\n')
		if nl < 0 {
			if off < len(conf) {
				out = append(out, iniLine{text: conf[off:], start: off, end: len(conf)})
			}
			break
		}
		start := off
		line := conf[off : off+nl]
		off += nl + 1
		out = append(out, iniLine{text: line, start: start, end: off})
	}
	return out
}
