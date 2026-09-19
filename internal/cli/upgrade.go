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
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/camalolo/freens/internal/blacklist"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/camalolo/freens/internal/blobman"
	"github.com/camalolo/freens/internal/confedit"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/dht"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/keychain"
	"github.com/camalolo/freens/internal/webui"
	"github.com/miekg/dns"
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

// upgradeHTTPGet GETs url with ONE automatic retry on a TRANSPORT error —
// dial/DNS/timeout, the fresh-box cold-upstream SERVFAIL class (found live
// on camalolo-box: its first `freens upgrade` died three times in a row on
// github.com lookups while the upstream resolver warmed; every manual
// retry was the user doing what the verb should have). HTTP-level errors
// are returned WITHOUT retrying — a 404 is an answer, not a hiccup.
func upgradeHTTPGet(ctx context.Context, url, accept string) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
				return nil, lastErr
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		// Optional token raises the unauthenticated 60 req/h API budget; also
		// the polite thing for release CDNs behind GitHub's rate limits.
		if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

// upgradeFetchRelease GETs one GitHub releases endpoint and decodes the
// subset of the object we use. Swapped by tests.
var upgradeFetchRelease = func(url string) (*ghRelease, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := upgradeHTTPGet(ctx, url, "application/vnd.github+json")
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

// checksumsAssetName is the SHA256SUMS.txt file release.yml attaches to
// every release (v0.19.7+). When present, a MIRROR-downloaded tarball is
// verified against it before anything is staged — the checksum travels
// from GitHub origin (a few hundred bytes; the slow path is irrelevant)
// so a compromised or misbehaving mirror cannot serve a tampered binary
// that merely REPORTS the right version.
const checksumsAssetName = "SHA256SUMS.txt"

// upgradeMirror returns the configured download-mirror base URL ("" ⇒
// download from GitHub origin). Env FREENS_UPGRADE_MIRROR wins over the
// [upgrade] mirror config key — an emergency bypass that works even when
// the config is stale or the mirror is temporarily broken.
func upgradeMirror() string {
	if m := strings.TrimSpace(os.Getenv("FREENS_UPGRADE_MIRROR")); m != "" {
		return strings.TrimRight(m, "/")
	}
	if m, found, err := confedit.Get(home.ConfPath(), "upgrade", "mirror"); err == nil && found {
		return strings.TrimRight(strings.TrimSpace(m), "/")
	}
	return ""
}

// mirrorAssetURL rewrites a GitHub release-download URL onto the mirror
// base, preserving the full github path: <mirror>/<owner>/<repo>/releases/
// download/... A mirror is therefore a TRANSPARENT github proxy (a worker
// or reverse proxy prepends https://github.com to the request path).
// Non-release URLs, foreign repos, and an empty mirror pass through
// unchanged — the API calls stay on github.com regardless (they are
// kilobytes).
func mirrorAssetURL(mirror, ghURL string) string {
	if mirror == "" {
		return ghURL
	}
	rest, ok := strings.CutPrefix(ghURL, "https://github.com/")
	if !ok || !strings.HasPrefix(rest, githubOwnerRepo+"/releases/download/") {
		return ghURL
	}
	return strings.TrimRight(mirror, "/") + "/" + rest
}

// fetchChecksums downloads SHA256SUMS.txt for the release FROM THE ORIGIN
// (never the mirror) and parses it into filename → sha256-hex. A missing
// asset (pre-v0.19.7 releases) yields nil, nil — verification is skipped
// and the mirror relies on the staged-version check alone.
func fetchChecksums(rel *ghRelease) (map[string]string, error) {
	var url string
	for i := range rel.Assets {
		if rel.Assets[i].Name == checksumsAssetName {
			url = rel.Assets[i].BrowserDownload
			break
		}
	}
	if url == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := upgradeHTTPGet(ctx, url, "")
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", checksumsAssetName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: %s", checksumsAssetName, resp.Status)
	}
	sums := make(map[string]string)
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		sums[fields[1]] = strings.ToLower(fields[0])
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parse %s: %w", checksumsAssetName, err)
	}
	return sums, nil
}

// verifyChecksum compares the downloaded tarball's SHA-256 with the
// release's published digest. A mismatch is a hard stop: a mirror that
// cannot reproduce origin's bytes must never reach staging.
func verifyChecksum(tarPath, assetName string, sums map[string]string) error {
	want, ok := sums[assetName]
	if !ok {
		return fmt.Errorf("%s has no checksum entry — refusing to stage from a mirror without one", assetName)
	}
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("checksum MISMATCH for %s: got %s, want %s — the download did not come from origin's bytes; aborting", assetName, got, want)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Chunked peer transfer (v0.19.7): the upgrade verb as a mini-swarm client.
// Peers are UNTRUSTED caches — every chunk is verified against the origin
// manifest before assembly, any failure falls back to origin — so the fleet
// becomes its own fast CDN without moving the trust anchor an inch.
// ---------------------------------------------------------------------------

// upgradeManifestAssetName is the CI naming scheme (release.yml): one chunk
// manifest per platform tarball.
func upgradeManifestAssetName() string {
	return "freens-manifest-" + runtime.GOOS + "-" + runtime.GOARCH + ".json"
}

// fetchUpgradeManifest pulls this platform's chunk manifest from GITHUB
// ORIGIN and validates it. nil (no error) when the release predates
// manifests — peer transfer simply doesn't engage.
func fetchUpgradeManifest(rel *ghRelease) *blobman.Manifest {
	var raw string
	for i := range rel.Assets {
		if rel.Assets[i].Name == upgradeManifestAssetName() {
			raw = rel.Assets[i].BrowserDownload
			break
		}
	}
	if raw == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := upgradeHTTPGet(ctx, raw, "")
	if err != nil {
		return nil // manifest fetch is best-effort: origin fallback below
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil
	}
	m, err := blobman.Parse(body)
	if err != nil {
		return nil
	}
	return m
}

// upgradePeerList gathers candidate peers for the swarm. DISK FIRST
// (the BitTorrent-resume rule, and the user's 20-year-old instinct is
// exactly right): the persisted peerbook already knows the fleet and
// survives restarts ON DISK — gating on the live daemon's freshly-warmed
// confirmation state made every post-restart upgrade swarm-blind (found
// live 2026-09-18: /peers showed 8 confirmed while the verb, started
// seconds after a daemon restart, saw zero and fell back to the slow
// origin path it existed to avoid). The live daemon's confirmed set is
// merged in when reachable. No confirmed-filtering: dead entries fail
// fast in the swarm's reachability gate and drop per-chunk.
func upgradePeerList() ([]dht.Peer, error) {
	seen := map[string]bool{}
	var out []dht.Peer
	add := func(ps []dht.Peer) {
		for _, p := range ps {
			if p.Addr == "" || seen[p.Addr] {
				continue
			}
			seen[p.Addr] = true
			out = append(out, p)
		}
	}
	// Peerbook first (disk survives restarts), then the live daemon set.
	book := home.LoadPeerbook()
	add(book)
	client := &admin.Client{Sock: home.AdminSock(), Timeout: 5 * time.Second}
	if admin.Alive(home.AdminSock()) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if live, err := client.Peers(ctx); err == nil {
			add(live)
		}
	}
	// THE PINNED COMMUNITY SEED is always in the list — not just as an
	// empty-list fallback. Its HOSTNAME resolves to the seed's CURRENT
	// public address, which makes it the one entry that cannot go stale:
	// boxes whose book is dominated by dead NAT mappings and one-shot
	// ephemeral ports (desktop and the friend's VPS during the v0.19.10/11
	// rolls — "context deadline exceeded" against twelve corpses) still
	// get one always-fresh bootstrap. Confirmed-fresh entries keep their
	// places ahead of it; stale ones come after.
	if seeds := home.ParseSeedsText(home.DefaultSeeds()); len(seeds) > 0 {
		add(seeds)
	}
	// VIABILITY BEFORE THE CAP: peers with no dialable address from this
	// machine drop out HERE, so foreign-LAN junk cannot consume slots in
	// the 12-cap (the user's original complaint: his bootstrap list was
	// crowded with 192.168.1.x entries he can never reach while real
	// candidates got capped out).
	nets := localNets()
	viable := make([]dht.Peer, 0, len(out))
	for _, p := range out {
		if len(dialPlan(p, nets)) > 0 {
			viable = append(viable, p)
		}
	}
	out = viable
	// Confirmation-recency ordering: live-confirmed first (freshest
	// first), never-confirmed last. The 12-cap then keeps the freshest
	// candidates instead of whichever the book listed first — a
	// ghost-dominated book must not crowd out the live seed.
	sort.SliceStable(out, func(i, j int) bool {
		ci, cj := out[i].Confirmed > 0, out[j].Confirmed > 0
		if ci != cj {
			return ci
		}
		return out[i].Confirmed > out[j].Confirmed
	})
	if len(out) > 12 {
		out = out[:12]
	}
	if len(out) == 0 {
		return nil, errors.New("no known peers (peerbook empty and daemon unreachable)")
	}
	return out, nil
}

// localNets enumerates this machine's interface subnets — the vantage for
// the LAN-address viability decision (once per verb run).
func localNets() []*net.IPNet {
	var out []*net.IPNet
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				out = append(out, v)
			case *net.IPAddr:
				bits := 128
				if v.IP.To4() != nil {
					bits = 32
				}
				out = append(out, &net.IPNet{IP: v.IP, Mask: net.CIDRMask(bits, bits)})
			}
		}
	}
	return out
}

// addrViable reports whether addr is worth dialing FROM THIS MACHINE:
// public (and hostname) addresses always; private/loopback/link-local
// addresses only when a local interface shares the subnet. A WAN box
// dialing another LAN's 192.168.1.x can never succeed — counting those
// dials as peer evidence filled the friend's VPS failure list with LAN
// IPs during the v0.19.10 roll (user-reported). Loopback lives on every
// machine, so the on-box heal pattern (-peers 127.0.0.1:15353#pk) stays
// viable, and hostnames (the pinned seed) pass for resolution.
func addrViable(addr string, nets []*net.IPNet) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return true // unparseable: let the dial report the real error
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true // hostname: resolvable; viability unknown until dialed
	}
	if !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() {
		return true
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// dialPlan returns the peer's addresses worth dialing from this machine,
// preferred first then viable alternates, deduplicated. Multi-homing
// keeps LAN addresses LEARNED (same-LAN peers need them, and the
// never-confirmed alt aging prunes the useless ones) — this only decides
// what we DIAL.
func dialPlan(p dht.Peer, nets []*net.IPNet) []string {
	plan := make([]string, 0, 1+len(p.Alts))
	add := func(a string) {
		if a == "" || !addrViable(a, nets) {
			return
		}
		for _, have := range plan {
			if have == a {
				return
			}
		}
		plan = append(plan, a)
	}
	add(p.Addr)
	for _, alt := range p.Alts {
		add(alt.Addr)
	}
	return plan
}

// viablePeers keeps only peers with at least one dialable address from
// this machine's vantage (counting the drops).
func viablePeers(peers []dht.Peer, nets []*net.IPNet, skipped *int) []dht.Peer {
	out := make([]dht.Peer, 0, len(peers))
	for _, p := range peers {
		if len(dialPlan(p, nets)) == 0 {
			*skipped++
			continue
		}
		out = append(out, p)
	}
	return out
}

// getViaPlan fetches one chunk trying the peer's viable addresses in
// order. Errors that are the PEER's answer — absent (never cached),
// throttled (pacing), blacklisted (refused) — return immediately: every
// address serves the same node. Only TRANSPORT failures are address-level
// and justify the next address.
func getViaPlan(ctx context.Context, sess *dht.BlobSession, p dht.Peer, plan []string, id []byte, off, length int) ([]byte, int64, error) {
	var last error
	for i, a := range plan {
		pp := p
		pp.Addr = a
		data, total, err := sess.Get(ctx, pp, id, off, length)
		if err == nil {
			return data, total, nil
		}
		switch err {
		case dht.ErrBlobAbsent, dht.ErrBlobThrottled, dht.ErrBlacklisted:
			return data, total, err // the node answered: address is done
		}
		last = err
		_ = i
	}
	return nil, 0, last
}

// filterBlacklisted drops peers carrying a live proven-violation flag in
// the local ledger (client-side containment: never fetch from a peer this
// node has cryptographically proven hostile — a wrong slice from an
// earlier run must not cost this run its retries). nil ledger ⇒ no-op.
func filterBlacklisted(node *dht.Node, peers []dht.Peer) []dht.Peer {
	out := make([]dht.Peer, 0, len(peers))
	for _, p := range peers {
		if node.PeerBlacklisted(p.ID()) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// fetchTarballFromPeers assembles the manifest's asset from peer-served
// chunks into workDir. Chunks are fetched round-robin from the peer set
// by a small worker pool; every chunk is verified against the manifest.
// Peer failures are CLASSIFIED (v0.19.8-live fix): ErrBlobThrottled means
// "wait, this seeder is alive" (blacklisting it discarded the fleet's
// only cache and broke every swarm), ErrBlobAbsent means "useless for
// this run" (blacklist), and a WRONG SLICE is hostile (blacklist). All
// failure modes requeue the chunk; bounded total retries hand over to
// the origin path when the swarm cannot finish.
func fetchTarballFromPeers(workDir string, man *blobman.Manifest, peers []dht.Peer) (string, error) {
	if len(man.Chunks) > 1<<16 {
		return "", fmt.Errorf("manifest too large")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// The transient one-shot node: every query it sends carries the §6.3
	// transient flag (v0.19.7), so this very verb stops planting the
	// ghosts that motivated the feature. The swarm's peers ride in as
	// BOOTSTRAPS — startCLINode pings each (reachability gate: with zero
	// reachable peers the swarm cannot possibly run) and the flagged
	// pings plant no ghosts on them.
	node, err := startCLINode(ctx, "", ":0", peers)
	if err != nil {
		return "", err
	}
	defer node.Close()
	session := node.BlobSession()

	id, err := hex.DecodeString(man.SHA256)
	if err != nil || len(id) != constants.SHA256Len {
		return "", fmt.Errorf("manifest digest")
	}

	outPath := filepath.Join(workDir, "release.tar.gz")
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer out.Close()
	// Pre-size the file so out-of-order chunk writes land at real offsets.
	if err := out.Truncate(man.Size); err != nil {
		return "", err
	}

	nets := localNets()
	skippedUnviable := 0
	var (
		mu          sync.Mutex
		next        int
		retries     int // total requeues (bounded: a non-converging swarm hands over to origin)
		absentCount = map[string]bool{}
		hostile     = map[string]bool{}
		// GLOBAL peer rotation with strikes (v0.19.8-live fix): the
		// first cut gave each worker its own rotation — dead peers
		// drained it, the worker EXITED, and requeued chunks stranded
		// while live seeders still existed. One shared rotation: a
		// worker only starves when every peer is genuinely out.
		live    = viablePeers(filterBlacklisted(node, peers), nets, &skippedUnviable)
		liveIdx int
		strikes = map[string]int{}
		// throttleGen graduates concurrent workers' throttle backoffs so
		// they do not all sleep the same 250 ms and re-fire in unison.
		throttleGen int
	)
	pop := func() (int, bool) {
		mu.Lock()
		defer mu.Unlock()
		if next < len(man.Chunks) {
			i := next
			next++
			return i, true
		}
		return 0, false
	}
	nextPeer := func() (dht.Peer, bool) {
		mu.Lock()
		defer mu.Unlock()
		if len(live) == 0 {
			return dht.Peer{}, false
		}
		p := live[liveIdx%len(live)]
		liveIdx++
		return p, true
	}
	// strike counts a failure against a peer; two strikes (or one
	// deliberate/hard failure) removes it from the shared rotation.
	strikeN := func(p dht.Peer, n int) {
		mu.Lock()
		defer mu.Unlock()
		strikes[p.Addr] += n
		if strikes[p.Addr] < 2 || len(live) == 0 {
			return
		}
		keep := live[:0]
		for _, q := range live {
			if q.Addr != p.Addr {
				keep = append(keep, q)
			}
		}
		live = keep
		if len(live) > 0 {
			liveIdx %= len(live)
		}
	}
	requeue := func(i int) {
		mu.Lock()
		defer mu.Unlock()
		retries++
		// A bounded number of total retries keeps a hostile/lossy swarm
		// from spinning forever; origin fallback below is the answer to
		// a swarm that cannot finish.
		if retries <= 3*len(man.Chunks) && next > i {
			next = i // rewind the cursor to retry this index
		}
	}

	// 6 workers: 6 x 48 KiB in flight keeps the client's socket buffer
	// and the path's fragment reassembly comfortably inside their
	// budgets while saturating the server-side rate limiter.
	workers := len(peers)
	if workers > 6 {
		workers = 6
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i, ok := pop()
				if !ok {
					return
				}
				p, ok2 := nextPeer()
				if !ok2 {
					// Every peer is out of the rotation (absent/hostile/
					// struck-out): the swarm cannot finish these chunks —
					// the origin path takes over.
					requeue(i)
					return
				}
				off := int64(i) * int64(man.ChunkSize)
				// Throttle pacing: a busy limiter is a PACING signal, not
				// a failure — the worker retries the SAME chunk in place
				// (graduated backoff) instead of requeueing it. The
				// requeue-retry budget exists for real failures only;
				// letting throttle cycles consume it starved whole swarms
				// while a perfectly healthy seeder sat at its 50/s limit
				// (the 54 s / absent=3 / digest-fail cascade).
				remain := man.ChunkLen(i)
				var data []byte
				attempts := 0
				for {
					data, _, err = getViaPlan(ctx, session, p, dialPlan(p, nets), id, int(off), int(remain))
					if err != dht.ErrBlobThrottled {
						break
					}
					attempts++
					if attempts > 200 { // a stuck limiter: give this worker's chunk to the pool
						break
					}
					mu.Lock()
					n := throttleGen
					throttleGen++
					mu.Unlock()
					back := 20 * time.Millisecond
					for k := 0; k < n%4 && back < 160*time.Millisecond; k++ {
						back *= 2
					}
					time.Sleep(back)
				}
				if attempts > 200 {
					requeue(i)
					continue
				}
				if err == dht.ErrBlobAbsent {
					mu.Lock()
					absentCount[p.Addr] = true
					mu.Unlock()
					strikeN(p, 2) // hard: this peer will never have this blob
					requeue(i)
					continue
				}
				if err != nil {
					// Timeout/transport: one strike (three strikes and
					// the peer leaves the rotation — a burst-induced
					// datagram drop must not evict a live seeder).
					strikeN(p, 1)
					requeue(i)
					continue
				}
				sum := sha256.Sum256(data)
				if hex.EncodeToString(sum[:]) != man.Chunks[i] {
					// A WRONG byte-slice is the hostile case: stop asking
					// this peer anything, retry the chunk elsewhere, and
					// persist the verdict — the ledger is the cross-run
					// form of this per-run hostile set.
					mu.Lock()
					hostile[p.Addr] = true
					mu.Unlock()
					node.RecordViolation(p.ID(), blacklist.ClassWrongSlice,
						fmt.Sprintf("chunk %d failed its manifest hash", i), data)
					strikeN(p, 5)
					requeue(i)
					continue
				}
				if _, err := out.WriteAt(data, off); err != nil {
					requeue(i)
					return
				}
			}
		}()
	}
	wg.Wait()

	if skippedUnviable > 0 {
		fmt.Printf("  skipped %d peer(s) whose addresses are unreachable from this machine (LAN-only seen from a WAN vantage)\n", skippedUnviable)
	}
	// Whole-file verification: the manifest's own digest over what we
	// assembled — belt and braces over the per-chunk checks, and the
	// origin SHA256SUMS check (when present) vouches a third time.
	f, err := os.Open(outPath)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err != nil {
		return "", err
	}
	if hex.EncodeToString(h.Sum(nil)) != man.SHA256 {
		mu.Lock()
		defer mu.Unlock()
		os.Remove(outPath)
		return "", fmt.Errorf("assembled tarball failed its manifest digest — absent=%d hostile=%d (of %d peers)",
			len(absentCount), len(hostile), len(peers))
	}
	return outPath, nil
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
	return upgradeDownloadCtx(context.Background(), url, dir)
}

// upgradeDownloadCtx is upgradeDownload with a caller-owned budget (the
// prefetch's deadline must be able to interrupt a slow download).
var upgradeDownloadCtx = func(ctx context.Context, url, dir string) (string, error) {
	if ctx.Err() == nil && ctx.Done() == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 15*time.Minute)
		defer cancel()
	}
	resp, err := upgradeHTTPGet(ctx, url, "")
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
		if !slices.Contains(releaseBinaries, strings.TrimSuffix(base, ".exe")) || staged[strings.TrimSuffix(base, ".exe")] != "" {
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
// tag (dev, garbage). The ordering itself is compareVersionsNumbers — one
// implementation, two entry points (string-level vs struct-level).
func compareVersions(a, b string) (int, bool) {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	if !aok || !bok {
		return 0, false
	}
	return compareVersionsNumbers(av, bv), true
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
		// No sudo equivalent: an elevated shell is the only way in.
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
	units := filterActiveUnits(listSystemdUnits("--type=service"))
	// The daemon first, the web UI last, anything else between.
	sort.SliceStable(units, func(i, j int) bool { return unitRestartRank(units[i]) < unitRestartRank(units[j]) })
	return units
}

// listFreensTimers lists the ACTIVE freens* timer units (the health check,
// a DDNS timer, …) — same active-only rule as the services.
func listFreensTimers() []string {
	return filterActiveUnits(listSystemdUnits("--type=timer"))
}

// systemdUnitRow is one listed unit and whether systemd calls it active.
type systemdUnitRow struct {
	name   string
	active bool
}

// listSystemdUnits raw-lists freens* units of one kind via list-units.
// sysOutput is the test seam; nil on any error (no systemctl, …).
func listSystemdUnits(kind string) []systemdUnitRow {
	out, err := sysOutput("systemctl", "list-units", "freens*", kind, "--no-legend", "--plain")
	if err != nil {
		return nil
	}
	var units []systemdUnitRow
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// Columns: UNIT LOAD ACTIVE SUB DESCRIPTION.
		if len(f) < 3 {
			continue
		}
		if !strings.HasSuffix(f[0], ".service") && !strings.HasSuffix(f[0], ".timer") {
			continue
		}
		units = append(units, systemdUnitRow{name: f[0], active: f[2] == "active"})
	}
	return units
}

// filterActiveUnits projects the listed units to active names only.
func filterActiveUnits(units []systemdUnitRow) []string {
	var out []string
	for _, u := range units {
		if u.active {
			out = append(out, u.name)
		}
	}
	return out
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

// waitDNSBack polls the daemon's DNS relay until it ANSWERS (any rcode) a
// query for the box's first keychain alias. Both NOERROR and NXDOMAIN
// count — the face is serving; SERVFAIL (degraded walk) and transport
// errors keep the poll running. Best-effort exactly like waitDaemonBack:
// prints and warns, never fails the upgrade.
func waitDNSBack(d time.Duration) {
	aliases := keychainAliases()
	if len(aliases) == 0 {
		return // nothing owned: nothing to prove
	}
	name := dns.Fqdn(aliases[0])
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	q.RecursionDesired = true
	payload, err := q.Pack()
	if err != nil {
		return
	}
	c := &admin.Client{Sock: home.AdminSock(), Timeout: 5 * time.Second}
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		respRaw, qerr := c.DNSQuery(ctx, payload)
		cancel()
		if qerr == nil && len(respRaw) > 0 {
			resp := new(dns.Msg)
			if uerr := resp.Unpack(respRaw); uerr == nil {
				if resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError {
					fmt.Printf("dns face answering: %s -> %s\n", aliases[0], dns.RcodeToString[resp.Rcode])
					return
				}
				// SERVFAIL etc.: the face answers but resolution is
				// degraded — keep polling until the deadline.
			}
		}
		time.Sleep(1 * time.Second)
	}
	fmt.Fprintf(os.Stderr, "%s: warning: DNS face did not settle for %s within %s — likely still converging (one more query re-checks); `freens doctor` if it persists\n",
		ProgName, aliases[0], d)
}

// waitWebUIBack polls the webui's own /healthz until it reports the freshly
// installed version. The daemon's version says nothing about the UI process
// (the footer even renders the DAEMON's stamp), so a webui left running a
// renamed-aside pre-upgrade image looks completely healthy from every
// version surface — it took a peer-table heading drawn twice to notice
// (found live 2026-09-01 on the desktop box: the UI served v0.13.1-pre
// templates through two successful upgrades). Best-effort like the daemon
// check: prints and warns, never fails the upgrade.
func waitWebUIBack(d time.Duration, want string) {
	port := "8090" // DefaultListen
	if b, err := os.ReadFile(home.ConfPath()); err == nil {
		if cfg, perr := webui.ParseConfig(string(b)); perr == nil && cfg != nil && cfg.Listen != "" {
			if _, p, err := net.SplitHostPort(cfg.Listen); err == nil && p != "" {
				port = p
			}
		}
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		// The one-port listener upgrades plaintext to https (308); the
		// §9.5 chain is self-certified, so verification is not the point
		// here — reaching the process is.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
		if err == nil {
			var body struct {
				Status  string `json:"status"`
				Version string `json:"version"`
			}
			err = json.NewDecoder(resp.Body).Decode(&body)
			resp.Body.Close()
			if err == nil && body.Version != "" {
				if want == "" || body.Version == want {
					fmt.Printf("webui back: version %s\n", body.Version)
					return
				}
				fmt.Fprintf(os.Stderr, "%s: WARNING: the webui on :%s reports version %s, want %s — it is serving PRE-UPGRADE code (stale service image). Restart the freens-web service.\n", ProgName, port, body.Version, want)
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "%s: warning: the webui on :%s did not answer /healthz within %s — check the freens-web service/unit\n", ProgName, port, d)
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

	// The tarball may ride a MIRROR ([upgrade] mirror / FREENS_UPGRADE_
	// MIRROR — github's release CDN is bandwidth-starved on some routes,
	// found live 2026-09-18: 65-75 KB/s from a HiNet box, i.e. minutes
	// per upgrade). Integrity travels the ORIGIN path: SHA256SUMS.txt is
	// fetched from github (a few hundred bytes) and the mirrored tarball
	// must reproduce its bytes or the upgrade aborts before staging.
	mirror := upgradeMirror()
	var sums map[string]string
	if mirror != "" {
		sums, err = fetchChecksums(rel)
		if err != nil {
			return err
		}
		if sums == nil {
			return fmt.Errorf("mirror %s is configured but this release carries no %s — remove the mirror or pin a v0.19.7+ release", mirror, checksumsAssetName)
		}
	}

	// CHUNKED PEER TRANSFER (v0.19.7): when the release carries a chunk
	// manifest, the tarball is pulled from fleet peers (each serving the
	// copy it downloaded) with every chunk verified against the manifest
	// BEFORE assembly. Peers are pure acceleration: any failure — no
	// responsive peers, a blacklisted bad actor, a timeout — falls back
	// to the origin/mirror path below. The trust anchor never moves: the
	// manifest comes from GITHUB ORIGIN, and origin's SHA256SUMS still
	// vouches for the assembled bytes.
	man := fetchUpgradeManifest(rel)
	tarPath := ""
	if man != nil {
		peers, perr := upgradePeerList()
		if perr == nil && len(peers) > 0 {
			t0 := time.Now()
			// FAST PATH: TCP whole-file streaming — one connection, the
			// seeder paced by kernel flow control (no rate bucket to
			// tune, no datagram ceiling). Verified chunk-by-chunk against
			// the origin manifest as bytes arrive.
			if p2p, via, ferr := fetchTarballViaTCP(work, man, peers); ferr == nil {
				tarPath = p2p
				fmt.Printf("streamed %s over TCP from %s in %s (%s/s), manifest-verified\n",
					asset.Name, via, time.Since(t0).Round(time.Millisecond),
					humanBytesPerSec(man.Size, time.Since(t0)))
			} else {
				fmt.Printf("tcp streaming unavailable after %s (%v)\n", time.Since(t0).Round(time.Millisecond), ferr)
				// FALLBACK: the UDP chunk swarm (48-60 KiB datagrams).
				t1 := time.Now()
				if p2p, ferr := fetchTarballFromPeers(work, man, peers); ferr != nil {
					fmt.Printf("peer transfer unavailable after %s (%v) — downloading from origin instead\n", time.Since(t1).Round(time.Millisecond), ferr)
				} else {
					tarPath = p2p
					fmt.Printf("assembled %s from %d peer-served, manifest-verified chunks in %s (%s/s)\n",
						asset.Name, len(man.Chunks), time.Since(t1).Round(time.Millisecond),
						humanBytesPerSec(man.Size, time.Since(t1)))
				}
			}
		}
	}
	fromOrigin := false
	if tarPath == "" {
		fromOrigin = true
		fmt.Printf("downloading %s (%s)%s ...\n", asset.Name, humanBytes(asset.Size),
			func() string {
				if mirror != "" {
					return " via mirror " + mirror
				}
				return ""
			}())
		url := mirrorAssetURL(mirror, asset.BrowserDownload)
		p, err := upgradeDownload(url, work)
		if err != nil {
			return err
		}
		tarPath = p
	}
	// Cache the tarball for the fleet (v0.19.7): every box that upgrades
	// becomes a seeder for the next one. ONLY verified bytes are cached —
	// caching an unverified origin download under the manifest's ID would
	// poison the fleet's swarm with permanently-failing chunks (found
	// live 2026-09-18). Best-effort: a cache failure never fails an
	// upgrade.
	if man != nil {
		if id, derr := hex.DecodeString(man.SHA256); derr == nil {
			if f, ferr := os.Open(tarPath); ferr == nil {
				h := sha256.New()
				_, cerr := io.Copy(h, f)
				f.Close()
				if cerr == nil && hex.EncodeToString(h.Sum(nil)) == man.SHA256 {
					if bc, bcerr := dht.NewBlobCache(filepath.Join(home.Dir(), "blobs")); bcerr == nil {
						if serr := bc.Store(id, tarPath); serr == nil {
							fmt.Println("cached release archive for peer transfer")
						}
					}
				} else {
					fmt.Println("not caching the release archive: bytes do not match the manifest (integrity)")
				}
			}
		}
	}
	if sums != nil {
		fmt.Printf("verifying %s against %s (origin) ...\n", asset.Name, checksumsAssetName)
		if err := verifyChecksum(tarPath, asset.Name, sums); err != nil {
			return err
		}
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

	// Windows: the SCM services LOCK their binary images — stop them
	// before a byte moves and start them again after. (Linux/darwin rename
	// over the running image instead, so systemd needs no dance.) The
	// webui service is stopped too: its image must not be renamed-aside
	// by the install, or the running process keeps serving the OLD
	// template set while the new exe sits unused on disk (found live
	// 2026-09-01: the v0.13.2 upgrade left freens-web serving v0.13.1-pre
	// until the next manual restart).
	winServiceWasRunning := false
	winWebWasRunning := false
	if goosWindows {
		winServiceWasRunning = winSvcRunning()
		winWebWasRunning = winSvcWebRunning()
		if (winServiceWasRunning || winWebWasRunning) && !winSvcElevated() {
			return usageErr("the freens services are running and `upgrade` needs admin rights to restart them — re-run from an elevated (Run as administrator) shell")
		}
		// v0.19: SWAP FIRST while the services keep running. installBinary
		// replaces a running image legally on Windows (rename-aside: the
		// old image's lock dies with the process), so the stop is no longer
		// the precondition for the swap — and the order means a killed verb
		// can never leave the services STOPPED. The old stop→swap→start
		// flow had a dead-DNS window between stop and start, and a verb
		// killed inside it (found live 2026-09-17: an aborted desktop
		// upgrade stopped the SCM service and died, taking the machine's
		// whole DNS down with it) had no way back but a manual start. The
		// worst case now is a completed swap with a restart still owed —
		// any restart (re-run, reboot, SCM recovery) finishes it. The
		// stop-first flow remains the fallback below for a swap that
		// refuses while running.
	}

	// Install each binary in place of the running one.
	fmt.Println("installing:")
	runInstall := func() error {
		for _, bin := range releaseBinaries {
			target := installTargetPath(bin)
			res, err := installBinary(staged[bin], target)
			if err != nil {
				return fmt.Errorf("installing %s: %w", target, err)
			}
			fmt.Printf("  %s: %s\n", target, res)
		}
		return nil
	}
	installErr := runInstall()
	if installErr != nil && goosWindows && (winServiceWasRunning || winWebWasRunning) {
		// The in-place swap refused while running (locked/permission
		// edge): fall back to the classic stop-first dance — the restore
		// semantics inside installBinary keep the old binaries in place
		// for a plain start, and the services come back right after.
		fmt.Println("in-place swap refused while running — falling back to stop-first…")
		if winServiceWasRunning {
			_ = winSvcStop()
		}
		if winWebWasRunning {
			_ = winSvcWebStop()
		}
		installErr = runInstall()
		if installErr != nil {
			if winServiceWasRunning {
				_ = winSvcStart()
			}
			if winWebWasRunning {
				_ = winSvcWebStart()
			}
			return installErr
		}
	} else if installErr != nil {
		if goosWindows && winServiceWasRunning {
			_ = winSvcStart()
		}
		if goosWindows && winWebWasRunning {
			_ = winSvcWebStart()
		}
		return installErr
	}

	// Restart the services around the new binaries.
	webWasUp := false
	if goosWindows {
		webWasUp = winWebWasRunning
		restartWindowsService(winServiceWasRunning, winWebWasRunning)
	} else {
		units := activeFreensUnits()
		if len(units) == 0 {
			fmt.Println("no active freens* systemd units found — restart the daemon yourself (systemctl restart freens.service)")
		} else {
			fmt.Printf("restarting: %s\n", strings.Join(units, ", "))
			restartFreensUnits(units)
			webWasUp = slices.Contains(units, "freens-web.service")
		}
	}

	if wasAlive {
		fmt.Println("health check:")
		waitDaemonBack(20 * time.Second)
		// The DNS-face gate (v0.16.7): the admin socket proves the process
		// is alive; it says nothing about SERVING — the post-upgrade
		// window's recurring hiccup was a daemon that looked healthy while
		// its resolver was still converging (the 2026-09-14 nanopi roll:
		// "upgrade complete" on every box while names needed another
		// query to answer). Bounded + warn-only: the daemon-side boot
		// lease warm-up makes this window short; the gate makes a long one
		// VISIBLE at upgrade time instead of in the morning logs.
		waitDNSBack(30 * time.Second)
		if webWasUp {
			// The daemon's version says nothing about the UI process:
			// a webui serving a renamed-aside old image survived two
			// "successful" upgrades (found live 2026-09-01 on the desktop
			// box — the footer version comes from the daemon, so nothing
			// surfaced it). Ask the UI itself for its stamp.
			waitWebUIBack(10*time.Second, tag)
		}
	}

	// THE FIRST MOVER BECOMES THE RELEASE'S UNIVERSAL SEEDER: this box
	// downloaded its own archive from origin (the slow path) — prefetch
	// the OTHER platforms' archives into the blob cache now (budget-
	// capped, best-effort) so boxes that could NEVER peer-download — no
	// Linux box ever cached the windows tarball; desktop and the friend's
	// VPS fell to origin every release — can swarm from the fleet.
	// Budget-capped so a slow first mover cannot hang the verb forever;
	// a partial prefetch still helps. Runs after the services are back.
	if fromOrigin && man != nil {
		fmt.Println("peer-transfer prefetch (first mover): caching the other platforms' archives for the fleet ...")
		prefetchPeerTransferAssets(rel, asset.Name, work, 3*time.Minute)
	}
	fmt.Println("upgrade complete. previous binaries kept as <binary>.freens-prev (copy back + restart to roll back).")
	return nil
}

// restartWindowsService brings the SCM services back after an upgrade (or
// reports how to roll back when one refuses to start). The webui service
// is only started when it was running before — its absence on pre-v0.13.0
// installs is normal.
func restartWindowsService(daemonWasRunning, webWasRunning bool) {
	if !daemonWasRunning {
		fmt.Println("service freens was not running — leaving it stopped (start with: net start freens)")
	} else {
		fmt.Println("starting: service freens")
		if err := winSvcStart(); err != nil {
			fmt.Fprintf(os.Stderr, "%s: warning: starting the freens service failed (%v)\n", ProgName, err)
			fmt.Fprintln(os.Stderr, "  start it manually with `net start freens`; roll back with the *.freens-prev files listed above")
		}
	}
	if webWasRunning {
		fmt.Println("starting: service freens-web")
		if err := winSvcWebStart(); err != nil {
			fmt.Fprintf(os.Stderr, "%s: warning: starting the freens-web service failed (%v)\n", ProgName, err)
			fmt.Fprintln(os.Stderr, "  start it manually with `net start freens-web`")
		}
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

	// Firewall convergence rides the same run-through-the-new-binary
	// moment (windows-only; no-op elsewhere): rules the CURRENT binary
	// needs — e.g. the v0.19.9 TCP blob channel's inbound 15353 — must
	// reach boxes that upgrade without ever re-running setup.
	if err := ensureFirewallRulesOnMigrate(); err != nil {
		exe, _ := os.Executable()
		fmt.Printf("firewall: rule ensure skipped (%v) — manual: netsh advfirewall firewall add rule \"name=freens DHT TCP\" dir=in action=allow program=\"%s\" protocol=tcp localport=15353\n", err, exe)
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

// humanBytesPerSec formats size/duration for the transfer log line.
func humanBytesPerSec(size int64, d time.Duration) string {
	if d <= 0 {
		return "?"
	}
	bps := float64(size) / d.Seconds()
	switch {
	case bps >= 1<<20:
		return fmt.Sprintf("%.1f MiB", bps/(1<<20))
	case bps >= 1<<10:
		return fmt.Sprintf("%.1f KiB", bps/(1<<10))
	default:
		return fmt.Sprintf("%.0f B", bps)
	}
}

// fetchTarballViaTCP streams the WHOLE asset over one TCP connection
// (the dht blob channel: kernel flow control paces the seeder, so there
// is no rate bucket to tune and no datagram ceiling) and verifies every
// manifest chunk as its bytes arrive. Peers are tried in order; the
// first that serves a fully-verified stream wins. A hash failure is
// hostile — that peer is skipped, not retried.
func fetchTarballViaTCP(workDir string, man *blobman.Manifest, peers []dht.Peer) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	node, err := startCLINode(ctx, "", ":0", peers)
	if err != nil {
		return "", "", err
	}
	defer node.Close()
	session := node.BlobSession()

	id, err := hex.DecodeString(man.SHA256)
	if err != nil || len(id) != constants.SHA256Len {
		return "", "", fmt.Errorf("manifest digest")
	}
	var lastErr error
	tcpNets := localNets()
peerLoop:
	for _, p := range filterBlacklisted(node, peers) {
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		// The same vantage rule as the UDP swarm: only dial addresses
		// this machine can possibly reach. A hostile verdict (proven
		// corruption) is about the NODE — every address serves it — so
		// that continue breaks out of the whole peer; transport errors
		// try the next address.
		for _, a := range dialPlan(p, tcpNets) {
			p.Addr = a
			path, via, err := tcpStreamFrom(workDir, man, node, session, p, id, &lastErr, ctx)
			if err == nil {
				return path, via, nil
			}
			if errors.Is(err, errHostilePeer) {
				continue peerLoop // proven corruption: skip the whole node
			}
			// address-level failure: try the peer's next viable address
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no candidate peers")
	}
	return "", "", lastErr
}

// prefetchPeerTransferAssets downloads every OTHER platform's release
// archive into the local blob cache (budget-capped, best-effort): the
// first origin mover pays the origin cost once and the whole fleet —
// including platforms no Linux box ever cached — swarms from it
// afterwards. Priority: windows first (its consumer always fell to
// origin), then the non-own linux arch, then darwin.
func prefetchPeerTransferAssets(rel *ghRelease, ownAsset, work string, budget time.Duration) {
	deadline := time.Now().Add(budget)
	prio := func(name string) int {
		switch {
		case strings.Contains(name, "windows"):
			return 0
		case strings.Contains(name, "linux"):
			return 1
		default:
			return 2 // darwin last: the rarest upgrader
		}
	}
	type cand struct {
		name, tarURL, manifestURL string
	}
	var cands []cand
	for i := range rel.Assets {
		name := rel.Assets[i].Name
		if !strings.HasSuffix(name, ".tar.gz") || name == ownAsset {
			continue
		}
		plat := strings.TrimSuffix(strings.TrimPrefix(name, "freens-"), ".tar.gz")
		c := cand{name: plat}
		for j := range rel.Assets {
			switch rel.Assets[j].Name {
			case "freens-manifest-" + plat + ".json":
				c.manifestURL = rel.Assets[j].BrowserDownload
			case name:
				c.tarURL = rel.Assets[j].BrowserDownload
			}
		}
		if c.tarURL != "" && c.manifestURL != "" {
			cands = append(cands, c)
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return prio(cands[i].name) < prio(cands[j].name) })
	bc, bcerr := dht.NewBlobCache(filepath.Join(home.Dir(), "blobs"))
	if bcerr != nil {
		return
	}
	for _, c := range cands {
		remain := time.Until(deadline)
		if remain <= 0 {
			return
		}
		mctx, mcancel := context.WithTimeout(context.Background(), 60*time.Second)
		resp, err := upgradeHTTPGet(mctx, c.manifestURL, "")
		mcancel()
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil {
			continue
		}
		man, err := blobman.Parse(body)
		if err != nil {
			continue
		}
		id, err := hex.DecodeString(man.SHA256)
		if err != nil || len(id) != constants.SHA256Len {
			continue
		}
		if _, _, err := bc.Open(id); err == nil {
			continue // already cached (this or an earlier run)
		}
		dl := remain
		if dl > 6*time.Minute {
			dl = 6 * time.Minute
		}
		tctx, tcancel := context.WithTimeout(context.Background(), dl)
		tarPath, err := upgradeDownloadCtx(tctx, c.tarURL, work)
		tcancel()
		if err != nil {
			continue
		}
		f, ferr := os.Open(tarPath)
		if ferr != nil {
			continue
		}
		h := sha256.New()
		_, cerr := io.Copy(h, f)
		f.Close()
		if cerr != nil || hex.EncodeToString(h.Sum(nil)) != man.SHA256 {
			os.Remove(tarPath) // integrity: never cache unverified bytes
			continue
		}
		if serr := bc.Store(id, tarPath); serr == nil {
			fmt.Printf("  prefetch %s: cached for peer transfer\n", c.name)
		}
	}
}

// errHostilePeer signals a PROVEN wrong-slice verdict: skip every address
// of this peer (they all serve the same node).
var errHostilePeer = errors.New("peer served a hostile blob slice")

// tcpStreamFrom is one fetchTarballViaTCP attempt against ONE address of
// one peer: token handshake, whole-file stream, per-chunk verification.
func tcpStreamFrom(workDir string, man *blobman.Manifest, node *dht.Node, session *dht.BlobSession, p dht.Peer, id []byte, lastErr *error, ctx context.Context) (string, string, error) {
	token, terr := session.RefreshToken(ctx, p)
	if terr != nil {
		*lastErr = terr
		return "", "", terr
	}
	t0 := time.Now()
	r, total, gerr := node.BlobTCPGet(ctx, p, token, id, 0, uint64(man.Size))
	if gerr != nil {
		*lastErr = gerr
		return "", "", gerr
	}
	outPath := filepath.Join(workDir, "release.tar.gz")
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		r.Close()
		return "", "", err
	}
	// Stream-verify: read exactly one manifest chunk at a time; every
	// piece must hash to the manifest's digest for that chunk. The final
	// piece is short. A short read (EOF early) fails the piece.
	good := true
	hostile := false
	for ci := 0; ci < len(man.Chunks) && good; ci++ {
		piece := make([]byte, man.ChunkLen(ci))
		if _, err := io.ReadFull(r, piece); err != nil {
			good = false
			*lastErr = fmt.Errorf("stream short at chunk %d: %v", ci, err)
			break
		}
		sum := sha256.Sum256(piece)
		if hex.EncodeToString(sum[:]) != man.Chunks[ci] {
			good = false
			hostile = true
			*lastErr = fmt.Errorf("chunk %d failed its manifest hash from %s", ci, p.Addr)
			break
		}
		if _, err := out.Write(piece); err != nil {
			r.Close()
			out.Close()
			return "", "", err
		}
	}
	r.Close()
	out.Close()
	if !good {
		os.Remove(outPath)
		// Only a hash MISMATCH is proven corruption (the bytes travelled
		// a verified TCP flow from that peer); a short stream is just a
		// broken peer — pacing handles brokenness, the ledger only
		// records proof. A hostile verdict is about the NODE (every
		// address serves it): skip the whole peer.
		if hostile {
			node.RecordViolation(p.ID(), blacklist.ClassWrongSlice, (*lastErr).Error(), nil)
			return "", "", errHostilePeer
		}
		return "", "", *lastErr
	}
	if total != man.Size {
		os.Remove(outPath)
		*lastErr = fmt.Errorf("blob size %d != manifest %d", total, man.Size)
		return "", "", *lastErr
	}
	fmt.Printf("  streamed %d bytes from %s in %s\n", man.Size, p.Addr, time.Since(t0).Round(time.Millisecond))
	return outPath, p.Addr, nil
}
