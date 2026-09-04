// pages.go — template loading and the read-only page handlers.
package webui

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/keychain"
)

//go:embed tmpl/*.tmpl
var tmplFS embed.FS

// pageTemplates is the per-page template sets. Every page file redefines
// "content", so pages CANNOT share one template set (the last definition
// would win everywhere — found the hard way). Instead each page gets a set
// cloned from the base (layout + icons + fragments) plus its own file.
// Filled once at init by mustParseTemplates.
var pageTemplates map[string]*template.Template

func init() { mustParseTemplates() }

func mustParseTemplates() {
	base := template.New("base")
	for _, frag := range []string{"tmpl/layout.tmpl", "tmpl/jobfragment.tmpl", "tmpl/networkpeers.tmpl", "tmpl/dashchecks.tmpl"} {
		if _, err := base.ParseFS(tmplFS, frag); err != nil {
			panic("webui: " + err.Error())
		}
	}
	pages := map[string]string{
		"dashboard":  "tmpl/dashboard.tmpl",
		"names":      "tmpl/names.tmpl",
		"namedetail": "tmpl/name_detail.tmpl",
		"register":   "tmpl/register.tmpl",
		"store":      "tmpl/store.tmpl",
		"lookup":     "tmpl/lookup.tmpl",
		"network":    "tmpl/network.tmpl",
		"keys":       "tmpl/keys.tmpl",
		"certs":      "tmpl/certs.tmpl",
		"settings":   "tmpl/settings.tmpl",
		"login":      "tmpl/login.tmpl",
		"bootstrap":  "tmpl/bootstrap.tmpl",
		"storeentry": "tmpl/storeentry.tmpl",
		"lookupout":  "tmpl/lookupout.tmpl",
		// networkpeers is also parsed into the base clone (inline use by
		// the network page) and registered standalone for the /api polling
		// endpoint (the peers table refreshes itself every 30s).
		"networkpeers": "tmpl/networkpeers.tmpl",
		// dashchecks: the Dashboard health card — same polling pattern
		// (every 30s), so a warm-up or failure state clears itself.
		"dashchecks": "tmpl/dashchecks.tmpl",
		// jobfragment is also parsed into the base clone (inline use by the
		// register page); registered standalone so /api/job/{id} polling can
		// execute it on its own (v0.6.1: the missing registration made the
		// live progress card 500 while the job itself ran fine).
		"jobfragment": "tmpl/jobfragment.tmpl",
	}
	pageTemplates = make(map[string]*template.Template, len(pages))
	for name, file := range pages {
		t, err := base.Clone()
		if err != nil {
			panic("webui: " + err.Error())
		}
		if _, err := t.ParseFS(tmplFS, file); err != nil {
			panic("webui: " + err.Error())
		}
		pageTemplates[name] = t
	}
}

// render executes the named page's layout with data.
func (s *Server) render(w http.ResponseWriter, status int, page string, data any) {
	t, ok := pageTemplates[page]
	if !ok {
		http.Error(w, "no such page", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		s.log.Error("webui: render", "page", page, "err", err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	// HTML is always fresh-or-nothing: a page cached by the browser across
	// an upgrade renders the OLD template set around NEW polling fragments
	// — the peers heading drew twice exactly this way (found live
	// 2026-09-01: a tab opened before the v0.13.2 template fix survived
	// sleep/wake, its 30s htmx polls kept the rows fresh, and the stale
	// static heading from the pre-fix page load sat above them looking
	// like a server bug). no-store, not no-cache: nothing about a state
	// page is worth revalidating either.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// DebugTemplates parses the full set (test hook).
func DebugTemplates() error {
	mustParseTemplates()
	return nil
}

// basePage is the common template data.
type basePage struct {
	Title   string
	Page    string
	Version string
	Host    string
	Home    string
}

func (s *Server) base(title, page string) basePage {
	h, _ := os.Hostname()
	return basePage{Title: title, Page: page, Version: s.version(), Host: h, Home: s.home}
}

func (s *Server) version() string {
	if b, err := s.d.Status(ctxBg()); err == nil && b != nil {
		return b.Version
	}
	return "?"
}

// --------------------------------------------------------------------------
// dashboard
// --------------------------------------------------------------------------

type dashName struct {
	Alias      string
	IP         string
	Healthy    bool
	Revoked    bool
	ExpiryText string
	TldIDB32   string
}

type recentJob struct {
	When  string
	Label string
	State string
}

type dashData struct {
	basePage
	DaemonUp      bool
	DaemonVersion string
	Peers         int
	PeersOK       bool
	NodeID        string
	StoreEnvs     int
	HistoryEnvs   int
	RelayMode     bool
	NetworkClaims bool
	Difficulty    int
	WitnessQuorum int
	DNSOK         bool
	ClockOK       bool
	Warming       bool
	Names         []dashName
	RecentJobs    []recentJob
	// §9.6 DoH (dash checks fragment): upstream mode + serve state.
	DoHUpstreamURL string
	DoHServe       bool
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	d := dashData{basePage: s.base("Dashboard", "dashboard"), ClockOK: true}
	if st, err := s.d.Status(r.Context()); err == nil && st != nil {
		d.DaemonUp = st.Running
		d.DaemonVersion = st.Version
		d.Peers = st.Peers
		d.PeersOK = st.Peers > 0
		d.Warming = st.Peers > 0 && st.ConfirmedPeers == 0
		d.NodeID = st.NodeID
		d.StoreEnvs = st.StoreEnvs
		d.HistoryEnvs = st.HistoryEnvs
		d.RelayMode = st.RelayMode
		d.NetworkClaims = st.NetworkClaims
	}
	if diff, err := s.d.Difficulty(r.Context()); err == nil {
		d.Difficulty = diff.Difficulty
		d.WitnessQuorum = diff.WitnessQuorum
	} else {
		d.WitnessQuorum = 5
	}
	// DNS check: resolve our first keychain alias through the daemon.
	if aliases := keychain.Aliases(s.keysDir); len(aliases) > 0 {
		if res, err := s.d.Resolve(r.Context(), aliases[0]); err == nil && res != nil {
			d.DNSOK = res.Found
		}
		for _, a := range aliases {
			n := dashName{Alias: a, TldIDB32: s.aliasTldB32(a)}
			if res, err := s.d.Resolve(r.Context(), a); err == nil && res != nil {
				if res.Revoked {
					n.Revoked = true
				} else if res.Found {
					n.Healthy = true
					n.IP = firstAdminIPText(res.RRset)
					n.ExpiryText = "live"
				}
			}
			if !n.Healthy && !n.Revoked {
				n.ExpiryText = "—"
			}
			d.Names = append(d.Names, n)
		}
	}
	d.RecentJobs = s.recentJobs()
	s.render(w, http.StatusOK, "dashboard", d)
}

// aliasTldB32 derives the keychain owner key's tld_id ("" when the key
// cannot be read — e.g. encrypted; not an error for display).
func (s *Server) aliasTldB32(alias string) string {
	kp, err := keychain.Load(keychain.OwnerKeyPath(s.keysDir, alias), "")
	if err != nil {
		return ""
	}
	tldID, err := tldIDOf(kp)
	if err != nil {
		return ""
	}
	return tldB32Display(tldID)
}

func firstAdminIPText(rrs []admin.RR) string {
	v6 := ""
	for _, rr := range rrs {
		if rr.Text == "" {
			continue
		}
		if rr.Type == rrTypeA {
			return rr.Text
		}
		if rr.Type == rrTypeAAAA && v6 == "" {
			v6 = rr.Text
		}
	}
	return v6
}

// rrTypeA/rrTypeAAAA mirror wire.RRType* without importing wire here.
const (
	rrTypeA    = 1
	rrTypeAAAA = 28
)

// --------------------------------------------------------------------------
// names + detail
// --------------------------------------------------------------------------

type nameCard struct {
	Alias      string
	TldIDB32   string
	IP         string
	Healthy    bool
	Revoked    bool
	ExpiryText string
	Encrypted  bool
}

func (s *Server) handleNames(w http.ResponseWriter, r *http.Request) {
	type page struct {
		basePage
		Names []nameCard
	}
	p := page{basePage: s.base("Names", "names")}
	for _, a := range keychain.Aliases(s.keysDir) {
		c := nameCard{Alias: a, TldIDB32: s.aliasTldB32(a), Encrypted: keychain.IsEncryptedPath(keychain.OwnerKeyPath(s.keysDir, a))}
		if res, err := s.d.Resolve(r.Context(), a); err == nil && res != nil {
			if res.Revoked {
				c.Revoked = true
				c.ExpiryText = "revoked"
			} else if res.Found {
				c.Healthy = true
				c.IP = firstAdminIPText(res.RRset)
				c.ExpiryText = "live"
			}
		}
		if c.IP == "" {
			c.IP = "—"
		}
		p.Names = append(p.Names, c)
	}
	s.render(w, http.StatusOK, "names", p)
}

type nameDetailData struct {
	basePage
	Alias      string
	TldIDB32   string
	Found      bool
	Revoked    bool
	IP         string
	Sequence   uint64
	Owner      string
	ExpiryText string
	TTLText    string
	RRs        []admin.RR
	SubNames   []string
	Encrypted  bool
}

func (s *Server) handleNameDetail(w http.ResponseWriter, r *http.Request) {
	alias := r.PathValue("alias")
	if _, err := validAlias(alias); err != nil {
		http.NotFound(w, r)
		return
	}
	d := nameDetailData{
		basePage:  s.base(alias, "names"),
		Alias:     alias,
		TldIDB32:  s.aliasTldB32(alias),
		Encrypted: keychain.IsEncryptedPath(keychain.OwnerKeyPath(s.keysDir, alias)),
		IP:        "—",
	}
	if res, err := s.d.Resolve(r.Context(), alias); err == nil && res != nil {
		if res.Revoked {
			d.Revoked = true
		} else if res.Found {
			d.Found = true
			d.Sequence = res.Sequence
			d.Owner = res.Owner
			d.RRs = res.RRset
			d.IP = firstAdminIPText(res.RRset)
			d.ExpiryText = "live"
			d.TTLText = "≤ 1 h cap"
		}
	}
	// Sub-names the store knows about under this namespace.
	d.SubNames = s.subNames(r.Context(), alias, d.TldIDB32)
	s.render(w, http.StatusOK, "namedetail", d)
}

func (s *Server) subNames(ctx context.Context, alias, tldB32 string) []string {
	st, err := s.d.Store(ctx)
	if err != nil || st == nil {
		return nil
	}
	var out []string
	for _, e := range st.Entries {
		if e.TldIDB32 == "" || tldB32 == "" || e.TldIDB32 != tldB32 {
			continue
		}
		if len(e.Labels) == 0 {
			continue
		}
		// display order: labels are stored TLD-adjacent (reversed)
		labels := append([]string(nil), e.Labels...)
		reverse(labels)
		out = append(out, strings.Join(labels, ".")+"."+alias)
	}
	sortStrings(out)
	return out
}

// --------------------------------------------------------------------------
// register page (form only; the POST is the job starter in mutations.go)
// --------------------------------------------------------------------------

type registerPageData struct {
	basePage
	DefaultIP     string
	WitnessQuorum int
	JobID         string
	// Job is the attached job's fragment view (nil when none) — what the
	// inline {{template "jobfragment"}} renders (see handleRegisterPage).
	Job jobView
}

func (s *Server) handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	d := registerPageData{basePage: s.base("Register", "register"), WitnessQuorum: 5}
	if ip, err := outboundIPv4(); err == nil {
		d.DefaultIP = ip
	}
	if diff, err := s.d.Difficulty(r.Context()); err == nil {
		d.WitnessQuorum = diff.WitnessQuorum
	}
	// An in-flight or recent job re-attaches the live progress card. The
	// inline render gets the JOB's view data — the fragment template
	// evaluates fields the page struct does not carry (the v0.6.0-era
	// page-data call 500'd every re-attach; found live 2026-09-04).
	if j := s.latestJob(); j != nil {
		d.JobID = j.ID
		d.Job = s.viewOf(j)
	}
	s.render(w, http.StatusOK, "register", d)
}

// --------------------------------------------------------------------------
// store / lookup / network / keys
// --------------------------------------------------------------------------

type storeRow struct {
	admin.StoreEntry
	DisplayName string
	ExpiryText  string
	Lapsed      bool
}

func (s *Server) handleStorePage(w http.ResponseWriter, r *http.Request) {
	type page struct {
		basePage
		Count   int
		Entries []storeRow
	}
	p := page{basePage: s.base("Store", "store")}
	if st, err := s.d.Store(r.Context()); err == nil && st != nil {
		p.Count = st.Count
		for _, e := range st.Entries {
			row := storeRow{StoreEntry: e}
			labels := append([]string(nil), e.Labels...)
			reverse(labels)
			row.DisplayName = strings.Join(labels, ".")
			switch {
			case e.Revoked:
				row.ExpiryText = "revoked"
			case e.ExpiresIn <= 0:
				row.ExpiryText = "lapsed"
				row.Lapsed = true
			default:
				row.ExpiryText = fmt.Sprintf("%dh %02dm", e.ExpiresIn/3600, (e.ExpiresIn%3600)/60)
			}
			p.Entries = append(p.Entries, row)
		}
	}
	s.render(w, http.StatusOK, "store", p)
}

func (s *Server) handleLookupPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "lookup", struct {
		basePage
	}{s.base("Lookup", "lookup")})
}

type peerRow struct {
	Addr          string
	PK            string
	Confirmed     int64
	ConfirmedText string
	ConfirmedAgo  bool
	AltAddrs      []peerAlt // the node's other known addresses (multi-homed)
	// ConfirmedAddr is the address the last direct exchange actually rode
	// ("" when never confirmed) — a "confirmed" row whose headline is an
	// ephemeral one-shot port explains itself this way (found live: a
	// friend's box only ever reached us through CLI one-shots).
	ConfirmedAddr string
}

// peerAlt is one alternate address row with its display marker. A
// never-confirmed alternate is marked only when the contact IS confirmed
// elsewhere (the asymmetry an operator needs to see — the friend's box
// whose daemon never answered while one-shot ports carried every
// confirmation); on an advertised contact every address is unconfirmed and
// the badge already says so. Confirmed alternates stay unmarked: the "at"
// line under the exchange cell names where the confirmation lives.
type peerAlt struct {
	Addr string
	Mark string
}

func (s *Server) handleNetwork(w http.ResponseWriter, r *http.Request) {
	type page struct {
		basePage
		NodeID        string
		Advertise     string
		DHTListen     string
		Difficulty    int
		RetargetBlock int
		Peers         int
		PeerRows      []peerRow
		Seeds         []string
	}
	p := page{basePage: s.base("Network", "network")}
	now := time.Now().Unix()
	if st, err := s.d.Status(r.Context()); err == nil && st != nil {
		p.NodeID = st.NodeID
		p.Advertise = st.Advertise
		p.DHTListen = st.DHTListen
	}
	if diff, err := s.d.Difficulty(r.Context()); err == nil {
		p.Difficulty = diff.Difficulty
		p.RetargetBlock = diff.RetargetBlock
	}
	if peers, err := s.d.Peers(r.Context()); err == nil {
		p.Peers, p.PeerRows = peerRows(peers, now)
	}
	p.Seeds = readSeeds(filepath.Join(s.home, "seeds.conf"))
	s.render(w, http.StatusOK, "network", p)
}

// handleNetworkPeers is the polling endpoint behind the Network page's
// peers table (htmx every-30s): just the table fragment, freshly fetched.
func (s *Server) handleNetworkPeers(w http.ResponseWriter, r *http.Request) {
	type frag struct {
		Peers    int
		PeerRows []peerRow
	}
	p := frag{}
	if peers, err := s.d.Peers(r.Context()); err == nil {
		p.Peers, p.PeerRows = peerRows(peers, time.Now().Unix())
	}
	s.fragment(w, "networkpeers", p)
}

// handleDashChecks is the polling endpoint behind the Dashboard health
// card (htmx every-30s): the checks card, freshly measured. While the
// daemon is WARMING UP (peerbook loaded, no contact confirmed yet — the
// seconds after a restart) the resolver line says so instead of showing a
// misleading ✗ (found live 2026-09-01 on the desktop box).
func (s *Server) handleDashChecks(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	d := dashData{basePage: s.base("Dashboard", "dashboard"), ClockOK: true}
	if st, err := s.d.Status(ctx); err == nil && st != nil {
		d.DaemonUp = st.Running
		d.Peers = st.Peers
		d.PeersOK = st.Peers > 0
		d.Warming = st.Peers > 0 && st.ConfirmedPeers == 0
	}
	if aliases := keychain.Aliases(s.keysDir); len(aliases) > 0 {
		if res, err := s.d.Resolve(ctx, aliases[0]); err == nil && res != nil {
			d.DNSOK = res.Found
		}
	}
	d.DoHUpstreamURL, d.DoHServe = s.dohState()
	s.fragment(w, "dashchecks", d)
}

// peerRows converts the daemon's peer list into render rows (the confirmed
// badge + "last direct exchange" text). Each row's address list is put in
// DISPLAY order by dht.DisplayAddrs: public/global first, LAN/private after,
// non-literal addresses dropped (the "<nil>:port" artifact class).
func peerRows(peers []dht.Peer, now int64) (int, []peerRow) {
	rows := make([]peerRow, 0, len(peers))
	for _, pr := range peers {
		row := peerRow{PK: fmt.Sprintf("%x", pr.PublicKey), Confirmed: pr.Confirmed}
		if pr.Confirmed > 0 && now-pr.Confirmed < 3600 {
			row.ConfirmedAgo = true
			row.ConfirmedText = fmt.Sprintf("%dm ago", (now-pr.Confirmed)/60)
		} else if pr.Confirmed > 0 {
			row.ConfirmedText = time.Unix(pr.Confirmed, 0).UTC().Format("2006-01-02 15:04")
		} else {
			row.ConfirmedText = "never"
		}
		var alts []string
		row.Addr, alts = dht.DisplayAddrs(pr.Addr, pr.Alts)
		row.AltAddrs = make([]peerAlt, 0, len(alts))
		for _, a := range alts {
			mark := ""
			if pr.Confirmed > 0 {
				confirmed := false
				for _, st := range pr.Alts {
					if st.Addr == a {
						confirmed = st.ConfirmedAt > 0
						break
					}
				}
				if !confirmed {
					mark = "never confirmed"
				}
			}
			row.AltAddrs = append(row.AltAddrs, peerAlt{Addr: a, Mark: mark})
		}
		row.ConfirmedAddr, _ = dht.ConfirmedAddr(pr)
		rows = append(rows, row)
	}
	return len(peers), rows
}

type keyRow = keychain.KeyInfo

func (s *Server) handleKeysPage(w http.ResponseWriter, r *http.Request) {
	type page struct {
		basePage
		KeysDir   string
		Inventory []keyRow
	}
	p := page{basePage: s.base("Keys", "keys"), KeysDir: s.keysDir}
	for _, k := range keychain.Inventory(s.keysDir) {
		k.ModTime = k.ModTime.Local().Truncate(time.Second)
		p.Inventory = append(p.Inventory, k)
	}
	s.render(w, http.StatusOK, "keys", p)
}

// --------------------------------------------------------------------------
// auth pages
// --------------------------------------------------------------------------

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if !s.auth.bootstrapped() {
		http.Redirect(w, r, "/bootstrap", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "login", struct {
		basePage
		Error string
	}{s.base("Sign in", "login"), r.URL.Query().Get("err")})
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ip := remoteIP(r)
	if s.auth.lockedOut(ip) {
		w.Header().Set("Location", "/login?err="+urlQuery("too many attempts — try again in a few minutes"))
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	sid, err := s.auth.checkPassword(ip, r.PostFormValue("password"))
	if err != nil {
		w.Header().Set("Location", "/login?err="+urlQuery("wrong password"))
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	setSessionCookie(w, sid)
	s.log.Info("webui: login", "remote", ip)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.dropSession(sessionFromRequest(r))
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleBootstrapPage(w http.ResponseWriter, r *http.Request) {
	if s.auth.bootstrapped() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "bootstrap", struct {
		basePage
		Error    string
		AuthPath string
	}{s.base("Welcome", "bootstrap"), r.URL.Query().Get("err"), s.auth.path})
}

func (s *Server) handleBootstrapPost(w http.ResponseWriter, r *http.Request) {
	if s.auth.bootstrapped() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	p1 := r.PostFormValue("password")
	p2 := r.PostFormValue("password2")
	if p1 != p2 {
		http.Redirect(w, r, "/bootstrap?err="+urlQuery("passwords differ"), http.StatusSeeOther)
		return
	}
	// Bootstrap is check-then-set and must be ATOMIC: two simultaneous
	// POSTs on a fresh install both passed the unlocked check above and
	// both set a password (the second silently replacing the first —
	// TOCTOU, audit F1). bootMu spans the re-check and the write, so of
	// any number of racers exactly one reaches setPassword; the losers
	// take the same /login redirect a sequential second POST would.
	// Nesting is safe in this direction only (bootMu → a.mu; see
	// authStore) — never the reverse.
	s.auth.bootMu.Lock()
	defer s.auth.bootMu.Unlock()
	if s.auth.bootstrapped() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := s.auth.setPassword(p1); err != nil {
		http.Redirect(w, r, "/bootstrap?err="+urlQuery(err.Error()), http.StatusSeeOther)
		return
	}
	sid, _ := s.auth.checkPassword(remoteIP(r), p1)
	setSessionCookie(w, sid)
	s.log.Info("webui: admin password set", "remote", remoteIP(r))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --------------------------------------------------------------------------
// small local helpers
// --------------------------------------------------------------------------

func urlQuery(s string) string { return template.URLQueryEscaper(s) }

func reverse(ss []string) {
	for i, j := 0, len(ss)-1; i < j; i, j = i+1, j-1 {
		ss[i], ss[j] = ss[j], ss[i]
	}
}

func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j] < ss[j-1]; j-- {
			ss[j], ss[j-1] = ss[j-1], ss[j]
		}
	}
}

func readSeeds(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}
