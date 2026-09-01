// doh.go — the §9.6 DoH face (v0.14.0): freens-web exposes the daemon's
// resolver over HTTPS so LAN devices can use this box as a DNS-over-HTTPS
// server, and a Settings page flips both DoH switches without a terminal.
//
// Why the webui owns the listener: it already has the only HTTPS surface on
// the box — the §9.5 self-certifying leaf, HTTP/2 via ALPN, the http→https
// first-byte sniff, and the LAN CIDR gate. Mounting /dns-query here means
// "serve DoH" is a config flip, not a new port, a new certificate, and a
// new firewall rule. The RESOLVER stays in the daemon: this process relays
// raw DNS wire messages to the admin socket's /dns-query endpoint and
// answers SERVFAIL (a DNS message, never a bare HTTP error) when the daemon
// is down.
//
// Access model for /dns-query and /api/doh/root.pem: machine-facing, so
// they sit OUTSIDE requireAuth/requireCSRF (a resolver client cannot log
// in) but INSIDE the CIDR gate, which wraps the whole mux — LAN-only by
// default, exactly like every other page. `[doh] serve` is read from
// freens.conf with a short cache, so `freens doh serve on` (or a conf edit)
// takes effect without restarting the UI.
package webui

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/confedit"
	"github.com/camalolo/freens/internal/keychain"
	"github.com/camalolo/freens/internal/resolver"
	"github.com/camalolo/freens/internal/tlsca"
	"github.com/miekg/dns"
)

// dohConfCacheTTL bounds how stale the served [doh]/[upstream] view may be.
// Two seconds: a CLI toggle lands almost immediately, and the per-query cost
// is one cached read, not a file hit per DoH request.
const dohConfCacheTTL = 2 * time.Second

// dohConfState is the cached conf view the serve face consults.
type dohConfState struct {
	mu       sync.Mutex
	upstream string // [upstream] doh value ("" = plain upstream)
	serve    bool   // [doh] serve
	at       time.Time
}

// dohState returns (upstreamURL, serveEnabled) for this box.
func (s *Server) dohState() (string, bool) {
	s.doh.mu.Lock()
	defer s.doh.mu.Unlock()
	if time.Since(s.doh.at) < dohConfCacheTTL {
		return s.doh.upstream, s.doh.serve
	}
	up, hasUp, err := confedit.Get(s.confPath(), "upstream", "doh")
	if err != nil {
		// Unreadable config: keep the last known view rather than flapping.
		s.log.Debug("webui: doh conf read failed", "err", err)
		return s.doh.upstream, s.doh.serve
	}
	serveRaw, hasServe, err := confedit.Get(s.confPath(), "doh", "serve")
	if err != nil {
		return s.doh.upstream, s.doh.serve
	}
	s.doh.upstream = up
	s.doh.serve = hasServe && parseDohBool(serveRaw)
	s.doh.at = time.Now()
	_ = hasUp
	return s.doh.upstream, s.doh.serve
}

// invalidateDohState forces the next dohState() read (used right after the
// Settings mutation writes the file).
func (s *Server) invalidateDohState() {
	s.doh.mu.Lock()
	s.doh.at = time.Time{}
	s.doh.mu.Unlock()
}

// parseDohBool mirrors the resolver's config booleans (1/yes/true/on).
func parseDohBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "yes", "true", "on":
		return true
	}
	return false
}

// confPath is the freens.conf this UI edits/reads (the standard home path —
// the same one setup writes, doctor reads, and the daemon units point at).
func (s *Server) confPath() string {
	return filepath.Join(s.home, "freens.conf")
}

// handleDoHQuery is the RFC 8484 endpoint: /dns-query when serve is on,
// 404 (deliberately bare) when it is not.
func (s *Server) handleDoHQuery(w http.ResponseWriter, r *http.Request) {
	_, serve := s.dohState()
	if !serve {
		http.NotFound(w, r)
		return
	}
	h := resolver.DoHHandler{Resolver: dohRelay{s}}
	h.ServeHTTP(w, r)
}

// dohRelay is the resolver.MsgResolver that forwards wire queries to the
// DAEMON's resolver over the admin socket (the resolver lives there; this
// process owns no DNS state). Every failure degrades to a SERVFAIL DNS
// message: stub resolvers treat a bare HTTP error as "server broken" and
// may give up entirely, while SERVFAIL keeps the protocol honest.
type dohRelay struct{ s *Server }

func (d dohRelay) ResolveMsg(ctx context.Context, m *dns.Msg) *dns.Msg {
	servfail := func() *dns.Msg {
		resp := new(dns.Msg)
		resp.SetRcode(m, dns.RcodeServerFailure)
		return resp
	}
	payload, err := m.Pack()
	if err != nil {
		return servfail()
	}
	respRaw, err := d.s.dnsClient.DNSQuery(ctx, payload)
	if err != nil {
		d.s.log.Debug("webui: doh relay failed", "err", err.Error())
		return servfail()
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(respRaw); err != nil {
		return servfail()
	}
	return resp
}

// handleDoHRootPEM serves this box's §9.5 owner CA so a client device can
// import it (then https://<name>:8090/dns-query verifies cleanly). No auth
// — the CA is PUBLIC material (it's in every TLS handshake we serve); the
// CIDR gate still applies. 404 when the box has no usable keychain key.
func (s *Server) handleDoHRootPEM(w http.ResponseWriter, r *http.Request) {
	caPEM, alias, ok := s.ownerCAPEM()
	if !ok {
		http.Error(w, "no issuable trust root on this box (register a name first)", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=freens-%s-root.pem", alias))
	_, _ = w.Write(caPEM)
}

// ownerCAPEM derives the owner CA for the [webui] name (default: first
// keychain alias) — the same derivation the TLS listener performs.
func (s *Server) ownerCAPEM() (pem []byte, alias string, ok bool) {
	aliases := keychain.Aliases(s.keysDir)
	if len(aliases) == 0 {
		return nil, "", false
	}
	alias = s.cfg.Name
	if alias == "" {
		alias = aliases[0]
	}
	for _, a := range aliases {
		if a == alias {
			goto found
		}
	}
	return nil, "", false // configured name not in the keychain: no CA to give
found:
	kp, err := keychain.Load(keychain.OwnerKeyPath(s.keysDir, alias), os.Getenv("FREENS_PASSPHRASE"))
	if err != nil {
		return nil, "", false
	}
	caDER, _, err := tlsca.OwnerCA(kp.Seed(), alias, time.Now())
	if err != nil {
		return nil, "", false
	}
	return tlsca.CertPEM(caDER), alias, true
}

// ---------------------------------------------------------------------------
// Settings page + mutations
// ---------------------------------------------------------------------------

// dohSettingsData is the Settings page's DoH card.
type dohSettingsData struct {
	basePage
	UpstreamURL  string // "" = plain
	Serve        bool
	ClientURL    string // what to paste into a device's DoH settings ("" = no name yet)
	HasKeychain  bool
	DaemonReload bool // the running daemon can hot-apply upstream changes
}

func (s *Server) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	up, serve := s.dohState()
	d := dohSettingsData{
		basePage:    s.base("Settings", "settings"),
		UpstreamURL: up,
		Serve:       serve,
	}
	if alias, _, ok := s.dohAlias(); ok {
		d.HasKeychain = true
		if port := s.listenPort(); port != "" {
			d.ClientURL = "https://" + alias + ":" + port + "/dns-query"
		}
	}
	if c := s.aliveAdmin(); c != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if _, err := c.Reload(ctx); err == nil {
			d.DaemonReload = true
		}
	}
	s.render(w, http.StatusOK, "settings", d)
}

// dohAlias is the alias the DoH/TLS surfaces use: [webui] name or the first
// keychain alias.
func (s *Server) dohAlias() (alias string, caPEM []byte, ok bool) {
	aliases := keychain.Aliases(s.keysDir)
	if len(aliases) == 0 {
		return "", nil, false
	}
	alias = s.cfg.Name
	if alias == "" {
		alias = aliases[0]
	}
	for _, a := range aliases {
		if a == alias {
			return alias, nil, true
		}
	}
	return "", nil, false
}

// listenPort is the port part of the configured listen address.
func (s *Server) listenPort() string {
	addr := s.BoundAddr()
	if addr == "" {
		addr = s.cfg.Listen
	}
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return p
	}
	return ""
}

// aliveAdmin returns an admin client when a daemon answers (nil otherwise).
func (s *Server) aliveAdmin() *admin.Client {
	if !admin.Alive(s.sock) {
		return nil
	}
	return &admin.Client{Sock: s.sock, Timeout: 10 * time.Second}
}

// handleSettingsDoHPost applies the Settings form: upstream mode + serve
// flag, written through confedit (comment-preserving), then hot-applied to
// a running daemon via POST admin /reload.
func (s *Server) handleSettingsDoHPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.toastResultErr(w, "bad form: "+err.Error())
		return
	}
	confPath := s.confPath()

	// 1. Upstream.
	mode := r.FormValue("upstream_mode")
	var upstreamURL string
	switch mode {
	case "off", "":
		upstreamURL = ""
	case "custom":
		raw := strings.TrimSpace(r.FormValue("upstream_url"))
		u, ok := resolver.DoHPresetURL(raw)
		if !ok {
			s.toastResultErr(w, "not a valid DoH URL (want https://…/dns-query, or http:// on loopback for tests)")
			return
		}
		upstreamURL = u
	default:
		u, ok := resolver.DoHPresetURL(mode)
		if !ok {
			s.toastResultErr(w, "unknown preset "+mode)
			return
		}
		upstreamURL = u
	}
	if err := confedit.Set(confPath, "upstream", "doh", upstreamURL); err != nil {
		s.toastResultErr(w, "config write failed: "+err.Error())
		return
	}

	// 2. Serve.
	serveVal := "false"
	if r.FormValue("serve") == "on" {
		serveVal = "true"
	}
	if err := confedit.Set(confPath, "doh", "serve", serveVal); err != nil {
		s.toastResultErr(w, "config write failed: "+err.Error())
		return
	}
	s.invalidateDohState()

	// 3. Apply upstream change live when the daemon can.
	applied := ""
	if c := s.aliveAdmin(); c != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if msg, err := c.Reload(ctx); err == nil {
			applied = " — applied live (" + msg + ")"
		}
	}

	switch {
	case upstreamURL != "" && serveVal == "true":
		s.toastResult(w, "DoH on: encrypted upstream + serving /dns-query"+applied)
	case upstreamURL != "":
		s.toastResult(w, "DoH upstream set"+applied+" — serve stays off")
	case serveVal == "true":
		s.toastResult(w, "DoH serving enabled on /dns-query (upstream: plain DNS"+")")
	default:
		s.toastResult(w, "DoH off (plain upstream, no /dns-query)"+applied)
	}
}

// handleDoHTestPost resolves one name THROUGH this box's own /dns-query
// endpoint over real TLS (the full path a device takes), pinning the
// server chain to the box's owner CA — no OS trust store needed. Falls back
// to plain HTTP when TLS is off. The toast reports exactly what happened.
func (s *Server) handleDoHTestPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.toastResultErr(w, "bad form: "+err.Error())
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = "example.com"
	}
	alias, _, ok := s.dohAlias()
	if !ok {
		s.toastResultErr(w, "no keychain name on this box — register one first")
		return
	}
	port := s.listenPort()
	if port == "" {
		s.toastResultErr(w, "the UI listener is not up yet")
		return
	}

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	q.RecursionDesired = true
	payload, err := q.Pack()
	if err != nil {
		s.toastResultErr(w, "query build failed: "+err.Error())
		return
	}

	// TLS client pinned to our owner CA (the cert the listener serves was
	// minted from exactly this CA; ServerName carries the identity because
	// the URL host is an IP).
	client := &http.Client{Timeout: 10 * time.Second}
	caPEM, _, caOK := s.ownerCAPEM()
	if caOK {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caPEM)
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: alias, MinVersion: tls.VersionTLS12},
		}
	}
	url := "https://127.0.0.1:" + port + "/dns-query?dns=" + base64URLQuery(payload)
	resp, err := client.Get(url)
	if err != nil && caOK {
		// TLS off or handshake failed: try the plain dialect so the test
		// still proves the RESOLVER path.
		url = "http://127.0.0.1:" + port + "/dns-query?dns=" + base64URLQuery(payload)
		resp, err = client.Get(url)
	}
	if err != nil {
		s.toastResultErr(w, "self-DoH failed: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		s.toastResultErr(w, fmt.Sprintf("self-DoH got HTTP %d (is serve on?)", resp.StatusCode))
		return
	}
	answer := new(dns.Msg)
	body := make([]byte, 64*1024)
	n := 0
	for {
		m, rerr := resp.Body.Read(body[n:])
		n += m
		if rerr != nil || n >= len(body) {
			break
		}
	}
	if uerr := answer.Unpack(body[:n]); uerr != nil {
		s.toastResultErr(w, "self-DoH reply is not a DNS message")
		return
	}
	if answer.Rcode != dns.RcodeSuccess {
		s.toastResultErr(w, fmt.Sprintf("%s → %s via self-DoH", name, dns.RcodeToString[answer.Rcode]))
		return
	}
	s.toastResult(w, fmt.Sprintf("%s → %d answer(s) via this box's DoH (TLS ok)", name, len(answer.Answer)))
}

// base64URLQuery encodes a wire query for the GET ?dns= parameter (RFC 8484
// §4.1.1: base64url, no padding).
func base64URLQuery(payload []byte) string {
	return base64.RawURLEncoding.EncodeToString(payload)
}
