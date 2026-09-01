// server.go — the web UI's HTTP surface: Server, routes, and the render
// helpers. Page handlers live in pages.go; mutation endpoints in
// mutations.go; the async register job in jobs.go.
package webui

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/camalolo/freens/internal/certmgr"
)

// Server is the freens-web server.
type Server struct {
	cfg     *Config
	home    string
	keysDir string
	sock    string // daemon admin socket
	d       Daemon
	log     *slog.Logger

	gateOpen bool
	allow    []*net.IPNet
	auth     *authStore

	// nginx is the certmgr toolchain the Certificates page deploys with
	// (nil = discover lazily; tests substitute a fixture tree).
	nginx *certmgr.NginxEnv

	mux *http.ServeMux

	// httpSrv is the server serve() is running (set just before Serve);
	// ready closes when it is set. Shutdown waits on it so a stop request
	// that arrives during the listen race still drains correctly. The
	// https variant also owns the plaintext redirect server and the master
	// listener, plus the one-shot listeners its dispatch hands out.
	httpSrv      *http.Server
	httpSrvPlain *http.Server
	masterLn     net.Listener
	boundAddr    string
	ready        chan struct{}
	shutMu       sync.Mutex
	shuttingDown bool
	oneshots     map[*oneShotListener]struct{}

	// jobs: at most a handful; keyed by id. The register job is the only
	// long-running one (PoW + witnesses can take ~1 min).
	jobsMu sync.Mutex
	jobs   map[string]*job
	jobSeq int
}

// New builds a Server from a resolved Config. sockPath is the daemon's
// admin socket. Call ListenAndServe to run.
func New(cfg *Config, sockPath string, log *slog.Logger) (*Server, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.Listen == "" {
		cfg.Listen = DefaultListen
	}
	if log == nil {
		log = slog.Default()
	}
	allow, gated, err := ParseAllow(cfg.Allow)
	if err != nil {
		return nil, err
	}
	if !gated {
		log.Warn("webui: [webui] allow = any — the UI is reachable from EVERY address this machine has (including any public/WAN side). This is only safe on an isolated, trusted network.")
	}
	home := homeDir(cfg.HomeDir)
	authPath := cfg.AuthPath
	if authPath == "" {
		authPath = filepath.Join(home, "webui", "auth")
	}
	s := &Server{
		cfg:      cfg,
		home:     home,
		keysDir:  filepath.Join(home, "keys"),
		sock:     sockPath,
		d:        NewDaemonClient(sockPath),
		log:      log,
		gateOpen: gated,
		allow:    allow,
		auth:     newAuthStore(authPath),
		jobs:     map[string]*job{},
		ready:    make(chan struct{}),
		oneshots: map[*oneShotListener]struct{}{},
	}
	if gated && len(allow) == 0 {
		return nil, errNoAllowlist
	}
	s.routes()
	if !s.auth.bootstrapped() {
		log.Info("webui: no admin password set — the first visit will ask for one",
			"addr", cfg.Listen)
	}
	return s, nil
}

var errNoAllowlist = &staticError{"webui: empty allowlist"}

type staticError struct{ msg string }

func (e *staticError) Error() string { return e.msg }

// routes builds the full mux (method patterns give 405/404 for free).
func (s *Server) routes() {
	s.mux = http.NewServeMux()

	// Static + health: no auth (login page needs CSS; health is for probes).
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", staticHandler()))
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "{\"status\":\"ok\",\"version\":%q}\n", s.cfg.SelfVersion)
	})
	s.mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no icon", http.StatusNoContent)
	})

	// Auth pages: the auth flow itself — NOT behind requireAuth (wrapping
	// /login in the session check made an unauthenticated GET /login
	// redirect to itself: the original "too many redirects" bug, found live
	// minutes after deployment). The handlers guard their own states
	// (/login → /bootstrap when no password exists; /bootstrap → /login
	// when one does); the CIDR gate still applies (it wraps the whole mux).
	authPage := func(pattern string, h http.HandlerFunc) {
		s.mux.Handle(pattern, s.logRequests(http.HandlerFunc(h)))
	}
	authPage("GET /login", s.handleLoginPage)
	s.mux.Handle("POST /login", s.logRequests(http.HandlerFunc(s.handleLoginPost)))
	s.mux.Handle("GET /logout", s.logRequests(http.HandlerFunc(s.handleLogout)))
	authPage("GET /bootstrap", s.handleBootstrapPage)
	s.mux.Handle("POST /bootstrap", s.logRequests(http.HandlerFunc(s.handleBootstrapPost)))

	// Pages (auth + gate).
	page := func(pattern string, h http.HandlerFunc) {
		s.mux.HandleFunc(pattern, s.page(h))
	}
	page("GET /", s.handleDashboard)
	page("GET /names", s.handleNames)
	page("GET /names/{alias}", s.handleNameDetail)
	page("GET /register", s.handleRegisterPage)
	page("GET /store", s.handleStorePage)
	page("GET /lookup", s.handleLookupPage)
	page("GET /network", s.handleNetwork)
	page("GET /api/network/peers", s.handleNetworkPeers)
	page("GET /api/dash/checks", s.handleDashChecks)
	page("GET /keys", s.handleKeysPage)
	page("GET /certs", s.handleCertsPage)

	// Mutations (auth + gate + CSRF header).
	mut := func(pattern string, h http.HandlerFunc) {
		s.mux.HandleFunc(pattern, s.mutation(h))
	}
	mut("POST /api/register", s.handleRegisterStart)
	mut("GET /api/job/{id}", s.handleJobStatus)
	mut("POST /api/name", s.handleSetName)
	mut("POST /api/renew", s.handleRenew)
	mut("POST /api/revoke", s.handleRevoke)
	mut("GET /api/backup", s.handleBackup)
	mut("GET /api/store/{key}", s.handleStoreEntry)
	mut("GET /api/dns", s.handleDNSProbe)
	mut("POST /api/cert/issue", s.handleCertIssue)
	mut("POST /api/cert/renew", s.handleCertRenew)
	mut("POST /api/cert/nginx", s.handleCertNginxInstall)
	mut("POST /api/cert/nginx/reload", s.handleCertNginxReload)
}

// page wraps a handler with gate + logging + auth.
func (s *Server) page(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logRequests(s.requireAuth(http.HandlerFunc(h))).ServeHTTP(w, r)
	}
}

// mutation wraps with gate + logging + auth + the CSRF header check.
func (s *Server) mutation(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logRequests(s.requireAuth(requireCSRF(http.HandlerFunc(h)))).ServeHTTP(w, r)
	}
}

// Handler returns the fully-wrapped root handler (gate outermost).
func (s *Server) Handler() http.Handler {
	return s.gate(s.mux)
}

// ListenAndServe binds cfg.Listen and serves until the process exits. The
// gate's allowlist is logged at startup so the operator sees exactly who
// can reach the UI.
func (s *Server) ListenAndServe() error {
	return s.serve(nil)
}

// ListenAndServeTLS is ListenAndServe over TLS with the given leaf
// certificate (§9.5: https://<name>:8090 by default). cert nil = plain HTTP.
func (s *Server) ListenAndServeTLS(cert *tls.Certificate) error {
	return s.serve(cert)
}

func (s *Server) serve(cert *tls.Certificate) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}

	// No issuable leaf: plain HTTP exactly as before (there is no https to
	// upgrade to — the redirect below needs a certificate to exist).
	if cert == nil {
		srv := &http.Server{
			Handler:           s.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
		}
		s.httpSrv = srv
		s.boundAddr = ln.Addr().String()
		close(s.ready)
		scheme := "http"
		if s.gateOpen {
			cidrs := make([]string, 0, len(s.allow))
			for _, n := range s.allow {
				cidrs = append(cidrs, n.String())
			}
			s.log.Info("webui: serving", "scheme", scheme, "addr", s.cfg.Listen, "allow", cidrs, "home", s.home)
		} else {
			s.log.Info("webui: serving", "scheme", scheme, "addr", s.cfg.Listen, "allow", "ANY (ungated)")
		}
		return srv.Serve(ln)
	}

	// TLS-capable install: ONE port speaks both dialects. Each connection
	// is sniffed on its first byte — 0x16 is a TLS ClientHello, everything
	// else is a plaintext HTTP request — so http:// gets a 308 upgrade
	// (plus HSTS) instead of a connection reset, and https:// is served
	// normally. Same pattern as Caddy's auto-HTTPS.
	tlsSrv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	plainSrv := &http.Server{
		Handler:           http.HandlerFunc(s.redirectToTLS),
		ReadHeaderTimeout: 10 * time.Second,
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}
	s.httpSrv, s.httpSrvPlain, s.masterLn = tlsSrv, plainSrv, ln
	s.boundAddr = ln.Addr().String()
	if s.gateOpen {
		cidrs := make([]string, 0, len(s.allow))
		for _, n := range s.allow {
			cidrs = append(cidrs, n.String())
		}
		s.log.Info("webui: serving", "scheme", "https (http redirects)", "addr", s.cfg.Listen, "allow", cidrs, "home", s.home)
	} else {
		s.log.Info("webui: serving", "scheme", "https (http redirects)", "addr", s.cfg.Listen, "allow", "ANY (ungated)")
	}
	close(s.ready)

	for {
		c, err := ln.Accept()
		if err != nil {
			if s.isShuttingDown() {
				return nil
			}
			return err
		}
		go s.routeConn(tlsSrv, plainSrv, tlsConf, c)
	}
}

// isShuttingDown reports whether Shutdown has closed the master listener.
func (s *Server) isShuttingDown() bool {
	s.shutMu.Lock()
	defer s.shutMu.Unlock()
	return s.shuttingDown
}

// redirectToTLS answers plaintext HTTP with a 308 to the same URL over
// https (the Host header the visitor typed is preserved), with HSTS set
// so the browser upgrades itself from then on. The response closes the
// connection — a redirect has nothing to keep alive.
func (s *Server) redirectToTLS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	w.Header().Set("Connection", "close")
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusPermanentRedirect)
}

// routeConn sniffs one accepted connection and hands it to the right
// server through a one-shot listener (each http.Server keeps its normal
// Serve machinery; the per-conn goroutine dies with the connection).
func (s *Server) routeConn(tlsSrv, plainSrv *http.Server, tlsConf *tls.Config, c net.Conn) {
	first := make([]byte, 1)
	c.SetReadDeadline(time.Now().Add(5 * time.Second)) // sniff bound: no slow-loris on Accept
	_, err := io.ReadFull(c, first)
	c.SetReadDeadline(time.Time{}) // back to unlimited for the real request
	if err != nil {
		c.Close()
		return
	}
	l := &oneShotListener{conn: &replayConn{Conn: c, first: first[0], prefix: true}, quit: make(chan struct{})}
	s.shutMu.Lock()
	s.oneshots[l] = struct{}{}
	shutting := s.shuttingDown
	s.shutMu.Unlock()
	if shutting {
		l.Close()
		c.Close()
		return
	}
	if first[0] == 0x16 {
		tlsSrv.Serve(tls.NewListener(l, tlsConf))
		return
	}
	plainSrv.Serve(l)
}

// replayConn replays the sniffed first byte before the real stream (the
// TLS handshake and the HTTP request both need it).
type replayConn struct {
	net.Conn
	first  byte
	prefix bool
	readMu sync.Mutex
}

func (c *replayConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.prefix {
		c.prefix = false
		p[0] = c.first
		return 1, nil
	}
	return c.Conn.Read(p)
}

// oneShotListener yields exactly one connection to an http.Server, then
// parks until Close (server Shutdown) so no Serve goroutine leaks.
type oneShotListener struct {
	conn  net.Conn
	quit  chan struct{}
	mu    sync.Mutex
	given bool
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.given {
		l.given = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.quit
	return nil, errors.New("webui: one-shot listener closed")
}

func (l *oneShotListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.quit:
	default:
		close(l.quit)
	}
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return &net.TCPAddr{} }

// Shutdown stops the listener(s) and drains open requests up to the ctx.
// Safe to call while serve is still racing through its listen setup: it
// waits for the server to be up (or the ctx to expire) first, so an SCM
// stop that lands during startup cannot leave the socket serving.
func (s *Server) Shutdown(ctx context.Context) error {
	select {
	case <-s.ready:
	case <-ctx.Done():
		return ctx.Err()
	}
	s.shutMu.Lock()
	if s.shuttingDown {
		s.shutMu.Unlock()
		return nil
	}
	s.shuttingDown = true
	ones := s.oneshots
	s.oneshots = map[*oneShotListener]struct{}{}
	s.shutMu.Unlock()
	for l := range ones {
		l.Close() // unblocks the parked Serve goroutines
	}
	if s.masterLn != nil {
		_ = s.masterLn.Close() // unblocks the accept loop
	}
	errs := []error{}
	if s.httpSrv != nil {
		errs = append(errs, s.httpSrv.Shutdown(ctx))
	}
	if s.httpSrvPlain != nil {
		errs = append(errs, s.httpSrvPlain.Shutdown(ctx))
	}
	return errors.Join(errs...)
}

// BoundAddr reports the address serve actually bound ("127.0.0.1:0"
// resolves here); empty until ready. Tests and tools use it instead of
// guessing the configured port.
func (s *Server) BoundAddr() string {
	select {
	case <-s.ready:
		return s.boundAddr
	default:
		return ""
	}
}

// cacheHeaders pins static asset caching (defined in assets.go).
