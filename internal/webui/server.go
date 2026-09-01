// server.go — the web UI's HTTP surface: Server, routes, and the render
// helpers. Page handlers live in pages.go; mutation endpoints in
// mutations.go; the async register job in jobs.go.
package webui

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"
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

	mux *http.ServeMux

	// httpSrv is the server serve() is running (set just before Serve);
	// ready closes when it is set. Shutdown waits on it so a stop request
	// that arrives during the listen race still drains correctly.
	httpSrv *http.Server
	ready   chan struct{}

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
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
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
	page("GET /keys", s.handleKeysPage)

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
	scheme := "http"
	if cert != nil {
		ln = tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
		})
		scheme = "https"
	}
	if s.gateOpen {
		cidrs := make([]string, 0, len(s.allow))
		for _, n := range s.allow {
			cidrs = append(cidrs, n.String())
		}
		s.log.Info("webui: serving", "scheme", scheme, "addr", s.cfg.Listen, "allow", cidrs, "home", s.home)
	} else {
		s.log.Info("webui: serving", "scheme", scheme, "addr", s.cfg.Listen, "allow", "ANY (ungated)")
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.httpSrv = srv
	close(s.ready)
	return srv.Serve(ln)
}

// Shutdown stops the listener and drains open requests up to the ctx.
// Safe to call while serve is still racing through its listen setup: it
// waits for the server to be up (or the ctx to expire) first, so an SCM
// stop that lands during startup cannot leave the socket serving.
func (s *Server) Shutdown(ctx context.Context) error {
	select {
	case <-s.ready:
	case <-ctx.Done():
		return ctx.Err()
	}
	return s.httpSrv.Shutdown(ctx)
}

// cacheHeaders pins static asset caching (defined in assets.go).
