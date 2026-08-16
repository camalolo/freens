// server.go — the web UI's HTTP surface: Server, routes, and the render
// helpers. Page handlers live in pages.go; mutation endpoints in
// mutations.go; the async register job in jobs.go.
package webui

import (
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

	// Auth pages.
	s.mux.HandleFunc("GET /login", s.page(s.handleLoginPage))
	s.mux.HandleFunc("POST /login", s.handleLoginPost)
	s.mux.HandleFunc("GET /logout", s.handleLogout)
	s.mux.HandleFunc("GET /bootstrap", s.page(s.handleBootstrapPage))
	s.mux.HandleFunc("POST /bootstrap", s.handleBootstrapPost)

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
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	if s.gateOpen {
		cidrs := make([]string, 0, len(s.allow))
		for _, n := range s.allow {
			cidrs = append(cidrs, n.String())
		}
		s.log.Info("webui: serving", "addr", s.cfg.Listen, "allow", cidrs, "home", s.home)
	} else {
		s.log.Info("webui: serving", "addr", s.cfg.Listen, "allow", "ANY (ungated)")
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.Serve(ln)
}

// cacheHeaders pins static asset caching (defined in assets.go).
