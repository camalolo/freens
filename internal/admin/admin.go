// Package admin implements freens' local control socket: a small HTTP server
// on a unix-domain stream socket (default ~/.freens/admin.sock — see
// home.AdminSock) exposed by the RUNNING daemon, plus the matching client.
//
// Why it exists: before the admin socket, `freens-cli publish`/`resolve` had
// to spin their OWN DHT node, which meant knowing bootstrap peers (the "-peers
// needed" problem) and duplicating the daemon's keychain state. With the admin
// socket the CLI dials the daemon's already-bootstrapped, already-routing node
// in-process-over-a-socket: no -peers flags, ever again, because the daemon
// learned them (seeds at first boot, then its persisted peerbook).
//
// The server is deliberately tiny and boring: net/http over net.Listen("unix"),
// JSON bodies, errors as {"error":"..."} with 4xx/5xx. All the interesting
// semantics live in the daemon's *dht.Node; admin is a privileged remote
// control for it. The socket is created 0600 (same-owner only) and lives in
// the 0700 freens home, so no authentication layer is needed — the OS
// filesystem is the ACL (the daemon user can drive the daemon; nobody else
// can even connect).
//
// Endpoints (see handlers.go for the full contract of each):
//
//	GET  /status   daemon/node snapshot for `freens status` and tests
//	POST /publish  {envelope: b64[, claim: bool]} — §6.4 PUT via node.Publish
//	              (auto-publishes the §7.4 claim at K_claim when field 11
//	              carries one; claim:true selects PublishClaim-only mode)
//	POST /get      {key_hex} — raw §6.4 GET by storage key
//	POST /resolve  {name[, tld_id_b32]} — display name → Resolved record
//	POST /witness  {alias, tld_id_hex, claimant_hex, ts} — §7.4 steps 3-4
//	GET  /peers    routing-table contacts (CLI standalone-fallback bootstrap)
//
// When the daemon runs WITHOUT a DHT node (node == nil — a resolver-only
// process), every network endpoint answers 503 {"error":"no dht node"} while
// /status keeps working, so tooling can distinguish "no daemon" from "daemon
// without DHT".
//
// This package is pure stdlib plus internal/dht (and, in handlers only,
// internal/{claims,constants,naming,wire}); it never imports internal/home
// (the daemon decides WHERE the socket lives) and it never starts network
// listeners of its own beyond the unix socket itself.
package admin

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/camalolo/freens/internal/dht"
)

// Logger is the minimal logging surface the admin server needs. It is
// satisfied structurally by *slog.Logger (the daemon passes its logger; nil
// falls back to slog.Default()), and is an interface rather than a concrete
// *slog.Logger so tests and alternative daemons can plug in anything with the
// same shape.
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Debug(msg string, args ...any)
}

// Server is the daemon-side admin socket: an HTTP server on a unix stream
// socket wrapping the daemon's running DHT node. Construct with New, serve
// with ListenAndServe (blocking; run it on its own goroutine), stop with
// Close (idempotent — the daemon's shutdown path may call it unconditionally).
//
// All exported methods are safe for concurrent use.
type Server struct {
	node    *dht.Node
	lookup  *dht.DHTLookup
	version string
	log     Logger

	// tlsSnapshot is the OPTIONAL §9.5 trust-sync status source wired by the
	// daemon (SetTLSProvider); nil ⇒ GET /tls answers 503. Guarded by mu:
	// the daemon wires it shortly after the serve goroutine starts.
	tlsSnapshot func() any

	// mu guards the lifecycle fields below. ListenAndServe fills them once
	// under mu before serving; Close flips closed and tears down under mu.
	// Handler goroutines only ever read s.node/s.lookup/s.log/s.version,
	// which are immutable after New.
	mu      sync.Mutex
	closed  bool
	sock    string
	httpSrv *http.Server
}

// New wraps a running DHT node (and its record-lookup adapter) in an admin
// Server. node may be nil — a daemon started without a DHT node (resolver
// only): every network endpoint then returns {"error":"no dht node"} (503)
// while GET /status keeps reporting the daemon itself. lookup may be nil;
// when present it is used for local-store-first record and claim lookups
// (DHTLookup.Lookup / LookupClaim), which is both faster and offline-friendly
// compared to a bare network IterativeGet. version is an opaque daemon
// version string echoed verbatim in Status. log may be nil ⇒ slog.Default().
func New(node *dht.Node, lookup *dht.DHTLookup, version string, log Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{node: node, lookup: lookup, version: version, log: log}
}

// ListenAndServe binds the unix stream socket at sock (creating its parent
// directory 0700 if missing), unlinks a stale predecessor socket, chmods the
// fresh socket 0600, and then BLOCKS serving HTTP until Close is called
// (returning nil) or the socket fails (returning the error).
//
// Stale-socket policy: a leftover admin.sock from a crashed daemon is removed
// and rebound — but only after a dial check proves nothing is serving on it.
// A socket that ANSWERS means a live daemon already owns it (two daemons on
// one home would corrupt each other's state), so ListenAndServe refuses with
// an error rather than stealing the endpoint. A non-socket file at sock is
// likewise never deleted.
//
// ListenAndServe returns an error if called on an already-closed or
// already-serving Server; in the daemon this is a startup bug, not a runtime
// condition.
func (s *Server) ListenAndServe(sock string) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("admin: server is closed")
	}
	if s.httpSrv != nil {
		s.mu.Unlock()
		return errors.New("admin: server is already serving")
	}
	if err := unlinkStale(sock, s.log); err != nil {
		s.mu.Unlock()
		return err
	}
	// The socket lives in the freens home in production; Ensure() normally
	// made it already. MkdirAll keeps ListenAndServe self-sufficient for
	// tests and exotic socket paths.
	if dir := filepath.Dir(sock); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			s.mu.Unlock()
			return fmt.Errorf("admin: mkdir %s: %w", dir, err)
		}
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("admin: listen %s: %w", sock, err)
	}
	// net.Listen applies the process umask; re-assert 0600 so the socket is
	// always same-owner-only regardless of how the daemon was launched.
	if err := os.Chmod(sock, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(sock)
		s.mu.Unlock()
		return fmt.Errorf("admin: chmod %s: %w", sock, err)
	}
	srv := &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second, // slowloris guard; bodies are tiny
	}
	s.sock = sock
	s.httpSrv = srv
	s.mu.Unlock()

	s.log.Info("admin: control socket listening", "sock", sock)
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil // orderly Close
	}
	// Abnormal exit (socket error): do not leave a dead socket file behind
	// for the next boot's stale-check to trip over.
	s.mu.Lock()
	if s.sock == sock && !s.closed {
		_ = os.Remove(sock)
		s.sock = ""
	}
	s.mu.Unlock()
	return fmt.Errorf("admin: serve: %w", err)
}

// Close stops the admin server: the listener and any in-flight requests are
// torn down and the socket file is removed. It is IDEMPOTENT — the daemon's
// shutdown path may call it unconditionally, and a second call returns nil.
// A Close before any ListenAndServe simply marks the server closed (and makes
// a subsequent ListenAndServe fail fast).
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var errs []error
	if s.httpSrv != nil {
		if err := s.httpSrv.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.sock != "" {
		if err := os.Remove(s.sock); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
		s.sock = ""
	}
	return errors.Join(errs...)
}

// unlinkStale implements ListenAndServe's stale-socket policy (see its doc
// comment): absent ⇒ nothing to do; a live-serving socket ⇒ error (refuse to
// steal it); a dead socket file ⇒ remove it so Listen can rebind.
//
// On Windows the ModeSocket gate is skipped: Win32 has no socket file type,
// so an AF_UNIX socket does NOT Lstat as ModeSocket there — the dial below
// is the only reliable liveness check (without this, a crashed daemon's
// socket file would wedge every future start into "not a unix socket").
func unlinkStale(sock string, log Logger) error {
	fi, err := os.Lstat(sock)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("admin: stat %s: %w", sock, err)
	}
	if runtime.GOOS != "windows" && fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("admin: %s exists and is not a unix socket", sock)
	}
	if c, derr := net.DialTimeout("unix", sock, 500*time.Millisecond); derr == nil {
		_ = c.Close()
		return fmt.Errorf("admin: %s is served by a live daemon", sock)
	}
	if err := os.Remove(sock); err != nil {
		return fmt.Errorf("admin: unlink stale socket %s: %w", sock, err)
	}
	log.Info("admin: removed stale socket from a previous run", "sock", sock)
	return nil
}
