// auth.go — bootstrap, login, sessions, and the per-IP login rate limit.
//
// Lifecycle: with no hash file on disk the server is in BOOTSTRAP state —
// the first unauthenticated page any visitor gets is "set your password";
// setting it writes the bcrypt hash (0600) and logs the setter in. From
// then on every page requires a valid session. The hash file's absence is
// the ONLY bootstrap trigger; deleting it re-opens bootstrap (a deliberate
// recovery path — it requires shell access to the box, which is already
// full control).
//
// Sessions are in-memory with random 256-bit IDs in HttpOnly,
// SameSite=Lax cookies; expiry is sliding (any use extends to 24 h) and
// idle sessions are swept opportunistically. Login attempts are limited to
// 5 failures per source IP per 10 minutes (successes reset the counter).
package webui

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookie = "freens_session"
	sessionTTL    = 24 * time.Hour
	bootstrapHint = "set the admin password"
	maxLoginFails = 5
	loginWindow   = 10 * time.Minute
)

// authStore is the password hash + sessions + login rate limiting. All
// methods are safe for concurrent use.
type authStore struct {
	path string // bcrypt hash file ("" = in-memory only, tests)

	mu       sync.Mutex
	hash     []byte // nil = bootstrap state
	sessions map[string]time.Time
	fails    map[string]*failState
}

type failState struct {
	count     int
	firstAt   time.Time
	lockUntil time.Time
}

func newAuthStore(path string) *authStore {
	a := &authStore{path: path, sessions: map[string]time.Time{}, fails: map[string]*failState{}}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			a.hash = b
		}
	}
	return a
}

// bootstrapped reports whether the admin password exists.
func (a *authStore) bootstrapped() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.hash != nil
}

// setPassword installs pass as the admin password (bootstrap or change;
// change requires the caller to have already authenticated — enforced by
// the handlers, not here).
func (a *authStore) setPassword(pass string) error {
	if len(pass) < 8 {
		return errWeakPassword
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.hash = h
	a.mu.Unlock()
	if a.path != "" {
		if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
			return err
		}
		return os.WriteFile(a.path, h, 0o600)
	}
	return nil
}

// checkPassword verifies pass; on success it drops the caller's fail
// counter and returns a fresh session ID.
func (a *authStore) checkPassword(ip, pass string) (string, error) {
	a.mu.Lock()
	hash := a.hash
	a.mu.Unlock()
	if hash == nil {
		return "", errNotBootstrapped
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(pass)) != nil {
		a.recordFail(ip)
		return "", errBadLogin
	}
	a.clearFails(ip)
	return a.newSession(), nil
}

// newSession mints and registers a session ID (caller holds no lock).
func (a *authStore) newSession() string {
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		panic("webui: crypto/rand failed: " + err.Error())
	}
	sid := hex.EncodeToString(id)
	a.mu.Lock()
	a.sessions[sid] = time.Now().Add(sessionTTL)
	a.mu.Unlock()
	return sid
}

// validSession reports whether sid is a live session; a hit slides the
// expiry forward.
func (a *authStore) validSession(sid string) bool {
	if sid == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[sid]
	if !ok {
		return false
	}
	now := time.Now()
	if now.After(exp) {
		delete(a.sessions, sid)
		return false
	}
	a.sessions[sid] = now.Add(sessionTTL)
	// Opportunistic sweep (cheap: sessions are few).
	if len(a.sessions) > 64 {
		for k, e := range a.sessions {
			if now.After(e) {
				delete(a.sessions, k)
			}
		}
	}
	return true
}

// dropSession logs sid out.
func (a *authStore) dropSession(sid string) {
	a.mu.Lock()
	delete(a.sessions, sid)
	a.mu.Unlock()
}

// lockedOut reports whether ip is currently login-locked.
func (a *authStore) lockedOut(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.fails[ip]
	return f != nil && time.Now().Before(f.lockUntil)
}

// recordFail counts one failed login; the maxLoginFails-th failure inside
// loginWindow locks the IP for loginWindow.
func (a *authStore) recordFail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	f := a.fails[ip]
	if f == nil || now.Sub(f.firstAt) > loginWindow {
		f = &failState{firstAt: now}
		a.fails[ip] = f
	}
	f.count++
	if f.count >= maxLoginFails {
		f.lockUntil = now.Add(loginWindow)
	}
}

func (a *authStore) clearFails(ip string) {
	a.mu.Lock()
	delete(a.fails, ip)
	a.mu.Unlock()
}

// sessionFromRequest extracts the session cookie value.
func sessionFromRequest(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(c.Value)
}

// setSessionCookie writes the session cookie (HttpOnly, SameSite=Lax,
// path=/, 24 h).
func setSessionCookie(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

// clearSessionCookie expires the session cookie.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}
