// mutations.go — the write endpoints: async register job start/status,
// set-name, renew, revoke, backup download, store entry detail, and the DNS
// probe. All run behind auth+CSRF (wired in routes).
package webui

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

// handleRegisterStart launches the async register job (see jobs.go) and
// redirects htmx to poll it.
func (s *Server) handleRegisterStart(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	in := RegisterInput{
		Alias:      strings.ToLower(strings.TrimSpace(r.PostFormValue("alias"))),
		IP:         strings.TrimSpace(r.PostFormValue("ip")),
		Passphrase: r.PostFormValue("passphrase"),
		NoRecovery: r.PostFormValue("recovery") != "on",
	}
	ttl, _ := time.ParseDuration(r.PostFormValue("ttl") + "s")
	if n, err := fmt.Sscanf(r.PostFormValue("ttl"), "%d", new(int)); err == nil && n == 1 {
		var secs uint64
		fmt.Sscanf(r.PostFormValue("ttl"), "%d", &secs)
		in.TTL = secs
	}
	_ = ttl
	job := s.startJob("register "+in.Alias, func(ctx context.Context, progress func(string)) (any, error) {
		return s.ops().Register(ctx, in, progress)
	})
	w.Header().Set("HX-Redirect", "/register?job="+job)
	w.WriteHeader(http.StatusOK)
}

// handleJobStatus renders the live job fragment (polled by the register
// page every 600 ms until done).
func (s *Server) handleJobStatus(w http.ResponseWriter, r *http.Request) {
	j := s.job(r.PathValue("id"))
	if j == nil {
		http.Error(w, "no such job", http.StatusNotFound)
		return
	}
	d := struct {
		JobID     string
		JobLabel  string
		JobPct    int
		JobDone   bool
		JobError  string
		JobResult *RegisterResult
		JobSteps  []jobStepView
	}{}
	_ = d
	s.renderJobFragment(w, j)
}

// handleSetName is `freens name` — apex or sub-name publish.
func (s *Server) handleSetName(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	target := strings.TrimSpace(r.PostFormValue("target"))
	if target == "" {
		target = strings.TrimSpace(r.PostFormValue("name")) // hidden alias fallback
	}
	seq, err := s.ops().SetName(r.Context(), target,
		strings.TrimSpace(r.PostFormValue("ip")),
		parseUintOr(r.PostFormValue("ttl"), 300),
		r.PostFormValue("passphrase"))
	if err != nil {
		s.mutationResult(w, err)
		return
	}
	s.toastResult(w, fmt.Sprintf("published %s (sequence %d) — live", target, seq))
}

// handleRenew is `freens renew` for one name.
func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	force := r.PostFormValue("force") == "on" || r.PostFormValue("force") == "true"
	seq, err := s.ops().Renew(r.Context(), name, r.PostFormValue("passphrase"), force)
	if err != nil {
		s.mutationResult(w, err)
		return
	}
	s.toastResult(w, fmt.Sprintf("renewed %s (sequence %d, +24 h)", name, seq))
}

// handleRevoke is `freens revoke` with the typed-confirmation guard.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	confirm := strings.TrimSpace(r.PostFormValue("confirm"))
	if confirm != name {
		s.toastResultErr(w, "typed confirmation did not match — nothing was revoked")
		return
	}
	seq, err := s.ops().Revoke(r.Context(), name, r.PostFormValue("passphrase"))
	if err != nil {
		s.mutationResult(w, err)
		return
	}
	s.toastResult(w, fmt.Sprintf("revoked %s (tombstone sequence %d) — stops resolving within the TTL", name, seq))
}

// handleBackup streams the keychain tar.gz (freens backup's bundle).
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=freens-backup-%s.tar.gz", time.Now().Format("20060102-150405")))
	if _, err := buildBackup(w, s.keysDir); err != nil {
		// headers already sent; nothing else to do but log
		s.log.Error("webui: backup", "err", err)
	}
}

// handleStoreEntry renders one store row's detail fragment.
func (s *Server) handleStoreEntry(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	st, err := s.d.Store(r.Context())
	if err != nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	for _, e := range st.Entries {
		if !strings.EqualFold(e.Key, key) {
			continue
		}
		s.fragment(w, "storeentry", e)
		return
	}
	http.Error(w, "no such key", http.StatusNotFound)
}

// handleDNSProbe resolves a name through the daemon and renders the
// verdict (freens vs upstream, rcode, records).
func (s *Server) handleDNSProbe(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		s.fragment(w, "lookupempty", nil)
		return
	}
	type row struct {
		Name    string
		Found   bool
		Revoked bool
		Source  string
		RRs     []string
		Error   string
	}
	out := row{Name: name}
	if _, err := validAliasOrDNSName(name); err != nil {
		out.Error = "invalid name"
		s.fragment(w, "lookupout", out)
		return
	}
	res, err := s.d.Resolve(r.Context(), name)
	switch {
	case err != nil:
		out.Error = "daemon error: " + err.Error()
	case res == nil:
		out.Error = "no answer"
	case res.Revoked:
		out.Revoked = true
		out.Source = "freens"
	case res.Found:
		out.Found = true
		out.Source = "freens"
	default:
		out.Source = "not found (freens + upstream)"
	}
	if res != nil {
		for _, rr := range res.RRset {
			out.RRs = append(out.RRs, fmt.Sprintf("%s %s ttl=%d", rrTypeName(rr.Type), rr.Text, rr.TTL))
		}
	}
	s.fragment(w, "lookupout", out)
}

// mutationResult maps op errors to the right UX: encrypted-key errors ask
// for a passphrase, user errors toast, anything else toasts generically.
func (s *Server) mutationResult(w http.ResponseWriter, err error) {
	var ek errEncryptedKey
	switch {
	case errors.As(err, &ek):
		s.toastResultErr(w, "that owner key is passphrase-encrypted — fill the passphrase field and retry")
	case err != nil:
		s.toastResultErr(w, err.Error())
	}
}

// toastResult emits the X-Toast header app.js turns into a toast.
func (s *Server) toastResult(w http.ResponseWriter, msg string) {
	w.Header().Set("X-Toast", template.URLQueryEscaper(msg))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) toastResultErr(w http.ResponseWriter, msg string) {
	w.Header().Set("X-Toast-Kind", "error")
	s.toastResult(w, msg)
}

func parseUintOr(v string, def uint64) uint64 {
	var n uint64
	if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &n); err != nil || n == 0 {
		return def
	}
	return n
}

func rrTypeName(t uint64) string {
	switch t {
	case rrTypeA:
		return "A"
	case rrTypeAAAA:
		return "AAAA"
	case 16:
		return "TXT"
	case 5:
		return "CNAME"
	case 2:
		return "NS"
	case 15:
		return "MX"
	case 33:
		return "SRV"
	}
	return fmt.Sprintf("TYPE%d", t)
}
