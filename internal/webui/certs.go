// certs.go — the Certificates page and its mutations: the web UI face of
// internal/certmgr. Issue/renew §9.5 leaves for any owned name, and wire
// existing nginx server blocks to them (backup → edit → nginx -t →
// reload), the same safety order the CLI verb runs. All local operations:
// the keychain is read directly (the UI's trust model, see config.go), no
// daemon round-trip.
package webui

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/certmgr"
	"github.com/camalolo/freens/internal/keychain"
)

// nginxEnv is the indirection tests swap for a fixture tree. The lazy init
// is once-guarded: the cert handlers run on concurrent goroutines and an
// unsynchronized nil check is a data race (found in the 2026-09-04 audit).
func (s *Server) nginxEnv() *certmgr.NginxEnv {
	s.nginxOnce.Do(func() {
		if s.nginx == nil {
			s.nginx = &certmgr.NginxEnv{}
		}
	})
	return s.nginx
}

// mapCertErr translates certmgr's keychain sentinels into the UI's
// passphrase-aware errors (everything else toasts as-is — the certmgr
// error strings are written operator-facing).
func mapCertErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, keychain.ErrNeedsPassphrase):
		return errEncryptedKey{}
	case errors.Is(err, keychain.ErrWrongPassphrase):
		return userErr("wrong passphrase for the owner key")
	default:
		return err
	}
}

// ---------------------------------------------------------------------------
// page
// ---------------------------------------------------------------------------

type certRow struct {
	Name        string
	Alias       string
	Tracked     bool
	CertPath    string
	NotAfter    string // "in 6d" / "expired 2d ago"
	NotAfterAbs string // absolute ("2026-09-08 10:01 UTC")
	Due         bool
	InNginx     bool
	Encrypted   bool
}

type nginxRow struct {
	File        string
	ServerNames string
	CloneSource string // first server_name — the clone-vhost form's handle
	Managed     bool   // a freens-<name> clone file (our own output)
	SSL         bool
	CertPath    string
	FreensName  string // a known name matching one of the server_names ("" = none)
	Block       int    // index into the scan (the install form's block handle)
}

type certsPageData struct {
	basePage
	Rows       []certRow
	NginxOK    bool
	NginxConf  string
	NginxRows  []nginxRow
	NginxError string
}

func (s *Server) handleCertsPage(w http.ResponseWriter, r *http.Request) {
	d := certsPageData{basePage: s.base("Certificates", "certs")}

	// Every name this machine could certify: keychain apexes plus the
	// sub-names the daemon's store knows under them.
	type nameEntry struct{ name, alias string }
	var names []nameEntry
	aliases := keychain.Aliases(s.keysDir)
	for _, a := range aliases {
		names = append(names, nameEntry{a, a})
		b32 := s.aliasTldB32(a)
		for _, sub := range s.subNames(r.Context(), a, b32) {
			names = append(names, nameEntry{sub, a})
		}
	}
	known := map[string]bool{}
	for _, ne := range names {
		known[ne.name] = true
	}

	now := time.Now()
	for _, ne := range names {
		row := certRow{Name: ne.name, Alias: ne.alias,
			Encrypted: keychain.IsEncryptedPath(keychain.OwnerKeyPath(s.keysDir, ne.alias))}
		if st, err := certmgr.LoadState(s.home, ne.name); err == nil {
			row.Tracked = true
			row.CertPath = st.CertPath
			row.InNginx = len(st.NginxFiles) > 0
			row.Due = certmgr.IsDue(st, now)
			na := time.Unix(st.NotAfter, 0)
			row.NotAfterAbs = na.UTC().Format("2006-01-02 15:04 UTC")
			left := time.Until(na)
			switch {
			case left < 0:
				row.NotAfter = "expired " + left.Round(24*time.Hour).Abs().String() + " ago"
			case row.Due:
				row.NotAfter = "in " + left.Round(time.Hour).String()
			default:
				row.NotAfter = "in " + left.Round(24*time.Hour).String()
			}
		}
		d.Rows = append(d.Rows, row)
	}

	// nginx half: presence and server blocks. A missing nginx is a normal
	// state (most boxes only run the daemon), rendered as quiet copy.
	env := s.nginxEnv()
	if err := env.Locate(); err != nil {
		d.NginxError = err.Error()
	} else if blocks, serr := env.Scan(); serr != nil {
		d.NginxError = "nginx config unreadable: " + serr.Error()
	} else {
		d.NginxOK = true
		d.NginxConf = env.ConfPath
		for i, b := range blocks {
			nr := nginxRow{
				File:        b.File,
				ServerNames: strings.Join(b.ServerNames, ", "),
				SSL:         b.ListensSSL,
				Block:       i,
			}
			nr.Managed = strings.HasPrefix(filepath.Base(b.File), "freens-")
			if len(b.ServerNames) > 0 {
				nr.CloneSource = b.ServerNames[0]
			}
			if len(b.CertPaths) > 0 {
				nr.CertPath = b.CertPaths[0]
			}
			for _, sn := range b.ServerNames {
				if known[sn] {
					nr.FreensName = sn
					break
				}
			}
			d.NginxRows = append(d.NginxRows, nr)
		}
	}
	s.render(w, http.StatusOK, "certs", d)
}

// ---------------------------------------------------------------------------
// mutations
// ---------------------------------------------------------------------------

// handleCertIssue is `freens cert <name>` (+ tracking).
func (s *Server) handleCertIssue(w http.ResponseWriter, r *http.Request) {
	name, pass, ok := s.certForm(w, r)
	if !ok {
		return
	}
	if _, err := validAliasOrDNSName(name); err != nil {
		s.toastResultErr(w, "invalid name")
		return
	}
	var iss *certmgr.Issued
	err := mapCertErr(func() error {
		var e error
		_, iss, e = certmgr.TrackIssue(s.home, s.keysDir, name, "", pass, "", time.Now())
		return e
	}())
	if err != nil {
		s.mutationResult(w, err)
		return
	}
	s.toastResult(w, fmt.Sprintf("issued %s — valid until %s, tracked for renewal",
		iss.Name, iss.NotAfter.UTC().Format("2006-01-02 15:04 UTC")))
}

// handleCertRenew renews one tracked name, or every due one with name="*"
// (the daily timer's exact job, one click).
func (s *Server) handleCertRenew(w http.ResponseWriter, r *http.Request) {
	name, pass, ok := s.certForm(w, r)
	if !ok {
		return
	}
	force := r.PostFormValue("force") == "on" || r.PostFormValue("force") == "true"
	if name == "*" {
		renewed, err := certmgr.RenewDue(s.home, s.keysDir, pass,
			certmgr.RenewOpts{Force: force}, time.Now())
		if err != nil {
			s.toastResultErr(w, truncateToast(mapCertErr(err).Error()))
			return
		}
		if len(renewed) == 0 {
			s.toastResult(w, "nothing to renew — every tracked certificate is fresh")
			return
		}
		s.toastResult(w, fmt.Sprintf("renewed %d certificate(s): %s",
			len(renewed), strings.Join(certNames(renewed), ", ")))
		return
	}
	if _, err := validAliasOrDNSName(name); err != nil {
		s.toastResultErr(w, "invalid name")
		return
	}
	var renewed *certmgr.Renewal
	err := mapCertErr(func() error {
		var e error
		renewed, e = certmgr.RenewOne(s.home, s.keysDir, name, pass,
			certmgr.RenewOpts{Force: force}, time.Now())
		return e
	}())
	switch {
	case errors.Is(err, certmgr.ErrNotDue):
		s.toastResult(w, name+" is still fresh — tick force to renew anyway")
		return
	case err != nil:
		s.mutationResult(w, err)
		return
	}
	s.toastResult(w, fmt.Sprintf("renewed %s — valid until %s",
		name, time.Unix(renewed.NotAfter, 0).UTC().Format("2006-01-02 15:04 UTC")))
}

// handleCertNginxInstall is `freens cert nginx <name>`: the matched server
// block starts serving the name's certificate — or, with clone_source set,
// a NEW vhost cloned from the given server_name is created for it (the
// "site already exists with its own valid certificate" case: the source is
// never modified).
func (s *Server) handleCertNginxInstall(w http.ResponseWriter, r *http.Request) {
	name, pass, ok := s.certForm(w, r)
	if !ok {
		return
	}
	if _, err := validAliasOrDNSName(name); err != nil {
		s.toastResultErr(w, "invalid name")
		return
	}
	cloneFrom := strings.TrimSpace(r.PostFormValue("clone_source"))
	match := strings.TrimSpace(r.PostFormValue("server"))
	if cloneFrom != "" {
		match = "" // clone path matches nothing; it creates
	}
	force := r.PostFormValue("force") == "on" || r.PostFormValue("force") == "true"
	res, err := s.nginxEnv().Install(s.home, s.keysDir, name, pass,
		certmgr.InstallOpts{MatchName: match, CloneFrom: cloneFrom, Force: force}, time.Now())
	if err != nil {
		s.mutationResult(w, mapCertErr(err))
		return
	}
	switch {
	case res.Cloned:
		s.toastResult(w, fmt.Sprintf("cloned %q for %s — %s, nginx -t ok, reloaded",
			res.ClonedSrc, name, strings.Join(res.Edited, ", ")))
	case res.Already && len(res.Edited) == 0:
		s.toastResult(w, "nginx already serves this exact certificate")
	case res.Reloaded:
		s.toastResult(w, fmt.Sprintf("installed into %s — nginx -t ok, reloaded", strings.Join(res.Edited, ", ")))
	default:
		s.toastResult(w, fmt.Sprintf("installed into %s (reload skipped)", strings.Join(res.Edited, ", ")))
	}
}

// handleCertNginxReload validates + reloads nginx (for after hand edits).
func (s *Server) handleCertNginxReload(w http.ResponseWriter, r *http.Request) {
	if err := s.certReload(); err != nil {
		s.toastResultErr(w, truncateToast(err.Error()))
		return
	}
	s.toastResult(w, "nginx -t ok, reloaded")
}

func (s *Server) certReload() error {
	env := s.nginxEnv()
	if err := env.Locate(); err != nil {
		return err
	}
	if err := env.Reload(false); err == nil {
		return nil
	}
	return env.Reload(true)
}

// certForm is the shared form parsing (name + optional passphrase) with
// the CSRF-safe handlers' error shape.
func (s *Server) certForm(w http.ResponseWriter, r *http.Request) (name, pass string, ok bool) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return "", "", false
	}
	name = strings.ToLower(strings.TrimSpace(r.PostFormValue("name")))
	name = strings.TrimSuffix(name, ".")
	pass = r.PostFormValue("passphrase")
	return name, pass, true
}

func certNames(rs []*certmgr.Renewal) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}

// truncateToast keeps pathological error spew (a failed bulk renew) inside
// one toast.
func truncateToast(msg string) string {
	if len(msg) <= 220 {
		return msg
	}
	return strings.TrimSpace(msg[:217]) + "…"
}
