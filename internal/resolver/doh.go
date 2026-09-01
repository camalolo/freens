// doh.go — the SERVER half of RFC 8484 DNS-over-HTTPS (v0.14.0, spec §9.6):
// an http.Handler that answers DoH queries by resolving through a
// MsgResolver (in the daemon that is *Resolver itself; in freens-web it is
// a thin admin-socket relay to the daemon's resolver).
//
// The handler is deliberately transport-naked: no TLS, no listener, no
// access control of its own. The webui mounts it on its existing §9.5
// HTTPS listener at /dns-query, so the certificate, HTTP/2 (ALPN), the LAN
// CIDR gate and the http→https sniffing all come from infrastructure that
// already runs on every install — enabling "serve DoH" is a config flip,
// not a new network surface.
package resolver

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/camalolo/freens/internal/metrics"
	"github.com/miekg/dns"
)

// DoHContentType is the single media type RFC 8484 defines for DoH request
// and response bodies (both directions).
const DoHContentType = "application/dns-message"

// maxDoHQueryBytes caps one DoH request body. RFC 8484 §4.1 lets the server
// choose; 64 KiB is ~128× the classic UDP datagram budget and far beyond any
// legitimate query, while keeping the endpoint useless for memory games.
const maxDoHQueryBytes = 64 << 10

// MsgResolver answers one DNS message (the slice of *Resolver the DoH
// handler needs). *Resolver satisfies it directly; remote transports (the
// webui's admin-socket relay) satisfy it by unpack → relay → unpack.
type MsgResolver interface {
	ResolveMsg(ctx context.Context, m *dns.Msg) *dns.Msg
}

// DoHHandler is the RFC 8484 request surface. Mount at /dns-query.
type DoHHandler struct {
	// Resolver answers the queries. nil ⇒ every query is answered SERVFAIL
	// (the DNS-shaped answer for "the resolution engine is unavailable" —
	// never a bare HTTP error, which stubs treat as a transport failure).
	Resolver MsgResolver
	// Queries optionally counts every answered query by (qtype, status) —
	// the SAME label layout the UDP/TCP servers use, so one counter family
	// covers all transports. nil disables instrumentation.
	Queries *metrics.Counter
}

// ServeHTTP answers one DoH request: GET ?dns=<base64url> or POST with an
// application/dns-message body. Errors are HTTP-status where RFC 8484 says
// so (bad method/content-type/oversize) and DNS-rcode where the client can
// still use the answer (malformed-but-decodable query → FORMERR).
func (h *DoHHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	payload, ok := h.readQuery(w, r)
	if !ok {
		return
	}
	q := new(dns.Msg)
	if err := q.Unpack(payload); err != nil {
		http.Error(w, "malformed DNS query", http.StatusBadRequest)
		return
	}
	if len(q.Question) == 0 {
		resp := new(dns.Msg)
		resp.SetRcode(q, dns.RcodeFormatError)
		h.writeDoH(w, resp)
		return
	}
	resp := h.resolve(r, q)
	if h.Queries != nil {
		h.Queries.With(qtypeLabel(q), statusLabel(resp.Rcode)).Inc()
	}
	h.writeDoH(w, resp)
}

// readQuery extracts the raw DNS wire query from the request, answering
// with the appropriate HTTP error (and ok == false) when the request is not
// a well-formed DoH query.
func (h *DoHHandler) readQuery(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return nil, false
		}
		payload, err := decodeBase64URL(dnsParam)
		if err != nil {
			http.Error(w, "malformed dns parameter", http.StatusBadRequest)
			return nil, false
		}
		return payload, true
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, DoHContentType) {
			w.Header().Set("Accept", DoHContentType)
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return nil, false
		}
		payload, err := io.ReadAll(io.LimitReader(r.Body, maxDoHQueryBytes+1))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return nil, false
		}
		if len(payload) > maxDoHQueryBytes {
			http.Error(w, "query too large", http.StatusRequestEntityTooLarge)
			return nil, false
		}
		return payload, true
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return nil, false
	}
}

// decodeBase64URL decodes the RFC 8484 §4.1.1 `dns` parameter: base64url.
// Padding is optional per RFC 4648 §3.2 but clients differ, so padded input
// is tolerated too (decode tolerant, emit canonical).
func decodeBase64URL(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}

// resolve answers q through the configured MsgResolver, SERVFAIL when none
// is wired (see the field doc).
func (h *DoHHandler) resolve(r *http.Request, q *dns.Msg) *dns.Msg {
	if h.Resolver == nil {
		resp := new(dns.Msg)
		resp.SetRcode(q, dns.RcodeServerFailure)
		return resp
	}
	return h.Resolver.ResolveMsg(r.Context(), q)
}

// writeDoH writes resp as the DoH payload: 200 with the DNS message, the
// media type, and a Cache-Control derived from the answer TTLs (RFC 8484
// §5.1: the smallest TTL in the response governs). Negative/empty answers
// carry no HTTP cache hint (max-age=0): the daemon's own §10.4 negative
// cache already absorbs repeat load, and overstating a negative TTL here
// would delay a just-published name on the CLIENT.
func (h *DoHHandler) writeDoH(w http.ResponseWriter, resp *dns.Msg) {
	payload, err := resp.Pack()
	if err != nil {
		http.Error(w, "response encoding failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", DoHContentType)
	if len(resp.Answer) > 0 {
		minTTL := ^uint32(0)
		for _, rr := range resp.Answer {
			if t := rr.Header().Ttl; t < minTTL {
				minTTL = t
			}
		}
		w.Header().Set("Cache-Control", "max-age="+strconv.FormatUint(uint64(minTTL), 10))
	} else {
		w.Header().Set("Cache-Control", "max-age=0")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}
