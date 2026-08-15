// handlers.go — the admin socket's HTTP surface: route table, the six
// endpoints, and the JSON wire types consumed verbatim by the CLI
// (cmd/freens-cli). Every endpoint is a thin, defensive translation between
// JSON and the daemon's already-running *dht.Node; no endpoint mutates node
// configuration (the control socket is read + publish + register-help, not a
// remote config API).
//
// Conventions:
//
//   - Errors are always {"error":"<message>"} with a 4xx (bad request) or
//     5xx (server/daemon-side) status; 503 specifically means "daemon runs
//     without a DHT node" on network endpoints.
//   - Binary payloads are base64 (encoding/base64.StdEncoding); keys and node
//     identifiers are lowercase hex; tld_id pins are lowercase RFC 4648 base32
//     without padding (the freens-cli display convention).
//   - The slow endpoints (/publish, /get, /resolve, /witness) cap their work
//     at 30 s server-side regardless of the client's deadline, so a stuck CLI
//     connection can never pin a daemon goroutine forever. (dht lookups apply
//     their own tighter per-hop budgets on top; the cap is the outer bound.)

package admin

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/laurent/freens/internal/claims"
	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/dht"
	"github.com/laurent/freens/internal/naming"
	"github.com/laurent/freens/internal/wire"
)

// requestCap bounds every network-touching endpoint's server-side context
// (see file doc). 30 s is ~6× the dht package's own worst-case iterative
// lookup budget, so it never cuts a healthy operation short — it only stops
// a pathological one.
const requestCap = 30 * time.Second

// maxBodyBytes caps POST bodies. The largest legitimate payload is a signed
// envelope (a few KiB at the spec's RR limits); 4 MiB is two orders of
// magnitude of headroom while still making the socket useless for
// memory-exhaustion games.
const maxBodyBytes = 4 << 20

// routes builds the admin mux. Method-specific patterns ("GET /status") get
// 405 Method Not Allowed from net/http for free on a method mismatch, and 404
// for unknown paths — no custom dispatch code to get wrong.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", s.handleStatus)
	mux.HandleFunc("POST /publish", s.handlePublish)
	mux.HandleFunc("POST /get", s.handleGet)
	mux.HandleFunc("POST /resolve", s.handleResolve)
	mux.HandleFunc("POST /witness", s.handleWitness)
	mux.HandleFunc("GET /peers", s.handlePeers)
	return s.logRequests(mux)
}

// logRequests wraps the mux with a Debug-level access log. Debug (not Info):
// the CLI may poll /status frequently and the daemon log must stay readable.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.log.Debug("admin: request",
			"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr,
			"dur", time.Since(start).Round(time.Microsecond))
	})
}

// ---------------------------------------------------------------------------
// JSON wire types (pinned — consumed verbatim by cmd/freens-cli)
// ---------------------------------------------------------------------------

// Status is the GET /status response: a snapshot of the daemon and its DHT
// node for `freens status`, test harnesses, and the CLI's "should I even
// try the network?" heuristics. Hex/base32 fields are empty when not
// applicable (e.g. node == nil), never zero-padded placeholders.
type Status struct {
	Running       bool   `json:"running"`
	Version       string `json:"version"`
	NodeID        string `json:"node_id,omitempty"` // hex(SHA-256(node_pk))
	NodePK        string `json:"node_pk,omitempty"` // hex(node_pk)
	DHTListen     string `json:"dht_listen,omitempty"`
	Advertise     string `json:"advertise,omitempty"` // best-known §6.2 address ("" = observed source)
	Peers         int    `json:"peers"`               // routing-table contacts
	StoreEnvs     int    `json:"store_envelopes"`     // live store entries
	HistoryEnvs   int    `json:"history_envelopes"`   // §8.3 audit-history entries
	RelayMode     bool   `json:"relay_mode"`          // TURN-routed transport
	TURNAllocs    int    `json:"turn_allocs"`         // co-located TURN server allocations
	NetworkClaims bool   `json:"network_claims"`      // this node co-signs §7.3 witness requests
}

// Resolved is the POST /resolve response: the winning record for a display
// name, rendered for humans (hex owner, base32 tld_id, dotted-quad A
// rdata). Found is false — not an HTTP error — when nothing is published for
// the name; the CLI distinguishes "no record" from "daemon broken" by HTTP
// status, not by this field.
type Resolved struct {
	Found    bool   `json:"found"`
	Name     string `json:"name,omitempty"`
	Owner    string `json:"owner,omitempty"` // hex
	Sequence uint64 `json:"sequence,omitempty"`
	TldIDB32 string `json:"tld_id_b32,omitempty"`
	RRset    []RR   `json:"rrset,omitempty"`
}

// RR is one resource record of a Resolved RRset. Rdata is the raw §4.3 bytes
// base64-encoded (type-agnostic); Text carries a human rendering when one
// exists (dotted quad for type A).
type RR struct {
	Type  uint64 `json:"type"`
	TTL   uint64 `json:"ttl"`
	Rdata string `json:"rdata_b64"`
	Text  string `json:"rdata_text,omitempty"` // dotted-quad for type A
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

// writeJSON emits v as the response body with the given status.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr emits the canonical error body {"error": msg} with the given 4xx/5xx.
func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// errNoNode is the pinned "daemon without -dht" answer for network endpoints.
func errNoNode(w http.ResponseWriter) {
	writeErr(w, http.StatusServiceUnavailable, "no dht node")
}

// decodeBody unmarshals one size-capped JSON request body into v. Any failure
// (wrong shape, oversized, truncated) is already answered with a 400; the
// handler just returns.
func (s *Server) decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return false
	}
	return true
}

// capped derives the endpoint's server-side context from the request's own
// (client-disconnect-aware) context with the 30 s outer bound applied.
func capped(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), requestCap)
}

// ---------------------------------------------------------------------------
// GET /status
// ---------------------------------------------------------------------------

// handleStatus reports the daemon/node snapshot (see Status). It works with
// or without a DHT node and never touches the network, which is what makes it
// the liveness probe: `freens status` first, everything else second.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := Status{
		Running: true, // this server is answering, by definition
		Version: s.version,
	}
	if n := s.node; n != nil {
		st.NodeID = hex.EncodeToString(n.ID())
		st.NodePK = hex.EncodeToString(n.PublicKey())
		if la, err := n.LocalAddr(); err == nil {
			st.DHTListen = la.String()
		}
		st.Advertise = s.advertisedAddr()
		st.Peers = n.RoutingTable().Size()
		st.StoreEnvs, st.HistoryEnvs = s.storeCounts()
		st.RelayMode = n.RelayedMode()
		if ts := n.TURNServer(); ts != nil {
			st.TURNAllocs = ts.Allocations()
		}
		st.NetworkClaims = true // a running node answers §7.3 witness RPCs
	}
	writeJSON(w, http.StatusOK, st)
}

// advertisedAddr returns the node's best-known §6.2 advertised address (""
// when peers learn the observed UDP source — behind no NAT or a cone NAT
// this is correct and the field stays empty by design, not by omission).
// The value is the daemon's live one: Advertised is updated at runtime by
// the STUN monitor / UPnP renewal, and /status reflects whatever the node
// would stamp on its next outbound query.
func (s *Server) advertisedAddr() string {
	if s.node == nil {
		return ""
	}
	return s.node.Advertised()
}

// storeCounts returns (live, history) envelope counts of the daemon's store.
//
// NOTE: pending the parallel dht.DHTLookup.Store() accessor these are 0; the
// daemon's store exists (it backs the node) but the admin side cannot reach
// it through the pinned New() surface yet. See the package report.
func (s *Server) storeCounts() (live, history int) {
	if s.lookup == nil || s.lookup.Store() == nil {
		return 0, 0
	}
	st := s.lookup.Store()
	return st.Count(), st.HistoryCount()
}

// ---------------------------------------------------------------------------
// POST /publish
// ---------------------------------------------------------------------------

// publishRequest is the /publish body. Envelope is the canonical
// SignedEnvelope CBOR, base64 (StdEncoding). Claim selects the mode:
//
//   - false (default): node.Publish at K_tld/K_name (§6.4 PUT), PLUS — when
//     the record's field 11 carries a decodable AliasClaim — node.PublishClaim
//     at K_claim (§7.4 step 5 / C.1 step 4: the claim envelope lives at BOTH
//     keys). This mirrors the daemon's own register path so a CLI publish is
//     indistinguishable from a first-party one.
//   - true: PublishClaim ONLY (the claim leg alone; 400 when the record
//     carries no decodable claim) — the re-publish/refresh path.
type publishRequest struct {
	Envelope string `json:"envelope"`
	Claim    bool   `json:"claim"`
}

// handlePublish verifies and publishes an envelope through the daemon's node.
// The response is {"accepted": N} where N counts the DISTINCT KEYS the daemon
// got at least one peer acceptance for (1 for a plain record, 2 when the
// claim-carrying record landed at both K_tld and K_claim). A primary publish
// accepted by zero peers is a 502 (the daemon is up but the network is not
// usable); a failed claim LEG after a successful primary publish is only
// warned about and still returns 200 with accepted=1 — mirroring
// dht.Publish/PublishClaim's own best-effort contract.
func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	if s.node == nil {
		errNoNode(w)
		return
	}
	var req publishRequest
	if !s.decodeBody(w, r, &req) {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.Envelope)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad envelope base64: "+err.Error())
		return
	}
	env, err := wire.DecodeEnvelope(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad envelope: "+err.Error())
		return
	}
	// Signature is checked here so garbage never costs a network round trip
	// (peers would reject it anyway — hPut re-verifies).
	if !env.VerifySignature() {
		writeErr(w, http.StatusBadRequest, "envelope signature does not verify")
		return
	}
	ctx, cancel := capped(r)
	defer cancel()

	// Does the record carry a §7.3 claim in field 11?
	claim, claimErr := claims.DecodeAliasClaim(env.Record.Claim)

	if req.Claim {
		// Claim-only mode: PublishClaim semantics, no primary publish.
		if claimErr != nil {
			writeErr(w, http.StatusBadRequest, "envelope carries no decodable alias claim (field 11)")
			return
		}
		if err := s.node.PublishClaim(ctx, env); err != nil {
			writeErr(w, http.StatusBadGateway, "publish-claim failed: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"accepted": 1})
		return
	}

	if err := s.node.Publish(ctx, env); err != nil {
		writeErr(w, http.StatusBadGateway, "publish failed: "+err.Error())
		return
	}
	accepted := 1
	if claimErr == nil {
		// §7.4/C.1: the same envelope also lives at K_claim. Best-effort —
		// the primary (K_tld/K_name) publication already succeeded.
		if err := s.node.PublishClaim(ctx, env); err != nil {
			s.log.Warn("admin: claim publication at K_claim failed (record published at its name key)",
				"alias", claim.Alias, "err", err)
		} else {
			accepted = 2
		}
	}
	writeJSON(w, http.StatusOK, map[string]int{"accepted": accepted})
}

// ---------------------------------------------------------------------------
// POST /get
// ---------------------------------------------------------------------------

// getRequest is the /get body: a 32-byte DHT storage key (K_tld / K_name /
// K_claim) as lowercase hex.
type getRequest struct {
	Key string `json:"key"`
}

// handleGet fetches the winning envelope at a raw storage key: the daemon's
// local store first (authoritative seeds + §6.4 lookup-path cache), then an
// iterative §6.4 GET across the network. 404 means "no envelope at this key
// anywhere reachable" — the CLI maps it to (nil, nil), not an error.
func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	if s.node == nil {
		errNoNode(w)
		return
	}
	var req getRequest
	if !s.decodeBody(w, r, &req) {
		return
	}
	key, err := hex.DecodeString(req.Key)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad key hex: "+err.Error())
		return
	}
	if len(key) != constants.SHA256Len {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("key must be %d bytes hex", constants.SHA256Len))
		return
	}
	ctx, cancel := capped(r)
	defer cancel()
	env, err := s.fetchEnvelope(ctx, key)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "get failed: "+err.Error())
		return
	}
	if env == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	b, err := env.Bytes()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "envelope encode failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"envelope": base64.StdEncoding.EncodeToString(b)})
}

// fetchEnvelope is the /get lookup: a §6.4 iterative GET across the network.
// (The daemon's local store would be the natural first hop, but no
// key-addressed store read is reachable through the pinned New() surface —
// DHTLookup.Lookup takes a wire_name, not a raw key — so /get is purely the
// network view. The iterative path caches into the daemon's store anyway,
// and a get immediately following a publish is served by the accepting
// peers.)
func (s *Server) fetchEnvelope(ctx context.Context, key []byte) (*wire.SignedEnvelope, error) {
	return s.node.IterativeGet(ctx, key)
}

// ---------------------------------------------------------------------------
// POST /resolve
// ---------------------------------------------------------------------------

// resolveRequest is the /resolve body. Name is the display form
// ("www.alice" — the TLD-adjacent component is the ALIAS). TldIDB32 is an
// optional RFC 4648 base32 tld_id pin (case-insensitive, padding optional):
// when present the alias→TLD claim lookup is skipped entirely, which is both
// the privacy option (no K_claim query) and the bootstrapping option (the
// claim may not exist yet when the pin came from a gen-key output).
type resolveRequest struct {
	Name     string `json:"name"`
	TldIDB32 string `json:"tld_id_b32"`
}

// handleResolve resolves a display name to its winning record. The two-hop
// algorithm mirrors the resolver's §9.2 walk, specialized to the CLI's
// one-shot use:
//
//  1. DecomposeName splits "www.alice" into labels ["www"] and alias "alice"
//     (§3.2; "alice" alone is the TLD apex — labels empty).
//  2. Find the alias's tld_id: from the optional base32 pin, or via the §7.4
//     claim path — K_claim(alias) → the claim-carrying TLD envelope → decode
//     the AliasClaim in field 11 → claim.TldID. This is the alias→owner
//     mapping that makes "www.alice" resolvable without any out-of-band
//     knowledge: the claim IS the alias's pointer to its TLD.
//  3. EncodeWireName(labels, alias, tldID) → KeyForWireName → K_name
//     (or K_tld for the apex) → fetch the winning envelope (§6.4).
//
// A miss at either hop is Found:false with 200 — resolution answered the
// question, the answer is "nothing published".
func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	if s.node == nil {
		errNoNode(w)
		return
	}
	var req resolveRequest
	if !s.decodeBody(w, r, &req) {
		return
	}
	labels, alias, err := naming.DecomposeName(req.Name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad name: "+err.Error())
		return
	}
	ctx, cancel := capped(r)
	defer cancel()

	// Hop 1: the alias's tld_id (pin or claim path).
	var tldID []byte
	if req.TldIDB32 != "" {
		tldID, err = decodeTldIDB32(req.TldIDB32)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad tld_id_b32: "+err.Error())
			return
		}
	} else if tldID, err = s.claimTLDID(ctx, alias); err != nil {
		writeErr(w, http.StatusInternalServerError, "claim lookup failed: "+err.Error())
		return
	} else if tldID == nil {
		writeJSON(w, http.StatusOK, Resolved{Found: false}) // no claim for alias
		return
	}

	// Hop 2: the record at K_name/K_tld for (labels, alias, tldID).
	wireName, err := naming.EncodeWireName(labels, alias, tldID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad name: "+err.Error())
		return
	}
	var env *wire.SignedEnvelope
	if s.lookup != nil {
		env, err = s.lookup.Lookup(ctx, wireName, time.Now().Unix())
	} else {
		var key []byte
		key, err = dht.KeyForWireName(wireName)
		if err == nil {
			env, err = s.node.IterativeGet(ctx, key)
		}
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "lookup failed: "+err.Error())
		return
	}
	if env == nil || env.Record == nil {
		writeJSON(w, http.StatusOK, Resolved{Found: false})
		return
	}
	writeJSON(w, http.StatusOK, resolvedFrom(labels, alias, tldID, env))
}

// claimTLDID resolves an alias to its tld_id via the §7.4 claim path:
// K_claim(alias) → claim envelope → AliasClaim.TldID. It uses the daemon's
// DHTLookup.LookupClaim when available (local store first, network second,
// cache-on-fetch) and falls back to a raw iterative GET otherwise. Returns
// (nil, nil) when no claim is published for the alias.
func (s *Server) claimTLDID(ctx context.Context, alias string) ([]byte, error) {
	var env *wire.SignedEnvelope
	var err error
	if s.lookup != nil {
		env, err = s.lookup.LookupClaim(ctx, alias, time.Now().Unix())
	} else {
		var key []byte
		key, err = dht.KeyForClaim(alias)
		if err == nil {
			env, err = s.node.IterativeGet(ctx, key)
		}
	}
	if err != nil {
		return nil, err
	}
	if env == nil || env.Record == nil {
		return nil, nil
	}
	claim, cerr := claims.DecodeAliasClaim(env.Record.Claim)
	if cerr != nil {
		// An envelope at K_claim without a decodable claim: treat as
		// unpublished rather than failing the whole request.
		return nil, nil
	}
	return claim.TldID, nil
}

// resolvedFrom renders a fetched envelope as the CLI-facing Resolved view.
// Owner is Record.Owner (the authority — §8.2/§8.3 transfers notwithstanding,
// the CLI cares who owns the name, not which key signed this sequence).
func resolvedFrom(labels []string, alias string, tldID []byte, env *wire.SignedEnvelope) Resolved {
	name := alias
	if len(labels) > 0 {
		name = strings.Join(labels, ".") + "." + alias
	}
	res := Resolved{
		Found:    true,
		Name:     name,
		Owner:    hex.EncodeToString(env.Record.Owner),
		Sequence: env.Record.Sequence,
		TldIDB32: encodeTldIDB32(tldID),
	}
	for _, rr := range env.Record.RRset {
		if rr == nil {
			continue
		}
		out := RR{
			Type:  rr.Type,
			TTL:   rr.TTL,
			Rdata: base64.StdEncoding.EncodeToString(rr.Rdata),
		}
		if rr.Type == wire.RRTypeA && len(rr.Rdata) == net.IPv4len {
			if ip := net.IP(rr.Rdata).To4(); ip != nil {
				out.Text = ip.String()
			}
		}
		res.RRset = append(res.RRset, out)
	}
	return res
}

// encodeTldIDB32 renders a tld_id in the freens display convention: lowercase
// RFC 4648 base32, padding stripped (what gen-key prints and pins accept).
func encodeTldIDB32(tldID []byte) string {
	return strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(tldID), "="))
}

// decodeTldIDB32 parses a tld_id pin tolerantly: case-insensitive, padding
// optional, must decode to exactly 32 bytes (mirrors freens-cli decodePin /
// resolver.decodeBase32TLDID).
func decodeTldIDB32(s string) ([]byte, error) {
	s = strings.ToUpper(strings.TrimRight(strings.TrimSpace(s), "="))
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != constants.SHA256Len {
		return nil, fmt.Errorf("decodes to %d bytes, want %d", len(b), constants.SHA256Len)
	}
	return b, nil
}

// ---------------------------------------------------------------------------
// POST /witness
// ---------------------------------------------------------------------------

// witnessRequest is the /witness body: the §7.3 claim IDENTITY (alias,
// tld_id, claimant_pk, timestamp). The PoW nonce does not exist yet at
// witness-collection time (§7.4 step 3 precedes step 2's assembly), so what
// rides here is exactly what the witness RPC binds: the identity fields whose
// canonical-CBOR SHA-256 is the claim prefix hash.
type witnessRequest struct {
	Alias    string `json:"alias"`
	TldID    string `json:"tld_id_hex"`
	Claimant string `json:"claimant_hex"`
	TS       uint64 `json:"ts"`
}

// witnessResponse carries the collected attestations as raw canonical
// WitnessAttestation CBOR, base64-encoded — the CLI embeds them verbatim into
// the claim's field 7 before its final publication.
type witnessResponse struct {
	Attestations []string `json:"attestations"`
}

// handleWitness implements the CLI side of §7.4 registration steps 3-4 on
// top of the daemon's node: first an IterativeFindNode walk toward K_claim
// (a freshly-bootstrapped daemon may know only its seeds; the WITNESS_SET
// are "the W nodes whose IDs are CLOSEST to K_claim", so the table must be
// warmed toward that region before the candidates are selected), then
// CollectWitnesses over the constants.WitnessSet closest candidates. Every
// returned attestation has already been verified by the dht layer against
// the exact claim context AND the answering node's identity.
//
// The result may be empty (witnessing is best-effort; §7.3's W=5 quorum
// assembly is the CLI's check) — an empty 200, not an error.
func (s *Server) handleWitness(w http.ResponseWriter, r *http.Request) {
	if s.node == nil {
		errNoNode(w)
		return
	}
	var req witnessRequest
	if !s.decodeBody(w, r, &req) {
		return
	}
	alias, err := naming.ValidateAlias(req.Alias)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad alias: "+err.Error())
		return
	}
	tldID, err := hex.DecodeString(req.TldID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad tld_id hex: "+err.Error())
		return
	}
	claimant, err := hex.DecodeString(req.Claimant)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad claimant hex: "+err.Error())
		return
	}
	ctx, cancel := capped(r)
	defer cancel()

	// §7.4 step 3, first half: walk toward K_claim so Closest(K_claim, W)
	// selects from a table that actually covers the witness region.
	kClaim, err := dht.KeyForClaim(alias)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad alias: "+err.Error())
		return
	}
	s.node.IterativeFindNode(ctx, kClaim, constants.WitnessSet)

	atts, err := s.node.CollectWitnesses(ctx, alias, tldID, claimant, req.TS, constants.WitnessSet)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "witness collection failed: "+err.Error())
		return
	}
	out := witnessResponse{Attestations: make([]string, 0, len(atts))}
	for _, att := range atts {
		b, err := att.CanonicalBytes()
		if err != nil {
			continue // cannot happen for a decoded attestation; defensive
		}
		out.Attestations = append(out.Attestations, base64.StdEncoding.EncodeToString(b))
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// GET /peers
// ---------------------------------------------------------------------------

// peersResponse lists the node's routing-table contacts. The CLI uses this
// for standalone fallback: when the daemon is unreachable, a one-shot CLI
// node can bootstrap from the LAST-KNOWN contacts instead of requiring -peers
// (the peerbook's live sibling — home.SavePeerbook persists the same set).
type peersResponse struct {
	Peers []peerJSON `json:"peers"`
}

// peerJSON is one contact: the dialable UDP address plus the peer's 32-byte
// node public key (required — recipient_id is inside every §6.3 signature,
// so a node can only address a peer whose key it knows).
type peerJSON struct {
	Addr string `json:"addr"`
	PK   string `json:"pk"`
}

// handlePeers returns every routing-table contact. Deliberately not capped:
// the table is bounded by construction (256 buckets × K), and the CLI wants
// the whole set when falling back to standalone mode.
func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	if s.node == nil {
		errNoNode(w)
		return
	}
	out := peersResponse{}
	for _, c := range s.node.RoutingTable().AllContacts() {
		out.Peers = append(out.Peers, peerJSON{
			Addr: c.Addr,
			PK:   hex.EncodeToString(c.PublicKey),
		})
	}
	writeJSON(w, http.StatusOK, out)
}
