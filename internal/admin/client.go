// client.go — the CLI-side half of the admin socket: a zero-config HTTP
// client over the daemon's unix socket (home.AdminSock in production) plus
// the Alive liveness probe. Everything here is transport plumbing; the
// semantics are the server's (see handlers.go).
//
// Usage sketch (cmd/freens-cli):
//
//	c := &admin.Client{Sock: home.AdminSock()}
//	if !admin.Alive(c.Sock) { /* fall back to standalone node */ }
//	st, err := c.Status(ctx)
//
// Requests time out at Client.Timeout (default 10 s) or the caller's context
// deadline, whichever is shorter; the server independently caps its own work
// at 30 s, so a hung request never outlives both ends' budgets.

package admin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/laurent/freens/internal/dht"
	"github.com/laurent/freens/internal/wire"
)

// defaultTimeout bounds one client request when Client.Timeout is unset.
// 10 s covers the daemon's slowest healthy endpoint (a 30 s-capped network
// operation that would exceed 10 s is not healthy from a CLI user's
// perspective — better a clean timeout than a frozen terminal).
const defaultTimeout = 10 * time.Second

// Client talks to a running daemon's admin socket. The zero value is not
// usable — set Sock (Timeout is optional).
type Client struct {
	// Sock is the daemon's unix socket path (home.AdminSock()).
	Sock string
	// Timeout bounds each request; zero ⇒ 10 s.
	Timeout time.Duration
}

// Alive reports whether a daemon is serving on sock: a plain unix-stream
// dial check, no HTTP. It is the CLI's first move — "use the daemon if there
// is one, spin a standalone node otherwise" — and doubles as the
// Close-semantics probe in tests. A socket file that exists but refuses the
// dial (stale from a crashed daemon) is dead, not alive.
func Alive(sock string) bool {
	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// timeout resolves the effective per-request budget.
func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return defaultTimeout
}

// httpClient builds a one-shot client dialing the unix socket. Per-call
// construction keeps Client safe for concurrent use without a lazily-shared
// Transport whose lifecycle nobody owns; the dial cost is a local AF_UNIX
// connect, i.e. nothing.
func (c *Client) httpClient() *http.Client {
	return &http.Client{
		Timeout: c.timeout(),
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", c.Sock)
			},
			// DisableKeepAlives: requests are one-shot CLI invocations; a
			// lingering pooled connection would only delay daemon shutdown.
			DisableKeepAlives: true,
		},
	}
}

// do performs one JSON round trip: reqBody (nil ⇒ no body) is marshalled,
// sent as method path, and a 2xx response is unmarshalled into out (non-nil).
// It returns the response status so callers can give special meaning to
// specific codes (Client.Get's 404 ⇒ not found). Non-2xx bodies carry the
// server's {"error": ...} and are surfaced as errors verbatim.
func (c *Client) do(ctx context.Context, method, path string, reqBody, out any) (int, error) {
	var body []byte
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return 0, fmt.Errorf("admin: encode request: %w", err)
		}
		body = b
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://admin"+path, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("admin: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return 0, fmt.Errorf("admin: dial %s: %w", c.Sock, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		msg := resp.Status
		if json.NewDecoder(resp.Body).Decode(&e) == nil && e.Error != "" {
			msg = e.Error
		}
		return resp.StatusCode, fmt.Errorf("admin: %s %s: %s", method, path, msg)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("admin: decode response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// Status fetches the daemon/node snapshot (GET /status).
func (c *Client) Status(ctx context.Context) (*Status, error) {
	var st Status
	if _, err := c.do(ctx, http.MethodGet, "/status", nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// envelopeRequest is the publish-family request body.
type envelopeRequest struct {
	Envelope string `json:"envelope"`
	Claim    bool   `json:"claim,omitempty"`
}

// Publish publishes env through the daemon's node (POST /publish): the §6.4
// PUT at the record's name key, plus — when the record carries an AliasClaim
// in field 11 — the §7.4/C.1 claim publication at K_claim. It returns the
// number of distinct keys at least one peer accepted (1, or 2 for a
// claim-carrying record).
func (c *Client) Publish(ctx context.Context, env *wire.SignedEnvelope) (accepted int, err error) {
	return c.publish(ctx, env, false)
}

// PublishClaim publishes env's claim leg only (POST /publish with
// claim:true): the §7.4/C.1 K_claim publication via node.PublishClaim
// semantics. The record must carry a decodable AliasClaim (field 11).
func (c *Client) PublishClaim(ctx context.Context, env *wire.SignedEnvelope) error {
	_, err := c.publish(ctx, env, true)
	return err
}

// publish is the shared body of Publish/PublishClaim.
func (c *Client) publish(ctx context.Context, env *wire.SignedEnvelope, claim bool) (int, error) {
	if env == nil {
		return 0, fmt.Errorf("admin: nil envelope")
	}
	b, err := env.Bytes()
	if err != nil {
		return 0, fmt.Errorf("admin: encode envelope: %w", err)
	}
	var out struct {
		Accepted int `json:"accepted"`
	}
	_, err = c.do(ctx, http.MethodPost, "/publish", &envelopeRequest{
		Envelope: base64.StdEncoding.EncodeToString(b),
		Claim:    claim,
	}, &out)
	if err != nil {
		return 0, err
	}
	return out.Accepted, nil
}

// Get fetches the winning envelope at a raw 32-byte storage key (POST /get).
// It returns (nil, nil) when no envelope is stored at the key anywhere
// reachable — "not found" is an answer, not an error, mirroring
// dht.Node.IterativeGet's contract so CLI code can treat both uniformly.
func (c *Client) Get(ctx context.Context, key []byte) (*wire.SignedEnvelope, error) {
	var out struct {
		Envelope string `json:"envelope"`
	}
	code, err := c.do(ctx, http.MethodPost, "/get", &struct {
		Key string `json:"key"`
	}{Key: hex.EncodeToString(key)}, &out)
	if code == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(out.Envelope)
	if err != nil {
		return nil, fmt.Errorf("admin: bad envelope base64: %w", err)
	}
	return wire.DecodeEnvelope(raw)
}

// Resolve resolves a display name (POST /resolve): "www.alice" with alice
// the ALIAS — the daemon maps the alias to its TLD via the §7.4 claim path
// (K_claim → AliasClaim.TldID), then fetches the record at the derived
// K_name/K_tld. A name with nothing published resolves to &Resolved{Found:
// false}, not an error.
func (c *Client) Resolve(ctx context.Context, name string) (*Resolved, error) {
	var res Resolved
	_, err := c.do(ctx, http.MethodPost, "/resolve", &struct {
		Name string `json:"name"`
	}{Name: name}, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// Witness collects §7.3 witness attestations for a claim identity through
// the daemon's node (POST /witness): the daemon walks toward K_claim, then
// solicits the WITNESS_SET closest candidates. The returned slice holds the
// RAW canonical WitnessAttestation CBORs (decode with
// claims.DecodeWitnessAttestation; the dht layer has already verified each
// signature against the exact claim context). It may be shorter than the
// witness set — possibly empty; assembling the W=5 quorum is the caller's
// check.
func (c *Client) Witness(ctx context.Context, alias string, tldID, claimant []byte, ts uint64) (atts [][]byte, err error) {
	var out struct {
		Attestations []string `json:"attestations"`
	}
	_, err = c.do(ctx, http.MethodPost, "/witness", &struct {
		Alias    string `json:"alias"`
		TldID    string `json:"tld_id_hex"`
		Claimant string `json:"claimant_hex"`
		TS       uint64 `json:"ts"`
	}{
		Alias:    alias,
		TldID:    hex.EncodeToString(tldID),
		Claimant: hex.EncodeToString(claimant),
		TS:       ts,
	}, &out)
	if err != nil {
		return nil, err
	}
	for _, b64 := range out.Attestations {
		raw, derr := base64.StdEncoding.DecodeString(b64)
		if derr != nil {
			return nil, fmt.Errorf("admin: bad attestation base64: %w", derr)
		}
		atts = append(atts, raw)
	}
	return atts, nil
}

// Peers returns the daemon's routing-table contacts (GET /peers) — the CLI's
// standalone-fallback bootstrap set: when the daemon is down, a one-shot CLI
// node dials these instead of demanding -peers.
func (c *Client) Peers(ctx context.Context) ([]dht.Peer, error) {
	var out struct {
		Peers []struct {
			Addr string `json:"addr"`
			PK   string `json:"pk"`
		} `json:"peers"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/peers", nil, &out); err != nil {
		return nil, err
	}
	peers := make([]dht.Peer, 0, len(out.Peers))
	for _, p := range out.Peers {
		pk, err := hex.DecodeString(p.PK)
		if err != nil || len(pk) != 32 || p.Addr == "" {
			continue // defensive: skip a malformed entry, not the whole set
		}
		peers = append(peers, dht.Peer{Addr: p.Addr, PublicKey: pk})
	}
	return peers, nil
}
