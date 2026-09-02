// admin_test.go — maybeAdmin against a temp socket (down), and against a
// hand-written stub unix listener serving minimal admin JSON (up). The stub
// is deliberately protocol-lenient (accepts any method, finds the resolve
// name in the query string, the path, or a JSON body, and decodes published
// envelopes from raw CBOR or JSON-carried bytes) so it tracks the pinned
// internal/admin client API, not incidental wire spellings.
package cli

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/camalolo/freens/internal/wire"
)

// stubAdmin is a tiny HTTP-over-unix admin server for tests.
type stubAdmin struct {
	t              *testing.T
	sock           string
	ln             net.Listener
	srv            *http.Server
	resolve        map[string]string // display name -> Resolved JSON
	published      []*wire.SignedEnvelope
	publishedClaim []*wire.SignedEnvelope
	rawPublish     [][]byte
	getKey         []byte               // when set, /get serves getEnv (base64)
	getEnv         *wire.SignedEnvelope // when getKey matches
	statusJSON     string               // when set, served instead of the default /status body
}

// startStubAdmin listens on sock (the admin socket path of a temp home).
func startStubAdmin(t *testing.T, sock string, resolve map[string]string) *stubAdmin {
	t.Helper()
	s := &stubAdmin{t: t, sock: sock, resolve: resolve}
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("stub admin listen: %v", err)
	}
	s.ln = ln

	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if s.statusJSON != "" {
			fmt.Fprint(w, s.statusJSON)
			return
		}
		fmt.Fprint(w, `{"running":true,"version":"stub-1","node_id":"aa","node_pk":"bb","dht_listen":"0.0.0.0:15353","advertise":"","peers":3,"store_envs":1,"history_envs":0,"relay_mode":false,"turn_allocs":0,"network_claims":true}`)
	})
	mux.HandleFunc("/resolve", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			name = strings.Trim(strings.TrimPrefix(r.URL.Path, "/resolve"), "/")
			if strings.Contains(name, "/") { // e.g. /resolve/www.alice
				name = filepath.Base(name)
			}
		}
		if name == "" {
			var bj struct {
				Name string `json:"name"`
			}
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &bj)
			name = bj.Name
		}
		if resp, ok := s.resolve[name]; ok {
			fmt.Fprint(w, resp)
			return
		}
		fmt.Fprint(w, `{"found":false}`)
	})
	mux.HandleFunc("/publish", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.rawPublish = append(s.rawPublish, body)
		if env := decodeStubEnvelope(body); env != nil {
			s.published = append(s.published, env)
		}
		fmt.Fprint(w, `{"accepted":2}`)
	})
	mux.HandleFunc("/publish-claim", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if env := decodeStubEnvelope(body); env != nil {
			s.publishedClaim = append(s.publishedClaim, env)
		}
		fmt.Fprint(w, `{}`)
	})
	mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[]`)
	})
	mux.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		var gj struct {
			Key string `json:"key"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gj)
		want := hex.EncodeToString(s.getKey)
		if s.getKey != nil && gj.Key == want && s.getEnv != nil {
			if eb, err := s.getEnv.Bytes(); err == nil {
				fmt.Fprintf(w, `{"envelope":%q}`, base64.StdEncoding.EncodeToString(eb))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"not found"}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// lenient catch-all: anything unknown answers success-shaped JSON so
		// minor protocol spelling differences do not fail the tests
		fmt.Fprint(w, `{}`)
	})

	s.srv = &http.Server{Handler: mux}
	go func() { _ = s.srv.Serve(ln) }()
	t.Cleanup(func() { _ = s.srv.Close() })
	return s
}

// decodeStubEnvelope pulls a SignedEnvelope out of a publish request body:
// the admin client's JSON form {"envelope": "<base64>"} (plus the claim leg
// flag), raw canonical CBOR, or JSON carrying it hex-encoded — lenient on
// purpose so incidental wire spellings do not fail the tests.
func decodeStubEnvelope(body []byte) *wire.SignedEnvelope {
	if env, err := wire.DecodeEnvelope(body); err == nil {
		return env
	}
	var pj struct {
		Envelope    string `json:"envelope"`     // admin client's form: base64
		EnvelopeB64 string `json:"envelope_b64"` // tolerated alias
		EnvelopeHex string `json:"envelope_hex"` // tolerated alias
	}
	if err := json.Unmarshal(body, &pj); err != nil {
		return nil
	}
	for _, b64 := range []string{pj.Envelope, pj.EnvelopeB64} {
		if b64 == "" {
			continue
		}
		if b, err := base64.StdEncoding.DecodeString(b64); err == nil {
			if env, err := wire.DecodeEnvelope(b); err == nil {
				return env
			}
		}
	}
	if pj.EnvelopeHex != "" {
		if b, err := hex.DecodeString(pj.EnvelopeHex); err == nil {
			if env, err := wire.DecodeEnvelope(b); err == nil {
				return env
			}
		}
	}
	return nil
}

// resolvedJSON builds a stub Resolved answer: found with the given sequence
// and an optional A record (rdata base64 + dotted-quad text, matching the
// daemon's rendering).
func resolvedJSON(name string, seq int, aIP string) string {
	rrset := "[]"
	if aIP != "" {
		parts := strings.Split(aIP, ".")
		b := make([]byte, 4)
		for i, p := range parts {
			fmt.Sscanf(p, "%d", &b[i])
		}
		rrset = fmt.Sprintf(`[{"type":1,"ttl":300,"rdata_b64":%q,"rdata_text":%q}]`,
			base64.StdEncoding.EncodeToString(b), aIP)
	}
	return fmt.Sprintf(`{"found":true,"name":%q,"owner":"ab","sequence":%d,"tld_id_b32":"","rrset":%s}`, name, seq, rrset)
}

// ---------------------------------------------------------------------------
// maybeAdmin
// ---------------------------------------------------------------------------

func TestMaybeAdminNoSocket(t *testing.T) {
	tempHome(t) // admin.sock does not exist there
	if c := maybeAdmin(); c != nil {
		t.Fatalf("maybeAdmin with no socket = %v, want nil", c)
	}
}

func TestMaybeAdminStubSocket(t *testing.T) {
	h := tempHome(t)
	startStubAdmin(t, filepath.Join(h, "admin.sock"), nil)
	c := maybeAdmin()
	if c == nil {
		t.Fatal("maybeAdmin with a live stub socket = nil, want a client")
	}
}

// TestPickTransportRules: the three-mode rule end to end — peers wins,
// daemon fills in, neither errors with the standing message.
func TestPickTransportRules(t *testing.T) {
	h := tempHome(t)

	// Neither: errNoDaemon, verbatim.
	if _, err := pickTransport(""); err == nil || err.Error() != errNoDaemon.Error() {
		t.Errorf("no peers/daemon: %v, want %v", err, errNoDaemon)
	}

	// Daemon.
	startStubAdmin(t, filepath.Join(h, "admin.sock"), nil)
	tr, err := pickTransport("")
	if err != nil || !tr.daemon() {
		t.Errorf("daemon transport: %v daemon=%v", err, tr.daemon())
	}

	// -peers overrides the daemon (standalone exactly as today).
	tr, err = pickTransport("127.0.0.1:15353#" + strings.Repeat("ab", 32))
	if err != nil || tr.daemon() || len(tr.peers) != 1 {
		t.Errorf("peers transport: err=%v daemon=%v peers=%d", err, tr.daemon(), len(tr.peers))
	}

	// A typo'd peer list is still a usage error, daemon or not.
	if _, err := pickTransport("not-a-peer"); err == nil {
		t.Error("malformed -peers accepted")
	}
}
