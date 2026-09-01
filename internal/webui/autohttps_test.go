// autohttps_test.go — the one-port both-dialects listener: plaintext HTTP
// gets a 308 upgrade (Host preserved, HSTS set), TLS serves the UI
// normally, and Shutdown drains both dialects without hanging.
package webui

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/tlsca"
)

// autoHTTPSFixture serves an https-capable UI on an ephemeral port with a
// real §9.5 leaf for "desktest" (the same minting the cmd binary does)
// and returns the live http/https base URLs.
func autoHTTPSFixture(t *testing.T) (httpBase, httpsBase string) {
	t.Helper()
	dir := t.TempDir()
	cfg := &Config{Listen: "127.0.0.1:0", Allow: "any", HomeDir: dir}
	srv, err := New(cfg, filepath.Join(dir, "admin.sock"), nil)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caDER, caKey, err := tlsca.OwnerCA(kp.Seed(), "desktest", now)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, leafKeyDER, err := tlsca.Leaf(caDER, caKey, []string{"desktest", "*.desktest"}, now)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(append([]byte{}, tlsca.CertPEM(leafDER)...), tlsca.CertPEM(caDER)...)
	cert, err := tls.X509KeyPair(chain, tlsca.KeyPEM(leafKeyDER))
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServeTLS(&cert) }()

	deadline := time.Now().Add(5 * time.Second)
	var base string
	for time.Now().Before(deadline) {
		if base = srv.BoundAddr(); base != "" {
			break
		}
		select {
		case e := <-serveErr:
			t.Fatalf("serve failed: %v", e)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	if base == "" {
		t.Fatal("server never bound (5s)")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		select {
		case <-serveErr:
		case <-time.After(3 * time.Second):
			t.Error("serve did not return after Shutdown (deadlocked dialect?)")
		}
	})
	host := base // "127.0.0.1:port"
	return "http://" + host, "https://" + host
}

// plainRoundTrip sends one plaintext HTTP request without redirect
// following (RoundTrip, not Client.Get).
func plainRoundTrip(t *testing.T, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Transport{}).RoundTrip(req)
	if err != nil {
		t.Fatalf("plaintext round trip: %v — the sniffed connection must answer, not reset", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestAutoHTTPSRedirectsPlaintext(t *testing.T) {
	httpBase, _ := autoHTTPSFixture(t)

	resp := plainRoundTrip(t, httpBase+"/some/page?x=1")
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Fatalf("status = %d; want 308", resp.StatusCode)
	}
	host := strings.TrimPrefix(httpBase, "http://")
	if want := "https://" + host + "/some/page?x=1"; resp.Header.Get("Location") != want {
		t.Errorf("Location = %q; want %q (host + query preserved)", resp.Header.Get("Location"), want)
	}
	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Error("HSTS header missing on the redirect")
	}
	// Note: "Connection: close" cannot be asserted here — it is a
	// hop-by-hop header the client transport strips from resp.Header. The
	// handler sets it; the server enforces the close.
}

func TestAutoHTTPSServesTLS(t *testing.T) {
	_, httpsBase := autoHTTPSFixture(t)

	// A TLS client (no verification — the test client holds no trust
	// root) reaches the real UI: the sniffed 0x16 byte routes to the TLS
	// server, Host header "desktest" matches the leaf SANs.
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := net.DialTimeout(network, addr, 3*time.Second)
			if err != nil {
				return nil, err
			}
			return tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: "desktest"}), nil
		},
	}
	req, err := http.NewRequest(http.MethodGet, httpsBase+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("https round trip: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("https status = %d; want 200", resp.StatusCode)
	}
}

// TestShutdownDrainsBothDialects: while in flight, both dialects answer;
// the fixture's cleanup Shutdown would hang the suite if either dialect
// deadlocked (Accept loop, redirect server, or TLS server).
func TestShutdownDrainsBothDialects(t *testing.T) {
	httpBase, httpsBase := autoHTTPSFixture(t)
	if resp := plainRoundTrip(t, httpBase+"/x"); resp.StatusCode != 308 {
		t.Fatalf("plaintext in flight: %d", resp.StatusCode)
	}
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := net.DialTimeout(network, addr, 3*time.Second)
			if err != nil {
				return nil, err
			}
			return tls.Client(c, &tls.Config{InsecureSkipVerify: true}), nil
		},
	}
	req, _ := http.NewRequest(http.MethodGet, httpsBase+"/healthz", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("https in flight: %v", err)
	}
	resp.Body.Close()
	_ = fmt.Sprint() // keep fmt for future assertions
}
