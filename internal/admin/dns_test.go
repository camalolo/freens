// dns_test.go — the v0.14.0 DoH relay endpoints: /dns-query (wire in/out,
// 503 when unwired, 415 wrong content type, 413 oversize) and /reload
// (summary passthrough, 503 when unwired, config-error → 500).
package admin

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// wireQuery packs an A query for name (the payload /dns-query carries).
func wireQuery(t *testing.T, name string) []byte {
	t.Helper()
	b, err := new(dns.Msg).SetQuestion(dns.Fqdn(name), dns.TypeA).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// postRaw POSTs a raw (non-JSON) body to a FRESH admin server and returns
// status + body bytes.
func postRaw(t *testing.T, srv *Server, path, contentType string, body []byte) (int, []byte) {
	t.Helper()
	return postRawTo(t, startAdmin(t, srv), path, contentType, body)
}

func postRawTo(t *testing.T, sock, path, contentType string, body []byte) (int, []byte) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		DisableKeepAlives: true,
	}}
	req, err := http.NewRequest(http.MethodPost, "http://admin"+path, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}

func TestDNSQueryUnwired(t *testing.T) {
	code, body := postRaw(t, New(nil, nil, "v-test", nil), "/dns-query", "application/dns-message", wireQuery(t, "example.com"))
	if code != http.StatusServiceUnavailable || !strings.Contains(string(body), "dns resolver unavailable") {
		t.Errorf("unwired relay = %d %s, want 503", code, body)
	}
}

func TestDNSQueryRelay(t *testing.T) {
	srv := New(nil, nil, "v-test", nil)
	srv.SetDNSHandler(func(ctx context.Context, query []byte) ([]byte, error) {
		q := new(dns.Msg)
		if err := q.Unpack(query); err != nil {
			return nil, err
		}
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte{192, 0, 2, 1},
		})
		return resp.Pack()
	})

	code, body := postRaw(t, srv, "/dns-query", "application/dns-message", wireQuery(t, "example.com"))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(body); err != nil {
		t.Fatalf("response body is not a DNS message: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Errorf("answers = %d, want 1", len(resp.Answer))
	}
}

func TestDNSQueryErrors(t *testing.T) {
	srv := New(nil, nil, "v-test", nil)
	srv.SetDNSHandler(func(ctx context.Context, query []byte) ([]byte, error) {
		return nil, errors.New("resolver exploded")
	})

	// ONE listener for the whole test (a Server serves exactly once).
	sock := startAdmin(t, srv)

	// Wrong content type.
	code, _ := postRawTo(t, sock, "/dns-query", "application/json", wireQuery(t, "example.com"))
	if code != http.StatusUnsupportedMediaType {
		t.Errorf("wrong content type = %d, want 415", code)
	}

	// Resolver error → 502 with the pinned error shape.
	code, body := postRawTo(t, sock, "/dns-query", "application/dns-message", wireQuery(t, "example.com"))
	if code != http.StatusBadGateway || !strings.Contains(string(body), "resolver exploded") {
		t.Errorf("resolver error = %d %s, want 502", code, body)
	}
}

func TestReload(t *testing.T) {
	srv := New(nil, nil, "v-test", nil)

	// Unwired.
	sock := startAdmin(t, srv)
	code, body := post(t, sock, "/reload", "")
	if code != http.StatusServiceUnavailable {
		t.Errorf("unwired reload = %d %s, want 503", code, body)
	}

	// Wired: summary in, summary out.
	srv.SetReloader(func() (string, error) {
		return "upstream: DoH https://9.9.9.9/dns-query", nil
	})
	code, body = post(t, sock, "/reload", "")
	if code != http.StatusOK || !strings.Contains(body, "upstream: DoH") {
		t.Errorf("reload = %d %s", code, body)
	}

	// Config error → 500 with the message.
	srv.SetReloader(func() (string, error) { return "", errors.New("bad config") })
	code, body = post(t, sock, "/reload", "")
	if code != http.StatusInternalServerError || !strings.Contains(body, "bad config") {
		t.Errorf("failed reload = %d %s", code, body)
	}
}
