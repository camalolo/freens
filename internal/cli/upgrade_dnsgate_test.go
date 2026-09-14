// upgrade_dnsgate_test.go — the upgrade verb's DNS-face gate (v0.16.7):
// "daemon back" proved only the admin socket; the resolver could still be
// converging while the verb printed "upgrade complete" (the 2026-09-14
// fleet roll: every box declared healthy while first queries timed out).
// The gate polls the admin DNS relay until the face ANSWERS (any
// terminal rcode).
package cli

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startStubDNSAdmin serves /dns-query with a fixed rcode over a unix
// socket at <home>/admin.sock — the relay waitDNSBack polls.
func startStubDNSAdmin(t *testing.T, home string, rcode int) {
	t.Helper()
	sock := filepath.Join(home, "admin.sock")
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("stub listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		q := new(dns.Msg)
		if q.Unpack(body[:n]) != nil {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Rcode = rcode
		out, err := resp.Pack()
		if err != nil {
			http.Error(w, "pack", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	})
	go http.Serve(ln, mux)
}

// writeOneKey plants a single owner keyfile so keychainAliases() is
// non-empty (the gate skips silently otherwise).
func writeOneKey(t *testing.T, home string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "keys", "alice.key"),
		[]byte("0000000000000000000000000000000000000000000000000000000000000001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWaitDNSBackAnswersOnNoError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("FREENS_HOME", home)
	writeOneKey(t, home)
	startStubDNSAdmin(t, home, dns.RcodeSuccess)

	done := make(chan struct{})
	go func() {
		waitDNSBack(5 * time.Second)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("waitDNSBack did not return on a NOERROR face")
	}
}

func TestWaitDNSBackTimesOutOnServfail(t *testing.T) {
	home := t.TempDir()
	t.Setenv("FREENS_HOME", home)
	writeOneKey(t, home)
	startStubDNSAdmin(t, home, dns.RcodeServerFailure)

	// SERVFAIL is "answering but degraded": the gate keeps polling until
	// its deadline, then warns (captured stderr is the assertion surface).
	start := time.Now()
	waitDNSBack(1500 * time.Millisecond)
	if elapsed := time.Since(start); elapsed < 1400*time.Millisecond {
		t.Fatalf("waitDNSBack returned after %s on SERVFAIL, want the full deadline", elapsed.Round(time.Millisecond))
	}
}

func TestWaitDNSBackSkipsWithoutKeychain(t *testing.T) {
	home := t.TempDir()
	t.Setenv("FREENS_HOME", home)
	// No keys, and NO stub at all: the gate must return instantly without
	// dialing anything.
	done := make(chan struct{})
	go func() {
		waitDNSBack(5 * time.Second)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("waitDNSBack hung with an empty keychain")
	}
}
