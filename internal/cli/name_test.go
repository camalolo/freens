// name_test.go — the easy-button sub-name verb against a stub admin socket
// (publish accepted): `name www.alice` builds a seq+1 record owned by the
// keychain key, inheriting the apex A unless -ip overrides.
package cli

import (
	"bytes"
	"encoding/base64"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/naming"
)

func TestNameViaStubAdmin(t *testing.T) {
	h := tempHome(t)
	kp := mustTestKeypair(t)
	if err := home.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := writeKeyFile(ownerKeyPath("alice"), kp); err != nil {
		t.Fatal(err)
	}
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}

	// Stub state: www.alice already at sequence 3; apex alice -> 203.0.113.9.
	// The sequence now comes from /get by key (tombstone-aware discovery),
	// so the stub carries a real envelope under www.alice's key.
	stub := startStubAdmin(t, filepath.Join(h, "admin.sock"), map[string]string{
		"www.alice": resolvedJSON("www.alice", 3, ""),
		"alice":     resolvedJSON("alice", 2, "203.0.113.9"),
	})
	wwwWire, err := naming.EncodeWireName([]string{"www"}, "alice", tldID)
	if err != nil {
		t.Fatal(err)
	}
	wwwKey, err := dht.KeyForWireName(wwwWire)
	if err != nil {
		t.Fatal(err)
	}
	wwwEnv := mustTestEnvelope(t, kp, wwwWire, 3)
	stub.getKey, stub.getEnv = wwwKey, wwwEnv

	out, err := captureStdout(t, func() error { return cmdName([]string{"www.alice"}) })
	if err != nil {
		t.Fatalf("name: %v\n%s", err, out)
	}

	// Exactly one publish, and it is the envelope we expect.
	if len(stub.published) != 1 {
		t.Fatalf("published %d envelopes, want 1", len(stub.published))
	}
	env := stub.published[0]
	rec := env.Record
	if !bytes.Equal(rec.Owner, kp.Public()) {
		t.Errorf("owner = %x, want the keychain key %x", rec.Owner, kp.Public())
	}
	if rec.Sequence != 4 {
		t.Errorf("sequence = %d, want current(3)+1 = 4", rec.Sequence)
	}
	// The A record inherits the apex's 203.0.113.9.
	if len(rec.RRset) != 1 || rec.RRset[0].Type != 1 || !bytes.Equal(rec.RRset[0].Rdata, []byte{203, 0, 113, 9}) {
		t.Errorf("RRset = %+v, want one A record 203.0.113.9", rec.RRset)
	}
	// Wire name: label www under alice's tld.
	labels, gotTLD, err := naming.DecodeWireName(rec.Name)
	if err != nil || len(labels) != 1 || labels[0] != "www" || !bytes.Equal(gotTLD, tldID) {
		t.Errorf("wire name decodes to labels=%v tld=%x (err %v), want [www] %x", labels, gotTLD, err, tldID)
	}
	if !env.VerifySignature() {
		t.Error("published envelope signature invalid")
	}
	for _, want := range []string{"ip=203.0.113.9", "sequence=4", "PUBLISHED. www.alice -> 203.0.113.9"} {
		if !strings.Contains(out, want) {
			t.Errorf("name output missing %q:\n%s", want, out)
		}
	}

	// -ip overrides the apex inheritance; a new name starts at sequence 1
	// (the /get stub is emptied so the key answers 404).
	stub.published = nil
	delete(stub.resolve, "www.alice") // fresh name now
	stub.getKey, stub.getEnv = nil, nil
	out, err = captureStdout(t, func() error { return cmdName([]string{"-ip", "198.51.100.7", "www.alice"}) })
	if err != nil {
		t.Fatalf("name -ip: %v\n%s", err, out)
	}
	if len(stub.published) != 1 {
		t.Fatalf("published %d envelopes, want 1", len(stub.published))
	}
	env2 := stub.published[0]
	if env2.Record.Sequence != 1 {
		t.Errorf("fresh name sequence = %d, want 1", env2.Record.Sequence)
	}
	if !bytes.Equal(env2.Record.RRset[0].Rdata, []byte{198, 51, 100, 7}) {
		t.Errorf("RRset rdata = %v, want 198.51.100.7", env2.Record.RRset[0].Rdata)
	}
}

func TestNameMissingOwnerKeyListsAliases(t *testing.T) {
	tempHome(t)
	if err := home.Ensure(); err != nil {
		t.Fatal(err)
	}
	// bob HAS a key; alice does not.
	if err := writeKeyFile(ownerKeyPath("bob"), mustTestKeypair(t)); err != nil {
		t.Fatal(err)
	}
	_, err := captureStdout(t, func() error { return cmdName([]string{"www.alice"}) })
	if err == nil {
		t.Fatal("name without an owner key must fail")
	}
	if !strings.Contains(err.Error(), "bob") || !strings.Contains(err.Error(), "alice") {
		t.Errorf("error should name the missing alias and the available ones: %v", err)
	}
}

func TestNameNoIPAndNoApexA(t *testing.T) {
	h := tempHome(t)
	if err := home.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := writeKeyFile(ownerKeyPath("alice"), mustTestKeypair(t)); err != nil {
		t.Fatal(err)
	}
	// Apex resolves but carries no A record to inherit.
	startStubAdmin(t, filepath.Join(h, "admin.sock"), map[string]string{
		"alice": resolvedJSON("alice", 2, ""),
	})
	_, err := captureStdout(t, func() error { return cmdName([]string{"www.alice"}) })
	if err == nil || !strings.Contains(err.Error(), ("-ip")) {
		t.Errorf("no ip + no apex A verdict = %v, want the -ip guidance", err)
	}
}

func TestNameApexRejected(t *testing.T) {
	tempHome(t)
	_, err := captureStdout(t, func() error { return cmdName([]string{"alice"}) })
	if err == nil || !strings.Contains(err.Error(), "apex") {
		t.Errorf("bare-alias name verdict = %v, want the apex guidance", err)
	}
}

// TestFirstAdminAIP: the apex-IP inheritance helper picks the first A
// record out of an admin RRset — via the daemon's dotted-quad Text
// rendering, or the base64 rdata when Text is absent.
func TestFirstAdminAIP(t *testing.T) {
	aB64 := func(ip string) string {
		return base64.StdEncoding.EncodeToString(net.ParseIP(ip).To4())
	}
	rrs := []adminRR{
		{Type: 16, TTL: 300, Rdata: base64.StdEncoding.EncodeToString([]byte("hello")), Text: `"hello"`}, // TXT: skipped
		{Type: 1, TTL: 300, Rdata: aB64("203.0.113.9")},                                                  // no Text: rdata path
		{Type: 1, TTL: 300, Rdata: aB64("192.0.2.1"), Text: "192.0.2.1"},
	}
	if got := firstAdminAIP(rrs); got != "203.0.113.9" {
		t.Errorf("firstAdminAIP = %q, want 203.0.113.9", got)
	}
	// Text rendering wins when present.
	if got := firstAdminAIP([]adminRR{{Type: 1, Rdata: aB64("198.51.100.5"), Text: "198.51.100.5"}}); got != "198.51.100.5" {
		t.Errorf("firstAdminAIP(Text) = %q, want 198.51.100.5", got)
	}
	if got := firstAdminAIP(nil); got != "" {
		t.Errorf("firstAdminAIP(nil) = %q, want empty", got)
	}
}
