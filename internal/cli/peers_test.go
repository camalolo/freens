package cli

// peers_test.go — the CLI half of the web UI's read surfaces (found
// missing 2026-09-02: the webui Network/Keys/Store pages had no `freens`
// verb behind them). The renderer shares dht.DisplayAddrs with the webui
// peers table, so public-first ordering is pinned once, tested twice.

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/home"
)

func TestCmdPeersOrdersPublicFirstAndMarksState(t *testing.T) {
	h := tempHome(t)
	s := startStubAdmin(t, h+"/admin.sock", nil)
	s.statusJSON = `{"running":true,"peers":2,"confirmed_peers":2}`
	s.peersJSON = `{"peers":[
		{"addr":"192.168.1.16:15454","pk":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899","confirmed":` + now2() + `,
		 "alts":[{"addr":"220.132.135.54:15454"},{"addr":"192.168.1.1:15454"},{"addr":"<nil>:15353"}]},
		{"addr":"220.132.135.54:15353","pk":"11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff","confirmed":0}
	]}`

	out, err := captureStdout(t, func() error { return cmdPeers(nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "peers: 2") {
		t.Errorf("missing the count header:\n%s", out)
	}
	// Public-first display ordering on the multi-homed row.
	if i := strings.Index(out, "220.132.135.54:15454"); i == -1 {
		t.Errorf("the public address is missing:\n%s", out)
	} else if j := strings.Index(out, "192.168.1.16:15454"); j != -1 && j < i {
		t.Errorf("the LAN address renders before the public one:\n%s", out)
	}
	if strings.Contains(out, "<nil>") {
		t.Errorf("the <nil> artifact must be dropped:\n%s", out)
	}
	if !strings.Contains(out, "advertised (never confirmed directly)") {
		t.Errorf("the unconfirmed peer must be marked advertised:\n%s", out)
	}
	if !strings.Contains(out, "confirmed ·") {
		t.Errorf("the confirmed peer must show its recency:\n%s", out)
	}
	if !strings.Contains(out, "node aabbccddeeff…") {
		t.Errorf("the node-id prefix is missing:\n%s", out)
	}
	// The confirmed-at address is named (the friend-box lesson: "confirmed"
	// on an ephemeral one-shot port must say which port carried it), and
	// the never-confirmed alternates are listed with same-host ports short.
	if !strings.Contains(out, "(at 192.168.1.16:15454)") {
		t.Errorf("the confirmation address is missing:\n%s", out)
	}
	if !strings.Contains(out, "never confirmed: 220.132.135.54:15454 192.168.1.1:15454") {
		t.Errorf("the never-confirmed alternates are missing:\n%s", out)
	}
	_ = s
}

// TestCmdPeersConfirmedAtEphemeralPort: the live fleet shape that prompted
// the rendering — a confirmed contact whose confirmation rode an ephemeral
// one-shot port (:1908) while the real daemon (:15353) never answered.
func TestCmdPeersConfirmedAtEphemeralPort(t *testing.T) {
	h := tempHome(t)
	s := startStubAdmin(t, h+"/admin.sock", nil)
	pk := "40b1a48208d40000000000000000000000000000000000000000000000000000"
	s.peersJSON = `{"peers":[{"addr":"61.224.174.153:1908","pk":"` + pk + `","confirmed":` + now2() + `,
		 "alts":[{"addr":"61.224.174.153:15353"},{"addr":"61.224.174.153:1025"}]}]}`

	out, err := captureStdout(t, func() error { return cmdPeers(nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "confirmed · 0m ago (at 61.224.174.153:1908)") {
		t.Errorf("the ephemeral confirmation address must be named:\n%s", out)
	}
	if !strings.Contains(out, "never confirmed: :15353 :1025") {
		t.Errorf("same-host never-confirmed addrs must render as :port:\n%s", out)
	}
	_ = s
}

func TestCmdPeersJSON(t *testing.T) {
	h := tempHome(t)
	s := startStubAdmin(t, h+"/admin.sock", nil)
	s.peersJSON = `{"peers":[{"addr":"220.132.135.54:15353","pk":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899","confirmed":0}]}`

	out, err := captureStdout(t, func() error { return cmdPeers([]string{"-json"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"addr": "220.132.135.54:15353"`) || !strings.Contains(out, `"node_pk": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"`) {
		t.Errorf("unexpected JSON output:\n%s", out)
	}
}

func TestCmdKeysListsInventory(t *testing.T) {
	tempHome(t)
	if err := writeKeyFile(filepath.Join(home.KeysDir(), "camalolo.key"), mustTestKeypair(t)); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error { return cmdKeys(nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "camalolo.key") || !strings.Contains(out, "owner") {
		t.Errorf("keychain inventory missing the owner key:\n%s", out)
	}
}

func TestCmdStoreListsEnvelopes(t *testing.T) {
	h := tempHome(t)
	s := startStubAdmin(t, h+"/admin.sock", nil)
	exp := time.Now().Add(-time.Hour).Unix() // lapsed
	s.storeJSON = `{"count":1,"entries":[{"key":"9393b3bb98e7","alias":"camalolo","labels":[],
		"sequence":22,"created":1,"expires":` + strconv.FormatInt(exp, 10) + `,"revoked":false,
		"owner":"aa","claim":true,"claim_key":true,"bytes":1647}]}`

	out, err := captureStdout(t, func() error { return cmdStore(nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "camalolo") || !strings.Contains(out, "lapsed") || !strings.Contains(out, "K_claim") {
		t.Errorf("store listing incomplete:\n%s", out)
	}
}

// now2 is the unix-time literal for a "just confirmed" peer.
func now2() string { return strconv.FormatInt(time.Now().Unix(), 10) }
