package cli

// health_network_test.go — doctor's stale-lease check (4b): the owner-local
// alias resolution can be green while the network lost the lease (the
// 2026-09-02 camalolo incident). The network view ({"network": true})
// must turn that into a visible FAILED check with the `renew -force` hint,
// stay quiet on a live lease, and mark degraded walks inconclusive.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/home"
)

// doctorNetHome builds a temp home with one alias keyfile and a stub admin
// server whose /status reports confirmed peers (not warming) and whose
// /resolve answers with the given canned body.
func doctorNetHome(t *testing.T, resolveBody string) {
	t.Helper()
	h := tempHome(t)
	stubSysForTest(t)
	if err := os.MkdirAll(home.KeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home.KeysDir(), "camalolo.key"),
		[]byte("deadbeef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := startStubAdmin(t, filepath.Join(h, "admin.sock"), map[string]string{
		"camalolo": resolveBody,
	})
	// Not warming: the network check only runs once contacts confirmed.
	s.statusJSON = `{"running":true,"version":"stub-1","node_id":"aa","node_pk":"bb",` +
		`"dht_listen":"0.0.0.0:15353","advertise":"","peers":3,"confirmed_peers":3,` +
		`"store_envs":1,"history_envs":0,"relay_mode":false,"turn_allocs":0,"network_claims":true}`
}

func TestDoctorNetworkViewStaleLeaseFails(t *testing.T) {
	doctorNetHome(t, fmt.Sprintf(
		`{"found":true,"name":"camalolo","sequence":5,"network":{"record_found":true,"record_sequence":5,"claim_found":false}}`))
	out, _ := captureStdout(t, func() error { return cmdDoctor(nil) })
	if !strings.Contains(out, "renew -force camalolo") {
		t.Errorf("stale lease must fail the check with the renew hint:\n%s", out)
	}
	if !strings.Contains(out, "✘ alias camalolo holds a LIVE network lease") {
		t.Errorf("stale lease must render as a failed check:\n%s", out)
	}
}

func TestDoctorNetworkViewLiveLeasePasses(t *testing.T) {
	exp := time.Now().Add(20 * time.Hour).Unix()
	doctorNetHome(t, fmt.Sprintf(
		`{"found":true,"name":"camalolo","sequence":5,"network":{"record_found":true,"record_sequence":5,"claim_found":true,"claim_sequence":5,"claim_expires":%d}}`, exp))
	out, _ := captureStdout(t, func() error { return cmdDoctor(nil) })
	if !strings.Contains(out, "network lease live") {
		t.Errorf("a live network lease must pass:\n%s", out)
	}
	if strings.Contains(out, "renew -force") {
		t.Errorf("a live network lease must not suggest renewing:\n%s", out)
	}
}

func TestDoctorNetworkViewDegradedInconclusive(t *testing.T) {
	doctorNetHome(t, `{"found":true,"name":"camalolo","sequence":5,"network":{"degraded":true}}`)
	out, _ := captureStdout(t, func() error { return cmdDoctor(nil) })
	if !strings.Contains(out, "inconclusive") {
		t.Errorf("a degraded walk must be reported inconclusive (not failed):\n%s", out)
	}
	if strings.Contains(out, "✗ alias camalolo holds") {
		t.Errorf("a degraded walk must not fail the lease check:\n%s", out)
	}
}
