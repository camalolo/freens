// peers_confirmed_test.go — the webui half of the confirmed-peers
// regression: a daemon peer confirmed a minute ago renders as
// "confirmed · Xm ago" on the Network page, never as "never"/"advertised"
// (the admin client used to drop the confirmed field entirely).
package webui

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
)

// confirmedPeersDaemon overrides Peers with a just-confirmed peer.
type confirmedPeersDaemon struct{ fakeDaemon }

func (d *confirmedPeersDaemon) Peers(ctx context.Context) ([]dht.Peer, error) {
	kp, err := crypto.Generate()
	if err != nil {
		return nil, err
	}
	return []dht.Peer{{Addr: "10.0.0.2:15353", PublicKey: kp.Public(), Confirmed: time.Now().Unix() - 60}}, nil
}

func TestNetworkPageShowsConfirmedBadge(t *testing.T) {
	_, ts := newTestServer(t, &confirmedPeersDaemon{fakeDaemon: *newFakeDaemon()})
	c := newUClient(t)
	c.bootstrap(ts.URL)

	resp, err := c.http.Get(ts.URL + "/network")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/network status = %d", resp.StatusCode)
	}
	if strings.Contains(string(body), "never") {
		t.Errorf("network page shows 'never' for a confirmed peer:\n%s", body)
	}
	if !strings.Contains(string(body), "m ago") {
		t.Errorf("network page missing the minutes-ago text:\n%s", body)
	}
	if strings.Count(string(body), "advertised") > 1 {
		// One occurrence is the badge's else-branch inside the template;
		// a rendered row must not carry it.
		t.Errorf("network page rendered the 'advertised' badge for a confirmed peer")
	}
}

// TestDashChecksFragmentWarming: while the daemon warms up (peers loaded,
// none confirmed) the health card says "warming up" instead of ✗.
func TestDashChecksFragmentWarming(t *testing.T) {
	_, ts := newTestServer(t, &warmingDaemon{fakeDaemon: *newFakeDaemon()})
	c := newUClient(t)
	c.bootstrap(ts.URL)

	resp, err := c.http.Get(ts.URL + "/api/dash/checks")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/dash/checks status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "warming up") {
		t.Errorf("checks fragment missing the warming state:\n%s", body)
	}
	if strings.Contains(string(body), "✗ resolver answers") {
		t.Errorf("checks fragment shows the broken ✗ during warm-up:\n%s", body)
	}
}

// warmingDaemon: peers known, none confirmed.
type warmingDaemon struct{ fakeDaemon }

func (d *warmingDaemon) Status(ctx context.Context) (*admin.Status, error) {
	st, err := d.fakeDaemon.Status(ctx)
	if err != nil {
		return nil, err
	}
	st.Peers = 7
	st.ConfirmedPeers = 0
	return st, nil
}

func (d *warmingDaemon) Peers(ctx context.Context) ([]dht.Peer, error) {
	kp, err := crypto.Generate()
	if err != nil {
		return nil, err
	}
	return []dht.Peer{{Addr: "10.0.0.9:15353", PublicKey: kp.Public()}}, nil
}
