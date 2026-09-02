// peer_order_test.go — the peers table's display ordering (2026-09-02):
// multi-homed contacts list up to 4 addresses per node, and the operator
// asked for public addresses FIRST with LAN addresses after. The renderer
// also drops addresses that are not IP literals — pre-2026-09-02 peers
// exchanged the hostname-shaped seed contact as empty {nodes} ip bytes,
// which receivers learned as the literal "<nil>:15353" (the dht half of
// that fix lives in internal/dht encodeNodes/parseNodes).
package webui

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/dht"
)

// orderPeersDaemon serves one multi-homed peer with mixed public/LAN/garbage
// addresses (the live fleet shape) to the network page and its fragment.
type orderPeersDaemon struct{ fakeDaemon }

func (d *orderPeersDaemon) Peers(ctx context.Context) ([]dht.Peer, error) {
	pk := sha512.Sum512_256([]byte("order-peers-peer"))
	return []dht.Peer{{
		Addr:      "192.168.1.16:15454",
		PublicKey: pk[:],
		Confirmed: time.Now().Unix() - 60,
		Alts: []dht.AddrState{
			{Addr: "220.132.135.54:1026"},
			{Addr: "220.132.135.54:15454"},
			{Addr: "192.168.1.1:15454"},
			{Addr: "<nil>:15353"},
		},
	}}, nil
}

// orderPeer builds a Peer with a deterministic 32-byte key from the addr.
func orderPeer(addr string, confirmed int64, alts ...dht.AddrState) dht.Peer {
	pk := sha256.Sum256([]byte(addr))
	return dht.Peer{Addr: addr, PublicKey: pk[:], Confirmed: confirmed, Alts: alts}
}

// TestPeerRowsPublicFirstLANNext: a LAN-preferred peer still lists its
// public addresses first; the "<nil>:port" artifact is dropped; stored
// order is kept inside each class.
func TestPeerRowsPublicFirstLANNext(t *testing.T) {
	now := time.Now().Unix()
	peers := []dht.Peer{
		// The exact shape reported live on the fleet (2026-09-02): a
		// LAN-preferred contact with public alts, a router hairpin addr
		// and the <nil> artifact from the hostname-seed {nodes} bug.
		orderPeer("192.168.1.16:15454", now, dht.AddrState{Addr: "220.132.135.54:1026"},
			dht.AddrState{Addr: "220.132.135.54:15454"},
			dht.AddrState{Addr: "192.168.1.1:15454"},
			dht.AddrState{Addr: "<nil>:15353"}),
		// A public-preferred peer with mixed alts.
		orderPeer("220.132.135.54:15353", now, dht.AddrState{Addr: "220.132.135.54:1024"},
			dht.AddrState{Addr: "192.168.1.16:15353"},
			dht.AddrState{Addr: "<nil>:15353"}),
	}
	_, rows := peerRows(peers, now)
	if len(rows) != 2 {
		t.Fatalf("peerRows returned %d rows, want 2", len(rows))
	}

	first := append([]string{rows[0].Addr}, rows[0].AltAddrs...)
	wantFirst := []string{
		"220.132.135.54:1026", // public (stored Alts order kept inside the class)
		"220.132.135.54:15454",
		"192.168.1.16:15454", // LAN
		"192.168.1.1:15454",
	}
	if len(first) != len(wantFirst) {
		t.Fatalf("row 0 lists %v, want %v (<nil> must be dropped)", first, wantFirst)
	}
	for i := range wantFirst {
		if first[i] != wantFirst[i] {
			t.Fatalf("row 0 order = %v, want %v", first, wantFirst)
		}
	}

	second := append([]string{rows[1].Addr}, rows[1].AltAddrs...)
	wantSecond := []string{
		"220.132.135.54:15353", // public preferred stays first
		"220.132.135.54:1024",
		"192.168.1.16:15353",
	}
	for i := range wantSecond {
		if second[i] != wantSecond[i] {
			t.Fatalf("row 1 order = %v, want %v", second, wantSecond)
		}
	}
}

// TestPeerRowsKeepsRawAddrWhenNothingParses: a pathological all-garbage
// contact still renders its stored addr (never an empty cell).
func TestPeerRowsKeepsRawAddrWhenNothingParses(t *testing.T) {
	_, rows := peerRows([]dht.Peer{orderPeer("seed.example.net:15353", 0)}, time.Now().Unix())
	if rows[0].Addr != "seed.example.net:15353" || len(rows[0].AltAddrs) != 0 {
		t.Fatalf("row = %+v, want the raw hostname addr kept", rows[0])
	}
}

// TestNetworkPageRendersOrderedAddrs: end to end through the template —
// the public addr is the row's first line, the <nil> artifact never shows.
func TestNetworkPageRendersOrderedAddrs(t *testing.T) {
	d := &orderPeersDaemon{fakeDaemon: *newFakeDaemon()}
	_, ts := newTestServer(t, d)
	c := newUClient(t)
	c.bootstrap(ts.URL)

	resp, err := c.http.Get(ts.URL + "/api/network/peers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/network/peers status = %d", resp.StatusCode)
	}
	s := string(body)
	if strings.Contains(s, "&lt;nil&gt;") || strings.Contains(s, "<nil>") {
		t.Errorf("peers table renders the <nil> artifact:\n%s", s)
	}
	head := "220.132.135.54:15454"
	iHead := strings.Index(s, head)
	iLAN := strings.Index(s, "192.168.1.16:15454")
	if iHead == -1 || iLAN == -1 {
		t.Fatalf("peers table missing expected addrs:\n%s", s)
	}
	if iHead > iLAN {
		t.Errorf("public addr renders after the LAN addr:\n%s", s)
	}
}
