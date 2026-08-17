package admin

// admin_test.go exercises the control socket end-to-end over a REAL unix
// socket in t.TempDir(), backed by REAL in-process DHT nodes (loopback UDP,
// ephemeral ports — the internal/dht transport_test.go startTestNode
// pattern, rebuilt here because test helpers are not importable across
// packages).
//
// Coverage, per the package contract:
//
//  1. Status round-trip (peers ≥ 1 after a ping, version echoed).
//  2. Publish + Get round-trip (a TLD record via the misc_test.go
//     makeTLDRecord fixture pattern).
//  3. Resolve: a register-style claim envelope, then the apex alias via the
//     K_claim path and "www.<alias>" via the wire-name path (both found).
//  4. Witness: a two-node net returns ≥ 1 §7.3-verifiable attestation.
//  5. Alive/Close semantics: Close removes the socket; Alive flips; Close is
//     idempotent; ListenAndServe returns.
//  6. Malformed JSON / bad base64 / bad hex → 4xx, never a panic.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
	"github.com/fxamacker/cbor/v2"
)

// ---------------------------------------------------------------------------
// Fixtures (internal/dht test patterns, rebuilt for package admin)
// ---------------------------------------------------------------------------

// startDHTNode starts a node on an ephemeral loopback port (the
// transport_test.go startTestNode pattern); t.Cleanup closes it.
func startDHTNode(t *testing.T) *dht.Node {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("gen keypair: %v", err)
	}
	n, err := dht.NewNode(dht.NodeConfig{
		Keypair:    kp,
		ListenAddr: "127.0.0.1:0",
		Store:      dht.NewEnvelopeStore(0, nil),
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = n.Close() })
	return n
}

// connectPeers cross-seeds two nodes' routing tables and verifies the link
// with a signed ping (the peerPair pattern). After it returns, both tables
// hold the other node.
func connectPeers(t *testing.T, a, b *dht.Node) {
	t.Helper()
	aAddr, err := a.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(a.PublicKey(), aAddr.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.Ping(ctx, dht.Peer{Addr: bAddr.String(), PublicKey: b.PublicKey()}); err != nil {
		t.Fatalf("ping a→b: %v", err)
	}
}

// startAdmin serves srv on a fresh unix socket in t.TempDir() and blocks
// until it answers. Returns the socket path.
func startAdmin(t *testing.T, srv *Server) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "admin.sock")
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(sock) }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("ListenAndServe did not return after Close")
		}
	})
	waitAlive(t, sock, done)
	return sock
}

// waitAlive polls the socket until it answers (or the server exits early).
func waitAlive(t *testing.T, sock string, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if Alive(sock) {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("ListenAndServe exited early: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("admin socket never came up")
}

// adminPair is the standard two-node fixture: node a (admin-served, with its
// lookup adapter over a fresh store) and node b (a's only peer, hence the
// closest node to every key), plus a ready Client on a's socket.
func adminPair(t *testing.T, version string) (*dht.Node, *dht.Node, *dht.DHTLookup, *Client) {
	t.Helper()
	a := startDHTNode(t)
	b := startDHTNode(t)
	connectPeers(t, a, b)
	lookup := dht.NewDHTLookup(dht.NewEnvelopeStore(0, nil), a)
	sock := startAdmin(t, New(a, lookup, version, slog.Default()))
	return a, b, lookup, &Client{Sock: sock, Timeout: 10 * time.Second}
}

// makeTLDRecord builds a self-signed TLD-root envelope for alias owned by kp
// (the misc_test.go / transport_test.go fixture pattern), returning the
// envelope and its K_tld storage key.
func makeTLDRecord(t *testing.T, kp *crypto.Keypair, alias string) (*wire.SignedEnvelope, []byte) {
	t.Helper()
	tid, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, alias, tid)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	rec, err := wire.NewRecord(wn, kp.Public(), 1, uint64(now), uint64(now+3600))
	if err != nil {
		t.Fatal(err)
	}
	rr, err := wire.A([]byte{203, 0, 113, 99}, 300)
	if err != nil {
		t.Fatal(err)
	}
	rec.RRset = []*wire.RR{rr}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	key, err := dht.KeyForWireName(wn)
	if err != nil {
		t.Fatal(err)
	}
	return env, key
}

// makeClaimTLDRecord builds a register-style TLD record: an AliasClaim mined
// for (alias, kp) embedded in field 11, carried by the TLD-root envelope
// (§7.4/C.1: the SAME envelope lives at K_tld and K_claim). Difficulty is
// lowered to keep the test fast; nothing on the publish/resolve path checks
// PoW (the store checks envelope signatures; the witness RPC checks the
// prefix-hash binding — both by design).
func makeClaimTLDRecord(t *testing.T, kp *crypto.Keypair, alias string) (*wire.SignedEnvelope, *claims.AliasClaim, []byte) {
	t.Helper()
	// v0.7.0: the hPut K_claim screen runs the full §7.4 filter, so the
	// fixture claim needs its W-witness quorum (in-band v2 attestations)
	// and the fast-difficulty floor to survive publication at K_claim.
	prevD := claims.PoWDifficultyInit
	claims.PoWDifficultyInit = 8
	t.Cleanup(func() { claims.PoWDifficultyInit = prevD })
	claim, err := claims.MineAliasClaim(alias, kp, uint64(time.Now().Unix()), 8, 1<<20, 12)
	if err != nil {
		t.Fatalf("mine claim: %v", err)
	}
	if !claim.VerifyPoW(8) {
		t.Fatal("mined claim does not verify at its own difficulty (fixture sanity)")
	}
	tid, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	ph, err := claim.PrefixHash()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < constants.W; i++ {
		wkp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		w, err := claims.NewWitnessAttestation(wkp, claim.Timestamp+uint64(i), ph)
		if err != nil {
			t.Fatalf("NewWitnessAttestation: %v", err)
		}
		claim.Witnesses = append(claim.Witnesses, w)
	}
	_ = tid
	env, key := makeTLDRecord(t, kp, alias)
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	env.Record.Claim = cbor.RawMessage(cb)
	// The record bytes changed (field 11 added): re-sign over them.
	env, err = wire.SignRecord(env.Record, kp)
	if err != nil {
		t.Fatal(err)
	}
	return env, claim, key
}

// unixHTTP builds a raw HTTP client over the admin socket for status-code
// level assertions the typed Client cannot express.
func unixHTTP(sock string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
			DisableKeepAlives: true,
		},
	}
}

// post sends a raw JSON body and returns (status, body).
func post(t *testing.T, sock, path, body string) (int, string) {
	t.Helper()
	resp, err := unixHTTP(sock).Post("http://admin"+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// ---------------------------------------------------------------------------
// 1. Status round-trip
// ---------------------------------------------------------------------------

// TestStatusRoundTrip: /status reflects the served node — version echoed,
// hex identity fields matching node.ID()/PublicKey(), a non-empty DHT listen
// address, and ≥ 1 peers after the fixture ping. With no node, /status
// still answers (running daemon, zeroed node fields).
func TestStatusRoundTrip(t *testing.T) {
	a, _, _, c := adminPair(t, "test-v1.2.3")

	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Running || st.Version != "test-v1.2.3" {
		t.Errorf("running/version = %v/%q, want true/test-v1.2.3", st.Running, st.Version)
	}
	if st.NodeID != hex.EncodeToString(a.ID()) {
		t.Errorf("node_id = %s, want %s", st.NodeID, hex.EncodeToString(a.ID()))
	}
	if st.NodePK != hex.EncodeToString(a.PublicKey()) {
		t.Errorf("node_pk = %s, want the node public key", st.NodePK)
	}
	if st.DHTListen == "" {
		t.Error("dht_listen is empty for a started node")
	}
	if st.Peers < 1 {
		t.Errorf("peers = %d, want ≥ 1 after the fixture ping", st.Peers)
	}
	if !st.NetworkClaims {
		t.Error("network_claims = false for a running node")
	}
	if st.Advertise != "" {
		t.Errorf("advertise = %q, want \"\" in observed-source mode", st.Advertise)
	}

	// A node configured with an explicit §6.2 advertised address echoes it.
	advKp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	advNode, err := dht.NewNode(dht.NodeConfig{
		Keypair:    advKp,
		ListenAddr: "127.0.0.1:0",
		Store:      dht.NewEnvelopeStore(0, nil),
		Advertise:  "127.0.0.1:15353",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := advNode.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = advNode.Close() })
	advSock := startAdmin(t, New(advNode, nil, "v-adv", slog.Default()))
	advSt, err := (&Client{Sock: advSock}).Status(context.Background())
	if err != nil {
		t.Fatalf("Status(advertised node): %v", err)
	}
	if advSt.Advertise != "127.0.0.1:15353" {
		t.Errorf("advertise = %q, want the configured 127.0.0.1:15353", advSt.Advertise)
	}
}

// TestStatusWithoutNode: a node-less daemon (resolver-only) answers /status
// with Running=true and no node identity, and every network endpoint
// returns 503 {"error":"no dht node"}.
func TestStatusWithoutNode(t *testing.T) {
	sock := startAdmin(t, New(nil, nil, "v-noNode", slog.Default()))

	st, err := (&Client{Sock: sock}).Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Running || st.Version != "v-noNode" {
		t.Errorf("running/version = %v/%q", st.Running, st.Version)
	}
	if st.NodeID != "" || st.Peers != 0 || st.NetworkClaims {
		t.Errorf("node-less status leaked node fields: %+v", st)
	}

	// Every network endpoint: 503 + the pinned error body.
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/publish", `{"envelope":""}`},
		{"POST", "/get", `{"key":"00"}`},
		{"POST", "/resolve", `{"name":"foo"}`},
		{"POST", "/witness", `{"alias":"foo"}`},
		{"GET", "/peers", ""},
	} {
		var code int
		var respBody string
		if tc.method == "GET" {
			r, err := unixHTTP(sock).Get("http://admin" + tc.path)
			if err != nil {
				t.Fatalf("%s %s: %v", tc.method, tc.path, err)
			}
			b, _ := io.ReadAll(r.Body)
			r.Body.Close()
			code, respBody = r.StatusCode, string(b)
		} else {
			code, respBody = post(t, sock, tc.path, tc.body)
		}
		if code != http.StatusServiceUnavailable {
			t.Errorf("%s %s: status = %d, want 503", tc.method, tc.path, code)
		}
		if !strings.Contains(respBody, "no dht node") {
			t.Errorf("%s %s: body = %q, want the no-dht-node error", tc.method, tc.path, respBody)
		}
	}
}

// ---------------------------------------------------------------------------
// 2. Publish + Get round-trip
// ---------------------------------------------------------------------------

// TestPublishGetRoundTrip: a TLD record published through the daemon's node
// is accepted by its peer and fetchable back through the daemon by storage
// key; a random key misses with (nil, nil), not an error.
func TestPublishGetRoundTrip(t *testing.T) {
	_, _, _, c := adminPair(t, "v-pg")

	owner, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	env, key := makeTLDRecord(t, owner, "pgtest")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	accepted, err := c.Publish(ctx, env)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if accepted != 1 {
		t.Errorf("accepted = %d, want 1 (no claim on this record)", accepted)
	}

	got, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil for a just-published record")
	}
	gh, _ := got.RecordHash()
	eh, _ := env.RecordHash()
	if !bytes.Equal(gh, eh) {
		t.Error("Get returned a different envelope than was published")
	}

	// A key nothing is stored under: (nil, nil).
	miss := make([]byte, 32)
	for i := range miss {
		miss[i] = byte(i)
	}
	got, err = c.Get(ctx, miss)
	if err != nil || got != nil {
		t.Errorf("Get(unknown) = (%v, %v), want (nil, nil)", got, err)
	}
}

// ---------------------------------------------------------------------------
// 3. Resolve (claim path + wire-name path)
// ---------------------------------------------------------------------------

// TestResolveClaimAndName: a register-style publication (claim-carrying TLD
// record, auto-published at K_tld AND K_claim by /publish), then:
//
//   - resolving the bare alias walks the K_claim path (alias → AliasClaim
//     → tld_id → K_tld) and finds the TLD record;
//   - resolving "www.<alias>" resolves through K_name and finds the www
//     record with its A record rendered as a dotted quad;
//   - resolving via an explicit tld_id_b32 pin skips the claim hop;
//   - an unpublished alias reports Found=false, not an error.
func TestResolveClaimAndName(t *testing.T) {
	_, _, _, c := adminPair(t, "v-res")

	owner, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tid, err := crypto.TldID(owner.Public())
	if err != nil {
		t.Fatal(err)
	}

	// The register-style TLD record: mined claim in field 11.
	tldEnv, claim, tldKey := makeClaimTLDRecord(t, owner, "apex")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if accepted, err := c.Publish(ctx, tldEnv); err != nil || accepted != 2 {
		t.Fatalf("Publish(claim record): accepted=%d err=%v, want 2 (K_tld + K_claim)", accepted, err)
	}

	// A www name record under the same TLD, published the ordinary way.
	wwwWire, err := naming.EncodeWireName([]string{"www"}, "apex", tid)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	wwwRec, err := wire.NewRecord(wwwWire, owner.Public(), 1, uint64(now), uint64(now+3600))
	if err != nil {
		t.Fatal(err)
	}
	aRR, err := wire.A([]byte{198, 51, 100, 7}, 300)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec.RRset = []*wire.RR{aRR}
	wwwEnv, err := wire.SignRecord(wwwRec, owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Publish(ctx, wwwEnv); err != nil {
		t.Fatalf("Publish(www): %v", err)
	}

	// (a) Bare alias via the K_claim path.
	res, err := c.Resolve(ctx, "apex")
	if err != nil {
		t.Fatalf("Resolve(apex): %v", err)
	}
	if !res.Found {
		t.Fatal("Resolve(apex).Found = false, want the claim-carrying TLD record")
	}
	if res.Owner != hex.EncodeToString(owner.Public()) {
		t.Errorf("owner = %s, want the TLD owner", res.Owner)
	}
	if res.TldIDB32 != encodeTldIDB32(claim.TldID) || res.TldIDB32 != encodeTldIDB32(tid) {
		t.Errorf("tld_id_b32 = %s, want %s", res.TldIDB32, encodeTldIDB32(tid))
	}
	if res.Sequence != 1 {
		t.Errorf("sequence = %d, want 1", res.Sequence)
	}

	// (b) "www.apex" via the wire-name path (K_name).
	res, err = c.Resolve(ctx, "www.apex")
	if err != nil {
		t.Fatalf("Resolve(www.apex): %v", err)
	}
	if !res.Found {
		t.Fatal("Resolve(www.apex).Found = false")
	}
	if res.Name != "www.apex" {
		t.Errorf("name = %q, want www.apex", res.Name)
	}
	if len(res.RRset) != 1 || res.RRset[0].Type != wire.RRTypeA {
		t.Fatalf("rrset = %+v, want one A record", res.RRset)
	}
	if res.RRset[0].Text != "198.51.100.7" {
		t.Errorf("rdata_text = %q, want 198.51.100.7", res.RRset[0].Text)
	}
	if res.RRset[0].Rdata == "" {
		t.Error("rdata_b64 is empty")
	}

	// (c) The pin path: tld_id_b32 supplied, claim hop skipped.
	pin := encodeTldIDB32(tid)
	resp, err := unixHTTP(c.Sock).Post("http://admin/resolve", "application/json",
		strings.NewReader(fmt.Sprintf(`{"name":"apex","tld_id_b32":%q}`, pin)))
	if err != nil {
		t.Fatal(err)
	}
	var pinned Resolved
	if err := json.NewDecoder(resp.Body).Decode(&pinned); err != nil {
		t.Fatalf("decode pinned resolve: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !pinned.Found {
		t.Errorf("pinned resolve: status=%d found=%v, want 200/true", resp.StatusCode, pinned.Found)
	}

	// (d) Nothing published for this alias: Found=false, no error.
	res, err = c.Resolve(ctx, "nothere")
	if err != nil {
		t.Fatalf("Resolve(nothere): %v", err)
	}
	if res.Found {
		t.Error("Resolve(nothere).Found = true, want false")
	}

	// The TLD record is also directly fetchable at its K_tld key.
	got, err := c.Get(ctx, tldKey)
	if err != nil || got == nil {
		t.Errorf("Get(K_tld): (%v, %v), want the published envelope", got, err)
	}
}

// ---------------------------------------------------------------------------
// 4. Witness collection
// ---------------------------------------------------------------------------

// TestWitness: through the daemon's node, the witness endpoint walks toward
// K_claim, collects from the peer, and returns ≥ 1 raw attestation that
// decodes and §7.3-verifies for the exact claim identity.
func TestWitness(t *testing.T) {
	_, b, _, c := adminPair(t, "v-wit")

	claimant, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tldID, err := crypto.TldID(claimant.Public())
	if err != nil {
		t.Fatal(err)
	}
	ts := uint64(time.Now().Unix())

	// Since v0.7.0 the witness verifies the PoW before signing (§7.3): mine
	// a fast difficulty-8 pair for the identity (and lower the claims
	// package's floor to match, as the other fixtures do).
	prevD := claims.PoWDifficultyInit
	claims.PoWDifficultyInit = 8
	t.Cleanup(func() { claims.PoWDifficultyInit = prevD })
	prefix, err := (&claims.AliasClaim{Alias: "witfoo", TldID: tldID, Timestamp: ts, ClaimantPK: claimant.Public()}).Prefix()
	if err != nil {
		t.Fatal(err)
	}
	nonce, powHash, err := crypto.MinePoW(prefix, 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MinePoW (fixture): %v", err)
	}
	ph, err := (&claims.AliasClaim{Alias: "witfoo", TldID: tldID, Timestamp: ts, ClaimantPK: claimant.Public()}).PrefixHash()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	atts, err := c.Witness(ctx, "witfoo", tldID, claimant.Public(), ts, nonce, powHash)
	if err != nil {
		t.Fatalf("Witness: %v", err)
	}
	if len(atts) < 1 {
		t.Fatal("witness endpoint returned 0 attestations, want ≥ 1 from the peer")
	}
	for i, raw := range atts {
		att, derr := claims.DecodeWitnessAttestation(raw)
		if derr != nil {
			t.Fatalf("attestation %d does not decode: %v", i, derr)
		}
		if !att.Verify(ph) {
			t.Errorf("attestation %d does not §7.3-verify for the claim identity", i)
		}
		if !bytes.Equal(att.NodeID, b.ID()) {
			t.Errorf("attestation %d is from node %s, want the peer %s", i, att.NodeID, b.ID())
		}
	}
}

// ---------------------------------------------------------------------------
// 5. Alive / Close semantics
// ---------------------------------------------------------------------------

// TestAliveCloseSemantics: Close is idempotent, removes the socket file,
// flips Alive to false, and makes a blocked ListenAndServe return nil.
// A live foreign daemon's socket is refused (not stolen).
func TestAliveCloseSemantics(t *testing.T) {
	srv := New(nil, nil, "v-close", slog.Default())
	sock := filepath.Join(t.TempDir(), "admin.sock")
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(sock) }()
	waitAlive(t, sock, done)

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("second Close: %v (want idempotent nil)", err)
	}
	if Alive(sock) {
		t.Error("Alive still true after Close")
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("socket file still exists after Close: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ListenAndServe returned %v, want nil after Close", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ListenAndServe did not return after Close")
	}

	// A second server on a FRESH socket serves fine...
	srv2 := New(nil, nil, "v-two", slog.Default())
	sock2 := filepath.Join(t.TempDir(), "admin.sock")
	done2 := make(chan error, 1)
	go func() { done2 <- srv2.ListenAndServe(sock2) }()
	waitAlive(t, sock2, done2)

	// ...but a third server must NOT steal the live second one's socket.
	srv3 := New(nil, nil, "v-three", slog.Default())
	if err := srv3.ListenAndServe(sock2); err == nil {
		t.Error("ListenAndServe stole a live daemon's socket")
	}
	if !Alive(sock2) {
		t.Error("the live daemon's socket died while being probed by a rival")
	}
	_ = srv2.Close()
	<-done2
}

// ---------------------------------------------------------------------------
// 6. Malformed input → 4xx, never a panic
// ---------------------------------------------------------------------------

// TestMalformedRequests: every flavor of garbage is answered with a 4xx and
// the server survives (still Alive, still serving /status).
func TestMalformedRequests(t *testing.T) {
	_, _, _, c := adminPair(t, "v-bad")

	badB64 := base64.StdEncoding.EncodeToString([]byte("definitely not a CBOR envelope"))
	for _, tc := range []struct {
		path string
		body string
	}{
		{"/publish", `{nope`},                                             // broken JSON
		{"/publish", `{"envelope":"@@@not base64@@@"}`},                   // bad b64
		{"/publish", fmt.Sprintf(`{"envelope":%q}`, badB64)},              // b64 of garbage
		{"/publish", `{"claim":true,"envelope":""}`},                      // claim mode, no envelope
		{"/get", `{"key":"xyz!"}`},                                        // bad hex
		{"/get", `{"key":"0102"}`},                                        // wrong key length
		{"/resolve", `{"name":"a..b"}`},                                   // empty label
		{"/resolve", `{"name":""}`},                                       // empty name
		{"/witness", `{"alias":"ok","tld_id":"zz","claimant":"","ts":1}`}, // bad hex
	} {
		code, body := post(t, c.Sock, tc.path, tc.body)
		if code < 400 || code > 499 {
			t.Errorf("POST %s %s: status = %d (body %s), want 4xx", tc.path, tc.body, code, body)
		}
	}

	// Unknown path → 404; wrong method → 405 (net/http method patterns).
	r, err := unixHTTP(c.Sock).Get("http://admin/nosuch")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusNotFound {
		t.Errorf("GET /nosuch: status = %d, want 404", r.StatusCode)
	}
	code, body := post(t, c.Sock, "/status", `{}`)
	if code != http.StatusMethodNotAllowed {
		t.Errorf("POST /status: status = %d (body %s), want 405", code, body)
	}

	// The server survived it all.
	if !Alive(c.Sock) {
		t.Fatal("server died under malformed input")
	}
	if st, err := c.Status(context.Background()); err != nil || !st.Running {
		t.Fatalf("Status after malformed input: (%v, %v)", st, err)
	}
}
