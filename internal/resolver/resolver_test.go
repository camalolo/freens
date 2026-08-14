package resolver

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/naming"
	"github.com/laurent/freens/internal/wire"
	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// Test fixtures: a self-certifying freens TLD "foo" with a www.foo A record.
// ---------------------------------------------------------------------------

const (
	// fixedNow is the wall-clock used by all tests so IsBasicValid's
	// created<=now<expires window holds deterministically.
	fixedNow int64 = 1_700_000_000
)

// freensWorld is a complete, properly-signed freens namespace for the tests.
type freensWorld struct {
	tldKP   *crypto.Keypair
	tldID   []byte
	tldEnv  *wire.SignedEnvelope // chain[0]: self-certifying TLD "foo"
	wwwEnv  *wire.SignedEnvelope // chain[1]: www.foo with an A RR
	wwwIPv4 net.IP
}

// newFreensWorld builds:
//   - a TLD keypair whose SHA-256(pk) is the self-certifying tld_id for "foo";
//   - a TLD record (wire_name = 0x00 || tld_id), owner=signer=tldKP.Public();
//   - a www.foo record (owner = signer = tldKP.Public() so the direct-sign
//     authority path verifies: parent.Owner == child.Signer) carrying an A RR.
//
// Every envelope is freshly signed, so wire.IsBasicValid / VerifyAuthorityChain
// pass for real (not stubbed).
func newFreensWorld(t *testing.T) *freensWorld {
	t.Helper()
	w := &freensWorld{}

	tldKP, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	w.tldKP = tldKP
	tldID, err := crypto.TldID(tldKP.Public())
	if err != nil {
		t.Fatal(err)
	}
	w.tldID = tldID
	w.wwwIPv4 = net.IPv4(203, 0, 113, 42)

	// TLD record: wire_name = 0x00 || tld_id; labels=nil.
	tldWireName, err := naming.EncodeWireName(nil, "foo", tldID)
	if err != nil {
		t.Fatal(err)
	}
	tldRec, err := wire.NewRecord(tldWireName, tldKP.Public(), 1, uint64(fixedNow-100), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	tldEnv, err := wire.SignRecord(tldRec, tldKP)
	if err != nil {
		t.Fatal(err)
	}
	w.tldEnv = tldEnv

	// www.foo record: direct-signed by the TLD owner so chain verifies via
	// parent.Owner == child.Signer (no Delegation field needed).
	wwwWireName, err := naming.EncodeWireName([]string{"www"}, "foo", tldID)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec, err := wire.NewRecord(wwwWireName, tldKP.Public(), 1, uint64(fixedNow-100), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	aRR, err := wire.A([]byte{203, 0, 113, 42}, 600)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec.RRset = []*wire.RR{aRR}
	wwwEnv, err := wire.SignRecord(wwwRec, tldKP)
	if err != nil {
		t.Fatal(err)
	}
	w.wwwEnv = wwwEnv

	// Sanity: the fixtures really do verify — a test bug should fail here, not
	// silently in the resolver assertions below.
	if !wire.IsBasicValid(tldEnv, uint64(fixedNow)) {
		t.Fatal("fixture: TLD env not IsBasicValid")
	}
	if !wire.IsBasicValid(wwwEnv, uint64(fixedNow)) {
		t.Fatal("fixture: www env not IsBasicValid")
	}
	if !wire.VerifyAuthorityChain([]*wire.SignedEnvelope{tldEnv, wwwEnv}) {
		t.Fatal("fixture: authority chain does not verify")
	}
	return w
}

// fakeLookup is a RecordLookup backed by a map keyed on the hex of the
// wire_name. Returning nil for a key simulates "no record at this name".
type fakeLookup struct {
	mu      sync.Mutex
	records map[string]*wire.SignedEnvelope
}

func newFakeLookup() *fakeLookup {
	return &fakeLookup{records: map[string]*wire.SignedEnvelope{}}
}

func (f *fakeLookup) put(env *wire.SignedEnvelope) {
	f.records[hex.EncodeToString(env.Record.Name)] = env
}

func (f *fakeLookup) Lookup(_ context.Context, wireName []byte, _ int64) (*wire.SignedEnvelope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.records[hex.EncodeToString(wireName)], nil
}

// fakeUpstream is an Upstream that returns a canned response, optionally
// recording the queries it saw. rcode lets a test simulate NXDOMAIN etc.
type fakeUpstream struct {
	mu     sync.Mutex
	seen   []*dns.Msg
	answer []dns.RR
	rcode  int
	err    error
}

func (u *fakeUpstream) Forward(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	cp := q.Copy()
	u.seen = append(u.seen, cp)
	if u.err != nil {
		return nil, u.err
	}
	m := new(dns.Msg)
	m.SetReply(q)
	m.Rcode = u.rcode
	m.Answer = u.answer
	return m, nil
}

// configFor builds a *Config that pins "foo" to the world's tld_id and routes
// "foo" to the given Route (plus "*" → DNSFirst).
func configFor(t *testing.T, w *freensWorld, route Route) *Config {
	t.Helper()
	cfg, err := ParseConfig(`[tld-routes]
* = dns-first
`)
	if err != nil {
		t.Fatal(err)
	}
	cfg.TLDRoutes["foo"] = route
	cfg.AliasPins = map[string][]byte{"foo": append([]byte(nil), w.tldID...)}
	return cfg
}

// newResolver wires a Resolver with the freens lookup + a fixed clock.
func newResolver(cfg *Config, lookup RecordLookup, up Upstream) *Resolver {
	r := New(cfg, lookup, up)
	r.Now = func() int64 { return fixedNow }
	return r
}

// ---------------------------------------------------------------------------
// FREENS route
// ---------------------------------------------------------------------------

func TestResolveQuestionFREENSHit(t *testing.T) {
	w := newFreensWorld(t)
	lookup := newFakeLookup()
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)

	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)

	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR(%d)", rcode, dns.RcodeSuccess)
	}
	if len(rrs) != 1 {
		t.Fatalf("len(rrs) = %d, want 1", len(rrs))
	}
	a, ok := rrs[0].(*dns.A)
	if !ok {
		t.Fatalf("rrs[0] is %T, want *dns.A", rrs[0])
	}
	if !a.A.Equal(w.wwwIPv4) {
		t.Errorf("A.A = %s, want %s", a.A, w.wwwIPv4)
	}
	// Header sanity: owner name echoed, type A, class IN, TTL within cap.
	hdr := a.Header()
	if hdr.Name != "www.foo." {
		t.Errorf("header Name = %q, want www.foo.", hdr.Name)
	}
	if hdr.Rrtype != dns.TypeA {
		t.Errorf("header Rrtype = %d, want A(%d)", hdr.Rrtype, dns.TypeA)
	}
	if hdr.Class != dns.ClassINET {
		t.Errorf("header Class = %d, want IN(%d)", hdr.Class, dns.ClassINET)
	}
	// TTL = min(rr.TTL=600, expires-now=3600, cap=3600) = 600.
	if hdr.Ttl != 600 {
		t.Errorf("header Ttl = %d, want 600", hdr.Ttl)
	}
}

func TestResolveQuestionFREENSMissNXDOMAIN(t *testing.T) {
	w := newFreensWorld(t)
	// Empty lookup → no record at any hop → NXDOMAIN.
	r := newResolver(configFor(t, w, RouteFREENS), newFakeLookup(), nil)

	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN(%d)", rcode, dns.RcodeNameError)
	}
	if len(rrs) != 0 {
		t.Errorf("len(rrs) = %d, want 0", len(rrs))
	}
}

func TestResolveQuestionFREENSMissNODATA(t *testing.T) {
	// Name exists (chain verifies) but the requested type is absent → NODATA
	// (NOERROR with empty answer).
	w := newFreensWorld(t)
	lookup := newFakeLookup()
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)

	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)

	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	rrs, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want NOERROR (NODATA)", rcode)
	}
	if len(rrs) != 0 {
		t.Errorf("len(rrs) = %d, want 0 (NODATA)", len(rrs))
	}
}

func TestResolveQuestionFREENSBrokenChain(t *testing.T) {
	// www record present and signed, but the TLD record is ABSENT from the
	// lookup → chain cannot be built → NXDOMAIN.
	w := newFreensWorld(t)
	lookup := newFakeLookup()
	lookup.put(w.wwwEnv) // only the child; no TLD root

	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)
	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	_, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("broken chain rcode = %d, want NXDOMAIN", rcode)
	}
}

// ---------------------------------------------------------------------------
// DENY route
// ---------------------------------------------------------------------------

func TestResolveQuestionDENY(t *testing.T) {
	w := newFreensWorld(t)
	// Even with a record present, DENY must REFUSED without consulting freens.
	lookup := newFakeLookup()
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)
	r := newResolver(configFor(t, w, RouteDENY), lookup, nil)

	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if rcode != dns.RcodeRefused {
		t.Errorf("rcode = %d, want REFUSED(%d)", rcode, dns.RcodeRefused)
	}
	if len(rrs) != 0 {
		t.Errorf("DENY returned %d RRs, want 0", len(rrs))
	}
}

// ---------------------------------------------------------------------------
// DNS route (no upstream → REFUSED; canned upstream → returned verbatim)
// ---------------------------------------------------------------------------

func TestResolveQuestionDNSNoUpstream(t *testing.T) {
	w := newFreensWorld(t)
	r := newResolver(configFor(t, w, RouteDNS), nil, nil)

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	_, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if rcode != dns.RcodeRefused {
		t.Errorf("rcode = %d, want REFUSED", rcode)
	}
}

func TestResolveQuestionDNSForwarded(t *testing.T) {
	w := newFreensWorld(t)
	want := net.IPv4(93, 184, 216, 34)
	rr := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: want}
	up := &fakeUpstream{answer: []dns.RR{rr}, rcode: dns.RcodeSuccess}
	r := newResolver(configFor(t, w, RouteDNS), nil, up)

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	out, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want NOERROR", rcode)
	}
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	a, ok := out[0].(*dns.A)
	if !ok || !a.A.Equal(want) {
		t.Errorf("out[0] = %v, want A %s", out[0], want)
	}
	// Upstream saw the verbatim question.
	if len(up.seen) != 1 {
		t.Fatalf("upstream saw %d queries, want 1", len(up.seen))
	}
	if got := up.seen[0].Question[0].Name; got != "example.com." {
		t.Errorf("upstream saw Name %q", got)
	}
}

// ---------------------------------------------------------------------------
// DNSFirst: DNS hit returns DNS; DNS NXDOMAIN falls through to freens.
// ---------------------------------------------------------------------------

func TestResolveQuestionDNSFirstHit(t *testing.T) {
	w := newFreensWorld(t)
	lookup := newFakeLookup()
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)
	// DNS returns a different IP; DNSFirst must return DNS's answer (NOT
	// freens's), proving DNS is consulted first.
	want := net.IPv4(1, 1, 1, 1)
	rr := &dns.A{Hdr: dns.RR_Header{Name: "www.foo.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 90}, A: want}
	up := &fakeUpstream{answer: []dns.RR{rr}, rcode: dns.RcodeSuccess}
	r := newResolver(configFor(t, w, RouteDNSFirst), lookup, up)

	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	out, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if rcode != dns.RcodeSuccess || len(out) != 1 {
		t.Fatalf("rcode=%d len=%d", rcode, len(out))
	}
	a := out[0].(*dns.A)
	if !a.A.Equal(want) {
		t.Errorf("DNSFirst returned freens IP %s, want DNS IP %s", a.A, want)
	}
}

func TestResolveQuestionDNSFirstFallthroughToFreens(t *testing.T) {
	w := newFreensWorld(t)
	lookup := newFakeLookup()
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)
	// DNS NXDOMAIN → fall through to freens, which has the answer.
	up := &fakeUpstream{rcode: dns.RcodeNameError}
	r := newResolver(configFor(t, w, RouteDNSFirst), lookup, up)

	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	out, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR (freens fallthrough)", rcode)
	}
	a := out[0].(*dns.A)
	if !a.A.Equal(w.wwwIPv4) {
		t.Errorf("fallthrough A = %s, want freens %s", a.A, w.wwwIPv4)
	}
}

// ---------------------------------------------------------------------------
// FREENSFirst: hit returns freens; miss falls through to DNS.
// ---------------------------------------------------------------------------

func TestResolveQuestionFREENSFirstHit(t *testing.T) {
	w := newFreensWorld(t)
	lookup := newFakeLookup()
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)
	up := &fakeUpstream{} // should NOT be consulted
	r := newResolver(configFor(t, w, RouteFREENSFirst), lookup, up)

	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	out, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d, want NOERROR", rcode)
	}
	a := out[0].(*dns.A)
	if !a.A.Equal(w.wwwIPv4) {
		t.Errorf("FREENSFirst A = %s, want %s", a.A, w.wwwIPv4)
	}
	if len(up.seen) != 0 {
		t.Errorf("FREENSFirst on hit should not consult upstream, saw %d", len(up.seen))
	}
}

func TestResolveQuestionFREENSFirstFallthroughToDNS(t *testing.T) {
	w := newFreensWorld(t)
	// No freens record → miss → fall through to DNS.
	lookup := newFakeLookup()
	want := net.IPv4(2, 2, 2, 2)
	rr := &dns.A{Hdr: dns.RR_Header{Name: "www.foo.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: want}
	up := &fakeUpstream{answer: []dns.RR{rr}, rcode: dns.RcodeSuccess}
	r := newResolver(configFor(t, w, RouteFREENSFirst), lookup, up)

	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	out, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d, want NOERROR", rcode)
	}
	a := out[0].(*dns.A)
	if !a.A.Equal(want) {
		t.Errorf("FREENSFirst fallthrough A = %s, want DNS %s", a.A, want)
	}
}

// ---------------------------------------------------------------------------
// Edge: unpinned alias (no AliasPins) → freens branch misses with no panic.
// ---------------------------------------------------------------------------

func TestResolveQuestionFreensUnpinnedAlias(t *testing.T) {
	w := newFreensWorld(t)
	cfg := &Config{TLDRoutes: map[string]Route{"foo": RouteFREENS, "*": RouteDNSFirst}}
	lookup := newFakeLookup()
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)
	r := newResolver(cfg, lookup, nil)

	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	_, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	// No pin → cannot resolve alias → NXDOMAIN (no claim source in-process).
	if rcode != dns.RcodeNameError {
		t.Errorf("unpinned rcode = %d, want NXDOMAIN", rcode)
	}
}

// ---------------------------------------------------------------------------
// Edge: unparseable name → NXDOMAIN.
// ---------------------------------------------------------------------------

func TestResolveQuestionBadName(t *testing.T) {
	r := newResolver(&Config{TLDRoutes: map[string]Route{"*": RouteFREENSFirst}}, nil, nil)
	// Empty label in the middle → DecomposeName errors.
	q := dns.Question{Name: "a..b.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	_, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("bad-name rcode = %d, want NXDOMAIN", rcode)
	}
}

// ---------------------------------------------------------------------------
// TTL clamping: RR.ttl > expires-now → clamped to expires-now; > cap → capped.
// ---------------------------------------------------------------------------

func TestResolveQuestionTTLClamped(t *testing.T) {
	w := newFreensWorld(t)
	// Build a www record whose RR.ttl (86400) exceeds expires-now and the cap.
	wwwWireName, err := naming.EncodeWireName([]string{"www"}, "foo", w.tldID)
	if err != nil {
		t.Fatal(err)
	}
	// expires = fixedNow + 30 → window of 30s; RR.ttl = 86400.
	rec, err := wire.NewRecord(wwwWireName, w.tldKP.Public(), 2, uint64(fixedNow-100), uint64(fixedNow+30))
	if err != nil {
		t.Fatal(err)
	}
	bigTTL := uint64(constants.RecordDefaultTTL) // 86400
	aRR, err := wire.A([]byte{203, 0, 113, 42}, bigTTL)
	if err != nil {
		t.Fatal(err)
	}
	rec.RRset = []*wire.RR{aRR}
	wwwEnv, err := wire.SignRecord(rec, w.tldKP)
	if err != nil {
		t.Fatal(err)
	}
	lookup := newFakeLookup()
	lookup.put(w.tldEnv)
	lookup.put(wwwEnv)
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)

	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	out, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if rcode != dns.RcodeSuccess || len(out) != 1 {
		t.Fatalf("rcode=%d len=%d", rcode, len(out))
	}
	// min(86400, 30) = 30; cap 3600 not reached.
	if got := out[0].Header().Ttl; got != 30 {
		t.Errorf("TTL = %d, want 30 (min(rr.ttl, expires-now))", got)
	}
}

// ---------------------------------------------------------------------------
// End-to-end: NewServer on an ephemeral UDP port, queried via dns.Client.
// ---------------------------------------------------------------------------

func TestServerUDPEndpoint(t *testing.T) {
	w := newFreensWorld(t)
	lookup := newFakeLookup()
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)

	// Build the Server but inject a pre-bound PacketConn so we can read the
	// ephemeral port before serving starts.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	srv := NewServer("127.0.0.1:0", "udp", r)
	srv.DNSServer().PacketConn = pc

	started := make(chan struct{})
	go func() {
		_ = srv.ListenAndServe()
		close(started)
	}()
	t.Cleanup(func() {
		_ = srv.Shutdown()
	})
	// Give ActivateAndServe a moment to install the handler. The socket is
	// already bound, so queries will queue if we race; we retry a few times.
	addr := pc.LocalAddr().String()

	q := new(dns.Msg)
	q.SetQuestion("www.foo.", dns.TypeA)
	q.RecursionDesired = true

	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second, UDPSize: 4096}

	var resp *dns.Msg
	for i := 0; i < 10; i++ {
		var exErr error
		resp, _, exErr = c.Exchange(q, addr)
		if exErr == nil && resp != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if resp == nil {
		t.Fatalf("no response from %s (last exchange error may have occurred)", addr)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("server rcode = %d, want NOERROR", resp.Rcode)
	}
	if !resp.Authoritative {
		t.Error("freens-sourced answer should set the AA bit")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("Answer[0] = %T, want *dns.A", resp.Answer[0])
	}
	if !a.A.Equal(w.wwwIPv4) {
		t.Errorf("server A.A = %s, want %s", a.A, w.wwwIPv4)
	}
	// Question is echoed back.
	if len(resp.Question) != 1 || resp.Question[0].Name != "www.foo." {
		t.Errorf("Question = %v", resp.Question)
	}
}

// ---------------------------------------------------------------------------
// End-to-end: NewServer on an ephemeral TCP port, queried via dns.Client.
// ---------------------------------------------------------------------------

func TestServerTCPEndpoint(t *testing.T) {
	w := newFreensWorld(t)
	lookup := newFakeLookup()
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen tcp: %v", err)
	}
	srv := NewServer("127.0.0.1:0", "tcp", r)
	srv.DNSServer().Listener = ln
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	addr := ln.Addr().String()
	q := new(dns.Msg).SetQuestion("www.foo.", dns.TypeA)
	c := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}

	var resp *dns.Msg
	for i := 0; i < 10; i++ {
		var exErr error
		resp, _, exErr = c.Exchange(q, addr)
		if exErr == nil && resp != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if resp == nil {
		t.Fatalf("no TCP response from %s", addr)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("server rcode=%d len=%d", resp.Rcode, len(resp.Answer))
	}
	a := resp.Answer[0].(*dns.A)
	if !a.A.Equal(w.wwwIPv4) {
		t.Errorf("TCP A.A = %s, want %s", a.A, w.wwwIPv4)
	}
}

// ---------------------------------------------------------------------------
// DNSUpstream: real loopback forwarder against an ephemeral DNS server.
// ---------------------------------------------------------------------------

func TestDNSUpstreamForwardLoopback(t *testing.T) {
	// Stand up a tiny DNS server that answers A=127.0.0.1 for any question.
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, m *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(m)
		if len(m.Question) > 0 {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   m.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.IPv4(127, 0, 0, 1),
			})
		}
		_ = w.WriteMsg(resp)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	ds := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = ds.ActivateAndServe() }()
	t.Cleanup(func() { _ = ds.Shutdown() })
	addr := pc.LocalAddr().String()

	up := &DNSUpstream{Servers: []string{addr}, Timeout: time.Second}
	q := new(dns.Msg).SetQuestion("loopback.test.", dns.TypeA)
	resp, err := up.Forward(context.Background(), q)
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("Forward rcode=%d len=%d", resp.Rcode, len(resp.Answer))
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || !a.A.IsLoopback() {
		t.Errorf("Forward Answer = %v, want loopback A", resp.Answer[0])
	}

	// No servers configured → error.
	if _, err := (&DNSUpstream{}).Forward(context.Background(), q); err == nil {
		t.Error("empty DNSUpstream should error")
	}

	// Bare host gets ":53" appended.
	if got := ensureDNSPort("9.9.9.9"); got != "9.9.9.9:53" {
		t.Errorf("ensureDNSPort(9.9.9.9) = %q", got)
	}
	if got := ensureDNSPort("9.9.9.9:53"); got != "9.9.9.9:53" {
		t.Errorf("ensureDNSPort(9.9.9.9:53) = %q", got)
	}
	// IPv6 literal preserved.
	if got := ensureDNSPort("[::1]:5300"); got != "[::1]:5300" {
		t.Errorf("ensureDNSPort([::1]:5300) = %q", got)
	}
}

// ---------------------------------------------------------------------------
// freensRRToDNS direct unit checks (AAA/TXT coverage).
// ---------------------------------------------------------------------------

func TestFreensRRToDNS(t *testing.T) {
	name := "host.foo."
	expires := int64(fixedNow + 100)

	// A
	aRR, _ := wire.A([]byte{10, 0, 0, 1}, 600)
	got := freensRRToDNS(name, aRR, expires, fixedNow)
	a, ok := got.(*dns.A)
	if !ok {
		t.Fatalf("A mapping: got %T, want *dns.A", got)
	}
	if !a.A.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Errorf("A.A = %s", a.A)
	}

	// AAAA
	v6 := net.ParseIP("2001:db8::1").To16()
	aaaaRR, _ := wire.AAAA(v6, 600)
	got = freensRRToDNS(name, aaaaRR, expires, fixedNow)
	aaaa, ok := got.(*dns.AAAA)
	if !ok {
		t.Fatalf("AAAA mapping: got %T, want *dns.AAAA", got)
	}
	if !aaaa.AAAA.Equal(v6) {
		t.Errorf("AAAA.AAAA = %s", aaaa.AAAA)
	}

	// TXT
	txtRR, _ := wire.TXT("hello freens", 600)
	got = freensRRToDNS(name, txtRR, expires, fixedNow)
	txt, ok := got.(*dns.TXT)
	if !ok {
		t.Fatalf("TXT mapping: got %T, want *dns.TXT", got)
	}
	if len(txt.Txt) != 1 || txt.Txt[0] != "hello freens" {
		t.Errorf("TXT.Txt = %v", txt.Txt)
	}

	// Unknown type → nil (skipped).
	unk, _ := wire.NewRR(999, 600, []byte{1, 2, 3})
	if g := freensRRToDNS(name, unk, expires, fixedNow); g != nil {
		t.Errorf("unknown type should map to nil, got %v", g)
	}

	// Bad rdata length → nil.
	badA, _ := wire.NewRR(wire.RRTypeA, 600, []byte{1, 2}) // too short
	if g := freensRRToDNS(name, badA, expires, fixedNow); g != nil {
		t.Errorf("short A rdata should map to nil, got %v", g)
	}
}

// prevent unused-import warnings if a subtest is compiled out.
var _ = fmt.Sprintf

// ---------------------------------------------------------------------------
// B2: AA flag — the ServeDNS response must label the answer authoritative iff
// the FINAL answer was produced by freensResolve. A FREENSFirst miss that falls
// through to upstream DNS must NOT set AA, even though the route is freens-first
// and the alias is "freens-routed" in the abstract. The check is on the ACTUAL
// answer source, not the configured route.
// ---------------------------------------------------------------------------

// serveDNSOverUDP stands up an ephemeral UDP server backed by r, sends q via a
// dns.Client, and returns the response. It retries briefly so the
// ActivateAndServe handler-install race (the socket is pre-bound) is absorbed.
// The server is shut down via t.Cleanup.
func serveDNSOverUDP(t *testing.T, r *Resolver, q *dns.Msg) *dns.Msg {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	srv := NewServer("127.0.0.1:0", "udp", r)
	srv.DNSServer().PacketConn = pc
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	addr := pc.LocalAddr().String()
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second, UDPSize: 4096}
	for i := 0; i < 10; i++ {
		resp, _, exErr := c.Exchange(q, addr)
		if exErr == nil && resp != nil {
			return resp
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no UDP response from %s", addr)
	return nil
}

func TestServeDNS_AAFlagOnFreensFirstFallthrough(t *testing.T) {
	w := newFreensWorld(t)

	// (1) FREENSFirst, freens MISS, upstream canned NOERROR → AA == false.
	t.Run("FREENSFirst_miss_fallthrough", func(t *testing.T) {
		// Empty lookup → freens NXDOMAIN → fall through to DNS.
		upstreamIP := net.IPv4(7, 7, 7, 7)
		rr := &dns.A{Hdr: dns.RR_Header{Name: "www.foo.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: upstreamIP}
		up := &fakeUpstream{answer: []dns.RR{rr}, rcode: dns.RcodeSuccess}
		r := newResolver(configFor(t, w, RouteFREENSFirst), newFakeLookup(), up)

		q := new(dns.Msg).SetQuestion("www.foo.", dns.TypeA)
		resp := serveDNSOverUDP(t, r, q)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("rcode = %d, want NOERROR (upstream)", resp.Rcode)
		}
		if resp.Authoritative {
			t.Errorf("AA = true on FREENSFirst→DNS fallthrough; DNS-sourced answers MUST be non-authoritative (RFC 1035 §4.1.1)")
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("len(Answer) = %d, want 1 (canned upstream)", len(resp.Answer))
		}
		if a, ok := resp.Answer[0].(*dns.A); !ok || !a.A.Equal(upstreamIP) {
			t.Errorf("Answer = %v, want canned upstream A %s", resp.Answer[0], upstreamIP)
		}
	})

	// (2) Pure FREENS hit → AA == true.
	t.Run("FREENS_hit", func(t *testing.T) {
		lookup := newFakeLookup()
		lookup.put(w.tldEnv)
		lookup.put(w.wwwEnv)
		r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)

		q := new(dns.Msg).SetQuestion("www.foo.", dns.TypeA)
		resp := serveDNSOverUDP(t, r, q)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("rcode = %d, want NOERROR", resp.Rcode)
		}
		if !resp.Authoritative {
			t.Errorf("AA = false on pure FREENS hit; freens IS the authoritative source for its namespace")
		}
	})

	// (3) DNS-forwarded answer → AA == false.
	t.Run("DNS_forwarded", func(t *testing.T) {
		upstreamIP := net.IPv4(8, 8, 4, 4)
		rr := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 90}, A: upstreamIP}
		up := &fakeUpstream{answer: []dns.RR{rr}, rcode: dns.RcodeSuccess}
		// Use the FREENS route config for "foo" but query example.com (which
		// falls through to "* = dns-first" → DNS hit → AA false).
		r := newResolver(configFor(t, w, RouteFREENS), nil, up)

		q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
		resp := serveDNSOverUDP(t, r, q)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("rcode = %d, want NOERROR", resp.Rcode)
		}
		if resp.Authoritative {
			t.Errorf("AA = true on DNS-forwarded answer; conventional DNS replies are non-authoritative for this server")
		}
	})
}

// ---------------------------------------------------------------------------
// R1: FREENSFirst NODATA-fallthrough (§9.3 line 784 "on miss" interpretation).
// freens has the NAME (chain valid) but no RR of the queried type → NODATA
// (NOERROR, empty answer). The resolver falls through to conventional DNS,
// which returns a canned RR. Assert the canned RR is returned and aa == false.
// ---------------------------------------------------------------------------

func TestResolveQuestionFREENSFirstNODATAFallthrough(t *testing.T) {
	w := newFreensWorld(t)
	// freens has www.foo with an A record only; we ask AAAA → NODATA →
	// fall through to the fake upstream, which returns a canned AAAA.
	lookup := newFakeLookup()
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)

	v6 := net.ParseIP("2001:db8::1").To16()
	cannedAAAA := &dns.AAAA{Hdr: dns.RR_Header{Name: "www.foo.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120}, AAAA: v6}
	up := &fakeUpstream{answer: []dns.RR{cannedAAAA}, rcode: dns.RcodeSuccess}
	r := newResolver(configFor(t, w, RouteFREENSFirst), lookup, up)

	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	out, rcode, aa, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want NOERROR (canned upstream)", rcode)
	}
	if aa {
		t.Errorf("aa = true on FREENSFirst NODATA→DNS fallthrough; want false (DNS-sourced)")
	}
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1 (canned AAAA from upstream)", len(out))
	}
	got, ok := out[0].(*dns.AAAA)
	if !ok || !got.AAAA.Equal(v6) {
		t.Errorf("out[0] = %v, want canned AAAA %s", out[0], v6)
	}
	// Upstream must have been consulted exactly once (the fallthrough).
	if len(up.seen) != 1 {
		t.Errorf("upstream saw %d queries, want 1 (the NODATA fallthrough)", len(up.seen))
	}
}

// ---------------------------------------------------------------------------
// R2: per-hop temporal validation. A chain with a VALID terminal envelope but
// an EXPIRED intermediate delegation record must be rejected (NXDOMAIN): the
// expired hop cannot continue to delegate authority past its lifetime. Before
// R2 only the terminal envelope was IsBasicValid'd, so a stale-but-signed
// intermediate would slip through VerifyAuthorityChain and the resolver would
// return the stale answer.
// ---------------------------------------------------------------------------

func TestResolveQuestionFreensExpiredIntermediate(t *testing.T) {
	w := newFreensWorld(t)

	// Build a 3-hop chain TLD → host.foo (EXPIRED) → sub.host.foo, all
	// direct-signed by the TLD key (parent.Owner == child.Signer) so
	// VerifyAuthorityChain passes structurally. Only the intermediate's
	// Expires is in the past relative to fixedNow.

	// Intermediate host.foo — EXPIRED. Its signature, owner binding, and
	// chain structure are all valid; only its [Created, Expires) window is
	// in the past.
	hostWireName, err := naming.EncodeWireName([]string{"host"}, "foo", w.tldID)
	if err != nil {
		t.Fatal(err)
	}
	hostRec, err := wire.NewRecord(hostWireName, w.tldKP.Public(), 1,
		uint64(fixedNow-10_000), uint64(fixedNow-1)) // Expires = fixedNow-1
	if err != nil {
		t.Fatal(err)
	}
	hostEnv, err := wire.SignRecord(hostRec, w.tldKP)
	if err != nil {
		t.Fatal(err)
	}

	// Terminal sub.host.foo — VALID window, carries the A RR we must NOT
	// receive (because its parent delegation is expired).
	subWireName, err := naming.EncodeWireName([]string{"sub", "host"}, "foo", w.tldID)
	if err != nil {
		t.Fatal(err)
	}
	subRec, err := wire.NewRecord(subWireName, w.tldKP.Public(), 1,
		uint64(fixedNow-100), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	staleA, err := wire.A([]byte{203, 0, 113, 99}, 600)
	if err != nil {
		t.Fatal(err)
	}
	subRec.RRset = []*wire.RR{staleA}
	subEnv, err := wire.SignRecord(subRec, w.tldKP)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: terminal env alone is IsBasicValid, the chain verifies
	// structurally (parent.Owner == child.Signer at every hop), so without
	// per-hop time checks the resolver would return the stale A record.
	if !wire.IsBasicValid(subEnv, uint64(fixedNow)) {
		t.Fatal("fixture: terminal sub.host.foo must be IsBasicValid alone")
	}
	// The intermediate is NOT IsBasicValid at fixedNow (expired).
	if wire.IsBasicValid(hostEnv, uint64(fixedNow)) {
		t.Fatal("fixture: intermediate host.foo must be EXPIRED at fixedNow")
	}
	chain := []*wire.SignedEnvelope{w.tldEnv, hostEnv, subEnv}
	if !wire.VerifyAuthorityChain(chain) {
		t.Fatal("fixture: chain must verify structurally (only time check fails)")
	}

	lookup := newFakeLookup()
	lookup.put(w.tldEnv)
	lookup.put(hostEnv)
	lookup.put(subEnv)
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)

	q := dns.Question{Name: "sub.host.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN (expired intermediate delegation)", rcode)
	}
	if len(rrs) != 0 {
		t.Errorf("expected 0 RRs (name unresolvable via stale delegation), got %d: %v", len(rrs), rrs)
	}
}
