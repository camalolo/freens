package resolver

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/laurent/freens/internal/claims"
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

// ---------------------------------------------------------------------------
// §8.5 — revocation. A revoked envelope anywhere on the authority chain
// (terminal OR intermediate) makes the name unresolvable → NXDOMAIN, even
// though every signature, window, and parent/child binding is otherwise valid.
// ---------------------------------------------------------------------------

// revokedEnv builds a properly-signed envelope for labels with revoke=true and
// an EMPTY rrset (§8.5: "revoke = true and empty rrset marks the name
// deliberately dead").
func revokedEnv(t *testing.T, w *freensWorld, labels []string, sequence uint64) *wire.SignedEnvelope {
	t.Helper()
	wn, err := naming.EncodeWireName(labels, "foo", w.tldID)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(wn, w.tldKP.Public(), sequence,
		uint64(fixedNow-100), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	tr := true
	rec.Revoke = &tr
	rec.RRset = []*wire.RR{}
	env, err := wire.SignRecord(rec, w.tldKP)
	if err != nil {
		t.Fatal(err)
	}
	if !env.IsRevoked() {
		t.Fatal("fixture: envelope must be revoked")
	}
	if !wire.IsBasicValid(env, uint64(fixedNow)) {
		t.Fatal("fixture: revoked envelope must still be IsBasicValid")
	}
	return env
}

func TestResolveQuestionFREENSRevokedTerminal(t *testing.T) {
	w := newFreensWorld(t)
	revokedWWW := revokedEnv(t, w, []string{"www"}, 2)
	if !wire.VerifyAuthorityChain([]*wire.SignedEnvelope{w.tldEnv, revokedWWW}) {
		t.Fatal("fixture: chain must verify structurally (revocation is not a signature issue)")
	}

	lookup := newFakeLookup()
	lookup.put(w.tldEnv)
	lookup.put(revokedWWW)
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)

	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, aa, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("revoked terminal rcode = %d, want NXDOMAIN (§8.5)", rcode)
	}
	if !aa {
		t.Error("aa = false; freens is authoritative for its own revoked-name NXDOMAIN")
	}
	if len(rrs) != 0 {
		t.Errorf("revoked name returned %d RRs, want 0", len(rrs))
	}
}

func TestResolveQuestionFREENSRevokedIntermediate(t *testing.T) {
	w := newFreensWorld(t)
	// 3-hop chain: TLD → host.foo (REVOKED delegation) → sub.host.foo (live,
	// carries the A RR we must NOT receive).
	revokedHost := revokedEnv(t, w, []string{"host"}, 1)

	subWireName, err := naming.EncodeWireName([]string{"sub", "host"}, "foo", w.tldID)
	if err != nil {
		t.Fatal(err)
	}
	subRec, err := wire.NewRecord(subWireName, w.tldKP.Public(), 1,
		uint64(fixedNow-100), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	liveA, err := wire.A([]byte{203, 0, 113, 77}, 600)
	if err != nil {
		t.Fatal(err)
	}
	subRec.RRset = []*wire.RR{liveA}
	subEnv, err := wire.SignRecord(subRec, w.tldKP)
	if err != nil {
		t.Fatal(err)
	}

	chain := []*wire.SignedEnvelope{w.tldEnv, revokedHost, subEnv}
	if !wire.VerifyAuthorityChain(chain) {
		t.Fatal("fixture: chain must verify structurally")
	}

	lookup := newFakeLookup()
	lookup.put(w.tldEnv)
	lookup.put(revokedHost)
	lookup.put(subEnv)
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)

	q := dns.Question{Name: "sub.host.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("revoked intermediate rcode = %d, want NXDOMAIN (§8.5)", rcode)
	}
	if len(rrs) != 0 {
		t.Errorf("expected 0 RRs through a revoked delegation, got %d: %v", len(rrs), rrs)
	}
}

// ---------------------------------------------------------------------------
// §4.3 — full RR type mapping (freensRRToDNS table-driven coverage).
// ---------------------------------------------------------------------------

func TestFreensRRToDNSMappings(t *testing.T) {
	name := "host.foo."
	expires := int64(fixedNow + 100)
	mkRR := func(typ uint64, rdata []byte) *wire.RR {
		t.Helper()
		rr, err := wire.NewRR(typ, 600, rdata)
		if err != nil {
			t.Fatal(err)
		}
		return rr
	}

	// longName is a hostname longer than the 255-octet DNS limit.
	longName := make([]byte, 300)
	for i := range longName {
		longName[i] = 'a'
	}

	tests := []struct {
		name  string
		rr    *wire.RR
		check func(t *testing.T, got dns.RR)
	}{
		{
			name: "MX",
			rr:   mkRR(wire.RRTypeMX, append([]byte{0x00, 0x0A}, []byte("mail.example.com.")...)),
			check: func(t *testing.T, got dns.RR) {
				mx, ok := got.(*dns.MX)
				if !ok {
					t.Fatalf("got %T, want *dns.MX", got)
				}
				if mx.Preference != 10 {
					t.Errorf("MX.Preference = %d, want 10", mx.Preference)
				}
				if mx.Mx != "mail.example.com." {
					t.Errorf("MX.Mx = %q", mx.Mx)
				}
			},
		},
		{
			name: "MX non-FQDN target is rooted",
			rr:   mkRR(wire.RRTypeMX, append([]byte{0x00, 0x14}, []byte("mail2.example.com")...)),
			check: func(t *testing.T, got dns.RR) {
				mx, ok := got.(*dns.MX)
				if !ok {
					t.Fatalf("got %T, want *dns.MX", got)
				}
				if mx.Preference != 20 || mx.Mx != "mail2.example.com." {
					t.Errorf("MX = %d %q", mx.Preference, mx.Mx)
				}
			},
		},
		{
			name: "MX rdata too short (no name)",
			rr:   mkRR(wire.RRTypeMX, []byte{0x00, 0x0A}),
			check: func(t *testing.T, got dns.RR) {
				if got != nil {
					t.Errorf("short MX rdata = %v, want nil", got)
				}
			},
		},
		{
			name: "MX invalid target name",
			rr:   mkRR(wire.RRTypeMX, append([]byte{0x00, 0x0A}, []byte("a..b.")...)),
			check: func(t *testing.T, got dns.RR) {
				if got != nil {
					t.Errorf("invalid MX target = %v, want nil", got)
				}
			},
		},
		{
			name: "SRV",
			rr:   mkRR(wire.RRTypeSRV, append([]byte{0x00, 0x0A, 0x00, 0x14, 0x1F, 0x90}, []byte("srv.example.com.")...)),
			check: func(t *testing.T, got dns.RR) {
				srv, ok := got.(*dns.SRV)
				if !ok {
					t.Fatalf("got %T, want *dns.SRV", got)
				}
				if srv.Priority != 10 || srv.Weight != 20 || srv.Port != 8080 {
					t.Errorf("SRV = %d/%d/%d", srv.Priority, srv.Weight, srv.Port)
				}
				if srv.Target != "srv.example.com." {
					t.Errorf("SRV.Target = %q", srv.Target)
				}
			},
		},
		{
			name: "SRV rdata too short",
			rr:   mkRR(wire.RRTypeSRV, []byte{0x00, 0x0A, 0x00, 0x14, 0x1F}),
			check: func(t *testing.T, got dns.RR) {
				if got != nil {
					t.Errorf("short SRV rdata = %v, want nil", got)
				}
			},
		},
		{
			name: "SRV empty target",
			rr:   mkRR(wire.RRTypeSRV, []byte{0x00, 0x0A, 0x00, 0x14, 0x1F, 0x90}),
			check: func(t *testing.T, got dns.RR) {
				if got != nil {
					t.Errorf("SRV with empty target = %v, want nil", got)
				}
			},
		},
		{
			name: "CNAME",
			rr:   mkRR(wire.RRTypeCNAME, []byte("alias.example.com.")),
			check: func(t *testing.T, got dns.RR) {
				cn, ok := got.(*dns.CNAME)
				if !ok {
					t.Fatalf("got %T, want *dns.CNAME", got)
				}
				if cn.Target != "alias.example.com." {
					t.Errorf("CNAME.Target = %q", cn.Target)
				}
			},
		},
		{
			name: "CNAME oversize name",
			rr:   mkRR(wire.RRTypeCNAME, longName),
			check: func(t *testing.T, got dns.RR) {
				if got != nil {
					t.Errorf("oversize CNAME target = %T, want nil", got)
				}
			},
		},
		{
			name: "NS",
			rr:   mkRR(wire.RRTypeNS, []byte("ns1.example.com.")),
			check: func(t *testing.T, got dns.RR) {
				ns, ok := got.(*dns.NS)
				if !ok {
					t.Fatalf("got %T, want *dns.NS", got)
				}
				if ns.Ns != "ns1.example.com." {
					t.Errorf("NS.Ns = %q", ns.Ns)
				}
			},
		},
		{
			name: "NS empty rdata",
			rr:   mkRR(wire.RRTypeNS, nil),
			check: func(t *testing.T, got dns.RR) {
				if got != nil {
					t.Errorf("empty NS rdata = %v, want nil", got)
				}
			},
		},
		{
			name: "SSHFP",
			rr:   mkRR(wire.RRTypeSSHFP, []byte{0x02, 0x01, 0xAB, 0xCD, 0xEF}),
			check: func(t *testing.T, got dns.RR) {
				fp, ok := got.(*dns.SSHFP)
				if !ok {
					t.Fatalf("got %T, want *dns.SSHFP", got)
				}
				if fp.Algorithm != 2 || fp.Type != 1 {
					t.Errorf("SSHFP alg/type = %d/%d", fp.Algorithm, fp.Type)
				}
				if fp.FingerPrint != "abcdef" {
					t.Errorf("SSHFP.FingerPrint = %q, want \"abcdef\"", fp.FingerPrint)
				}
			},
		},
		{
			name: "SSHFP missing fingerprint",
			rr:   mkRR(wire.RRTypeSSHFP, []byte{0x02, 0x01}),
			check: func(t *testing.T, got dns.RR) {
				if got != nil {
					t.Errorf("SSHFP without fingerprint = %v, want nil", got)
				}
			},
		},
		{
			name: "TLSA",
			rr:   mkRR(wire.RRTypeTLSA, []byte{0x03, 0x01, 0x01, 0x9A, 0xBC}),
			check: func(t *testing.T, got dns.RR) {
				td, ok := got.(*dns.TLSA)
				if !ok {
					t.Fatalf("got %T, want *dns.TLSA", got)
				}
				if td.Usage != 3 || td.Selector != 1 || td.MatchingType != 1 {
					t.Errorf("TLSA = %d/%d/%d", td.Usage, td.Selector, td.MatchingType)
				}
				if td.Certificate != "9abc" {
					t.Errorf("TLSA.Certificate = %q, want \"9abc\"", td.Certificate)
				}
			},
		},
		{
			name: "TLSA missing cert data",
			rr:   mkRR(wire.RRTypeTLSA, []byte{0x03, 0x01, 0x01}),
			check: func(t *testing.T, got dns.RR) {
				if got != nil {
					t.Errorf("TLSA without cert data = %v, want nil", got)
				}
			},
		},
		{
			name: "CAA",
			rr: mkRR(wire.RRTypeCAA, append(append([]byte{0x00, 0x05},
				[]byte("issue")...), []byte("letsencrypt.org")...)),
			check: func(t *testing.T, got dns.RR) {
				caa, ok := got.(*dns.CAA)
				if !ok {
					t.Fatalf("got %T, want *dns.CAA", got)
				}
				if caa.Flag != 0 || caa.Tag != "issue" || caa.Value != "letsencrypt.org" {
					t.Errorf("CAA = %d/%q/%q", caa.Flag, caa.Tag, caa.Value)
				}
			},
		},
		{
			name: "CAA critical flag preserved",
			rr: mkRR(wire.RRTypeCAA, append(append([]byte{0x80, 0x05},
				[]byte("issue")...), []byte("pki.example.com")...)),
			check: func(t *testing.T, got dns.RR) {
				caa, ok := got.(*dns.CAA)
				if !ok {
					t.Fatalf("got %T, want *dns.CAA", got)
				}
				if caa.Flag != 0x80 {
					t.Errorf("CAA.Flag = %#x, want 0x80", caa.Flag)
				}
			},
		},
		{
			name: "CAA tag length overruns rdata",
			rr:   mkRR(wire.RRTypeCAA, append([]byte{0x80, 0x40}, []byte("issue")...)), // tagLen=64 > remaining
			check: func(t *testing.T, got dns.RR) {
				if got != nil {
					t.Errorf("CAA overrun tag = %v, want nil", got)
				}
			},
		},
		{
			name: "CAA empty tag",
			rr:   mkRR(wire.RRTypeCAA, append([]byte{0x00, 0x00}, []byte("value")...)),
			check: func(t *testing.T, got dns.RR) {
				if got != nil {
					t.Errorf("CAA empty tag = %v, want nil", got)
				}
			},
		},
		{
			name: "CAA rdata too short",
			rr:   mkRR(wire.RRTypeCAA, []byte{0x00}),
			check: func(t *testing.T, got dns.RR) {
				if got != nil {
					t.Errorf("1-byte CAA = %v, want nil", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := freensRRToDNS(name, tt.rr, expires, fixedNow)
			tt.check(t, got)
			if got != nil {
				// Every mapped RR must be packable (well-formed for the wire).
				m := new(dns.Msg)
				m.SetQuestion(name, got.Header().Rrtype)
				m.Answer = []dns.RR{got}
				if _, err := m.Pack(); err != nil {
					t.Errorf("mapped RR does not pack: %v", err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// §9.2 step 3a — network alias-claim resolution (§7) via ClaimResolver
// ---------------------------------------------------------------------------

// withFastPoW lowers claims.PoWDifficultyInit to 8 for the duration of one
// test (restored on cleanup) so difficulty-8 claims are spec-valid through the
// default difficulty-inference path (Appendix A.4). These tests are
// intentionally NOT parallel: the claims difficulty is package state.
func withFastPoW(t *testing.T) {
	t.Helper()
	saved := claims.PoWDifficultyInit
	claims.PoWDifficultyInit = 8
	t.Cleanup(func() { claims.PoWDifficultyInit = saved })
}

// claimedWorld is a complete §7-registered fixture: a mined + W-witnessed
// alias claim embedded in a self-certifying TLD record, plus a www A record.
type claimedWorld struct {
	tldKP   *crypto.Keypair
	tldID   []byte
	claim   *claims.AliasClaim
	tldEnv  *wire.SignedEnvelope // TLD record carrying the claim in field 11
	wwwEnv  *wire.SignedEnvelope
	wwwIPv4 net.IP
}

// newClaimedWorld mines a difficulty-8 claim for alias (with W distinct
// witnesses, §7.3 quorum), embeds it in the TLD record (field 11), and builds
// the www.<alias> A record — the state the network would hold at K_claim,
// K_tld, and K_name after a §7.4/C.1 registration.
func newClaimedWorld(t *testing.T, alias string) *claimedWorld {
	t.Helper()
	withFastPoW(t)

	w := &claimedWorld{wwwIPv4: net.IPv4(203, 0, 113, 77)}
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

	// §7.3: mine the PoW at difficulty 8 (nonce_size 16 pins nonce[0]=8).
	claim, err := claims.MineAliasClaim(alias, tldKP, uint64(fixedNow-50), 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MineAliasClaim: %v", err)
	}
	// §7.3 witness quorum: W distinct node keypairs co-sign the claim.
	witnesses := make([]*claims.WitnessAttestation, 0, constants.W)
	for i := 0; i < constants.W; i++ {
		wkp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		w, err := claims.NewWitnessAttestation(wkp, uint64(fixedNow-50)+uint64(i), alias, tldID, tldKP.Public())
		if err != nil {
			t.Fatalf("NewWitnessAttestation: %v", err)
		}
		witnesses = append(witnesses, w)
	}
	claim.Witnesses = witnesses
	if !claims.VerifyFull(claim, claims.InferDifficulty, nil, constants.W) {
		t.Fatal("fixture: claim does not pass VerifyFull")
	}
	w.claim = claim

	// TLD record with the claim embedded (§7.4 step 5 / C.1 step 4).
	tldWire, err := naming.EncodeWireName(nil, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}
	tldRec, err := wire.NewRecord(tldWire, tldKP.Public(), 1, uint64(fixedNow-100), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	tldRec.Claim = cb
	w.tldEnv, err = wire.SignRecord(tldRec, tldKP)
	if err != nil {
		t.Fatal(err)
	}

	// www.<alias> direct-signed by the TLD key.
	wwwWire, err := naming.EncodeWireName([]string{"www"}, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec, err := wire.NewRecord(wwwWire, tldKP.Public(), 1, uint64(fixedNow-100), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	aRR, err := wire.A([]byte{203, 0, 113, 77}, 600)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec.RRset = []*wire.RR{aRR}
	w.wwwEnv, err = wire.SignRecord(wwwRec, tldKP)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// resignWithClaim returns a fresh TLD-record envelope whose embedded claim is
// a mutated (decoded → mutate → re-encoded) copy of the world's claim,
// re-signed by the TLD key so the envelope signature itself stays valid —
// isolating which CHECKLIST item (not the signature) rejects it.
func (w *claimedWorld) resignWithClaim(t *testing.T, alias string, mutate func(*claims.AliasClaim)) *wire.SignedEnvelope {
	t.Helper()
	claim, err := claims.DecodeAliasClaim(w.tldEnv.Record.Claim)
	if err != nil {
		t.Fatalf("decode fixture claim: %v", err)
	}
	mutate(claim)
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	rec := *w.tldEnv.Record // shallow copy: only Claim is replaced
	rec.Claim = cb
	env, err := wire.SignRecord(&rec, w.tldKP)
	if err != nil {
		t.Fatal(err)
	}
	if !env.VerifySignature() {
		t.Fatal("fixture: re-signed envelope must have a valid signature")
	}
	return env
}

// fakeClaimLookup is a RecordLookup + ClaimResolver backed by maps: records by
// wire_name (the §3b chain hops) and claim envelopes by alias (the §9.2 step-3a
// K_claim view). Returning a claim for an alias it was not registered under
// simulates a claim served under the wrong K_claim.
type fakeClaimLookup struct {
	fakeLookup
	claims map[string]*wire.SignedEnvelope
}

func newFakeClaimLookup() *fakeClaimLookup {
	return &fakeClaimLookup{fakeLookup: *newFakeLookup(), claims: map[string]*wire.SignedEnvelope{}}
}

// putClaim registers the claim envelope for alias and, as the chain[0] hop,
// its carrier TLD record.
func (f *fakeClaimLookup) putClaim(alias string, env *wire.SignedEnvelope) {
	f.claims[alias] = env
	f.put(env)
}

func (f *fakeClaimLookup) LookupClaim(_ context.Context, alias string, _ int64) (*wire.SignedEnvelope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.claims[alias], nil
}

// claimConfig routes "foo" into freens with NO alias pins — the network claim
// layer (§7) must carry the alias on its own.
func claimConfig() *Config {
	cfg, err := ParseConfig("[tld-routes]\n* = dns-first\n")
	if err != nil {
		panic(err)
	}
	cfg.TLDRoutes["foo"] = RouteFREENS
	return cfg
}

// resolveFoo runs www.foo. A through a resolver over the given lookup.
func resolveFoo(t *testing.T, lookup RecordLookup) ([]dns.RR, int, error) {
	t.Helper()
	r := newResolver(claimConfig(), lookup, nil)
	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	return rrs, rcode, err
}

// TestResolveQuestionFREENSViaNetworkClaim is THE §9.2 step-3a test: with no
// pin, the resolver pulls the claim envelope from the (fake) K_claim source,
// runs the full §7 checklist, derives tld_id = SHA-256(claimant_pk), and
// proceeds with the normal self-certifying chain walk to the A record.
func TestResolveQuestionFREENSViaNetworkClaim(t *testing.T) {
	w := newClaimedWorld(t, "foo")
	lookup := newFakeClaimLookup()
	lookup.putClaim("foo", w.tldEnv)
	lookup.put(w.wwwEnv)

	rrs, rcode, err := resolveFoo(t, lookup)
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
}

// TestResolveQuestionClaimBrokenWitnessSig: one corrupted witness signature
// drops the quorum to W-1 verified witnesses → the claim fails §7.4 step 2 →
// the freens branch misses (NXDOMAIN), even though the envelope signature is
// perfectly valid.
func TestResolveQuestionClaimBrokenWitnessSig(t *testing.T) {
	w := newClaimedWorld(t, "foo")
	broken := w.resignWithClaim(t, "foo", func(c *claims.AliasClaim) {
		c.Witnesses[0].Sig[0] ^= 0xff
	})
	lookup := newFakeClaimLookup()
	lookup.putClaim("foo", broken)
	lookup.put(w.wwwEnv)

	rrs, rcode, err := resolveFoo(t, lookup)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN(%d) for a broken witness signature", rcode, dns.RcodeNameError)
	}
	if len(rrs) != 0 {
		t.Errorf("len(rrs) = %d, want 0", len(rrs))
	}
}

// TestResolveQuestionClaimBelowQuorum: W-1 (valid) witnesses < W → no quorum
// → NXDOMAIN.
func TestResolveQuestionClaimBelowQuorum(t *testing.T) {
	w := newClaimedWorld(t, "foo")
	trimmed := w.resignWithClaim(t, "foo", func(c *claims.AliasClaim) {
		c.Witnesses = c.Witnesses[:constants.W-1]
	})
	lookup := newFakeClaimLookup()
	lookup.putClaim("foo", trimmed)
	lookup.put(w.wwwEnv)

	_, rcode, err := resolveFoo(t, lookup)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN(%d) below witness quorum", rcode, dns.RcodeNameError)
	}
}

// TestResolveQuestionClaimAliasMismatch: a claim registered for "bar" but
// served for "foo" must not resolve "foo" (the claim envelope is otherwise
// fully valid — the alias-match checklist item is what rejects it).
func TestResolveQuestionClaimAliasMismatch(t *testing.T) {
	w := newClaimedWorld(t, "bar")
	lookup := newFakeClaimLookup()
	// Serve the bar-claim under foo's lookup AND make the chain hops
	// resolvable so only the alias check can be failing.
	lookup.putClaim("foo", w.tldEnv)
	lookup.put(w.wwwEnv)

	_, rcode, err := resolveFoo(t, lookup)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN(%d) for an alias-mismatched claim", rcode, dns.RcodeNameError)
	}
}

// TestResolveQuestionClaimBadPoW: a tampered pow_hash (envelope re-signed so
// only the PoW check can fail) → NXDOMAIN.
func TestResolveQuestionClaimBadPoW(t *testing.T) {
	w := newClaimedWorld(t, "foo")
	bad := w.resignWithClaim(t, "foo", func(c *claims.AliasClaim) {
		c.PowHash[0] ^= 0xff
	})
	lookup := newFakeClaimLookup()
	lookup.putClaim("foo", bad)
	lookup.put(w.wwwEnv)

	_, rcode, err := resolveFoo(t, lookup)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN(%d) for a bad PoW hash", rcode, dns.RcodeNameError)
	}
}

// TestResolveQuestionClaimClaimantMismatch: claim.TldID pointing at a tld_id
// that is NOT SHA-256(claimant_pk) (claimant-consistency failure) → NXDOMAIN.
func TestResolveQuestionClaimClaimantMismatch(t *testing.T) {
	w := newClaimedWorld(t, "foo")
	bad := w.resignWithClaim(t, "foo", func(c *claims.AliasClaim) {
		c.TldID[0] ^= 0xff
	})
	lookup := newFakeClaimLookup()
	lookup.putClaim("foo", bad)
	lookup.put(w.wwwEnv)

	_, rcode, err := resolveFoo(t, lookup)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN(%d) for an inconsistent claimant/tld_id", rcode, dns.RcodeNameError)
	}
}

// TestResolveQuestionClaimWrongSigner: the claim envelope signed by a key
// OTHER than the claimant's TLD key fails the claimant-binding checklist item
// → NXDOMAIN (an attacker cannot carry someone's claim on their own record).
func TestResolveQuestionClaimWrongSigner(t *testing.T) {
	w := newClaimedWorld(t, "foo")
	other, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	rec := *w.tldEnv.Record
	env, err := wire.SignRecord(&rec, other)
	if err != nil {
		t.Fatal(err)
	}
	lookup := newFakeClaimLookup()
	lookup.putClaim("foo", env)
	lookup.put(w.wwwEnv)

	_, rcode, err := resolveFoo(t, lookup)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN(%d) for a non-claimant-signed claim envelope", rcode, dns.RcodeNameError)
	}
}

// TestResolveQuestionClaimGarbageField11: an envelope whose field 11 is not
// decodable AliasClaim CBOR is treated as "no claim" → NXDOMAIN (the chain
// hop for the TLD still exists via the record map, so the decode/checklist
// path is exercised, not the hop walk).
func TestResolveQuestionClaimGarbageField11(t *testing.T) {
	w := newClaimedWorld(t, "foo")
	rec := *w.tldEnv.Record
	rec.Claim = []byte{0x44, 0xde, 0xad, 0xbe, 0xef} // valid CBOR bstr, not an AliasClaim
	env, err := wire.SignRecord(&rec, w.tldKP)
	if err != nil {
		t.Fatal(err)
	}
	lookup := newFakeClaimLookup()
	lookup.putClaim("foo", env)
	lookup.put(w.wwwEnv)

	_, rcode, err := resolveFoo(t, lookup)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN(%d) for an undecodable claim", rcode, dns.RcodeNameError)
	}
}

// TestResolveQuestionClaimExpiredEnvelope: a claim envelope past its expiry
// fails IsBasicValid at `now` → NXDOMAIN (a claim cannot outlive the record
// that carries it).
func TestResolveQuestionClaimExpiredEnvelope(t *testing.T) {
	w := newClaimedWorld(t, "foo")
	tldWire, err := naming.EncodeWireName(nil, "foo", w.tldID)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(tldWire, w.tldKP.Public(), 1, uint64(fixedNow-7200), uint64(fixedNow-10))
	if err != nil {
		t.Fatal(err)
	}
	rec.Claim = w.tldEnv.Record.Claim
	expired, err := wire.SignRecord(rec, w.tldKP)
	if err != nil {
		t.Fatal(err)
	}
	lookup := newFakeClaimLookup()
	lookup.putClaim("foo", expired)
	lookup.put(w.wwwEnv)

	_, rcode, err := resolveFoo(t, lookup)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN(%d) for an expired claim envelope", rcode, dns.RcodeNameError)
	}
}

// TestResolveQuestionPinWinsOverClaim: §9.3 — a pin is local policy and
// ALWAYS beats the claim layer. The pin points at world2 while a fully valid
// claim points at world1; the answer must come from world2.
func TestResolveQuestionPinWinsOverClaim(t *testing.T) {
	w1 := newClaimedWorld(t, "foo")
	w2 := newClaimedWorld(t, "foo") // second, independent TLD for the same alias

	lookup := newFakeClaimLookup()
	lookup.putClaim("foo", w1.tldEnv) // network says world1
	lookup.put(w1.wwwEnv)
	lookup.put(w2.tldEnv)
	lookup.put(w2.wwwEnv)

	cfg := claimConfig()
	cfg.AliasPins = map[string][]byte{"foo": append([]byte(nil), w2.tldID...)} // pin says world2
	r := newResolver(cfg, lookup, nil)
	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR(%d)", rcode, dns.RcodeSuccess)
	}
	a, ok := rrs[0].(*dns.A)
	if !ok {
		t.Fatalf("rrs[0] is %T, want *dns.A", rrs[0])
	}
	if !a.A.Equal(w2.wwwIPv4) {
		t.Errorf("pin did not win: A.A = %s, want world2's %s", a.A, w2.wwwIPv4)
	}
}

// TestResolveQuestionNoClaimResolver: a RecordLookup WITHOUT the ClaimResolver
// extension and no pin keeps the previous pin-only behavior — NXDOMAIN
// (backward compatibility: the claim path is strictly additive).
func TestResolveQuestionNoClaimResolver(t *testing.T) {
	w := newClaimedWorld(t, "foo")
	lookup := newFakeLookup() // plain RecordLookup
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)

	_, rcode, err := resolveFoo(t, lookup)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN(%d) without a claim-capable source", rcode, dns.RcodeNameError)
	}
}
