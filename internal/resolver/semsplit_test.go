package resolver

// semsplit_test.go — the 2026-09-18 decoupling: freens walk load must
// never starve conventional (upstream) resolution. Before the split, ONE
// 64-slot semaphore gated every cache-miss query; 80 concurrent freens
// lookups SERVFAILed 20/20 google.com queries (proven live on the test
// fleet — the OS then failed over to slower secondaries, which is why the
// class surfaced as "DNS latency varies" instead of outages).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/wire"
	"github.com/miekg/dns"
)

// blockingLookup is a RecordLookup whose Lookups park until released —
// it simulates a DHT walk costing "seconds" while the test holds the
// freens pool saturated.
type blockingLookup struct {
	release chan struct{}
	started chan struct{}
}

func newBlockingLookup(n int) *blockingLookup {
	return &blockingLookup{release: make(chan struct{}), started: make(chan struct{}, n)}
}

func (b *blockingLookup) Lookup(_ context.Context, _ []byte, _ int64) (*wire.SignedEnvelope, error) {
	b.started <- struct{}{}
	<-b.release
	return nil, errors.New("no record")
}

func TestFreensWalkLoadCannotStarveUpstream(t *testing.T) {
	// Fill the walk pool to capacity with parked "walks".
	const walkCap = 4 // small pool: easy to saturate deterministically
	bl := newBlockingLookup(walkCap)
	rr := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(93, 184, 216, 34)}
	up := &fakeUpstream{answer: []dns.RR{rr}, rcode: dns.RcodeSuccess}
	cfg, err := ParseConfig("[tld-routes]\nfootld = freens-first\n* = dns-first\n")
	if err != nil {
		t.Fatal(err)
	}
	pin := make([]byte, 32) // tld_id-shaped: 32 bytes or the record walk is skipped
	pin[0] = 7
	cfg.AliasPins = map[string][]byte{"footld": pin}
	r := newResolver(cfg, bl, up)
	r.MaxConcurrentResolutions = walkCap
	r.Cache = NewResponseCache(0, nil)
	t.Cleanup(bl.cleanup) // release parked lookups even on failure

	// walkCap concurrent freens-name queries park inside Lookup (each
	// holds a resSem slot). They MUST go through ResolveMsg — the
	// semaphores live in resolveShared, the client-facing wrapper — and
	// use DISTINCT names: same-name queries would join one flight
	// (single-flight by design) and occupy a single slot.
	for i := 0; i < walkCap; i++ {
		go func(i int) {
			m := new(dns.Msg)
			m.SetQuestion(fmt.Sprintf("parked%d.footld.", i), dns.TypeA)
			_ = r.ResolveMsg(context.Background(), m)
		}(i)
	}
	for i := 0; i < walkCap; i++ {
		select {
		case <-bl.started:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d parked walks started", i)
		}
	}

	// THE assertion: an upstream query answers normally while every walk
	// slot is occupied. (It must not share the walks' pool.)
	resp := serveOnce(t, r, "example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("upstream query under full walk load = rcode %d, %d answers (SERVFAIL means the pools still share)",
			resp.Rcode, len(resp.Answer))
	}

	// A freens-first query while the pool is full: refused, not queued.
	// Runs STRICTLY after the 4 starteds above, so all walk slots are
	// verifiably held by parked lookups.
	m := new(dns.Msg)
	m.SetQuestion("overflow.footld.", dns.TypeA)
	if got := r.ResolveMsg(context.Background(), m); got.Rcode != dns.RcodeServerFailure {
		t.Fatalf("overflow freens query = rcode %d, want SERVFAIL (the walk pool must refuse, never queue)", got.Rcode)
	}
}

func (b *blockingLookup) cleanup() { close(b.release) }
