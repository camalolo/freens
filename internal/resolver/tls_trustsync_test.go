// tls_trustsync_test.go — §9.5.4: the resolver's trust-sync notifications.
// The sink must hear about VERIFIED owner CAs (and never about anything the
// DNS path would not answer from), and about definite alias deaths.
package resolver

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/tlsca"
	"github.com/camalolo/freens/internal/wire"
	"github.com/miekg/dns"
)

// captureSync is a TLSTrustSync test double recording every notification.
type captureSync struct {
	mu    sync.Mutex
	cas   []caCall
	deads []deadCall
	delay time.Duration // artificial sink latency (race testing)
}

type caCall struct {
	alias   string
	tldID   []byte
	caDER   []byte
	expires int64
}

type deadCall struct {
	alias string
	tldID []byte
}

func (c *captureSync) OnOwnerCA(alias string, tldID, caDER []byte, expires int64) {
	if c.delay > 0 {
		time.Sleep(c.delay)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cas = append(c.cas, caCall{alias, tldID, caDER, expires})
}

func (c *captureSync) OnAliasDead(alias string, tldID []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deads = append(c.deads, deadCall{alias, tldID})
}

func (c *captureSync) caCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cas)
}

func (c *captureSync) deadCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.deads)
}

// waitFor polls until cond or the deadline — the notifications are async.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("timed out waiting for trust-sync notification")
}

// addTLSCA re-signs w's apex with a TLSCA RR carrying the owner CA derived
// from the TLD key's seed (the real §9.5.1 derivation).
func addTLSCA(t *testing.T, w *claimedWorld, alias string) []byte {
	t.Helper()
	caDER, _, err := tlsca.OwnerCA(w.tldKP.Seed(), alias, time.Unix(fixedNow, 0))
	if err != nil {
		t.Fatal(err)
	}
	rr, err := wire.NewRR(wire.RRTypeTLSCA, 3600, caDER)
	if err != nil {
		t.Fatal(err)
	}
	rec := *w.tldEnv.Record
	rec.RRset = append(append([]*wire.RR(nil), rec.RRset...), rr)
	env, err := wire.SignRecord(&rec, w.tldKP)
	if err != nil {
		t.Fatal(err)
	}
	if !env.VerifySignature() {
		t.Fatal("fixture: TLSCA-carrying apex signature invalid")
	}
	w.tldEnv = env
	return caDER
}

func TestTrustSyncNotifiedOnVerifiedOwnerCA(t *testing.T) {
	w := newClaimedWorld(t, "foo")
	caDER := addTLSCA(t, w, "foo")
	lookup := newFakeClaimLookup()
	lookup.putClaim("foo", w.tldEnv)
	lookup.put(w.wwwEnv)

	sync := &captureSync{}
	r := newResolver(claimConfig(), lookup, nil)
	r.TLSSync = sync
	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil || rcode != dns.RcodeSuccess || len(rrs) != 1 {
		t.Fatalf("answer broken by the hook: rcode=%d len=%d err=%v", rcode, len(rrs), err)
	}
	waitFor(t, func() bool { return sync.caCount() == 1 })
	if got := sync.deads; len(got) != 0 {
		t.Fatalf("unexpected dead signal: %+v", got)
	}
	call := sync.cas[0]
	if call.alias != "foo" {
		t.Fatalf("alias = %q, want foo", call.alias)
	}
	if !bytesEq(call.caDER, caDER) {
		t.Fatal("caDER bytes do not match the apex TLSCA RR")
	}
	if call.expires != int64(w.tldEnv.Record.Expires) {
		t.Fatalf("expires = %d, want %d", call.expires, w.tldEnv.Record.Expires)
	}
}

func TestTrustSyncSilentWithoutTLSCA(t *testing.T) {
	w := newClaimedWorld(t, "foo") // no TLSCA in the apex
	lookup := newFakeClaimLookup()
	lookup.putClaim("foo", w.tldEnv)
	lookup.put(w.wwwEnv)
	sync := &captureSync{}
	r := newResolver(claimConfig(), lookup, nil)
	r.TLSSync = sync
	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if _, rcode, _, err := r.ResolveQuestion(context.Background(), q); err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("answer broken: rcode=%d err=%v", rcode, err)
	}
	time.Sleep(50 * time.Millisecond)
	if sync.caCount() != 0 || sync.deadCount() != 0 {
		t.Fatal("notifications fired for a TLSCA-less namespace")
	}
}

// A revoked apex (§8.5): the claim carriers are revoked too, so the claim
// set has no live winner — the resolver NXDOMAINs with no tld_id, and trust
// sync must hear the death (purge regardless of identity).
func TestTrustSyncNotifiedOnRevokedAlias(t *testing.T) {
	w := newClaimedWorld(t, "foo")
	addTLSCA(t, w, "foo")
	// Re-sign the claim carrier as a tombstone (revoke = true, rrset nil).
	rec := *w.tldEnv.Record
	b := true
	rec.Revoke = &b
	rec.RRset = nil
	tomb, err := wire.SignRecord(&rec, w.tldKP)
	if err != nil {
		t.Fatal(err)
	}
	lookup := newFakeClaimLookup()
	lookup.putClaim("foo", tomb)

	sync := &captureSync{}
	r := newResolver(claimConfig(), lookup, nil)
	r.TLSSync = sync
	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	_, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("ResolveQuestion: %v", err)
	}
	_ = rcode // NXDOMAIN or its DNS-first fallthrough is fine; the point is the signal
	waitFor(t, func() bool { return sync.deadCount() == 1 })
	if got := sync.deads[0]; got.alias != "foo" {
		t.Fatalf("dead alias = %q, want foo", got.alias)
	}
	// Either flavor is correct: a nil tldID (claim layer found no live
	// winner — purge regardless of identity) or the concrete tldID (the walk
	// reached the tombstoned apex — definite identity purge). Both purge.
	if got := len(sync.deads[0].tldID); got != 0 && got != 32 {
		t.Fatalf("tldID on death signal is %d bytes, want 0 or 32", got)
	}
	if sync.caCount() != 0 {
		t.Fatal("OnOwnerCA fired for a revoked namespace")
	}
}

// A revoked SUB-name must NOT kill the alias-level CA (the apex is healthy);
// the owner CA notification still fires.
func TestTrustSyncKeptOnSubNameRevoke(t *testing.T) {
	w := newClaimedWorld(t, "foo")
	caDER := addTLSCA(t, w, "foo")
	// host1.foo: revoked (tombstone at the sub-name's K_name).
	subWire, err := naming.EncodeWireName([]string{"host1"}, "foo", w.tldID)
	if err != nil {
		t.Fatal(err)
	}
	subRec, err := wire.NewRecord(subWire, w.tldKP.Public(), 1, uint64(fixedNow-100), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	b := true
	subRec.Revoke = &b
	subTomb, err := wire.SignRecord(subRec, w.tldKP)
	if err != nil {
		t.Fatal(err)
	}
	lookup := newFakeClaimLookup()
	lookup.putClaim("foo", w.tldEnv)
	lookup.put(w.wwwEnv)
	lookup.put(subTomb)

	sync := &captureSync{}
	r := newResolver(claimConfig(), lookup, nil)
	r.TLSSync = sync
	// www.foo still answers; the TLSCA must be re-notified, no death signal.
	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if _, rcode, _, err := r.ResolveQuestion(context.Background(), q); err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("www.foo should still answer: rcode=%d err=%v", rcode, err)
	}
	waitFor(t, func() bool { return sync.caCount() == 1 })
	if !bytesEq(sync.cas[0].caDER, caDER) {
		t.Fatal("caDER mismatch")
	}
	time.Sleep(50 * time.Millisecond)
	if sync.deadCount() != 0 {
		t.Fatalf("sub-name revoke killed the alias CA: %+v", sync.deads)
	}
	// And the tombstoned sub-name itself NXDOMAINs (spec §8.5), still without
	// a death signal for the alias.
	q2 := dns.Question{Name: "host1.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, _, err := r.ResolveQuestion(context.Background(), q2)
	if err != nil {
		t.Fatalf("host1.foo: %v", err)
	}
	if rcode != dns.RcodeNameError || len(rrs) != 0 {
		t.Fatalf("revoked sub-name answered: rcode=%d len=%d", rcode, len(rrs))
	}
	time.Sleep(50 * time.Millisecond)
	if sync.deadCount() != 0 {
		t.Fatalf("sub-name tombstone produced an alias death signal: %+v", sync.deads)
	}
}

// The sink runs asynchronously: a SLOW sink must not delay the DNS answer.
func TestTrustSyncAsyncNeverBlocks(t *testing.T) {
	w := newClaimedWorld(t, "foo")
	addTLSCA(t, w, "foo")
	lookup := newFakeClaimLookup()
	lookup.putClaim("foo", w.tldEnv)
	lookup.put(w.wwwEnv)
	sync := &captureSync{delay: 250 * time.Millisecond}
	r := newResolver(claimConfig(), lookup, nil)
	r.TLSSync = sync
	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	start := time.Now()
	if _, _, _, err := r.ResolveQuestion(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("slow sink delayed the answer by %s", elapsed)
	}
	waitFor(t, func() bool { return sync.caCount() == 1 })
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
