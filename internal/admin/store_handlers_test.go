// store_handlers_test.go — GET /store and GET /difficulty over the real
// unix-socket server (the admin_test.go fixture pattern): a seeded claim
// envelope must appear twice (K_tld + K_claim) with the contest-set row
// flagged, lease fields must be sane, and difficulty must report the A.4
// baseline with no gossip observed.
package admin

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// seedClaimEnvelope publishes a register-style claim envelope for alias into
// lookup's store at K_tld AND K_claim (the §7.4/C.1 double-publish), mined at
// difficulty 8 for speed (the store listing does not verify PoW).
func seedClaimEnvelope(t *testing.T, lookup *dht.DHTLookup, alias string) {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	claim, err := claims.MineAliasClaim(alias, kp, uint64(time.Now().Unix()), 8, 2_000_000, 16)
	if err != nil {
		t.Fatal(err)
	}
	tldWire, err := naming.EncodeWireName(nil, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	rec, err := wire.NewRecord(tldWire, kp.Public(), 1, uint64(now), uint64(now+3600))
	if err != nil {
		t.Fatal(err)
	}
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	rec.Claim = cb
	rr, _ := wire.A([]byte{203, 0, 113, 71}, 300)
	rec.RRset = []*wire.RR{rr}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	kTld := tldID // zero labels ⇒ K_tld = tld_id
	kClaim, err := dht.KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}
	nowI := time.Now().Unix()
	if _, err := lookup.Store().Put(kTld, env, nowI, true); err != nil {
		t.Fatal(err)
	}
	if _, err := lookup.Store().Put(kClaim, env, nowI, true); err != nil {
		t.Fatal(err)
	}
}

func getJSON(t *testing.T, c *Client, path string, out any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.do(ctx, http.MethodGet, path, nil, out)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if resp != http.StatusOK {
		t.Fatalf("%s: status %d", path, resp)
	}
}

func TestStoreEndpoint(t *testing.T) {
	_, _, lookup, c := adminPair(t, "test")

	before := time.Now().Unix()
	seedClaimEnvelope(t, lookup, "storedemo")

	var res StoreResponse
	getJSON(t, c, "/store", &res)
	if res.Count != 2 {
		t.Fatalf("store count = %d, want 2 (K_tld + K_claim): %+v", res.Count, res.Entries)
	}
	var claimRows, apexRows int
	for _, e := range res.Entries {
		if e.Alias != "storedemo" {
			t.Errorf("entry %s: alias = %q, want storedemo", e.Key[:8], e.Alias)
		}
		if e.Sequence != 1 || !e.Claim || e.Revoked {
			t.Errorf("entry %s: unexpected fields %+v", e.Key[:8], e)
		}
		if e.Expires <= uint64(before) || e.ExpiresIn <= 0 || e.ExpiresIn > 3600 {
			t.Errorf("entry %s: lease fields off (expires_in=%d)", e.Key[:8], e.ExpiresIn)
		}
		if len(e.Labels) != 0 || e.TldIDB32 == "" {
			t.Errorf("entry %s: labels/tld_id not decoded", e.Key[:8])
		}
		if len(e.RRs) != 1 || e.RRs[0].Type != wire.RRTypeA || e.RRs[0].Text != "203.0.113.71" {
			t.Errorf("entry %s: rrs = %+v", e.Key[:8], e.RRs)
		}
		if e.Bytes < 100 {
			t.Errorf("entry %s: envelope size %d implausible", e.Key[:8], e.Bytes)
		}
		if e.ClaimKey {
			claimRows++
		} else {
			apexRows++
		}
	}
	if claimRows != 1 || apexRows != 1 {
		t.Errorf("claim_key rows = %d, apex rows = %d (want 1/1 — the same envelope at both keys)", claimRows, apexRows)
	}

	// Sanity: the flagged row's key is exactly K_claim.
	kc, err := dht.KeyForClaim("storedemo")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range res.Entries {
		if e.ClaimKey && e.Key == fmt.Sprintf("%x", kc) {
			found = true
		}
	}
	if !found {
		t.Error("the claim_key row's key is not K_claim(storedemo)")
	}
}

func TestStoreWithoutNode(t *testing.T) {
	sock := startAdmin(t, New(nil, nil, "test", nil))
	r, err := unixHTTP(sock).Get("http://admin/store")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("/store without a node = %d, want 503", r.StatusCode)
	}
}

func TestDifficultyEndpoint(t *testing.T) {
	_, _, _, c := adminPair(t, "test")
	var res Difficulty
	getJSON(t, c, "/difficulty", &res)
	if res.Difficulty != constants.PoWDifficultyInit {
		t.Errorf("difficulty = %d, want the baseline %d (no gossip observed)", res.Difficulty, constants.PoWDifficultyInit)
	}
	if res.PoWInit != constants.PoWDifficultyInit || res.WitnessQuorum != constants.W ||
		res.WitnessSet != constants.WitnessSet || res.RetargetBlock != constants.PoWRetargetBlock {
		t.Errorf("protocol constants wrong: %+v", res)
	}
}
