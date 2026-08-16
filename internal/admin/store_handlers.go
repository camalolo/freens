// store_handlers.go — two read-only endpoints added for the web UI (and any
// future tooling): GET /store (the daemon's live envelope store) and
// GET /difficulty (the Appendix A.4 oracle). Both honor the admin socket's
// contract: pure reads, no configuration mutation, JSON like every other
// endpoint.
package admin

import (
	"encoding/base32"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// StoreEntry is one live envelope of GET /store (exported: the CLI/web UI
// client consumes it).
type StoreEntry struct {
	Key       string   `json:"key"`             // hex storage key (K_tld / K_name / K_claim)
	Labels    []string `json:"labels"`          // display labels under the alias (empty = the apex itself)
	TldIDB32  string   `json:"tld_id_b32"`      // the namespace the record lives in
	Alias     string   `json:"alias,omitempty"` // the claimed alias, on claim-carrying envelopes
	Sequence  uint64   `json:"sequence"`
	Created   uint64   `json:"created"`
	Expires   uint64   `json:"expires"`
	ExpiresIn int64    `json:"expires_in"` // seconds from now (negative = lapsed)
	Revoked   bool     `json:"revoked"`
	Owner     string   `json:"owner"`     // hex signer pk
	Claim     bool     `json:"claim"`     // carries a §7.4 AliasClaim (field 11)
	ClaimKey  bool     `json:"claim_key"` // this row IS the K_claim copy (contest set)
	RRs       []RR     `json:"rrs,omitempty"`
	Bytes     int      `json:"bytes"` // canonical envelope size
}

type StoreResponse struct {
	Entries []StoreEntry `json:"entries"`
	Count   int          `json:"count"`
}

// handleStore lists the daemon's live envelope store (§6.4) — every envelope
// this node is serving, with decoded names, lease state, and RRsets.
// Read-only; the store's own expiry/eviction semantics decide what is live.
func (s *Server) handleStore(w http.ResponseWriter, r *http.Request) {
	if s.lookup == nil {
		errNoNode(w)
		return
	}
	now := time.Now().Unix()
	out := StoreResponse{Entries: []StoreEntry{}}
	for _, e := range s.lookup.Store().Entries(now) {
		if e.Env == nil || e.Env.Record == nil {
			continue
		}
		rec := e.Env.Record
		entry := StoreEntry{
			Key:      hex.EncodeToString(e.Key),
			Sequence: rec.Sequence,
			Created:  rec.Created,
			Expires:  rec.Expires,
			Revoked:  e.Env.IsRevoked(),
			Owner:    hex.EncodeToString(e.Env.Signer),
			Claim:    len(rec.Claim) > 0,
		}
		if int64(entry.Expires) > now {
			entry.ExpiresIn = int64(entry.Expires) - now
		}
		if labels, tldID, err := naming.DecodeWireName(rec.Name); err == nil {
			entry.Labels = labels
			entry.TldIDB32 = tldB32(tldID)
		}
		// Claim-carrying envelopes: decode the embedded claim for the alias,
		// and mark the row that IS K_claim (the contest-set copy §7.4/C.1
		// store at both keys — the same envelope appears twice).
		if entry.Claim {
			if c, err := claims.DecodeAliasClaim(rec.Claim); err == nil {
				entry.Alias = c.Alias
				if k, err := dht.KeyForClaim(c.Alias); err == nil && hex.EncodeToString(k) == entry.Key {
					entry.ClaimKey = true
				}
			}
		}
		for _, rr := range rec.RRset {
			entry.RRs = append(entry.RRs, rrJSON(rr))
		}
		if b, err := e.Env.Bytes(); err == nil {
			entry.Bytes = len(b)
		}
		out.Entries = append(out.Entries, entry)
	}
	out.Count = len(out.Entries)
	writeJSON(w, http.StatusOK, out)
}

// Difficulty is the GET /difficulty response (exported for the client).
type Difficulty struct {
	Difficulty     int `json:"difficulty"`      // effective mining/verify floor (bits)
	PoWInit        int `json:"pow_init"`        // protocol baseline (constants.PoWDifficultyInit)
	WitnessQuorum  int `json:"witness_quorum"`  // W (§7.3)
	WitnessSet     int `json:"witness_set"`     // candidates per walk
	RetargetBlock  int `json:"retarget_block"`  // claims per retarget (A.4)
	TargetInterval int `json:"target_interval"` // seconds per claim the retarget aims at
}

// handleDifficulty reports the Appendix A.4 difficulty this node verifies at
// (the DHTLookup oracle's median of observed peer values, falling back to
// this node's own current D, falling back to the protocol baseline). The web
// UI's register form shows it so users know what they are about to pay for.
func (s *Server) handleDifficulty(w http.ResponseWriter, r *http.Request) {
	d := constants.PoWDifficultyInit
	if s.lookup != nil {
		d = s.lookup.NetworkDifficulty()
	}
	writeJSON(w, http.StatusOK, Difficulty{
		Difficulty:     d,
		PoWInit:        constants.PoWDifficultyInit,
		WitnessQuorum:  constants.W,
		WitnessSet:     constants.WitnessSet,
		RetargetBlock:  constants.PoWRetargetBlock,
		TargetInterval: int(constants.PoWTargetInterval),
	})
}

// tldB32 renders a tld_id in the display convention (lowercase RFC 4648
// base32, padding stripped).
func tldB32(tldID []byte) string {
	return strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(tldID), "="))
}

// rrJSON renders one wire RR with the human rdata filled for the types the
// store page shows (A/AAAA dotted/literal, TXT verbatim).
func rrJSON(rr *wire.RR) RR {
	out := RR{
		Type:  rr.Type,
		TTL:   rr.TTL,
		Rdata: "",
	}
	switch rr.Type {
	case wire.RRTypeA, wire.RRTypeAAAA:
		if ip := net.IP(rr.Rdata); ip != nil {
			if (len(rr.Rdata) == 4 && ip.To4() != nil) || len(rr.Rdata) == 16 {
				out.Text = ip.String()
			}
		}
	case wire.RRTypeTXT:
		out.Text = string(rr.Rdata)
	}
	return out
}
