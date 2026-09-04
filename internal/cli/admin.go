// admin.go — the admin-awareness core: every live-network subcommand picks
// one of two transports.
//
//	-peers given                 -> standalone one-shot DHT node (classic mode)
//	no -peers, daemon alive      -> the user's running daemon via its admin
//	                                socket (internal/admin): publish/resolve/
//	                                get/register's witnesses all ride the
//	                                daemon's already-connected routing table
//	neither                      -> errNoDaemon, which tells the user exactly
//	                                what to run
package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/keychain"
)

// adminTimeout bounds every admin-socket round trip from the CLI side.
const adminTimeout = 15 * time.Second

// errNoDaemon is the standing error when neither a -peers list nor a living
// daemon exists. The wording is the product decision: setup is the fix.
var errNoDaemon = errors.New("no -peers given and no running freens daemon found (start one with: freens setup)")

// maybeAdmin returns a client for the user's running daemon when one answers
// on the admin socket, else nil. This is THE helper that makes the CLI
// admin-aware: callers treat a nil result as "standalone mode required".
func maybeAdmin() *admin.Client {
	sock := home.AdminSock()
	if admin.Alive(sock) {
		return &admin.Client{Sock: sock, Timeout: adminTimeout}
	}
	return nil
}

// adminCtx is the per-call context for admin round trips.
func adminCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), adminTimeout)
}

// publishTimeout bounds one admin-mediated publish INCLUDING its daemon-side
// job (the client polls GET /job/{id} under this budget). The keyed K_claim
// leg walks its own keyspace and can run for tens of seconds on a busy node
// — a 15 s budget killed the CLI mid-publish while the daemon-side job
// completed a minute later (found live 2026-08-31).
const publishTimeout = 2 * time.Minute

// publishCtx is the context for Publish/PublishClaim round trips.
func publishCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), publishTimeout)
}

// adminResolved aliases admin.Resolved (resolved-name answer) for the
// pretty-printer in dht.go.
type adminResolved = admin.Resolved

// adminRR aliases admin.RR (one resolved resource record).
type adminRR = admin.RR

// transport is the resolved network access mode of a live-network
// subcommand: exactly one of client (daemon) or peers (standalone) is set.
type transport struct {
	client *admin.Client // non-nil: use the running daemon
	peers  []dht.Peer    // non-empty: standalone mode with these bootstraps
}

// pickTransport implements the admin-awareness rule shared by publish /
// resolve / get / register / name:
//
//	-peers non-empty -> standalone (parse + fail on typos, as today)
//	daemon alive     -> daemon
//	neither          -> errNoDaemon
func pickTransport(peersCSV string) (*transport, error) {
	if strings.TrimSpace(peersCSV) != "" {
		peers, err := parsePeerList(peersCSV)
		if err != nil {
			return nil, err
		}
		return &transport{peers: peers}, nil
	}
	if c := maybeAdmin(); c != nil {
		return &transport{client: c}, nil
	}
	return nil, errNoDaemon
}

// daemon reports whether the transport is the running daemon.
func (t *transport) daemon() bool { return t != nil && t.client != nil }

// firstAdminIP extracts the first A-record address from an admin Resolved
// RRset — falling back to AAAA (16-byte rdata) when no A exists — the
// apex-IP inheritance rule of `name` (v4 preferred, v6 capable).
func firstAdminIP(rrs []admin.RR) string {
	if ip := firstAdminAIP(rrs); ip != "" {
		return ip
	}
	for _, rr := range rrs {
		if rr.Text != "" {
			if ip := net.ParseIP(rr.Text); ip != nil && ip.To4() == nil && ip.To16() != nil {
				return ip.To16().String()
			}
		}
		d, err := base64.StdEncoding.DecodeString(rr.Rdata)
		if err != nil || len(d) != net.IPv6len {
			continue
		}
		if ip := net.IP(d); ip.To4() == nil {
			return ip.String()
		}
	}
	return ""
}

// firstAdminAIP extracts the first A-record address from an admin Resolved
// RRset — the apex-IP inheritance rule of `name`. The daemon renders A
// records' dotted quad in RR.Text ("rdata_text"); when absent the base64
// rdata ("rdata_b64") is decoded and its length checked (an A record is
// exactly 4 opaque bytes).
func firstAdminAIP(rrs []admin.RR) string {
	for _, rr := range rrs {
		if rr.Text != "" {
			if ip := net.ParseIP(rr.Text); ip != nil && ip.To4() != nil {
				return ip.To4().String()
			}
		}
		d, err := base64.StdEncoding.DecodeString(rr.Rdata)
		if err != nil || len(d) != net.IPv4len {
			continue
		}
		if ip := net.IP(d).To4(); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// keychain helpers
// ---------------------------------------------------------------------------

// keychainAliases lists the aliases that have an owner key in the freens
// keychain (home.KeysDir(), sorted) — the "which namespaces can I manage"
// answer used by name/status/doctor. (Implementation lives once in
// internal/keychain, shared with the web UI.)
func keychainAliases() []string {
	return keychain.Aliases(home.KeysDir())
}

// ownerKeyPath is the keychain location of alias' owner key.
func ownerKeyPath(alias string) string {
	return keychain.OwnerKeyPath(home.KeysDir(), alias)
}
