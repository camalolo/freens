// daemon.go — the web UI's view of the daemon: a thin wrapper around
// admin.Client (same unix socket the CLI uses) exposing every endpoint the
// pages need. An interface so handler tests can drive pages without a
// daemon.
package webui

import (
	"context"
	"sync"
	"time"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/wire"
)

// Daemon is everything the UI needs from the freens daemon. Satisfied by
// NewDaemonClient (admin socket) and fakes in tests.
type Daemon interface {
	Status(ctx context.Context) (*admin.Status, error)
	Peers(ctx context.Context) ([]dht.Peer, error)
	Resolve(ctx context.Context, name string) (*admin.Resolved, error)
	Publish(ctx context.Context, env *wire.SignedEnvelope) (int, error)
	PublishClaim(ctx context.Context, env *wire.SignedEnvelope) error
	Get(ctx context.Context, key []byte) (*wire.SignedEnvelope, error)
	Witness(ctx context.Context, alias string, tldID, claimant []byte, ts uint64, nonce, powHash []byte) ([][]byte, error)
	Store(ctx context.Context) (*admin.StoreResponse, error)
	Difficulty(ctx context.Context) (*admin.Difficulty, error)
}

// statusTTL bounds how stale a cached Status may be. One second collapses
// the per-render double fetch (base()'s version lookup + the page's own
// Status call — the dashboard asked twice per hit) and the per-hit daemon
// round trip unauthenticated /login paid, without ever showing meaningfully
// stale data (audit F4).
const statusTTL = time.Second

// daemonClient adapts *admin.Client to Daemon (the socket path is fixed at
// construction; the CLI's EnvSock override is honored identically).
type daemonClient struct {
	c *admin.Client

	// Status cache: (result, fetchedAt) guarded by statusMu. Successful
	// results are replayed for statusTTL; failures are NEVER cached, so a
	// daemon that just came back is noticed within one request. The mutex
	// is dropped for the RPC itself — a slow daemon must not serialize
	// unrelated requests — so a small herd may redundantly fetch when the
	// entry expires together; harmless (the answer is idempotent, and
	// readers treat the shared *admin.Status as immutable, only copying
	// scalars out of it).
	statusMu sync.Mutex
	status   *admin.Status
	statusAt time.Time
}

// NewDaemonClient wraps the daemon's admin socket as a Daemon.
func NewDaemonClient(sock string) Daemon {
	return &daemonClient{c: &admin.Client{Sock: sock, Timeout: 30 * time.Second}}
}

func (d *daemonClient) Status(ctx context.Context) (*admin.Status, error) {
	d.statusMu.Lock()
	if d.status != nil && time.Since(d.statusAt) < statusTTL {
		st := d.status
		d.statusMu.Unlock()
		return st, nil
	}
	d.statusMu.Unlock()
	st, err := d.c.Status(ctx)
	if err != nil {
		return nil, err // failures are not cached
	}
	d.statusMu.Lock()
	d.status, d.statusAt = st, time.Now()
	d.statusMu.Unlock()
	return st, nil
}

func (d *daemonClient) Peers(ctx context.Context) ([]dht.Peer, error) {
	return d.c.Peers(ctx)
}

func (d *daemonClient) Resolve(ctx context.Context, name string) (*admin.Resolved, error) {
	return d.c.Resolve(ctx, name)
}

func (d *daemonClient) Publish(ctx context.Context, env *wire.SignedEnvelope) (int, error) {
	return d.c.Publish(ctx, env)
}

func (d *daemonClient) PublishClaim(ctx context.Context, env *wire.SignedEnvelope) error {
	return d.c.PublishClaim(ctx, env)
}

func (d *daemonClient) Get(ctx context.Context, key []byte) (*wire.SignedEnvelope, error) {
	return d.c.Get(ctx, key)
}

func (d *daemonClient) Witness(ctx context.Context, alias string, tldID, claimant []byte, ts uint64, nonce, powHash []byte) ([][]byte, error) {
	return d.c.Witness(ctx, alias, tldID, claimant, ts, nonce, powHash)
}

func (d *daemonClient) Store(ctx context.Context) (*admin.StoreResponse, error) {
	return d.c.Store(ctx)
}

func (d *daemonClient) Difficulty(ctx context.Context) (*admin.Difficulty, error) {
	return d.c.Difficulty(ctx)
}
