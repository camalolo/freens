// daemon.go — the web UI's view of the daemon: a thin wrapper around
// admin.Client (same unix socket the CLI uses) exposing every endpoint the
// pages need. An interface so handler tests can drive pages without a
// daemon.
package webui

import (
	"context"
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

// daemonClient adapts *admin.Client to Daemon (the socket path is fixed at
// construction; the CLI's EnvSock override is honored identically).
type daemonClient struct{ c *admin.Client }

// NewDaemonClient wraps the daemon's admin socket as a Daemon.
func NewDaemonClient(sock string) Daemon {
	return &daemonClient{c: &admin.Client{Sock: sock, Timeout: 30 * time.Second}}
}

func (d *daemonClient) Status(ctx context.Context) (*admin.Status, error) {
	return d.c.Status(ctx)
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
