package resolver

import (
	"context"
	"errors"
	"sync"

	"github.com/miekg/dns"
)

// UpstreamRef is a hot-swappable Upstream: an atomic current-value cell that
// itself implements Upstream by delegation. The daemon builds its resolver
// against ONE UpstreamRef at startup and `freens doh` / the webui Settings
// page / POST admin /reload swap the value underneath (v0.14.0 §9.6) — so
// enabling or disabling the DoH upstream takes effect on the NEXT query,
// with no daemon restart and no torn read (in-flight queries finish on the
// upstream they started with).
//
// The zero value is NOT usable (a nil current value forwards to a nil
// Upstream and panics); always construct with NewUpstreamRef.
type UpstreamRef struct {
	mu sync.RWMutex
	u  Upstream
}

// NewUpstreamRef wraps u (which may be nil — Forward then errors, matching
// a plain nil Upstream's "no upstream configured" semantics).
func NewUpstreamRef(u Upstream) *UpstreamRef {
	return &UpstreamRef{u: u}
}

// Set swaps the current upstream. Safe for concurrent use with Forward.
func (r *UpstreamRef) Set(u Upstream) {
	r.mu.Lock()
	r.u = u
	r.mu.Unlock()
}

// Get returns the current upstream (nil when none).
func (r *UpstreamRef) Get() Upstream {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.u
}

// errNoUpstream mirrors DNSUpstream's "nothing configured" answer for an
// empty ref.
var errNoUpstream = errors.New("resolver: no upstream servers configured")

// Forward implements Upstream by delegating to the current value. nil ⇒ the
// standard "no upstream servers configured" error.
func (r *UpstreamRef) Forward(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	u := r.Get()
	if u == nil {
		return nil, errNoUpstream
	}
	return u.Forward(ctx, q)
}
