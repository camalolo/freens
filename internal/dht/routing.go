// Package dht — routing.go implements the 256-bucket Kademlia routing table
// described in specifications.md §6.2 (Node identity and routing): 256
// k-buckets (one per bit prefix length), constants.K (20) entries per bucket,
// with the simplified eviction variant called out in §6.2 — when a bucket is
// full, a new contact is *not* inserted and the oldest (least-recently-seen)
// entry is returned as a "ping candidate" so the RPC layer can perform live
// eviction (ping-oldest; on failure, remove the candidate and re-add).
//
// Re-adding an already-known contact refreshes it: its fields are updated and
// it is moved to the tail (most-recently-seen) of its bucket.
//
// This file ports archive/python-v0.1/freens/dht/routing.py. Pure stdlib.
package dht

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/camalolo/freens/internal/constants"
)

// numBuckets is the number of k-buckets — one per bit prefix length of a
// 256-bit ID.
const numBuckets = 256

// NodeContact is a peer known to the routing table. Identity is the 32-byte
// NodeID (= SHA-256(PublicKey)); the public key is stored alongside so that
// signatures on incoming RPCs can be verified without a separate lookup.
// Addr is the "ip:port" form. LastSeen is a unix timestamp updated on
// add/refresh. ConfirmedAt is the last time THIS node exchanged directly
// with the contact (a verified inbound message, or a successful RPC round
// trip): advertisement alone ({nodes} lists) never advances it — that is
// the anti-ghost invariant (issue #2): a dead contact re-taught by peers
// must not look alive.
//
// A node may legitimately be reachable at MORE than one address — the
// canonical case is a daemon holding its public IP while also sitting on
// the operator's LAN (the community seed: WAN + LAN simultaneously). Alts
// keeps those other known addresses with their own recency so the table
// accumulates them instead of flip-flopping the single Addr field between
// them (found live 2026-09-01: the desktop's view of the seed alternated
// between its WAN and LAN address on every re-learn, and a probe timeout
// against whichever address was currently stored evicted the node whole).
// Addr always mirrors the PREFERRED address — the freshest-confirmed one,
// or the most-recently-seen when none was ever confirmed — because that is
// the address probes use and {nodes} lists advertise. Alts may be nil.
type NodeContact struct {
	NodeID      []byte // 32 bytes (SHA-256(PublicKey))
	PublicKey   []byte // 32 bytes (Ed25519 verifying key)
	Addr        string // "ip:port" — the preferred address (see type doc)
	LastSeen    int64  // unix seconds
	ConfirmedAt int64  // unix seconds; 0 = never directly confirmed

	Alts []AddrState `json:"alts,omitempty"` // other known addresses, preferred excluded
}

// AddrState is one known address of a (multi-homed) contact, with the same
// recency semantics as the contact-level fields — ConfirmedAt is only
// advanced by direct verified exchanges with that exact address, never by
// advertisement.
type AddrState struct {
	Addr        string `json:"addr"`
	LastSeen    int64  `json:"last_seen"`
	ConfirmedAt int64  `json:"confirmed_at,omitempty"`
}

// maxAddrsPerContact caps how many distinct addresses are tracked per node
// (preferred + Alts). NAT-mapped ephemeral source addresses can churn; the
// LRU drop in AddOrRefresh keeps the list to the genuinely-used ones.
const maxAddrsPerContact = 4

// NewNodeContact validates and constructs a NodeContact. nodeID and publicKey
// must each be 32 bytes; addr must be non-empty. The byte slices are copied
// so the contact does not alias caller memory.
func NewNodeContact(nodeID, publicKey []byte, addr string, lastSeen int64) (*NodeContact, error) {
	if len(nodeID) != constants.NodeIDLen {
		return nil, fmt.Errorf("dht: node_id must be %d bytes, got %d", constants.NodeIDLen, len(nodeID))
	}
	if len(publicKey) != constants.Ed25519PublicKeyLen {
		return nil, fmt.Errorf("dht: public_key must be %d bytes, got %d", constants.Ed25519PublicKeyLen, len(publicKey))
	}
	if addr == "" {
		return nil, errors.New("dht: addr must be non-empty")
	}
	id := make([]byte, len(nodeID))
	copy(id, nodeID)
	pk := make([]byte, len(publicKey))
	copy(pk, publicKey)
	return &NodeContact{
		NodeID:    id,
		PublicKey: pk,
		Addr:      addr,
		LastSeen:  lastSeen,
	}, nil
}

// clone returns a deep copy of the contact (independent byte slices) so callers
// can read fields without racing an in-place refresh performed under the
// routing-table lock.
func (c *NodeContact) clone() *NodeContact {
	if c == nil {
		return nil
	}
	cc := &NodeContact{
		NodeID:      append([]byte(nil), c.NodeID...),
		PublicKey:   append([]byte(nil), c.PublicKey...),
		Addr:        c.Addr,
		LastSeen:    c.LastSeen,
		ConfirmedAt: c.ConfirmedAt,
	}
	if len(c.Alts) > 0 {
		cc.Alts = make([]AddrState, len(c.Alts))
		copy(cc.Alts, c.Alts)
	}
	return cc
}

// KBucket is a single k-bucket: at most Capacity NodeContact entries ordered
// oldest-first (Nodes[0] = least-recently-seen / eviction candidate;
// Nodes[len-1] = most-recently-seen).
type KBucket struct {
	Index    int
	Capacity int
	Nodes    []*NodeContact
}

// IsFull reports whether the bucket is at capacity.
func (b *KBucket) IsFull() bool {
	return len(b.Nodes) >= b.Capacity
}

// Get returns the contact with the given nodeID, or nil if absent.
func (b *KBucket) Get(nodeID []byte) *NodeContact {
	for _, c := range b.Nodes {
		if bytes.Equal(c.NodeID, nodeID) {
			return c
		}
	}
	return nil
}

// Remove removes the contact with the given nodeID; returns true if it was
// present.
func (b *KBucket) Remove(nodeID []byte) bool {
	for i, c := range b.Nodes {
		if bytes.Equal(c.NodeID, nodeID) {
			b.Nodes = append(b.Nodes[:i], b.Nodes[i+1:]...)
			return true
		}
	}
	return false
}

// Demote clears the stored contact's ConfirmedAt in place, returning it to
// probation while keeping the table slot (address and learn history stay).
// Returns true if the contact was present. See RoutingTable.Demote.
func (b *KBucket) Demote(nodeID []byte) bool {
	for _, c := range b.Nodes {
		if bytes.Equal(c.NodeID, nodeID) {
			c.ConfirmedAt = 0
			return true
		}
	}
	return false
}

// AddOrRefresh performs the Kademlia bucket update and returns the eviction
// candidate (or nil):
//
//   - If the contact's NodeID is already present: PublicKey/Addr update in
//     place. A DIRECT confirmation (c.ConfirmedAt > 0) also refreshes
//     LastSeen/ConfirmedAt and moves the contact to the tail
//     (most-recently-seen). A mere ADVERTISEMENT (c.ConfirmedAt == 0) of an
//     entry this node has never confirmed keeps the stored LastSeen and
//     bucket position — re-teaching must not launder a dead contact into
//     liveness (issue #2).
//   - If absent and the bucket is not full: the contact is appended at the
//     tail. Returns nil.
//   - If absent and the bucket is FULL: does NOT insert; returns the head
//     (Nodes[0], the oldest) as a ping candidate for live eviction.
func (b *KBucket) AddOrRefresh(c *NodeContact) *NodeContact {
	for i, cur := range b.Nodes {
		if bytes.Equal(cur.NodeID, c.NodeID) {
			// Refresh the stored contact's fields in place so other holders
			// of the same *NodeContact reference observe the update.
			cur.PublicKey = c.PublicKey
			// Multi-homing (2026-09-01): a re-learn at a DIFFERENT address
			// must not clobber the previously known one — it joins Alts,
			// and the preferred address only moves when the incoming one
			// is more recent where it counts (direct confirmations first,
			// then last-seen). One slot per node, every address preserved.
			cur.mergeAddr(c.Addr, c.LastSeen, c.ConfirmedAt)
			if c.ConfirmedAt > cur.ConfirmedAt {
				cur.ConfirmedAt = c.ConfirmedAt
			}
			if c.ConfirmedAt > 0 {
				// A direct exchange: full recency refresh + move to tail.
				cur.LastSeen = c.LastSeen
				b.Nodes = append(b.Nodes[:i], b.Nodes[i+1:]...)
				b.Nodes = append(b.Nodes, cur)
			}
			return nil
		}
	}
	if b.IsFull() {
		// Full and unknown: return head as ping candidate. Do NOT insert.
		return b.Nodes[0]
	}
	b.Nodes = append(b.Nodes, c)
	return nil
}

// mergeAddr folds the incoming (addr, lastSeen, confirmedAt) observation of
// THIS node into the contact: refreshing it in place when it is already the
// preferred address, adding/updating it in Alts when it is not, and
// re-pointing the preferred address when the incoming one outranks the
// stored one. The ranking: any direct confirmation beats any lack thereof;
// among confirmed addresses the fresher confirmation wins; among
// never-confirmed ones the fresher learn wins.
func (c *NodeContact) mergeAddr(addr string, lastSeen, confirmedAt int64) {
	if addr == c.Addr {
		return // the preferred address itself — contact-level fields carry it
	}
	for i := range c.Alts {
		if c.Alts[i].Addr == addr {
			a := &c.Alts[i]
			a.LastSeen = lastSeen
			if confirmedAt > a.ConfirmedAt {
				a.ConfirmedAt = confirmedAt
			}
			c.repointPreferredIfNeeded()
			return
		}
	}
	c.Alts = append(c.Alts, AddrState{Addr: addr, LastSeen: lastSeen, ConfirmedAt: confirmedAt})
	c.trimAlts()
	c.repointPreferredIfNeeded()
}

// repointPreferredIfNeeded moves the preferred address to the stored address
// that ranks best (see mergeAddr). Called after every Alts mutation.
func (c *NodeContact) repointPreferredIfNeeded() {
	if len(c.Alts) == 0 {
		return
	}
	best := -1
	for i := range c.Alts {
		if !addrOutranks(c.Alts[i].ConfirmedAt, c.Alts[i].LastSeen, c.ConfirmedAt, c.LastSeen) {
			continue
		}
		if best == -1 || addrOutranks(c.Alts[i].ConfirmedAt, c.Alts[i].LastSeen, c.Alts[best].ConfirmedAt, c.Alts[best].LastSeen) {
			best = i
		}
	}
	if best == -1 {
		return
	}
	old := AddrState{Addr: c.Addr, LastSeen: c.LastSeen, ConfirmedAt: c.ConfirmedAt}
	c.Addr = c.Alts[best].Addr
	c.LastSeen = c.Alts[best].LastSeen
	c.ConfirmedAt = c.Alts[best].ConfirmedAt
	c.Alts[best] = old
}

// addrOutranks reports whether incoming (confirmedAt, lastSeen) ranks above
// the stored pair: fresher direct confirmation wins outright; with neither
// ever confirmed, the fresher learn wins.
func addrOutranks(inConfirmed, inLastSeen, curConfirmed, curLastSeen int64) bool {
	if inConfirmed > 0 || curConfirmed > 0 {
		return inConfirmed > curConfirmed
	}
	return inLastSeen > curLastSeen
}

// trimAlts caps Alts at maxAddrsPerContact-1, dropping the least-recently-
// seen entries first. Never drops an entry with a fresher confirmation in
// favor of an older-seen one unless the cap forces it.
func (c *NodeContact) trimAlts() {
	for len(c.Alts) > maxAddrsPerContact-1 {
		oldest := 0
		for i := range c.Alts {
			if c.Alts[i].LastSeen < c.Alts[oldest].LastSeen {
				oldest = i
			}
		}
		c.Alts = append(c.Alts[:oldest], c.Alts[oldest+1:]...)
	}
}

// OtherAddrs returns the contact's known addresses other than the preferred
// one, freshest first. Read-only helper for probes and surfaces.
func (c *NodeContact) OtherAddrs() []AddrState {
	out := make([]AddrState, len(c.Alts))
	copy(out, c.Alts)
	sort.Slice(out, func(i, j int) bool {
		if out[i].ConfirmedAt != out[j].ConfirmedAt {
			return out[i].ConfirmedAt > out[j].ConfirmedAt
		}
		return out[i].LastSeen > out[j].LastSeen
	})
	return out
}

// PromoteAlt re-points the preferred address to the given alt address (which
// must be present in Alts), demoting the current preferred into Alts. The
// outgoing preferred enters Alts with its confirmation CLEARED — the caller
// promotes an alternate precisely because the preferred just failed a probe,
// and the anti-ghost invariant says a missed probe must not leave liveness
// behind. Returns true if the switch happened. Used by the probe-failure
// failover.
func (rt *RoutingTable) PromoteAlt(nodeID []byte, addr string) bool {
	bucket, err := rt.BucketFor(nodeID)
	if err != nil {
		return false
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, cur := range bucket.Nodes {
		if !bytes.Equal(cur.NodeID, nodeID) {
			continue
		}
		for i := range cur.Alts {
			if cur.Alts[i].Addr != addr {
				continue
			}
			old := AddrState{Addr: cur.Addr, LastSeen: cur.LastSeen, ConfirmedAt: 0}
			cur.Addr = cur.Alts[i].Addr
			cur.LastSeen = cur.Alts[i].LastSeen
			cur.ConfirmedAt = cur.Alts[i].ConfirmedAt
			cur.Alts[i] = old
			return true
		}
	}
	return false
}

// RoutingTable is a 256-bucket Kademlia routing table keyed on a node's own
// ID. The table never stores the node itself; operations on SelfID return an
// error.
//
// A sync.RWMutex guards the buckets so the table is safe for concurrent use by
// the RPC transport (the read loop mutates it from learnPeer while iterative
// lookups read it via Closest). Public mutators take the write lock; readers
// take the read lock. Closest/AllContacts return deep-copied contacts so a
// caller cannot observe an in-place refresh after the lock is released.
type RoutingTable struct {
	SelfID   []byte
	Capacity int
	Buckets  [numBuckets]*KBucket
	mu       sync.RWMutex
}

// NewRoutingTable constructs a routing table centred on selfID with the given
// per-bucket capacity. selfID must be 32 bytes and capacity must be > 0.
func NewRoutingTable(selfID []byte, capacity int) (*RoutingTable, error) {
	if len(selfID) != constants.NodeIDLen {
		return nil, fmt.Errorf("dht: self_id must be %d bytes, got %d", constants.NodeIDLen, len(selfID))
	}
	if capacity <= 0 {
		return nil, fmt.Errorf("dht: capacity must be > 0, got %d", capacity)
	}
	id := make([]byte, len(selfID))
	copy(id, selfID)
	rt := &RoutingTable{
		SelfID:   id,
		Capacity: capacity,
	}
	for i := 0; i < numBuckets; i++ {
		rt.Buckets[i] = &KBucket{Index: i, Capacity: capacity}
	}
	return rt, nil
}

// BucketFor returns the k-bucket governing nodeID. Returns an error if nodeID
// equals SelfID (a node never stores itself) or has the wrong length. The
// bucket index is the common-prefix length of SelfID and nodeID, defensively
// clamped to [0, 255].
func (rt *RoutingTable) BucketFor(nodeID []byte) (*KBucket, error) {
	if len(nodeID) != constants.NodeIDLen {
		return nil, fmt.Errorf("dht: node_id must be %d bytes, got %d", constants.NodeIDLen, len(nodeID))
	}
	if bytes.Equal(nodeID, rt.SelfID) {
		return nil, errors.New("dht: a node does not route to itself")
	}
	idx, err := CommonPrefixLength(rt.SelfID, nodeID)
	if err != nil {
		return nil, err
	}
	if idx < 0 {
		idx = 0
	} else if idx > numBuckets-1 {
		idx = numBuckets - 1
	}
	return rt.Buckets[idx], nil
}

// Add inserts or refreshes a contact. Returns the evict-candidate
// NodeContact (the oldest in the full bucket) if the contact could not be
// inserted; nil on success. Safe for concurrent use.
func (rt *RoutingTable) Add(c *NodeContact) (*NodeContact, error) {
	bucket, err := rt.BucketFor(c.NodeID)
	if err != nil {
		return nil, err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return bucket.AddOrRefresh(c).clone(), nil
}

// Remove removes a contact by nodeID; returns true if it was present. Returns
// false (without error) if nodeID is SelfID or otherwise invalid. Safe for
// concurrent use.
func (rt *RoutingTable) Remove(nodeID []byte) bool {
	bucket, err := rt.BucketFor(nodeID)
	if err != nil {
		return false
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return bucket.Remove(nodeID)
}

// Demote clears a contact's direct-confirmation stamp (ConfirmedAt → 0)
// without dropping the table slot, returning it to probation: the peers
// surface shows it as advertised rather than confirmed until the next
// successful exchange re-stamps it. Returns true if the contact was present.
// Used by the §6.2 probe-failure path so a single missed probe cannot
// disconnect a peer we exchanged with directly moments ago — the idle sweep
// (contactIdleTTL) remains the judge of whether it is truly gone. Safe for
// concurrent use.
func (rt *RoutingTable) Demote(nodeID []byte) bool {
	bucket, err := rt.BucketFor(nodeID)
	if err != nil {
		return false
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return bucket.Demote(nodeID)
}

// Get looks up a contact by nodeID across the appropriate bucket. Returns nil
// if absent or if nodeID is SelfID/invalid. Safe for concurrent use; the
// returned contact is a copy.
func (rt *RoutingTable) Get(nodeID []byte) *NodeContact {
	bucket, err := rt.BucketFor(nodeID)
	if err != nil {
		return nil
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return bucket.Get(nodeID).clone()
}

// Closest returns the n contacts nearest to target by XOR distance, ascending.
// All contacts are gathered and stably sorted by XOR distance to target, so
// equal distances retain storage order. n is clamped to [0, len(contacts)].
// Safe for concurrent use; the returned contacts are copies.
//
// v0.15.3: the per-call cost dropped from clone-EVERY-contact to clone-the-n
// survivors — Closest runs on every walk step, RPC reply, and put target
// pick, and the table's contact count grows with the peer book while n is
// typically 8-20 (found in the 2026-09-04 audit). The sort and the surviving
// clones both hold the read lock: contact structs are mutated in place by
// probation/exchange updates, so touching them unlocked would race.
func (rt *RoutingTable) Closest(target []byte, n int) []*NodeContact {
	rt.mu.RLock()
	ptrs := make([]*NodeContact, 0, rt.Size())
	for _, b := range rt.Buckets {
		ptrs = append(ptrs, b.Nodes...)
	}
	sort.SliceStable(ptrs, func(i, j int) bool {
		return CompareDistance(target, ptrs[i].NodeID, ptrs[j].NodeID) < 0
	})
	if n < 0 {
		n = 0
	}
	if n > len(ptrs) {
		n = len(ptrs)
	}
	out := make([]*NodeContact, n)
	for i := 0; i < n; i++ {
		out[i] = ptrs[i].clone()
	}
	rt.mu.RUnlock()
	return out
}

// AllContacts returns cloned copies of every contact in storage order (bucket
// 0..255, each oldest-first). Used for diagnostics and tests. Safe for
// concurrent use.
func (rt *RoutingTable) AllContacts() []*NodeContact {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.allContactsLocked()
}

// allContactsLocked returns cloned contacts in storage order. Caller must hold
// rt.mu (read or write).
func (rt *RoutingTable) allContactsLocked() []*NodeContact {
	var out []*NodeContact
	for _, b := range rt.Buckets {
		for _, c := range b.Nodes {
			out = append(out, c.clone())
		}
	}
	return out
}

// Size returns the total number of contacts across all buckets. Safe for
// concurrent use.
func (rt *RoutingTable) Size() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	n := 0
	for _, b := range rt.Buckets {
		n += len(b.Nodes)
	}
	return n
}
