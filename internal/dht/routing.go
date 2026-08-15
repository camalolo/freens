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
// add/refresh.
type NodeContact struct {
	NodeID    []byte // 32 bytes (SHA-256(PublicKey))
	PublicKey []byte // 32 bytes (Ed25519 verifying key)
	Addr      string // "ip:port"
	LastSeen  int64  // unix seconds
}

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
	return &NodeContact{
		NodeID:    append([]byte(nil), c.NodeID...),
		PublicKey: append([]byte(nil), c.PublicKey...),
		Addr:      c.Addr,
		LastSeen:  c.LastSeen,
	}
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

// AddOrRefresh performs the Kademlia bucket update and returns the eviction
// candidate (or nil):
//
//   - If the contact's NodeID is already present: its PublicKey/Addr/LastSeen
//     are updated in place and it is moved to the tail (most-recently-seen).
//     Returns nil.
//   - If absent and the bucket is not full: the contact is appended at the
//     tail. Returns nil.
//   - If absent and the bucket is FULL: does NOT insert; returns the head
//     (Nodes[0], the oldest) as a ping candidate for live eviction.
func (b *KBucket) AddOrRefresh(c *NodeContact) *NodeContact {
	for i, cur := range b.Nodes {
		if bytes.Equal(cur.NodeID, c.NodeID) {
			// Refresh the stored contact's fields in place so other holders
			// of the same *NodeContact reference observe the update, then
			// move it to the tail.
			cur.PublicKey = c.PublicKey
			cur.Addr = c.Addr
			cur.LastSeen = c.LastSeen
			b.Nodes = append(b.Nodes[:i], b.Nodes[i+1:]...)
			b.Nodes = append(b.Nodes, cur)
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
// All contacts are gathered (cloned) and stably sorted by XOR distance to
// target, so equal distances retain storage order. n is clamped to
// [0, len(contacts)]. Safe for concurrent use; the returned contacts are copies.
func (rt *RoutingTable) Closest(target []byte, n int) []*NodeContact {
	rt.mu.RLock()
	all := rt.allContactsLocked()
	rt.mu.RUnlock()
	sort.SliceStable(all, func(i, j int) bool {
		return CompareDistance(target, all[i].NodeID, all[j].NodeID) < 0
	})
	if n < 0 {
		n = 0
	}
	if n > len(all) {
		n = len(all)
	}
	return all[:n]
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
