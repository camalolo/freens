package dht

import (
	"bytes"
	"testing"

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
)

// makeNode derives a deterministic NodeContact from a single seed byte. The
// Ed25519 keypair is reconstructed from a 32-byte seed (s repeated), the node
// ID is SHA-256(public_key), and the contact is built with that id+pk pair so
// it is internally consistent (per spec §6.2: Node ID = SHA-256(public_key)).
func makeNode(t *testing.T, seedByte byte, addr string, lastSeen int64) *NodeContact {
	t.Helper()
	seed := bytes.Repeat([]byte{seedByte}, constants.Ed25519PrivateKeyLen)
	kp, err := crypto.FromSeed(seed)
	if err != nil {
		t.Fatalf("crypto.FromSeed(%02x): %v", seedByte, err)
	}
	pk := kp.Public()
	id, err := crypto.NodeID(pk)
	if err != nil {
		t.Fatalf("crypto.NodeID(%02x): %v", seedByte, err)
	}
	c, err := NewNodeContact(id, pk, addr, lastSeen)
	if err != nil {
		t.Fatalf("NewNodeContact(%02x): %v", seedByte, err)
	}
	return c
}

func TestNewNodeContactValidation(t *testing.T) {
	t.Parallel()

	pk := bytes.Repeat([]byte{0x01}, constants.Ed25519PublicKeyLen)
	goodID := bytes.Repeat([]byte{0x02}, constants.NodeIDLen)

	if _, err := NewNodeContact(make([]byte, 31), pk, "1.2.3.4:5", 0); err == nil {
		t.Fatal("NewNodeContact(31-byte id) want error, got nil")
	}
	if _, err := NewNodeContact(goodID, make([]byte, 31), "1.2.3.4:5", 0); err == nil {
		t.Fatal("NewNodeContact(31-byte pk) want error, got nil")
	}
	if _, err := NewNodeContact(goodID, pk, "", 0); err == nil {
		t.Fatal("NewNodeContact(empty addr) want error, got nil")
	}
	c, err := NewNodeContact(goodID, pk, "1.2.3.4:15353", 42)
	if err != nil {
		t.Fatalf("NewNodeContact(valid) unexpected error: %v", err)
	}
	if !bytes.Equal(c.NodeID, goodID) || !bytes.Equal(c.PublicKey, pk) {
		t.Fatal("NewNodeContact stored wrong id/pk")
	}
	if c.Addr != "1.2.3.4:15353" || c.LastSeen != 42 {
		t.Fatalf("NewNodeContact fields wrong: addr=%q lastSeen=%d", c.Addr, c.LastSeen)
	}
	// Must copy inputs, not alias them.
	mut := []byte{0xff}
	mut = append(mut, make([]byte, constants.NodeIDLen-1)...)
	if bytes.Equal(c.NodeID, mut) {
		t.Fatal("NewNodeContact did not copy node_id (aliased caller memory)")
	}
}

func TestNewRoutingTable(t *testing.T) {
	t.Parallel()

	self := makeNode(t, 0xAA, "9.9.9.9:15353", 0)
	rt, err := NewRoutingTable(self.NodeID, constants.K)
	if err != nil {
		t.Fatalf("NewRoutingTable: %v", err)
	}
	// 256 buckets, all non-nil, each at capacity K.
	gotBuckets := 0
	for _, b := range rt.Buckets {
		if b != nil {
			gotBuckets++
			if b.Capacity != constants.K {
				t.Fatalf("bucket %d capacity = %d, want %d", b.Index, b.Capacity, constants.K)
			}
		}
	}
	if gotBuckets != 256 {
		t.Fatalf("got %d non-nil buckets, want 256", gotBuckets)
	}
	if rt.Size() != 0 {
		t.Fatalf("fresh table Size = %d, want 0", rt.Size())
	}

	// Validation.
	if _, err := NewRoutingTable(make([]byte, 31), constants.K); err == nil {
		t.Fatal("NewRoutingTable(31-byte self) want error, got nil")
	}
	if _, err := NewRoutingTable(self.NodeID, 0); err == nil {
		t.Fatal("NewRoutingTable(capacity=0) want error, got nil")
	}
}

func TestBucketForSelfErrors(t *testing.T) {
	t.Parallel()

	z := make([]byte, constants.NodeIDLen)
	rt, err := NewRoutingTable(z, constants.K)
	if err != nil {
		t.Fatalf("NewRoutingTable: %v", err)
	}
	if _, err := rt.BucketFor(z); err == nil {
		t.Fatal("BucketFor(SelfID) want error, got nil")
	}
	if _, err := rt.BucketFor(make([]byte, 31)); err == nil {
		t.Fatal("BucketFor(31-byte) want error, got nil")
	}
}

func TestRoutingTablePlacementAndOps(t *testing.T) {
	t.Parallel()

	// Use a deterministic SelfID of all-zeros so bucket placement is
	// predictable via CommonPrefixLength.
	z := make([]byte, constants.NodeIDLen)
	rt, err := NewRoutingTable(z, constants.K)
	if err != nil {
		t.Fatalf("NewRoutingTable: %v", err)
	}

	// A contact whose NodeID has its MSB set has CPL 0 with the zero SelfID,
	// so it lands in bucket 0.
	c0 := makeNode(t, 0x01, "1.0.0.0:1", 1)
	// Force a bucket-0 node id deterministically: 0x80 followed by zeros.
	bucketZeroID := append([]byte{0x80}, make([]byte, constants.NodeIDLen-1)...)
	cBucket0, err := NewNodeContact(bucketZeroID, c0.PublicKey, "1.0.0.1:1", 1)
	if err != nil {
		t.Fatalf("NewNodeContact: %v", err)
	}
	bucket, err := rt.BucketFor(cBucket0.NodeID)
	if err != nil {
		t.Fatalf("BucketFor(0x80+zeros): %v", err)
	}
	if bucket.Index != 0 {
		t.Fatalf("0x80+zeros placed in bucket %d, want 0", bucket.Index)
	}

	// Adding the contact inserts it into bucket 0.
	evict, err := rt.Add(cBucket0)
	if err != nil {
		t.Fatalf("Add(0x80+zeros): %v", err)
	}
	if evict != nil {
		t.Fatalf("Add returned eviction candidate on a fresh bucket: %v", evict)
	}
	if rt.Size() != 1 {
		t.Fatalf("Size after one add = %d, want 1", rt.Size())
	}
	if rt.Get(cBucket0.NodeID) == nil {
		t.Fatal("Get(0x80+zeros) returned nil after add")
	}

	// Remove works and reflects in Size.
	if !rt.Remove(cBucket0.NodeID) {
		t.Fatal("Remove returned false for present contact")
	}
	if rt.Size() != 0 {
		t.Fatalf("Size after remove = %d, want 0", rt.Size())
	}
	if rt.Remove(cBucket0.NodeID) {
		t.Fatal("Remove returned true for absent contact")
	}
}

func TestKBucketFillRefreshOverflow(t *testing.T) {
	t.Parallel()

	b := &KBucket{Index: 0, Capacity: 3}
	mk := func(seed byte, lastSeen int64) *NodeContact {
		return makeNode(t, seed, "1.2.3.4:15353", lastSeen)
	}
	c1, c2, c3, c4 := mk(0x01, 1), mk(0x02, 2), mk(0x03, 3), mk(0x04, 4)

	if r := b.AddOrRefresh(c1); r != nil {
		t.Fatalf("AddOrRefresh(c1) want nil, got %v", r)
	}
	if r := b.AddOrRefresh(c2); r != nil {
		t.Fatalf("AddOrRefresh(c2) want nil, got %v", r)
	}
	if r := b.AddOrRefresh(c3); r != nil {
		t.Fatalf("AddOrRefresh(c3) want nil, got %v", r)
	}
	if !b.IsFull() {
		t.Fatal("IsFull want true after 3 adds with capacity 3")
	}
	if len(b.Nodes) != 3 || b.Nodes[0] != c1 || b.Nodes[2] != c3 {
		t.Fatalf("bucket order wrong: %v", b.Nodes)
	}

	// Refresh c1: it should move to the tail (most-recently-seen).
	c1Refreshed := makeNode(t, 0x01, "5.5.5.5:99", 100)
	if r := b.AddOrRefresh(c1Refreshed); r != nil {
		t.Fatalf("AddOrRefresh(refresh) want nil, got %v", r)
	}
	if b.Nodes[2] != c1 {
		t.Fatalf("after refresh, tail = %p, want c1 (%p)", b.Nodes[2], c1)
	}
	if b.Nodes[0] != c2 {
		t.Fatalf("after refresh, head = %p, want c2 (%p)", b.Nodes[0], c2)
	}
	// Refresh must update fields in place on the same *NodeContact instance.
	if b.Nodes[2].Addr != "5.5.5.5:99" || b.Nodes[2].LastSeen != 100 {
		t.Fatalf("refresh did not update fields: addr=%q lastSeen=%d",
			b.Nodes[2].Addr, b.Nodes[2].LastSeen)
	}

	// 4th distinct add: bucket full -> returns head (c2) as ping candidate.
	head := b.Nodes[0]
	evict := b.AddOrRefresh(c4)
	if evict != head {
		t.Fatalf("AddOrRefresh(full) returned %p, want head %p", evict, head)
	}
	// And must NOT have inserted c4.
	if len(b.Nodes) != 3 {
		t.Fatalf("AddOrRefresh(full) mutated bucket length to %d, want 3", len(b.Nodes))
	}
	if b.Get(c4.NodeID) != nil {
		t.Fatal("Get(c4) returned non-nil; c4 must not be inserted when bucket is full")
	}

	// Remove then add c4 should now succeed.
	if !b.Remove(head.NodeID) {
		t.Fatal("Remove(head) returned false")
	}
	if r := b.AddOrRefresh(c4); r != nil {
		t.Fatalf("AddOrRefresh(c4 after remove) want nil, got %v", r)
	}
	if b.Get(c4.NodeID) == nil {
		t.Fatal("Get(c4) returned nil after add")
	}
}

func TestRoutingTableClosest(t *testing.T) {
	t.Parallel()

	z := make([]byte, constants.NodeIDLen)
	rt, err := NewRoutingTable(z, constants.K)
	if err != nil {
		t.Fatalf("NewRoutingTable: %v", err)
	}

	// Add several contacts with distinct IDs.
	for _, s := range []byte{0x01, 0x02, 0x03, 0x10, 0x20, 0x40} {
		// Place each contact deterministically in bucket 0 (MSB set) so
		// their distances to the zero target differ only in byte 0.
		id := append([]byte{s | 0x80}, make([]byte, constants.NodeIDLen-1)...)
		// Use a deterministic pk derived from a seed for the contact.
		seed := bytes.Repeat([]byte{s}, constants.Ed25519PrivateKeyLen)
		kp, err := crypto.FromSeed(seed)
		if err != nil {
			t.Fatalf("FromSeed: %v", err)
		}
		c, err := NewNodeContact(id, kp.Public(), "1.2.3.4:5", int64(s))
		if err != nil {
			t.Fatalf("NewNodeContact: %v", err)
		}
		if _, err := rt.Add(c); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	target := make([]byte, constants.NodeIDLen) // zero target
	got := rt.Closest(target, 3)
	// 6 contacts are present, so n=3 must return EXACTLY 3 — not merely an
	// upper bound. A regression that silently dropped results (returning 1 or
	// 2) would pass the old len(got) > 3 check, so assert equality.
	if len(got) != 3 {
		t.Fatalf("Closest(n=3) returned %d contacts, want exactly 3", len(got))
	}
	// The 3 nearest to the zero target by XOR distance are the contacts whose
	// first byte is 0x81, 0x82, 0x83 (the other three — 0x90, 0xa0, 0xc0 — are
	// all farther). Assert the returned set is exactly these three, in that
	// order, which also pins down ascending-by-distance ordering.
	wantFirstBytes := []byte{0x81, 0x82, 0x83}
	for i, want := range wantFirstBytes {
		if got[i].NodeID[0] != want {
			t.Fatalf("Closest(n=3)[%d] first byte = %02x, want %02x (ids: %x %x %x)",
				i, got[i].NodeID[0], want, got[0].NodeID, got[1].NodeID, got[2].NodeID)
		}
	}
	// Verify distances to target are ascending.
	for i := 1; i < len(got); i++ {
		dPrev, _ := XORBytes(target, got[i-1].NodeID)
		dCur, _ := XORBytes(target, got[i].NodeID)
		if bytes.Compare(dPrev, dCur) > 0 {
			t.Fatalf("Closest not ascending at %d: prev=%x cur=%x", i, dPrev, dCur)
		}
	}
	// Closest entry must be the 0x81 contact (smallest distance to zero).
	first := got[0].NodeID[0]
	if first != 0x81 {
		t.Fatalf("Closest[0] first byte = %02x, want 0x81", first)
	}

	// n larger than Size() returns all contacts, still sorted.
	all := rt.Closest(target, 999)
	if len(all) != rt.Size() {
		t.Fatalf("Closest(n=999) returned %d, want %d", len(all), rt.Size())
	}

	// n <= 0 returns no contacts.
	if got := rt.Closest(target, 0); len(got) != 0 {
		t.Fatalf("Closest(n=0) returned %d, want 0", len(got))
	}
	if got := rt.Closest(target, -5); len(got) != 0 {
		t.Fatalf("Closest(n=-5) returned %d, want 0", len(got))
	}
}

func TestRoutingTableAllContactsOrder(t *testing.T) {
	t.Parallel()

	z := make([]byte, constants.NodeIDLen)
	rt, err := NewRoutingTable(z, constants.K)
	if err != nil {
		t.Fatalf("NewRoutingTable: %v", err)
	}

	// Two contacts in bucket 0 (MSB set), one in bucket 1 (bit 0 shared).
	idB0a := append([]byte{0xff}, make([]byte, constants.NodeIDLen-1)...)
	idB0b := append([]byte{0x80}, make([]byte, constants.NodeIDLen-1)...)
	idB1 := append([]byte{0x40}, make([]byte, constants.NodeIDLen-1)...)

	for _, id := range [][]byte{idB0a, idB0b, idB1} {
		seed := bytes.Repeat(id[:1], constants.Ed25519PrivateKeyLen)
		kp, _ := crypto.FromSeed(seed)
		c, _ := NewNodeContact(id, kp.Public(), "1.1.1.1:1", 0)
		if _, err := rt.Add(c); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	all := rt.AllContacts()
	if len(all) != 3 {
		t.Fatalf("AllContacts returned %d, want 3", len(all))
	}
	// Bucket 0 holds idB0a (first added) then idB0b; bucket 1 holds idB1.
	if !bytes.Equal(all[0].NodeID, idB0a) {
		t.Fatalf("AllContacts[0] = %x, want %x", all[0].NodeID, idB0a)
	}
	if !bytes.Equal(all[1].NodeID, idB0b) {
		t.Fatalf("AllContacts[1] = %x, want %x", all[1].NodeID, idB0b)
	}
	if !bytes.Equal(all[2].NodeID, idB1) {
		t.Fatalf("AllContacts[2] = %x, want %x", all[2].NodeID, idB1)
	}
	if rt.Size() != 3 {
		t.Fatalf("Size = %d, want 3", rt.Size())
	}
}
