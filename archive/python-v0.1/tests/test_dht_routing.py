"""Unit tests for :mod:`freens.dht.routing` — contacts, k-buckets, table.

Covers the pure data structures in ``freens/dht/routing.py``:

* :class:`NodeContact` field validation (node_id/public_key length, addr shape).
* :class:`KBucket` fill / refresh-moves-to-tail / overflow-returns-head /
  get / remove semantics.
* :class:`RoutingTable` 256-bucket construction, self-exclusion,
  deterministic bucket placement, ``closest`` ascending ordering, removal,
  and the simplified Kademlia "full bucket returns the oldest as a ping
  candidate (no insertion)" rule.

Bucket placement is made **deterministic** by using ``self_id = bytes(32)``
(an all-zero ID).  Relative to an all-zero ID, any contact whose most-
significant bit is set shares zero leading bits and therefore lands in
bucket 0 — so a controlled set of ``0x80..0x82`` IDs collides in a single
bucket, exercising overflow reliably.

Run via ``python3 -m unittest discover`` from the project root.
"""

import unittest

from freens import crypto
from freens.dht import ids, routing


def contact(seed_byte, addr=("1.2.3.4", 15353)):
    """Build a deterministic :class:`NodeContact` from a single seed byte.

    The Ed25519 seed is ``seed_byte`` repeated 32 times, so distinct seed
    bytes yield distinct public keys and therefore distinct node IDs.
    ``last_seen`` is set to ``seed_byte`` for deterministic ordering.
    """
    kp = crypto.Keypair.from_private_bytes(bytes([seed_byte]) * 32)
    nid = crypto.node_id(kp.public_bytes)
    return routing.NodeContact(
        node_id=nid,
        public_key=kp.public_bytes,
        addr=addr,
        last_seen=seed_byte,
    )


class TestNodeContact(unittest.TestCase):
    def test_fields_populated(self):
        c = contact(1)
        self.assertEqual(len(c.node_id), 32)
        self.assertEqual(len(c.public_key), 32)
        self.assertEqual(c.addr, ("1.2.3.4", 15353))

    def test_bad_node_id_length_raises(self):
        with self.assertRaises(ValueError):
            routing.NodeContact(
                node_id=bytes(31),
                public_key=bytes(32),
                addr=("1.2.3.4", 1),
            )

    def test_bad_addr_type_raises(self):
        with self.assertRaises(ValueError):
            routing.NodeContact(
                node_id=bytes(32),
                public_key=bytes(32),
                addr="not a tuple",
            )


class TestKBucket(unittest.TestCase):
    def test_fill_refresh_and_overflow(self):
        b = routing.KBucket(index=0, capacity=3)
        self.assertFalse(b.is_full())

        b.add_or_refresh(contact(1))
        b.add_or_refresh(contact(2))
        self.assertEqual(len(b.nodes), 2)

        # Refreshing an already-present contact moves it to the TAIL
        # (most-recently-seen) without growing the bucket.
        c1 = contact(1)
        b.add_or_refresh(c1)
        self.assertEqual(len(b.nodes), 2)
        self.assertEqual(b.nodes[-1].node_id, c1.node_id)

        # Fill the bucket to capacity.
        b.add_or_refresh(contact(3))
        self.assertTrue(b.is_full())

        # Overflow: adding a fourth DISTINCT contact returns the HEAD
        # (oldest, least-recently-seen) as a ping candidate and does NOT
        # insert the newcomer.
        head_before = b.nodes[0]
        evicted = b.add_or_refresh(contact(4))
        self.assertIsNotNone(evicted)
        self.assertEqual(evicted.node_id, head_before.node_id)
        self.assertEqual(len(b.nodes), 3)  # unchanged — not inserted

    def test_get_and_remove(self):
        b = routing.KBucket(index=0, capacity=3)
        b.add_or_refresh(contact(1))
        b.add_or_refresh(contact(2))

        self.assertIsNotNone(b.get(contact(1).node_id))
        self.assertTrue(b.remove(contact(2).node_id))
        self.assertIsNone(b.get(contact(2).node_id))


class TestRoutingTable(unittest.TestCase):
    def test_construction(self):
        rt = routing.RoutingTable(self_id=bytes(32))
        self.assertEqual(rt.size(), 0)
        self.assertEqual(len(rt.buckets), 256)

    def test_self_is_not_routable(self):
        rt = routing.RoutingTable(self_id=bytes(32))
        with self.assertRaises(ValueError):
            rt.bucket_for(bytes(32))

    def test_bucket_placement_and_get(self):
        # self_id all-zeros => a contact with MSB set differs at bit 0 and
        # therefore lands in bucket 0 deterministically.
        rt = routing.RoutingTable(self_id=bytes(32))
        c = routing.NodeContact(
            node_id=b"\x80" + bytes(31),
            public_key=crypto.Keypair.generate().public_bytes,
            addr=("1.1.1.1", 1),
        )
        self.assertIsNone(rt.add(c))
        self.assertEqual(rt.bucket_for(c.node_id).index, 0)
        self.assertEqual(rt.size(), 1)
        # get returns the same stored object.
        self.assertIs(rt.get(c.node_id), c)

    def test_closest_returns_sorted_subset(self):
        rt = routing.RoutingTable(self_id=bytes(32))  # default capacity K=20
        for s in (1, 2, 3, 4, 5):
            rt.add(contact(s))
        closest = rt.closest(target=bytes(32), n=3)
        self.assertLessEqual(len(closest), 3)
        # Ascending by XOR distance to the target.
        dists = [ids.distance_int(bytes(32), c.node_id) for c in closest]
        self.assertEqual(dists, sorted(dists))

    def test_remove_and_all_contacts(self):
        rt = routing.RoutingTable(self_id=bytes(32))
        c = contact(7)
        rt.add(c)
        self.assertTrue(rt.remove(c.node_id))
        self.assertIsNone(rt.get(c.node_id))
        # Removing a missing contact returns False, not an error.
        self.assertFalse(rt.remove(c.node_id))
        self.assertIsInstance(rt.all_contacts(), list)

    def test_full_bucket_returns_oldest_without_inserting(self):
        # self_id all-zeros => every MSB-set ID (0x80..0x90) lands in
        # bucket 0, so a small-capacity table reliably overflows there.
        rt = routing.RoutingTable(self_id=bytes(32), capacity=2)
        candidates = [
            routing.NodeContact(
                node_id=bytes([off]) + bytes(31),
                public_key=crypto.Keypair.generate().public_bytes,
                addr=("1.1.1.1", 1),
            )
            for off in (0x80, 0x81, 0x82)
        ]
        # First two fit; bucket is now full.
        self.assertIsNone(rt.add(candidates[0]))
        self.assertIsNone(rt.add(candidates[1]))
        self.assertEqual(rt.size(), 2)

        # Third distinct contact: bucket full -> returns HEAD (oldest) and
        # does not insert.  Table size is unchanged.
        ping_candidate = rt.add(candidates[2])
        self.assertIsNotNone(ping_candidate)
        self.assertEqual(ping_candidate.node_id, candidates[0].node_id)
        self.assertEqual(rt.size(), 2)


if __name__ == "__main__":
    unittest.main()
