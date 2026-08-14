"""Kademlia routing table for the freens DHT.

Implements the 256-bucket, K-per-bucket routing table described in
specifications.md §6.2 (Node identity and routing):

    - Node ID = SHA-256(node_public_key) (32 bytes).
    - Distance metric: bitwise XOR of 256-bit IDs.
    - Routing table: 256 k-buckets (one per bit prefix length), K = 20
      entries per bucket, standard Kademlia eviction (ping-oldest,
      replace on failure).

This module provides the pure data structure. The eviction policy here is
the simplified variant called out in §6.2: when a bucket is full, a new
contact is *not* inserted, and the oldest (least-recently-seen) entry is
returned as a "ping candidate" so that the RPC layer can perform live
eviction (ping-oldest; on failure, remove the candidate and re-add the new
contact). Re-adding an already-known contact refreshes it: its fields are
updated and it is moved to the tail (most-recently-seen) of its bucket.

Pure stdlib (dataclasses only).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .. import constants
from . import ids


@dataclass
class NodeContact:
    """A peer known to the routing table.

    Identity is ``node_id`` (32 bytes; ``SHA-256(public_key)``). The
    ``public_key`` is stored alongside so that signatures on incoming RPCs
    can be verified without a separate lookup.
    """

    node_id: bytes                 # 32 bytes
    public_key: bytes              # 32 bytes (id == SHA-256(public_key))
    addr: tuple[str, int]          # (ip, port)
    last_seen: int = 0             # unix seconds; updated on add/refresh

    def __post_init__(self) -> None:
        if not isinstance(self.node_id, (bytes, bytearray)) or len(self.node_id) != 32:
            raise ValueError("node_id must be 32 bytes")
        if not isinstance(self.public_key, (bytes, bytearray)) or len(self.public_key) != 32:
            raise ValueError("public_key must be 32 bytes")
        # addr must be (ip:str, port:int)
        if not (isinstance(self.addr, tuple) and len(self.addr) == 2
                and isinstance(self.addr[0], str) and isinstance(self.addr[1], int)):
            raise ValueError("addr must be (ip:str, port:int)")
        # Normalise to immutable bytes/tuple so the contact is hashable-ish
        # and not accidentally mutated through bytearray aliases.
        if isinstance(self.node_id, bytearray):
            self.node_id = bytes(self.node_id)
        if isinstance(self.public_key, bytearray):
            self.public_key = bytes(self.public_key)


@dataclass
class KBucket:
    """A single k-bucket.

    Holds up to ``capacity`` :class:`NodeContact` instances ordered
    oldest-first: the list head is the least-recently-seen entry (the
    Kademlia eviction candidate), the tail is the most-recently-seen.
    """

    index: int                                      # 0..255
    capacity: int = constants.K
    nodes: list[NodeContact] = field(default_factory=list)

    # ---- inspection ----------------------------------------------------

    def is_full(self) -> bool:
        """True iff the bucket is at capacity."""
        return len(self.nodes) >= self.capacity

    def get(self, node_id: bytes) -> Optional[NodeContact]:
        """Return the contact with ``node_id`` if present, else None."""
        for c in self.nodes:
            if c.node_id == node_id:
                return c
        return None

    # ---- mutation ------------------------------------------------------

    def remove(self, node_id: bytes) -> bool:
        """Remove the contact with ``node_id``. True if it was present."""
        for i, c in enumerate(self.nodes):
            if c.node_id == node_id:
                del self.nodes[i]
                return True
        return False

    def add_or_refresh(self, contact: NodeContact) -> Optional[NodeContact]:
        """Kademlia bucket update.

        - If ``contact.node_id`` is already present: update its
          ``public_key``/``addr``/``last_seen`` and move it to the TAIL
          (most-recently-seen). Return None.
        - If not present and the bucket is not full: append to the tail.
          Return None.
        - If not present and the bucket is FULL: do NOT insert; return the
          HEAD (oldest) contact as a 'ping candidate' so the caller can
          decide live eviction.

        The caller guarantees a contact is never its own bucket's owner.
        """
        existing_idx: Optional[int] = None
        for i, c in enumerate(self.nodes):
            if c.node_id == contact.node_id:
                existing_idx = i
                break

        if existing_idx is not None:
            # Refresh: mutate the stored contact's fields in place, then
            # move it to the tail. We mutate in place so that other holders
            # of the same NodeContact reference observe the update.
            cur = self.nodes[existing_idx]
            cur.public_key = contact.public_key
            cur.addr = contact.addr
            cur.last_seen = contact.last_seen
            # Move to tail (most-recently-seen).
            self.nodes.append(self.nodes.pop(existing_idx))
            return None

        if self.is_full():
            # Full and unknown: return the head as a ping candidate.
            # Do NOT insert or mutate.
            return self.nodes[0]

        # Not full and unknown: append at tail.
        self.nodes.append(contact)
        return None


class RoutingTable:
    """256-bucket Kademlia routing table keyed on a node's own ID.

    The table never stores the node itself (``self_id``); attempting to
    add a contact whose ``node_id == self_id`` raises ``ValueError``.
    """

    def __init__(self, self_id: bytes, capacity: int = constants.K) -> None:
        ids._check_id(self_id)
        self.self_id = self_id
        self.capacity = capacity
        # 256 buckets, one per bit prefix length (0..255).
        self.buckets: list[KBucket] = [
            KBucket(index=i, capacity=capacity) for i in range(256)
        ]

    # ---- bucket selection ---------------------------------------------

    def bucket_for(self, node_id: bytes) -> KBucket:
        """Return the bucket governing ``node_id``.

        Raises ``ValueError`` if ``node_id == self_id`` (a node never
        stores itself).

        The bucket index is the common-prefix length of ``self_id`` and
        ``node_id``: the bucket holds IDs sharing that many leading bits
        with our own ID (see :func:`freens.dht.ids.bucket_index`).
        ``common_prefix_length`` is at most 255 when two IDs differ only
        in the LSB; 256 only occurs when the IDs are equal, which we
        reject above.
        """
        ids._check_id(node_id)
        if node_id == self.self_id:
            raise ValueError("a node does not route to itself")
        idx = ids.common_prefix_length(self.self_id, node_id)
        # Defensive clamp; common_prefix_length is in [0, 255] here.
        if idx < 0:
            idx = 0
        elif idx > 255:
            idx = 255
        return self.buckets[idx]

    # ---- table-level mutation -----------------------------------------

    def add(self, contact: NodeContact) -> Optional[NodeContact]:
        """Add or refresh a contact.

        Returns None on success, or the evict-candidate
        :class:`NodeContact` (the oldest in the full bucket) if the
        bucket is full and the contact could not be inserted. The caller
        should ping the candidate and, on failure, call
        ``remove(candidate.node_id)`` then ``add(contact)`` again.
        """
        bucket = self.bucket_for(contact.node_id)
        return bucket.add_or_refresh(contact)

    def remove(self, node_id: bytes) -> bool:
        """Remove a contact by ``node_id``. True if it was present."""
        bucket = self.bucket_for(node_id)
        return bucket.remove(node_id)

    def get(self, node_id: bytes) -> Optional[NodeContact]:
        """Look up a contact by ``node_id`` across all buckets."""
        bucket = self.bucket_for(node_id)
        return bucket.get(node_id)

    # ---- queries ------------------------------------------------------

    def closest(self, target: bytes, n: int = constants.K) -> list[NodeContact]:
        """Return the ``n`` contacts closest to ``target`` by XOR distance
        (ascending).

        Implemented by collecting every contact and sorting by
        ``ids.distance_int(target, c.node_id)``. ``self_id`` is never
        stored in the table, so no explicit exclusion is needed; ties are
        broken by insertion/storage order because Python's sort is stable
        and we gather contacts in storage order.
        """
        all_c = self.all_contacts()
        # Stable sort: equal distances keep storage (insertion) order.
        all_c.sort(key=lambda c: ids.distance_int(target, c.node_id))
        if n < 0:
            n = 0
        return all_c[:n]

    def all_contacts(self) -> list[NodeContact]:
        """All contacts in insertion/storage order (diagnostics/tests).

        Iterates buckets 0..255, each of which is itself oldest-first;
        concatenation gives a deterministic storage order.
        """
        out: list = []
        for b in self.buckets:
            out.extend(b.nodes)
        return out

    def size(self) -> int:
        """Total contact count across all buckets."""
        return sum(len(b.nodes) for b in self.buckets)
