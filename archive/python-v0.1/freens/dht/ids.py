"""Kademlia XOR distance metric and helpers over 32-byte (256-bit) IDs.

Implements the node-identity and routing primitives described in
``specifications.md`` §6.2 (lines 410-424):

* ``Node ID = SHA-256(node_public_key)`` — 32 bytes, 256 bits.
* Distance metric: bitwise XOR of two 256-bit IDs.
* Routing table: 256 k-buckets, one per bit prefix length (``K = 20``).

All functions in this module operate on raw 32-byte IDs (``bytes``).
Distances are interpreted as big-endian unsigned integers, so *smaller ==
closer*, which is the canonical Kademlia convention.

This module is pure stdlib and depends only on :mod:`freens.constants`.
"""

from __future__ import annotations

from .. import constants

# ---------------------------------------------------------------------------
# Length constants (mirror constants.NODE_ID_LEN / SHA-256 width).
# ---------------------------------------------------------------------------
ID_LEN = constants.NODE_ID_LEN  # 32 bytes (256 bits)
BITS = ID_LEN * 8               # 256


class IDError(ValueError):
    """Raised when an ID is malformed (wrong type, wrong length, or invalid)."""


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def _check_id(x, name: str = "id") -> bytes:
    """Validate that *x* is a 32-byte ID and return it as ``bytes``.

    Accepts ``bytes`` or ``bytearray``; raises :class:`IDError` for any other
    type or for the wrong length. The returned object is always an immutable
    ``bytes`` copy of the input.
    """
    if isinstance(x, (bytes, bytearray)):
        b = bytes(x)
        if len(b) != ID_LEN:
            raise IDError(
                f"{name} must be {ID_LEN} bytes, got {len(b)}"
            )
        return b
    raise IDError(
        f"{name} must be bytes of length {ID_LEN}, got {type(x).__name__}"
    )


# ---------------------------------------------------------------------------
# Core metric
# ---------------------------------------------------------------------------
def xor(a: bytes, b: bytes) -> bytes:
    """Bitwise XOR of two 32-byte IDs, returned as 32 bytes.

    Golden vector (by construction):
        xor(bytes(32), bytes(32))          == bytes(32)
        xor(bytes(32), b"\\xff"*32)        == b"\\xff"*32
        xor(b"\\x01"+bytes(31), bytes(32)) == b"\\x01"+bytes(31)
    """
    a = _check_id(a, "a")
    b = _check_id(b, "b")
    return bytes(x ^ y for x, y in zip(a, b))


def distance_int(a: bytes, b: bytes) -> int:
    """The XOR of *a* and *b* as a big-endian unsigned integer.

    Result is in ``0 .. 2**256 - 1``; smaller means *closer*. This is the
    canonical Kademlia distance.

    Golden vector (by construction):
        distance_int(bytes(32), bytes(32)) == 0
    """
    return int.from_bytes(xor(a, b), "big")


def common_prefix_length(a: bytes, b: bytes) -> int:
    """Number of leading bits shared by *a* and *b* (``0..256``).

    Equivalent to the index of the highest bit where they differ; returns
    ``256`` when ``a == b``. Bits are counted from the most-significant bit
    (bit 0) of byte 0.

    Golden vectors (by construction):
        common_prefix_length(bytes(32), bytes(32))            == 256
        common_prefix_length(b"\\x80"+bytes(31), bytes(32))   == 0   # differ at MSB
        common_prefix_length(b"\\x40"+bytes(31), bytes(32))   == 1   # 0x40=01000000, share bit 0
        common_prefix_length(b"\\x01"+bytes(31), bytes(32))   == 7   # 0x01=00000001, differ at bit 7
    """
    a = _check_id(a, "a")
    b = _check_id(b, "b")
    shared = 0
    for x, y in zip(a, b):
        d = x ^ y
        if d == 0:
            shared += 8
            continue
        # d != 0: the first set bit of d marks the first differing position
        # within this byte. (8 - d.bit_length()) counts the leading zero bits
        # of d, i.e. the number of additional shared bits before the split.
        shared += 8 - d.bit_length()
        break
    return shared


# ---------------------------------------------------------------------------
# Routing-table placement
# ---------------------------------------------------------------------------
def bucket_index(self_id: bytes, other_id: bytes) -> int:
    """Which k-bucket (``0..255``) *other_id* belongs in, relative to *self_id*.

    Kademlia rule: bucket ``i`` holds contacts sharing exactly ``i`` leading
    bits with ``self_id`` and differing at bit ``i`` (bits indexed from the
    MSB, 0-indexed). Equivalently::

        bucket_index == common_prefix_length(self_id, other_id)

    Examples:
        bucket_index(bytes(32), b"\\x80"+bytes(31)) == 0   # differ at MSB
        bucket_index(bytes(32), b"\\x40"+bytes(31)) == 1   # share bit 0, differ at bit 1

    Raises :class:`IDError` if ``self_id == other_id``: an ID never routes to
    itself (its common prefix length would be 256, which is not a valid
    bucket).
    """
    cpl = common_prefix_length(self_id, other_id)
    if cpl == BITS:
        raise IDError("an ID never routes to itself; no valid bucket")
    return cpl


# ---------------------------------------------------------------------------
# Comparison / ordering
# ---------------------------------------------------------------------------
def closer(target: bytes, a: bytes, b: bytes) -> int:
    """Compare XOR distances of *a* and *b* to *target*.

    Returns ``-1`` if *a* is closer to *target* than *b*, ``+1`` if *b* is
    closer, and ``0`` if equidistant (``a == b``).

    Golden vector (by construction):
        closer(b"\\x00"*32, b"\\x00"*32, b"\\x01"+bytes(31)) == -1  # a is target itself
    """
    da = distance_int(target, a)
    db = distance_int(target, b)
    return (da > db) - (da < db)


def sort_by_distance(target: bytes, ids: list[bytes]) -> list[bytes]:
    """Return *ids* sorted ascending by XOR distance to *target* (stable).

    Does not mutate the input list. Golden vector (by construction):
        sort_by_distance(bytes(32),
                         [b"\\xff"*32, b"\\x01"+bytes(31), bytes(32)])
        == [bytes(32), b"\\x01"+bytes(31), b"\\xff"*32]
    """
    target = _check_id(target, "target")
    # Validate every id up front so a malformed id does not slip through
    # only after some ordering has already happened.
    checked = [_check_id(i, "ids[i]") for i in ids]
    return sorted(checked, key=lambda i: distance_int(target, i))


def k_closest(
    target: bytes,
    ids: list[bytes],
    k: int = constants.K,
) -> list[bytes]:
    """The *k* IDs closest to *target* (ascending by XOR distance).

    If fewer than *k* IDs are available, all of them are returned (still
    sorted). Defaults to :data:`freens.constants.K` (``20``). Does not mutate
    the input list.
    """
    if k < 0:
        raise ValueError(f"k must be non-negative, got {k}")
    ordered = sort_by_distance(target, ids)
    return ordered[:k]


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------
def hex_id(x: bytes) -> str:
    """Lowercase hex of a 32-byte ID (64 chars), for diagnostics."""
    return _check_id(x, "x").hex()
