"""Deterministic (canonical) CBOR codec for the freens protocol.

This module implements the **deterministic CBOR** encoding mandated by
``specifications.md`` §4.2 ("Canonical encoding and signing"), which in turn
makes **RFC 8949 §4.2** normative. It is a self-contained, dependency-free
pure-stdlib replacement for the third-party ``cbor2`` library, restricted to
exactly the subset freens requires on the wire:

* unsigned and (for completeness) negative integers, **minimum-length**;
* byte strings (bstr, major type 2) and text strings (tstr, major type 3,
  UTF-8, NFC-normalised on encode);
* definite arrays (major type 4) and definite maps (major type 5) with
  canonical key ordering and no duplicate keys;
* the three RFC 8949 simple values freens uses: ``true`` (0xf5), ``false``
  (0xf4), ``null`` (0xf6).

Forbidden and rejected on sight:

* **floats** (RFC 8949 §4.2 / spec §4.2: "No floating-point values anywhere
  in the record (MUST NOT)") — ``TypeError`` on encode, ``ValueError`` on
  decode (codes 0xf9 half / 0xfa single / 0xfb double);
* **indefinite-length** items and the **break** code 0xff — ``ValueError``;
* **CBOR tags** (major type 6) — ``ValueError``;
* **duplicate map keys** (identical encoded key bytes) — ``ValueError``;
* any unsupported Python type on encode — ``TypeError``.

Only the Python standard library is used (``struct``, ``unicodedata``).

Public API
----------
``dumps(obj) -> bytes``
    Canonical-encode a Python object.

``loads(data: bytes)``
    Decode canonical CBOR bytes back to a Python object.

``dumps_map(items) -> bytes``
    Convenience encoder: ``items`` is an iterable of ``(key, value)`` pairs,
    encoded as a canonical map after sorting. Useful when callers want
    explicit field lists with small integer keys (the freens norm).
"""

import struct
import unicodedata

__all__ = ["dumps", "loads", "dumps_map"]


# ===========================================================================
# Golden vectors (hand-derived against RFC 8949 §4.2; the test suite asserts
# these EXACT bytes). Every line below is produced by construction by the
# encoder in this file.
#
#   dumps(0)                                == bytes.fromhex("00")
#   dumps(1)                                == bytes.fromhex("01")
#   dumps(23)                               == bytes.fromhex("17")
#   dumps(24)                               == bytes.fromhex("1818")
#   dumps(100)                              == bytes.fromhex("1864")
#   dumps(255)                              == bytes.fromhex("18ff")
#   dumps(256)                              == bytes.fromhex("190100")
#   dumps(300)                              == bytes.fromhex("19012c")
#   dumps(65535)                            == bytes.fromhex("19ffff")
#   dumps(65536)                            == bytes.fromhex("1a00010000")
#   dumps(b"")                              == bytes.fromhex("40")
#   dumps(b"abc")                           == bytes.fromhex("43616263")
#   dumps("abc")                            == bytes.fromhex("63616263")
#   dumps(True)                             == bytes.fromhex("f5")
#   dumps(False)                            == bytes.fromhex("f4")
#   dumps(None)                             == bytes.fromhex("f6")
#   dumps([])                               == bytes.fromhex("80")
#   dumps([1, 2, 3])                        == bytes.fromhex("83010203")
#   dumps({})                               == bytes.fromhex("a0")
#   dumps({1: 2})                           == bytes.fromhex("a10102")
#   dumps({1: 2, 3: 4})                     == bytes.fromhex("a201020304")
#   dumps({3: 4, 1: 2})                     == bytes.fromhex("a201020304")
#   dumps([1, 300, b"\x01\x02\x03"])        == bytes.fromhex("830119012c43010203")
#   dumps({2: b"abc", 1: 1})                == bytes.fromhex("a201010243616263")
#   dumps({1: 1, 7: [[1, 300, b"\x01\x02\x03"]]})
#                                           == bytes.fromhex("a201010781830119012c43010203")
#   dumps(b"\x00" * 24)                     == bytes.fromhex("5818") + b"\x00" * 24
#   dumps(b"\x00" * 32)                     == bytes.fromhex("5820") + b"\x00" * 32
#
# For every value ``x`` above, ``loads(dumps(x)) == x`` must also hold.
# ===========================================================================


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------

def _encode_head(major, argument):
    """Encode a CBOR "head": the initial byte (major type + additional
    information) plus, when needed, the minimal big-endian argument bytes.

    ``major`` is the major type (0..7); ``argument`` is the unsigned integer
    carried by the additional-information field. The encoding is always
    **minimum-length**: a value that fits inline (0..23) is never expanded.

    Derivation of the threshold/byte layout (RFC 8949 §3):
        ai 24 -> 1 byte follows    (values 24..255)
        ai 25 -> 2 bytes follow    (values 256..65535)
        ai 26 -> 4 bytes follow    (values 2**16..2**32-1)
        ai 27 -> 8 bytes follow    (values 2**32..2**64-1)
    """
    if argument < 0:
        # Should never happen: callers compute non-negative arguments only.
        raise ValueError("negative argument in CBOR head: %d" % argument)
    base = major << 5  # major type occupies the high 3 bits
    if argument <= 23:
        # Inline: 0..23 in the low 5 bits. e.g. major 0 -> 0x00..0x17,
        # major 2 -> 0x40..0x57, major 3 -> 0x60..0x77, major 4 -> 0x80..0x97,
        # major 5 -> 0xa0..0xb7.
        return struct.pack(">B", base | argument)
    elif argument <= 0xFF:
        return struct.pack(">BB", base | 24, argument)
    elif argument <= 0xFFFF:
        return struct.pack(">BH", base | 25, argument)
    elif argument <= 0xFFFFFFFF:
        return struct.pack(">BI", base | 26, argument)
    elif argument <= 0xFFFFFFFFFFFFFFFF:
        return struct.pack(">BQ", base | 27, argument)
    else:
        # CBOR has no standard encoding for integers beyond u64 without
        # bignum tags (major type 6), which freens forbids.
        raise ValueError(
            "integer too large for canonical CBOR (exceeds unsigned 64-bit)")


def _encode(obj):
    """Recursively canonical-encode ``obj`` to ``bytes``.

    Type dispatch order matters: ``bool`` is checked before ``int`` because
    ``bool`` is a subclass of ``int`` in Python (``isinstance(True, int)`` is
    ``True``), but freens maps the two to different CBOR bytes.
    """
    # --- Singletons (must precede the int branch) -------------------------
    # RFC 8949 preferred encoding: true = 0xf5, false = 0xf4, null = 0xf6.
    if obj is True:
        return b"\xf5"
    if obj is False:
        return b"\xf4"
    if obj is None:
        return b"\xf6"

    # --- Numbers ----------------------------------------------------------
    if isinstance(obj, int):
        # Major type 0 (unsigned). freens keys/values are all >= 0 here.
        # e.g. dumps(0)->00, dumps(1)->01, dumps(23)->17, dumps(24)->1818,
        #      dumps(100)->1864, dumps(255)->18ff, dumps(256)->190100,
        #      dumps(300)->19012c, dumps(65535)->19ffff, dumps(65536)->1a00010000.
        if obj >= 0:
            return _encode_head(0, obj)
        # Major type 1 (negative): value n encodes argument (-1 - n), minimal.
        # freens never emits negatives, but we support them for completeness.
        # e.g. dumps(-1)->20, dumps(-24)->37, dumps(-25)->3818.
        return _encode_head(1, -1 - obj)

    if isinstance(obj, float):
        # spec §4.2: "No floating-point values anywhere in the record (MUST NOT)".
        raise TypeError("floats forbidden in freens canonical CBOR")

    # --- Byte strings (major type 2) -------------------------------------
    if isinstance(obj, (bytes, bytearray)):
        # dumps(b"")->40, dumps(b"abc")->43616263,
        # dumps(b"\x00"*24)->5818 + 24 zero bytes (len 24 needs 0x58 0x18),
        # dumps(b"\x00"*32)->5820 + 32 zero bytes (len 32 -> 0x58 0x20).
        payload = bytes(obj)
        return _encode_head(2, len(payload)) + payload

    # --- Text strings (major type 3) -------------------------------------
    if isinstance(obj, str):
        # spec §4.2: "Text strings are UTF-8, NFC-normalized where human-supplied."
        normalised = unicodedata.normalize("NFC", obj)
        payload = normalised.encode("utf-8")
        # dumps("abc")->63616263 (len 3 -> 0x60|3 = 0x63, then "abc").
        return _encode_head(3, len(payload)) + payload

    # --- Arrays (major type 4, always definite) --------------------------
    if isinstance(obj, (list, tuple)):
        # dumps([])->80, dumps([1,2,3])->83010203,
        # dumps([1,300,b"\x01\x02\x03"])->830119012c43010203.
        parts = [_encode_head(4, len(obj))]
        parts.extend(_encode(item) for item in obj)
        return b"".join(parts)

    # --- Maps (major type 5, always definite, canonically sorted) --------
    if isinstance(obj, dict):
        return _encode_pairs(obj.items())

    raise TypeError(
        "unsupported type for canonical CBOR: %r" % type(obj).__name__)


def _encode_pairs(pairs):
    """Encode an iterable of ``(key, value)`` pairs as a canonical map.

    Canonical key ordering (RFC 8949 §4.2.1) is "length-first, then
    bytewise": sort by ``(len(encoded_key), encoded_key)``. For freens this
    is simply ascending numeric order for the small integer keys 1..12, but
    the rule is implemented in full generality so any mix of int/bytes/str/
    bool/None/tuple keys sorts correctly.

    Duplicate keys (two keys whose encodings are byte-identical) are rejected
    with ``ValueError`` per spec §4.2 ("No duplicate map keys (MUST NOT)").
    """
    encoded = []
    for key, value in pairs:
        # Keys use the same encoder as values; a tuple key becomes a CBOR
        # array, which still sorts correctly by its encoded bytes.
        kb = _encode(key)
        vb = _encode(value)
        encoded.append((kb, vb))

    # Canonical order: shorter encoded key first, then lexicographic bytes.
    encoded.sort(key=lambda kv: (len(kv[0]), kv[0]))

    # Detect byte-identical key encodings (true CBOR-level duplicates).
    seen = set()
    for kb, _ in encoded:
        if kb in seen:
            raise ValueError("duplicate map key in canonical CBOR")
        seen.add(kb)

    head = _encode_head(5, len(encoded))
    # dumps({})->a0, dumps({1:2})->a10102,
    # dumps({1:2,3:4})->a201020304 (and dumps({3:4,1:2}) re-sorts to the same),
    # dumps({2:b"abc",1:1})->a201010243616263 (key 01 01, then key 02 43 616263).
    body = b"".join(kb + vb for kb, vb in encoded)
    return head + body


def dumps(obj):
    """Canonical-encode ``obj`` to deterministic CBOR ``bytes``.

    Supported Python types and their CBOR mapping:

    ===============  ===========  ===========================================
    Python           CBOR         Notes
    ===============  ===========  ===========================================
    ``int`` (>=0)    major 0      minimum-length unsigned
    ``int`` (<0)     major 1      argument = -1-n, minimum-length (rarely used)
    ``bytes``/       major 2      definite byte string
    ``bytearray``
    ``str``          major 3      UTF-8, NFC-normalised
    ``list``/        major 4      definite array
    ``tuple``
    ``dict``         major 5      definite map, keys sorted canonically
    ``bool``         0xf5/0xf4    RFC 8949 preferred simple values
    ``NoneType``     0xf6         null
    ===============  ===========  ===========================================

    ``float`` raises ``TypeError`` ("floats forbidden in freens canonical
    CBOR"). Any other type raises ``TypeError``. Duplicate map keys (after
    canonical encoding) raise ``ValueError``.
    """
    return _encode(obj)


def dumps_map(items):
    """Encode ``items`` (an iterable of ``(key, value)`` pairs) as a canonical
    map after sorting.

    Convenient when a caller wants an explicit, ordered field list with small
    integer keys instead of building a ``dict`` first::

        dumps_map([(1, "alice"), (2, b"\x00\x01")])

    The result is byte-identical to ``dumps(dict(items))`` whenever ``items``
    has no duplicate keys, because both paths sort by canonical key order.
    """
    return _encode_pairs(items)


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

def _read_argument(buf, ai, offset):
    """Given the additional-information value ``ai`` and the current read
    ``offset``, return ``(argument, new_offset)``.

    ``ai`` values 24..27 indicate 1/2/4/8 big-endian argument bytes follow;
    ``ai`` 31 is the indefinite-length / break marker (rejected); 28..30 are
    reserved by RFC 8949 (rejected).
    """
    if ai < 24:
        return ai, offset
    if ai == 24:
        if offset + 1 > len(buf):
            raise ValueError("unexpected end of CBOR input (1-byte argument)")
        return buf[offset], offset + 1
    if ai == 25:
        if offset + 2 > len(buf):
            raise ValueError("unexpected end of CBOR input (2-byte argument)")
        return struct.unpack_from(">H", buf, offset)[0], offset + 2
    if ai == 26:
        if offset + 4 > len(buf):
            raise ValueError("unexpected end of CBOR input (4-byte argument)")
        return struct.unpack_from(">I", buf, offset)[0], offset + 4
    if ai == 27:
        if offset + 8 > len(buf):
            raise ValueError("unexpected end of CBOR input (8-byte argument)")
        return struct.unpack_from(">Q", buf, offset)[0], offset + 8
    if ai == 31:
        # Covers all indefinite-length starters (0x5f/0x7f/0x9f/0xbf, and the
        # invalid-for-those-types 0x1f/0x3f) and the break code 0xff (major 7,
        # ai 31). All are forbidden in freens canonical CBOR.
        raise ValueError(
            "indefinite-length CBOR items and break codes are forbidden")
    # ai == 28, 29, 30 are reserved by RFC 8949 §3.1 and must not appear.
    raise ValueError("reserved additional-information value %d" % ai)


def _decode(buf, offset):
    """Decode one CBOR data item starting at ``offset``.

    Returns ``(value, new_offset)``. Raises ``ValueError`` on any
    spec-forbidden construct (indefinite length, break, tags, floats,
    duplicate map keys, truncated input, invalid UTF-8).
    """
    if offset >= len(buf):
        raise ValueError("unexpected end of CBOR input")
    initial = buf[offset]
    offset += 1
    major = initial >> 5
    ai = initial & 0x1F
    argument, offset = _read_argument(buf, ai, offset)

    if major == 0:
        # Unsigned integer.
        return argument, offset

    if major == 1:
        # Negative integer: value = -1 - argument.
        return -1 - argument, offset

    if major == 2:
        # Byte string (definite; indefinite rejected in _read_argument).
        end = offset + argument
        if end > len(buf):
            raise ValueError("byte string length exceeds available input")
        return bytes(buf[offset:end]), end

    if major == 3:
        # Text string: must be valid UTF-8.
        end = offset + argument
        if end > len(buf):
            raise ValueError("text string length exceeds available input")
        chunk = bytes(buf[offset:end])
        try:
            text = chunk.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid UTF-8 in CBOR text string") from exc
        return text, end

    if major == 4:
        # Definite array.
        items = []
        for _ in range(argument):
            item, offset = _decode(buf, offset)
            items.append(item)
        return items, offset

    if major == 5:
        # Definite map. Duplicates are detected by byte-identical key
        # encodings (robust against the bool/1 Python-equality quirk: True
        # and 1 encode to different bytes, so they are not CBOR duplicates).
        result = {}
        seen_key_bytes = set()
        for _ in range(argument):
            key_start = offset
            key, offset = _decode(buf, offset)
            key_end = offset
            value, offset = _decode(buf, offset)
            key_bytes = bytes(buf[key_start:key_end])
            if key_bytes in seen_key_bytes:
                raise ValueError("duplicate map key in canonical CBOR")
            seen_key_bytes.add(key_bytes)
            result[key] = value
        return result, offset

    if major == 6:
        # CBOR tags are not used by freens and are rejected outright.
        raise ValueError("CBOR tags (major type 6) are not supported")

    if major == 7:
        # Simple values and floats.
        if ai == 20:
            return False, offset            # 0xf4
        if ai == 21:
            return True, offset             # 0xf5
        if ai == 22:
            return None, offset             # 0xf6
        # Float encodings (spec §4.2 forbids floats entirely).
        if ai in (25, 26, 27):
            # ai 25 = 0xf9 half-float, ai 26 = 0xfa single, ai 27 = 0xfb double.
            raise ValueError("floats are forbidden in freens canonical CBOR")
        if ai == 23:
            # 0xf7 undefined: freens never emits it and Python has no
            # undefined singleton, so reject rather than silently alias null.
            raise ValueError("CBOR undefined value (0xf7) is not supported")
        if ai == 24:
            # 0xf8 + 1-byte simple value (32..255). Unsupported.
            raise ValueError(
                "unsupported CBOR simple value (0xf8, value %d)" % argument)
        # ai < 24 handled above; only 0xe0..0xf3 (simple values 0..19 encoded
        # inline) remain, none of which freens uses.
        raise ValueError(
            "unsupported major-type-7 simple value (ai=%d)" % ai)

    # Unreachable: major is 0..7 by construction (3 high bits).
    raise ValueError("invalid CBOR major type %d" % major)


def loads(data):
    """Decode canonical CBOR ``data`` (a bytes-like object) to a Python object.

    Mirrors the inputs accepted by :func:`dumps`: ``int``, ``bytes``, ``str``,
    ``bool``, ``None``, ``list``, ``dict``.

    Rejected with ``ValueError``:

    * indefinite-length items and the break code (0x1f/0x3f/0x5f/0x7f/0x9f/
      0xbf/0xff);
    * floats (major-type-7 float codes 0xf9/0xfa/0xfb);
    * CBOR tags (major type 6);
    * duplicate map keys (identical encoded key bytes);
    * truncated input, trailing bytes, or invalid UTF-8.

    ``TypeError`` is raised if ``data`` is not bytes-like.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("loads() requires a bytes-like input")
    buf = bytes(data)
    if not buf:
        raise ValueError("empty CBOR input")
    value, offset = _decode(buf, 0)
    if offset != len(buf):
        raise ValueError("trailing bytes after top-level CBOR value")
    return value
