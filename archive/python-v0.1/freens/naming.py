"""freens naming model — aliases, name decomposition, wire names, DHT keys.

Implements ``specifications.md`` §3.2 ("Aliases: the human-readable layer",
lines 138-163) and §3.3 ("Name decomposition and wire format",
lines 164-201).

§3.2 — aliases
    An alias is the human-readable pointer to a TLD ID.  It MUST be
    1-63 bytes long, consist only of ``a-z``, ``0-9``, ``-`` (the LDH
    rule, RFC 5890 §3.2), MUST NOT begin or end with ``-`` and MUST NOT
    be all-numeric.  Normalization is lowercase ASCII.

    (IDNA2008 U-labels are a spec MAY; this module implements strict
    ASCII LDH and exposes ``IDNA_NORMALIZER`` as an injection hook so a
    caller can supply a UTS #46 normalizer without this module depending
    on any IDNA library.)

§3.3 — names and wire format
    A displayed name ``www.alice.foo`` decomposes into displayed labels
    ``["www", "alice"]`` (most-specific first, TLD-adjacent last) plus the
    alias ``"foo"``.  The wire name stores labels in the *reverse* order
    (TLD-adjacent first, mirroring DNS canonical ordering)::

        wire_name = concat( for each label from TLD-adjacent to most-specific:
                              0x01 || uint8(len) || label_bytes )
                    || 0x00
                    || tld_id            # 32 raw bytes

    Worked example (spec line 192)::

        wire_name("www.alice.foo") =
            0x01 05 "alice" 0x01 03 "www" 0x00 <32-byte tld_id of foo>

    DHT storage keys (32 bytes each, spec lines 195-201)::

        K_tld   = tld_id
        K_name  = SHA-256(0x02 || wire_name)
        K_claim = SHA-256(0x03 || "claim:" || alias_bytes)

Golden vectors (hold by construction; see the doctests below)::

    decompose_name("www.alice.foo") == (["www", "alice"], "foo")
    encode_wire_name(["www","alice"], "foo", tld_id_32) ==
        b"\\x01\\x05alice\\x01\\x03www\\x00" + tld_id_32
    decode_wire_name(wire) == (["www", "alice"], tld_id_32)
    dht_key_name(wire)     == SHA-256(b"\\x02" + wire)
    dht_key_claim("foo")   == SHA-256(b"\\x03claim:foo")

Error cases (raise :class:`NamingError`, a ``ValueError`` subclass):

* ``validate_alias``: ``"-a"``, ``"a-"``, ``""``, ``"a" * 64``,
  ``"123"`` (all-numeric), ``"a_b"`` (bad char), ``"abé"`` (non-ASCII).
* ``decompose_name``: ``".foo"`` (empty leading label), ``"a..b.foo"``
  (empty interior label), more than ``constants.MAX_LABELS`` labels,
  empty alias.

Doctests (deterministic, stdlib-only)::

    >>> from freens.naming import (validate_alias, is_valid_alias,
    ...     decompose_name, encode_wire_name, decode_wire_name,
    ...     dht_key_tld, dht_key_name, dht_key_claim)
    >>> import hashlib
    >>> validate_alias("Foo")
    'foo'
    >>> validate_alias("a")
    'a'
    >>> validate_alias("a-b")
    'a-b'
    >>> is_valid_alias("foo")
    True
    >>> is_valid_alias("123")
    False
    >>> decompose_name("www.alice.foo")
    (['www', 'alice'], 'foo')
    >>> decompose_name("alice.foo")
    (['alice'], 'foo')
    >>> decompose_name("foo")
    ([], 'foo')
    >>> decompose_name("foo.")
    ([], 'foo')
    >>> tld_id = bytes(range(32))
    >>> wire = encode_wire_name(["www", "alice"], "foo", tld_id)
    >>> wire == b"\\x01\\x05alice\\x01\\x03www\\x00" + tld_id
    True
    >>> labels, tid = decode_wire_name(wire)
    >>> (labels, tid == tld_id)
    (['www', 'alice'], True)
    >>> labels, tid = decode_wire_name(encode_wire_name([], "foo", tld_id))
    >>> (labels, tid == tld_id)
    ([], True)
    >>> dht_key_tld(tld_id) == tld_id
    True
    >>> dht_key_name(wire) == hashlib.sha256(b"\\x02" + wire).digest()
    True
    >>> dht_key_claim("foo") == hashlib.sha256(b"\\x03claim:foo").digest()
    True
    >>> dht_key_claim("FOO") == dht_key_claim("foo")
    True
"""

from __future__ import annotations

import hashlib
import re
from typing import Callable, Optional

from . import constants

__all__ = [
    "NamingError",
    "validate_alias",
    "is_valid_alias",
    "validate_label",
    "decompose_name",
    "encode_wire_name",
    "decode_wire_name",
    "dht_key_tld",
    "dht_key_name",
    "dht_key_claim",
]


class NamingError(ValueError):
    """Raised when an alias, label, or name violates the §3.2/§3.3 rules.

    Subclasses ``ValueError`` so callers may catch either.
    """


# ---------------------------------------------------------------------------
# IDNA hook (spec §3.2 makes U-labels a MAY)
# ---------------------------------------------------------------------------
# If set, ``validate_alias`` passes non-ASCII input through this callable
# before the LDH checks (the callable should return an ASCII A-label form,
# e.g. "xn--…", per UTS #46 transitional=False, useSTD3Rules=true).  Left
# as ``None`` by this reference implementation: strict ASCII LDH only.
IDNA_NORMALIZER: Optional[Callable[[str], str]] = None

# LDH charset (post-lowercase): a-z, 0-9, hyphen.
_LDH_RE = re.compile(r"[a-z0-9-]+")

# Entirely numeric (checked for aliases only; numeric labels are allowed).
_NUMERIC_RE = re.compile(r"[0-9]+")


# ---------------------------------------------------------------------------
# §3.2 — alias / label validation
# ---------------------------------------------------------------------------

def _check_ldh(s: str, what: str, allow_numeric: bool) -> None:
    """Shared LDH checks for ``s`` (already stripped + lowercased).

    Enforces: length 1..``constants.MAX_LABEL_LEN`` *bytes* (equivalent to
    characters once the charset check below has passed, since LDH is ASCII),
    charset ``[a-z0-9-]``, and no leading/trailing ``-``.  When
    ``allow_numeric`` is False (aliases), additionally rejects all-numeric
    strings.
    """
    if len(s) < constants.MIN_ALIAS_LEN or len(s) > constants.MAX_LABEL_LEN:
        raise NamingError(
            f"{what} length must be "
            f"{constants.MIN_ALIAS_LEN}-{constants.MAX_LABEL_LEN} bytes, "
            f"got {len(s)}"
        )
    if not _LDH_RE.fullmatch(s):
        hint = (
            ""
            if s.isascii()
            else " (non-ASCII input requires an installed IDNA_NORMALIZER hook)"
        )
        raise NamingError(
            f"{what} contains characters outside [a-z0-9-]: {s!r}{hint}"
        )
    if s.startswith("-") or s.endswith("-"):
        raise NamingError(f"{what} must not begin or end with '-': {s!r}")
    if not allow_numeric and _NUMERIC_RE.fullmatch(s):
        raise NamingError(f"{what} must not be all-numeric: {s!r}")


def validate_alias(alias: str) -> str:
    """Validate and normalize an alias per §3.2.  Return the normalized form.

    Steps: strip surrounding whitespace; lowercase ASCII; enforce length
    1-63 bytes; charset ``[a-z0-9-]``; no leading/trailing ``-``; and at
    least one non-digit (all-numeric aliases are forbidden).  Raise
    :class:`NamingError` on any violation.

    >>> validate_alias("Foo")
    'foo'
    >>> validate_alias("a-b")
    'a-b'

    Raises (see module docstring): ``"-a"``, ``"a-"``, ``""``,
    ``"a" * 64``, ``"123"``, ``"a_b"``, ``"abé"``.
    """
    if not isinstance(alias, str):
        raise TypeError(f"alias must be str, got {type(alias).__name__}")
    s = alias.strip()
    # §3.2 MAY: IDNA U-labels.  Hook-based so no idna dependency here.
    if not s.isascii() and IDNA_NORMALIZER is not None:
        s = IDNA_NORMALIZER(s)
    s = s.lower()
    _check_ldh(s, "alias", allow_numeric=False)
    return s


def is_valid_alias(alias: str) -> bool:
    """True iff :func:`validate_alias` succeeds on ``alias``.

    >>> is_valid_alias("foo")
    True
    >>> is_valid_alias("123")
    False
    """
    try:
        validate_alias(alias)
    except NamingError:
        return False
    return True


def validate_label(label: str) -> str:
    """Validate and normalize a single DNS-style label.  Return normalized.

    Same LDH rules as :func:`validate_alias` — length 1-63, charset
    ``[a-z0-9-]``, no leading/trailing ``-`` — except all-numeric labels
    are *allowed* (subdomains may be numeric, e.g. ``"123.foo"``; §3.2's
    all-numeric restriction applies only to the alias/TLD layer).  Raise
    :class:`NamingError` on violation.
    """
    if not isinstance(label, str):
        raise TypeError(f"label must be str, got {type(label).__name__}")
    s = label.strip().lower()
    _check_ldh(s, "label", allow_numeric=True)
    return s


# ---------------------------------------------------------------------------
# §3.3 — name decomposition and wire format
# ---------------------------------------------------------------------------

def decompose_name(name: str) -> tuple[list[str], str]:
    """Split a displayed dotted name into ``(displayed_labels, alias)``.

    ``'foo'`` -> ``([], 'foo')``;  ``'alice.foo'`` -> ``(['alice'], 'foo')``;
    ``'www.alice.foo'`` -> ``(['www', 'alice'], 'foo')``.  Displayed labels
    are returned in display order (most-specific first, TLD-adjacent last).

    Each label and the alias are normalized (lowercased + validated).  A
    single trailing root dot is stripped first (``'foo.'`` -> ``'foo'``).
    Raise :class:`NamingError` on: empty label or alias (leading dot,
    double dots), more than ``constants.MAX_LABELS`` labels, or any label /
    alias failing validation.

    >>> decompose_name("www.alice.foo")
    (['www', 'alice'], 'foo')
    >>> decompose_name("foo.")
    ([], 'foo')
    """
    if not isinstance(name, str):
        raise TypeError(f"name must be str, got {type(name).__name__}")
    s = name.strip()
    if s.endswith("."):  # strip a single trailing root dot
        s = s[:-1]
    parts = s.split(".")  # for s == "" this is [""], caught below
    if any(p == "" for p in parts):
        raise NamingError(
            f"empty label or alias in name {name!r} "
            "(leading/trailing dot or double dots)"
        )
    if len(parts) - 1 > constants.MAX_LABELS:
        raise NamingError(
            f"too many labels in name {name!r}: "
            f"max {constants.MAX_LABELS}, got {len(parts) - 1}"
        )
    labels = [validate_label(p) for p in parts[:-1]]
    alias = validate_alias(parts[-1])
    return (labels, alias)


def encode_wire_name(displayed_labels: list[str], alias: str, tld_id: bytes) -> bytes:
    """Build the §3.3 ``wire_name``.  Return ``bytes``.

    ``displayed_labels`` is in display order (most-specific first,
    TLD-adjacent last); it is reversed so labels are emitted TLD-adjacent
    first, mirroring DNS canonical ordering.  For each label, emit
    ``0x01 || uint8(len) || label_bytes``; then the ``0x00`` terminator;
    then the raw 32-byte ``tld_id``.

    The alias and every label are validated (and lowercased) first.
    Because validated labels are 1-63 ASCII bytes, the length always fits
    a uint8.  Raise :class:`NamingError` for invalid labels/alias or too
    many labels; ``ValueError`` if ``tld_id`` is not exactly 32 bytes.

    Worked example (spec line 192)::

        encode_wire_name(["www","alice"], "foo", tld_id) ==
            b"\\x01\\x05alice\\x01\\x03www\\x00" + tld_id
    """
    if not isinstance(tld_id, (bytes, bytearray)):
        raise ValueError(f"tld_id must be bytes, got {type(tld_id).__name__}")
    if len(tld_id) != constants.SHA256_LEN:
        raise ValueError(
            f"tld_id must be {constants.SHA256_LEN} bytes, got {len(tld_id)}"
        )
    alias_n = validate_alias(alias)
    labels_n = [validate_label(lb) for lb in displayed_labels]
    if len(labels_n) > constants.MAX_LABELS:
        raise NamingError(
            f"too many labels: max {constants.MAX_LABELS}, got {len(labels_n)}"
        )
    out = bytearray()
    # TLD-adjacent first == reverse of displayed order.
    for lb in reversed(labels_n):
        raw = lb.encode("ascii")  # 1..63 bytes after validation
        out.append(constants.WIRE_NAME_LABEL_MARKER)
        out.append(len(raw))  # uint8 length; 1..63 always fits
        out.extend(raw)
    out.append(constants.WIRE_NAME_TERMINATOR)
    out.extend(tld_id)
    return bytes(out)


def decode_wire_name(wire: bytes) -> tuple[list[str], bytes]:
    """Inverse of :func:`encode_wire_name`.

    Parse ``0x01 || len || label_bytes`` pairs until the ``0x00``
    terminator, then read the 32-byte ``tld_id``.  Labels are stored
    TLD-adjacent-first on the wire, so they are reversed back to displayed
    (left-to-right) order.  Return ``(displayed_labels, tld_id)``.

    Raise ``ValueError`` (possibly :class:`NamingError`) on malformed
    input: bad marker byte, label length overrunning the buffer,
    zero-length label, missing ``0x00`` terminator, trailing garbage or
    missing bytes around the 32-byte ``tld_id``, non-ASCII label bytes,
    or more than ``constants.MAX_LABELS`` labels.
    """
    if not isinstance(wire, (bytes, bytearray)):
        raise ValueError(f"wire must be bytes, got {type(wire).__name__}")
    w = bytes(wire)
    pos = 0
    tld_adjacent_first: list[str] = []
    while True:
        if pos >= len(w):
            raise ValueError("missing 0x00 terminator in wire name")
        marker = w[pos]
        pos += 1
        if marker == constants.WIRE_NAME_TERMINATOR:
            break
        if marker != constants.WIRE_NAME_LABEL_MARKER:
            raise ValueError(
                f"bad marker byte 0x{marker:02x} at offset {pos - 1} "
                f"(expected 0x01 or 0x00)"
            )
        if pos >= len(w):
            raise ValueError("truncated wire name: missing label length byte")
        length = w[pos]
        pos += 1
        if length == 0:
            raise ValueError("zero-length label in wire name")
        if pos + length > len(w):
            raise ValueError("label length overruns end of wire name")
        try:
            label = w[pos:pos + length].decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("non-ASCII bytes in wire name label") from None
        tld_adjacent_first.append(label)
        pos += length
    if len(tld_adjacent_first) > constants.MAX_LABELS:
        raise ValueError(
            f"too many labels in wire name: max {constants.MAX_LABELS}, "
            f"got {len(tld_adjacent_first)}"
        )
    tld_id = w[pos:]
    if len(tld_id) != constants.SHA256_LEN:
        raise ValueError(
            f"tld_id must be exactly {constants.SHA256_LEN} bytes after "
            f"terminator, got {len(tld_id)}"
        )
    displayed_labels = list(reversed(tld_adjacent_first))
    return (displayed_labels, tld_id)


# ---------------------------------------------------------------------------
# §3.3 — DHT storage-key derivation
# ---------------------------------------------------------------------------

def dht_key_tld(tld_id: bytes) -> bytes:
    """K_tld = tld_id (must be exactly 32 bytes)."""
    if not isinstance(tld_id, (bytes, bytearray)):
        raise ValueError(f"tld_id must be bytes, got {type(tld_id).__name__}")
    if len(tld_id) != constants.SHA256_LEN:
        raise ValueError(
            f"tld_id must be {constants.SHA256_LEN} bytes, got {len(tld_id)}"
        )
    return bytes(tld_id)


def dht_key_name(wire_name: bytes) -> bytes:
    """K_name = SHA-256(0x02 || wire_name).  Return 32 bytes.

    >>> dht_key_name(b"\\x01\\x05alice\\x00" + bytes(32)) == __import__(
    ...     "hashlib").sha256(b"\\x02\\x01\\x05alice\\x00" + bytes(32)).digest()
    True
    """
    if not isinstance(wire_name, (bytes, bytearray)):
        raise ValueError(
            f"wire_name must be bytes, got {type(wire_name).__name__}"
        )
    h = hashlib.sha256()
    h.update(bytes([constants.DHT_KEY_PREFIX_NAME]))
    h.update(bytes(wire_name))
    return h.digest()


def dht_key_claim(alias: str) -> bytes:
    """K_claim = SHA-256(0x03 || b"claim:" || alias_bytes).  Return 32 bytes.

    The alias is validated (and lowercased) first, so ``K_claim("FOO") ==
    K_claim("foo")``.  Raise :class:`NamingError` for an invalid alias.

    >>> dht_key_claim("foo") == __import__("hashlib").sha256(
    ...     b"\\x03claim:foo").digest()
    True
    """
    alias_n = validate_alias(alias)
    h = hashlib.sha256()
    h.update(bytes([constants.DHT_KEY_PREFIX_CLAIM]))
    h.update(b"claim:")
    h.update(alias_n.encode("ascii"))
    return h.digest()
