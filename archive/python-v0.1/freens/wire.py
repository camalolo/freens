"""freens central wire-format module — records, signed envelopes, KRPC messages.

This module implements the protocol-critical wire structures defined in
``specifications.md``:

* **§4 (lines 232-338)** — ``FREENS_Record``, ``SignedEnvelope``, canonical
  encoding & signing (§4.2), resource records (§4.3), validity rules (§4.4).
* **§3.4 (lines 203-224)** — delegation and authority-chain verification.
* **§8 (lines 643-719)** — ownership lifecycle (create / update / transfer /
  recovery / revoke / rotate) as it constrains record fields.
* **§6.3 / Appendix B (lines 1010-1051)** — the KRPC-like signed ``Message``
  envelope and its signature input.

Only relative imports of :mod:`freens.constants`, :mod:`freens.cbor_canon`,
:mod:`freens.crypto`, :mod:`freens.naming`, and :mod:`freens.claims` are used.
Every byte that crosses the wire or feeds a signature is produced by the
deterministic CBOR codec in :mod:`freens.cbor_canon` (RFC 8949 §4.2), so
encoding is byte-stable: ``from_bytes(to_bytes(x)).to_bytes() == to_bytes(x)``.

Design decisions (chosen interpretation; documented here as normative for this
implementation)
---------------------------------------------------------------

1. **SignedEnvelope field 1 (``record``) is the ``FREENS_Record`` encoded as an
   EMBEDDED canonical CBOR map (major type 5), NOT a bstr wrapper.** §4.1's
   schema ``1 : record ; FREENS_Record (canonical CBOR)`` denotes the value
   type, and canonical encoding is deterministic, so the bytes produced by
   ``cbor_canon.dumps(record.to_cbor_value())`` are byte-identical to the
   embedded serialization of the same dict inside the envelope map. The
   signature is therefore computed over ``record.canonical_bytes()`` and
   verification is unambiguous: re-encoding the decoded record yields exactly
   the bytes the signer signed.

2. **``H_record`` (record hash; used for ``prev_hash`` chaining and the §6.4 DHT
   store tie-break) = SHA-256(canonical_cbor(SignedEnvelope)).** Per §4.2 line
   288 ``H_record = SHA-256(canonical_cbor(SignedEnvelope))`` — i.e. the hash
   covers the WHOLE signed envelope (record + sig + signer), not just the
   record. Implemented as ``SHA-256(self.to_bytes())``.

3. **Optional record fields (8 delegation, 9 prev_hash, 10 recovery, 11 claim,
   12 revoke) are OMITTED from the CBOR map when absent** (not encoded as
   null). Field 12 (``revoke``) is included ONLY when its value is ``True``;
   ``False``/``None`` are both omitted (a record without ``revoke`` is the
   normal, non-revoked state).

4. **RR = a 3-element CBOR array ``[type:uint, ttl:uint, rdata:bstr]``.** The
   ``rrset`` (field 7) is an array of these arrays and MAY be empty.

A note on the §6.3 signature-input ambiguity: §6.3 (line 437) says the message
signature covers ``canonical(t||id||peer_id||a)`` while Appendix B.1 (line
1022) writes ``canonical(t|id|peer_id|a)``. We follow §6.3's 4-tuple
``(transaction_id, sender_id, recipient_id, payload)`` and encode it as a
canonical CBOR **array** ``[t, id, recipient_id, a]`` for unambiguity. The
``recipient_id`` is transport context, so it is supplied as a parameter to
:meth:`Message.sign` / :meth:`Message.verify` rather than carried in the
message body.

Public API
----------
* :class:`WireError` — raised on malformed wire structures (a ``ValueError``
  subclass).
* :class:`RR`, :class:`RecoveryPolicyWire`, :class:`Record`,
  :class:`SignedEnvelope`, :class:`Message` — the wire dataclasses.
* :func:`sign_record`, :func:`is_basic_valid`, :func:`record_is_revoked`,
  :func:`envelope_wins`, :func:`verify_authority_chain` — the protocol helpers.
* ``RR_TYPE_*`` / ``MSG_TYPE_*`` — IANA DNS RR type codes and KRPC ``y``
  markers (the latter are also exposed as the string constants used on the
  wire).
"""

from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass, field
from typing import Optional

from . import constants, cbor_canon, crypto, naming, claims

__all__ = [
    "WireError",
    # RR type codes (IANA DNS parameters; §4.3 table)
    "RR_TYPE_A",
    "RR_TYPE_NS",
    "RR_TYPE_CNAME",
    "RR_TYPE_TXT",
    "RR_TYPE_MX",
    "RR_TYPE_AAAA",
    "RR_TYPE_SRV",
    "RR_TYPE_SSHFP",
    "RR_TYPE_TLSA",
    "RR_TYPE_CAA",
    # wire dataclasses
    "RR",
    "RecoveryPolicyWire",
    "Record",
    "SignedEnvelope",
    "Message",
    # protocol helpers
    "sign_record",
    "is_basic_valid",
    "record_is_revoked",
    "envelope_wins",
    "verify_authority_chain",
    # KRPC message-type markers
    "MSG_TYPE_QUERY",
    "MSG_TYPE_RESPONSE",
    "MSG_TYPE_ERROR",
]


class WireError(ValueError):
    """Raised when a wire structure (Record / SignedEnvelope / Message / RR)
    is malformed: missing required map keys, wrong value shapes, bad byte
    lengths on decode, etc.

    Subclasses ``ValueError`` so callers may catch either. Range/length
    problems raised eagerly at construction time (e.g. an out-of-range TTL)
    are also ``ValueError`` (often ``WireError``); the helper
    :func:`is_basic_valid` and :func:`verify_authority_chain` never raise —
    they convert every failure into a ``False`` return.
    """


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _is_uint(x) -> bool:
    """True iff ``x`` is a plain ``int`` (NOT a ``bool``).

    ``bool`` is a subclass of ``int`` in Python (``isinstance(True, int)`` is
    ``True``), but freens maps the two to distinct CBOR bytes (``True``->0xf5,
    ``1``->0x01). Every ``uint`` field on the wire MUST therefore reject a
    ``bool`` so a value like ``sequence=True`` cannot be emitted as 0xf5 where
    a minimal unsigned integer was required.
    """
    return isinstance(x, int) and not isinstance(x, bool)


def _is_bytes(x) -> bool:
    """True iff ``x`` is ``bytes`` or ``bytearray``."""
    return isinstance(x, (bytes, bytearray))


# ---------------------------------------------------------------------------
# RR type codes (IANA DNS parameters; §4.3 table)
# ---------------------------------------------------------------------------
RR_TYPE_A = 1        # rdata = 4 raw bytes
RR_TYPE_NS = 2       # rdata = wire_name / DNS name
RR_TYPE_CNAME = 5    # rdata = wire_name / DNS name
RR_TYPE_TXT = 16     # rdata = opaque bytes (RECOMMENDED UTF-8, <=4096 bytes)
RR_TYPE_MX = 15      # rdata = uint16 preference || wire_name/DNS name
RR_TYPE_AAAA = 28    # rdata = 16 raw bytes
RR_TYPE_SRV = 33     # rdata = uint16 prio, uint16 weight, uint16 port, target
RR_TYPE_SSHFP = 44   # rdata = algorithm, fingerprint-type, fingerprint
RR_TYPE_TLSA = 52    # rdata = usage, selector, matching-type, certificate data
RR_TYPE_CAA = 257    # rdata = flags, tag, value


# ---------------------------------------------------------------------------
# §4.3 — Resource record
# ---------------------------------------------------------------------------
@dataclass
class RR:
    """A single resource record (§4.3): ``RR = [type:uint, ttl:uint, rdata:bstr]``.

    Constraints enforced on construction (``ValueError``):

    * ``type`` is a uint ``>= 0`` (any IANA DNS type code; unknown codes are
      preserved verbatim for opaque forwarding, as in DNS).
    * ``ttl`` is in ``1..RECORD_MAX_TTL`` seconds.
    * ``rdata`` is a byte string (``bytearray`` is coerced to ``bytes``).

    The CBOR value is a definite 3-element array; the ``rrset`` (Record field
    7) is an array of these arrays and MAY be empty.
    """

    type: int
    ttl: int
    rdata: bytes

    def __post_init__(self) -> None:
        # type: uint >= 0 (bool rejected — see _is_uint).
        if not _is_uint(self.type) or self.type < 0:
            raise ValueError("RR.type must be a uint >= 0")
        # ttl: 0 < ttl <= RECORD_MAX_TTL (§4.3 line 319).
        if (
            not _is_uint(self.ttl)
            or self.ttl <= 0
            or self.ttl > constants.RECORD_MAX_TTL
        ):
            raise ValueError(
                f"RR.ttl must be in 1..{constants.RECORD_MAX_TTL}, "
                f"got {self.ttl!r}"
            )
        # rdata: bytes (coerce bytearray -> bytes).
        if not _is_bytes(self.rdata):
            raise ValueError(
                f"RR.rdata must be bytes, got {type(self.rdata).__name__}"
            )
        self.rdata = bytes(self.rdata)

    def to_cbor_value(self) -> list:
        """Return the §4.3 array ``[type, ttl, rdata]``."""
        return [self.type, self.ttl, self.rdata]

    @classmethod
    def from_cbor_value(cls, v) -> "RR":
        """Decode a §4.3 RR array.

        Requires a 3-element array (``list``/``tuple``); any other shape raises
        :class:`WireError`. Element type/range checks then run in
        ``__post_init__`` (raising ``ValueError`` on a bad type/ttl/rdata).
        """
        if not isinstance(v, (list, tuple)) or len(v) != 3:
            raise WireError(
                f"RR must be a 3-element array [type, ttl, rdata], "
                f"got {type(v).__name__} of length "
                f"{len(v) if hasattr(v, '__len__') else '?'}"
            )
        return cls(type=v[0], ttl=v[1], rdata=v[2])

    # -- convenience constructors (common record types) --------------------
    @classmethod
    def a(cls, ip4_bytes: bytes, ttl: int = constants.RECORD_DEFAULT_TTL) -> "RR":
        """Build an A record; ``rdata`` = 4 raw bytes. ``ValueError`` if not 4."""
        if not _is_bytes(ip4_bytes):
            raise ValueError("A rdata must be bytes")
        b = bytes(ip4_bytes)
        if len(b) != 4:
            raise ValueError(f"A rdata must be exactly 4 bytes, got {len(b)}")
        return cls(type=RR_TYPE_A, ttl=ttl, rdata=b)

    @classmethod
    def aaaa(cls, ip6_bytes: bytes, ttl: int = constants.RECORD_DEFAULT_TTL) -> "RR":
        """Build an AAAA record; ``rdata`` = 16 raw bytes. ``ValueError`` if not 16."""
        if not _is_bytes(ip6_bytes):
            raise ValueError("AAAA rdata must be bytes")
        b = bytes(ip6_bytes)
        if len(b) != 16:
            raise ValueError(f"AAAA rdata must be exactly 16 bytes, got {len(b)}")
        return cls(type=RR_TYPE_AAAA, ttl=ttl, rdata=b)

    @classmethod
    def txt(cls, text: str, ttl: int = constants.RECORD_DEFAULT_TTL) -> "RR":
        """Build a TXT record; ``rdata`` = UTF-8 bytes, NFC-normalized.

        §4.3 recommends TXT rdata be UTF-8 and <=4096 bytes; the size cap is a
        RECOMMENDATION (not enforced here), but NFC normalization IS applied
        so two equivalent human-supplied strings encode identically.
        """
        if not isinstance(text, str):
            raise ValueError("TXT text must be a str")
        rdata = unicodedata.normalize("NFC", text).encode("utf-8")
        return cls(type=RR_TYPE_TXT, ttl=ttl, rdata=rdata)


# ---------------------------------------------------------------------------
# §5.4 — Recovery policy (wire representation)
# ---------------------------------------------------------------------------
@dataclass
class RecoveryPolicyWire:
    """Wire form of the §5.4 ``RecoveryPolicy``.

    CBOR::

        RecoveryPolicy = {
          1 : threshold    ; uint, e.g. 2 (>= 1, <= len(keys))
          2 : keys         ; array of bstr(32), recovery public keys
          3 : timelock     ; uint seconds before a recovery takes effect
        }

    This is a thin serializable mirror of :class:`crypto.RecoveryPolicy`; it
    carries no signing/recovery logic, only the on-wire fields and their
    structural validation.
    """

    threshold: int
    keys: list            # list of 32-byte recovery public keys
    timelock: int = constants.RECOVERY_TIMELOCK

    def __post_init__(self) -> None:
        if not _is_uint(self.threshold) or self.threshold < 1:
            raise ValueError("threshold must be a uint >= 1")
        if not isinstance(self.keys, (list, tuple)):
            raise ValueError("keys must be a list of 32-byte public keys")
        coerced: list = []
        for k in self.keys:
            if not _is_bytes(k) or len(k) != constants.ED25519_PUBLIC_KEY_LEN:
                raise ValueError(
                    "each recovery key must be "
                    f"{constants.ED25519_PUBLIC_KEY_LEN} bytes"
                )
            coerced.append(bytes(k))
        self.keys = coerced
        if self.threshold > len(self.keys):
            raise ValueError("threshold must be <= len(keys)")
        if not _is_uint(self.timelock) or self.timelock < 0:
            raise ValueError("timelock must be a uint >= 0")

    def to_cbor_value(self) -> dict:
        """Return the §5.4 map ``{1: threshold, 2: keys, 3: timelock}``."""
        return {1: self.threshold, 2: self.keys, 3: self.timelock}

    @classmethod
    def from_cbor_value(cls, m) -> "RecoveryPolicyWire":
        """Decode a §5.4 recovery-policy map (keys 1, 2, 3 required)."""
        if not isinstance(m, dict):
            raise WireError(
                f"RecoveryPolicy must be a map, got {type(m).__name__}"
            )
        for k in (1, 2, 3):
            if k not in m:
                raise WireError(f"RecoveryPolicy missing required key {k}")
        if not isinstance(m[2], list):
            raise WireError("RecoveryPolicy field 2 (keys) must be an array")
        try:
            return cls(threshold=m[1], keys=list(m[2]), timelock=m[3])
        except (ValueError, TypeError) as exc:
            raise WireError(f"invalid RecoveryPolicy: {exc}") from exc


# ---------------------------------------------------------------------------
# §4.1 — FREENS_Record
# ---------------------------------------------------------------------------
@dataclass
class Record:
    """A freens record (§4.1). Fields 1-12.

    Required fields (always present in the CBOR map):

    * ``version`` (1) — uint, MUST be 1 (``constants.PROTO_VERSION``).
    * ``name`` (2) — bstr, the §3.3 ``wire_name`` (TLD-adjacent-first).
    * ``owner`` (3) — bstr(32), the Ed25519 public key currently authorized.
    * ``sequence`` (4) — uint, strictly increasing per name (>= 1).
    * ``created`` (5) / ``expires`` (6) — uint unix seconds; ``created <= expires``.
    * ``rrset`` (7) — array of :class:`RR` (MAY be empty; <= ``MAX_RRS_PER_RECORD``).

    Optional fields (OMITTED from the CBOR map when absent — design decision 3):

    * ``delegation`` (8) — bstr(32), new owner pk taking over this name + subtree.
    * ``prev_hash`` (9) — bstr(32), SHA-256 of the previous signed envelope.
    * ``recovery`` (10) — :class:`RecoveryPolicyWire`.
    * ``claim`` (11) — :class:`claims.AliasClaim` (TLD records only).
    * ``revoke`` (12) — bool; included ONLY when ``True``.

    Dataclass field order places all non-default fields first (required by
    ``@dataclass``); CBOR key order in :meth:`to_cbor_value` is canonical
    (ascending numeric) and is INDEPENDENT of dataclass field order —
    ``cbor_canon`` sorts map keys regardless of insertion order.
    """

    # --- required (no defaults) ---
    name: bytes                                  # field 2: wire_name bstr
    owner: bytes                                 # field 3: bstr(32)
    sequence: int                                # field 4: uint, strictly increasing
    created: int                                 # field 5: uint unix seconds
    expires: int                                 # field 6: uint unix seconds
    # --- defaulted ---
    rrset: list = field(default_factory=list)    # field 7: array of RR (MAY be empty)
    version: int = constants.PROTO_VERSION       # field 1 (always 1)
    delegation: Optional[bytes] = None           # field 8: bstr(32)
    prev_hash: Optional[bytes] = None            # field 9: bstr(32)
    recovery: Optional[RecoveryPolicyWire] = None  # field 10
    claim: Optional[claims.AliasClaim] = None    # field 11 (TLD records only)
    revoke: Optional[bool] = None                # field 12: include only when True

    def __post_init__(self) -> None:
        # Defensive coercion of mutable bytearray fields to immutable bytes
        # before structural validation (cbor decode already yields bytes, so
        # this is a no-op on the decode path; it protects callers that pass
        # bytearray).
        if isinstance(self.name, bytearray):
            self.name = bytes(self.name)
        if isinstance(self.owner, bytearray):
            self.owner = bytes(self.owner)
        if isinstance(self.delegation, bytearray):
            self.delegation = bytes(self.delegation)
        if isinstance(self.prev_hash, bytearray):
            self.prev_hash = bytes(self.prev_hash)
        self.validate_structure()

    def validate_structure(self) -> None:
        """Re-run all structural checks (§4.1/§4.3/§4.4 rule 1).

        Pure (no mutation). Raises :class:`WireError` on the first violation.
        Called by ``__post_init__`` and by :func:`is_basic_valid`; also safe to
        call on a record decoded from CBOR.
        """
        # 1 : version (uint, MUST be 1)
        if not _is_uint(self.version) or self.version != constants.PROTO_VERSION:
            raise WireError(
                f"version must be {constants.PROTO_VERSION}, got {self.version!r}"
            )
        # 2 : name (non-empty bstr — wire_name; deeper parsing is a §3.3
        # concern performed by the authority-chain walker)
        if not _is_bytes(self.name) or len(self.name) == 0:
            raise WireError("name (field 2) must be a non-empty byte string")
        # 3 : owner (bstr(32))
        if (
            not _is_bytes(self.owner)
            or len(self.owner) != constants.ED25519_PUBLIC_KEY_LEN
        ):
            raise WireError(
                f"owner (field 3) must be {constants.ED25519_PUBLIC_KEY_LEN} bytes"
            )
        # 4 : sequence (uint >= 1)
        if not _is_uint(self.sequence) or self.sequence < 1:
            raise WireError("sequence (field 4) must be a uint >= 1")
        # 5 : created (uint unix seconds)
        if not _is_uint(self.created) or self.created < 0:
            raise WireError("created (field 5) must be a non-negative uint")
        # 6 : expires (uint unix seconds; created <= expires)
        if not _is_uint(self.expires) or self.expires < 0:
            raise WireError("expires (field 6) must be a non-negative uint")
        if self.created > self.expires:
            raise WireError("created (field 5) must be <= expires (field 6)")
        # 7 : rrset (list of RR, <= MAX_RRS_PER_RECORD)
        if not isinstance(self.rrset, list):
            raise WireError("rrset (field 7) must be a list of RR")
        if len(self.rrset) > constants.MAX_RRS_PER_RECORD:
            raise WireError(
                f"rrset (field 7) exceeds {constants.MAX_RRS_PER_RECORD} RRs"
            )
        for rr in self.rrset:
            if not isinstance(rr, RR):
                raise WireError("rrset (field 7) must contain only RR instances")
        # 8 : delegation (None | bstr(32))
        if self.delegation is not None:
            if (
                not _is_bytes(self.delegation)
                or len(self.delegation) != constants.ED25519_PUBLIC_KEY_LEN
            ):
                raise WireError(
                    f"delegation (field 8) must be "
                    f"{constants.ED25519_PUBLIC_KEY_LEN} bytes or None"
                )
        # 9 : prev_hash (None | bstr(32))
        if self.prev_hash is not None:
            if (
                not _is_bytes(self.prev_hash)
                or len(self.prev_hash) != constants.SHA256_LEN
            ):
                raise WireError(
                    f"prev_hash (field 9) must be "
                    f"{constants.SHA256_LEN} bytes or None"
                )
        # 10 : recovery (None | RecoveryPolicyWire)
        if self.recovery is not None and not isinstance(
            self.recovery, RecoveryPolicyWire
        ):
            raise WireError(
                "recovery (field 10) must be a RecoveryPolicyWire or None"
            )
        # 11 : claim (None | AliasClaim)
        if self.claim is not None and not isinstance(
            self.claim, claims.AliasClaim
        ):
            raise WireError("claim (field 11) must be an AliasClaim or None")
        # 12 : revoke (None | bool) — emitted only when True (decision 3)
        if self.revoke is not None and not isinstance(self.revoke, bool):
            raise WireError("revoke (field 12) must be None or bool")

    def to_cbor_value(self) -> dict:
        """Build the §4.1 map.

        Always includes keys 1-7. Includes 8 if ``delegation``, 9 if
        ``prev_hash``, 10 if ``recovery`` (as a nested map), 11 if ``claim``
        (as ``claim.to_cbor_value()``), and 12 ONLY when ``revoke is True``.
        ``cbor_canon`` sorts the keys into canonical (ascending numeric)
        order, so the dict's insertion order here is irrelevant to the output
        bytes.
        """
        m: dict = {
            1: self.version,
            2: self.name,
            3: self.owner,
            4: self.sequence,
            5: self.created,
            6: self.expires,
            7: [rr.to_cbor_value() for rr in self.rrset],
        }
        if self.delegation is not None:
            m[8] = self.delegation
        if self.prev_hash is not None:
            m[9] = self.prev_hash
        if self.recovery is not None:
            m[10] = self.recovery.to_cbor_value()
        if self.claim is not None:
            m[11] = self.claim.to_cbor_value()
        if self.revoke is True:  # design decision 3: include only when True
            m[12] = True
        return m

    @classmethod
    def from_cbor_value(cls, m: dict) -> "Record":
        """Decode a §4.1 map. Require keys 1-7; optional 8-12 as present.

        Field 11 is decoded via :meth:`claims.AliasClaim.from_cbor_value`;
        field 10 via :meth:`RecoveryPolicyWire.from_cbor_value`; field 7 via
        :meth:`RR.from_cbor_value`. Raises :class:`WireError` on missing
        required keys or any malformed sub-structure.
        """
        if not isinstance(m, dict):
            raise WireError(
                f"FREENS_Record must be a map, got {type(m).__name__}"
            )
        for k in (1, 2, 3, 4, 5, 6, 7):
            if k not in m:
                raise WireError(f"FREENS_Record missing required key {k}")

        # field 7: rrset (array of 3-element arrays)
        raw_rrset = m[7]
        if not isinstance(raw_rrset, list):
            raise WireError("rrset (field 7) must be an array")
        try:
            rrset = [RR.from_cbor_value(rr) for rr in raw_rrset]
        except WireError:
            raise
        except (ValueError, TypeError) as exc:
            raise WireError(f"invalid RR in rrset (field 7): {exc}") from exc

        # field 10: recovery
        recovery = None
        if 10 in m:
            try:
                recovery = RecoveryPolicyWire.from_cbor_value(m[10])
            except WireError:
                raise
            except (ValueError, TypeError) as exc:
                raise WireError(f"invalid recovery (field 10): {exc}") from exc

        # field 11: claim
        claim = None
        if 11 in m:
            try:
                claim = claims.AliasClaim.from_cbor_value(m[11])
            except claims.ClaimError as exc:
                raise WireError(f"invalid claim (field 11): {exc}") from exc
            except (ValueError, TypeError) as exc:
                raise WireError(f"invalid claim (field 11): {exc}") from exc

        # field 12: revoke (bool, optional). Decoded verbatim; validate_structure
        # will reject a non-bool.
        revoke = m.get(12)

        try:
            return cls(
                name=m[2],
                owner=m[3],
                sequence=m[4],
                created=m[5],
                expires=m[6],
                rrset=rrset,
                version=m[1],
                delegation=m.get(8),
                prev_hash=m.get(9),
                recovery=recovery,
                claim=claim,
                revoke=revoke,
            )
        except WireError:
            raise
        except (ValueError, TypeError) as exc:
            raise WireError(f"invalid FREENS_Record: {exc}") from exc

    def canonical_bytes(self) -> bytes:
        """The deterministic bytes that get signed / hashed.

        = ``cbor_canon.dumps(self.to_cbor_value())`` (RFC 8949 §4.2). Because
        canonical encoding is deterministic, this is byte-identical to the
        embedded serialization of the record map inside a SignedEnvelope
        (design decision 1), so signature verification is unambiguous.
        """
        return cbor_canon.dumps(self.to_cbor_value())


# ---------------------------------------------------------------------------
# §4.1 — SignedEnvelope
# ---------------------------------------------------------------------------
@dataclass
class SignedEnvelope:
    """§4.1 ``SignedEnvelope = {1: record, 2: sig, 3: signer}``.

    The object stored in and served from the DHT (§4.1 last paragraph). Field
    1 is the ``FREENS_Record`` as an EMBEDDED canonical CBOR map (design
    decision 1); field 2 is a 64-byte Ed25519 signature over
    ``record.canonical_bytes()``; field 3 is the 32-byte signer public key.

    ``sig``/``signer`` default to empty bytes so an envelope can be
    constructed before signing; :meth:`verify_signature` and
    :meth:`from_bytes` enforce the full 64/32-byte lengths.
    """

    record: Record
    sig: bytes = b""            # 64 bytes; set by sign_record()
    signer: bytes = b""         # 32 bytes; set by sign_record()

    def __post_init__(self) -> None:
        if not isinstance(self.record, Record):
            raise WireError("record must be a Record instance")
        if isinstance(self.sig, bytearray):
            self.sig = bytes(self.sig)
        if isinstance(self.signer, bytearray):
            self.signer = bytes(self.signer)
        if not _is_bytes(self.sig):
            raise WireError("sig must be bytes")
        if not _is_bytes(self.signer):
            raise WireError("signer must be bytes")
        # Allow empty (pre-sign) or full length only.
        if len(self.sig) not in (0, constants.ED25519_SIGNATURE_LEN):
            raise WireError(
                f"sig must be 0 or {constants.ED25519_SIGNATURE_LEN} bytes, "
                f"got {len(self.sig)}"
            )
        if len(self.signer) not in (0, constants.ED25519_PUBLIC_KEY_LEN):
            raise WireError(
                f"signer must be 0 or {constants.ED25519_PUBLIC_KEY_LEN} bytes, "
                f"got {len(self.signer)}"
            )

    # -- canonical bytes ---------------------------------------------------
    def canonical_record_bytes(self) -> bytes:
        """The bytes the signature covers = ``self.record.canonical_bytes()``.

        Identical to ``cbor_canon.dumps(record.to_cbor_value())`` and, by
        determinism, byte-identical to the embedded record serialization in
        :meth:`to_bytes` (design decision 1).
        """
        return self.record.canonical_bytes()

    def to_cbor_value(self) -> dict:
        """Return the §4.1 envelope map ``{1: record_map, 2: sig, 3: signer}``."""
        return {
            1: self.record.to_cbor_value(),
            2: self.sig,
            3: self.signer,
        }

    def to_bytes(self) -> bytes:
        """Canonical CBOR of the whole envelope.

        = ``cbor_canon.dumps(self.to_cbor_value())``. This is what is stored
        and transmitted in the DHT and what :meth:`record_hash` hashes.
        """
        return cbor_canon.dumps(self.to_cbor_value())

    def record_hash(self) -> bytes:
        """``H_record`` = SHA-256(canonical_cbor(SignedEnvelope)) (§4.2 line 288).

        = ``SHA-256(self.to_bytes())`` — 32 bytes. Covers the WHOLE envelope
        (record + sig + signer). Used for ``prev_hash`` chaining (§8.3) and the
        §6.4 DHT store tie-break (higher sequence, else bytewise-greater hash).
        """
        return hashlib.sha256(self.to_bytes()).digest()

    # -- signature verification --------------------------------------------
    def verify_signature(self) -> bool:
        """True iff ``sig`` verifies under ``signer`` against
        ``canonical_record_bytes()``.

        Enforces ``len(sig) == 64`` and ``len(signer) == 32`` first, then
        delegates to :func:`crypto.verify_signature` (non-raising). Returns
        ``False`` (never raises) on any mismatch.
        """
        if len(self.sig) != constants.ED25519_SIGNATURE_LEN:
            return False
        if len(self.signer) != constants.ED25519_PUBLIC_KEY_LEN:
            return False
        return crypto.verify_signature(
            self.signer, self.sig, self.canonical_record_bytes()
        )

    # -- decode ------------------------------------------------------------
    @classmethod
    def from_cbor_value(cls, m: dict) -> "SignedEnvelope":
        """Decode a §4.1 envelope map. Require keys 1, 2, 3; field 1 must be a
        map (decoded via :meth:`Record.from_cbor_value`); field 2 must be a
        64-byte bstr; field 3 must be a 32-byte bstr. Raises :class:`WireError`.
        """
        if not isinstance(m, dict):
            raise WireError(
                f"SignedEnvelope must be a map, got {type(m).__name__}"
            )
        for k in (1, 2, 3):
            if k not in m:
                raise WireError(f"SignedEnvelope missing required key {k}")
        rec_val = m[1]
        if not isinstance(rec_val, dict):
            raise WireError(
                "SignedEnvelope field 1 (record) must be an embedded CBOR map"
            )
        record = Record.from_cbor_value(rec_val)
        sig = m[2]
        signer = m[3]
        if (
            not _is_bytes(sig)
            or len(sig) != constants.ED25519_SIGNATURE_LEN
        ):
            raise WireError(
                f"SignedEnvelope field 2 (sig) must be a "
                f"{constants.ED25519_SIGNATURE_LEN}-byte bstr"
            )
        if (
            not _is_bytes(signer)
            or len(signer) != constants.ED25519_PUBLIC_KEY_LEN
        ):
            raise WireError(
                f"SignedEnvelope field 3 (signer) must be a "
                f"{constants.ED25519_PUBLIC_KEY_LEN}-byte bstr"
            )
        return cls(record=record, sig=bytes(sig), signer=bytes(signer))

    @classmethod
    def from_bytes(cls, data: bytes) -> "SignedEnvelope":
        """Decode canonical CBOR envelope bytes (the DHT store payload).

        Validates CBOR well-formedness, then delegates to
        :meth:`from_cbor_value` for structural checks. Raises
        :class:`WireError` on any problem (bad CBOR, missing keys, bad lengths,
        malformed record).
        """
        if not _is_bytes(data):
            raise WireError("envelope bytes must be bytes-like")
        try:
            m = cbor_canon.loads(data)
        except Exception as exc:
            raise WireError(f"invalid CBOR for SignedEnvelope: {exc}") from exc
        try:
            return cls.from_cbor_value(m)
        except WireError:
            raise
        except (ValueError, TypeError) as exc:
            raise WireError(f"invalid SignedEnvelope: {exc}") from exc


# ---------------------------------------------------------------------------
# Signing factory
# ---------------------------------------------------------------------------
def sign_record(record: Record, keypair: crypto.Keypair) -> SignedEnvelope:
    """Build a :class:`SignedEnvelope` over ``record`` signed by ``keypair``.

    ``signer = keypair.public_bytes``; ``sig = keypair.sign(record.canonical_bytes())``.
    The returned envelope's :meth:`SignedEnvelope.verify_signature` is ``True``
    by construction.
    """
    signer = keypair.public_bytes
    sig = keypair.sign(record.canonical_bytes())
    return SignedEnvelope(record=record, sig=sig, signer=signer)


# ---------------------------------------------------------------------------
# §4.4 validity (structural + sig + time; authority chain is separate)
# ---------------------------------------------------------------------------
def is_basic_valid(envelope: SignedEnvelope, now: int) -> bool:
    """§4.4 structural + signature + time-window check (NON-raising).

    Returns ``True`` iff ALL hold:

    * ``record.version == 1`` and structural validity (``validate_structure``);
    * ``verify_signature() == True``;
    * ``record.sequence >= 1``;
    * ``record.created <= now < record.expires``.

    This does NOT check the authority chain (§3.4 — use
    :func:`verify_authority_chain`) nor sequence history (§4.4 rule 4, which
    requires DHT state). Any exception is converted to ``False``.
    """
    try:
        if not isinstance(envelope, SignedEnvelope):
            return False
        r = envelope.record
        if r.version != constants.PROTO_VERSION:
            return False
        r.validate_structure()
        if not envelope.verify_signature():
            return False
        if r.sequence < 1:
            return False
        if not (r.created <= now < r.expires):
            return False
        return True
    except Exception:
        return False


def record_is_revoked(envelope: SignedEnvelope) -> bool:
    """True iff field 12 (``revoke``) is ``True`` (§8.5).

    A record with ``revoke=True`` (and conventionally an empty rrset) marks the
    name deliberately dead, as opposed to merely expired.
    """
    return envelope.record.revoke is True


# ---------------------------------------------------------------------------
# §6.4 PUT step 3 — DHT store winner rule
# ---------------------------------------------------------------------------
def envelope_wins(newer: SignedEnvelope, older: SignedEnvelope) -> bool:
    """§6.4 step 3: does ``newer`` strictly win over ``older``?

    A storing node keeps the new record only if it strictly wins::

        newer.sequence > older.sequence, OR
        (newer.sequence == older.sequence AND
         newer.record_hash() > older.record_hash()  # bytewise)

    The tie-break (same sequence, bytewise-greater ``H_record``) makes
    idempotent concurrent republication convergent: two identical-sequence
    replicas of the SAME envelope have identical hashes (neither wins — they
    are the same record), while two DIFFERENT same-sequence records are
    resolved deterministically by hash. Assumes both envelopes are already
    signature-valid (the caller checks that).

    Python's ``bytes > bytes`` is lexicographic bytewise (big-endian), matching
    the spec's "bytewise-greater H_record".
    """
    ns = newer.record.sequence
    os_ = older.record.sequence
    if ns > os_:
        return True
    if ns == os_:
        return newer.record_hash() > older.record_hash()
    return False


# ---------------------------------------------------------------------------
# §3.4 — authority chain
# ---------------------------------------------------------------------------
def verify_authority_chain(chain: list) -> bool:
    """Walk a chain of :class:`SignedEnvelope` from the TLD record down to a
    name record (§3.4) and return ``True`` iff every hop verifies.

    ``chain`` is ordered TLD-first: ``chain[0]`` is the TLD record,
    ``chain[-1]`` is the target. Rules:

    * Every envelope's :meth:`SignedEnvelope.verify_signature` must hold.
    * **chain[0] (TLD record)** — self-certifying root:
        - ``signer == record.owner`` (the TLD key self-signs its TLD record);
        - the record name decodes to ZERO labels (it IS the TLD);
        - ``crypto.tld_id(owner) == tld_id`` embedded in the name
          (self-certifying: the TLD key's SHA-256 is the namespace root).
    * **chain[i] for i > 0** — authorized by the parent ``chain[i-1]``:
        - either ``parent.record.delegation == child.signer`` (a §3.4
          delegation names the child's signer), OR
        - ``parent.record.owner == child.signer`` (the parent signs the child
          directly, with no delegation in between); AND
        - the child name is a STRICT DESCENDANT of the parent name: same
          ``tld_id`` and the parent's labels are a proper suffix of the child's
          (displayed order is most-specific-first, so the shared TLD-adjacent
          root is the suffix).
    * Maximum chain length is ``MAX_LABELS + 1`` (the TLD root plus at most
      ``MAX_LABELS`` label-level records); ``decode_wire_name`` independently
      caps each name at ``MAX_LABELS`` labels.

    Non-raising: every decode/structural failure yields ``False``.
    """
    if not isinstance(chain, (list, tuple)) or len(chain) == 0:
        return False
    # Max depth: TLD root (0 labels) + up to MAX_LABELS label-level records.
    if len(chain) > constants.MAX_LABELS + 1:
        return False

    # (0) Every envelope must be a SignedEnvelope with a valid signature.
    for env in chain:
        if not isinstance(env, SignedEnvelope):
            return False
        try:
            if not env.verify_signature():
                return False
        except Exception:
            return False

    # (1) chain[0]: self-certifying TLD root.
    root = chain[0]
    if root.signer != root.record.owner:
        return False  # the TLD record must be self-signed by its owner key
    try:
        root_labels, root_tld_id = naming.decode_wire_name(root.record.name)
    except Exception:
        return False
    if len(root_labels) != 0:
        return False  # the TLD record's wire_name has no labels
    if crypto.tld_id(root.record.owner) != root_tld_id:
        return False  # not self-certifying: SHA-256(owner) != tld_id in name

    # (2) Each subsequent hop: authorized by the parent AND a strict descendant.
    for i in range(1, len(chain)):
        parent = chain[i - 1]
        child = chain[i]

        # (2a) Authorization: child.signer is named by the parent.
        authorized = False
        if (
            parent.record.delegation is not None
            and parent.record.delegation == child.signer
        ):
            # §3.4 delegation: parent record points at the child's signer for
            # this name AND its subtree.
            authorized = True
        elif parent.record.owner == child.signer:
            # Parent signs the child directly (owner = TLD signs alice.foo).
            authorized = True
        if not authorized:
            return False

        # (2b) Descent: child name is a strict descendant of parent name.
        try:
            p_labels, p_tld_id = naming.decode_wire_name(parent.record.name)
            c_labels, c_tld_id = naming.decode_wire_name(child.record.name)
        except Exception:
            return False
        if c_tld_id != p_tld_id:
            return False  # different TLD root
        if len(c_labels) <= len(p_labels):
            return False  # child must be strictly deeper than parent
        # Parent's labels are the shared TLD-adjacent suffix of the child
        # (displayed order is most-specific-first => shared root is the tail).
        # When the parent is the TLD (p_labels == []) every same-TLD child
        # qualifies, so the suffix check is skipped.
        if len(p_labels) > 0 and c_labels[-len(p_labels):] != p_labels:
            return False

    return True


# ---------------------------------------------------------------------------
# §6.3 / Appendix B.1 — DHT KRPC Message
# ---------------------------------------------------------------------------
MSG_TYPE_QUERY = "q"
MSG_TYPE_RESPONSE = "r"
MSG_TYPE_ERROR = "e"


@dataclass
class Message:
    """§6.3 / Appendix B.1 KRPC-like signed CBOR message envelope.

    CBOR::

        Message = {
          1 : y    ; "q" | "r" | "e"             (query / response / error)
          2 : t    ; bstr(<=16)                  transaction id
          3 : q    ; text                        method name (queries only)
          4 : a    ; map                         arguments / return values
          5 : id   ; bstr(32)                    sender Node ID
          6 : pk   ; bstr(32)                    sender public key
          7 : sig  ; bstr(64)                    Ed25519 over signing_input
        }

    Node identity is verified on receipt: ``id == SHA-256(pk)`` (§6.2), enforced
    in ``__post_init__``. The signature covers the canonical CBOR array
    ``[t, id, recipient_id, a]`` (§6.3 line 437; design-decision note above on
    the §6.3/Appendix-B ``recipient_id``/``peer_id`` wording). ``recipient_id``
    is transport context (the receiving node's ID), so it is supplied to
    :meth:`sign` / :meth:`verify` rather than stored in the message body.
    """

    y: str                          # "q" / "r" / "e"
    t: bytes                        # transaction id, 1..16 bytes
    a: dict                         # arguments / return values
    id: bytes                       # field 5: sender node id (32) = SHA-256(pk)
    pk: bytes                       # field 6: sender public key (32)
    q: Optional[str] = None         # field 3: method name (queries only)
    sig: bytes = b""                # field 7: 64-byte signature (0 before sign)

    def __post_init__(self) -> None:
        # 1 : y
        if self.y not in (MSG_TYPE_QUERY, MSG_TYPE_RESPONSE, MSG_TYPE_ERROR):
            raise WireError(
                f"y (field 1) must be 'q', 'r', or 'e', got {self.y!r}"
            )
        # 2 : t (bstr 1..16)
        if not _is_bytes(self.t):
            raise WireError("t (field 2) must be bytes")
        self.t = bytes(self.t)
        if not (1 <= len(self.t) <= 16):
            raise WireError(
                f"t (field 2) must be 1..16 bytes, got {len(self.t)}"
            )
        # 4 : a (map)
        if not isinstance(self.a, dict):
            raise WireError(
                f"a (field 4) must be a map, got {type(self.a).__name__}"
            )
        # 6 : pk (bstr 32)
        if (
            not _is_bytes(self.pk)
            or len(self.pk) != constants.ED25519_PUBLIC_KEY_LEN
        ):
            raise WireError(
                f"pk (field 6) must be {constants.ED25519_PUBLIC_KEY_LEN} bytes"
            )
        self.pk = bytes(self.pk)
        # 5 : id (bstr 32) = SHA-256(pk)  (§6.2: verified on receipt)
        if (
            not _is_bytes(self.id)
            or len(self.id) != constants.NODE_ID_LEN
        ):
            raise WireError(
                f"id (field 5) must be {constants.NODE_ID_LEN} bytes"
            )
        self.id = bytes(self.id)
        if crypto.node_id(self.pk) != self.id:
            raise WireError("id (field 5) must equal SHA-256(pk) (field 6)")
        # 3 : q (text, queries only; ignored on responses/errors)
        if self.y == MSG_TYPE_QUERY:
            if not isinstance(self.q, str) or not self.q:
                raise WireError(
                    "query message requires a non-empty method name "
                    "(field 3 'q')"
                )
        else:
            self.q = None  # tolerate and drop a stray field 3 on r/e
        # 7 : sig (0 before signing, or 64)
        if isinstance(self.sig, bytearray):
            self.sig = bytes(self.sig)
        if not _is_bytes(self.sig):
            raise WireError("sig (field 7) must be bytes")
        if len(self.sig) not in (0, constants.ED25519_SIGNATURE_LEN):
            raise WireError(
                f"sig (field 7) must be 0 or "
                f"{constants.ED25519_SIGNATURE_LEN} bytes, got {len(self.sig)}"
            )

    # -- signature input / sign / verify -----------------------------------
    def signing_input(self, recipient_id: bytes) -> bytes:
        """The bytes the signature covers.

        = canonical CBOR of the 4-element array ``[self.t, self.id,
        recipient_id, self.a]`` (§6.3 line 437). ``recipient_id`` is the
        receiving node's 32-byte ID (transport context). Raises
        :class:`WireError` if ``recipient_id`` is not 32 bytes.
        """
        if (
            not _is_bytes(recipient_id)
            or len(recipient_id) != constants.NODE_ID_LEN
        ):
            raise WireError(
                f"recipient_id must be {constants.NODE_ID_LEN} bytes"
            )
        return cbor_canon.dumps(
            [self.t, self.id, bytes(recipient_id), self.a]
        )

    def sign(self, keypair: crypto.Keypair, recipient_id: bytes) -> None:
        """Sign this message in place.

        Sets ``pk = keypair.public_bytes``, refreshes ``id = SHA-256(pk)`` (so
        the ``id == node_id(pk)`` invariant always holds post-sign), and sets
        ``sig = keypair.sign(signing_input(recipient_id))``.
        """
        if (
            not _is_bytes(recipient_id)
            or len(recipient_id) != constants.NODE_ID_LEN
        ):
            raise WireError(
                f"recipient_id must be {constants.NODE_ID_LEN} bytes"
            )
        self.pk = keypair.public_bytes
        self.id = crypto.node_id(self.pk)
        self.sig = keypair.sign(self.signing_input(bytes(recipient_id)))

    def verify(self, recipient_id: bytes) -> bool:
        """True iff ``id == SHA-256(pk)`` AND ``sig`` verifies under ``pk``
        against ``signing_input(recipient_id)``.

        Non-raising: any failure (bad recipient_id length, missing signature,
        bad signature) returns ``False``.
        """
        try:
            if crypto.node_id(self.pk) != self.id:
                return False
            if len(self.sig) != constants.ED25519_SIGNATURE_LEN:
                return False
            return crypto.verify_signature(
                self.pk, self.sig, self.signing_input(recipient_id)
            )
        except Exception:
            return False

    # -- CBOR ---------------------------------------------------------------
    def to_cbor_value(self) -> dict:
        """Build the §6.3 map. Always keys 1, 2, 4, 5, 6, 7; include key 3
        (``q``) iff ``y == "q"``."""
        m: dict = {
            1: self.y,
            2: self.t,
            4: self.a,
            5: self.id,
            6: self.pk,
            7: self.sig,
        }
        if self.y == MSG_TYPE_QUERY:
            m[3] = self.q
        return m

    def to_bytes(self) -> bytes:
        """Canonical CBOR of the whole message."""
        return cbor_canon.dumps(self.to_cbor_value())

    @classmethod
    def from_cbor_value(cls, m: dict) -> "Message":
        """Decode a §6.3 message map. Require keys 1, 2, 4, 5, 6, 7; key 3
        (``q``) is optional and read only for queries. Structural validation
        (``y`` value, ``id == SHA-256(pk)``, lengths) runs in ``__post_init__``.
        """
        if not isinstance(m, dict):
            raise WireError(f"Message must be a map, got {type(m).__name__}")
        for k in (1, 2, 4, 5, 6, 7):
            if k not in m:
                raise WireError(f"Message missing required key {k}")
        return cls(
            y=m[1],
            t=m[2],
            a=m[4],
            id=m[5],
            pk=m[6],
            q=m.get(3),
            sig=m[7],
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "Message":
        """Decode canonical CBOR message bytes. Raises :class:`WireError` on
        bad CBOR or any structural problem (including a forged ``id``)."""
        if not _is_bytes(data):
            raise WireError("message bytes must be bytes-like")
        try:
            m = cbor_canon.loads(data)
        except Exception as exc:
            raise WireError(f"invalid CBOR for Message: {exc}") from exc
        try:
            return cls.from_cbor_value(m)
        except WireError:
            raise
        except (ValueError, TypeError) as exc:
            raise WireError(f"invalid Message: {exc}") from exc

    # -- factory helpers ---------------------------------------------------
    @classmethod
    def query(
        cls,
        method: str,
        args: dict,
        sender_keypair: crypto.Keypair,
        recipient_id: bytes,
        txid: bytes,
    ) -> "Message":
        """Build and sign a query message (``y == "q"``).

        ``method`` becomes field 3; ``txid`` is the transaction id (1..16
        bytes); ``id``/``pk`` are derived from ``sender_keypair``.
        """
        if not isinstance(method, str) or not method:
            raise WireError("method must be a non-empty string")
        if not isinstance(args, dict):
            raise WireError("args must be a dict")
        pk = sender_keypair.public_bytes
        nid = crypto.node_id(pk)
        msg = cls(
            y=MSG_TYPE_QUERY, t=txid, a=dict(args), id=nid, pk=pk, q=method
        )
        msg.sign(sender_keypair, recipient_id)
        return msg

    @classmethod
    def response(
        cls,
        args: dict,
        sender_keypair: crypto.Keypair,
        recipient_id: bytes,
        txid: bytes,
    ) -> "Message":
        """Build and sign a response message (``y == "r"``)."""
        if not isinstance(args, dict):
            raise WireError("args must be a dict")
        pk = sender_keypair.public_bytes
        nid = crypto.node_id(pk)
        msg = cls(y=MSG_TYPE_RESPONSE, t=txid, a=dict(args), id=nid, pk=pk)
        msg.sign(sender_keypair, recipient_id)
        return msg

    @classmethod
    def error(
        cls,
        args: dict,
        sender_keypair: crypto.Keypair,
        recipient_id: bytes,
        txid: bytes,
    ) -> "Message":
        """Build and sign an error message (``y == "e"``)."""
        if not isinstance(args, dict):
            raise WireError("args must be a dict")
        pk = sender_keypair.public_bytes
        nid = crypto.node_id(pk)
        msg = cls(y=MSG_TYPE_ERROR, t=txid, a=dict(args), id=nid, pk=pk)
        msg.sign(sender_keypair, recipient_id)
        return msg


# ===========================================================================
# Golden / sanity vectors (asserted BY CONSTRUCTION; documented here, exercised
# by the test suite — not executed in this module).
#
# Let kp = crypto.Keypair.generate(); tid = crypto.tld_id(kp.public_bytes);
# wire = naming.encode_wire_name([], "foo", tid). Then:
#
#   * rec = Record(name=wire, owner=kp.public_bytes, sequence=1,
#                  created=1000, expires=2000,
#                  rrset=[RR.a(bytes([203,0,113,42]), ttl=300)])
#     env = sign_record(rec, kp)
#         -> env.verify_signature() == True
#         -> env.record_hash() == hashlib.sha256(env.to_bytes()).digest()
#
#   * Tampering any record field (e.g. env.record.rrset[0].ttl = 301) changes
#     env.record.canonical_bytes(), so env.verify_signature() == False.
#
#   * Round trip: SignedEnvelope.from_bytes(env.to_bytes()) yields an envelope
#     whose record fields, sig, and signer are equal to env's, and whose
#     .to_bytes() == env.to_bytes() (byte-stable canonical encoding).
#
#   * envelope_wins(seq5_env, seq4_env) == True
#     envelope_wins(seq4_env, seq5_env) == False
#     For two same-sequence envelopes, the one with the bytewise-greater
#     record_hash() wins; identical hashes at the same sequence yield False
#     (neither strictly wins — they are the same record).
#
#   * record_is_revoked(env_with_revoke_True)  == True
#     record_is_revoked(env_with_revoke_None)  == False
#
#   * A 1-hop authority chain [tld_env] verifies True iff
#     tld_env.signer == tld_env.record.owner == kp.public_bytes AND
#     crypto.tld_id(kp.public_bytes) == tld_id decoded from the wire_name.
#
#   * A 2-hop chain: tld_env (owner=tld_pk, delegation=alice_pk, signed by
#     tld_pk) + alice_env (owner=alice_pk, signer=alice_pk, name=
#     encode_wire_name(["alice"], "foo", tld_id)) ->
#     verify_authority_chain([tld_env, alice_env]) == True.
#     If alice_env.signer is forged to a different key, it returns False
#     (the delegation names alice_pk specifically).
#
#   * Message.query("ping", {}, kp, recipient_id, txid).verify(recipient_id)
#     == True. Tampering message.a (or t, id, pk, sig, recipient_id) makes
#     verify() == False. Message.from_bytes(m.to_bytes()) round-trips and
#     re-encodes byte-identically.
# ===========================================================================
