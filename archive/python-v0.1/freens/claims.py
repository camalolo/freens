"""Alias claims, witness attestations, proof-of-work, and deterministic
collision ordering for the freens protocol.

Implements ``specifications.md`` §7 ("Registration and Collision
Resolution", lines 501-642), in particular the ``AliasClaim`` and
``WitnessAttestation`` CBOR records of §7.3 (lines 544-578), the
registration / resolution procedure of §7.4 (lines 588-623), and the
worked example of Appendix C.1 (lines 1054-1066).

PoW prefix — nonce is EXCLUDED (authoritative interpretation)
-------------------------------------------------------------
§7.3 line 566-567 says the PoW ``prefix`` is "the canonical CBOR of
fields ``{1..5}`` of ``AliasClaim``". Taken literally that would include
field 4 (``nonce``), which is nonsensical — the nonce is precisely the
value being searched and cannot be part of its own hash input. Appendix
C.1 line 1057-1058 is the authoritative worked example and resolves the
ambiguity::

    Alice mines ``nonce``:
        SHA-256(cbor{alias:"foo", tld_id, ts, claimant_pk} || nonce) < 2^232

i.e. the prefix is the canonical CBOR of the **identity** fields
``{1:alias, 2:tld_id, 3:timestamp, 5:claimant_pk}`` — field 4 (``nonce``)
is intentionally EXCLUDED. The literal ``{1..5}`` in §7.3 is loose prose;
C.1 is normative. This module follows C.1 exactly, and
:meth:`AliasClaim.prefix_bytes` documents the field-4 skip in a comment.

Deterministic ordering (§7.4 step 3)
------------------------------------
Surviving claims are ordered ascending by the lexicographic tuple
``(timestamp, pow_hash, tld_id)``: earliest asserted time wins; ties are
broken by the lower PoW hash (a public lottery), then by the lower TLD ID.
This total order is computable by any client from claim contents alone,
yielding convergence without consensus. Ties on ``(timestamp, pow_hash)``
are impossible between distinct claimants because ``tld_id`` differs.

Public API
----------
* :class:`ClaimError` — raised on malformed claim/attestation maps.
* :class:`WitnessAttestation` — a single witness's co-signature of a claim.
* :class:`AliasClaim` — a full alias-claim record (PoW + witnesses).
* :func:`select_winner` — pick the deterministic winner of a claim set.
* :func:`order_claims` — sort surviving claims by §7.4 order.
* :func:`verify_full` — the §7.4 step-2 full-validity filter.

Only relative imports of :mod:`freens.constants`, :mod:`freens.cbor_canon`,
:mod:`freens.crypto`, and :mod:`freens.naming` are used.
"""

from __future__ import annotations

import hashlib  # noqa: F401  (part of the documented crypto surface; SHA-256 underlies crypto.pow_hash/tld_id)
from dataclasses import dataclass, field
from typing import Optional, Set

from . import constants, cbor_canon, crypto, naming

__all__ = [
    "ClaimError",
    "WitnessAttestation",
    "AliasClaim",
    "select_winner",
    "order_claims",
    "verify_full",
]


class ClaimError(ValueError):
    """Raised when a claim or attestation CBOR map is structurally invalid
    (missing required keys, wrong shape). Subclasses ``ValueError`` so
    callers may catch either. Byte-length violations are raised as plain
    ``ValueError`` by ``__post_init__``; CBOR-shape problems (missing keys,
    non-map witnesses, …) are raised as ``ClaimError`` by the
    ``from_cbor_value`` classmethods.
    """


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _as_bytes(value, name: str, length: Optional[int]) -> bytes:
    """Coerce ``value`` to ``bytes``, enforcing it is bytes/bytearray and
    (when ``length`` is not None) exactly ``length`` bytes long.

    Raises ``TypeError`` for non-bytes input and ``ValueError`` on length
    mismatch. Using a dedicated helper keeps the dataclass ``__post_init__``
    bodies small and uniform.
    """
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
    b = bytes(value)
    if length is not None and len(b) != length:
        raise ValueError(f"{name} must be {length} bytes, got {len(b)}")
    return b


# ---------------------------------------------------------------------------
# §7.3 — WitnessAttestation
# ---------------------------------------------------------------------------
@dataclass
class WitnessAttestation:
    """A single witness node's co-signature of an alias claim (§7.3).

    CBOR::

        WitnessAttestation = {
          1 : node_id      ; bstr(32) = SHA-256(node_pk)
          2 : node_pk      ; bstr(32), Ed25519 verifying key
          3 : ts           ; uint, the witness's own timestamp (seconds)
          4 : sig          ; bstr(64): node_pk signs
                             canonical("freens-witness-v1",
                                        alias, tld_id, claimant_pk, ts)
        }

    The signed message is built by :func:`crypto.witness_signing_message`
    (a length-prefixed, self-contained byte string — no CBOR encoder on the
    verify path, so verification is deterministic and dependency-free).
    """

    node_id: bytes   # 32 = SHA-256(node_pk)
    node_pk: bytes   # 32, Ed25519 verifying key
    ts: int          # witness's own timestamp (unix seconds)
    sig: bytes       # 64, Ed25519 signature

    def __post_init__(self) -> None:
        # Length checks (raise ValueError per spec). Coerce bytearray->bytes
        # and ts->int so downstream crypto/ordering is type-stable.
        self.node_id = _as_bytes(self.node_id, "node_id", constants.NODE_ID_LEN)
        self.node_pk = _as_bytes(self.node_pk, "node_pk", constants.ED25519_PUBLIC_KEY_LEN)
        self.sig = _as_bytes(self.sig, "sig", constants.ED25519_SIGNATURE_LEN)
        self.ts = int(self.ts)

    # -- signing / verification --------------------------------------------
    def signing_input(self, alias: str, tld_id: bytes,
                      claimant_pk: bytes) -> bytes:
        """The canonical bytes the witness signed for this claim context.

        Delegates to :func:`crypto.witness_signing_message` using this
        attestation's own ``ts``. ``alias`` is normalized inside that helper
        indirectly via the length-prefixed encoding (the raw UTF-8 of the
        caller-supplied alias is used; callers SHOULD pass the already-
        normalized alias — :class:`AliasClaim` always does).
        """
        return crypto.witness_signing_message(alias, tld_id, claimant_pk, self.ts)

    def verify(self, alias: str, tld_id: bytes, claimant_pk: bytes) -> bool:
        """True iff (a) ``node_id == SHA-256(node_pk)`` and (b) ``sig``
        verifies under ``node_pk`` against the canonical signing input for
        ``(alias, tld_id, claimant_pk, ts)``.

        Never raises: a bad signature or a node_id/pubkey mismatch simply
        returns ``False`` (matching :func:`crypto.verify_signature`'s
        no-raise contract). Tampering *any* of ``(node_id, node_pk, ts, sig)``
        or the claim context ``(alias, tld_id, claimant_pk)`` makes this
        return ``False``.
        """
        # (a) node_id must bind to node_pk (prevents a claimant forging an
        #     attestation under an unrelated node_id).
        if crypto.node_id(self.node_pk) != self.node_id:
            return False
        # (b) signature must verify under node_pk.
        return crypto.verify_signature(
            self.node_pk, self.sig, self.signing_input(alias, tld_id, claimant_pk)
        )

    # -- CBOR ---------------------------------------------------------------
    def to_cbor_value(self) -> dict:
        """Return the §7.3 map ``{1:node_id, 2:node_pk, 3:ts, 4:sig}``."""
        return {1: self.node_id, 2: self.node_pk, 3: self.ts, 4: self.sig}

    @classmethod
    def from_cbor_value(cls, m: dict) -> "WitnessAttestation":
        """Decode a witness map. Require keys 1, 2, 3, 4 (raise
        :class:`ClaimError` if any is missing); lengths are then enforced
        by ``__post_init__``.
        """
        if not isinstance(m, dict):
            raise ClaimError(f"WitnessAttestation must be a map, got {type(m).__name__}")
        for k in (1, 2, 3, 4):
            if k not in m:
                raise ClaimError(f"WitnessAttestation missing required key {k}")
        return cls(node_id=m[1], node_pk=m[2], ts=m[3], sig=m[4])

    # -- factory ------------------------------------------------------------
    @classmethod
    def create(cls, node_keypair: "crypto.Keypair", ts: int, alias: str,
               tld_id: bytes, claimant_pk: bytes) -> "WitnessAttestation":
        """Build a fully-signed attestation from a witness keypair.

        Computes ``node_pk`` from the keypair, ``node_id = SHA-256(node_pk)``,
        and signs the canonical witness message for
        ``(alias, tld_id, claimant_pk, ts)``. The returned attestation
        verifies ``True`` under the same context.
        """
        node_pk = node_keypair.public_bytes
        node_id = crypto.node_id(node_pk)
        msg = crypto.witness_signing_message(alias, tld_id, claimant_pk, ts)
        sig = node_keypair.sign(msg)
        return cls(node_id=node_id, node_pk=node_pk, ts=ts, sig=sig)


# ---------------------------------------------------------------------------
# §7.3 — AliasClaim
# ---------------------------------------------------------------------------
@dataclass
class AliasClaim:
    """An alias-claim record (§7.3): PoW-bound identity + witness quorum.

    CBOR::

        AliasClaim = {
          1 : alias        ; text, normalized per §3.2
          2 : tld_id       ; bstr(32), claimant's TLD = SHA-256(claimant_pk)
          3 : timestamp    ; uint, unix seconds, claimant-asserted
          4 : nonce        ; bstr(<=128), PoW nonce (nonce[0] == difficulty)
          5 : claimant_pk  ; bstr(32), Ed25519 TLD verifying key
          6 : pow_hash     ; bstr(32), SHA-256(prefix || nonce)
          7 : witnesses    ; array of WitnessAttestation
        }
    """

    alias: str
    tld_id: bytes        # 32; MUST == SHA-256(claimant_pk) (checked separately)
    timestamp: int       # unix seconds, claimant-asserted
    nonce: bytes         # <=128 bytes; conventionally nonce[0] == difficulty
    claimant_pk: bytes   # 32
    pow_hash: bytes      # 32
    witnesses: list = field(default_factory=list)

    def __post_init__(self) -> None:
        # Normalize the alias on construction (store the §3.2 normalized
        # form so prefix_bytes()/order are stable). NamingError is a
        # ValueError subclass, so invalid aliases surface as ValueError.
        self.alias = naming.validate_alias(self.alias)
        self.tld_id = _as_bytes(self.tld_id, "tld_id", constants.SHA256_LEN)
        self.timestamp = int(self.timestamp)
        # nonce: bstr(<=128); allow 0..128 bytes. nonce[0] conventionally
        # carries the difficulty (Appendix A.4), enforced nowhere structurally
        # (it is informational for verifiers).
        self.nonce = _as_bytes(self.nonce, "nonce", None)
        if len(self.nonce) > 128:
            raise ValueError(f"nonce must be <=128 bytes, got {len(self.nonce)}")
        self.claimant_pk = _as_bytes(
            self.claimant_pk, "claimant_pk", constants.ED25519_PUBLIC_KEY_LEN
        )
        self.pow_hash = _as_bytes(self.pow_hash, "pow_hash", constants.SHA256_LEN)
        # witnesses: accept any iterable of WitnessAttestation; store a list.
        if not isinstance(self.witnesses, list):
            self.witnesses = list(self.witnesses)

    # ---- PoW prefix & hashing --------------------------------------------
    def prefix_bytes(self) -> bytes:
        """Canonical CBOR of the claim's identity fields
        ``{1:alias, 2:tld_id, 3:timestamp, 5:claimant_pk}``.

        Field 4 (``nonce``) is intentionally EXCLUDED: Appendix C.1 line
        1057-1058 is authoritative and hashes ``cbor{alias, tld_id, ts,
        claimant_pk} || nonce``. (The literal ``{1..5}`` in §7.3 line 567
        is loose prose that would otherwise be self-referential.) See the
        module docstring for the full rationale.

        The alias is re-normalized via :func:`naming.validate_alias` for
        defensiveness; since ``__post_init__`` already stores the
        normalized form, this is a no-op in normal use.
        """
        return cbor_canon.dumps_map([
            (1, naming.validate_alias(self.alias)),
            (2, self.tld_id),
            (3, self.timestamp),
            (5, self.claimant_pk),
            # NOTE: field 4 (nonce) is deliberately OMITTED here — see C.1.
        ])

    def verify_pow(self, difficulty_bits: Optional[int] = None) -> bool:
        """Recompute ``pow_hash`` from ``prefix || nonce`` and verify it.

        Returns ``True`` iff BOTH hold:

        * ``SHA-256(self.prefix_bytes() || self.nonce) == self.pow_hash``
          (never trusts the stored ``pow_hash`` — always recomputes), AND
        * the recomputed digest has at least ``difficulty_bits`` leading
          zero bits.

        If ``difficulty_bits`` is ``None`` it is inferred: if ``nonce`` is
        non-empty and ``nonce[0] >= POW_DIFFICULTY_INIT`` we use
        ``nonce[0]`` (the Appendix A.4 convention), otherwise we default to
        :data:`constants.POW_DIFFICULTY_INIT`.
        """
        if difficulty_bits is None:
            if len(self.nonce) >= 1 and self.nonce[0] >= constants.POW_DIFFICULTY_INIT:
                difficulty_bits = self.nonce[0]
            else:
                difficulty_bits = constants.POW_DIFFICULTY_INIT
        # Recompute from the prefix + nonce (do NOT trust self.pow_hash).
        recomputed = crypto.pow_hash(self.prefix_bytes(), self.nonce)
        if recomputed != self.pow_hash:
            return False
        return crypto.meets_difficulty(recomputed, difficulty_bits)

    def verify_claimant_consistency(self) -> bool:
        """True iff ``tld_id == SHA-256(claimant_pk)`` (self-certifying TLD)."""
        return crypto.tld_id(self.claimant_pk) == self.tld_id

    # ---- Witnesses --------------------------------------------------------
    def valid_witnesses(self) -> list:
        """Subset of :attr:`witnesses` that verify under
        ``(self.alias, self.tld_id, self.claimant_pk)`` and whose
        ``node_id == SHA-256(node_pk)``.

        Deduplicated by ``node_id`` keeping the FIRST occurrence (a verifier
        must not let an attacker substitute a fresh valid signature for a
        node_id already present — the first one wins).
        """
        seen: Set[bytes] = set()
        deduped: list = []
        for w in self.witnesses:
            # Dedup by node_id first, keeping the first occurrence.
            if w.node_id in seen:
                continue
            seen.add(w.node_id)
            deduped.append(w)
        return [
            w for w in deduped
            if w.verify(self.alias, self.tld_id, self.claimant_pk)
        ]

    def has_quorum(self, witness_set_node_ids: Optional[Set[bytes]] = None,
                   quorum: int = constants.W) -> bool:
        """True iff there are at least ``quorum`` DISTINCT valid witnesses.

        If ``witness_set_node_ids`` is provided, only witnesses whose
        ``node_id`` is in that set are counted — this is the §7.3/§7.4
        restriction to the ``WITNESS_SET`` (=8) closest nodes to
        ``K_claim = SHA-256(0x03 || "claim:" || alias)``.
        """
        valid = self.valid_witnesses()
        if witness_set_node_ids is None:
            counted = {w.node_id for w in valid}
        else:
            counted = {w.node_id for w in valid if w.node_id in witness_set_node_ids}
        return len(counted) >= quorum

    # ---- CBOR -------------------------------------------------------------
    def to_cbor_value(self) -> dict:
        """Return the full §7.3 ``AliasClaim`` map (all 7 fields)."""
        return {
            1: self.alias,
            2: self.tld_id,
            3: self.timestamp,
            4: self.nonce,
            5: self.claimant_pk,
            6: self.pow_hash,
            7: [w.to_cbor_value() for w in self.witnesses],
        }

    @classmethod
    def from_cbor_value(cls, m: dict) -> "AliasClaim":
        """Decode an ``AliasClaim`` map. Require keys 1..6; key 7
        (``witnesses``) is optional and defaults to ``[]``. Each witness
        element is decoded via :meth:`WitnessAttestation.from_cbor_value`.
        """
        if not isinstance(m, dict):
            raise ClaimError(f"AliasClaim must be a map, got {type(m).__name__}")
        for k in (1, 2, 3, 4, 5, 6):
            if k not in m:
                raise ClaimError(f"AliasClaim missing required key {k}")
        raw_witnesses = m.get(7, [])
        if not isinstance(raw_witnesses, list):
            raise ClaimError(
                f"AliasClaim field 7 (witnesses) must be an array, "
                f"got {type(raw_witnesses).__name__}"
            )
        witnesses = [WitnessAttestation.from_cbor_value(wm) for wm in raw_witnesses]
        return cls(
            alias=m[1],
            tld_id=m[2],
            timestamp=m[3],
            nonce=m[4],
            claimant_pk=m[5],
            pow_hash=m[6],
            witnesses=witnesses,
        )

    def canonical_bytes(self) -> bytes:
        """Canonical CBOR encoding of the whole claim (RFC 8949 §4.2)."""
        return cbor_canon.dumps(self.to_cbor_value())

    # ---- §7.4 deterministic ordering (step 3) ----------------------------
    def order_key(self) -> tuple:
        """Lexicographic ascending key ``(timestamp, pow_hash, tld_id)``
        for §7.4 step-3 ordering. All three elements are directly
        comparable (``int``, ``bytes``, ``bytes``) and Python compares the
        tuple element-wise, giving the spec's "earliest time wins; ties
        broken by lower PoW hash, then lower TLD ID" total order.

        Ties on ``(timestamp, pow_hash)`` are impossible between distinct
        claimants because ``tld_id = SHA-256(claimant_pk)`` differs, so the
        order is total over distinct claimants.
        """
        return (self.timestamp, self.pow_hash, self.tld_id)

    # ---- Mining factory ---------------------------------------------------
    @classmethod
    def mine(cls, alias: str, claimant_keypair: "crypto.Keypair", timestamp: int,
             difficulty_bits: int = constants.POW_DIFFICULTY_INIT,
             max_iters: int = 5_000_000, nonce_size: int = 16,
             witnesses: Optional[list] = None) -> "AliasClaim":
        """Mine a valid PoW nonce and assemble the claim.

        Steps mirror Appendix C.1:

        1. Normalize ``alias``; derive ``claimant_pk`` from the keypair and
           ``tld_id = SHA-256(claimant_pk)``.
        2. Build the PoW ``prefix`` = canonical CBOR of identity fields
           (field 4 / nonce excluded — see :meth:`prefix_bytes`).
        3. :func:`crypto.mine_pow` searches nonces (with ``nonce[0]``
           fixed to ``min(difficulty_bits, 255)`` per Appendix A.4) until
           ``SHA-256(prefix || nonce)`` has enough leading zero bits.
        4. Return a fully-populated :class:`AliasClaim`.

        By construction the returned claim satisfies
        :meth:`verify_claimant_consistency`, :meth:`verify_pow` (with
        ``nonce[0] == difficulty_bits``), and — once ``witnesses`` with a
        quorum are attached — :func:`verify_full`.
        """
        alias_n = naming.validate_alias(alias)
        claimant_pk = claimant_keypair.public_bytes
        tld_id = crypto.tld_id(claimant_pk)
        ts = int(timestamp)

        # prefix = canonical CBOR of {1:alias, 2:tld_id, 3:ts, 5:claimant_pk}
        # (field 4 / nonce EXCLUDED — see prefix_bytes() and Appendix C.1).
        prefix = cbor_canon.dumps_map([
            (1, alias_n),
            (2, tld_id),
            (3, ts),
            (5, claimant_pk),
        ])
        nonce, pow_hash = crypto.mine_pow(
            prefix, difficulty_bits, max_iters=max_iters, nonce_size=nonce_size
        )
        return cls(
            alias=alias_n,
            tld_id=tld_id,
            timestamp=ts,
            nonce=nonce,
            claimant_pk=claimant_pk,
            pow_hash=pow_hash,
            witnesses=list(witnesses) if witnesses is not None else [],
        )


# ---------------------------------------------------------------------------
# §7.4 — module-level ordering / full-validity helpers
# ---------------------------------------------------------------------------
def _structurally_and_pow_valid(claim: "AliasClaim") -> bool:
    """§7.4 step-2 core (excluding the witness-quorum check): the claimant
    key binds to ``tld_id`` AND the stored PoW recomputes against the
    inferred/default difficulty. Used by :func:`select_winner` and
    :func:`order_claims` (which deliberately do NOT require a witness
    quorum — quorum is checked separately by :func:`verify_full`).
    """
    return claim.verify_claimant_consistency() and claim.verify_pow()


def select_winner(claims) -> Optional[AliasClaim]:
    """Deterministic winner of a set of competing claims (§7.4 step 3).

    Filters to claims that are structurally consistent (``tld_id`` binds to
    ``claimant_pk``) and whose PoW recomputes (difficulty inferred from
    ``nonce[0]`` when sane, else :data:`constants.POW_DIFFICULTY_INIT`),
    then returns the one with the SMALLEST :meth:`AliasClaim.order_key`.
    Returns ``None`` if no claim survives. Witness quorum is intentionally
    NOT required here (a caller may want the best candidate even before
    quorum is assembled); use :func:`verify_full` for the full filter.
    """
    survivors = [c for c in claims if _structurally_and_pow_valid(c)]
    if not survivors:
        return None
    return min(survivors, key=lambda c: c.order_key())


def order_claims(claims) -> list:
    """Return the surviving claims sorted ascending by
    :meth:`AliasClaim.order_key` (§7.4 step 3). Only structurally-and-PoW-
    valid claims are included; the rest are dropped.
    """
    survivors = [c for c in claims if _structurally_and_pow_valid(c)]
    return sorted(survivors, key=lambda c: c.order_key())


def verify_full(claim: "AliasClaim",
                difficulty_bits: Optional[int] = None,
                witness_set_node_ids: Optional[Set[bytes]] = None,
                quorum: int = constants.W) -> bool:
    """Full §7.4 step-2 validity filter.

    Returns ``True`` iff ALL hold:

    * the claimant key is consistent (``tld_id == SHA-256(claimant_pk)``);
    * the PoW is valid at ``difficulty_bits`` (inferred from ``nonce[0]``
      when ``None``) — recomputed, never trusting the stored hash;
    * the witness quorum (default ``W = 5``) is met among distinct valid
      witnesses, optionally restricted to ``witness_set_node_ids`` (the
      ``WITNESS_SET`` closest to ``K_claim``).

    Structural validity (field lengths, alias normalization) is enforced
    at construction time, so any :class:`AliasClaim` instance that exists
    is already structurally sound.
    """
    if not claim.verify_claimant_consistency():
        return False
    if not claim.verify_pow(difficulty_bits):
        return False
    if not claim.has_quorum(witness_set_node_ids, quorum):
        return False
    return True


# ===========================================================================
# Golden / sanity vectors (asserted BY CONSTRUCTION; not executed here —
# the test suite exercises them. Kept as documentation of intended behavior.)
#
#   * AliasClaim.mine(alias="foo", kp, ts=T, difficulty_bits=24) yields a
#     claim whose nonce[0] == 24 (crypto.mine_pow fixes nonce[0] to the
#     difficulty) and whose pow_hash has >= 24 leading zero bits.
#
#   * Such a claim satisfies:
#         claim.verify_pow()                      == True
#         claim.verify_claimant_consistency()     == True
#         verify_full(claim, quorum=0)            == True   # quorum bypassed
#
#   * With W valid witnesses attached (built via WitnessAttestation.create):
#         verify_full(claim)                      == True
#
#   * select_winner([A, B]) == A   iff   A.order_key() < B.order_key(),
#     i.e. lexicographic on (timestamp, pow_hash, tld_id). Two claims with
#     identical (timestamp, pow_hash) but different tld_id: the lower
#     tld_id (bytewise) wins. Ties are impossible for distinct claimants
#     because tld_id = SHA-256(claimant_pk) differs.
#
#   * order_key() returns a plain (int, bytes, bytes) tuple — Python
#     compares these lexicographically and deterministically.
#
#   * WitnessAttestation.create(kp, ts, alias, tld_id, pk).verify(
#         alias, tld_id, pk)                      == True
#     Tampering ANY field (node_id, node_pk, ts, sig, or the context
#     alias/tld_id/claimant_pk) makes verify() == False.
#
#   * prefix_bytes() == cbor_canon.dumps_map([(1,alias),(2,tld_id),
#                                              (3,ts),(5,claimant_pk)])
#     — field 4 (nonce) is skipped, per Appendix C.1 line 1057-1058.
# ===========================================================================
