"""Cryptographic primitives for the freens protocol.

Implements the cryptography layer described in ``specifications.md``:

* **§5.1 / §5.2** — Ed25519 (RFC 8032) signatures and SHA-256 key
  identities. A key's identity is always ``SHA-256(public_key)`` when
  used as an ID (TLD ID, Node ID).
* **§5.3** — simple per-purpose hierarchical key derivation
  ``SK_purpose = SHA-256(SK_root || "freens:" || purpose)`` so a single
  root secret can back TLD/node/recovery keys without reuse.
* **§5.4** — recovery policy (threshold-of-N multisig with a timelock).
* **§7.3** — hashcash-style proof of work
  ``pow_hash = SHA-256(prefix || nonce) < 2^(256 - D)`` and the
  canonical witness-attestation signing input.
* **Appendix A.4** — the convention that the difficulty used to mine a
  nonce is recorded in ``nonce[0]`` (so a verifier can confirm the claim
  against *any* historically valid ``D >= POW_DIFFICULTY_INIT``).

Only third-party dependency is ``cryptography`` (Ed25519 primitives).
Everything else uses the standard library.
"""

from __future__ import annotations

import hashlib
import hmac  # noqa: F401  (re-exported for downstream modules; part of the crypto surface)
import secrets
from dataclasses import dataclass, field  # noqa: F401  (field kept for API symmetry)
from typing import Optional  # noqa: F401  (kept for API symmetry / future use)

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from . import constants

# ---------------------------------------------------------------------------
# Primitive sizes (bytes)
# ---------------------------------------------------------------------------
ED25519_PUBLIC_KEY_LEN = 32
ED25519_PRIVATE_KEY_LEN = 32   # raw seed (RFC 8032: the 32-byte private seed)
ED25519_SIGNATURE_LEN = 64


class CryptoError(Exception):
    """Raised on unrecoverable cryptographic failures (e.g. PoW exhaustion)."""
    pass


# ---------------------------------------------------------------------------
# Ed25519 keypairs  (§5.1, §5.2)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Keypair:
    """Ed25519 keypair. Holds the private key object and exposes raw bytes.

    A ``Keypair`` is the unit of identity for every signing role in freens
    (TLD owner, node, witness, delegation, recovery). Frozen so it may be
    safely shared / cached.
    """

    private: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "Keypair":
        """Generate a fresh Ed25519 keypair using the OS CSPRNG."""
        return cls(private=Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, seed: bytes) -> "Keypair":
        """Reconstruct a keypair from a 32-byte raw Ed25519 seed."""
        if len(seed) != ED25519_PRIVATE_KEY_LEN:
            raise ValueError("seed must be 32 bytes")
        return cls(private=Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def private_bytes(self) -> bytes:
        """The 32-byte raw private seed."""
        return self.private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    @property
    def public_bytes(self) -> bytes:
        """The 32-byte raw Ed25519 verifying key."""
        return self.private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> bytes:
        """Sign ``message``, returning a 64-byte Ed25519 signature."""
        return self.private.sign(message)


def verify_signature(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify an Ed25519 signature.

    ``public_key`` must be 32 bytes and ``signature`` 64 bytes; any other
    length yields ``False``. Returns ``True``/``False`` and never raises on a
    bad signature (``InvalidSignature`` and all other exceptions are caught).
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except Exception:
        # Defensive: any unexpected failure is treated as a failed verification
        # rather than propagating to the caller (e.g. malformed key material).
        return False


# ---------------------------------------------------------------------------
# Key identity  (§5.2, §3.1, §6.2)
# ---------------------------------------------------------------------------
def tld_id(public_key: bytes) -> bytes:
    """TLD_ID = SHA-256(PK_tld) — 32 bytes. §3.1, §5.2."""
    if len(public_key) != 32:
        raise ValueError("public key must be 32 bytes")
    return hashlib.sha256(public_key).digest()


def node_id(public_key: bytes) -> bytes:
    """Node ID = SHA-256(node_public_key) — 32 bytes. §6.2.

    Same algorithm as ``tld_id``; the distinct name documents intent."""
    return tld_id(public_key)


def id_for(public_key: bytes) -> bytes:
    """Alias for ``tld_id`` / ``node_id`` (both are SHA-256 of a public key)."""
    return tld_id(public_key)


# ---------------------------------------------------------------------------
# Hierarchical key derivation  (§5.3)
# ---------------------------------------------------------------------------
def derive_purpose(root_private_seed: bytes, purpose: str) -> bytes:
    """Derive a per-purpose 32-byte Ed25519 seed from a root seed.

    ``SK_purpose = SHA-256(SK_root || b"freens:" || purpose)`` per §5.3's
    "simple per-purpose derivation". The result is a valid 32-byte Ed25519
    private seed, so TLD/node/recovery keys can all stem from one root
    secret without key reuse.
    """
    if len(root_private_seed) != 32:
        raise ValueError("root seed must be 32 bytes")
    m = hashlib.sha256()
    m.update(root_private_seed)
    m.update(b"freens:")
    m.update(purpose.encode("utf-8"))
    return m.digest()


def derive_purpose_keypair(root_private_seed: bytes, purpose: str) -> Keypair:
    """Convenience: derive a purpose seed and wrap it into a ``Keypair``."""
    return Keypair.from_private_bytes(derive_purpose(root_private_seed, purpose))


# ---------------------------------------------------------------------------
# Proof of work  (§7.3, Appendix A.4)
# ---------------------------------------------------------------------------
def leading_zero_bits(digest: bytes) -> int:
    """Count the number of leading zero BITS in a big-endian byte string.

    Used by the hashcash-style PoW check
    ``pow_hash = SHA-256(prefix || nonce) < 2^(256 - D)`` (§7.3): a digest
    meets difficulty ``D`` iff it has at least ``D`` leading zero bits.

    Algorithm: scan bytes left to right. Each ``0x00`` byte contributes 8
    zero bits; the first non-zero byte ``b`` contributes
    ``8 - b.bit_length()`` zero bits (``bit_length`` is the index of the
    highest set bit, so ``8 - bit_length`` is the count of zero bits above
    it), and scanning then stops.

    Worked examples (verified against ``8 - b.bit_length()``):

        bytes.fromhex("ff")   -> 0x00..  N/A, 0xff: bit_length=8, 8-8=0  => 0
        bytes.fromhex("7f")   -> 0x7f: bit_length=7, 8-7=1               => 1
        bytes.fromhex("01")   -> 0x01: bit_length=1, 8-1=7               => 7
        bytes.fromhex("00")   -> 0x00: +8, then end of input             => 8
        bytes.fromhex("0001") -> 0x00: +8; 0x01: bit_length=1, 8-1=7     => 15
        bytes.fromhex("0010") -> 0x00: +8; 0x10: bit_length=5, 8-5=3     => 11
        bytes(32)             -> 32 * 0x00 bytes                         => 256

    Note on 0x7f: 0x7f = 0b0111_1111 has its top bit clear, so it has
    exactly one leading zero bit (=> 1). This is consistent with both the
    counting method above (the same method that gives 0x10 => 3 and
    0x01 => 7) and with the spec inequality ``hash < 2^(256-D)``: a digest
    whose first byte is 0x7f is < 0x80... = 2^255 = 2^(256-1), so it
    satisfies difficulty 1.
    """
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        # First non-zero byte: count the zero bits above its highest set bit.
        bits += 8 - byte.bit_length()
        break
    return bits


def meets_difficulty(digest: bytes, difficulty_bits: int) -> bool:
    """True iff ``digest`` has at least ``difficulty_bits`` leading zero bits."""
    return leading_zero_bits(digest) >= difficulty_bits


def pow_hash(prefix: bytes, nonce: bytes) -> bytes:
    """pow_hash = SHA-256(prefix || nonce). §7.3."""
    h = hashlib.sha256()
    h.update(prefix)
    h.update(nonce)
    return h.digest()


def mine_pow(prefix: bytes, difficulty_bits: int, max_iters: int = 10_000_000,
             nonce_size: int = 16) -> tuple[bytes, bytes]:
    """Search for a nonce such that ``SHA-256(prefix || nonce)`` has at least
    ``difficulty_bits`` leading zero bits.

    Returns ``(nonce, pow_hash)``. Raises ``CryptoError`` if ``max_iters`` is
    exceeded without finding a valid nonce. Nonces are drawn with
    ``secrets.token_bytes`` (CSPRNG).

    Per Appendix A.4, the difficulty used SHOULD be recorded in the nonce's
    first byte so a verifier can confirm the claim against any historically
    valid ``D``. We therefore fix ``nonce[0] = min(difficulty_bits, 255)``
    (when ``nonce_size >= 1``) and only randomize the remaining
    ``nonce_size - 1`` bytes — keeping the hash input ``prefix || nonce``
    while still varying the tail. (Difficulty fits in a byte for v1; the
    clamp guards against absurd inputs.)
    """
    if difficulty_bits < 0:
        raise ValueError("difficulty must be >= 0")
    if nonce_size < 0:
        raise ValueError("nonce_size must be >= 0")

    # Fixed first byte carries the difficulty; the tail is the search space.
    d_byte = bytes([min(difficulty_bits, 255)]) if nonce_size >= 1 else b""
    tail_len = max(nonce_size - 1, 0)

    for _ in range(max_iters):
        tail = secrets.token_bytes(tail_len)
        nonce = d_byte + tail
        h = pow_hash(prefix, nonce)
        if meets_difficulty(h, difficulty_bits):
            return nonce, h
    raise CryptoError(
        f"PoW mining exceeded {max_iters} iterations at difficulty {difficulty_bits}"
    )


def verify_pow(prefix: bytes, nonce: bytes, difficulty_bits: int) -> bool:
    """True iff ``SHA-256(prefix || nonce)`` meets ``difficulty_bits``.

    Verifies the hash only; it does NOT require ``nonce[0] == difficulty``
    (that byte is informational, per Appendix A.4 — a claim is valid against
    any historically valid ``D >= POW_DIFFICULTY_INIT``).
    """
    return meets_difficulty(pow_hash(prefix, nonce), difficulty_bits)


# ---------------------------------------------------------------------------
# Recovery policy  (§5.4)
# ---------------------------------------------------------------------------
@dataclass
class RecoveryPolicy:
    """A threshold-of-N recovery policy with an optional timelock (§5.4).

    Mirrors the CBOR structure::

        RecoveryPolicy = {
          1 : threshold    ; uint, e.g. 2
          2 : keys         ; array of bstr(32), recovery public keys
          3 : timelock     ; uint seconds before a recovery takes effect
        }

    Semantics (§9.4): any ``threshold``-of-``keys`` can, after ``timelock``,
    replace the primary key. The current primary may cancel/rotate during
    the timelock window.
    """

    threshold: int
    keys: list[bytes]          # list of 32-byte recovery public keys
    timelock: int = constants.RECOVERY_TIMELOCK

    def __post_init__(self):
        if self.threshold < 1:
            raise ValueError("threshold must be >= 1")
        if not isinstance(self.keys, (list, tuple)):
            raise ValueError("keys must be a list of public keys")
        for k in self.keys:
            if len(k) != 32:
                raise ValueError("recovery keys must be 32 bytes")
        if self.threshold > len(self.keys):
            raise ValueError("threshold > keys count")
        if self.timelock < 0:
            raise ValueError("timelock must be >= 0")


def default_recovery_policy(primary_pk: bytes, recovery_keys: list[bytes],
                            threshold: int = 2,
                            timelock: int = constants.RECOVERY_TIMELOCK) -> RecoveryPolicy:
    """Build a threshold-of-N recovery policy. §5.4 recommends 2-of-3.

    ``primary_pk`` is the record's current primary key; it is accepted for
    API symmetry but is intentionally NOT added to ``keys`` — the recovery
    set is the separately-stored keys that can *replace* the primary. The
    default 2-of-3 policy is the primary plus two recovery keys held in
    distinct locations; here ``recovery_keys`` carries those recovery keys
    and ``threshold`` defaults to 2.
    """
    return RecoveryPolicy(
        threshold=threshold,
        keys=list(recovery_keys),
        timelock=timelock,
    )


# ---------------------------------------------------------------------------
# Witness attestation signing helpers  (§7.3)
# ---------------------------------------------------------------------------
WITNESS_SIGNING_TAG = b"freens-witness-v1"


def witness_signing_message(alias: str, tld_id: bytes, claimant_pk: bytes,
                            ts: int) -> bytes:
    """Canonical signing input for a witness attestation (§7.3).

    The witness signs ``canonical("freens-witness-v1", alias, tld_id,
    claimant_pk, ts)``. We encode it as an unambiguous, length-prefixed
    byte string (no reliance on a CBOR encoder here, so signing is
    self-contained and deterministic)::

        b"freens-witness-v1"
        || uint32_be(len(alias)) || alias_utf8
        || tld_id (32 bytes)
        || claimant_pk (32 bytes)
        || uint64_be(ts)

    ``ts`` is encoded unsigned and big-endian.
    """
    if len(tld_id) != 32 or len(claimant_pk) != 32:
        raise ValueError("ids/pks must be 32 bytes")
    ab = alias.encode("utf-8")
    return (
        WITNESS_SIGNING_TAG
        + len(ab).to_bytes(4, "big")
        + ab
        + tld_id
        + claimant_pk
        + int(ts).to_bytes(8, "big", signed=False)
    )
