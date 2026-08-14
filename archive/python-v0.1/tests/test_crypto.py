"""Foundational tests for :mod:`freens.crypto`.

Covers the cryptography layer of ``specifications.md``:

* :class:`TestKeypair` — Ed25519 keypair generation, deterministic
  reconstruction from a seed, signature sizes, and ``verify_signature``
  round-trips / failures.
* :class:`TestIds` — SHA-256 key identities (``tld_id``/``node_id``/``id_for``).
* :class:`TestHierarchicalDerivation` — the per-purpose
  ``SHA-256(SK_root || "freens:" || purpose)`` derivation.
* :class:`TestLeadingZeroBits` — the hashcash leading-zero-bit counter and
  the ``meets_difficulty`` predicate.
* :class:`TestPow` — proof-of-work mining / verification (difficulty recorded
  in ``nonce[0]``).
* :class:`TestRecovery` — threshold-of-N recovery policy construction and
  validation.
* :class:`TestWitnessMessage` — the canonical witness-attestation signing
  input.

Run from the project root with::

    python3 -m unittest discover
"""

import hashlib
import unittest

from freens import constants
from freens.crypto import (
    CryptoError,
    Keypair,
    RecoveryPolicy,
    WITNESS_SIGNING_TAG,
    default_recovery_policy,
    derive_purpose,
    derive_purpose_keypair,
    id_for,
    leading_zero_bits,
    meets_difficulty,
    mine_pow,
    node_id,
    pow_hash,
    tld_id,
    verify_pow,
    verify_signature,
    witness_signing_message,
)


class TestKeypair(unittest.TestCase):
    """Ed25519 keypair behaviour (§5.1)."""

    def test_generate_sizes(self):
        kp = Keypair.generate()
        self.assertEqual(len(kp.public_bytes), 32)
        self.assertEqual(len(kp.private_bytes), 32)
        self.assertEqual(len(kp.sign(b"msg")), 64)

    def test_deterministic_from_seed(self):
        kp1 = Keypair.from_private_bytes(b"\x11" * 32)
        kp2 = Keypair.from_private_bytes(b"\x11" * 32)
        self.assertEqual(kp1.public_bytes, kp2.public_bytes)
        self.assertEqual(kp1.sign(b"x"), kp2.sign(b"x"))

    def test_from_private_bytes_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            Keypair.from_private_bytes(bytes(31))

    def test_verify_roundtrip(self):
        kp = Keypair.generate()
        msg = b"hello world"
        sig = kp.sign(msg)
        self.assertIs(verify_signature(kp.public_bytes, sig, msg), True)

    def test_verify_rejects_tampered_message(self):
        kp = Keypair.generate()
        sig = kp.sign(b"hello world")
        self.assertIs(verify_signature(kp.public_bytes, sig, b"tampered"), False)

    def test_verify_rejects_wrong_key(self):
        kp = Keypair.generate()
        sig = kp.sign(b"hello world")
        self.assertIs(verify_signature(b"\x00" * 32, sig, b"hello world"), False)

    def test_verify_rejects_bad_signature(self):
        kp = Keypair.generate()
        self.assertIs(verify_signature(kp.public_bytes, b"\x00" * 64, b"msg"), False)

    def test_verify_rejects_wrong_signature_length(self):
        kp = Keypair.generate()
        self.assertIs(verify_signature(kp.public_bytes, b"\x00" * 32, b"msg"), False)


class TestIds(unittest.TestCase):
    """SHA-256 key identities: tld_id == node_id == id_for (§5.2)."""

    def test_tld_id_is_sha256_of_pubkey(self):
        kp = Keypair.generate()
        pk = kp.public_bytes
        self.assertEqual(tld_id(pk), hashlib.sha256(pk).digest())
        self.assertEqual(len(tld_id(pk)), 32)

    def test_node_and_id_for_alias_tld_id(self):
        kp = Keypair.generate()
        pk = kp.public_bytes
        self.assertEqual(node_id(pk), tld_id(pk))
        self.assertEqual(id_for(pk), tld_id(pk))

    def test_ids_reject_wrong_length(self):
        with self.assertRaises(ValueError):
            tld_id(bytes(31))
        with self.assertRaises(ValueError):
            node_id(bytes(31))
        with self.assertRaises(ValueError):
            id_for(bytes(31))

    def test_distinct_keys_have_distinct_ids(self):
        kp1 = Keypair.generate()
        kp2 = Keypair.generate()
        self.assertNotEqual(tld_id(kp1.public_bytes), tld_id(kp2.public_bytes))


class TestHierarchicalDerivation(unittest.TestCase):
    """Per-purpose hierarchical key derivation (§5.3)."""

    def setUp(self):
        self.root = b"\xaa" * 32

    def test_distinct_purposes_distinct_seeds(self):
        k1 = derive_purpose(self.root, "tld")
        k2 = derive_purpose(self.root, "node")
        self.assertNotEqual(k1, k2)

    def test_same_purpose_deterministic(self):
        k1 = derive_purpose(self.root, "tld")
        k3 = derive_purpose(self.root, "tld")
        self.assertEqual(k1, k3)

    def test_seed_length(self):
        self.assertEqual(len(derive_purpose(self.root, "tld")), 32)

    def test_derive_matches_spec_formula(self):
        # SK_purpose = SHA-256(SK_root || b"freens:" || purpose)
        expected = hashlib.sha256(self.root + b"freens:tld").digest()
        self.assertEqual(derive_purpose(self.root, "tld"), expected)

    def test_derive_rejects_wrong_root_length(self):
        with self.assertRaises(ValueError):
            derive_purpose(bytes(31), "tld")

    def test_derive_keypair_signs_and_verifies(self):
        kp = derive_purpose_keypair(self.root, "tld")
        msg = b"sign me"
        sig = kp.sign(msg)
        self.assertIs(verify_signature(kp.public_bytes, sig, msg), True)


class TestLeadingZeroBits(unittest.TestCase):
    """The hashcash leading-zero-bit counter (§7.3)."""

    def test_ff(self):
        self.assertEqual(leading_zero_bits(bytes.fromhex("ff")), 0)

    def test_7f(self):
        # 0x7f = 0b01111111 -> exactly one leading zero bit.
        self.assertEqual(leading_zero_bits(bytes.fromhex("7f")), 1)

    def test_40(self):
        # 0x40 = 0b01000000 -> one leading zero bit.
        self.assertEqual(leading_zero_bits(bytes.fromhex("40")), 1)

    def test_01(self):
        self.assertEqual(leading_zero_bits(bytes.fromhex("01")), 7)

    def test_10(self):
        # 0x10 = 0b00010000 -> three leading zero bits.
        self.assertEqual(leading_zero_bits(bytes.fromhex("10")), 3)

    def test_single_zero_byte(self):
        self.assertEqual(leading_zero_bits(bytes.fromhex("00")), 8)

    def test_two_bytes_0001(self):
        self.assertEqual(leading_zero_bits(bytes.fromhex("0001")), 15)

    def test_two_bytes_0010(self):
        self.assertEqual(leading_zero_bits(bytes.fromhex("0010")), 11)

    def test_all_zero_digest(self):
        self.assertEqual(leading_zero_bits(bytes(32)), 256)

    def test_empty(self):
        self.assertEqual(leading_zero_bits(b""), 0)

    # --- meets_difficulty ------------------------------------------------
    def test_meets_difficulty_exact(self):
        self.assertIs(meets_difficulty(bytes.fromhex("00"), 8), True)

    def test_meets_difficulty_one_short(self):
        self.assertIs(meets_difficulty(bytes.fromhex("00"), 9), False)

    def test_meets_difficulty_7f_one(self):
        self.assertIs(meets_difficulty(bytes.fromhex("7f"), 1), True)

    def test_meets_difficulty_7f_two(self):
        self.assertIs(meets_difficulty(bytes.fromhex("7f"), 2), False)


class TestPow(unittest.TestCase):
    """Hashcash proof-of-work mining and verification (§7.3, Appendix A.4).

    Mining tests use a low difficulty (8 bits, ~256 expected hashes) so they
    complete quickly and deterministically enough for a unit test.
    """

    def test_mine_and_verify(self):
        prefix = b"test-prefix"
        nonce, h = mine_pow(prefix, 8, max_iters=2_000_000, nonce_size=16)

        # Appendix A.4: the difficulty is recorded in nonce[0].
        self.assertEqual(len(nonce), 16)
        self.assertEqual(nonce[0], 8)

        # The returned hash is exactly pow_hash(prefix, nonce).
        self.assertEqual(pow_hash(prefix, nonce), h)

        # The mined hash meets the requested difficulty.
        self.assertIs(meets_difficulty(h, 8), True)

        # And verify_pow agrees.
        self.assertIs(verify_pow(prefix, nonce, 8), True)

    def test_verify_pow_does_not_overconstrain_higher_difficulty(self):
        # A hash with >= 8 leading zeros may or may not have >= 9; we only
        # assert that verify_pow returns a bool (no over-constraint).
        prefix = b"test-prefix"
        nonce, _ = mine_pow(prefix, 8, max_iters=2_000_000, nonce_size=16)
        self.assertIn(verify_pow(prefix, nonce, 9), (True, False))

    def test_pow_hash_determinism(self):
        self.assertEqual(pow_hash(b"a", b"b"), hashlib.sha256(b"ab").digest())

    def test_mine_difficulty_zero_succeeds_immediately(self):
        nonce, h = mine_pow(b"x", 0, max_iters=10, nonce_size=8)
        self.assertEqual(nonce[0], 0)
        self.assertIs(meets_difficulty(h, 0), True)

    def test_verify_pow_impossible_difficulty(self):
        # Difficulty 256 requires an all-zero SHA-256 output — effectively
        # impossible, so verification must fail for any real prefix.
        prefix = b"test-prefix"
        self.assertIs(verify_pow(prefix, b"", 256), False)


class TestRecovery(unittest.TestCase):
    """Threshold-of-N recovery policy (§5.4)."""

    def setUp(self):
        self.kp1 = Keypair.generate()
        self.kp2 = Keypair.generate()
        self.kp3 = Keypair.generate()

    def test_policy_fields(self):
        rp = RecoveryPolicy(
            threshold=2,
            keys=[self.kp1.public_bytes, self.kp2.public_bytes, self.kp3.public_bytes],
            timelock=100,
        )
        self.assertEqual(rp.threshold, 2)
        self.assertEqual(len(rp.keys), 3)
        self.assertEqual(rp.timelock, 100)

    def test_rejects_threshold_zero(self):
        with self.assertRaises(ValueError):
            RecoveryPolicy(threshold=0, keys=[self.kp1.public_bytes])

    def test_rejects_threshold_exceeds_key_count(self):
        with self.assertRaises(ValueError):
            RecoveryPolicy(
                threshold=5,
                keys=[self.kp1.public_bytes, self.kp2.public_bytes, self.kp3.public_bytes],
            )

    def test_rejects_wrong_key_length(self):
        with self.assertRaises(ValueError):
            RecoveryPolicy(threshold=1, keys=[bytes(31)])

    def test_rejects_negative_timelock(self):
        with self.assertRaises(ValueError):
            RecoveryPolicy(threshold=1, keys=[self.kp1.public_bytes], timelock=-1)

    def test_default_recovery_policy(self):
        rp = default_recovery_policy(
            primary_pk=self.kp1.public_bytes,
            recovery_keys=[self.kp2.public_bytes, self.kp3.public_bytes],
        )
        self.assertEqual(rp.threshold, 2)
        self.assertEqual(rp.timelock, constants.RECOVERY_TIMELOCK)


class TestWitnessMessage(unittest.TestCase):
    """Canonical witness-attestation signing input (§7.3)."""

    def test_message_layout(self):
        alias = "foo"
        tid = bytes(range(32))
        pk = bytes(range(32))
        ts = 12345
        msg = witness_signing_message(alias, tid, pk, ts)

        self.assertTrue(msg.startswith(WITNESS_SIGNING_TAG))
        expected = (
            WITNESS_SIGNING_TAG
            + len(b"foo").to_bytes(4, "big")
            + b"foo"
            + tid
            + pk
            + ts.to_bytes(8, "big")
        )
        self.assertEqual(msg, expected)

    def test_rejects_wrong_tld_id_length(self):
        with self.assertRaises(ValueError):
            witness_signing_message("foo", bytes(31), bytes(range(32)), 12345)

    def test_rejects_wrong_claimant_pk_length(self):
        with self.assertRaises(ValueError):
            witness_signing_message("foo", bytes(range(32)), bytes(31), 12345)


if __name__ == "__main__":
    unittest.main()
