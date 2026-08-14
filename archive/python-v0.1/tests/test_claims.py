"""PROTOCOL-CORE claims test suite for the freens package.

Exercises :mod:`freens.claims` — ``WitnessAttestation``, ``AliasClaim`` (mining,
PoW, prefix bytes, ordering, CBOR round trip), and the module-level helpers
``select_winner``, ``order_claims``, ``verify_full`` — against the exact public
API, using only the standard-library :mod:`unittest`.  Run with::

    python3 -m unittest discover

Note on PoW difficulty
---------------------
All mining uses ``difficulty_bits=8`` so tests stay fast (a valid 8-bit nonce
is found within a few hundred hashes).  Per :meth:`AliasClaim.verify_pow`, when
``difficulty_bits`` is ``None`` the difficulty is inferred from ``nonce[0]``
ONLY when ``nonce[0] >= POW_DIFFICULTY_INIT`` (24 by default); otherwise it
defaults to ``POW_DIFFICULTY_INIT`` itself — so a bare ``verify_pow()`` would
normally reject a difficulty-8 claim.

PoW difficulty is a retargetable network parameter (Appendix A.4), so the test
classes below that exercise the full §7.4 default-difficulty validity path
lower ``constants.POW_DIFFICULTY_INIT`` to ``8`` in ``setUp`` (restoring the
original in ``tearDown``).  The library modules read the constant via
attribute access at call time (``constants.POW_DIFFICULTY_INIT``), so the
patch propagates to :mod:`freens.claims` immediately: with the init lowered to
8, ``nonce[0] == 8`` meets the inference floor, and ``verify_pow()`` /
``select_winner`` / ``order_claims`` / ``verify_full`` all run end-to-end on
fast difficulty-8 claims exactly as they would on difficulty-24 claims in
production.
"""

import unittest

from freens import cbor_canon, claims, constants, crypto


# ---------------------------------------------------------------------------
# §7.3 — WitnessAttestation
# ---------------------------------------------------------------------------
class TestWitnessAttestation(unittest.TestCase):
    def setUp(self):
        self.node_kp = crypto.Keypair.generate()
        self.claimant_kp = crypto.Keypair.generate()
        self.alias = "foo"
        self.tid = crypto.tld_id(self.claimant_kp.public_bytes)
        self.claimant_pk = self.claimant_kp.public_bytes
        self.ts = 1000
        self.wa = claims.WitnessAttestation.create(
            self.node_kp, self.ts, self.alias, self.tid, self.claimant_pk
        )

    def test_verify_true(self):
        wa = self.wa
        self.assertTrue(wa.verify(self.alias, self.tid, self.claimant_pk))

    def test_node_id_binds_to_node_pk(self):
        wa = self.wa
        self.assertEqual(crypto.node_id(wa.node_pk), wa.node_id)

    def test_tampered_timestamp_fails(self):
        wa = self.wa
        wa_bad = claims.WitnessAttestation(
            node_id=wa.node_id, node_pk=wa.node_pk,
            ts=self.ts + 1, sig=wa.sig,
        )
        self.assertFalse(wa_bad.verify(self.alias, self.tid, self.claimant_pk))

    def test_tampered_alias_context_fails(self):
        wa = self.wa
        self.assertFalse(wa.verify("bar", self.tid, self.claimant_pk))

    def test_cbor_roundtrip(self):
        wa = self.wa
        wa2 = claims.WitnessAttestation.from_cbor_value(wa.to_cbor_value())
        self.assertTrue(wa2.verify(self.alias, self.tid, self.claimant_pk))

    def test_from_cbor_value_missing_keys_raises(self):
        with self.assertRaises(claims.ClaimError):
            claims.WitnessAttestation.from_cbor_value({1: b"\x00" * 32})

    def test_bad_length_raises_valueerror(self):
        with self.assertRaises(ValueError):
            claims.WitnessAttestation(
                node_id=b"\x00" * 31, node_pk=b"\x00" * 32,
                ts=1, sig=b"\x00" * 64,
            )


# ---------------------------------------------------------------------------
# §7.3 / Appendix C.1 — AliasClaim.mine
# ---------------------------------------------------------------------------
class TestAliasClaimMine(unittest.TestCase):
    def setUp(self):
        self._orig_init = constants.POW_DIFFICULTY_INIT
        constants.POW_DIFFICULTY_INIT = 8   # let difficulty-8 claims be spec-valid
        self.claimant = crypto.Keypair.generate()
        self.ts = 12345
        self.claim = claims.AliasClaim.mine(
            alias="foo",
            claimant_keypair=self.claimant,
            timestamp=self.ts,
            difficulty_bits=8,
            max_iters=2_000_000,
            nonce_size=16,
        )

    def tearDown(self):
        constants.POW_DIFFICULTY_INIT = self._orig_init

    def test_identity_fields(self):
        c = self.claim
        self.assertEqual(c.alias, "foo")
        self.assertEqual(c.tld_id, crypto.tld_id(self.claimant.public_bytes))
        self.assertEqual(c.claimant_pk, self.claimant.public_bytes)
        self.assertEqual(c.timestamp, self.ts)

    def test_nonce_carries_difficulty(self):
        c = self.claim
        self.assertEqual(len(c.nonce), 16)
        self.assertEqual(c.nonce[0], 8)
        self.assertEqual(len(c.pow_hash), constants.SHA256_LEN)

    def test_claimant_consistency(self):
        self.assertTrue(self.claim.verify_claimant_consistency())

    def test_pow_with_explicit_difficulty(self):
        # The claim was mined at difficulty 8 -> it satisfies difficulty 8.
        self.assertTrue(self.claim.verify_pow(8))

    def test_pow_default_inference_succeeds_with_lowered_init(self):
        # nonce[0]==8 >= POW_DIFFICULTY_INIT (lowered to 8) -> verify_pow() infers 8
        # and the mined hash meets it.
        self.assertTrue(self.claim.verify_pow())

    def test_prefix_bytes_excludes_nonce_field4(self):
        c = self.claim
        self.assertEqual(
            c.prefix_bytes(),
            cbor_canon.dumps_map([
                (1, "foo"),
                (2, c.tld_id),
                (3, self.ts),
                (5, self.claimant.public_bytes),
            ]),
        )

    def test_pow_hash_recomputes_from_prefix_and_nonce(self):
        c = self.claim
        self.assertEqual(
            crypto.pow_hash(c.prefix_bytes(), c.nonce), c.pow_hash
        )

    def test_order_key_tuple(self):
        c = self.claim
        self.assertEqual(c.order_key(), (self.ts, c.pow_hash, c.tld_id))

    def test_cbor_roundtrip_byte_stable(self):
        c = self.claim
        c2 = claims.AliasClaim.from_cbor_value(c.to_cbor_value())
        self.assertTrue(c2.verify_pow(8))
        self.assertTrue(c2.verify_claimant_consistency())
        self.assertEqual(c2.canonical_bytes(), c.canonical_bytes())


# ---------------------------------------------------------------------------
# §7.4 step 3 — select_winner / order_claims
# ---------------------------------------------------------------------------
class TestSelectWinner(unittest.TestCase):
    def setUp(self):
        self._orig_init = constants.POW_DIFFICULTY_INIT
        constants.POW_DIFFICULTY_INIT = 8   # let difficulty-8 claims be spec-valid

    def tearDown(self):
        constants.POW_DIFFICULTY_INIT = self._orig_init

    def test_empty_returns_none(self):
        self.assertIsNone(claims.select_winner([]))

    def test_structurally_invalid_claim_filtered(self):
        # tld_id != SHA-256(claimant_pk) -> fails verify_claimant_consistency.
        bad = claims.AliasClaim(
            alias="foo",
            tld_id=b"\xff" * 32,
            timestamp=1,
            nonce=bytes([8]) + b"\x00" * 15,
            claimant_pk=crypto.Keypair.generate().public_bytes,
            pow_hash=crypto.pow_hash(b"", bytes([8]) + b"\x00" * 15),
        )
        self.assertIsNone(claims.select_winner([bad]))

    def test_order_key_orders_by_timestamp(self):
        c1 = claims.AliasClaim.mine(
            "foo", crypto.Keypair.from_private_bytes(b"\x01" * 32),
            timestamp=2000, difficulty_bits=8, max_iters=2_000_000,
        )
        c2 = claims.AliasClaim.mine(
            "foo", crypto.Keypair.from_private_bytes(b"\x02" * 32),
            timestamp=1000, difficulty_bits=8, max_iters=2_000_000,
        )
        self.assertLess(c2.order_key(), c1.order_key())
        # select_winner end-to-end: c2 (earlier ts) is the deterministic winner.
        winner = claims.select_winner([c1, c2])
        self.assertIsNotNone(winner)
        self.assertEqual(winner.timestamp, 1000)
        self.assertEqual(winner.order_key(), c2.order_key())
        # ordering is total: same winner regardless of input order.
        self.assertEqual(
            claims.select_winner([c2, c1]).claimant_pk, winner.claimant_pk
        )

    def test_order_claims_returns_survivors_sorted(self):
        c1 = claims.AliasClaim.mine(
            "foo", crypto.Keypair.from_private_bytes(b"\x01" * 32),
            timestamp=2000, difficulty_bits=8, max_iters=2_000_000,
        )
        c2 = claims.AliasClaim.mine(
            "foo", crypto.Keypair.from_private_bytes(b"\x02" * 32),
            timestamp=1000, difficulty_bits=8, max_iters=2_000_000,
        )
        # With POW_DIFFICULTY_INIT lowered to 8, both difficulty-8 claims survive
        # the PoW filter; order_claims returns them sorted ascending by order_key.
        ordered = claims.order_claims([c1, c2])
        self.assertEqual(len(ordered), 2)
        self.assertEqual(ordered[0].timestamp, 1000)   # c2 first (earlier ts)
        self.assertEqual(ordered[1].timestamp, 2000)   # c1 second
        self.assertTrue(ordered[0].order_key() < ordered[1].order_key())


# ---------------------------------------------------------------------------
# §7.3 / §7.4 — witness quorum
# ---------------------------------------------------------------------------
class TestWitnessQuorum(unittest.TestCase):
    def setUp(self):
        self._orig_init = constants.POW_DIFFICULTY_INIT
        constants.POW_DIFFICULTY_INIT = 8   # let difficulty-8 claims be spec-valid
        self.W = constants.W  # 5
        self.claimant = crypto.Keypair.generate()
        self.claim = claims.AliasClaim.mine(
            "foo", self.claimant, 1000,
            difficulty_bits=8, max_iters=2_000_000,
        )
        self.tid = self.claim.tld_id
        self.pk = self.claim.claimant_pk
        self.witnesses = [
            claims.WitnessAttestation.create(
                crypto.Keypair.generate(), 1000 + i, "foo", self.tid, self.pk
            )
            for i in range(self.W + 2)
        ]

    def tearDown(self):
        constants.POW_DIFFICULTY_INIT = self._orig_init

    def test_exact_quorum_valid(self):
        self.claim.witnesses = self.witnesses[: self.W]
        self.assertTrue(self.claim.has_quorum(quorum=self.W))
        # verify_full also checks PoW; pass the mined difficulty explicitly.
        self.assertTrue(
            claims.verify_full(self.claim, difficulty_bits=8, quorum=self.W)
        )
        self.assertTrue(claims.verify_full(self.claim, quorum=self.W))  # default difficulty inference

    def test_below_quorum_invalid(self):
        self.claim.witnesses = self.witnesses[: self.W - 1]
        self.assertFalse(self.claim.has_quorum(quorum=self.W))
        self.assertFalse(
            claims.verify_full(self.claim, difficulty_bits=8, quorum=self.W)
        )

    def test_tampered_witness_excluded_from_quorum(self):
        bad_w = self.witnesses[0]
        tampered = claims.WitnessAttestation(
            node_id=bad_w.node_id, node_pk=bad_w.node_pk,
            ts=bad_w.ts + 99, sig=bad_w.sig,
        )
        self.claim.witnesses = [tampered] + self.witnesses[1: self.W]
        # One tampered witness -> only W-1 valid -> no quorum.
        self.assertFalse(self.claim.has_quorum(quorum=self.W))

    def test_witness_set_restriction(self):
        self.claim.witnesses = self.witnesses[: self.W]
        allowed = {w.node_id for w in self.witnesses[: self.W]}
        self.assertTrue(
            self.claim.has_quorum(witness_set_node_ids=allowed, quorum=self.W)
        )
        allowed_few = {w.node_id for w in self.witnesses[:2]}
        self.assertFalse(
            self.claim.has_quorum(
                witness_set_node_ids=allowed_few, quorum=self.W
            )
        )


if __name__ == "__main__":
    unittest.main()
