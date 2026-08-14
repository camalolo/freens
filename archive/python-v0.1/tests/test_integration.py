"""End-to-end integration test for the freens protocol.

Simulates a complete create-TLD -> claim-alias -> delegate -> publish ->
resolve flow against the in-process :class:`freens.dht.store.EnvelopeStore`
(used here as the DHT). Every cryptographic and wire-format primitive is
exercised at least once:

  * Ed25519 keypairs, SHA-256 tld_id, hashcash-style PoW mining
    (:mod:`freens.crypto`).
  * Alias claims with a witness quorum, deterministic collision ordering
    (:mod:`freens.claims`).
  * Wire names, DHT storage-key derivation (:mod:`freens.naming`).
  * ``FREENS_Record`` / ``SignedEnvelope`` signing, the §4.2 record hash,
    the §4.4 basic-validity check, the §3.4 authority chain, and the
    §6.4 DHT store winner rule (:mod:`freens.wire`, :mod:`freens.dht.store`).
  * Resolver per-alias routing (:mod:`freens.resolver_config`).

Mining uses ``difficulty_bits=8`` throughout so the test stays fast. PoW
difficulty is a retargetable network parameter (Appendix A.4), so the test
class below lowers ``constants.POW_DIFFICULTY_INIT`` to ``8`` in ``setUp``
(restoring the original in ``tearDown``); the library reads the constant via
attribute access at call time, so the DEFAULT difficulty-inference path
inside ``verify_pow`` / ``verify_full`` / ``select_winner`` is exercised
end-to-end on the fast difficulty-8 claims exactly as it would be on
difficulty-24 claims in production.
"""

import hashlib
import unittest

from freens import claims, constants, crypto, naming, wire
from freens import cbor_canon  # noqa: F401  (part of the exercised surface)
from freens import resolver_config as rc
from freens.dht import store


class TestEndToEndFlow(unittest.TestCase):
    """Full create -> claim -> delegate -> publish -> resolve lifecycle."""

    def setUp(self):
        self._orig_init = constants.POW_DIFFICULTY_INIT
        constants.POW_DIFFICULTY_INIT = 8   # let difficulty-8 claims be spec-valid

    def tearDown(self):
        constants.POW_DIFFICULTY_INIT = self._orig_init

    def test_full_flow(self):
        now = 2_000_000
        dht = store.EnvelopeStore(time_fn=lambda: now)

        # ---- 1. Alice creates a TLD keypair and claims alias "foo". ----
        alice = crypto.Keypair.generate()
        alice_tid = crypto.tld_id(alice.public_bytes)
        # Mine the alias claim at LOW difficulty (fast). nonce_size=16 fixes
        # nonce[0]=8 per Appendix A.4.
        claim = claims.AliasClaim.mine(
            alias="foo",
            claimant_keypair=alice,
            timestamp=now,
            difficulty_bits=8,
            max_iters=2_000_000,
            nonce_size=16,
        )
        # Self-certifying TLD: tld_id == SHA-256(claimant_pk).
        self.assertTrue(claim.verify_claimant_consistency())
        # PoW recomputes at the difficulty we mined (8 leading-zero bits).
        self.assertTrue(claim.verify_pow(difficulty_bits=8))

        # Simulate W witnesses (distinct node keypairs) co-signing the claim.
        witnesses = []
        for i in range(constants.W):
            nkp = crypto.Keypair.generate()
            witnesses.append(
                claims.WitnessAttestation.create(
                    nkp, now + i, "foo", alice_tid, alice.public_bytes
                )
            )
        claim.witnesses = witnesses
        # Full §7.4 validity: claimant binds, PoW valid via DEFAULT difficulty
        # inference (nonce[0]=8 >= the lowered POW_DIFFICULTY_INIT), and the
        # W distinct witness signatures all verify.
        self.assertTrue(claims.verify_full(claim, quorum=constants.W))

        # ---- 2. Publish the TLD record (empty rrset, claim in field 11). ----
        tld_name = naming.encode_wire_name([], "foo", alice_tid)
        tld_rec = wire.Record(
            name=tld_name,
            owner=alice.public_bytes,
            sequence=1,
            created=now,
            expires=now + constants.RECORD_DEFAULT_TTL,
            claim=claim,
        )
        tld_env = wire.sign_record(tld_rec, alice)
        self.assertTrue(tld_env.verify_signature())
        # The TLD record is self-signed (signer == owner == the TLD key); this
        # is what makes it the self-certifying root of the authority chain.
        self.assertEqual(tld_env.signer, tld_env.record.owner)
        k_tld = naming.dht_key_tld(alice_tid)
        self.assertTrue(dht.put(k_tld, tld_env, now=now))

        # K_claim is deterministic: SHA-256(0x03 || "claim:" || alias).
        k_claim = naming.dht_key_claim("foo")
        self.assertEqual(
            k_claim, hashlib.sha256(bytes([3]) + b"claim:foo").digest()
        )

        # ---- 3. Alice delegates "alice.foo" to a fresh key. ----
        alice_sub = crypto.Keypair.generate()
        alice_sub_pk = alice_sub.public_bytes
        alice_name = naming.encode_wire_name(["alice"], "foo", alice_tid)
        alice_rec = wire.Record(
            name=alice_name,
            owner=alice_sub_pk,
            sequence=1,
            created=now,
            expires=now + constants.RECORD_DEFAULT_TTL,
            delegation=alice_sub_pk,
        )
        # Alice (the TLD key) signs the alice.foo record; its delegation
        # field names alice_sub as the authorized signer of the subtree.
        alice_env = wire.sign_record(alice_rec, alice)
        k_alice = naming.dht_key_name(alice_name)
        self.assertTrue(dht.put(k_alice, alice_env, now=now))

        # ---- 4. alice.foo (now owned by alice_sub) serves www.alice.foo. ----
        www_name = naming.encode_wire_name(["www", "alice"], "foo", alice_tid)
        www_rec = wire.Record(
            name=www_name,
            owner=alice_sub_pk,
            sequence=1,
            created=now,
            expires=now + constants.RECORD_DEFAULT_TTL,
            rrset=[wire.RR.a(bytes([203, 0, 113, 42]), ttl=300)],
        )
        # alice_sub signs the www record directly (it was delegated authority
        # over the alice.foo subtree by the parent record in step 3).
        www_env = wire.sign_record(www_rec, alice_sub)
        k_www = naming.dht_key_name(www_name)
        self.assertTrue(dht.put(k_www, www_env, now=now))

        # ---- 5. RESOLVE www.alice.foo: walk the authority chain. ----
        fetched_tld = dht.get(k_tld, now=now)
        self.assertIsNotNone(fetched_tld)
        fetched_alice = dht.get(k_alice, now=now)
        self.assertIsNotNone(fetched_alice)
        fetched_www = dht.get(k_www, now=now)
        self.assertIsNotNone(fetched_www)

        # TLD -> alice -> www: every hop is signature-valid, the root is
        # self-certifying, and each child is authorized by its parent
        # (delegation field or direct owner-signs-child).
        chain = [fetched_tld, fetched_alice, fetched_www]
        self.assertTrue(wire.verify_authority_chain(chain))
        self.assertTrue(wire.is_basic_valid(fetched_www, now))

        # Read the A record out of the resolved rrset.
        a_rrs = [rr for rr in fetched_www.record.rrset if rr.type == wire.RR_TYPE_A]
        self.assertEqual(len(a_rrs), 1)
        self.assertEqual(a_rrs[0].rdata, bytes([203, 0, 113, 42]))
        self.assertEqual(a_rrs[0].ttl, 300)

        # ---- 6. Resolver routing: alias "foo" is freens-routed. ----
        cfg = rc.parse_config("[tld-routes]\n* = dns-first\nfoo = freens\n")
        self.assertEqual(rc.route_for(cfg, "foo"), rc.Route.FREENS)

        # ---- 7. A record signed by an UNAUTHORIZED key is rejected. ----
        evil = crypto.Keypair.generate()
        evil_rec = wire.Record(
            name=www_name,
            owner=alice_sub_pk,
            sequence=2,
            created=now,
            expires=now + constants.RECORD_DEFAULT_TTL,
            rrset=[wire.RR.a(bytes([6, 6, 6, 6]), ttl=300)],
        )
        evil_env = wire.sign_record(evil_rec, evil)  # signed by evil, not alice_sub
        # evil is in no delegation/owner position of any parent, so the
        # authority chain rejects it even though the envelope is alone
        # structurally + signature valid.
        chain_evil = [fetched_tld, fetched_alice, evil_env]
        self.assertFalse(wire.verify_authority_chain(chain_evil))
        self.assertTrue(wire.is_basic_valid(evil_env, now))

        # ---- 8. DHT winner rule: a stale same-sequence record does NOT ----
        #       necessarily replace the incumbent (bytewise-hash tie-break).
        stale_rec = wire.Record(
            name=www_name,
            owner=alice_sub_pk,
            sequence=1,
            created=now,
            expires=now + constants.RECORD_DEFAULT_TTL,
            rrset=[wire.RR.a(bytes([7, 7, 7, 7]), ttl=300)],
        )
        stale_env = wire.sign_record(stale_rec, alice_sub)
        # Same sequence as the incumbent (seq 1) -> the store keeps exactly
        # one winner deterministically by bytewise-greater record_hash.
        dht.put(k_www, stale_env, now=now)
        winner = dht.get(k_www, now=now)
        self.assertIsNotNone(winner)
        self.assertIn(
            winner.record_hash(),
            {www_env.record_hash(), stale_env.record_hash()},
        )

        # ---- 9. Sequence bump: a seq-2 update with a new IP wins. ----
        www_rec2 = wire.Record(
            name=www_name,
            owner=alice_sub_pk,
            sequence=2,
            created=now,
            expires=now + constants.RECORD_DEFAULT_TTL,
            rrset=[wire.RR.a(bytes([198, 51, 100, 7]), ttl=300)],
        )
        www_env2 = wire.sign_record(www_rec2, alice_sub)
        self.assertTrue(dht.put(k_www, www_env2, now=now))
        final = dht.get(k_www, now=now)
        self.assertEqual(final.record.sequence, 2)
        self.assertEqual(
            [rr for rr in final.record.rrset if rr.type == wire.RR_TYPE_A][0].rdata,
            bytes([198, 51, 100, 7]),
        )

    def test_collision_resolution(self):
        """Two parties claim "foo"; the §7.4 ordering picks one deterministically."""
        now = 1_000_000
        alice = crypto.Keypair.from_private_bytes(b"\xa1" * 32)
        bob = crypto.Keypair.from_private_bytes(b"\xb0" * 32)
        # Mine both claims at low difficulty for speed; Bob's asserted
        # timestamp (now+50) is earlier than Alice's (now+100).
        c_a = claims.AliasClaim.mine(
            "foo", alice, now + 100, difficulty_bits=8, max_iters=2_000_000
        )
        c_b = claims.AliasClaim.mine(
            "foo", bob, now + 50, difficulty_bits=8, max_iters=2_000_000
        )
        # Both are valid at the difficulty they were mined.
        self.assertTrue(c_a.verify_pow(difficulty_bits=8))
        self.assertTrue(c_b.verify_pow(difficulty_bits=8))
        # Default difficulty inference succeeds too (nonce[0]=8 >= the
        # lowered POW_DIFFICULTY_INIT).
        self.assertTrue(c_a.verify_pow())

        # With POW_DIFFICULTY_INIT lowered to 8, both difficulty-8 claims survive the
        # PoW filter; select_winner applies the (timestamp, pow_hash, tld_id) total
        # order and deterministically picks Bob (earlier asserted timestamp).
        winner = claims.select_winner([c_a, c_b])
        self.assertIsNotNone(winner)
        self.assertEqual(winner.claimant_pk, bob.public_bytes)
        self.assertEqual(winner.timestamp, now + 50)
        # Deterministic: same winner regardless of input order.
        self.assertEqual(
            claims.select_winner([c_b, c_a]).claimant_pk, winner.claimant_pk
        )
        # And it agrees with a direct tuple comparison.
        self.assertLess(c_b.order_key(), c_a.order_key())


if __name__ == "__main__":
    unittest.main()
