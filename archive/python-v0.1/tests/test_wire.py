"""PROTOCOL-CORE wire-format test suite for the freens package.

Exercises :mod:`freens.wire` — ``RR``, ``Record``, ``SignedEnvelope``, the
``Message`` KRPC envelope — and the protocol helpers (``sign_record``,
``is_basic_valid``, ``record_is_revoked``, ``envelope_wins``,
``verify_authority_chain``) against the exact public API, using only the
standard-library :mod:`unittest`.  Run with::

    python3 -m unittest discover
"""

import hashlib
import unittest

from freens import cbor_canon, claims, constants, crypto, naming, wire


# ---------------------------------------------------------------------------
# §4.3 — Resource records
# ---------------------------------------------------------------------------
class TestRR(unittest.TestCase):
    def test_cbor_value_roundtrip(self):
        rr = wire.RR(type=wire.RR_TYPE_A, ttl=300, rdata=bytes([1, 2, 3, 4]))
        self.assertEqual(rr.to_cbor_value(), [1, 300, bytes([1, 2, 3, 4])])
        dec = wire.RR.from_cbor_value([1, 300, bytes([1, 2, 3, 4])])
        self.assertEqual(dec.type, wire.RR_TYPE_A)
        self.assertEqual(dec.ttl, 300)
        self.assertEqual(dec.rdata, bytes([1, 2, 3, 4]))

    def test_a_constructor(self):
        a = wire.RR.a(bytes([203, 0, 113, 42]), ttl=300)
        self.assertEqual(a.type, wire.RR_TYPE_A)
        self.assertEqual(a.rdata, bytes([203, 0, 113, 42]))

    def test_invalid_construction_raises_valueerror(self):
        # ttl must be > 0.
        with self.assertRaises(ValueError):
            wire.RR(type=1, ttl=0, rdata=b"x")
        # ttl must be <= RECORD_MAX_TTL.
        with self.assertRaises(ValueError):
            wire.RR(type=1, ttl=constants.RECORD_MAX_TTL + 1, rdata=b"x")
        # A rdata must be exactly 4 bytes.
        with self.assertRaises(ValueError):
            wire.RR.a(bytes(3))
        # AAAA rdata must be exactly 16 bytes.
        with self.assertRaises(ValueError):
            wire.RR.aaaa(bytes(15))
        # bool is not accepted where a uint is required (_is_uint rejects bool).
        with self.assertRaises(ValueError):
            wire.RR(type=True, ttl=300, rdata=b"x")

    def test_txt_unicode_roundtrip(self):
        rr = wire.RR.txt("é")
        self.assertEqual(rr.type, wire.RR_TYPE_TXT)
        # NFC-normalized UTF-8 of U+00E9.
        self.assertEqual(rr.rdata, "é".encode("utf-8"))
        dec = wire.RR.from_cbor_value(
            [wire.RR_TYPE_TXT, constants.RECORD_DEFAULT_TTL, rr.rdata]
        )
        self.assertEqual(dec.rdata, rr.rdata)

    def test_arbitrary_rdata_accepted(self):
        rr = wire.RR(type=1, ttl=300, rdata=b"x")
        self.assertEqual(rr.rdata, b"x")


# ---------------------------------------------------------------------------
# §4.1 — FREENS_Record (minimal TLD record)
# ---------------------------------------------------------------------------
class TestRecordMinimal(unittest.TestCase):
    def _build(self):
        kp = crypto.Keypair.generate()
        tid = crypto.tld_id(kp.public_bytes)
        name = naming.encode_wire_name([], "foo", tid)
        rec = wire.Record(
            name=name,
            owner=kp.public_bytes,
            sequence=1,
            created=1000,
            expires=2000,
        )
        return kp, name, rec

    def test_defaults_and_structure(self):
        kp, name, rec = self._build()
        self.assertEqual(rec.version, 1)
        self.assertEqual(len(rec.owner), 32)
        self.assertIsNone(rec.validate_structure())

    def test_canonical_bytes_match_hand_built_dict(self):
        kp, name, rec = self._build()
        expected = {
            1: 1,
            2: name,
            3: kp.public_bytes,
            4: 1,
            5: 1000,
            6: 2000,
            7: [],
        }
        self.assertEqual(rec.canonical_bytes(), cbor_canon.dumps(expected))

    def test_invalid_records_raise_wireerror(self):
        kp, name, rec = self._build()
        # owner wrong length.
        with self.assertRaises(wire.WireError):
            wire.Record(name=name, owner=bytes(31), sequence=1,
                        created=1000, expires=2000)
        # sequence < 1.
        with self.assertRaises(wire.WireError):
            wire.Record(name=name, owner=kp.public_bytes, sequence=0,
                        created=1000, expires=2000)
        # created > expires.
        with self.assertRaises(wire.WireError):
            wire.Record(name=name, owner=kp.public_bytes, sequence=1,
                        created=2000, expires=1000)
        # wrong version.
        with self.assertRaises(wire.WireError):
            wire.Record(name=name, owner=kp.public_bytes, sequence=1,
                        created=1000, expires=2000, version=2)
        # empty name.
        with self.assertRaises(wire.WireError):
            wire.Record(name=b"", owner=kp.public_bytes, sequence=1,
                        created=1000, expires=2000)
        # rrset must contain only RR instances.
        with self.assertRaises(wire.WireError):
            wire.Record(name=name, owner=kp.public_bytes, sequence=1,
                        created=1000, expires=2000, rrset=[object()])

    def test_optional_fields_omitted_when_none(self):
        kp, name, rec = self._build()
        d = rec.to_cbor_value()
        for k in (8, 9, 10, 11, 12):
            self.assertNotIn(k, d)


# ---------------------------------------------------------------------------
# §4.1 — SignedEnvelope
# ---------------------------------------------------------------------------
class TestSignedEnvelope(unittest.TestCase):
    def _env(self):
        kp = crypto.Keypair.generate()
        tid = crypto.tld_id(kp.public_bytes)
        name = naming.encode_wire_name([], "foo", tid)
        rec = wire.Record(name=name, owner=kp.public_bytes, sequence=1,
                          created=1000, expires=2000)
        return kp, wire.sign_record(rec, kp)

    def test_signature_and_identity(self):
        kp, env = self._env()
        self.assertTrue(env.verify_signature())
        self.assertEqual(env.signer, kp.public_bytes)
        self.assertEqual(len(env.sig), constants.ED25519_SIGNATURE_LEN)

    def test_record_hash_is_sha256_of_envelope_bytes(self):
        kp, env = self._env()
        self.assertEqual(
            env.record_hash(),
            hashlib.sha256(env.to_bytes()).digest(),
        )

    def test_tampering_record_breaks_signature(self):
        kp, env = self._env()
        env2 = wire.SignedEnvelope(record=env.record, sig=env.sig, signer=env.signer)
        # Mutating the rrset changes canonical_record_bytes -> sig no longer matches.
        env2.record.rrset.append(wire.RR.a(bytes([1, 2, 3, 4])))
        self.assertFalse(env2.verify_signature())

    def test_byte_stable_roundtrip(self):
        kp, env = self._env()
        decoded = wire.SignedEnvelope.from_bytes(env.to_bytes())
        self.assertTrue(decoded.verify_signature())
        self.assertEqual(decoded.to_bytes(), env.to_bytes())
        self.assertEqual(decoded.record.owner, env.record.owner)
        self.assertEqual(decoded.record.sequence, env.record.sequence)

    def test_from_bytes_rejects_garbage(self):
        kp, env = self._env()
        # Not CBOR at all.
        with self.assertRaises(wire.WireError):
            wire.SignedEnvelope.from_bytes(b"not cbor")
        # Valid CBOR but missing all envelope keys.
        with self.assertRaises(wire.WireError):
            wire.SignedEnvelope.from_bytes(cbor_canon.dumps({}))
        # Valid CBOR map present but missing field 2 (sig).
        with self.assertRaises(wire.WireError):
            wire.SignedEnvelope.from_bytes(
                cbor_canon.dumps({1: {}, 3: b"\x00" * 32})
            )


# ---------------------------------------------------------------------------
# §6.4 PUT step 3 — DHT store winner rule
# ---------------------------------------------------------------------------
class TestEnvelopeWins(unittest.TestCase):
    def _fixture(self):
        kp = crypto.Keypair.generate()
        tid = crypto.tld_id(kp.public_bytes)
        name = naming.encode_wire_name([], "foo", tid)
        return kp, name

    def _seq_env(self, kp, name, sequence, rrset=None):
        rec = wire.Record(name=name, owner=kp.public_bytes, sequence=sequence,
                          created=1000, expires=20000, rrset=rrset or [])
        return wire.sign_record(rec, kp)

    def test_higher_sequence_wins(self):
        kp, name = self._fixture()
        e4 = self._seq_env(kp, name, 4)
        e5 = self._seq_env(kp, name, 5)
        self.assertTrue(wire.envelope_wins(e5, e4))
        self.assertFalse(wire.envelope_wins(e4, e5))

    def test_same_envelope_neither_wins(self):
        kp, name = self._fixture()
        e5 = self._seq_env(kp, name, 5)
        # Same sequence AND same hash -> not strictly greater.
        self.assertFalse(wire.envelope_wins(e5, e5))

    def test_same_sequence_bytewise_hash_tiebreak(self):
        kp, name = self._fixture()
        e5 = self._seq_env(kp, name, 5)
        e5b = self._seq_env(kp, name, 5, rrset=[wire.RR.a(bytes([9, 9, 9, 9]))])
        # Hashes must differ because the rrset differs.
        self.assertNotEqual(e5.record_hash(), e5b.record_hash())
        winner_is_5b = e5b.record_hash() > e5.record_hash()
        self.assertEqual(wire.envelope_wins(e5b, e5), winner_is_5b)
        self.assertEqual(wire.envelope_wins(e5, e5b), (not winner_is_5b))


# ---------------------------------------------------------------------------
# §4.4 — basic validity (structural + signature + time window)
# ---------------------------------------------------------------------------
class TestIsBasicValid(unittest.TestCase):
    def _env(self):
        kp = crypto.Keypair.generate()
        tid = crypto.tld_id(kp.public_bytes)
        name = naming.encode_wire_name([], "foo", tid)
        rec = wire.Record(name=name, owner=kp.public_bytes, sequence=1,
                          created=1000, expires=2000)
        return kp, rec, wire.sign_record(rec, kp)

    def test_valid_in_window(self):
        kp, rec, env = self._env()
        self.assertTrue(wire.is_basic_valid(env, 1500))

    def test_before_created_invalid(self):
        kp, rec, env = self._env()
        self.assertFalse(wire.is_basic_valid(env, 500))

    def test_at_or_after_expires_invalid(self):
        kp, rec, env = self._env()
        self.assertFalse(wire.is_basic_valid(env, 2000))

    def test_bad_signature_invalid(self):
        kp, rec, env = self._env()
        env_bad = wire.SignedEnvelope(
            record=rec, sig=env.sig,
            signer=crypto.Keypair.generate().public_bytes,
        )
        self.assertFalse(wire.is_basic_valid(env_bad, 1500))


# ---------------------------------------------------------------------------
# §8.5 — revocation
# ---------------------------------------------------------------------------
class TestRevoke(unittest.TestCase):
    def test_revoked_record_detected(self):
        kp = crypto.Keypair.generate()
        tid = crypto.tld_id(kp.public_bytes)
        name = naming.encode_wire_name([], "foo", tid)
        rec_rev = wire.Record(name=name, owner=kp.public_bytes, sequence=2,
                              created=1000, expires=2000, revoke=True)
        env = wire.sign_record(rec_rev, kp)
        self.assertTrue(wire.record_is_revoked(env))

    def test_normal_record_not_revoked(self):
        kp = crypto.Keypair.generate()
        tid = crypto.tld_id(kp.public_bytes)
        name = naming.encode_wire_name([], "foo", tid)
        rec_norm = wire.Record(name=name, owner=kp.public_bytes, sequence=2,
                               created=1000, expires=2000, revoke=None)
        env = wire.sign_record(rec_norm, kp)
        self.assertFalse(wire.record_is_revoked(env))


# ---------------------------------------------------------------------------
# §3.4 — authority chain verification
# ---------------------------------------------------------------------------
class TestAuthorityChain(unittest.TestCase):
    def _tld_fixture(self):
        tld_kp = crypto.Keypair.generate()
        tid = crypto.tld_id(tld_kp.public_bytes)
        tld_name = naming.encode_wire_name([], "foo", tid)
        return tld_kp, tid, tld_name

    def test_one_hop_self_certifying(self):
        tld_kp, tid, tld_name = self._tld_fixture()
        tld_rec = wire.Record(name=tld_name, owner=tld_kp.public_bytes,
                              sequence=1, created=1000, expires=10_000_000)
        tld_env = wire.sign_record(tld_rec, tld_kp)
        self.assertTrue(wire.verify_authority_chain([tld_env]))

    def test_forged_signer_fails(self):
        tld_kp, tid, tld_name = self._tld_fixture()
        tld_rec = wire.Record(name=tld_name, owner=tld_kp.public_bytes,
                              sequence=1, created=1000, expires=10_000_000)
        tld_env = wire.sign_record(tld_rec, tld_kp)
        forged = wire.SignedEnvelope(
            record=tld_rec, sig=tld_env.sig,
            signer=crypto.Keypair.generate().public_bytes,
        )
        self.assertFalse(wire.verify_authority_chain([forged]))

    def test_two_hop_delegation(self):
        tld_kp, tid, tld_name = self._tld_fixture()
        alice_kp = crypto.Keypair.generate()
        alice_pk = alice_kp.public_bytes
        tld_rec_del = wire.Record(name=tld_name, owner=tld_kp.public_bytes,
                                  sequence=1, created=1000, expires=10_000_000,
                                  delegation=alice_pk)
        tld_env_del = wire.sign_record(tld_rec_del, tld_kp)
        alice_name = naming.encode_wire_name(["alice"], "foo", tid)
        alice_rec = wire.Record(name=alice_name, owner=alice_pk,
                                sequence=1, created=1000, expires=10_000_000)
        alice_env = wire.sign_record(alice_rec, alice_kp)
        self.assertTrue(wire.verify_authority_chain([tld_env_del, alice_env]))

    def test_two_hop_wrong_child_key_fails(self):
        tld_kp, tid, tld_name = self._tld_fixture()
        alice_kp = crypto.Keypair.generate()
        alice_pk = alice_kp.public_bytes
        tld_rec_del = wire.Record(name=tld_name, owner=tld_kp.public_bytes,
                                  sequence=1, created=1000, expires=10_000_000,
                                  delegation=alice_pk)
        tld_env_del = wire.sign_record(tld_rec_del, tld_kp)
        alice_name = naming.encode_wire_name(["alice"], "foo", tid)
        alice_rec = wire.Record(name=alice_name, owner=alice_pk,
                                sequence=1, created=1000, expires=10_000_000)
        evil_kp = crypto.Keypair.generate()
        # Signature is valid under alice_pk, but signer claims evil_pk.
        alice_env_evil = wire.SignedEnvelope(
            record=alice_rec,
            sig=alice_kp.sign(alice_rec.canonical_bytes()),
            signer=evil_kp.public_bytes,
        )
        self.assertFalse(wire.verify_authority_chain([tld_env_del, alice_env_evil]))

    def test_three_hop_delegation(self):
        tld_kp, tid, tld_name = self._tld_fixture()
        alice_kp = crypto.Keypair.generate()
        alice_pk = alice_kp.public_bytes
        bob_kp = crypto.Keypair.generate()
        bob_pk = bob_kp.public_bytes
        tld_rec_del = wire.Record(name=tld_name, owner=tld_kp.public_bytes,
                                  sequence=1, created=1000, expires=10_000_000,
                                  delegation=alice_pk)
        tld_env_del = wire.sign_record(tld_rec_del, tld_kp)
        alice_name = naming.encode_wire_name(["alice"], "foo", tid)
        alice_rec_del = wire.Record(name=alice_name, owner=alice_pk,
                                    sequence=1, created=1000, expires=10_000_000,
                                    delegation=bob_pk)
        alice_env_del = wire.sign_record(alice_rec_del, alice_kp)
        www_name = naming.encode_wire_name(["www", "alice"], "foo", tid)
        www_rec = wire.Record(name=www_name, owner=bob_pk,
                              sequence=1, created=1000, expires=10_000_000)
        www_env = wire.sign_record(www_rec, bob_kp)
        self.assertTrue(wire.verify_authority_chain(
            [tld_env_del, alice_env_del, www_env]))

    def test_chain_exceeding_max_depth_rejected(self):
        tld_kp, tid, tld_name = self._tld_fixture()
        tld_rec_del = wire.Record(
            name=tld_name, owner=tld_kp.public_bytes,
            sequence=1, created=1000, expires=10_000_000,
            delegation=crypto.Keypair.generate().public_bytes,
        )
        tld_env_del = wire.sign_record(tld_rec_del, tld_kp)
        deep = [tld_env_del]
        cur_kp = tld_kp
        # MAX_LABELS + 1 hops on top of the TLD root -> one too many.
        for _ in range(constants.MAX_LABELS + 1):
            child_kp = crypto.Keypair.generate()
            parent_rec = wire.Record(
                name=tld_name, owner=cur_kp.public_bytes,
                sequence=1, created=1000, expires=10_000_000,
                delegation=child_kp.public_bytes,
            )
            deep.append(wire.sign_record(parent_rec, cur_kp))
            cur_kp = child_kp
        # The length cap (MAX_LABELS + 1) is enforced before semantic checks.
        self.assertGreater(len(deep), constants.MAX_LABELS + 1)
        self.assertFalse(wire.verify_authority_chain(deep))


# ---------------------------------------------------------------------------
# §6.3 / Appendix B.1 — KRPC Message
# ---------------------------------------------------------------------------
class TestMessage(unittest.TestCase):
    def _msg(self):
        sender = crypto.Keypair.generate()
        recipient = crypto.Keypair.generate()
        recipient_id = crypto.node_id(recipient.public_bytes)
        txid = b"\x01\x02\x03"
        msg = wire.Message.query(
            method="ping", args={}, sender_keypair=sender,
            recipient_id=recipient_id, txid=txid,
        )
        return sender, recipient_id, txid, msg

    def test_query_fields_and_id_binding(self):
        sender, recipient_id, txid, msg = self._msg()
        self.assertEqual(msg.y, wire.MSG_TYPE_QUERY)
        self.assertEqual(msg.q, "ping")
        self.assertEqual(msg.t, txid)
        # id == SHA-256(pk).
        self.assertEqual(crypto.node_id(msg.pk), msg.id)

    def test_verify_and_signing_input(self):
        sender, recipient_id, txid, msg = self._msg()
        self.assertTrue(msg.verify(recipient_id))
        # signing_input is the canonical CBOR array [t, id, recipient_id, a].
        self.assertEqual(
            msg.signing_input(recipient_id),
            cbor_canon.dumps([msg.t, msg.id, recipient_id, msg.a]),
        )

    def test_tampered_args_fail_verify(self):
        sender, recipient_id, txid, msg = self._msg()
        msg2 = wire.Message(
            y="q", t=txid, a={"k": "v"}, id=msg.id, pk=msg.pk,
            q="ping", sig=msg.sig,
        )
        self.assertFalse(msg2.verify(recipient_id))

    def test_wrong_recipient_fails_verify(self):
        sender, recipient_id, txid, msg = self._msg()
        other_id = crypto.node_id(crypto.Keypair.generate().public_bytes)
        self.assertFalse(msg.verify(other_id))

    def test_byte_roundtrip(self):
        sender, recipient_id, txid, msg = self._msg()
        decoded = wire.Message.from_bytes(msg.to_bytes())
        self.assertTrue(decoded.verify(recipient_id))

    def test_response_and_error_factories(self):
        sender = crypto.Keypair.generate()
        recipient_id = crypto.node_id(crypto.Keypair.generate().public_bytes)
        txid = b"\x01\x02\x03"
        r = wire.Message.response(args={"x": 1}, sender_keypair=sender,
                                  recipient_id=recipient_id, txid=txid)
        self.assertEqual(r.y, wire.MSG_TYPE_RESPONSE)
        self.assertTrue(r.verify(recipient_id))
        e = wire.Message.error(args={"code": 301}, sender_keypair=sender,
                               recipient_id=recipient_id, txid=txid)
        self.assertEqual(e.y, wire.MSG_TYPE_ERROR)
        self.assertTrue(e.verify(recipient_id))

    def test_forged_id_rejected_at_construction(self):
        sender = crypto.Keypair.generate()
        txid = b"\x01\x02\x03"
        # id != SHA-256(pk).
        with self.assertRaises(wire.WireError):
            wire.Message(y="q", t=txid, a={}, id=b"\x00" * 32,
                         pk=sender.public_bytes, q="ping")

    def test_query_without_method_rejected(self):
        sender = crypto.Keypair.generate()
        txid = b"\x01\x02\x03"
        with self.assertRaises(wire.WireError):
            wire.Message(y="q", t=txid, a={},
                         id=crypto.node_id(sender.public_bytes),
                         pk=sender.public_bytes, q=None)


if __name__ == "__main__":
    unittest.main()
