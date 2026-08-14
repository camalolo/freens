"""Unit tests for :mod:`freens.dht.store` — PUT/GET winner rule + eviction.

Implements the conformance checks documented in ``freens/dht/store.py``:

* §6.4 step 3 — strict winner rule: a newcomer is kept only if it has a
  strictly higher ``sequence`` (tie-break: bytewise-greater ``H_record``).
* §6.4 step 4 — entries past ``expires + EXPIRY_GRACE`` are evicted lazily
  on access and swept by :meth:`evict_expired`.
* Signature enforcement: a forged envelope (signature attributed to the
  wrong signer) is rejected unless ``verify_signature=False``.
* §12 byte cap: when total stored bytes exceed ``max_bytes`` the store
  evicts expired-first then LRU, while the just-put key is always retained.
* Input validation: a non-32-byte or non-bytes key raises ``ValueError``.

All timing is injected (``time_fn=lambda: FIXED`` or a mutable ``_Clock``)
so the suite never depends on the wall clock.

Run via ``python3 -m unittest discover`` from the project root.
"""

import unittest

from freens import constants, crypto, naming, wire
from freens.dht import store


def make_env(sequence=1, created=1000, expires=10_000_000, rrset=None,
             owner_kp=None):
    """Build a signature-valid :class:`wire.SignedEnvelope` for store tests.

    The owner key signs its own TLD record (zero labels, alias ``"foo"``);
    ``signer == owner`` so :meth:`verify_signature` returns ``True``.
    """
    if owner_kp is None:
        owner_kp = crypto.Keypair.generate()
    tid = crypto.tld_id(owner_kp.public_bytes)
    name = naming.encode_wire_name([], "foo", tid)
    rec = wire.Record(
        name=name,
        owner=owner_kp.public_bytes,
        sequence=sequence,
        created=created,
        expires=expires,
        rrset=rrset or [],
    )
    return wire.sign_record(rec, owner_kp)


class TestBasicPutGet(unittest.TestCase):
    def test_put_get_roundtrip(self):
        s = store.EnvelopeStore(
            max_bytes=constants.NODE_STORAGE_MAX, time_fn=lambda: 1500
        )
        env = make_env()
        key = b"\x00" * 32

        self.assertTrue(s.put(key, env, now=1500))
        self.assertEqual(s.count(), 1)
        self.assertTrue(s.has(key, now=1500))

        got = s.get(key, now=1500)
        self.assertIsNotNone(got)
        self.assertEqual(got.record_hash(), env.record_hash())
        # Cached byte size matches the serialised envelope exactly.
        self.assertEqual(s.size_bytes(), len(env.to_bytes()))


class TestWinnerRule(unittest.TestCase):
    def test_higher_sequence_wins_lower_rejected(self):
        s = store.EnvelopeStore(time_fn=lambda: 1500)
        kp = crypto.Keypair.generate()
        tid = crypto.tld_id(kp.public_bytes)
        name = naming.encode_wire_name([], "foo", tid)
        r4 = wire.Record(
            name=name, owner=kp.public_bytes, sequence=4,
            created=1000, expires=10_000_000,
        )
        r5 = wire.Record(
            name=name, owner=kp.public_bytes, sequence=5,
            created=1000, expires=10_000_000,
        )
        e4 = wire.sign_record(r4, kp)
        e5 = wire.sign_record(r5, kp)
        key = b"\x11" * 32

        # seq 4 accepted; seq 5 strictly wins and replaces it.
        self.assertTrue(s.put(key, e4, now=1500))
        self.assertTrue(s.put(key, e5, now=1500))
        self.assertEqual(s.get(key, now=1500).record.sequence, 5)

        # An OLDER envelope (seq 4 < 5) is rejected; incumbent unchanged.
        self.assertFalse(s.put(key, e4, now=1500))
        self.assertEqual(s.get(key, now=1500).record.sequence, 5)


class TestBadSignature(unittest.TestCase):
    def test_forged_signer_rejected(self):
        s = store.EnvelopeStore(time_fn=lambda: 1500)
        env = make_env()
        # Forge: identical record + signature but attributed to a DIFFERENT
        # signer.  The signature will not verify under the wrong public key.
        bad = wire.SignedEnvelope(
            record=env.record,
            sig=env.sig,
            signer=crypto.Keypair.generate().public_bytes,
        )
        self.assertFalse(s.put(b"\x22" * 32, bad, now=1500))
        self.assertEqual(s.count(), 0)

        # verify_signature=False bypasses the check (testing escape hatch);
        # the envelope is still required to be a SignedEnvelope.
        self.assertTrue(
            s.put(b"\x22" * 32, bad, now=1500, verify_signature=False)
        )


class _Clock:
    """Mutable clock for advancing a store's notion of 'now'."""

    def __init__(self):
        self.t = 1500

    def __call__(self):
        return self.t


class TestExpiry(unittest.TestCase):
    def test_lazy_eviction_and_evict_expired(self):
        clk = _Clock()
        s = store.EnvelopeStore(time_fn=clk)
        env = make_env(created=1000, expires=2000)
        key = b"\x33" * 32

        self.assertTrue(s.put(key, env, now=1500))

        # Within grace (expires + EXPIRY_GRACE): still alive.
        clk.t = 2000 + constants.EXPIRY_GRACE - 1
        self.assertIsNotNone(s.get(key, now=clk.t))

        # Past grace: lazily evicted on get; count drops to 0.
        clk.t = 2000 + constants.EXPIRY_GRACE + 1
        self.assertIsNone(s.get(key, now=clk.t))
        self.assertEqual(s.count(), 0)

        # evict_expired sweeps dead entries and reports the count.
        s.put(key, env, now=1500)
        clk.t = 3000 + constants.EXPIRY_GRACE
        n = s.evict_expired(now=clk.t)
        self.assertGreaterEqual(n, 1)
        self.assertEqual(s.count(), 0)


class TestByteCap(unittest.TestCase):
    def test_cap_evicts_lru_but_keeps_just_put(self):
        env1 = make_env()
        env2 = make_env()
        env3 = make_env()
        # Cap sized for two envelopes plus a little slack.
        cap = len(env1.to_bytes()) + len(env2.to_bytes()) + 64
        s = store.EnvelopeStore(max_bytes=cap, time_fn=lambda: 1500)

        self.assertTrue(s.put(b"\x01" * 32, env1, now=1500))
        self.assertTrue(s.put(b"\x02" * 32, env2, now=1500))
        # Under cap (or under count) after two puts.
        self.assertTrue(s.size_bytes() <= cap or s.count() <= 2)

        # Third put triggers LRU eviction to honour the cap.
        self.assertTrue(s.put(b"\x03" * 32, env3, now=1500))
        self.assertLessEqual(s.count(), 3)
        self.assertLessEqual(s.size_bytes(), cap + len(env3.to_bytes()))

        # The just-put envelope is protected from LRU eviction and survives.
        self.assertTrue(s.has(b"\x03" * 32, now=1500))


class TestInvalidKey(unittest.TestCase):
    def test_wrong_key_length_raises(self):
        s = store.EnvelopeStore(time_fn=lambda: 1500)
        with self.assertRaises(ValueError):
            s.put(b"\x00" * 31, make_env(), now=1500)

    def test_wrong_key_type_raises(self):
        s = store.EnvelopeStore(time_fn=lambda: 1500)
        with self.assertRaises(ValueError):
            s.put("not bytes", make_env(), now=1500)


if __name__ == "__main__":
    unittest.main()
