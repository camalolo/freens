"""Unit tests for :mod:`freens.dht.tokens` — rotating HMAC-SHA256 write tokens.

The :class:`tokens.TokenStore` derives a per-epoch secret from a root secret
and issues ``token = HMAC-SHA256(epoch_secret, peer_ip)``.  Epochs advance
every ``TOKEN_ROTATION`` (300 s) seconds; a token remains valid for the
current epoch and the previous ``tolerance_epochs`` (default 1).

Determinism is achieved entirely via the injectable ``time_fn`` clock — no
wall-clock dependence.  A mutable ``_Clock`` holder lets a single store's
clock be advanced across epoch boundaries.

Run via ``python3 -m unittest discover`` from the project root.
"""

import unittest

from freens import constants
from freens.dht import tokens


class TestTokenIssue(unittest.TestCase):
    def test_issue_returns_32_byte_digest(self):
        ts = tokens.TokenStore(root_secret=b"k" * 32, time_fn=lambda: 1000.0)
        tok = ts.issue("1.2.3.4")
        self.assertIsInstance(tok, bytes)
        self.assertEqual(len(tok), 32)  # SHA-256 digest length

    def test_deterministic_same_secret_peer_time(self):
        # Two stores sharing (root_secret, peer, time) issue identical tokens.
        ts1 = tokens.TokenStore(root_secret=b"k" * 32, time_fn=lambda: 1000.0)
        ts2 = tokens.TokenStore(root_secret=b"k" * 32, time_fn=lambda: 1000.0)
        self.assertEqual(ts1.issue("1.2.3.4"), ts2.issue("1.2.3.4"))

    def test_different_peer_different_token(self):
        ts = tokens.TokenStore(root_secret=b"k" * 32, time_fn=lambda: 1000.0)
        tok = ts.issue("1.2.3.4")
        self.assertNotEqual(ts.issue("5.6.7.8"), tok)

    def test_different_secret_different_token(self):
        ts_k = tokens.TokenStore(root_secret=b"k" * 32, time_fn=lambda: 1000.0)
        ts_j = tokens.TokenStore(root_secret=b"j" * 32, time_fn=lambda: 1000.0)
        self.assertNotEqual(ts_j.issue("1.2.3.4"), ts_k.issue("1.2.3.4"))

    def test_bytes_peer_ip_accepted(self):
        ts = tokens.TokenStore(root_secret=b"k" * 32, time_fn=lambda: 1000.0)
        tok = ts.issue(b"\x0a\x00\x00\x01")
        self.assertIsInstance(tok, bytes)
        self.assertEqual(len(tok), 32)


class _Clock:
    """Mutable clock: advancing ``.t`` moves the store's notion of 'now'."""

    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


class TestTokenVerify(unittest.TestCase):
    def test_full_rotation_window(self):
        clk = _Clock(1000.0)
        ts = tokens.TokenStore(root_secret=b"k" * 32, time_fn=clk)
        tok = ts.issue("1.2.3.4")  # issued in epoch floor(1000/300) == 3

        # Same epoch (3): valid.
        self.assertTrue(ts.verify("1.2.3.4", tok))

        # Still epoch 3 (floor(1199/300) == 3): valid.
        clk.t = 1199.0
        self.assertTrue(ts.verify("1.2.3.4", tok))

        # Epoch 4 (floor(1300/300) == 4); tok from epoch 3, tolerance 1
        # honours epochs {4, 3}: valid.
        clk.t = 1300.0
        self.assertTrue(ts.verify("1.2.3.4", tok))

        # Epoch 5 (floor(1600/300) == 5); tolerance 1 honours {5, 4} only:
        # the epoch-3 token is no longer valid.
        clk.t = 1600.0
        self.assertFalse(ts.verify("1.2.3.4", tok))

    def test_wrong_peer_rejected(self):
        clk = _Clock(1000.0)
        ts = tokens.TokenStore(root_secret=b"k" * 32, time_fn=clk)
        tok = ts.issue("1.2.3.4")
        clk.t = 1000.0
        self.assertFalse(ts.verify("9.9.9.9", tok))

    def test_malformed_token_rejected(self):
        # verify is deliberately lenient: it returns False (never raises) on
        # bad input.
        ts = tokens.TokenStore(root_secret=b"k" * 32, time_fn=lambda: 1000.0)
        tok = ts.issue("1.2.3.4")
        # Wrong content, right length:
        self.assertFalse(ts.verify("1.2.3.4", b"not a token"))
        # Wrong length (31 bytes):
        self.assertFalse(ts.verify("1.2.3.4", b"\x00" * 31))

    def test_tolerance_zero_honours_current_epoch_only(self):
        clk = _Clock(1000.0)
        ts = tokens.TokenStore(root_secret=b"k" * 32, time_fn=clk)
        tok = ts.issue("1.2.3.4")  # epoch 3
        # tolerance_epochs=0 checks only the current epoch {3}: still valid.
        self.assertTrue(ts.verify("1.2.3.4", tok, tolerance_epochs=0))
        # One epoch later, tolerance 0 checks only {4}: invalid.
        clk.t = 1300.0
        self.assertFalse(ts.verify("1.2.3.4", tok, tolerance_epochs=0))


class TestEpochHelper(unittest.TestCase):
    def test_epoch_values(self):
        self.assertEqual(constants.TOKEN_ROTATION, 300)
        ts = tokens.TokenStore(root_secret=b"k" * 32, time_fn=lambda: 1000.0)
        # epoch = floor(now / rotation) ; [900, 1200) is epoch 3.
        self.assertEqual(ts._epoch(), 3)
        self.assertEqual(ts._epoch(900), 3)    # inclusive lower bound
        self.assertEqual(ts._epoch(899), 2)    # just below -> epoch 2
        self.assertEqual(ts._epoch(1200), 4)   # inclusive lower bound of 4


if __name__ == "__main__":
    unittest.main()
