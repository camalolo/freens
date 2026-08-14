"""Foundational tests for :mod:`freens.naming`.

Covers ``specifications.md`` §3.2 (alias/label validation) and §3.3 (name
decomposition, the wire-name format, and DHT storage-key derivation):

* :class:`TestAliasValidation` — the LDH alias/label rules (length, charset,
  leading/trailing hyphen, all-numeric aliases forbidden, numeric labels
  allowed).
* :class:`TestDecompose` — splitting dotted display names, label-count limits,
  normalization, and the various malformed-name rejections.
* :class:`TestWireName` — the ``0x01 || len || label ... 0x00 || tld_id`` wire
  layout, round-trips, the spec worked example, and malformed-input handling.
* :class:`TestDhtKeys` — the three DHT key derivations (K_tld, K_name, K_claim)
  cross-checked against raw SHA-256 computations.

Run from the project root with::

    python3 -m unittest discover
"""

import hashlib
import unittest

from freens import naming
from freens.naming import (
    NamingError,
    decode_wire_name,
    decompose_name,
    dht_key_claim,
    dht_key_name,
    dht_key_tld,
    encode_wire_name,
    is_valid_alias,
    validate_alias,
    validate_label,
)


class TestAliasValidation(unittest.TestCase):
    """§3.2 alias and label validation (LDH rule, length, all-numeric)."""

    # --- validate_alias: happy paths ------------------------------------
    def test_validate_alias_lowercases(self):
        self.assertEqual(validate_alias("Foo"), "foo")

    def test_validate_alias_single_char(self):
        self.assertEqual(validate_alias("a"), "a")

    def test_validate_alias_hyphen(self):
        self.assertEqual(validate_alias("a-b"), "a-b")

    def test_validate_alias_alphanumeric(self):
        self.assertEqual(validate_alias("a1"), "a1")

    # --- validate_alias: rejections -------------------------------------
    def test_validate_alias_rejects_invalid(self):
        bad = [
            "-a",       # leading hyphen
            "a-",       # trailing hyphen
            "",         # empty
            "a" * 64,   # too long (64 > 63)
            "a_b",      # underscore outside LDH
            "abé",      # non-ASCII
            "a.b",      # dot not allowed in an alias
            ".a",       # leading dot
            "a.",       # trailing dot
            "1" * 63,   # all-numeric (length ok, but digits only)
        ]
        for s in bad:
            with self.subTest(alias=s):
                with self.assertRaises(NamingError):
                    validate_alias(s)

    # --- is_valid_alias --------------------------------------------------
    def test_is_valid_alias_true(self):
        self.assertIs(is_valid_alias("foo"), True)
        self.assertIs(is_valid_alias("foo-bar"), True)

    def test_is_valid_alias_false_all_numeric(self):
        self.assertIs(is_valid_alias("123"), False)

    def test_is_valid_alias_false_bad_char(self):
        self.assertIs(is_valid_alias("foo_bar"), False)

    # --- validate_label --------------------------------------------------
    def test_validate_label_lowercases(self):
        self.assertEqual(validate_label("WWW"), "www")

    def test_validate_label_numeric_allowed(self):
        # Numeric labels are permitted (only aliases forbid all-numeric).
        self.assertEqual(validate_label("123"), "123")

    def test_validate_label_rejects_invalid(self):
        bad = ["-x", "x-", "", "x" * 64]
        for s in bad:
            with self.subTest(label=s):
                with self.assertRaises(NamingError):
                    validate_label(s)


class TestDecompose(unittest.TestCase):
    """§3.3 name decomposition: (displayed_labels, alias)."""

    def test_decompose_alias_only(self):
        self.assertEqual(decompose_name("foo"), ([], "foo"))

    def test_decompose_one_label(self):
        self.assertEqual(decompose_name("alice.foo"), (["alice"], "foo"))

    def test_decompose_two_labels(self):
        self.assertEqual(decompose_name("www.alice.foo"), (["www", "alice"], "foo"))

    def test_decompose_trailing_dot(self):
        # A single trailing root dot is stripped.
        self.assertEqual(decompose_name("foo."), ([], "foo"))

    def test_decompose_normalizes_labels(self):
        self.assertEqual(decompose_name("WWW.Alice.FOO"), (["www", "alice"], "foo"))

    def test_decompose_eight_labels_ok(self):
        # MAX_LABELS == 8: eight labels under the alias is the legal maximum.
        name = "a.b.c.d.e.f.g.h.foo"
        labels, alias = decompose_name(name)
        self.assertEqual(labels, ["a", "b", "c", "d", "e", "f", "g", "h"])
        self.assertEqual(alias, "foo")

    # --- rejections ------------------------------------------------------
    def test_decompose_rejects_leading_dot(self):
        with self.assertRaises(NamingError):
            decompose_name(".foo")

    def test_decompose_rejects_double_dot(self):
        with self.assertRaises(NamingError):
            decompose_name("a..b.foo")

    def test_decompose_rejects_trailing_double_dot(self):
        with self.assertRaises(NamingError):
            decompose_name("foo..")

    def test_decompose_rejects_too_many_labels(self):
        # Nine labels under the alias exceeds MAX_LABELS (8).
        name = "a.b.c.d.e.f.g.h.i.foo"
        with self.assertRaises(NamingError):
            decompose_name(name)


class TestWireName(unittest.TestCase):
    """§3.3 wire-name format: ``0x01 || len || label ... 0x00 || tld_id``."""

    def setUp(self):
        # A fixed, non-trivial 32-byte TLD id (all distinct byte values).
        self.tld_id = bytes(range(32))

    # --- encoding --------------------------------------------------------
    def test_encode_two_labels(self):
        wire = encode_wire_name(["www", "alice"], "foo", self.tld_id)
        expected = (
            bytes([0x01, 5]) + b"alice"
            + bytes([0x01, 3]) + b"www"
            + bytes([0x00])
            + self.tld_id
        )
        self.assertEqual(wire, expected)

    def test_encode_empty_labels(self):
        wire = encode_wire_name([], "foo", self.tld_id)
        self.assertEqual(wire, bytes([0x00]) + self.tld_id)

    def test_encode_single_label(self):
        wire = encode_wire_name(["alice"], "foo", self.tld_id)
        self.assertEqual(
            wire,
            bytes([0x01, 5]) + b"alice" + bytes([0x00]) + self.tld_id,
        )

    def test_encode_matches_spec_worked_example_prefix(self):
        # spec line 192: wire_name("www.alice.foo") starts with
        #   0x01 05 "alice" 0x01 03 "www" 0x00  then the 32-byte tld_id.
        wire = encode_wire_name(["www", "alice"], "foo", self.tld_id)
        prefix = (
            bytes([0x01, 5]) + b"alice"
            + bytes([0x01, 3]) + b"www"
            + bytes([0x00])
        )
        self.assertTrue(wire.startswith(prefix))

    # --- round-trips -----------------------------------------------------
    def test_decode_two_labels(self):
        wire = encode_wire_name(["www", "alice"], "foo", self.tld_id)
        self.assertEqual(decode_wire_name(wire), (["www", "alice"], self.tld_id))

    def test_decode_empty_labels(self):
        wire = encode_wire_name([], "foo", self.tld_id)
        self.assertEqual(decode_wire_name(wire), ([], self.tld_id))

    def test_decode_single_label(self):
        wire = encode_wire_name(["alice"], "foo", self.tld_id)
        self.assertEqual(decode_wire_name(wire), (["alice"], self.tld_id))

    # --- malformed decode ------------------------------------------------
    def test_decode_rejects_truncated(self):
        # Just a terminator and no tld_id.
        with self.assertRaises(ValueError):
            decode_wire_name(bytes([0x00]))

    def test_decode_rejects_bad_marker(self):
        with self.assertRaises(ValueError):
            decode_wire_name(bytes([0x02]) + bytes(32))

    def test_decode_rejects_missing_terminator(self):
        # A label with no following 0x00 terminator.
        with self.assertRaises(ValueError):
            decode_wire_name(bytes([0x01, 5]) + b"alice")

    def test_decode_rejects_tld_id_wrong_length(self):
        # Terminator present but only 31 trailing bytes.
        with self.assertRaises(ValueError):
            decode_wire_name(bytes([0x00]) + bytes(31))

    # --- encode rejections ----------------------------------------------
    def test_encode_rejects_tld_id_wrong_length(self):
        with self.assertRaises(ValueError):
            encode_wire_name([], "foo", bytes(31))

    def test_encode_rejects_invalid_alias(self):
        with self.assertRaises(NamingError):
            encode_wire_name([], "123", self.tld_id)

    def test_encode_rejects_too_many_labels(self):
        # Nine labels exceeds MAX_LABELS (8).
        nine = ["a", "b", "c", "d", "e", "f", "g", "h", "i"]
        with self.assertRaises(NamingError):
            encode_wire_name(nine, "foo", self.tld_id)


class TestDhtKeys(unittest.TestCase):
    """§3.3 DHT storage-key derivation: K_tld, K_name, K_claim."""

    def setUp(self):
        self.tld_id = bytes(range(32))
        self.wire = encode_wire_name([], "foo", self.tld_id)

    def test_dht_key_tld_is_identity(self):
        self.assertEqual(dht_key_tld(self.tld_id), self.tld_id)

    def test_dht_key_name_is_sha256_prefix02(self):
        expected = hashlib.sha256(bytes([0x02]) + self.wire).digest()
        self.assertEqual(dht_key_name(self.wire), expected)

    def test_dht_key_claim_is_sha256_prefix03(self):
        expected = hashlib.sha256(bytes([0x03]) + b"claim:foo").digest()
        self.assertEqual(dht_key_claim("foo"), expected)

    def test_dht_key_claim_case_insensitive(self):
        self.assertEqual(dht_key_claim("FOO"), dht_key_claim("foo"))

    def test_dht_key_tld_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            dht_key_tld(bytes(31))

    def test_dht_key_claim_rejects_invalid_alias(self):
        with self.assertRaises(NamingError):
            dht_key_claim("123")


if __name__ == "__main__":
    unittest.main()
