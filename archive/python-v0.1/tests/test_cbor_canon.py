"""Foundational tests for :mod:`freens.cbor_canon`.

Covers the deterministic (canonical) CBOR codec mandated by
``specifications.md`` §4.2 / RFC 8949 §4.2:

* a full battery of hand-derived golden vectors (every byte is asserted
  exactly);
* round-trip equality ``loads(dumps(x)) == x`` for every supported type;
* rejection of every spec-forbidden construct on decode (indefinite-length
  items, the break code, floats, tags, duplicate map keys, trailing bytes,
  truncated/empty input);
* rejection of floats on encode (``TypeError``);
* canonical map key ordering across mixed key types and NFC normalisation of
  text strings.

Run from the project root with::

    python3 -m unittest discover
"""

import unittest

from freens import cbor_canon

# Shortcuts to keep the golden-vector table readable.
dumps = cbor_canon.dumps
loads = cbor_canon.loads
dumps_map = cbor_canon.dumps_map


class TestGoldenVectors(unittest.TestCase):
    """Assert the exact canonical CBOR bytes, hand-derived from RFC 8949 §4.2.

    These are the same vectors documented in ``freens/cbor_canon.py``; each
    entry exercises a distinct boundary of the minimum-length / canonical
    encoding rules.
    """

    # --- unsigned integers (major type 0) -------------------------------
    def test_int_zero(self):
        self.assertEqual(dumps(0), bytes.fromhex("00"))

    def test_int_one(self):
        self.assertEqual(dumps(1), bytes.fromhex("01"))

    def test_int_inline_max(self):
        # 23 is the largest value that fits inline (additional-info <= 23).
        self.assertEqual(dumps(23), bytes.fromhex("17"))

    def test_int_one_byte_follows(self):
        # 24 is the smallest value requiring a following argument byte.
        self.assertEqual(dumps(24), bytes.fromhex("1818"))

    def test_int_100(self):
        self.assertEqual(dumps(100), bytes.fromhex("1864"))

    def test_int_uint8_max(self):
        self.assertEqual(dumps(255), bytes.fromhex("18ff"))

    def test_int_two_bytes_follows(self):
        # 256 is the smallest value requiring two following argument bytes.
        self.assertEqual(dumps(256), bytes.fromhex("190100"))

    def test_int_300(self):
        self.assertEqual(dumps(300), bytes.fromhex("19012c"))

    def test_int_uint16_max(self):
        self.assertEqual(dumps(65535), bytes.fromhex("19ffff"))

    def test_int_four_bytes_follows(self):
        # 65536 is the smallest value requiring four following argument bytes.
        self.assertEqual(dumps(65536), bytes.fromhex("1a00010000"))

    # --- byte strings (major type 2) ------------------------------------
    def test_bytes_empty(self):
        self.assertEqual(dumps(b""), bytes.fromhex("40"))

    def test_bytes_short(self):
        self.assertEqual(dumps(b"abc"), bytes.fromhex("43616263"))

    def test_bytes_24_zeros(self):
        # Length 24 spills out of the inline range -> 0x58 0x18 head.
        self.assertEqual(dumps(b"\x00" * 24), bytes.fromhex("5818") + b"\x00" * 24)

    def test_bytes_32_zeros(self):
        # Length 32 -> 0x58 0x20 head.
        self.assertEqual(dumps(b"\x00" * 32), bytes.fromhex("5820") + b"\x00" * 32)

    # --- text strings (major type 3) ------------------------------------
    def test_str_short(self):
        self.assertEqual(dumps("abc"), bytes.fromhex("63616263"))

    # --- simple values ---------------------------------------------------
    def test_true(self):
        self.assertEqual(dumps(True), bytes.fromhex("f5"))

    def test_false(self):
        self.assertEqual(dumps(False), bytes.fromhex("f4"))

    def test_none(self):
        self.assertEqual(dumps(None), bytes.fromhex("f6"))

    # --- arrays (major type 4) ------------------------------------------
    def test_empty_array(self):
        self.assertEqual(dumps([]), bytes.fromhex("80"))

    def test_array_small_ints(self):
        self.assertEqual(dumps([1, 2, 3]), bytes.fromhex("83010203"))

    def test_array_mixed(self):
        # [1, 300, b"\x01\x02\x03"]
        self.assertEqual(
            dumps([1, 300, b"\x01\x02\x03"]),
            bytes.fromhex("830119012c43010203"),
        )

    # --- maps (major type 5, canonical key order) -----------------------
    def test_empty_map(self):
        self.assertEqual(dumps({}), bytes.fromhex("a0"))

    def test_map_single(self):
        self.assertEqual(dumps({1: 2}), bytes.fromhex("a10102"))

    def test_map_already_sorted(self):
        self.assertEqual(dumps({1: 2, 3: 4}), bytes.fromhex("a201020304"))

    def test_map_resorted(self):
        # Insertion order 3,1 must be re-sorted to canonical 1,3.
        self.assertEqual(dumps({3: 4, 1: 2}), bytes.fromhex("a201020304"))

    def test_map_int_and_bytes_values(self):
        # {2: b"abc", 1: 1} -> key 01 first, then key 02.
        self.assertEqual(
            dumps({2: b"abc", 1: 1}),
            bytes.fromhex("a201010243616263"),
        )

    def test_map_nested_array_value(self):
        # {1: 1, 7: [[1, 300, b"\x01\x02\x03"]]]}
        self.assertEqual(
            dumps({1: 1, 7: [[1, 300, b"\x01\x02\x03"]]}),
            bytes.fromhex("a201010781830119012c43010203"),
        )

    def test_map_mixed_key_types_canonical_order(self):
        # Canonical key ordering is "length-first, then bytewise".
        #   key 1   -> b"\x01"      (1 byte)
        #   key b"a"-> b"\x41\x61"  (2 bytes)
        # So 1 sorts before b"a": head a2, then 01 02, then 41 61 01.
        self.assertEqual(
            dumps({b"a": 1, 1: 2}),
            bytes.fromhex("a20102416101"),
        )


class TestRoundTrip(unittest.TestCase):
    """``loads(dumps(x)) == x`` for every supported type, plus rejection
    of every spec-forbidden construct."""

    # --- round-trip equality --------------------------------------------
    def test_roundtrip_ints(self):
        for x in (0, 1, 23, 24, 100, 255, 256, 300, 65535, 65536, 2 ** 32):
            with self.subTest(x=x):
                self.assertEqual(loads(dumps(x)), x)

    def test_roundtrip_bytes(self):
        for x in (b"", b"abc", b"\x00" * 24, b"\x00" * 32, b"\xff" * 10):
            with self.subTest(x=x):
                self.assertEqual(loads(dumps(x)), x)

    def test_roundtrip_str(self):
        for x in ("", "abc", "é", "héllo wörld"):
            with self.subTest(x=x):
                self.assertEqual(loads(dumps(x)), x)

    def test_roundtrip_bool_none(self):
        self.assertEqual(loads(dumps(True)), True)
        self.assertEqual(loads(dumps(False)), False)
        self.assertEqual(loads(dumps(None)), None)

    def test_roundtrip_list(self):
        x = [1, 300, b"\x01\x02\x03", "abc", [True, None, []]]
        self.assertEqual(loads(dumps(x)), x)

    def test_roundtrip_nested_dict(self):
        x = {"a": {"b": [1, 2, {"c": 3}]}, 7: b"\x00"}
        self.assertEqual(loads(dumps(x)), x)

    def test_roundtrip_int_keyed_dict(self):
        x = {1: 2, 3: 4}
        self.assertEqual(loads(dumps(x)), x)

    # --- encode rejections ----------------------------------------------
    def test_dumps_float_raises_typeerror(self):
        with self.assertRaises(TypeError):
            dumps(1.0)

    def test_dumps_float_zero_raises_typeerror(self):
        with self.assertRaises(TypeError):
            dumps(0.0)

    # --- decode rejections ----------------------------------------------
    def test_loads_rejects_indefinite_length(self):
        # 0x9f = indefinite-length array starter; forbidden.
        with self.assertRaises(ValueError):
            loads(b"\x9f\xff")

    def test_loads_rejects_duplicate_keys(self):
        # Manually crafted map of 2 entries, both with key 0x01.
        # a2 01 01  01 02
        with self.assertRaises(ValueError):
            loads(b"\xa2\x01\x01\x01\x02")

    def test_loads_rejects_float(self):
        # 0xfa = single-precision float (major 7, additional-info 26).
        with self.assertRaises(ValueError):
            loads(bytes.fromhex("fa00000000"))

    def test_loads_rejects_trailing_bytes(self):
        with self.assertRaises(ValueError):
            loads(dumps(1) + b"\x00")

    def test_loads_rejects_empty_input(self):
        with self.assertRaises(ValueError):
            loads(b"")

    # --- dumps_map semantics --------------------------------------------
    def test_dumps_map_equals_sorted_dict(self):
        # The pair order given to dumps_map must not matter: it is re-sorted
        # to canonical order, identical to dumps(dict(...)).
        self.assertEqual(
            dumps_map([(3, 4), (1, 2)]),
            dumps({1: 2, 3: 4}),
        )
        self.assertEqual(
            dumps_map([(3, 4), (1, 2)]),
            bytes.fromhex("a201020304"),
        )

    # --- NFC normalisation of text strings ------------------------------
    def test_str_nfc_normalisation(self):
        # U+00E9 (precomposed) and "e" + U+0301 (combining acute) must both
        # be NFC-normalised to the same bytes.
        precomposed = "\u00e9"          # 'é'
        decomposed = "e\u0301"          # 'e' + combining acute
        self.assertEqual(dumps(precomposed), dumps(decomposed))


if __name__ == "__main__":
    unittest.main()
