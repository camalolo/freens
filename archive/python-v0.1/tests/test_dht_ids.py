"""Unit tests for :mod:`freens.dht.ids` — XOR distance metric and helpers.

Exercises the golden vectors documented in ``freens/dht/ids.py``:

* ``xor`` of 32-byte IDs and its length validation.
* ``distance_int`` interpreting the XOR big-endian (MSB byte is worth
  ``2**(8*31)``; LSB byte is worth ``1``).
* ``common_prefix_length`` bit-counting over the MSB-first bit stream.
* ``bucket_index`` (identical to ``common_prefix_length``; raises ``IDError``
  when the two IDs are equal).
* ``closer`` / ``sort_by_distance`` / ``k_closest`` ordering primitives.
* ``hex_id`` lowercase-hex diagnostic.

Run via ``python3 -m unittest discover`` from the project root.
"""

import unittest

from freens.dht import ids


class TestXor(unittest.TestCase):
    def test_zero_xor_zero(self):
        self.assertEqual(ids.xor(bytes(32), bytes(32)), bytes(32))

    def test_zero_xor_ff(self):
        self.assertEqual(ids.xor(bytes(32), b"\xff" * 32), b"\xff" * 32)

    def test_single_msb_byte(self):
        self.assertEqual(
            ids.xor(b"\x01" + bytes(31), bytes(32)), b"\x01" + bytes(31)
        )

    def test_self_inverse(self):
        self.assertEqual(ids.xor(b"\xff" * 32, b"\xff" * 32), bytes(32))

    def test_length_mismatch_raises_iderror(self):
        # IDError is a ValueError subclass; either is acceptable, but the
        # canonical type is ids.IDError.
        with self.assertRaises(ids.IDError):
            ids.xor(bytes(31), bytes(32))


class TestDistance(unittest.TestCase):
    def test_zero_distance(self):
        self.assertEqual(ids.distance_int(bytes(32), bytes(32)), 0)

    def test_msb_position(self):
        # 0x01 in the MOST-significant byte is worth 2**(8*31) big-endian,
        # NOT 1.  (1 << (8*31) == 2**248.)
        self.assertEqual(
            ids.distance_int(bytes(32), b"\x01" + bytes(31)), 2 ** (8 * 31)
        )

    def test_lsb_position(self):
        # 0x01 in the LEAST-significant byte is worth 1.
        self.assertEqual(ids.distance_int(bytes(32), bytes(31) + b"\x01"), 1)


class TestCommonPrefix(unittest.TestCase):
    def test_identical(self):
        self.assertEqual(ids.common_prefix_length(bytes(32), bytes(32)), 256)

    def test_differ_at_msb(self):
        # 0x80 vs 0x00 differ at bit 0 -> 0 shared leading bits.
        self.assertEqual(
            ids.common_prefix_length(b"\x80" + bytes(31), bytes(32)), 0
        )

    def test_share_one_bit(self):
        # 0x40 = 0b01000000 shares bit 0 (0) and differs at bit 1 -> 1.
        self.assertEqual(
            ids.common_prefix_length(b"\x40" + bytes(31), bytes(32)), 1
        )

    def test_share_seven_bits(self):
        # 0x01 = 0b00000001 shares bits 0-6 and differs at bit 7 -> 7.
        self.assertEqual(
            ids.common_prefix_length(b"\x01" + bytes(31), bytes(32)), 7
        )

    def test_differ_in_lsb(self):
        # Differ only at the final bit of the 256-bit stream -> 255 shared.
        self.assertEqual(
            ids.common_prefix_length(bytes(31) + b"\x01", bytes(32)), 255
        )


class TestBucketIndex(unittest.TestCase):
    def test_msb_bucket(self):
        self.assertEqual(ids.bucket_index(bytes(32), b"\x80" + bytes(31)), 0)

    def test_one_shared_bit(self):
        self.assertEqual(ids.bucket_index(bytes(32), b"\x40" + bytes(31)), 1)

    def test_lsb_bucket(self):
        self.assertEqual(ids.bucket_index(bytes(32), bytes(31) + b"\x01"), 255)

    def test_self_routes_to_error(self):
        # An ID never routes to itself: common-prefix-length 256 is not a
        # valid bucket index.
        with self.assertRaises(ids.IDError):
            ids.bucket_index(bytes(32), bytes(32))


class TestCloser(unittest.TestCase):
    def test_a_is_target(self):
        # a == target -> distance 0 -> a is closer -> -1.
        self.assertEqual(
            ids.closer(bytes(32), bytes(32), b"\x01" + bytes(31)), -1
        )

    def test_b_is_target(self):
        # b == target -> b is closer -> +1.
        self.assertEqual(
            ids.closer(bytes(32), b"\x01" + bytes(31), bytes(32)), 1
        )

    def test_tiebreak_by_value(self):
        # distances 1 and 2 (LSB position) -> 1 < 2 -> a closer -> -1.
        self.assertEqual(
            ids.closer(bytes(32), bytes(31) + b"\x01", bytes(31) + b"\x02"), -1
        )


class TestSortByDistance(unittest.TestCase):
    def test_sort_ascending(self):
        target = bytes(32)
        ids_list = [b"\xff" * 32, b"\x01" + bytes(31), bytes(32)]
        ordered = ids.sort_by_distance(target, ids_list)
        # Distances: 2**256-1, 2**248, 0  -> ascending order below.
        self.assertEqual(ordered, [bytes(32), b"\x01" + bytes(31), b"\xff" * 32])

    def test_k_closest(self):
        target = bytes(32)
        ids_list = [b"\xff" * 32, b"\x01" + bytes(31), bytes(32)]
        k = ids.k_closest(target, ids_list, k=2)
        self.assertEqual(len(k), 2)
        self.assertEqual(k[0], bytes(32))  # the closest is target itself

    def test_does_not_mutate_input(self):
        target = bytes(32)
        original = [b"\xff" * 32, bytes(32)]
        ids.sort_by_distance(target, original)
        self.assertEqual(original, [b"\xff" * 32, bytes(32)])

    def test_hex_id(self):
        self.assertEqual(ids.hex_id(bytes(32)), "00" * 32)


if __name__ == "__main__":
    unittest.main()
