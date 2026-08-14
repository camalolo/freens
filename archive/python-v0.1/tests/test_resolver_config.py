"""Tests for ``freens.resolver_config`` — §9.3 INI parsing and routing.

Exercises the on-disk resolver configuration surface:

  * :func:`parse_config` on the spec's reference example (``[listen]``,
    ``[upstream]``, ``[tld-routes]``, ``[alias-pins]`` sections) — every
    parsed field is asserted against its expected value.
  * :func:`route_for` — exact-match lookup, case-insensitive alias
    normalization (``"FOO"`` == ``"foo"``), and fallthrough to the ``"*"``
    wildcard route.
  * :func:`resolve_pin` — RFC 4648 base32 alias pins round-trip, lookup is
    case-insensitive, unpinned aliases yield ``None``; and the
    :func:`_decode_base32_tld_id` helper tolerates lowercase input and
    missing ``=`` padding.
  * Defaults — empty input and :data:`DEFAULT_CONFIG` both yield
    ``listen_udp == "127.0.0.1:53"``, no upstreams, and the ``"*"`` route
    defaulting to :data:`Route.DNS_FIRST`.
  * :class:`ConfigError` is raised on a bad route token, a non-base32 pin,
    and a pin whose decoded length is not 32 bytes; unknown INI sections
    are silently ignored (forward-compat).
"""

import base64
import unittest

from freens import resolver_config as rc
from freens.resolver_config import ConfigError, Route


# The spec's reference resolver configuration (§9.3). Used by several test
# classes below; parsed afresh in each test for isolation.
SPEC_EXAMPLE = """\
[listen]
udp = 127.0.0.1:53
tcp = 127.0.0.1:53

[upstream]
servers = 9.9.9.9, 149.112.112.112
doh = https://dns.quad9.net/dns-query

[tld-routes]
; default is dns-first
*       = dns-first
foo     = freens
laurent = freens
example = deny

[alias-pins]
; foo = <base32 tld_id>
"""


class TestParseSpecExample(unittest.TestCase):
    """``parse_config`` faithfully decodes the spec's reference INI."""

    def test_spec_example_fields(self):
        cfg = rc.parse_config(SPEC_EXAMPLE)
        # [listen]
        self.assertEqual(cfg.listen_udp, "127.0.0.1:53")
        self.assertEqual(cfg.listen_tcp, "127.0.0.1:53")
        # [upstream]: comma-separated servers + a single DoH URL.
        self.assertEqual(cfg.upstream_servers, ["9.9.9.9", "149.112.112.112"])
        self.assertEqual(cfg.upstream_doh, "https://dns.quad9.net/dns-query")
        # [tld-routes]
        self.assertEqual(cfg.tld_routes["*"], Route.DNS_FIRST)
        self.assertEqual(cfg.tld_routes["foo"], Route.FREENS)
        self.assertEqual(cfg.tld_routes["laurent"], Route.FREENS)
        self.assertEqual(cfg.tld_routes["example"], Route.DENY)
        # [alias-pins]: only a comment present -> empty dict.
        self.assertEqual(cfg.alias_pins, {})


class TestRouteFor(unittest.TestCase):
    """``route_for`` resolves an alias to a :class:`Route`."""

    def test_exact_match_and_normalization(self):
        cfg = rc.parse_config(SPEC_EXAMPLE)
        # Exact-match entries.
        self.assertEqual(rc.route_for(cfg, "foo"), Route.FREENS)
        # Alias is normalized (lowercased ASCII) before lookup, so "FOO"
        # resolves identically to "foo".
        self.assertEqual(rc.route_for(cfg, "FOO"), Route.FREENS)
        self.assertEqual(rc.route_for(cfg, "example"), Route.DENY)

    def test_wildcard_fallthrough(self):
        cfg = rc.parse_config(SPEC_EXAMPLE)
        # Aliases with no explicit entry fall through to the "*" wildcard
        # (dns-first in the spec example).
        self.assertEqual(rc.route_for(cfg, "com"), Route.DNS_FIRST)
        self.assertEqual(rc.route_for(cfg, "net"), Route.DNS_FIRST)


class TestPins(unittest.TestCase):
    """``resolve_pin`` and the base32 decode helper."""

    def test_resolve_pin_round_trip_and_normalization(self):
        tid = bytes(range(32))
        # RFC 4648 base32 of the 32-byte tld_id, WITH standard "=" padding.
        pin = base64.b32encode(tid).decode("ascii")
        text = "[alias-pins]\nfoo = " + pin + "\n"
        cfg = rc.parse_config(text)
        self.assertEqual(rc.resolve_pin(cfg, "foo"), tid)
        # Lookup is case-insensitive (alias normalized to lowercase).
        self.assertEqual(rc.resolve_pin(cfg, "FOO"), tid)
        # An unpinned alias yields None (no KeyError, no exception).
        self.assertIsNone(rc.resolve_pin(cfg, "bar"))

    def test_decode_tolerates_lowercase_and_missing_padding(self):
        tid = bytes(range(32))
        pin = base64.b32encode(tid).decode("ascii")
        # Strip the padding and lowercase the data chars; the decode helper
        # re-pads to a multiple of 8 and upper-cases first.
        low = pin.rstrip("=").lower()
        self.assertEqual(rc._decode_base32_tld_id(low), tid)


class TestDefaults(unittest.TestCase):
    """Empty input and :data:`DEFAULT_CONFIG` yield the documented defaults."""

    def test_empty_config_yields_defaults(self):
        cfg = rc.parse_config("")
        self.assertEqual(cfg.listen_udp, "127.0.0.1:53")
        self.assertEqual(cfg.listen_tcp, "127.0.0.1:53")
        self.assertIsNone(cfg.upstream_doh)
        self.assertEqual(cfg.upstream_servers, [])
        self.assertEqual(cfg.tld_routes, {"*": Route.DNS_FIRST})
        self.assertEqual(cfg.alias_pins, {})

    def test_module_level_default_config(self):
        # The "*" entry always defaults to dns-first.
        self.assertEqual(rc.DEFAULT_CONFIG.tld_routes["*"], Route.DNS_FIRST)
        self.assertEqual(rc.DEFAULT_ROUTE, Route.DNS_FIRST)


class TestErrors(unittest.TestCase):
    """``ConfigError`` is raised on malformed config; unknown sections OK."""

    def test_bad_route_token_raises(self):
        # "bogus" is not one of the Route enum tokens.
        with self.assertRaises(ConfigError):
            rc.parse_config("[tld-routes]\nfoo = bogus\n")

    def test_bad_base32_pin_raises(self):
        # "$$$" is outside the base32 alphabet.
        with self.assertRaises(ConfigError):
            rc.parse_config("[alias-pins]\nfoo = $$$\n")

    def test_wrong_length_pin_raises(self):
        # "AA==" decodes to a single byte, not the required 32.
        with self.assertRaises(ConfigError):
            rc.parse_config("[alias-pins]\nfoo = AA==\n")

    def test_unknown_section_is_ignored(self):
        # Forward-compat: unknown sections produce no error and leave the
        # default "*" route intact.
        cfg = rc.parse_config("[unknown-section]\nkey = value\n")
        self.assertEqual(cfg.tld_routes["*"], Route.DNS_FIRST)


if __name__ == "__main__":
    unittest.main()
