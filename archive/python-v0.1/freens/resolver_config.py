"""freens resolver configuration — §9.3 INI parsing and per-alias routing.

Implements ``specifications.md`` §9.3 ("Local resolver", lines 756-795):
the on-disk INI config that drives the local resolver's listening
sockets, its upstream conventional-DNS forwarders, the per-alias routing
policy (``[tld-routes]``), and the optional vendor/user alias pins
(``[alias-pins]``).

Route semantics (spec lines 781-789):

- ``dns-first`` (DEFAULT for ``*``): ask conventional DNS first; on
  NXDOMAIN, fall through to freens.
- ``freens-first``: ask freens first; on a miss, fall through to DNS.
- ``freens``: freens only.
- ``dns``: conventional DNS only.
- ``deny``: refuse the query (DNS REFUSED).

``[alias-pins]`` let a distributor ship a pinned alias -> TLD ID mapping
(base32 / RFC 4648, 32 raw bytes) that bypasses the DHT claim race.
Pinning is local policy and never a protocol assertion (spec lines
787-789).

This module is stdlib-only (``configparser``, ``base64``, ``binascii``)
plus relative imports of :mod:`freens.constants` and
:mod:`freens.naming`.  It performs no I/O and starts no resolver.
"""

from __future__ import annotations

import base64
import binascii
import configparser
import io
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from . import constants, naming

__all__ = [
    "ConfigError",
    "Route",
    "DEFAULT_ROUTE",
    "Config",
    "DEFAULT_CONFIG",
    "parse_config",
    "route_for",
    "resolve_pin",
]


class ConfigError(ValueError):
    """Raised on malformed resolver config (bad route name, bad base32 pin,
    wrong pin decoded length, etc.).

    Subclasses ``ValueError`` so callers may catch either.  Note that
    :class:`freens.naming.NamingError` (also a ``ValueError`` subclass)
    is intentionally allowed to propagate *unchanged* from
    :func:`parse_config` when an alias fails validation — per the §9.3
    contract, alias errors surface as ``NamingError`` rather than
    ``ConfigError``.
    """


class Route(Enum):
    """Per-alias routing policy (spec §9.3 lines 770-786).

    Each member's ``value`` is the lowercase token used in the
    ``[tld-routes]`` section of the INI file.
    """

    DNS = "dns"
    FREENS = "freens"
    FREENS_FIRST = "freens-first"
    DNS_FIRST = "dns-first"
    DENY = "deny"


DEFAULT_ROUTE = Route.DNS_FIRST
"""Default route for any alias lacking an explicit entry or a ``*`` match
(spec line 772: the default for ``*`` is ``dns-first``)."""


@dataclass
class Config:
    """Parsed resolver configuration.

    All mutable fields use ``field(default_factory=...)`` so each
    instance owns its own list/dict (no shared mutable class state).
    """

    listen_udp: str = "127.0.0.1:53"
    listen_tcp: str = "127.0.0.1:53"
    upstream_servers: list = field(default_factory=list)
    upstream_doh: Optional[str] = None
    tld_routes: dict = field(default_factory=lambda: {"*": DEFAULT_ROUTE})
    alias_pins: dict = field(default_factory=dict)


DEFAULT_CONFIG = Config()
"""Module-level default :class:`Config`.  Treat as read-only — mutating
its list/dict fields affects every holder of this shared instance."""


# Case-insensitive route lookup table: lowercase token -> Route member.
_ROUTE_BY_TOKEN = {r.value: r for r in Route}


def _decode_base32_tld_id(s: str) -> bytes:
    """Decode an RFC 4648 base32 string to exactly 32 bytes.

    Whitespace is stripped and the input is upper-cased first (so
    lowercase base32 is accepted too); ``=`` padding is then appended to
    a multiple of 8 before :func:`base64.b32decode` is called.  Raise
    :class:`ConfigError` on:

    - :class:`binascii.Error` (non-base32 alphabet, bad padding, ...), or
    - a decoded length other than ``constants.SHA256_LEN`` (32 bytes).
    """
    if not isinstance(s, str):
        raise ConfigError(f"base32 pin must be a str, got {type(s).__name__}")
    s2 = s.strip().upper()
    pad = (-len(s2)) % 8
    s2 += "=" * pad
    try:
        decoded = base64.b32decode(s2)
    except binascii.Error as exc:
        raise ConfigError(f"invalid base32 tld_id pin {s!r}: {exc}") from exc
    if len(decoded) != constants.SHA256_LEN:
        raise ConfigError(
            f"decoded tld_id pin is {len(decoded)} bytes, expected "
            f"{constants.SHA256_LEN}: {s!r}"
        )
    return decoded


def parse_config(text: str) -> Config:
    """Parse a §9.3 INI config string into a :class:`Config`.

    Sections handled: ``[listen]``, ``[upstream]``, ``[tld-routes]``,
    ``[alias-pins]``.  Unknown sections are silently ignored
    (forward-compat).  Missing sections yield the corresponding field
    defaults.

    Details:

    - ``[listen]``: keys ``udp`` and ``tcp`` (both optional; default
      ``127.0.0.1:53``).  Values are stored verbatim (no host/port split).
    - ``[upstream]``: ``servers`` is split on commas *and* generic
      whitespace via ``value.replace(',', ' ').split()`` (drops empties
      and tolerates either separator — documented choice over a regex);
      ``doh`` is a single URL string, optional.
    - ``[tld-routes]``: ``alias = route-name``.  Route tokens are matched
      case-insensitively to :class:`Route` values; an unknown token
      raises :class:`ConfigError`.  Every alias is normalized via
      :func:`freens.naming.validate_alias` (a :class:`NamingError`, a
      ``ValueError`` subclass, propagates unchanged).  ``*`` is accepted
      verbatim as the wildcard key and skips alias validation.  The
      resulting dict always contains a ``"*"`` entry (defaulting to
      :data:`DEFAULT_ROUTE` if the config omits it).
    - ``[alias-pins]``: ``alias = base32(tld_id)``.  Each value is
      decoded via :func:`_decode_base32_tld_id` (must yield 32 bytes);
      the alias is normalized via :func:`freens.naming.validate_alias`.

    configparser lowercases option keys by default
    (``optionxform = str.lower``); freens aliases are ASCII-lowercase
    anyway, so this is harmless, and every non-``*`` key is still passed
    through :func:`freens.naming.validate_alias` for full LDH validation.

    Empty / whitespace-only ``text`` returns :func:`Config` with defaults.

    Raises :class:`ConfigError` on: an unknown route value, a bad base32
    pin, or a pin whose decoded length is not 32 bytes.  Raises
    :class:`freens.naming.NamingError` (a ``ValueError``) on an invalid
    alias in ``[tld-routes]`` or ``[alias-pins]``.
    """
    if not isinstance(text, str):
        raise TypeError(f"config text must be str, got {type(text).__name__}")
    if not text.strip():
        return Config()

    parser = configparser.ConfigParser()
    parser.read_file(io.StringIO(text))

    cfg = Config()

    # ----- [listen] -------------------------------------------------------
    if parser.has_section("listen"):
        if parser.has_option("listen", "udp"):
            cfg.listen_udp = parser.get("listen", "udp").strip()
        if parser.has_option("listen", "tcp"):
            cfg.listen_tcp = parser.get("listen", "tcp").strip()

    # ----- [upstream] -----------------------------------------------------
    if parser.has_section("upstream"):
        if parser.has_option("upstream", "servers"):
            raw = parser.get("upstream", "servers")
            # Comma- and/or whitespace-separated; drop empties.
            cfg.upstream_servers = raw.replace(",", " ").split()
        if parser.has_option("upstream", "doh"):
            doh = parser.get("upstream", "doh").strip()
            cfg.upstream_doh = doh or None

    # ----- [tld-routes] ---------------------------------------------------
    cfg.tld_routes = {}
    if parser.has_section("tld-routes"):
        for key, value in parser.items("tld-routes"):
            if key == "*":
                alias = "*"
            else:
                # NamingError (a ValueError subclass) propagates unchanged.
                alias = naming.validate_alias(key)
            token = value.strip().lower()
            route = _ROUTE_BY_TOKEN.get(token)
            if route is None:
                raise ConfigError(
                    f"unknown route {value!r} for alias {key!r} in "
                    f"[tld-routes] (expected one of: "
                    f"{', '.join(sorted(_ROUTE_BY_TOKEN))})"
                )
            cfg.tld_routes[alias] = route
    if "*" not in cfg.tld_routes:
        cfg.tld_routes["*"] = DEFAULT_ROUTE

    # ----- [alias-pins] ---------------------------------------------------
    if parser.has_section("alias-pins"):
        for key, value in parser.items("alias-pins"):
            # No '*' wildcard for pins; every alias must validate.
            alias = naming.validate_alias(key)
            cfg.alias_pins[alias] = _decode_base32_tld_id(value)

    return cfg


def route_for(cfg: Config, alias: str) -> Route:
    """Return the :class:`Route` for ``alias`` under ``cfg``.

    The alias is normalized via :func:`freens.naming.validate_alias`
    (an invalid alias propagates :class:`freens.naming.NamingError`).
    Lookup is exact-match first, then the ``"*"`` wildcard, then
    :data:`DEFAULT_ROUTE`.  Never raises on a valid alias.
    """
    alias_n = naming.validate_alias(alias)
    if alias_n in cfg.tld_routes:
        return cfg.tld_routes[alias_n]
    return cfg.tld_routes.get("*", DEFAULT_ROUTE)


def resolve_pin(cfg: Config, alias: str) -> Optional[bytes]:
    """Return the pinned 32-byte tld_id for ``alias`` if any, else ``None``.

    The alias is normalized via :func:`freens.naming.validate_alias`
    (an invalid alias propagates :class:`freens.naming.NamingError`).
    Never raises on a valid alias.
    """
    alias_n = naming.validate_alias(alias)
    return cfg.alias_pins.get(alias_n)
