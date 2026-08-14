"""Rotating HMAC-SHA256 write-token issuer/verifier.

Implements the spoofed-STORE defense described in ``specifications.md``
§6.3 ("Write tokens", spec lines 453-458): before a peer may ``put`` a
record onto this node it must first obtain a write token via a prior
``get``/``ping`` exchange. A token is::

    token = HMAC-SHA256(rotating_secret, peer_ip)

where ``rotating_secret`` is derived per-epoch from a long-lived root
secret and the current epoch number. Epochs advance every
``TOKEN_ROTATION`` seconds (Appendix A, spec line 976 — 5 minutes /
300 s). A token remains valid for the *current* and the *previous*
epoch, so that a token minted moments before an epoch boundary is still
honoured after the rotation.

Design notes
------------
* Pure stdlib: ``hmac``, ``hashlib``, ``secrets``, ``time``.
* The per-epoch secret is ``HMAC-SHA256(root_secret, str(epoch))``; the
  root secret never appears directly in any issued token, so leaking a
  single epoch's tokens does not compromise other epochs.
* Verification uses ``hmac.compare_digest`` for constant-time comparison
  and iterates over the tolerated epoch window, short-circuiting on the
  first match.
* ``verify`` is deliberately lenient (returns ``False`` on any
  malformed input), while ``issue`` is strict (raises ``ValueError`` on
  a malformed ``peer_ip``), matching how the two are used on the wire:
  verification handles untrusted data, issuance handles local data.

Deterministic test helper
-------------------------
A test can construct::

    ts = TokenStore(root_secret=b"k" * 32, time_fn=lambda: 1000)

and know that ``ts._epoch() == floor(1000 / 300) == 3``. Advancing the
injected clock to ``1300`` moves to epoch 4 while leaving epoch 3
verifiable (previous), and to ``1600`` (epoch 5) which is no longer
verifiable with the default ``tolerance_epochs=1``.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from .. import constants


class TokenStore:
    """Rotating HMAC-SHA256 write-token issuer/verifier.

    A token authorizes one peer (identified by its IP bytes/string) to
    issue a ``put`` to this node. Tokens rotate every
    ``TOKEN_ROTATION`` seconds; a token is accepted if it matches
    either the current or the previous epoch's secret.

    Golden / sanity vectors (asserted by construction, see comments
    inline):

    * Two ``TokenStore`` instances sharing the same ``root_secret``
      issue byte-identical tokens for the same peer at the same time.
    * A token issued at time ``T`` verifies at ``T``, at
      ``T + TOKEN_ROTATION - 1`` (same or previous epoch), and at
      ``T + TOKEN_ROTATION`` (previous epoch, still valid), but **not**
      at ``T + 2 * TOKEN_ROTATION`` with ``tolerance_epochs=1``.
    * ``verify`` rejects a token minted for a different ``peer_ip``.
    * ``verify`` rejects a token minted under a different
      ``root_secret``.
    * Injecting ``time_fn=lambda: fixed_T`` makes behaviour fully
      deterministic.
    * Every issued token is exactly 32 bytes (a SHA-256 digest).
    """

    def __init__(
        self,
        rotation_seconds: int = constants.TOKEN_ROTATION,
        root_secret: bytes | None = None,
        time_fn=time.time,
    ):
        # root_secret: 32 random bytes used to derive per-epoch secrets.
        #              If None, a fresh 32-byte secret is generated.
        # time_fn:     injectable clock for testing (defaults to time.time).
        if rotation_seconds <= 0:
            raise ValueError("rotation must be > 0")
        self.rotation_seconds = rotation_seconds
        self.root_secret = (
            root_secret if root_secret is not None else secrets.token_bytes(32)
        )
        if len(self.root_secret) < 16:
            raise ValueError("root_secret too short (min 16 bytes)")
        self._time = time_fn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _epoch(self, now: float | None = None) -> int:
        """The current rotation epoch number = ``floor(now / rotation_seconds)``.

        For the default ``TOKEN_ROTATION = 300`` and ``now = 1000`` this
        is ``floor(1000 / 300) == 3`` (epoch 3 spans the half-open
        interval ``[900, 1200)``).
        """
        t = now if now is not None else self._time()
        return int(t // self.rotation_seconds)

    def _secret_for_epoch(self, epoch: int) -> bytes:
        """Derive the HMAC secret for a given epoch.

        ``HMAC-SHA256(root_secret, str(epoch).encode("ascii"))``. The
        root secret itself never leaves this object and is never used
        directly as an HMAC key for token issuance, so a per-epoch
        secret compromise is scoped to that epoch.
        """
        return hmac.new(
            self.root_secret, str(epoch).encode("ascii"), hashlib.sha256
        ).digest()

    def _peer_key(self, peer_ip) -> bytes:
        """Canonical bytes for a peer identity.

        Accepts a ``str`` (e.g. ``'1.2.3.4'`` or ``'host:port'``) —
        returned as its UTF-8 encoding — or ``bytes`` / ``bytearray`` —
        returned coerced to ``bytes``. Any other type raises
        ``TypeError``; callers decide whether to propagate (``issue``)
        or swallow (``verify``).
        """
        if isinstance(peer_ip, str):
            return peer_ip.encode("utf-8")
        if isinstance(peer_ip, (bytes, bytearray)):
            return bytes(peer_ip)
        raise TypeError(
            f"peer_ip must be str or bytes, not {type(peer_ip).__name__}"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def issue(self, peer_ip, now: float | None = None) -> bytes:
        """Issue a token for ``peer_ip`` valid in the current epoch.

        ``token = HMAC-SHA256(secret_for_current_epoch, peer_key)``.
        Returns exactly 32 bytes (the SHA-256 digest length).

        Strict on input: a ``peer_ip`` that is neither ``str`` nor
        ``bytes`` raises ``ValueError`` (wrapping the underlying
        ``TypeError`` from ``_peer_key``), since issuance operates on
        locally-controlled data.
        """
        try:
            key = self._peer_key(peer_ip)
        except TypeError as exc:
            raise ValueError(f"invalid peer_ip: {exc}") from exc
        secret = self._secret_for_epoch(self._epoch(now))
        # 32-byte HMAC-SHA256 digest — the issued token.
        return hmac.new(secret, key, hashlib.sha256).digest()

    def verify(
        self,
        peer_ip,
        token: bytes,
        now: float | None = None,
        tolerance_epochs: int = 1,
    ) -> bool:
        """Return ``True`` iff ``token`` matches the HMAC under the
        current epoch **or** any of the previous ``tolerance_epochs``
        epochs.

        With the default ``tolerance_epochs=1`` this honours exactly the
        spec's "current and previous rotation" rule. Comparison uses
        ``hmac.compare_digest`` (constant-time).

        Lenient on input: a non-``bytes`` token, a wrong-length token,
        or an unparseable ``peer_ip`` all yield ``False`` rather than
        raising, since verification handles untrusted wire data.
        """
        # Reject anything that is not exactly a 32-byte bytes object.
        if not isinstance(token, bytes):
            return False
        if len(token) != constants.SHA256_LEN:
            return False
        try:
            key = self._peer_key(peer_ip)
        except TypeError:
            return False

        current_epoch = self._epoch(now)
        # range(tolerance_epochs + 1): off=0 is current, off=1 is previous.
        # A negative tolerance yields an empty range -> returns False.
        for off in range(tolerance_epochs + 1):
            cand_epoch = current_epoch - off
            secret = self._secret_for_epoch(cand_epoch)
            candidate = hmac.new(secret, key, hashlib.sha256).digest()
            if hmac.compare_digest(candidate, token):
                return True
        return False

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------
    def current_secret(self, now=None) -> bytes:
        """The active epoch's secret (diagnostic; do not transmit)."""
        return self._secret_for_epoch(self._epoch(now))

    def previous_secret(self, now=None) -> bytes:
        """The previous epoch's secret (diagnostic; do not transmit)."""
        return self._secret_for_epoch(self._epoch(now) - 1)
