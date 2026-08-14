"""freens in-process DHT envelope store — §6.4 PUT/GET + §12 eviction.

This module implements the storing-node side of the freens DHT record store as
described in ``specifications.md``:

* **§6.4 (lines 459-490) — Store and retrieve semantics.** PUT step 3: a
  storing node keeps a new ``SignedEnvelope`` for a DHT key only if it
  *strictly wins* over the current occupant — higher ``sequence``, or same
  ``sequence`` but bytewise-greater ``H_record`` (the tie-break that makes
  idempotent concurrent republication convergent). PUT step 4: storing nodes
  evict at ``expires + EXPIRY_GRACE`` (24 h grace for clock skew and network
  partitions). GET returns the single winning envelope stored under the key.

* **§12 (lines 900-915) — Economics and incentives.** "Storage per node is
  capped (``NODE_STORAGE_MAX``); nodes evict expired envelopes first, then
  LRU." This module's :meth:`EnvelopeStore._enforce_cap` realises that policy.

* **Appendix A (normative constants table, lines 965-993).**
  ``NODE_STORAGE_MAX = 256 MiB`` (the per-node envelope storage cap) and
  ``EXPIRY_GRACE = 86400 s`` (the post-expiry retention window) are imported
  from :mod:`freens.constants`; they are NOT redefined here.

Design
------

Each entry is keyed by its 32-byte DHT storage key (``K_name`` / ``K_tld`` /
``K_claim`` — all SHA-256 digests). For each key, **at most one** winning
:class:`wire.SignedEnvelope` is retained; a fresh put replaces the occupant
only when :func:`wire.envelope_wins` says the newcomer strictly wins (or when
the occupant is already past ``expires + EXPIRY_GRACE``, in which case the slot
is treated as empty).

Three plain ``dict`` objects back the store (an "ordered hash map" via dict +
implicit insertion order): ``_env`` (key -> envelope), ``_last_access`` (key ->
unix seconds, for LRU), and ``_size`` (key -> cached ``len(envelope.to_bytes())``
so the byte budget is O(1) per entry to recompute). A single
:class:`threading.RLock` guards every public method; the re-entrant lock lets
:meth:`put` call :meth:`evict_expired` and :meth:`_enforce_cap` internally
without self-deadlock.

This module is pure stdlib (``threading``, ``time``) and depends only on
:mod:`freens.constants` and :mod:`freens.wire`.
"""

from __future__ import annotations

import threading
import time
from typing import Optional

from .. import constants
from .. import wire

__all__ = ["EnvelopeStore"]


class EnvelopeStore:
    """In-process DHT envelope store implementing §6.4 winner rule + §12 eviction.

    Each entry is keyed by its 32-byte DHT storage key
    (``K_name`` / ``K_tld`` / ``K_claim``). For each key, at most ONE winning
    :class:`wire.SignedEnvelope` is retained. Inserts must strictly win
    (:func:`wire.envelope_wins`) over the current occupant. Entries past
    ``expires + EXPIRY_GRACE`` are evicted lazily on access and via
    :meth:`evict_expired`. When total stored bytes exceed ``NODE_STORAGE_MAX``,
    entries are evicted in order: expired-first, then least-recently-used.

    Conformance references: §6.4 (lines 459-490), §12 (lines 900-915), and the
    ``NODE_STORAGE_MAX`` / ``EXPIRY_GRACE`` rows of Appendix A (lines 980, 993).
    """

    def __init__(
        self,
        max_bytes: int = constants.NODE_STORAGE_MAX,
        time_fn=time.time,
    ):
        """Construct an empty store.

        Parameters
        ----------
        max_bytes : int
            Per-node byte budget; defaults to ``constants.NODE_STORAGE_MAX``
            (256 MiB, Appendix A line 993). When total stored bytes exceed this,
            :meth:`_enforce_cap` evicts expired-first then LRU (§12 line 908).
        time_fn : callable
            Wall-clock source returning the current unix time (seconds) when a
            method is called without an explicit ``now``. Defaults to
            :func:`time.time`; tests inject a deterministic clock.
        """
        self.max_bytes = max_bytes
        self._time = time_fn
        # key -> SignedEnvelope (the single winner retained for that key).
        self._env: dict = {}
        # key -> last access unix seconds (drives LRU; §12 "then LRU").
        self._last_access: dict = {}
        # key -> cached byte size = len(envelope.to_bytes()); cached at put()
        # so the byte budget is O(1) per entry to recompute (do NOT recompute
        # to_bytes() on every _total_bytes() call).
        self._size: dict = {}
        # RLock (not Lock) so put() may call evict_expired()/_enforce_cap()
        # re-entrantly without self-deadlock.
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Internal helpers (callers MUST already hold self._lock).
    # ------------------------------------------------------------------
    def _alive(self, key, now) -> bool:
        """True iff the entry for ``key`` is within ``expires + EXPIRY_GRACE``
        at time ``now`` (§6.4 step 4 / Appendix A line 980).

        Caller must hold the lock and guarantee ``key`` is present in
        ``self._env``.
        """
        env = self._env[key]
        return now < env.record.expires + constants.EXPIRY_GRACE

    def _drop(self, key) -> None:
        """Remove ``key`` from all three backing dicts (caller holds the lock)."""
        self._env.pop(key, None)
        self._last_access.pop(key, None)
        self._size.pop(key, None)

    def _total_bytes(self) -> int:
        """Sum of cached ``len(envelope.to_bytes())`` over all entries.

        Caller must hold the lock.
        """
        return sum(self._size.values())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def put(
        self,
        key: bytes,
        envelope: wire.SignedEnvelope,
        now: Optional[int] = None,
        verify_signature: bool = True,
    ) -> bool:
        """Attempt to store ``envelope`` under ``key``; return True iff accepted.

        Acceptance rules (applied in order):

        1. ``key`` is exactly :data:`constants.SHA256_LEN` (32) bytes — else
           ``ValueError`` (``bytearray`` is coerced to ``bytes``).
        2. ``envelope`` is a :class:`wire.SignedEnvelope` — else ``ValueError``.
           If ``verify_signature`` is True (the default), its
           :meth:`~wire.SignedEnvelope.verify_signature` MUST return ``True``;
           a bad signature rejects the put (returns ``False``, count unchanged).
           ``verify_signature=False`` skips the check (testing only) but the
           argument MUST still be a ``SignedEnvelope``.
        3. If an entry exists for ``key`` AND is still alive (within
           ``expires + EXPIRY_GRACE``): accept the newcomer only if
           :func:`wire.envelope_wins` (``new=envelope, old=existing``) returns
           ``True``. If the existing entry is past grace, the slot is treated
           as empty and the newcomer is accepted unconditionally.
        4. After acceptance: cache ``len(envelope.to_bytes())`` in ``_size``,
           set ``_last_access[key] = now``, run :meth:`evict_expired` then
           :meth:`_enforce_cap`. The post-accept sweeps MAY evict OTHER
           entries (never the just-accepted one — see :meth:`_enforce_cap`).

        Returns ``True`` iff the envelope was stored under ``key``.
        Thread-safe via the RLock.

        Conformance: §6.4 PUT step 3 (lines 466-470) — strict winner rule.
        """
        # --- rule 1: key length ----------------------------------------
        if not isinstance(key, (bytes, bytearray)):
            raise ValueError(
                f"key must be bytes, got {type(key).__name__}"
            )
        if len(key) != constants.SHA256_LEN:
            raise ValueError(
                f"key must be {constants.SHA256_LEN} bytes, got {len(key)}"
            )
        key = bytes(key)

        # --- rule 2: envelope type + signature -------------------------
        if not isinstance(envelope, wire.SignedEnvelope):
            raise ValueError(
                "envelope must be a wire.SignedEnvelope, got "
                f"{type(envelope).__name__}"
            )
        if verify_signature and not envelope.verify_signature():
            return False

        now = self._time() if now is None else now

        with self._lock:
            # --- rule 3: winner check vs incumbent ---------------------
            existing = self._env.get(key)
            if existing is not None and self._alive(key, now):
                # Alive incumbent: newcomer must STRICTLY win (§6.4 step 3).
                if not wire.envelope_wins(newer=envelope, older=existing):
                    return False
            # else: no incumbent, or incumbent is past grace -> slot is empty.

            # --- accept: install the new winner ------------------------
            # Cache the byte size once (do not recompute to_bytes() later).
            self._size[key] = len(envelope.to_bytes())
            self._env[key] = envelope
            self._last_access[key] = now

            # --- rule 4: post-accept eviction sweeps -------------------
            # evict_expired first (expired-past-grace), then cap enforcement
            # (LRU). The just-accepted key is protected from LRU eviction;
            # evict_expired may still drop it iff it is itself past grace
            # (an already-long-dead envelope does not deserve storage).
            self.evict_expired(now)
            self._enforce_cap(now, _protected=key)
            return True

    def get(
        self, key: bytes, now: Optional[int] = None
    ) -> Optional[wire.SignedEnvelope]:
        """Return the stored envelope for ``key`` if present and alive, else None.

        Lazily evicts a dead entry on access (§6.4 step 4): if an entry exists
        but ``now >= expires + EXPIRY_GRACE``, it is dropped and ``None`` is
        returned. On a successful hit, ``_last_access[key]`` is refreshed to
        ``now`` (LRU bookkeeping). Thread-safe.
        """
        # Coerce bytearray -> bytes so lookups match put()'s canonical keys.
        if isinstance(key, bytearray):
            key = bytes(key)
        now = self._time() if now is None else now
        with self._lock:
            env = self._env.get(key)
            if env is None:
                return None
            if not self._alive(key, now):
                # Lazy eviction of a dead entry (§6.4 step 4 / §12).
                self._drop(key)
                return None
            self._last_access[key] = now
            return env

    def has(self, key: bytes, now: Optional[int] = None) -> bool:
        """True iff an ALIVE entry is stored under ``key``.

        Non-mutating: does NOT lazily evict a dead entry (use :meth:`get` or
        :meth:`evict_expired` for that); it simply reports ``False`` for a
        dead or absent key. Thread-safe.
        """
        if isinstance(key, bytearray):
            key = bytes(key)
        now = self._time() if now is None else now
        with self._lock:
            if key not in self._env:
                return False
            return self._alive(key, now)

    def remove(self, key: bytes) -> bool:
        """Unconditionally drop the entry for ``key``. Return True iff something
        was removed. Thread-safe. (Not on the §6.4 critical path; provided for
        admin / testability.)
        """
        if isinstance(key, bytearray):
            key = bytes(key)
        with self._lock:
            if key in self._env:
                self._drop(key)
                return True
            return False

    def evict_expired(self, now: Optional[int] = None) -> int:
        """Remove every entry past ``expires + EXPIRY_GRACE``; return the count.

        Implements §6.4 step 4 ("storing nodes evict at ``expires + GRACE``")
        and the "expired envelopes first" half of the §12 eviction policy.
        Thread-safe.
        """
        now = self._time() if now is None else now
        with self._lock:
            evicted = 0
            for k in list(self._env):
                if not self._alive(k, now):
                    self._drop(k)
                    evicted += 1
            return evicted

    def _enforce_cap(
        self, now: int, _protected: Optional[bytes] = None
    ) -> int:
        """If total bytes exceed ``max_bytes``, evict until under cap.

        Eviction order (§12 line 908): **expired-first** (a defensive re-check
        — :meth:`evict_expired` normally already ran), then
        **least-recently-used** (smallest ``_last_access`` first; ties broken
        bytewise on the key for determinism).

        The ``_protected`` key (used by :meth:`put` to name the just-accepted
        envelope) is NEVER evicted by this method: it is excluded from the LRU
        candidate set. This guarantees the just-put entry survives even if its
        ``_last_access`` is not strictly the largest (e.g. backdated ``now`` or
        a prior :meth:`get` that bumped another entry's access time forward).

        Edge case (documented): a SINGLE entry that alone exceeds ``max_bytes``
        is never evicted by the cap — the loop stops when fewer than two
        candidates remain, so one oversized envelope is retained. (Distributors
        bound envelope size on the wire; a single >256 MiB envelope is not a
        realistic v1 input.)

        Never raises. Returns the number of entries evicted. Called under the
        lock by :meth:`put`; safe to call directly (``_protected=None``).
        """
        evicted = 0
        # --- expired-first (re-check; evict_expired usually ran already) ---
        for k in list(self._env):
            if k == _protected:
                continue
            if not self._alive(k, now):
                self._drop(k)
                evicted += 1
        # --- then LRU until under cap (or nothing evictable remains) -------
        while self._total_bytes() > self.max_bytes and len(self._env) > 1:
            candidates = [k for k in self._env if k != _protected]
            if not candidates:
                # Only the protected entry remains; keep it (edge case above).
                break
            # LRU = smallest last_access; bytewise key tie-break for determinism.
            lru_key = min(
                candidates, key=lambda k: (self._last_access.get(k, 0), k)
            )
            self._drop(lru_key)
            evicted += 1
        return evicted

    # ------------------------------------------------------------------
    # Introspection (pure snapshots; no time-based side effects).
    # ------------------------------------------------------------------
    def size_bytes(self) -> int:
        """Current total stored bytes (sum of cached ``to_bytes()`` lengths)."""
        with self._lock:
            return self._total_bytes()

    def count(self) -> int:
        """Number of entries currently held.

        Note: this is the count of entries physically present in the store.
        Entries that are past ``expires + EXPIRY_GRACE`` but not yet swept
        (by :meth:`get`, :meth:`evict_expired`, or a :meth:`put`) are still
        counted here; they are removed lazily on the next access. Call
        :meth:`evict_expired` first if an exact "live" count is required.
        """
        with self._lock:
            return len(self._env)

    def keys(self) -> list:
        """Snapshot list of the store's current keys (insertion order)."""
        with self._lock:
            return list(self._env.keys())


# ===========================================================================
# Golden / sanity vectors (asserted BY CONSTRUCTION; documented here, exercised
# by the test suite — not executed in this module).
#
# Build envelopes via wire.sign_record (see wire.py's own golden block):
#   kp   = crypto.Keypair.generate()
#   tid  = crypto.tld_id(kp.public_bytes)
#   name = naming.encode_wire_name([], "foo", tid)
#   rec  = Record(name=name, owner=kp.public_bytes, sequence=1,
#                 created=1000, expires=2000, rrset=[])
#   env  = wire.sign_record(rec, kp)            # verify_signature() == True
#   key  = hashlib.sha256(b"\x02" + name).digest()   # any 32-byte key
#
#   s = EnvelopeStore()
#   assert s.count() == 0 and s.size_bytes() == 0           # empty store
#
#   assert s.put(key, env, now=1500) is True                 # accepted
#   assert s.count() == 1
#   assert s.get(key, now=1500) is env                       # winner returned
#   assert s.has(key, now=1500) is True
#
#   # Bad signature -> rejected (count unchanged) unless verify_signature=False.
#   bad = SignedEnvelope(record=rec, sig=b"\x00"*64, signer=kp.public_bytes)
#   assert s.put(key, bad, now=1500) is False
#   assert s.count() == 1
#   assert s.put(key, bad, now=1500, verify_signature=False) is True
#
#   # Winner rule (§6.4 step 3): higher sequence wins; lower rejected.
#   rec_hi = Record(..., sequence=2, ...) ; env_hi = sign_record(rec_hi, kp)
#   assert s.put(key, env_hi, now=1600) is True              # 2 > 1 -> wins
#   assert s.get(key, now=1600) is env_hi
#   assert s.put(key, env, now=1600) is False                # 1 < 2 -> rejected
#
#   # Same sequence: bytewise-greater H_record wins; loser rejected.
#   # (env_a, env_b same sequence, different rrset -> distinct record_hash.)
#   #   assert envelope_wins(env_b, env_a) != envelope_wins(env_a, env_b)
#   #   s.put(key, env_a, ...); s.put(key, env_b, ...) iff env_b.record_hash() >
#   #     env_a.record_hash()
#
#   # Lazy eviction on get (§6.4 step 4): now >= expires + EXPIRY_GRACE.
#   #   env_dead = sign_record(Record(..., expires=T, ...), kp)
#   #   s.put(k, env_dead, now=T)
#   #   assert s.get(k, now=T + EXPIRY_GRACE) is None
#   #   assert s.count() == 0
#
#   # evict_expired sweeps all dead entries:
#   #   n = s.evict_expired(now=far_future)
#   #   assert n == <number dead> and s.count() == 0
#
#   # Cap + LRU (§12): with max_bytes small and many live envelopes, the
#   # just-put entry survives while older (smaller last_access) ones are evicted
#   # in LRU order until size_bytes() <= max_bytes.
#   #   s = EnvelopeStore(max_bytes=1<<20)
#   #   for i in range(N): s.put(keys[i], envs[i], now=1000+i)
#   #   assert keys[N-1] in s.keys()                         # just-put survives
#   #   assert s.size_bytes() <= s.max_bytes or s.count() == 1
#
#   # Thread-safety: RLock allows put() -> evict_expired() -> _enforce_cap()
#   # re-entry without deadlock (exercised by concurrent put/get stress tests).
