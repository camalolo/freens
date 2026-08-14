"""Normative protocol constants for the freens reference implementation.

All values in this module mirror ``specifications.md`` — in particular
``Appendix A. Constants (normative)`` (the table at spec lines 965-993) and
the difficulty-retargeting rule of ``Appendix A.4`` (spec lines 995-1008).

Unless otherwise noted, every duration is expressed in **seconds** and every
length/size is expressed in **bytes**. Sizes that the spec states in MiB are
materialised here as plain integer byte counts (e.g. ``NODE_STORAGE_MAX``).

This module intentionally contains only constants (and the single helper
``retarget_difficulty`` required by Appendix A.4); there is no class or
runtime state. Importing it has no side effects.
"""

import math

# ---------------------------------------------------------------------------
# Protocol version  (spec A: "record `version` field")
# ---------------------------------------------------------------------------
PROTO_VERSION = 1

# ---------------------------------------------------------------------------
# Name structure
# ---------------------------------------------------------------------------
MAX_LABELS = 8           # max name depth (labels under TLD)
MAX_LABEL_LEN = 63       # max length of a single label, in bytes (DNS-style)

# ---------------------------------------------------------------------------
# Network / DHT  (Kademlia parameters)
# ---------------------------------------------------------------------------
FREENS_PORT = 15353      # default DHT UDP port
K = 20                   # k-bucket size / closest-set size
ALPHA = 3                # lookup parallelism
R = 8                    # replication factor for put
GET_CLOSEST = 4          # nodes merged when selecting a winner
RPC_TIMEOUT = 5          # per-RPC timeout (seconds)
BUCKET_REFRESH = 900     # Kademlia bucket refresh interval (15 min)
TOKEN_ROTATION = 300     # write-token epoch (5 min)

# ---------------------------------------------------------------------------
# Records / TTL
# ---------------------------------------------------------------------------
RECORD_DEFAULT_TTL = 86400     # default record lifetime (24 h)
RECORD_MAX_TTL = 2592000      # max record lifetime (30 d)
REFRESH_FRACTION = 0.8        # republish at 80% of lifetime
EXPIRY_GRACE = 86400          # store past expiry (skew/partitions) (24 h)
MAX_RRS_PER_RECORD = 64       # max resource records within a single record

# ---------------------------------------------------------------------------
# Witnessing
# ---------------------------------------------------------------------------
W = 5                   # witness quorum size
WITNESS_SET = 8         # candidate witnesses (closest to K_claim)
WITNESS_COOLDOWN = 3600 # min spacing between a witness's signatures on
                        # competing claims (1 h)

# ---------------------------------------------------------------------------
# Proof-of-Work / difficulty
# ---------------------------------------------------------------------------
POW_DIFFICULTY_INIT = 24     # initial claim PoW difficulty (bits)
POW_RETARGET_BLOCK = 2016   # difficulty retarget interval (accepted claims)
# The spec table (line 986) lists ``POW_TARGET_RATE = 1 / 600 s`` (target
# global claim rate). Expressed as the target *interval* between claims it is
# 600 seconds, which is the form used by the retarget formula in Appendix A.4.
POW_TARGET_INTERVAL = 600   # target global claim interval (seconds)


def retarget_difficulty(d_old, actual_interval_seconds, target_interval_seconds):
    """Compute the new PoW difficulty, per ``specifications.md`` Appendix A.4.

    Implements the normative retarget rule::

        D_new = D_old + clamp(ceil(log2(actual_interval / target_interval)),
                              -2, +2)

    using the wall-clock span of the retarget block.

    Parameters
    ----------
    d_old : int
        Current difficulty (``D_old``).
    actual_interval_seconds : int | float
        Wall-clock span of the retarget block (``actual_interval``).
    target_interval_seconds : int | float
        Target interval, normally ``POW_TARGET_INTERVAL`` (``target_interval``).

    Returns
    -------
    int
        The new difficulty ``D_new``, clamped to never fall below
        ``POW_DIFFICULTY_INIT``.
    """
    ratio = actual_interval_seconds / target_interval_seconds
    delta = math.ceil(math.log2(ratio))
    # Clamp the per-block adjustment to [-2, +2].
    if delta < -2:
        delta = -2
    elif delta > 2:
        delta = 2
    d_new = d_old + delta
    # Difficulty must never fall below the initial floor.
    if d_new < POW_DIFFICULTY_INIT:
        d_new = POW_DIFFICULTY_INIT
    return int(d_new)

# ---------------------------------------------------------------------------
# Aliases / claims / timing
# ---------------------------------------------------------------------------
MIN_ALIAS_LEN = 1            # minimum length of a claimable alias
SKEW_TOLERANCE = 60          # near-simultaneous claim window (seconds)
CONTEST_WINDOW = 172800      # contested-alias finalization wait (48 h)
ALIAS_REUSE_DELAY = 2592000  # alias re-claimable after expiry (30 d)
RECOVERY_TIMELOCK = 259200   # default recovery delay (72 h)

# ---------------------------------------------------------------------------
# Resolver caching
# ---------------------------------------------------------------------------
RESPONSE_TTL_CAP = 3600      # max TTL emitted by resolver (seconds)
NEG_TTL = 60                 # negative caching (seconds)

# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
NODE_STORAGE_MAX = 256 * 1024 * 1024  # per-node envelope storage cap (256 MiB)

# ---------------------------------------------------------------------------
# Cryptographic primitive sizes (bytes)
# ---------------------------------------------------------------------------
ED25519_PUBLIC_KEY_LEN = 32   # Ed25519 verifying key length
ED25519_SIGNATURE_LEN = 64    # Ed25519 signature length
SHA256_LEN = 32               # SHA-256 digest length
NODE_ID_LEN = 32              # DHT node identifier length

# ---------------------------------------------------------------------------
# Wire-format markers / DHT key prefixes
# ---------------------------------------------------------------------------
WIRE_NAME_LABEL_MARKER = 0x01  # precedes each label in a wire-encoded name
WIRE_NAME_TERMINATOR = 0x00    # terminates a wire-encoded name
DHT_KEY_PREFIX_NAME = 0x02     # K_name  = SHA-256(0x02 || wire_name)
DHT_KEY_PREFIX_CLAIM = 0x03    # K_claim = SHA-256(0x03 || "claim:" || alias)
