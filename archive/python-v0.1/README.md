# freens — Free Namespace (reference implementation, v0.1 draft)

**freens** is a decentralized, permissionless, self-certifying naming system. Human-readable names (`<alias>.<tld>`) map to signed resource records whose authority traces back to a proof-of-work-mined alias claim on a top-level domain. The system layers four mechanisms: a canonical CBOR wire format, Ed25519 signatures with SHA-256 identifiers, a Kademlia-style DHT storage layer, and witness-attested proof-of-work alias collision resolution. A local DNS-compatible resolver routes queries per a per-alias policy.

The normative protocol specification is [`specifications.md`](specifications.md) in this repository. That document's reference language is **Go**, but it states explicitly that "Go is the reference, not a requirement." This package is a **Python** implementation of the protocol-critical core.

## Status / Scope

**Implemented (protocol-critical, fully tested):**
- Naming model & wire format — §3 (aliases, `wire_name`, DHT storage keys).
- Deterministic canonical CBOR — §4.2, hand-rolled per **RFC 8949 §4.2** (no `cbor2` dependency).
- Ed25519 + SHA-256 + PoW + recovery — §5, §7.3, Appendix A.4.
- Records, signed envelopes, validity rules, authority chains — §4, §3.4.
- Alias claims, witness attestations, deterministic §7.4 ordering.
- DHT data structures: XOR metric, 256 k-bucket routing table, rotating HMAC write tokens, envelope store with the §6.4 `(sequence, H_record)` winner rule and §12 LRU/expiry eviction.
- Resolver config parser + per-alias routing decisions — §9.3.

**Not implemented (out of scope for this core; hooks exist):**
- UDP DHT transport / live RPC exchange — the `Message` type and store/routing logic exist, but the network loop does not.
- Live miekg/dns-style UDP/TCP DNS listener — config + routing-decision logic exist; the socket loop does not.
- The CLI/daemon (`cmd/freens`).
- IDNA2008 U-label normalization — strict ASCII LDH is enforced; an `IDNA_NORMALIZER` injection hook is exposed in `naming.py`.

## Requirements

- Python ≥ 3.9
- The `cryptography` package (≥ 38.0.4) — provides Ed25519. There is **no `cbor2` dependency**: canonical CBOR is hand-rolled in `freens.cbor_canon` for byte-stable golden vectors.
- Install: `python3 -m pip install -e .` (or just ensure `cryptography` is present and run from the repo root).

## Project layout

```
freens/
├── specifications.md          # the protocol spec (normative)
├── pyproject.toml
├── README.md
├── freens/
│   ├── __init__.py
│   ├── constants.py           # Appendix A normative constants
│   ├── cbor_canon.py          # deterministic CBOR (RFC 8949 §4.2), pure stdlib
│   ├── naming.py              # §3.2/§3.3 aliases, wire_name, DHT keys
│   ├── crypto.py              # §5 Ed25519, IDs, hierarchical derivation, PoW, recovery
│   ├── wire.py                # §4 Record/SignedEnvelope/Message, signing, validity, authority chain
│   ├── claims.py              # §7 AliasClaim, witnesses, deterministic ordering
│   ├── resolver_config.py     # §9.3 INI parser + per-alias routing
│   └── dht/
│       ├── ids.py             # §6.2 XOR metric, bucket index
│       ├── tokens.py          # §6.3 rotating HMAC write tokens
│       ├── routing.py         # §6.2 256-bucket Kademlia routing table
│       └── store.py           # §6.4 envelope store (winner rule) + §12 eviction
└── tests/                     # unittest suite (11 files)
```

## Running the tests

```
python3 -m unittest discover
```

Run from the repo root. The suite is pure stdlib `unittest` (no pytest). **257 test methods** across 11 files. Tests cover: CBOR golden vectors (exact bytes hand-derived from RFC 8949), the wire-name worked example (spec line 192), Ed25519 sign/verify, PoW mining and leading-zero-bit counting, deterministic claim ordering, authority-chain walking (1/2/3-hop delegation), the DHT `(sequence, hash)` winner rule, write-token epoch rotation, k-bucket eviction, resolver config parsing of the spec's §9.3 example, and an end-to-end integration test simulating create-TLD → mine-claim → delegate → publish → resolve with an in-process envelope store standing in for the DHT.

**Note on test speed.** Alias-claim PoW is mined at difficulty 8 in tests (fast — hundreds of hashes). Tests that exercise the full §7.4 default-difficulty validity path (`select_winner`, `verify_full`, bare `verify_pow`) temporarily lower `freens.constants.POW_DIFFICULTY_INIT` to 8. This is legitimate: difficulty is a retargetable network parameter (Appendix A.4, default 24 bits) and the modules read it via attribute access at call time, so monkey-patching it models a network with a lower floor.

## Key design decisions

These are chosen interpretations of ambiguous spec wording; each is documented at its source location.

1. Canonical CBOR is hand-rolled in `freens/cbor_canon.py` (RFC 8949 §4.2) rather than depending on `cbor2`, so golden-vector byte stability cannot drift on a library upgrade. (`cbor_canon.py`)
2. `SignedEnvelope` field 1 (`record`) is the `FREENS_Record` as an **embedded canonical CBOR map**, not a bstr wrapper — the signature covers `record.canonical_bytes()`, which is byte-identical to the embedded serialization. (`wire.py`)
3. `H_record = SHA-256(canonical_cbor(SignedEnvelope))` — the hash covers the **whole** envelope (record + sig + signer), per §4.2 line 288. (`wire.py`)
4. The PoW prefix is the canonical CBOR of the identity fields `{1:alias, 2:tld_id, 3:timestamp, 5:claimant_pk}` — field 4 (`nonce`) is **excluded**, per the authoritative worked example Appendix C.1 (the literal `{1..5}` in §7.3 is loose prose). (`claims.py`)
5. Optional record fields 8–12 are **omitted** from the CBOR map when absent; field 12 (`revoke`) is emitted only when `True`. (`wire.py`)
6. The DHT `Message` signature covers the canonical CBOR array `[t, sender_id, recipient_id, a]` — resolving the §6.3 vs Appendix B.1 "recipient_id/peer_id" wording in favour of §6.3's 4-tuple. (`wire.py`)
7. The §6.4 store winner rule is *higher sequence, else bytewise-greater `H_record`* — Python's native `bytes > bytes` is lexicographic big-endian, matching the spec. (`wire.envelope_wins`, `dht/store.py`)
8. `bucket_index == common_prefix_length(self, other)` (0..255): bucket *i* holds IDs sharing exactly *i* leading bits with the node's own ID. (`dht/ids.py`, `dht/routing.py`)

## License / references

- Protocol specification: [`specifications.md`](specifications.md) (v0.1 draft), the normative document for this implementation.
- **RFC 8032** — Ed25519 digital signatures.
- **RFC 8949 §4.2** — deterministic CBOR encoding.
- **FIPS 180-4** — SHA-256.
- **RFC 2119** / **RFC 8174** — requirements language (MUST, SHOULD, …).
