# freens — Free Namespace (Go reference implementation, v0.1 draft)

freens is a decentralized, permissionless naming system that maps
human-readable names to signed resource records (IP addresses, TXT, etc.)
without a central registry. Ownership is cryptographic: the owner of a name is
whoever controls the private key its authority chain points to. This is the
**Go reference implementation** of `specifications.md` (the spec's Appendix D
is normative for the reference client and recommends exactly the mature
libraries used here).

Conceptually freens is closer to **BitTorrent DHT + DNS + public-key identity**
than to traditional DNS: self-certifying TLDs (ID = SHA-256 of the owner key),
a Kademlia-style DHT storing signed records, a local DNS resolver so existing
apps work unmodified, and witness-quorum + proof-of-work to deterministically
resolve collisions on human-readable aliases.

## Status

Implemented and fully tested (130 test functions, `go test ./...` green,
`go vet` clean, `-race` clean):

| Package | Implements | Spec |
|---|---|---|
| `internal/constants` | Appendix A normative constants + difficulty retarget (A.4) | A |
| `internal/naming` | alias LDH validation, `wire_name` encoding, DHT key derivation | §3.2, §3.3 |
| `internal/crypto` | Ed25519, SHA-256 IDs, hierarchical derivation, hashcash PoW, recovery | §5, §7.3 |
| `internal/wire` | `FREENS_Record`, `SignedEnvelope`, KRPC `Message`; canonical CBOR; signing; §4.4 validity; §3.4 authority chains; §6.4 winner rule | §4, §3.4, §6.3 |
| `internal/claims` | `AliasClaim`, witness attestations, PoW, deterministic §7.4 ordering | §7 |
| `internal/dht` | XOR metric, 256 k-bucket routing table, rotating HMAC write tokens, envelope store (winner rule + LRU/grace eviction) | §6 |
| `internal/resolver` | §9.3 INI config parser, per-alias routing, live UDP+TCP DNS server via `miekg/dns`, DNS fallback | §9 |
| `cmd/freens` | DNS resolver daemon; optional full DHT node (`-dht`, `-peers`, `-node-seed`, `-passive`, `-persist`, `-advertise`, `-stun`, `-turn`, `-turn-relay`, `-dns`, `-metrics`, `-peers-file` + SIGHUP reload): serves/republishes records, answers `ping`/`find_node`/`get`/`put`/`witness` RPCs, resolves aliases from network claims (§7) | §6, §9.1 |
| `cmd/freens-cli` | `gen-key`, `mine-claim`, `make-record`, `publish` (incl. `-evidence` for §8.4 recovery transport), `resolve`, `get`, `transfer`/`rotate`/`recover`/`verify-recovery`, `demo` subcommands | §6.4, §8 |

Multi-node operation: with `-dht <addr>` the daemon joins the Kademlia
network — records seeded locally are served to (and fetched from) peers via
iterative GET, aliases without a local pin are resolved from claim envelopes
stored at `K_claim` (pin-first policy: `alias-pins` always win), and due
records are republished at 80% of lifetime (§6.4). `-advertise <addr>`
publishes a dialable address (e.g. your public `ip:15353` behind NAT/port
forwarding) instead of the observed source in peer contact lists (§6.2) —
see "NAT traversal" in `contrib/README.md`; `-stun <server>`
discovers that reflexive address automatically, and for symmetric NAT
`-turn-relay <server>` routes ALL peer DHT traffic through an allocation
on a community relay and advertises the relayed address (precedence
`-advertise` > `-turn-relay` > `-stun`, with graceful fallback to
direct). `-turn <addr>` runs such a relay — a public node can donate
bandwidth to nodes that cannot be dialed directly; see "Running a
community TURN relay" in `contrib/README.md`. `-dns <addr>` overrides the
DNS listen without a config file, `-metrics <addr>` exposes metrics +
`/healthz`, and `-peers-file` + `SIGHUP` hot-reloads the bootstrap set.
Without `-dht` the daemon is a single-node island (spec §9.4 stage 1).
`contrib/testnet.sh [N] [mode]` spins up an N-node localhost interop
testnet and asserts DNS convergence on every node (update included;
`relay` mode routes all but one node through a `-turn` relay).

## Requirements

- Go ≥ 1.25 (the toolchain auto-downloads on `go build`)
- Dependencies (Appendix D mature libraries, all fetched via `go mod`):
  - `github.com/fxamacker/cbor/v2` — deterministic CBOR, RFC 8949 §4.2
  - `github.com/miekg/dns` — UDP/TCP DNS serve + upstream forwarding
  - `golang.org/x/net/idna` — IDNA2008 U-label normalization (opt-in)
  - stdlib `crypto/ed25519`, `crypto/sha256`, `crypto/hmac`

No CGO. `go build ./...` works offline after the first `go mod download`.

## Project layout

```
freens/
├── specifications.md              # the protocol spec (normative)
├── go.mod / go.sum
├── cmd/
│   ├── freens/main.go             # DNS resolver daemon
│   └── freens-cli/main.go         # gen-key / mine-claim / make-record / publish / resolve / get / demo
├── internal/
│   ├── constants/                 # Appendix A
│   ├── naming/                    # §3.2/§3.3 aliases, wire_name, DHT keys
│   ├── crypto/                    # §5 Ed25519, IDs, PoW, recovery
│   ├── wire/                      # §4 Record/Envelope/Message, authority chain
│   ├── claims/                    # §7 AliasClaim, witnesses, ordering
│   ├── dht/                       # §6 ids / tokens / routing / store
│   ├── resolver/                  # §9 config + miekg/dns server + routing
│   └── integration/               # end-to-end + golden-vector tests
├── contrib/                       # §9.1/§9.4 OS-integration recipes (port-53 redirect, resolv.conf, systemd)
└── archive/python-v0.1/           # the earlier Python prototype (archived)
```

## Running the tests

```bash
go test ./...                      # all 130 test functions
go test -race ./...                # race-clean
go test -v ./internal/integration/ # the end-to-end flow + golden vectors
```

The integration test (`internal/integration/integration_test.go`) is the Go
analog of a full create→claim→delegate→publish→resolve lifecycle, including
collision resolution and exact-byte golden vectors that cross-validate against
the spec (and the archived Python reference, since both are spec-derived).

## Trying it

```bash
# Self-contained end-to-end demo (no daemon needed):
go run ./cmd/freens-cli demo

# Generate a TLD keypair:
go run ./cmd/freens-cli gen-key

# Run the DNS resolver daemon on a high port (53 needs privileges):
go run ./cmd/freens -listen 127.0.0.1:5300 -upstream 9.9.9.9,1.1.1.1 \
    -load ./my-records/   # directory of *.cbor signed envelopes to serve

# N-node localhost interop testnet (publish once, dig every node):
./contrib/testnet.sh 3
```

The daemon was validated end-to-end with `dig`: a freens record served from the
in-process store answers authoritatively (`aa` bit, `203.0.113.42` per spec
Appendix C.2), while conventional names fall through to upstream recursive
resolvers (`dns-first` default).

## OS integration (§9.4)

Spec §9.4 stage 1 is the local resolver itself: apps keep using the OS stub,
which points at the daemon's `127.0.0.1:53` (§9.1). Because port 53 is
privileged, `contrib/` ships the §9.1 forwarding recipes — see
`contrib/README.md` for the full guide:

- `contrib/port53-redirect.sh` — iptables/nftables REDIRECT of :53 → :5300
  (UDP+TCP) when the daemon runs on a high port (`-listen 127.0.0.1:5300`),
  idempotent, with a `remove` action;
- `contrib/resolv.conf.example` and `contrib/systemd/freens-resolved.conf` —
  point the stub (`/etc/resolv.conf` or systemd-resolved) at the daemon;
- `CAP_NET_BIND_SERVICE` via `setcap` to bind :53 directly.

The daemon logs guidance automatically when binding :53 fails (§9.1).

## Key design decisions (chosen interpretations; documented in source)

1. **Canonical CBOR via `fxamacker/cbor` `CoreDetEncOptions()`** (RFC 8949 §4.2
   bytewise) with Go structs tagged `cbor:"N,keyasint,omitempty"`. Verified by
   golden-vector tests that the output is byte-identical to the spec-derived
   encodings.
2. **`SignedEnvelope` field 1 (`record`) is the embedded `FREENS_Record`
   canonical map**; the signature covers `Record.CanonicalBytes()`, which is
   byte-identical to the embedded serialization. `H_record = SHA-256(envelope)`.
3. **The PoW prefix excludes field 4 (nonce)** — fields `{1:alias, 2:tld_id,
   3:timestamp, 5:claimant_pk}`. Per the authoritative worked example Appendix
   C.1 line 1057-1058 (`SHA-256(cbor{alias,tld_id,ts,claimant_pk} || nonce)`),
   which overrides §7.3's loose "{1..5}" prose.
4. **Optional record fields 8–12 are omitted when absent**; field 12 (`revoke`)
   is emitted only when `&true` (a `*bool` with `omitempty`).
5. **DHT `Message` signature covers the canonical CBOR array
   `[t, sender_id, recipient_id, a]`** — resolving the §6.3 vs Appendix B.1
   "recipient_id/peer_id" wording in favour of §6.3's 4-tuple.
6. **The §6.4 store winner rule** is `higher sequence, else bytewise-greater
   H_record` (Go's `bytes.Compare` is big-endian lexicographic = the spec's
   "bytewise-greater").
7. **`bucket_index == common_prefix_length(self, other)`** (0..255): bucket *i*
   holds IDs sharing exactly *i* leading bits with the node's own ID.

## Cross-implementation conformance

The archived `archive/python-v0.1/` prototype implements the same protocol
semantics. The canonical-CBOR and `wire_name` golden vectors are identical
across both (both are spec-derived), and the Go integration test asserts them
byte-for-byte. Ed25519 signatures are deterministic (RFC 8032), so a fixed-seed
signing key produces identical signatures in either implementation.

## References

- Protocol spec: `specifications.md` (v0.1 draft)
- RFC 8032 (Ed25519), RFC 8949 §4.2 (deterministic CBOR), FIPS 180-4 (SHA-256),
  RFC 2119/8174 (requirements language), RFC 4648 (base32)
