# freens — Free Namespace

**Protocol Specification — Version 0.1 (Draft)**

| Field            | Value                                  |
|------------------|----------------------------------------|
| Project          | freens                                 |
| Document status  | Draft, subject to change               |
| Protocol version | 1                                      |
| Date             | 2026-08-14                             |

## 1. Introduction

### 1.1 Summary

freens is a decentralized, permissionless naming system that maps
human-readable names to resource records (IP addresses, text records,
service endpoints, etc.) without a central registry. Ownership of a name
is established cryptographically: the owner of a name is whoever controls
the private key that the name's authority chain points to.

Conceptually, freens is closer to **BitTorrent + DNS + public-key
identity** than to traditional DNS. There is no ICANN, no registrar, no
WHOIS owner of record, and no registration fee. The system consists of:

- a **self-certifying namespace** in which top-level identities are
  derived from public keys,
- a **Kademlia-style distributed hash table (DHT)** that stores and
  serves signed records,
- a **local DNS resolver** that makes the namespace usable by unmodified
  applications, and
- a **registration ordering mechanism** (witness quorum + proof of work)
  that deterministically resolves collisions on human-readable aliases.

### 1.2 Design goals

1. **No central registry.** Anyone can create a top-level namespace
   without asking permission.
2. **Cryptographic authenticity.** Every record is signed; a malicious
   peer cannot forge or alter records it does not own.
3. **Zero-cost registration.** Registration costs $0. The only costs are
   a keypair, proof-of-work electricity, and bandwidth.
4. **Backwards compatibility.** Existing applications work unmodified
   via a local DNS resolver with fallback to conventional DNS.
5. **Trivial transfers and recovery.** Transferring a name is a signed
   key hand-off; losing one key does not permanently destroy a name.
6. **No blockchain by default.** The lookup layer is a DHT. Consensus is
   only used where strictly necessary (human-alias collision ordering),
   and is deliberately weak, deterministic, and best-effort.

### 1.3 Non-goals

- freens does **not** establish legal identity. The protocol can prove
  *"key X controls `paypal.foo`"*; it cannot prove *"key X belongs to
  PayPal Inc."* (see Section 12).
- freens is **not** a trademark dispute-resolution system.
- freens is **not** a replacement for ICANN DNS unless and until it is
  widely integrated into browsers and operating systems. Until then it
  is a parallel namespace.
- freens does not provide anonymity for record publishers; record
  signatures are public-key authenticated by design.
- freens does not guarantee availability or censorship resistance at the
  storage layer beyond DHT replication; a globally extinguished name
  (all replicas expired and no owner refresh) simply disappears.

### 1.4 Requirements language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 and RFC 8174.

### 1.5 Reference implementation language

The reference implementation is written in **Go**. Go is chosen because
every major subsystem of freens maps onto a mature, well-maintained Go
library (or the standard library directly), which minimizes the amount
of protocol-critical code that must be written from scratch:

- Ed25519 and SHA-256 are in the standard library (`crypto/ed25519`,
  `crypto/sha256`),
- deterministic CBOR (RFC 8949 §4.2) is provided by `fxamacker/cbor`,
- the local DNS resolver is built on `miekg/dns` (the library underlying
  CoreDNS), covering UDP/TCP serving, EDNS0, and upstream forwarding,
- Kademlia routing-table and iterative-lookup *patterns* follow
  `anacrolix/dht` (the freens wire protocol itself is custom; see
  Appendix D).

Appendix D is the normative mapping from specification sections to Go
packages, and notes the one subsystem (the DHT message layer) that must
be hand-written regardless of language choice. Nothing in the *wire
format* is Go-specific: the protocol remains implementable in any
language; Go is the reference, not a requirement.

## 2. Terminology

| Term              | Definition                                                                 |
|-------------------|----------------------------------------------------------------------------|
| Name              | A dotted string such as `www.alice.foo`, resolvable within freens.        |
| Alias             | The human-readable leftmost-adjacent component that identifies a TLD (`foo`). Purely a human-facing pointer; the underlying identity is the TLD ID. |
| TLD               | A top-level namespace in freens. Its canonical identity is a public key hash (TLD ID); it may carry one claimed alias. |
| TLD ID            | `SHA-256(TLD_owner_public_key)` — 32 bytes. The self-certifying identifier of a TLD. |
| Wire name         | The canonical binary encoding of a name used for hashing and signing.      |
| Record            | A signed set of resource records (RRset) plus ownership metadata for one name. |
| Authority chain   | The sequence of delegations from a TLD key down to a record that establishes which key is allowed to sign that record. |
| Owner             | The entity controlling the private key currently authorized by the authority chain for a name. |
| Peer / Node       | A freens client participating in the DHT. Every client is a node by default. |
| Node ID           | `SHA-256(node_public_key)` — 32 bytes; used in the Kademlia XOR metric.    |
| Witness           | A node that co-signes timestamp attestations for alias claims.             |
| Resolver          | The local DNS-compatible service (default `127.0.0.1:53`).                 |
| Claim             | The dispute-resolved mapping from an alias to a TLD ID.                    |
| Conventional DNS  | The ICANN-coordinated DNS, used as fallback.                               |

## 3. Naming Model

### 3.1 Self-certifying TLDs

The fundamental object is the **TLD**. A TLD is created by generating a
fresh Ed25519 keypair. The canonical identity of the TLD is:

```
TLD_ID = SHA-256(PK_tld)        # 32 bytes
```

where `PK_tld` is the 32-byte Ed25519 public key. This identity is
*intrinsic*: because the ID is derived from the key, there is no
collision and no allocation authority. Two different keys yield two
different TLDs, always.

A TLD owner may create **arbitrary subdomains** under its TLD with no
further protocol action:

```
alice.foo        -> owned by (or delegated by) PK_tld
mycompany.foo    -> owned by (or delegated by) PK_tld
whatever.laurent -> owned by (or delegated by) PK_laurent
```

### 3.2 Aliases: the human-readable layer

Raw TLD IDs are ugly for humans. freens therefore has an **alias
layer**: a mapping from a human-readable string to a TLD ID.

```
foo  ->  SHA-256(PK_tld) = 7f4a9c3b...
```

The alias layer is *not* authoritative for identity — it is a
convenience pointer. Resolution always terminates in key verification:
even if an attacker corrupts the alias mapping, they cannot forge
records under the target TLD because they lack `SK_tld`. The worst an
alias attack can do is redirect `foo` to a *different* TLD (a
homograph/spoofing concern, mitigated by the claim mechanism in
Section 7 and addressed again in Section 11).

Aliases MUST satisfy:

- Length: 1–63 bytes.
- Allowed characters: `a`–`z`, `0`–`9`, `-` (LDH rule, RFC 5890 §3.2),
  plus IDNA2008 U-labels for internationalized aliases.
- MUST NOT be all-numeric, MUST NOT begin or end with `-`.
- Normalization: lowercase ASCII; IDNA U-labels normalized via
  IDNA2008 (UTS #46 transitional=false, `useSTD3Rules=true`).

### 3.3 Name decomposition and wire format

A displayed name decomposes as:

```
www.alice.foo
 ^^^^^^^^^ ^^^
 labels    alias

labels = ["www", "alice"]      # path under the TLD, TLD-adjacent last
alias  = "foo"
tld_id = 32-byte TLD ID (looked up via the alias claim, or pinned)
```

**Wire name** encoding (used for hashing, DHT keys, and signatures):

```
wire_name = concat( for each label from TLD-adjacent to most-specific:
                      0x01 || uint8(len) || label_bytes )
            || 0x00
            || tld_id            # 32 raw bytes
```

Labels are stored in *reverse* order (TLD-adjacent first), mirroring
DNS's canonical ordering. Example:

```
wire_name("www.alice.foo") =
  0x01 05 "alice" 0x01 03 "www" 0x00 <32-byte tld_id of foo>
```

**DHT storage keys** (32 bytes each):

```
K_tld   = tld_id                                        # TLD record
K_name  = SHA-256(0x02 || wire_name)                    # name records
K_claim = SHA-256(0x03 || "claim:" || alias_bytes)      # alias claims
```

### 3.4 Delegation and authority chains

Authority flows from the TLD key downward, exactly like DNS zone
delegation but with signatures instead of registrar hierarchies:

1. The **TLD record** (stored at `K_tld`) is signed by `PK_tld`.
2. A record at `alice.foo` is either:
   - signed directly by `PK_tld` (owner = TLD), or
   - a **delegation**: signed by `PK_tld`, containing
     `delegation = PK_alice`. From then on, records at `alice.foo` and
     *all names beneath it* MUST be signed by `PK_alice` (or by a
     further-delegated key).
3. `www.alice.foo` is signed by `PK_alice` (or delegated further).

To verify any record, a resolver walks the **authority chain** from the
TLD record down, checking each hop's signature and sequence number. A
chain is valid if and only if every hop verifies. Maximum chain depth
(name labels) is 8.

Delegation is how "domains" under a TLD become independently ownable,
transferable objects (Section 9).

### 3.5 What "owning a name" means

Owning `alice.foo` means: controlling the private key that the currently
highest-sequence valid delegation for `alice.foo` points to. Nothing
more, nothing less. There is no out-of-band ownership database to
consult, agree with, or litigate in the protocol.

## 4. Record Format

### 4.1 Record structure

A freens record is a CBOR map. Field numbers are stable and part of the
protocol.

```cbor
FREENS_Record = {
  1  : version          ; uint, MUST be 1
  2  : name             ; bstr, wire_name (Section 3.3), TLD-adjacent-first
  3  : owner            ; bstr(32), Ed25519 public key currently authorized
  4  : sequence         ; uint, strictly increasing per name
  5  : created          ; uint, unix time seconds
  6  : expires          ; uint, unix time seconds; created <= expires
  7  : rrset            ; array of RR (Section 4.3), MAY be empty
  8  : delegation?      ; bstr(32), new Ed25519 public key taking over
                        ;   this name AND its subtree
  9  : prev_hash?       ; bstr(32), SHA-256 of previous record's signed
                        ;   envelope (transfer chain; Section 9.3)
  10 : recovery?        ; RecoveryPolicy (Section 5.4)
  11 : claim?           ; AliasClaim (Section 7.3), TLD records only
  12 : revoke?          ; true: this record revokes the name (Section 9.5)
}

SignedEnvelope = {
  1 : record            ; FREENS_Record (canonical CBOR)
  2 : sig               ; bstr(64), Ed25519 signature over the canonical
                        ;   CBOR encoding of `record`
  3 : signer            ; bstr(32), public key that produced `sig`
}
```

The object stored in and served from the DHT is the `SignedEnvelope`.

### 4.2 Canonical encoding and signing

Signing is defined over **deterministic CBOR** per RFC 8949 §4.2:

- Map keys encoded as minimal-length uints; map entries sorted by
  canonical CBOR key ordering (shorter encodings first, then
  lexicographic bytewise — with integer keys 1–12 this is simply
  ascending numeric order).
- Integers use minimum-length encoding; negative integers are not used.
- All lengths definite; no indefinite-length items.
- No floating-point values anywhere in the record (MUST NOT).
- Text strings are UTF-8, NFC-normalized where human-supplied.
- No duplicate map keys (MUST NOT).

The signature input is the canonical CBOR encoding of the inner
`FREENS_Record` map **with fields `claim` (11) and `revoke` (12) treated
as ordinary content** (they are signed like everything else).

Record hash (used for `prev_hash` and auditing):

```
H_record = SHA-256(canonical_cbor(SignedEnvelope))
```

### 4.3 Resource records (RRset)

Each RR is a CBOR array of exactly 3 elements:

```cbor
RR = [ type: uint, ttl: uint, rdata: bstr ]
```

`type` reuses DNS RR type codes (IANA DNS parameters registry):

| Type | Code | rdata format                                        |
|------|------|-----------------------------------------------------|
| A    | 1    | 4 raw bytes                                          |
| AAAA | 28   | 16 raw bytes                                         |
| NS   | 2    | wire_name of target (freens) or DNS name (hybrid)    |
| CNAME| 5    | wire_name or DNS name                                |
| TXT  | 16   | opaque bytes; RECOMMENDED UTF-8, ≤ 4096 bytes        |
| MX   | 15   | uint16 preference || wire_name/DNS name              |
| SRV  | 33   | uint16 prio, uint16 weight, uint16 port, target      |
| SSHFP| 44   | algorithm, fingerprint-type, fingerprint             |
| TLSA | 52   | usage, selector, matching-type, certificate data     |
| CAA  | 257  | flags, tag, value                                    |
| TLSCA| 65280| DER X.509 owner-CA certificate (apex records only; §9.5) |

Unknown/unsupported type codes MUST be preserved verbatim by clients
(opaque forwarding), as in DNS.

Constraints:

- `ttl` is in seconds; 0 < `ttl` ≤ `RECORD_MAX_TTL` (Appendix A).
- At most 64 RRs per record.
- Multiple RRs of the same type in one record form that type's RRset and
  replace any prior RRset of that type atomically.

### 4.4 Validity rules

A `SignedEnvelope` is **valid for name N at time T** iff:

1. `version == 1` and all structural constraints above hold.
2. `sig` verifies under `signer` against the canonical CBOR of `record`.
3. `signer` is authorized for N: either `signer` satisfies the authority
   chain (Section 3.4), or the record *is* the delegation/toplevel hop
   that establishes that authorization.
4. `sequence` is strictly greater than that of any other valid,
   non-expired record for N previously accepted (Section 9.2).
5. `created <= T < expires`.
6. Name equality is bytewise on `wire_name` (which embeds `tld_id`), so
   aliases never affect validity.

## 5. Cryptography

### 5.1 Algorithms

| Purpose            | Algorithm      | Reference  | Parameters |
|--------------------|----------------|------------|------------|
| Signatures         | Ed25519 (PureEdDSA) | RFC 8032 | 32-byte keys, 64-byte signatures |
| Hashing            | SHA-256        | FIPS 180-4 | 32-byte digests |
| Canonical encoding | CBOR (deterministic) | RFC 8949 §4.2 | |
| Key derivation     | none required  |            | keys generated with a CSPRNG |

Ed25519 signing MUST use RFC 8032 canonical (non-malleable) form;
verifiers SHOULD reject non-canonical encodings.

There is deliberately **no algorithm agility registry in v1**. A future
version may add algorithm identifiers; the cost of a v2 migration is a
record version bump, which is itself gated by signature validity.

### 5.2 Key identity

All keys (TLD, node, witness, delegation, recovery) are Ed25519
keypairs. A key's identity is always `SHA-256(public_key)` when used as
an ID (TLD ID, Node ID), and the raw public key when used for
verification.

### 5.3 Key hierarchy and wallet safety

Implementations SHOULD support hierarchical key derivation (e.g.,
BIP32-style Ed25519 slides or simple per-purpose derivation
`SK_purpose = SHA-256(SK_root || "freens:" || purpose)`) so that a
single root secret can back TLD keys, node keys, and recovery keys
without key reuse. Key reuse across roles is NOT RECOMMENDED but not
forbidden.

### 5.4 Recovery policy

A record MAY embed a recovery policy:

```cbor
RecoveryPolicy = {
  1 : threshold    ; uint, e.g. 2
  2 : keys         ; array of bstr(32), e.g. 3 recovery public keys
  3 : timelock     ; uint, seconds a recovery operation waits before
                    ;   taking effect (default 259200 = 72 h)
}
```

The default policy shipped by implementations SHOULD be **2-of-3
multisig**: a primary key plus two recovery keys stored separately
(e.g., one printed offline, one in a second device/location).

Semantics (Section 9.4): any `threshold`-of-`keys` can, after
`timelock`, replace the primary key. During the timelock window the
current primary key can cancel the recovery and optionally rotate the
recovery set (protecting against a stolen recovery key).

## 6. DHT Layer

### 6.1 Overview

Record storage and lookup use a Kademlia-style DHT
[Maymounkov & Mazières, IPTPS 2002] with parameters in Appendix A.
No blockchain, no global ledger. The DHT provides:

- `PUT(SignedEnvelope)` — store a record at `K_name` / `K_tld`.
- `GET(key)` — retrieve the winning record for a key.

Every freens client participates by default ("anyone running the client
automatically contributes a node"). Clients MAY disable participation
(`--passive`), at the cost of relying on others.

### 6.2 Node identity and routing

- `Node ID = SHA-256(node_public_key)` (32 bytes).
- Distance metric: bitwise XOR of 256-bit IDs.
- Routing table: 256 k-buckets (one per bit prefix length), `K = 20`
  entries per bucket, standard Kademlia eviction (ping-oldest, replace
  on failure).
- Messages are signed at the RPC layer: every message carries the node
  public key and an Ed25519 signature over `(transaction_id || sender_id
  || recipient_id || payload)`. Node IDs are verified as
  `SHA-256(public_key)` on receipt. This makes address spoofing and ID
  forgery detectable.
- Transport: UDP. Default port 15353 (`FREENS_PORT`). Port is
  configurable; nodes advertise `(ip, port, node_pubkey)`.

### 6.3 RPC protocol

KRPC-like message envelope (CBOR):

```cbor
Message = {
  1 : y    ; "q" or "r" (query/response) ; "e" for error
  2 : t    ; bstr(<=16), transaction id
  3 : q    ; text, method name (queries only)
  4 : a    ; map, arguments / return values
  5 : id   ; bstr(32), sender node id
  6 : pk   ; bstr(32), sender node public key
  7 : sig  ; bstr(64), signature over canonical(t||id||peer_id||a)
}
```

Methods:

| Method       | Arguments (a)                                | Response (a)                                  |
|--------------|----------------------------------------------|-----------------------------------------------|
| `ping`       | `{}`                                         | `{}`                                          |
| `find_node`  | `{target: bstr(32)}`                         | `{nodes: [(ip, port, node_id, pk), ...]}` — K closest |
| `get`        | `{key: bstr(32)}`                            | `{envelope: SignedEnvelope}` or `{nodes: [...]}` |
| `put`        | `{token: bstr, envelope: SignedEnvelope}`    | `{}`                                          |
| `witness`    | `{claim_prefix_hash, claimant, ts, alias, tld_id, nonce, pow_hash}` | `{attestation: sig, difficulty}` (Section 7.4) |

Error codes: `301` generic, `302` invalid token, `303` invalid
signature, `304` stale record (sequence too low), `305` invalid record.

**Write tokens** (spoofed-STORE defense, as in BitTorrent DHT): to
`put`, a node first obtains a token from the target via `get`/`ping`;
tokens are `HMAC-SHA256(rotating_secret, peer_ip)` and rotate every
5 minutes, valid for the current and previous rotation.

### 6.4 Store and retrieve semantics

**PUT (publish/refresh):**

1. Owner (or any refresh helper) locates the `R = 8` closest nodes to
   `K_name` via iterative `find_node` with parallelism `ALPHA = 3`.
2. Obtains write tokens, then issues `put` to each.
3. Storing nodes verify (in order): token, envelope signature, record
   validity rules (Section 4.4 as checkable locally), sequence number
   vs. what they hold. They store only if the new record strictly wins:
   higher `sequence`, or same `sequence` but bytewise-greater `H_record`
   (tie-break for idempotent concurrent republication). A put landing
   at `K_claim` additionally passes the full Section 7.4 claim screen
   (claimant binding, PoW, corroborating witness quorum) before
   entering the store or the top-2 claim pool (v0.7.0: claim-space
   seeding of garbage claims was otherwise free). Two displacement
   restrictions apply against a LIVE incumbent (v0.7.0
   anti-censorship): a newcomer with `prev_hash` signed by a
   non-owner is accepted only as a Section 8.4 recovery with quorum
   evidence, and a newcomer WITHOUT `prev_hash` signed by a key other
   than the incumbent's owner is accepted only when the store's live
   PARENT record for the name authorizes that key (`parent.owner` or
   `parent.delegation` — the Section 8.3 delegated-republication
   path); anything else is rejected. An incumbent past
   `expires + EXPIRY_GRACE` is dead: the slot recycles freely.
4. Stored records are republished by the owner at `REFRESH_INTERVAL`
   (80% of time-to-expiry). Storing nodes evict at `expires + GRACE`
   (24 h grace for clock skew and network partitions).

**GET (lookup):**

1. Iterative Kademlia lookup on `K_name`; terminate on first node
   returning an envelope.
2. On completion (or early success), the client queries `GET_CLOSEST =
   4` of the closest reachable nodes for their envelopes and selects the
   winner by `(sequence desc, H_record desc)` — this is deterministic
   and convergent.
3. Full validity (authority chain) is verified client-side
   (Section 4.4). An envelope that fails verification is discarded even
   if it won the DHT race.

**Caching:** nodes along the lookup path MAY cache valid envelopes
(key = `K_name`) and answer `get` from cache subject to expiry. Caching
nodes never mutate envelopes (they are opaque + signature-protected).

### 6.5 What the DHT does *not* do

- It does not order transactions globally.
- It does not adjudicate alias races (that is Section 7).
- It does not guarantee storage of expired or never-refreshed records.

These are deliberate omissions: for everything except human aliases,
cryptographic validity fully determines the answer, and "the winner" is
a pure function of (sequence, hash) — no consensus required.

## 7. Registration and Collision Resolution

### 7.1 The problem

Suppose two parties generate keypairs and both claim the alias `foo`.
Both TLDs are cryptographically valid — that is the whole point of
self-certification. The alias string, unlike the TLD ID, is a *scarce
human-readable token*, so a deterministic rule is required. The options
considered:

| Option                    | Mechanism                          | Assessment |
|---------------------------|------------------------------------|------------|
| **First registration wins** (chosen) | network-visible timestamp ordering with witness quorum | No coins needed; requires (weak) time ordering; vulnerable to races and backdating without mitigations |
| Proof of work             | registering costs computation      | Good Sybil cost; alone, does not pick *between* two valid claims; folded into freens as a *cost* component |
| Proof of stake / deposit  | lock tokens to register            | Requires a token + ledger = reintroduces a blockchain and a market; rejected as default |
| Auction                   | names sold to highest bidder       | Recreates a centralized market, favors wealth, needs an auctioneer/ledger; rejected |
| Purely cryptographic names| name = `7f4a9c...` derived from key | Zero collision, zero squatting; but unusable by humans; kept as the *identity* layer (Section 3.1) |
| Hidden-name commit–reveal | two-phase register: witness a commitment `H(alias‖salt)`, reveal the alias after a delay | Defeats front-running observers; but freens claims already hide the alias from the storage layer (`K_claim` hashes it) — the one pre-publication disclosure is the witness RPC, narrowed by the `WITNESS_PRESENT_WINDOW` gate (§7.3); costs a second round trip, a mandatory commit–reveal delay and unrevealed-commit cleanup; deferred as a §7 v2 candidate, not rejected |

**Chosen default:** first-valid-registration-wins, where "first" is
established by (a) a **witness quorum** of DHT peers co-signing the
claim's timestamp, and (b) a **hashcash-style proof of work** that makes
mass alias squatting expensive and provides a deterministic, verifiable
tie-break. Stake, auctions, and ledger-based schemes remain possible
future extensions but are not part of v1.

The property delivered: for any two competing claims for the same
alias, *all honest clients compute the same winner deterministically*,
even if they observed the race differently — because ordering falls
back to public, verifiable data (PoW hash, then key hash), not on
observation order.

### 7.2 What is being claimed

Only **aliases** are scarce. TLD IDs, and all names under them, are
not. This shrinks the ordering problem to a single, thin map:

```
alias -> TLD_ID        (one winner per alias)
```

Everything else (`alice.foo`, `www.alice.foo`, ...) is collision-free
by construction (Section 3.1, 3.4).

### 7.3 Alias claim record

```cbor
AliasClaim = {
  1 : alias        ; text, normalized per Section 3.2
  2 : tld_id       ; bstr(32), the claimant's TLD
  3 : timestamp    ; uint, unix seconds, claimant-asserted
  4 : nonce        ; bstr(<=128), proof-of-work nonce
  5 : claimant_pk  ; bstr(32), = TLD public key (tld_id = SHA-256 of it)
  6 : pow_hash     ; bstr(32), SHA-256 of the claim prefix (below)
  7 : witnesses    ; array of WitnessAttestation
}

WitnessAttestation = {
  1 : node_id      ; bstr(32)
  2 : node_pk      ; bstr(32)
  3 : ts           ; uint, witness's own timestamp
  4 : sig          ; bstr(64): node_pk signs canonical
                    ;   ("freens-witness-v2", claim_prefix_hash, ts)
}
```

The signed `claim_prefix_hash` is `SHA-256(prefix)` — a commitment to the
FULL claim identity `{alias, tld_id, timestamp, claimant_pk}` (the PoW
prefix of Section 7.3). v2 (v0.7.0 security fix): the v1 form signed the
identity fields but let attestations gathered for one claim be replayed
against a re-mined, backdated claim of the same alias; binding the hash
(which covers the timestamp) makes each attestation valid for exactly
the claim it was issued for.

**Proof of work:** let `prefix` be the canonical CBOR of fields
`{1..5}` of `AliasClaim`. Miners search `nonce` until:

```
pow_hash = SHA-256(prefix || nonce)  <  2^(256 - D)
```

`D` (leading zero bits required) is a network parameter, initial value
24, retargeted per Appendix A.4 to hold the global claim rate near one
per 10 minutes. Verification is a single hash — cheap for resolvers,
expensive for squatters: at D=24, one claim ≈ 16.7 MH (minutes on a
laptop; thousands of aliases = real cost, while `alice.foo`-under-your-
own-TLD remains free).

**Witness quorum:** a claim is *attested* when it carries valid
v2 signatures from `W = 5` distinct CORROBORATING witnesses. Two
conditions make a witness count (v0.7.0):

1. *Membership* (when the verifier can name it): the witness node ID is
   among the `WITNESS_SET = 8` closest nodes to
   `K_claim = SHA-256(0x03 || "claim:" || alias)` as the verifier's
   converged lookup observed them. A verifier whose reachable view holds
   fewer than `WITNESS_SET` nodes (small fleets, partitions, young
   routing tables) MUST NOT enforce membership against a partial set —
   it skips the restriction rather than reject honest witnesses. The
   converged set INCLUDES the verifying node's own ID (v0.14.1: a walk
   from a node never reaches that node itself, yet it is a member of
   the network's closest set like any other node — excluding it made
   membership unsatisfiable for every claim the node had witnessed).
   Membership is also horizon-bounded (v0.14.1): it is enforced only
   while the claim is inside its §7.5 contest window
   (`now - claim.ts < CONTEST_WINDOW`); a claim past the window is
   FINAL per §7.5(b), its attestations are historical evidence
   (signatures + the corroboration band are timeless), and
   re-litigating them against the verifier's CURRENT routing view
   would let witness departure or ordinary keyspace churn kill mature
   names — against §8's rule that ownership lives and dies with the
   OWNER's liveness, not the witnesses'. The residual — an adversary
   grinding sybil IDs into the true witness set AND holding them for
   the whole contest window — is the §12 Sybil bound, priced by
   grinding cost plus 48 h of presence.
2. *Corroboration band*: the witness's own attestation timestamp lies
   within `[claim.ts - SKEW_TOLERANCE, claim.ts + WITNESS_PRESENT_WINDOW +
   SKEW_TOLERANCE]` — the honest witnessing window (signed at mining
   time, or re-presented during register's cooldown-safe retries, with
   clock slack on both ends). An attestation dated outside the band is
   not evidence for the claim's asserted time and does not count.

Witnesses MUST verify the PoW before signing (the witness RPC carries the
claim's `nonce` and `pow_hash` for exactly this purpose) and MUST
only sign one claim per alias per `WITNESS_COOLDOWN` (1 h) unless a
strictly earlier-ordered claim appears (they may sign both; ordering is
computed by verifiers, not witnesses — conservatively refusing the
second claim is also conformant, as the reference implementation does).
A witness also refuses claims whose asserted timestamp is future-dated
beyond `SKEW_TOLERANCE` or older than `WITNESS_PRESENT_WINDOW`
(5 min; the anti-forgery gate: ordering is earliest-first, so an
arbitrarily old claim would otherwise out-order every honest one
forever).

**Why so tight (v0.9.0, anti-sniping):** the age gate was formerly
`WITNESS_COOLDOWN` (1 h). But the witness RPC necessarily discloses the
alias to its witness set — the alias is inside the PoW prefix a witness
must re-verify before signing — so a listener on the witness round could
mine a competing claim backdated to the gate's edge and out-order the
victim under §7.4's earliest-first rule. Such a steal is feasible only
while the accepted age exceeds the victim's mine-plus-witness latency
(the sniper needs `ts_sniper < ts_victim ≈ now − victim_elapsed`, with
`ts_sniper ≥ now − window`); an honest registration — mining at the
initial difficulty plus the 3×10 s retry cycle — completes well inside
5 minutes, so `WITNESS_PRESENT_WINDOW` covers every honest
re-presentation while shrinking the backdate margin twelvefold. The
corroboration band (above) tracks the same window so the verifier side
accepts exactly what the witness side would sign; late cross-run
retries re-mine rather than re-present. (Claims are otherwise hidden
from the network: they are stored at `K_claim = SHA-256(...)` of the
alias, so storing nodes and passive observers never learn it before
publication.) Closing the residual — a listener who can complete a
fresh mine faster than the victim, needing no backdating at all —
would require commit–reveal registration (see §7.1), deferred as a v2
candidate.

**Residual (documented):** against a verifier that cannot name the
witness set, an attacker forging a fully self-consistent quorum (own
keys, in-band backdated clocks, valid PoW) still wins the Section 7.4
ordering for a backdated claim. The v2 binding, the band, and the
membership gate raise this from a zero-cost attack to a Sybil attack
priced by NodeID grinding against the real witness set; closing it
entirely requires a network dense enough that converged lookups always
name the `WITNESS_SET`.

### 7.4 Registration procedure

To claim alias `foo` for a new TLD:

1. Generate Ed25519 TLD keypair; compute `tld_id`.
2. Mine the PoW (Section 7.3) at current difficulty `D`.
3. Iteratively find the `WITNESS_SET` closest nodes to `K_claim`; send
   each a `witness` RPC with `(prefix_hash, claimant_pk, timestamp)`
   plus the claim's `nonce`, `pow_hash`, `alias` and `tld_id` (the
   witness re-derives the prefix hash from the identity fields and
   verifies the PoW before signing; see Section 6.3).
4. Assemble the claim with `≥ W` attestations.
5. Publish the TLD record (containing the claim in field 11) and `put`
   the claim envelope at `K_claim` to the `R` closest nodes.

Resolution of a contested alias (verifier side):

1. `get(K_claim)`; collect **all** competing claims nodes offer
   (storing nodes keep the top 2 by ordering; clients SHOULD probe
   `GET_CLOSEST` nodes and merge).
2. Filter: structurally valid, PoW valid, witness quorum valid
   (v2 attestations, corroboration band, and — when the collecting
   walk reached `WITNESS_SET` or more nodes — membership in the
   converged witness set it observed).
3. **Order** surviving claims by the lexicographic tuple, ascending:

```
( timestamp, pow_hash, tld_id )
```

   i.e., earliest asserted time wins; ties broken by lower PoW hash
   (a public lottery), then by lower TLD ID. This total order is
   computable by any client from claim contents alone — convergence
   without consensus.
4. The winner's `tld_id` is the resolution of the alias. Cache per
   Section 10.4.

Witness timestamps, not claimant timestamps, are the honest ordering
signal; the claimant `timestamp` is used only as the first tie-break
because it is in the signed+PoW-covered prefix. A claim with
backdated `timestamp` gains nothing *that survives verification*:
witnesses attest what they saw and when (v2 attestations bind the
exact claim identity via the prefix hash, and the corroboration band
drops attestations inconsistent with the asserted time), and the
`(pow_hash, tld_id)` tail is uncheatable. See the documented residual
in Section 7.3 for the sparse-view limit of this argument.

### 7.5 Honest behavior for races

If two claims for one alias are created within `SKEW_TOLERANCE` (60 s)
of each other, clients MUST NOT treat either as final until either
(a) one expires, or (b) the deterministic order picks a winner and no
earlier-ordered valid claim appears within `CONTEST_WINDOW` (48 h).
Resolvers MAY resolve contested aliases to the current deterministic
winner while flagging the name as contested in diagnostics.

### 7.6 Cost summary

| Action                            | Cost                          |
|-----------------------------------|-------------------------------|
| Create a TLD (key generation)     | $0                            |
| Register subdomains under your TLD| $0 (a signature)              |
| Claim a human alias               | $0 + PoW electricity + witness round-trips |
| Mass squatting (1000 aliases)     | 1000 × PoW + witness scrutiny |

## 8. Ownership Lifecycle

### 8.1 Create (TLD)

Generate keypair → (optionally) claim alias → publish TLD record at
`K_tld`. The TLD record's `rrset` is usually empty; the point is the
signed existence + claim anchoring.

### 8.2 Update

Owner signs a new record for the name with `sequence = old + 1`, new
`created`/`expires`, and the new `rrset`. Publishes to `R` closest
nodes. Atomic per name: there is one winning record per `K_name`.

Rules:

- `sequence` increments by exactly 1 (gaps allowed only after expiry +
  re-creation by the same authority chain, where sequence resets to 1).
- A newer-sequence record fully replaces the older RRsets; there are no
  partial updates in v1.
- Republish/refresh at 80% of lifetime; otherwise the record expires
  network-wide.

### 8.3 Transfer

Transferring `alice.foo` means re-pointing its authority, not editing a
database:

```
transfer record for alice.foo:
  owner:      B82F1...            (new owner key)
  delegation: B82F1...            (subtree authority follows)
  prev_hash:  H_record(previous signed envelope)
  sequence:   prev + 1
  signature:  by A7C91...         (current owner key)
```

The network accepts the new record because the previous owner — whose
key the current authority chain names — signed it. After the transfer,
only `B82F1...` can sign further updates. `prev_hash` links the
transfer into an auditable chain so third parties can verify the
hand-off history offline.

For a whole-TLD transfer, the same operation on the TLD record
transfers the alias and all undelegated names at once.

### 8.4 Recovery

If the primary key is lost but a `recovery` policy exists:

1. Any `threshold`-of-`keys` sign a recovery declaration: `(name,
   new_primary_pk, execute_not_before = now + timelock)`, published like
   any record (sequence +1, `recovery` fields updated).
2. During the `timelock` (default 72 h), the *current* primary key MAY
   cancel by publishing a higher-sequence normal record (and SHOULD
   also rotate the recovery keys — this defeats a single stolen
   recovery key).
3. After the timelock elapses with no cancellation, the recovery record
   takes effect and the new primary key owns the name.

Losing the primary key with **no** recovery policy means the name
cannot be re-pointered; after expiry it disappears and (for aliases)
the alias becomes claimable again after `ALIAS_REUSE_DELAY` (30 days
past the claim's own expiry).

**Reuse window (v0.8.0 — enforcement of `ALIAS_REUSE_DELAY`).** For
`ALIAS_REUSE_DELAY` past a claim carrier's signed `expires`, the alias
is in a *reuse window* during which new claims for it are not served.
The evidence (the "tombstone") is the EXPIRED CLAIM ENVELOPE ITSELF —
carrier signature, claimant binding, PoW, and the witness attestations
are all timeless and verify identically after death, so no new wire
format is needed. Storing nodes retain expired claim envelopes in their
§7.4 top-2 pools until `expires + ALIAS_REUSE_DELAY` (bounded storage,
persisted across restarts, best-effort availability like every DHT
value), and collectors re-offer them to verifiers. During an open
window:

- **witnesses** refuse to co-sign a *different* claim for the alias
  (error 301 "alias in reuse window"; the refusal is classified apart
  from cooldown/throttle so registrants learn to retry after the
  window, not to add peers);
- **storing nodes** refuse a `put` at `K_claim` carrying a *different*
  claim identity while a verified tombstone's window is open. A carrier
  of the tombstone's OWN claim identity is always accepted (v0.9.1):
  only the claimant key can sign it, and it embeds the exact claim —
  same PoW, same attestations — that registered the alias, so whether
  it overlaps the dead lease (a renewal) or post-dates it (a
  resurrection after a lapse) it is ownership continuity, not a
  re-claim. (v0.8.0 refused the resurrection case; found live on the
  LAN fleet 2026-08-22 that this locked every alias whose auto-renewal
  arrived one tick late — the pools retain every dead generation, so
  after the first generation's death even perfectly-overlapping later
  renewals were refused against the older tombstone, deadlocking the
  whole namespace into `ALIAS_REUSE_DELAY`.)
- **resolvers** select no winner for the alias (NXDOMAIN) while a
  verified tombstone's window is open and no surviving claim is
  *continuity* with the dead lease: either a carrier created before
  the tombstone's `expires` (an unbroken renewal chain) or a carrier
  of the tombstone's own claim identity (the claimant re-asserting
  its lapsed lease; v0.9.1 — same reasoning as the storing-node rule
  above).

A carrier with `revoke = true` (§8.5, deliberate death) is NOT a
tombstone. Tombstone quorum verification does not apply `WITNESS_SET`
membership (the converged set names today's closest nodes and churns
over a 30-day window); binding, distinctness, and the corroboration
band still apply, and every consumer re-verifies the full content — a
PoW-valid but quorum-less fabrication pooled by a rogue node must not
lock an alias. Enforcement is best-effort at the availability of a
retained envelope: a network that retains no copy of the dead claim
cannot distinguish the window (the same R-replication availability
argument as record storage).

### 8.5 Revoke

A record with `revoke = true` and empty `rrset` marks the name
deliberately dead (as opposed to expired). Revoked names MAY be
un-revoked by the owner before expiry via a newer sequence.

### 8.6 Rotate (key hygiene)

Rotation = transfer to a fresh key (Section 8.3), optionally in the
same record as a normal update. Implementations SHOULD encourage
rotation and SHOULD make delegation-style rotation cheap (one record
per level of the chain affected).

## 9. Local DNS Resolver

### 9.1 Deployment model

The freens client runs a DNS resolver on **`127.0.0.1:53`** (UDP +
TCP). Applications, browsers, and OS stub resolvers point at it (or it
is installed as the system resolver). Existing software requires **zero
modification**.

If the OS forbids binding port 53 unprivileged, implementations bind a
high port and provide documented forwarding recipes (`iptables`,
systemd socket units, or a small setuid launcher). Implementations
SHOULD auto-detect and guide the user. (Windows has no privileged-port
concept: the reference implementation binds `127.0.0.1:53` directly
there and points the network adapters' DNS at it; the Linux redirect
recipes do not apply.)

### 9.2 Resolution algorithm

For an incoming DNS question `Q` for name `N`:

1. Split `N` into `(labels, alias_candidate)`.
2. Consult the routing table (9.3) for `alias_candidate`.
3. **freens route:** resolve the alias claim → `tld_id` → walk authority
   chain → collect winning record → answer `Q` from its `rrset`,
   mapping types 1:1 to DNS. If the name or type is absent, return
   NXDOMAIN/NODATA (with negative caching, 60 s).
4. **conventional route:** forward `Q` verbatim to the configured
   upstream recursive resolvers, over the same protocol the client used
   (UDP/TCP; EDNS0 passthrough). Implementations SHOULD support
   DNSSEC-validating or encrypted upstreams (DoT/DoH).
5. **freens-first mode:** try freens; on NXDOMAIN, fall through to
   conventional DNS and answer from there.

TTLs in DNS responses: `min(RR.ttl, expires - now)` capped by
`RESPONSE_TTL_CAP` (Appendix A).

### 9.3 Routing table

Config file (default path `/etc/freens/resolver.conf`, XDG equivalent
on Windows/macOS):

```ini
[listen]
udp = 127.0.0.1:53
tcp = 127.0.0.1:53

[upstream]              ; conventional DNS forwarders
servers = 9.9.9.9, 149.112.112.112
doh = https://dns.quad9.net/dns-query

[tld-routes]
; route = freens | dns | freens-first | dns-first | deny
; default is dns-first: safe, non-surprising
*     = dns-first
foo   = freens
laurent = freens
example = deny

[alias-pins]            ; pin aliases to TLD IDs, bypassing claims
; foo = <base32 tld_id>
```

Semantics:

- `dns-first`: ask conventional DNS first; on NXDOMAIN, try freens.
- `freens-first`: ask freens first; on miss, fall through to DNS.
- `freens`: freens only.
- `deny`: refuse (REFUSED), for known-bad or policy-blocked TLDs.
- `alias-pins` let a user or vendor ship **pinned** alias→TLD mappings
  (e.g., a software distributor pinning its own TLD), immune to claim
  races. Pinning is local policy, never a protocol assertion.

**ICANN collision policy:** if an alias equals an ICANN gTLD (e.g.,
someone claims `com` or a future ICANN string collides with an old
freens alias), the *default* `dns-first` for `*` guarantees freens
never silently shadows existing internet names. Users opt into
`freens`/`freens-first` per TLD deliberately.

### 9.4 Browser/OS integration path

1. **Today:** local resolver (this section) — zero app changes.
2. **Today, with §9.5:** self-certifying TLS — `https://<name>.<alias>`
   works in stock browsers between freens users (§9.5).
3. **Near term:** browser extensions resolving freens names; DoH-style
   bootstrap (`resolver.freens.example` style well-known endpoints).
   Extensions MAY enforce the TLSA RR (§4.3) directly — native
   DANE-style validation that supersedes §9.5's local cross-
   certificates where available.
4. **Long term:** native OS/browser recognition of the freens
   namespace, at which point freens stops being merely parallel.

This spec normatively defines stages 1–2.

### 9.5 Self-certifying TLS (HTTPS for freens names)

Stage-1 HTTPS for freens names, in stock browsers, with no central
CA. WebPKI cannot serve this namespace: CA/Browser Forum Baseline
Requirements restrict issuance to names under public suffixes, so no
public CA may ever issue for `blog.bob` — the name form itself is
excluded. freens replaces the trust anchor instead: **the certificate
authority for a freens namespace is the name owner**, and the CA
binding is distributed and authenticated by the same signed records
that carry the addresses.

The property delivered: when a freens user (running the daemon, §9.1)
opens `https://blog.bob`, the browser accepts the connection without
warnings or per-site exceptions, and the assurance is exactly *"this
server holds a key authorized by the owner of `bob`"* — the same
proposition resolution itself makes about addresses.

#### 9.5.1 Owner CA (name side)

The owner CA key is **derived**, not generated:

```
seed_tls = HKDF-SHA256(ikm = SK_tld_seed, salt = ∅,
                       info = "freens-tls-ca-v1", L = 32)
CA_key   = P-256 private key from seed_tls
           (deterministic; if seed_tls ≥ n, append a uint8 counter
           to info and re-derive — negligible probability)
```

Consequences (all deliberate):

- No new secret to back up — the CA restores from the name seed
  (§5.4, §8) alone.
- Transfer and rotation (§8.3, §8.6) re-key TLS for free: the new
  owner derives a different CA, and old leaves die with their TTLs.
- Possession of `SK_tld` already implied total control of the
  namespace (§3.5); the derived CA grants no new power to the owner.

The CA certificate is self-signed (P-256, BasicConstraints CA=true,
KeyUsage keyCertSign|cRLSign, Subject CN = alias, validity
`TLS_CA_VALIDITY`). A self-declared nameConstraint on it is advisory
only — some verifiers do not apply constraints to anchors; the
enforcement point is the cross-cert (§9.5.4). P-256 rather than
Ed25519 because universal client compatibility is the entire point.

#### 9.5.2 Publication: the TLSCA RR

The apex record's rrset carries the CA binding:

```
TLSCA RR:  type  = 65280 (DNS private-use range)
           rdata = DER encoding of the X.509 owner-CA certificate
```

Semantics: *this CA is authorized to issue TLS certificates for this
alias and every name under it.* Exactly one TLSCA RR per record; a
TLSCA RR in a non-apex record MUST be ignored by verifiers. Atomic
RRset replacement (§4.3) governs updates — a sequence bump carrying a
new TLSCA rotates the CA. Revocation (§8.5) or expiry removes the
binding entirely (§9.5.4 refuses stale CAs).

#### 9.5.3 Leaf issuance (server side)

Implementations SHOULD issue leaf certificates on demand (SNI) for
names in the local keychain: SAN = the exact freens name (an apex leaf
MAY additionally carry `*.<alias>`), EKU serverAuth, lifetime ≤
`TLS_LEAF_TTL`, P-256, fresh key per leaf. No CRL/OCSP machinery:
short leaf lifetimes plus CA rotation (§8) are the revocation story.
Leaves and keys live under the daemon home; implementations MUST
provide an export verb (PEM) so non-daemon TLS endpoints (nginx, etc.)
can serve freens names.

#### 9.5.4 Trust sync (visitor side)

Each installation generates **one local root CA** at setup (P-256,
validity `TLS_CA_VALIDITY`, stored 0600 under the daemon home,
included in `backup`). It is unconstrained BY DESIGN: the daemon
already terminates this machine's name resolution (§9.1), so the
machine + daemon was already the trust boundary — the local root adds
no new trusted party. It MUST NOT leave the machine except in backups
(§5.4).

When the resolver answers a freens name through the full screened
path — §4.4 validity **plus** §7.4 claim screening, i.e. the same path
the DNS answers ride, never a raw DHT read — and the winning apex
record carries a TLSCA RR for which no valid cross-cert is cached, the
daemon cross-certifies the owner CA:

```
cross-cert, signed by the LOCAL ROOT:
    subject public key   = owner-CA public key (from the TLSCA RR)
    nameConstraints      = permittedSubtrees dNSName { <alias>, *.<alias> }
    NotAfter             = min(record.expires, now + TLS_CROSSCERT_TTL)
```

and installs it into the OS and browser trust stores. Cross-certs are
keyed by alias → tld_id; if a different tld_id wins §7.4 screening
(rotation/transfer), or the record is a tombstone (§8.5), the daemon
MUST re-issue or purge. The nameConstraint is what makes third-party
CA import safe: a stolen or malicious owner CA can misrepresent only
its own namespace — never another freens name, never a WebPKI name.

The browser then verifies a completely standard chain — leaf
(owner-CA-signed, presented by the server) → constrained intermediate
(local-root-signed) → local root (anchor) — with no browser
modification and **no per-friend imports**: the first name resolution
already delivered and authenticated every CA the visitor will need,
via the DHT.

#### 9.5.5 First-visit race

Browsers resolve before connecting; trust sync starts on that resolve,
but a trust-store update can lag the TLS handshake. The FIRST
`https://` visit to a never-before-seen namespace MAY fail once; a
retry succeeds. Implementations SHOULD pre-warm where possible (e.g.
sync when an alias is observed in store/status views) and MUST make
the one-retry behavior discoverable in user-facing copy. The §10.4
response cache can likewise delay a purge or refresh until its entry
expires (≤ RESPONSE_TTL_CAP); the cross-cert's own record-capped
lifetime bounds any staleness.

#### 9.5.6 Deployment and non-goals

- Trust-store mechanics: Linux — system bundle plus the NSS user DB
  (covers Chromium and Firefox); installing the local root is
  privileged (`setup` / `doctor --fix`), cross-cert updates SHOULD be
  unprivileged where the store allows (NSS user DB is user-writable).
  Other platforms: implementation-defined, same shape.
  IMPLEMENTATION NOTE (reference client, fleet-verified): Chromium's
  Chrome-Root-Store verifier ignores NSS non-anchor intermediates, so
  cross-certificates install as trusted-but-name-CONSTRAINED anchors
  (`certutil -t C,,`); constraint enforcement was verified on
  Chromium, NSS (vfychain), and OpenSSL, and a self-declared
  constraint on the owner CA (§9.5.1) backstops verifiers that skip
  anchor constraints.
- Stock-internet visitors (no daemon) get no automatic trust and see
  an ordinary self-signed warning. Serving them is stage 3 (§9.4).
- DANE-capable clients — and the §9.4 stage-3 extension — MAY use the
  TLSA RR (§4.3) against the record directly; §9.5 is the
  stock-browser bridge, not a DANE replacement.
- No protection against a malicious NAME OWNER (same as WebPKI DV);
  no certificates for IP literals; WebPKI names are unreachable by
  construction (nameConstraints).

### 9.6 DNS over HTTPS (DoH)

RFC 8484 support in BOTH directions, introduced v0.14.0. Each
direction is an independent one-line switch in `freens.conf`; both
default OFF so an upgrade changes nothing until the operator asks.

#### 9.6.1 Encrypted upstream

```
  [upstream]
  servers = 9.9.9.9, 1.1.1.1          ; stays configured as the fallback
  doh = https://9.9.9.9/dns-query     ; when set, upstreams are DoH-first
```

When `doh` is set, every §9.2 step-4 forward goes out as one RFC 8484
POST (`application/dns-message`); on ANY DoH failure (network, HTTP
4xx/5xx, malformed reply) the query is retried over the `servers`
list — enabling DoH MUST NOT reduce availability. freens names never
ride this path (§9.2 keeps them on the DHT); DoH here only protects
the conventional-DNS traffic from passive observers on the local
segment and at the recursive resolver.

BOOTSTRAP RULE (normative): the DoH endpoint's own hostname, when the
endpoint is not an IP literal, MUST be resolved via the plaintext
`servers` — never via the OS resolver. Rationale: the standard wiring
points `resolv.conf` at this very daemon, so an OS-resolved bootstrap
dial loops back into the forwarder (self-deadlock, every forwarded
name SERVFAILs). Resolved addresses are pinned onto the connection
dialer; TLS verification continues to use the URL's hostname (SNI and
name check are unaffected by the pinned IP). Shipped presets are
IP-form URLs (`https://9.9.9.9/dns-query`, `https://1.1.1.1/dns-query`)
so the default configuration has nothing to bootstrap at all.

#### 9.6.2 Serving DoH (downstream)

```
  [doh]
  serve = true
```

When enabled, the local resolver answers RFC 8484 requests at
`https://<name>:8090/dns-query` — hosted on the freens-web listener
rather than a new port. The UI's existing infrastructure is the
feature: the §9.5 self-certifying leaf (a device trusts the box's
owner CA once, via `GET /api/doh/root.pem` or `freens trust-install`),
HTTP/2 via ALPN, and the LAN CIDR gate. Consequences:

  - The gate's default (the machine's private subnets) makes every
    install a LAN-scoped resolver by construction. Widening the gate
    (`allow = any`) widens DoH with it — an operator choosing that
    becomes a public resolver and inherits open-resolver etiquette.
  - `/dns-query` and `/api/doh/root.pem` are machine-facing: they are
    exempt from UI session auth and the CSRF header, never from the
    gate.
  - The HTTPS face relays raw DNS wire messages to the daemon's
    resolver over the admin socket; a down daemon answers SERVFAIL
    (a well-formed DNS message), never a bare HTTP error, so stub
    resolvers fail over honestly.
  - `[doh] serve` is re-read with a short cache: the switch (CLI or
    UI) takes effect without restarting either process.

GET (`?dns=` base64url) and POST are both served; the smallest answer
TTL drives `Cache-Control: max-age=`; bodies are capped at 64 KiB
(RFC 8484 §4.1 lets the server choose). DoH-served answers pass the
identical §9.2 resolution and §10.4 caching as the UDP/TCP faces —
DoH is a transport, not a different authority.

#### 9.6.3 Control surface

```
  freens doh                              # status
  freens doh upstream <quad9|cloudflare|google|URL|off>
  freens doh serve <on|off>
  freens doh test [name]                  # through the daemon relay
```

Both switches are lines in `freens.conf`; editors (CLI, webui Settings
page) MUST modify it by comment-preserving line surgery with an atomic
replace and a one-generation backup — never by regenerating the file
(operators keep notes in it). An upstream change applies to a running
daemon via the admin socket's `POST /reload` (hot upstream swap) so
"enable/disable" never costs a restart; daemons without the endpoint
fall back to "restart to apply".

Doctor treats both switches as warn-only checks (the upstream has its
plaintext fallback; the serve face is gate-bounded) — a DoH problem
MUST NOT paint the health unit red.


## 10. Security Considerations

### 10.1 Authentication model

Traditional DNS: *ask the hierarchy what IP belongs to this name* —
trust the path.

freens: *give me the signed record for this name and verify it
cryptographically* — trust the math.

A malicious peer cannot substitute `foo -> 6.6.6.6` when the legitimate
owner signed `foo -> 1.2.3.4`: the fake envelope fails signature
verification under the authority-chain key. Authentication of the
namespace does not require trusting individual peers. This holds for
records and TLD IDs; the alias layer is weaker (10.3).

### 10.2 Threat matrix

| Threat                          | Mechanism                                   | Mitigation |
|---------------------------------|---------------------------------------------|------------|
| Forged/altered records          | signature verification (Section 4.4)        | defeated |
| Replay of old records           | `sequence` monotonicity + `expires`         | defeated |
| Spoofed DHT STOREs              | write tokens + signed RPCs                  | defeated |
| Node ID forgery / spoofing      | Node ID = SHA-256(node key), signed RPCs    | defeated |
| Eclipse of a resolver           | attacker surrounds lookup path              | mitigated: `ALPHA` disjoint paths, `GET_CLOSEST` merge, `alias-pins`; not fully defeated (inherent to open DHTs) |
| Sybil flood of alias witnesses  | attacker mints many node IDs near `K_claim` | mitigated: PoW cost per claim + converged witness-set membership where the view can name it + pinned aliases; documented residual risk |
| Backdated claim timestamps      | v2 witness attestations (claim-bound) + corroboration band + witness-set membership (7.3) | defeated against honest witnesses; sparse-view residual documented (Sybil-priced) |
| Alias hijack via claim race     | two near-simultaneous claims                | deterministic ordering + contest window (7.5) |
| Key compromise                  | stolen primary key                          | recovery/rotation (8.4, 8.6); timelock cancel |
| Recovery-key theft              | 2-of-3 required; primary cancels in timelock| defeated for single theft |
| Storage attrition (records lost)| nodes churn, owner offline                  | replication R=8, refresh, grace; NOT defeated if owner never refreshes (by design: expired = gone) |
| Resolver→upstream tampering     | conventional fallback path                  | use DoT/DoH/DNSSEC upstreams (RECOMMENDED) |
| Homograph aliases (`paypa1.foo`)| human confusables                           | out of scope; client MAY display punycode/signal confusables |

### 10.2.1 Convergence model of the alias layer (documented)

The alias layer has NO strong first-seen: a witness's one-claim-per-
cooldown is local state, not consensus, and two partitions can
accumulate different quorums for one alias. Ordering is therefore a
CONVERGENCE mechanism, not an adjudication: verifiers merge the set of
competing claims storing nodes offer (top-2 pools, `GET_CLOSEST`
probes), apply the deterministic `(timestamp, pow_hash, tld_id)`
order, and treat a winner as final only after `CONTEST_WINDOW` with no
earlier-ordered valid claim appearing. A claim that was censored or
unreachable during its window can still surface later and displace a
younger winner — by design. Clients needing immediate finality use
`alias-pins` (9.3).

### 10.3 What aliases cannot defend

The alias map is the softest part of the system: it is protected by
PoW, witness quorums, deterministic ordering, and optional local pins —
not by proof of ownership (an alias points *to* ownership; it cannot
*be* ownership). Security-critical deployments SHOULD pin aliases
(9.3) or address TLDs by ID.

### 10.4 Caching rules

- Positive freens answers cached ≤ min(TTL, validity remaining).
- Positive answers MAY additionally be served STALE past that horizon —
  same bounds as serve-stale-while-revalidate in classical DNS — while a
  background refresh revalidates the entry, for at most a bounded window
  past expiry (reference implementation: 6 h — long enough that evening-
  to-morning idle gaps never cost the client a walk; the window only
  ever matters while the namespace is unreachable, where the last known
  good address beats none). The stale copy carries
  exactly the validation the fresh one had (it went through the same
  screened path when fetched) and a short TTL so clients re-ask soon.
  This is a latency guarantee, not a weaker trust model: the walk cost
  stops landing on the answering path, and a fresh outcome — positive OR
  negative (revocation, rotation, transfer) — replaces the entry as soon
  as the background walk completes. When the namespace is unreachable,
  the last known good address keeps being answered until the window
  closes (better an old address than none during an outage).
- Negative freens answers cached 60 s, marked unauthenticated, and
  NEVER served stale (a revoked name must go dark within TTL + 60 s).
- Alias claim winners cached per 7.5 (contested: 60 s; uncontested:
   6 h) — the re-consultation cadence of a contested winner bounds how
   long a challenge can go unanswered and is not extended by the
   serve-stale rule: the refresh re-consults at the same cadence, and
   the fresh winner replaces the entry.
- Cached envelopes are re-verified on use after fetch; verification
  results (not envelopes) may be cached for their validity period.

### 10.5 Privacy notes

- All DHT lookups are linkable to your IP by the peers you contact
  (same class of exposure as conventional DNS to recursive resolvers).
  A future work item is lookup privacy (query obfuscation, proxy
  lookups); v1 does not provide it.
- Record publishing is public-key authenticated; publishers seeking
  pseudonymity must use per-TLD fresh keys and avoid linking metadata.

### 10.6 TLS trust model (§9.5)

Server authentication under §9.5 is exactly as strong as freens
resolution, no stronger: the CA for a namespace is its owner key, and
the binding travels inside the signed record. A network attacker
without `SK_tld` cannot mint an acceptable certificate for the
namespace. An attacker who can lie to the resolver about records (a
compromised daemon, a corrupted DHT view) can misdirect TLS as well as
addresses — the trust boundary is the machine and its daemon,
unchanged from §9.1. The local root never leaves the machine;
cross-certificates are name-constrained to a single namespace, so a
compromised owner CA degrades only that owner's visitors, and WebPKI
names are unreachable by construction. Revocation is rotation
(§8.3/§8.6): a new owner key implies a new derived CA, and stale
cross-certs expire within `TLS_CROSSCERT_TTL`. A first-visit
TOFU-style latency window is inherent (§9.5.5).

## 11. Ownership versus Identity

The protocol establishes exactly one proposition:

> **"Key X controls `paypal.foo`."**

It cannot establish:

> **"Key X belongs to PayPal Inc."**

Nothing technically prevents `paypal.foo`, `microsoft.foo`,
`bankofamerica.foo` from being created and cryptographically owned by
anyone. This is not fundamentally different from today's DNS, where
confusingly similar names (`paypa1.com`, `paypal-login.example`) are
routinely registered. freens makes the split **explicit**:

- **Cryptographic ownership** — in-protocol, verifiable, complete.
- **Legal identity / trademark** — out-of-protocol, must come from an
  external identity system.

Non-normative bridging mechanisms implementations MAY provide:

- **Verification records:** a domain holder proves control of some
  external account (web page at a legacy HTTPS domain, social account,
  incorporated entity) via TXT-style challenges; clients render such
  proofs as badges, never as protocol truth.
- **Web-of-trust attestations:** third-party keys sign statements
  binding a freens name to an identity; resolution UIs may surface
  these, clearly labeled as opinions.
- **Vendor pinning:** distributors pin well-known aliases (9.3).

Clients MUST NOT present cryptographic ownership as an identity claim.

## 12. Economics and Incentives

- **Registration: $0.** There is no registry to pay. Costs are a
  keypair, PoW electricity (aliases only), and bandwidth.
- **Infrastructure: contributed.** Every client is a DHT node storing
  `O(bucket_size × buckets)` routing entries plus cached/replicated
  envelopes (bounded, evictable). Storage per node is capped
  (`NODE_STORAGE_MAX`, Appendix A); nodes evict expired envelopes
  first, then LRU.
- **No tokens, no fees, no market.** v1 has deliberately no native
  currency. If economics are ever needed (e.g., to price alias
  witnesses), they must justify reintroducing a ledger — a bar this
  spec sets very high.
- **Freeloading is tolerated:** passive clients (no DHT participation)
  still resolve via peers, at the cost of the ecosystem's health.
  Implementations MAY throttle passive clients' `get` rates (the
  reference client applies one shared per-source-IP token bucket to
  `get`, `find_node` and `witness` alike — the latter being the most
  expensive unauthenticated request to serve: PoW verification plus an
  Ed25519 signature). Because per-source buckets cannot bound a
  distributed or spoofed-source flood (every distinct source draws a
  fresh bucket), implementations SHOULD additionally cap the AGGREGATE
  inbound packet rate ahead of signature verification, and bound how
  many concurrent iterative lookups one node runs (v0.9.2: the
  reference client enforces a single global pre-verify token bucket
  — excess datagrams are dropped silently, never answered, since
  answering an unverified source would aid amplification — plus a
  walk-concurrency semaphore whose refusal is a retryable "busy"
  error, never a negative answer).

## 13. Prior Art and Rationale

| System    | Approach                                      | freens difference |
|-----------|-----------------------------------------------|-------------------|
| Namecoin  | blockchain, first-wins by block order        | no blockchain; DHT lookup; PoW only as claim cost |
| ENS       | Ethereum smart contracts; names as NFTs      | no chain, no gas, no registrar contract |
| Handshake | blockchain, TLD auctions                     | no auctions; aliases by first-attested claim + PoW |
| GNS (GNUnet) | cryptographic zones + petnames            | strongest influence on Section 3; freens adds DNS-fallback resolver, witness ordering, and Kademlia lookup instead of zone flooding |
| IPFS/IPNS | self-certifying mutable names                | freens targets the DNS surface (A/AAAA/TXT/...) for app compatibility |
| `.onion`  | self-authenticated names (key = address)     | same principle for TLD IDs; freens adds the human alias layer |
| BitTorrent DHT | Kademlia for trackerless peers           | freens adopts its token-based STORE defense nearly verbatim |

**Why no blockchain:** a ledger buys *global total ordering* — needed
only for the alias map. Paying ledger costs (consensus, forks, miners,
finality delay) for the entire namespace would burden the 99% of
operations (record publish/lookup/verify) that need no ordering at all,
since cryptographic validity + `(sequence, hash)` determine winners
locally. The alias map instead uses witness quorums + PoW + a
deterministic public tie-break: weaker, but sufficient, and two orders
of magnitude cheaper to run.

## 14. Open Questions

1. **Un-revoke verb for apexes (found live, fleet test 2026-08-31).**
   §8.5 says un-revoke = "publish a newer record", but `register`
   re-mines a claim (new identity → blocked by the §8.4 reuse window)
   and renewal refuses revoked records. The correct carrier is the
   SAME claim identity at sequence+1 (the §8.4 v0.9.1 continuity
   rule); a dedicated `un-revoke` verb (fetch the surviving K_claim
   carrier, carry its witnesses, restore the RRset, bump sequence)
   needs specifying and wiring into §8.5.
2. **Registration ordering under adversarial timestamps.** The
   `(timestamp, pow_hash, tld_id)` order converges, but witness
   quorums near a contested `K_claim` can be Sybil-attacked. Options:
   witness-age weighting, cross-region witness sampling, or accepting
   a small ledger *only for aliases*. This is the fundamental design
   question and the most likely place v2 will differ from v1.
2. **Alias expiry and reuse.** Should popular aliases require periodic
   re-attestation to stay mapped, or does first-claim-last-forever
   recreate squatting at the alias layer? (Partially answered in
   v0.8.0: expired aliases now cool off inside a 30-day reuse window,
   §8.4; whether LIVE popular aliases should also require periodic
   re-attestation remains open.)
3. **Difficulty retargeting governance.** Appendix A.4 targets a claim
   rate, but someone must define the target; who, and how, without a
   central body?
4. **Negative answers.** Signed denials (an NSEC-analog) would make
   NXDOMAIN authenticated; deferred.
5. **Lookup privacy** (10.5).
6. **Browser integration timeline** (9.4 stages 2–3).
7. **Trademark conflict processes.** Deliberately out of protocol;
   ecosystem norms (pins, attestations) need real-world testing.
8. **DHT storage scaling.** If freens held billions of records, what
   fraction survive? Simulation + testnet data required before v2.

---

## Appendix A. Constants (normative)

| Name                  | Value    | Meaning                                    |
|-----------------------|----------|--------------------------------------------|
| `PROTO_VERSION`       | 1        | record `version` field                     |
| `MAX_LABELS`          | 8        | max name depth (labels under TLD)          |
| `FREENS_PORT`         | 15353    | default DHT UDP port                       |
| `K`                   | 20       | k-bucket size / closest-set size           |
| `ALPHA`               | 3        | lookup parallelism                         |
| `R`                   | 8        | replication factor for put                 |
| `GET_CLOSEST`         | 4        | nodes merged when selecting a winner       |
| `RPC_TIMEOUT`         | 5 s      | per-RPC timeout                            |
| `BUCKET_REFRESH`      | 15 min   | Kademlia bucket refresh interval           |
| `TOKEN_ROTATION`      | 5 min    | write-token epoch                          |
| `RECORD_DEFAULT_TTL`  | 86400 s  | default record lifetime (24 h)             |
| `RECORD_MAX_TTL`      | 2592000 s| max record lifetime (30 d)                 |
| `REFRESH_FRACTION`    | 0.8      | republish at 80% of lifetime               |
| `EXPIRY_GRACE`        | 86400 s  | store past expiry (skew/partitions)        |
| `W`                   | 5        | witness quorum size                        |
| `WITNESS_SET`         | 8        | candidate witnesses (closest to `K_claim`) |
| `WITNESS_COOLDOWN`    | 3600 s   | min spacing between a witness's signatures on competing claims |
| `WITNESS_PRESENT_WINDOW` | 300 s | max age of a claim ts a witness accepts (anti-forgery + anti-sniping gate, §7.3; v0.9.0, was `WITNESS_COOLDOWN`) |
| `POW_DIFFICULTY_INIT` | 24 bits  | initial claim PoW difficulty               |
| `POW_RETARGET_BLOCK`  | 256 claims | difficulty retarget interval (v0.8.0)   |
| `POW_TARGET_RATE`     | 1 / 600 s| target global claim rate                   |
| `SKEW_TOLERANCE`      | 60 s     | near-simultaneous claim window             |
| `CONTEST_WINDOW`      | 172800 s | contested-alias finalization wait          |
| `ALIAS_REUSE_DELAY`   | 2592000 s| alias re-claimable after expiry (§8.4 reuse window; enforced since v0.8.0) |
| `RECOVERY_TIMELOCK`   | 259200 s | default recovery delay (72 h)              |
| `RESPONSE_TTL_CAP`    | 3600 s   | max TTL emitted by resolver                |
| `NEG_TTL`             | 60 s     | negative caching                            |
| `NODE_STORAGE_MAX`    | 256 MiB  | per-node envelope storage cap              |
| `TLS_CA_VALIDITY`     | 10 y     | owner-CA and local-root cert lifetime (§9.5) |
| `TLS_LEAF_TTL`        | 604800 s | max leaf certificate lifetime (§9.5)       |
| `TLS_CROSSCERT_TTL`   | 604800 s | max cross-cert lifetime, ≤ record expiry (§9.5) |

### A.4 Difficulty retargeting

Every `POW_RETARGET_BLOCK` accepted claims, computing nodes adjust:

```
D_new = D_old + clamp(round(log2(target_block_span / actual_block_span)), -2, +2)
```

where `actual_block_span` is the wall-clock span of the completed retarget
block and `target_block_span = POW_RETARGET_BLOCK × 600 s` is the span the
target rate (one claim per `POW_TARGET_RATE` interval) would produce.
(v0.8.0 corrected form: the v0.1 draft inverted the ratio and compared a
whole block's span against the per-claim target, so a registration flood
lowered D to the floor while a quiet network ratcheted it up — the exact
opposite of the anti-squatting intent of §7.1; `round` replaces `ceil` so
span jitter at equilibrium does not bias D upward.) The control direction
is load-sensitive in the anti-squatting sense: a block that completes
FASTER than the target span — claims arriving too quickly, the
mass-squatting scenario — RAISES the difficulty; a slower block lowers
it, floored at `POW_DIFFICULTY_INIT`. `POW_RETARGET_BLOCK` is 256 claims
(≈ 42.7 h of target-rate registration per block; lowered from 2016 in
v0.8.0 so a retarget can fire on a network smaller than Bitcoin).

Nodes gossip the current `D` in `witness` responses; clients use the
median of the `GET_CLOSEST` nodes' advertised values. Forks in `D` are
harmless: claims are individually verified against *any* historically
valid `D ≥ POW_DIFFICULTY_INIT` recorded with the claim (`pow_bits` SHOULD
be recorded in `nonce`'s first byte for this purpose).

## Appendix B. Wire Format Summary

### B.1 DHT message envelope

```
Message (CBOR map):
  1: y    "q"|"r"|"e"
  2: t    bstr <=16          transaction id
  3: q    text               method (queries)
  4: a    map                payload
  5: id   bstr(32)           sender Node ID
  6: pk   bstr(32)           sender public key (id = SHA-256(pk))
  7: sig  bstr(64)           Ed25519 over canonical(t|id|peer_id|a)
```

### B.2 FREENS_Record field table

```
 1  version   uint = 1
 2  name      bstr       wire_name, TLD-adjacent first
 3  owner     bstr(32)   Ed25519 public key
 4  sequence  uint
 5  created   uint       unix seconds
 6  expires   uint       unix seconds
 7  rrset     array([uint type, uint ttl, bstr rdata])
 8  delegation? bstr(32)
 9  prev_hash?  bstr(32)
10  recovery?   {1: threshold, 2: [bstr(32)], 3: timelock}
11  claim?      AliasClaim (TLD records only)
12  revoke?     bool
```

### B.3 Ed25519 signature input

```
sig_input = canonical_cbor(FREENS_Record map)
```

Deterministic CBOR per RFC 8949 §4.2: minimal ints, definite lengths,
map keys sorted per canonical CBOR ordering (equivalently: ascending
integer key for this schema), no floats, no duplicate keys.

## Appendix C. Worked Examples

### C.1 Creating `foo`

1. Alice generates `SK_tld` / `PK_tld`; `tld_id = SHA-256(PK_tld)`.
2. Alice mines `nonce`: `SHA-256(cbor{alias:"foo",tld_id,ts,claimant_pk}
   || nonce) < 2^232`.
3. Alice's client finds the 8 nodes closest to
   `SHA-256(0x03 || "claim:foo")`; 5 of them verify the PoW and return
   signed attestations.
4. Alice assembles `AliasClaim`, embeds it in her TLD record (field
   11), signs the record with `SK_tld`, publishes at `K_tld = tld_id`
   and the claim envelope at `K_claim`.
5. Network state: `foo -> tld_id`, total cost $0 + minutes of PoW.

### C.2 Resolving `www.alice.foo`

1. Browser asks `127.0.0.1:53` for `www.alice.foo` A record.
2. Resolver: routing says `foo = freens`. Claim lookup at `K_claim`
   yields `tld_id` (uncontested; cached).
3. `get(K_tld)` → TLD record, verify `sig` under `PK_tld`.
4. `get(K_name("alice.foo"))` → delegation to `PK_alice`, signed by
   `PK_tld`. Verify.
5. `get(K_name("www.alice.foo"))` → A record `{1, 300, 203.0.113.42}`,
   signed by `PK_alice`. Verify; check sequence, expiry.
6. Answer: `www.alice.foo. 300 IN A 203.0.113.42`.
   A malicious peer mid-path could not have substituted an address:
   every hop was signature-checked against the chain from `PK_tld`.

### C.3 Transferring `alice.foo`

1. Alice signs a record with `owner = delegation = B82F1...`,
   `prev_hash = H_record(old envelope)`, `sequence = old+1`.
2. She publishes it; peers verify her current key `A7C91...` signed the
   hand-off and accept.
3. Bob, holding `SK_B82F1`, is now the owner. There was no WHOIS to
   update, no registrar to notify, no fee to pay.

### C.4 Recovering from a lost key

1. Alice loses `SK_A7C91`. Her recovery policy is 2-of-3, timelock 72 h.
2. Two recovery keys sign a declaration naming a fresh primary key.
3. For 72 h, whoever holds the old primary (nobody) could cancel; after
   the timelock the recovery record takes effect and the fresh key owns
   `alice.foo`.

## Appendix D. Implementation Map (Go, normative for the reference client)

The reference implementation is Go. This appendix maps each subsystem
of the specification to the package that implements it, and states what
remains hand-written. Guiding rule: **never hand-roll crypto, CBOR, or
DNS message handling** — those are where library maturity exists and
where homegrown code would be dangerous.

### D.1 Package matrix

| Spec section | Subsystem | Go package | Notes |
|---|---|---|---|
| 5.1 | Ed25519 sign/verify | `crypto/ed25519` (stdlib) | PureEdDSA per RFC 8032; 32-byte keys, 64-byte sigs. No third-party dep needed. |
| 5.1 | SHA-256 | `crypto/sha256` (stdlib) | `sha256.Sum256` returns exactly the 32-byte digests the spec uses for TLD IDs, Node IDs, record hashes, PoW. |
| 4.2 | Deterministic CBOR | `github.com/fxamacker/cbor/v2` | Enable `EncOptions{Canonical: true}` — this is RFC 8949 §4.2 deterministic encoding, which §4.2 makes normative. Map keys MUST encode as the spec's integer keys: use `struct`-based schemas with `keyasint` struct tags, or `cbor.MapKeyEncoder`/integer-keyed maps; verify byte-stability with golden-vector tests (Appendix D.4). |
| 9 | DNS resolver (UDP+TCP on `127.0.0.1:53`) | `github.com/miekg/dns` | Serves and forwards. `dns.Server` for both protocols, `dns.Client`/`dns.ClientConfig` for upstream fallback (§9.2 step 4), full RR type coverage incl. TLSA/CAA/SSHFP (§4.3), EDNS0 passthrough. This is the killer-feature section and it is almost entirely library assembly. |
| 9.3 | Resolver config file | stdlib only: `net/netip`, `os`, manual `key = value` parse or `github.com/spf13/viper` (optional) | The `.ini` format in §9.3 is simple enough for a 50-line parser; avoid pulling a config framework unless CLI grows. |
| 9.5 | TLS owner CA, leaf issuance, trust sync, cross-certs | stdlib `crypto/x509`, `crypto/ecdsa`, plus `golang.org/x/crypto/hkdf` for §9.5.1 derivation | Entirely stdlib-shaped: X.509 create/parse/sign; NSS trust-store sync via optional `certutil` exec (§9.5.6); the screened-resolution hook rides the §9.2 path. |
| 6 | Kademlia: k-buckets, XOR metric, iterative lookup | hand-written, *patterned on* `github.com/anacrolix/dht` | See D.2 — no off-the-shelf Kademlia speaks the freens wire protocol. |
| 6.2 | UDP transport, `net.UDPConn`, read/write deadlines | `net` (stdlib) | Goroutine-per-packet or `ReadFromUDP` loop; `SetReadDeadline` implements `RPC_TIMEOUT`. |
| 6.3 | HMAC write tokens | `crypto/hmac` (stdlib) | `TOKEN_ROTATION` = keep current+previous secret in a small struct guarded by a mutex. |
| 7.3 | Alias normalization (LDH + IDNA2008) | `golang.org/x/net/idna` | `idna.Lookup` profile; matches §3.2 (UTS #46 transitional=false, STD3 rules). |
| 7.3 | PoW mining loop | hand-written (~30 lines) over `crypto/sha256` | Trivially parallelizable with `errgroup` (`golang.org/x/sync/errgroup`). |
| 5.3 | Hierarchical key derivation | `crypto/hmac` + `crypto/sha256` (stdlib) or `github.com/tyler-smith/go-bip32` (optional, secp256k1-only — prefer hand-rolled Ed25519 derivation per §5.3) | |
| 8.4 | 2-of-3 recovery multisig | hand-written thin layer over `crypto/ed25519` | "Multisig" here is *n threshold signatures collected*, not script-level crypto — a `[]Signature` plus a counter. |
| 12 | Storage caps / LRU eviction | `github.com/hashicorp/golang-lru/v2` or container/list (stdlib) | For `NODE_STORAGE_MAX` envelope caches. |
| — | CLI, daemon, logging | stdlib `flag`/`log/slog`; `cobra` only if subcommands multiply | `log/slog` (Go 1.21+) is sufficient. |
| — | Unit + integration tests | stdlib `testing`, `net.Pipe`/ephemeral UDP ports for DHT tests | |

### D.2 What must be hand-written (and what to copy instead)

The freens DHT wire layer (§6.3 — signed KRPC envelope, write tokens,
`witness`/claim RPCs, `SignedEnvelope` store/verify semantics of §6.4)
is protocol-specific and exists in no library. Options assessed:

- `anacrolix/dht` — excellent Kademlia implementation, but deeply
  coupled to BitTorrent's KRPC/infohash semantics. **Do not import;
  do read.** Its routing table refresh logic, bucket eviction, and
  iterative lookup termination are the patterns §6.2–6.4 encode.
- `libp2p/go-libp2p-kad-dht` — correct but drags in the entire libp2p
  stack (transports, peer records, pubsub optionality) for a protocol
  that only needs UDP + CBOR. Rejected for the reference client.
- Estimate for the hand-written DHT core: ~1,500 lines Go (routing
  table, RPC loop, iterative lookup, token store, envelope store) —
  the Kademlia *algorithm* is small; it is the coupling to other
  systems that makes existing libraries heavy.

Everything else in the matrix above is direct library use.

### D.3 Suggested module layout

```
freens/
  cmd/freens/          main: daemon wiring (DHT node + resolver)
  cmd/freens-cli/      register/transfer/resolve/pin subcommands
  internal/wire/       CBOR types: Record, SignedEnvelope, Message,
                       canonical encoding + golden vectors
  internal/crypto/     keys, node/TLD IDs, recovery policy, PoW
  internal/dht/        k-buckets, RPC, iterative lookup, tokens,
                       envelope store (the hand-written core)
  internal/claims/     AliasClaim, witness client/server, ordering
  internal/resolver/   miekg/dns server, routing table, fallback
  internal/store/      LRU + persistence for cached envelopes
```

`internal/` on purpose: the wire formats are the public interface; the
Go API is not.

### D.4 Golden vectors

Because §4.2 makes byte-exact canonical CBOR normative, the reference
client MUST ship golden vectors (fixture files of `wire_name`,
`FREENS_Record`, `SignedEnvelope` bytes + expected SHA-256 hashes and
signatures) and test against them, so that `fxamacker/cbor` upgrades or
schema refactors cannot silently change signature inputs. The same
vectors double as cross-implementation conformance tests for any
non-Go client.

---

*End of specification, freens v0.1 draft.*
