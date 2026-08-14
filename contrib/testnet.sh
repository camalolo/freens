#!/usr/bin/env bash
#
# contrib/testnet.sh — N-node freens interop testnet (spec §D interop /
# ops hardening).
#
# Spins up N freens daemons on localhost (Kademlia DHT + DNS resolver each),
# publishes one TLD record and a www record through node 1's DHT port, and
# asserts with dig that EVERY node serves the record — first the initial
# version, then a sequence+1 UPDATE (new IP) within 30 s on all nodes (the
# records use -ttl 5 so resolver/response caches revalidate quickly). That is
# the beyond-two-nodes convergence proof: publish once, resolve everywhere,
# update once, converge everywhere.
#
# Usage:
#	testnet.sh [N=5] [workdir]
#
#   N        number of nodes (>= 2; default 5)
#   workdir  scratch dir (default: mktemp -d); per-node state in n<i>/,
#            binaries in bin/, records in records/, daemon log in log
#
# Node i listens on DHT 127.0.0.1:$((15353+i)) and DNS 127.0.0.1:$((5300+i));
# nodes 2..N bootstrap from node 1 (-peers 127.0.0.1:15354#<pk1>), node 1 has
# no -peers. Every node passes -advertise (§6.2) and -persist so the run also
# exercises the advertised-address and persistence paths.
#
# Alias resolution: the test alias "tn" is routed freens-side and pinned via
# [alias-pins] (§9.3; a pin always wins). The §7 network-claim path
# additionally requires the W=5 witness quorum of §7.3, which needs a live
# witness-collecting publisher the one-shot CLI does not emulate; §7 claim
# semantics are covered by the internal/resolver + internal/dht test suites.
# What THIS script proves is N-node DHT data convergence + authoritative DNS
# serving on every node — the interop/ops surface (spec §D).
#
# Requirements: bash, GNU coreutils, go (>= 1.25), dig (bind9 dnsutils).
# Run from the repo root. Exits 0 and prints "PASS: N nodes converged" on
# success; on any failure it dumps the tail of every node log and exits 1.
# All daemons are killed on exit (trap).

set -euo pipefail

N="${1:-5}"
WORK="${2:-$(mktemp -d)}"

die() { echo "testnet: FAIL: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$2"; }

[[ "$N" =~ ^[0-9]+$ ]] || die "N must be an integer, got '$N'"
[ "$N" -ge 2 ] || die "N must be >= 2 (the point is multi-node convergence), got $N"
need dig "dig (bind9/bind9-dnsutils) is required for the DNS assertions"
need go "go (>= 1.25) is required to build the binaries"

# Node 1's fixed ports (peers of nodes 2..N point here).
DHT_PORT_BASE=15353   # node i -> $((DHT_PORT_BASE + i)); node 1 = 15354
DNS_PORT_BASE=5300    # node i -> $((DNS_PORT_BASE + i)); node 1 = 5301
ALIAS="tn"            # the test alias (routed freens + pinned per node)

mkdir -p "$WORK/bin"
PIDS=()

cleanup() {
	for pid in "${PIDS[@]:-}"; do
		kill "$pid" 2>/dev/null || true
	done
	# Give the daemons a beat to flush their shutdown-time persist snapshot.
	for pid in "${PIDS[@]:-}"; do
		wait "$pid" 2>/dev/null || true
	done
}
trap cleanup EXIT

dump_logs() {
	echo "---- node logs (tail) ----" >&2
	for i in $(seq 1 "$N"); do
		echo "## $WORK/n$i/log:" >&2
		tail -n 25 "$WORK/n$i/log" >&2 2>/dev/null || echo "(no log)" >&2
	done
}

# wait_for_ip PORT EXPECTED_IP LABEL — poll one node's DNS port until it
# answers www.$ALIAS with EXPECTED_IP; 30 x 1 s budget, hard FAIL on miss.
wait_for_ip() {
	local port="$1" want="$2" label="$3" got="" attempt
	for attempt in $(seq 1 30); do
		got="$(dig +short +time=2 +tries=1 @127.0.0.1 -p "$port" "www.$ALIAS" A 2>/dev/null || true)"
		if [ "$got" = "$want" ]; then
			echo "testnet: node :$port serves www.$ALIAS -> $want ($label, attempt $attempt)"
			return 0
		fi
		sleep 1
	done
	echo "testnet: node :$port did not serve $want for www.$ALIAS within 30s ($label); last answer: '${got:-none}'" >&2
	dump_logs
	return 1
}

echo "testnet: workdir=$WORK nodes=$N"

# --- build (run from repo root) -------------------------------------------------
echo "testnet: building freens + freens-cli"
go build -o "$WORK/bin/freens" ./cmd/freens || die "go build ./cmd/freens"
go build -o "$WORK/bin/freens-cli" ./cmd/freens-cli || die "go build ./cmd/freens-cli"
FREENS="$WORK/bin/freens"
CLI="$WORK/bin/freens-cli"

# --- per-node identities --------------------------------------------------------
SEEDS=()
PKS=()
for i in $(seq 1 "$N"); do
	out="$("$CLI" gen-key)" || die "gen-key node $i"
	seed="$(sed -n 's/^seed=//p' <<<"$out")"
	pk="$(sed -n 's/^public=//p' <<<"$out")"
	[ -n "$seed" ] && [ -n "$pk" ] || die "could not parse gen-key output for node $i"
	SEEDS[$i]="$seed"
	PKS[$i]="$pk"
done
PK1="${PKS[1]}"

# --- the record owner key K (TLD "tn") + records ---------------------------------
# K owns the TLD record at K_tld and (same key, §3.4 parent-owner signer rule)
# the www.$ALIAS record at K_name. 192.0.2.0/24 is TEST-NET-1 (RFC 5737).
out="$("$CLI" gen-key)" || die "gen-key owner"
KSEED="$(sed -n 's/^seed=//p' <<<"$out")"
KB32="$(sed -n 's/^tld_id_b32=//p' <<<"$out")"
[ -n "$KSEED" ] && [ -n "$KB32" ] || die "could not parse gen-key output for the owner key"
IP_V1="192.0.2.10"
IP_V2="192.0.2.20"

# --- launch N daemons ------------------------------------------------------------
for i in $(seq 1 "$N"); do
	mkdir -p "$WORK/n$i/records"
	dht_port=$((DHT_PORT_BASE + i))
	dns_port=$((DNS_PORT_BASE + i))
	# Per-node resolver config: route the test alias freens-side and pin it to
	# K's tld_id (§9.3 [alias-pins]). [listen] mirrors the -dns flag below.
	cat >"$WORK/n$i/resolver.conf" <<EOF
[listen]
udp = 127.0.0.1:$dns_port
tcp = 127.0.0.1:$dns_port
[upstream]
servers = 9.9.9.9
[tld-routes]
$ALIAS = freens
* = dns-first
[alias-pins]
$ALIAS = $KB32
EOF
	args=(
		-dht "127.0.0.1:$dht_port"
		-dns "127.0.0.1:$dns_port"
		-node-seed "${SEEDS[$i]}"
		-persist "$WORK/n$i/records"
		-idna
		-advertise "127.0.0.1:$dht_port"
		-config "$WORK/n$i/resolver.conf"
	)
	if [ "$i" -gt 1 ]; then
		args+=(-peers "127.0.0.1:$((DHT_PORT_BASE + 1))#$PK1")
	fi
	"$FREENS" "${args[@]}" >"$WORK/n$i/log" 2>&1 &
	PIDS+=("$!")
	echo "testnet: node $i started (dht :$dht_port, dns :$dns_port, pid ${PIDS[-1]})"
done

# --- readiness: node 1's DNS port answers (any rcode counts — incl. the
# NXDOMAIN this probe name yields before records exist) --------------------------
ready=0
for attempt in $(seq 1 15); do
	kill -0 "${PIDS[0]}" 2>/dev/null || { dump_logs; die "node 1 exited early"; }
	if dig +time=1 +tries=1 @127.0.0.1 -p $((DNS_PORT_BASE + 1)) "startup.$ALIAS" A 2>/dev/null | grep -q 'status:'; then
		ready=1
		break
	fi
	sleep 1
done
[ "$ready" -eq 1 ] || { dump_logs; die "node 1 DNS port not answering within 15s"; }
echo "testnet: node 1 DNS ready (attempt $attempt)"

# --- records + initial publish ---------------------------------------------------
# TTL 5 keeps the resolver response cache and the DHT cache-freshness window
# short so the UPDATE convergence below fits the 30 s budget.
"$CLI" make-record -name "$ALIAS" -owner-seed "$KSEED" -ip 192.0.2.1 \
	-pin "$KB32" -ttl 5 -out "$WORK/tld.cbor" >/dev/null \
	|| die "make-record TLD"
"$CLI" make-record -name "www.$ALIAS" -owner-seed "$KSEED" -signer-seed "$KSEED" \
	-ip "$IP_V1" -pin "$KB32" -ttl 5 -seq 1 -out "$WORK/www1.cbor" >/dev/null \
	|| die "make-record www v1"
pub="$("$CLI" publish -files "$WORK/tld.cbor,$WORK/www1.cbor" -peers "127.0.0.1:$((DHT_PORT_BASE + 1))#$PK1")" \
	|| die "initial publish failed: $pub"
grep -q "accepted" <<<"$pub" || die "initial publish accepted nothing: $pub"
echo "testnet: published TLD + www v1 ($IP_V1)"

# --- convergence check A: every node serves IP_V1 --------------------------------
for i in $(seq 1 "$N"); do
	wait_for_ip $((DNS_PORT_BASE + i)) "$IP_V1" "initial"
done

# --- UPDATE: www sequence 2 with a new IP, republished via node 1 ----------------
"$CLI" make-record -name "www.$ALIAS" -owner-seed "$KSEED" -signer-seed "$KSEED" \
	-ip "$IP_V2" -pin "$KB32" -ttl 5 -seq 2 -out "$WORK/www2.cbor" >/dev/null \
	|| die "make-record www v2"
pub="$("$CLI" publish -files "$WORK/www2.cbor" -peers "127.0.0.1:$((DHT_PORT_BASE + 1))#$PK1")" \
	|| die "update publish failed: $pub"
grep -q "accepted" <<<"$pub" || die "update publish accepted nothing: $pub"
echo "testnet: published www v2 ($IP_V2, seq 2)"

# --- convergence check B: every node serves IP_V2 within 30 s --------------------
for i in $(seq 1 "$N"); do
	wait_for_ip $((DNS_PORT_BASE + i)) "$IP_V2" "update"
done

echo "PASS: $N nodes converged"
