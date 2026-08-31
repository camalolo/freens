#!/usr/bin/env bash
# ddns-cloudflare.sh — Cloudflare DDNS for dynamic-IP seed nodes (spec §10):
# keep one A record pointed at this machine's current WAN IP.
#
#   WAN IP       read from a LOCAL INTERFACE (default ppp0 — the typical
#                PPPoE WAN on a seed box); no "what is my IP" web calls,
#                so the reported address is exactly the one the DHT
#                advertises.
#   Drift-only   the record is PATCHed only when it differs — safe to run
#                every 5 minutes from the freens-ddns.timer units.
#   --check      dry-run: report interface IP vs the live record, write
#                nothing (still needs a read-capable token).
#   Token        $CLOUDFLARE_API_TOKEN, or dns_cloudflare_api_token from a
#                certbot-style cloudflare.ini (default
#                /etc/letsencrypt/.secrets/cloudflare.ini, the file
#                certbot-dns-cloudflare users already have). The token is
#                never printed, logged, or put on a command line — curl
#                receives it via --config on stdin.
#
# Single-record assumption: exactly one A record matches RECORD; extra
# matching records (round-robin setups) are ignored by the API filter.
#
# Needs: curl, jq, ip (iproute2). bash 4+.
#
# Flags (each defaults to the matching CLOUDFLARE_* env var, so the
# systemd units configure everything through Environment=):
#   -i IFACE   interface holding the WAN address (CLOUDFLARE_INTERFACE)
#   -z ZONE    Cloudflare zone name, e.g. example.com   (CLOUDFLARE_ZONE)
#   -r RECORD  A record FQDN,    e.g. seed.example.com  (CLOUDFLARE_RECORD)
#   --ttl N    record TTL seconds, default 300           (CLOUDFLARE_TTL)
#   --check    dry-run; nothing is created or updated
#
# Install (as root), with the systemd pair in contrib/systemd/:
#   install -m755 ddns-cloudflare.sh /usr/local/bin/
#   install -m644 freens-ddns.service freens-ddns.timer /etc/systemd/system/
#   # edit the Environment= lines in freens-ddns.service, then:
#   systemctl daemon-reload && systemctl enable --now freens-ddns.timer
#   # always dry-run once by hand before enabling:
#   /usr/local/bin/ddns-cloudflare.sh --check -i ppp0 -z example.com -r seed.example.com

set -euo pipefail
export LC_ALL=C

usage() { awk 'NR>1 && !/^#/ {exit} NR>1 {sub(/^# ?/, ""); print}' "$0"; exit "${1:-0}"; }

ZONE="${CLOUDFLARE_ZONE:-}"
RECORD="${CLOUDFLARE_RECORD:-}"
IFACE="${CLOUDFLARE_INTERFACE:-}"
TTL="${CLOUDFLARE_TTL:-300}"
INI="${CLOUDFLARE_INI:-/etc/letsencrypt/.secrets/cloudflare.ini}"
CHECK=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	-i) IFACE=$2; shift 2 ;;
	-z) ZONE=$2; shift 2 ;;
	-r) RECORD=$2; shift 2 ;;
	--ttl) TTL=$2; shift 2 ;;
	--check) CHECK=1; shift ;;
	-h|--help) usage 0 ;;
	*) echo "ddns-cloudflare: unknown argument $1 (try --help)" >&2; exit 1 ;;
	esac
done

die() { echo "ddns-cloudflare: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "missing dependency: $1"; }
need curl; need jq; need ip

[[ -n $ZONE ]] || die "no zone: pass -z or set CLOUDFLARE_ZONE"
[[ -n $RECORD ]] || die "no record: pass -r or set CLOUDFLARE_RECORD"
[[ -n $IFACE ]] || die "no interface: pass -i or set CLOUDFLARE_INTERFACE"
[[ $ZONE =~ ^[A-Za-z0-9.-]+$ ]] || die "zone looks wrong: $ZONE"
[[ $RECORD =~ ^[A-Za-z0-9.-]+$ ]] || die "record looks wrong: $RECORD"
[[ $TTL =~ ^[0-9]+$ ]] || die "ttl must be a number: $TTL"

# token resolves the API credential WITHOUT ever echoing it: env first,
# then the certbot ini. curl reads it via --config stdin, so it never
# appears in a command line, the journal, or this script's output.
token() {
	if [[ -n ${CLOUDFLARE_API_TOKEN:-} ]]; then
		printf '%s' "$CLOUDFLARE_API_TOKEN"
		return
	fi
	if [[ -r $INI ]]; then
		sed -n 's/^[[:space:]]*dns_cloudflare_api_token[[:space:]]*=[[:space:]]*//p' "$INI" |
			head -1 | tr -d "\"' "
		return
	fi
	die "no API token: set CLOUDFLARE_API_TOKEN or make $INI readable (root)"
}
TOKEN=$(token)
[[ -n $TOKEN ]] || die "empty API token"

# wan_ip is the global v4 address on the interface (one per line; the first
# is used — a seed box with several WAN addresses is its own adventure).
# The `|| true` matters: under set -e a failing `ip` would otherwise kill
# the script inside the ASSIGNMENT, before the friendly die below runs.
WAN=$(ip -4 -o addr show dev "$IFACE" scope global 2>/dev/null |
	awk '{sub(/\/.*/, "", $4); print $4; exit}') || true
[[ -n $WAN ]] || die "no global IPv4 address on $IFACE"

CLOUDFLARE_API_URL="${CLOUDFLARE_API_URL:-https://api.cloudflare.com/client/v4}"

# api METHOD PATH [JSON-BODY] — one authenticated Cloudflare call; the body
# travels as a curl argument (it holds only the IP and name — nothing
# secret), while the token goes to curl's stdin config so it never shows
# up in argv, the journal, or this script's output.
api() {
	local method=$1 path=$2
	if [[ $# -gt 2 ]]; then
		curl -sSf -X "$method" -K - "$CLOUDFLARE_API_URL$path" -d "$3" <<CFG
header = "Authorization: Bearer $TOKEN"
CFG
	else
		curl -sSf -X "$method" -K - "$CLOUDFLARE_API_URL$path" <<CFG
header = "Authorization: Bearer $TOKEN"
CFG
	fi
}

zone_id=$(api GET "/zones?name=$ZONE" | jq -r '.result[0].id // empty') ||
	die "Cloudflare API call failed (zone lookup)"
[[ -n $zone_id ]] || die "zone not found or token lacks access: $ZONE"

rec=$(api GET "/zones/$zone_id/dns_records?type=A&name=$RECORD") ||
	die "Cloudflare API call failed (record lookup)"
[[ $(jq -r '.success' <<<"$rec") == "true" ]] || die "record lookup rejected: $(jq -r '.errors[].message' <<<"$rec" | head -1)"
rec_id=$(jq -r '.result[0].id // empty' <<<"$rec")
rec_ip=$(jq -r '.result[0].content // empty' <<<"$rec")

if [[ $rec_ip == "$WAN" ]]; then
	echo "ddns: $RECORD already points at $WAN — up to date"
	exit 0
fi

body=$(jq -cn --arg ip "$WAN" --argjson ttl "$TTL" '{content:$ip, ttl:$ttl}')

if [[ $CHECK == 1 ]]; then
	if [[ -n $rec_id ]]; then
		echo "ddns (dry-run): would PATCH $RECORD: $rec_ip -> $WAN (ttl $TTL)"
	else
		echo "ddns (dry-run): would CREATE A $RECORD -> $WAN (ttl $TTL)"
	fi
	exit 0
fi

if [[ -n $rec_id ]]; then
	out=$(api PATCH "/zones/$zone_id/dns_records/$rec_id" "$body")
else
	create=$(jq -cn --arg r "$RECORD" --arg ip "$WAN" --argjson ttl "$TTL" \
		'{type:"A", name:$r, content:$ip, ttl:$ttl, proxied:false}')
	out=$(api POST "/zones/$zone_id/dns_records" "$create") ||
		die "record create failed"
fi
[[ $(jq -r '.success' <<<"$out") == "true" ]] ||
	die "API refused the update: $(jq -r '.errors[].message' <<<"$out" | head -1)"
echo "ddns: $RECORD -> $WAN (was: ${rec_ip:-<none>})"
