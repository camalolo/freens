#!/usr/bin/env bash
# port53-redirect.sh — redirect local DNS (port 53) to a freens daemon on a
# high port, per spec §9.1 ("If the OS forbids binding port 53 unprivileged,
# implementations bind a high port and provide documented forwarding recipes
# (iptables, systemd socket units, or a small setuid launcher)") and §9.4
# stage 1 (local resolver, zero app changes).
#
# The recommended model: run `freens -listen 127.0.0.1:5300` as an
# unprivileged user, then redirect outgoing UDP/TCP port 53 to 5300 so the
# system's stub resolver keeps working unmodified.
#
# Usage:
#   ./port53-redirect.sh add                  # install rules (default)
#   ./port53-redirect.sh remove               # uninstall rules
#   ./port53-redirect.sh status               # show current rules
#
# Options (environment variables):
#   TO_PORT   high port the daemon listens on      (default: 5300)
#   UID_EXCL  (deprecated, ignored — rules are daddr-scoped now)
#             Kept for compatibility only.
#
#             loop back into the daemon forever.
#   BACKEND   force "nft" or "ipt"                  (default: auto-detect)
#
# Notes:
#   * Runs locally only (nat OUTPUT chain); LAN clients would additionally
#     need PREROUTING rules on the router, out of scope here.
#   * Rules are not persistent across reboots; persist them with your
#     distribution's firewall service (e.g. iptables-persistent, or an
#     nftables.conf include).
#   * Idempotent: rules are checked before being added.
#
# This script needs root; it is a contributed example — review it before
# running. (Validated with `bash -n` only.)

set -euo pipefail

ACTION="${1:-add}"
TO_PORT="${TO_PORT:-5300}"
UID_EXCL="${UID_EXCL:-$(id -u)}"
BACKEND="${BACKEND:-}"

NFT_TABLE="freens-redirect"

usage() {
    sed -n '2,30p' "$0"
    exit 1
}

die() { echo "port53-redirect: $*" >&2; exit 1; }

case "$ACTION" in
    add|remove|status) ;;
    -h|--help|help) usage ;;
    *) die "unknown action '$ACTION' (want add|remove|status)" ;;
esac

command -v iptables >/dev/null 2>&1 && HAVE_IPT=1 || HAVE_IPT=0
command -v nft      >/dev/null 2>&1 && HAVE_NFT=1 || HAVE_NFT=0

if [ -z "$BACKEND" ]; then
    if [ "$HAVE_NFT" = 1 ]; then BACKEND=nft; else BACKEND=ipt; fi
fi

case "$BACKEND" in
    nft)
        [ "$HAVE_NFT" = 1 ] || die "nft not found"
        ;;
    ipt)
        [ "$HAVE_IPT" = 1 ] || die "iptables not found"
        ;;
    *) die "BACKEND must be 'nft' or 'ipt'" ;;
esac

# ---------------------------------------------------------------------------
# nftables backend: one inet table with a nat OUTPUT redirect. `add table`
# and `flush ruleset`-free management keep this idempotent and reversible.
# ---------------------------------------------------------------------------
nft_add() {
    if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        echo "nft: table inet/$NFT_TABLE already present, nothing to do"
        return 0
    fi
    nft -f - <<EOF
table inet $NFT_TABLE {
    chain output {
        type nat hook output priority -100; policy accept;
        # Redirect only loopback-destined :53 to the high-port daemon.
        # daddr-scoping (not uid-exclusion — that breaks single-user
        # machines where apps share the daemon's uid, found live): the
        # daemon's own upstream forwards go to EXTERNAL resolver
        # addresses, so they never match and cannot loop.
        ip daddr 127.0.0.1 meta l4proto { tcp, udp } th dport 53 redirect to :$TO_PORT
    }
}
EOF
    echo "nft: added redirect 127.0.0.1:53 -> :$TO_PORT"
}

nft_remove() {
    if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        nft delete table inet "$NFT_TABLE"
        echo "nft: removed table inet/$NFT_TABLE"
    else
        echo "nft: table inet/$NFT_TABLE not present, nothing to do"
    fi
}

nft_status() {
    nft list table inet "$NFT_TABLE" 2>/dev/null \
        || echo "nft: table inet/$NFT_TABLE not present"
}

# ---------------------------------------------------------------------------
# iptables backend: classic nat OUTPUT REDIRECT rules, check-before-add.
# ---------------------------------------------------------------------------
ipt_rule() { # <tcp|udp>
    echo "-t nat -A OUTPUT -p $1 -d 127.0.0.1 --dport 53 -j REDIRECT --to-ports $TO_PORT"
}

ipt_add() {
    for p in udp tcp; do
        if iptables $(ipt_rule "$p" | sed 's/-A /-C /'); then
            echo "iptables: $p rule already present, nothing to do"
        else
            # shellcheck disable=SC2046
            iptables $(ipt_rule "$p")
            echo "iptables: added $p 127.0.0.1:53 -> :$TO_PORT"
        fi
    done
}

ipt_remove() {
    for p in udp tcp; do
        if iptables $(ipt_rule "$p" | sed 's/-A /-C /'); then
            # shellcheck disable=SC2046
            iptables $(ipt_rule "$p" | sed 's/-A /-D /')
            echo "iptables: removed $p rule"
        else
            echo "iptables: $p rule not present, nothing to do"
        fi
    done
}

ipt_status() {
    iptables -t nat -S OUTPUT | grep -F -- "--to-ports $TO_PORT" \
        || echo "iptables: no redirect rules to port $TO_PORT"
}

case "$BACKEND" in
    nft) "nft_$ACTION" ;;
    ipt) "ipt_$ACTION" ;;
esac
