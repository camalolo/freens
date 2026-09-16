#!/usr/bin/env bash
# fleet-upgrade.sh — a rolling freens fleet upgrade with verification built
# in. The point is that every upgrade is IDENTICAL: the same pre-flight
# snapshot, the same post-roll checks, no ad-hoc curls (a `--resolve`
# literal-IP TLS check bypasses the resolver and HIDES resolver-side
# breakage — the 2026-09-14 mistake this script exists to prevent).
#
# Usage:
#   FLEET_BOXES="server laurent-minipc nanopi" contrib/fleet-upgrade.sh [upgrade-args…]
#
# Per box the remote command defaults to "freens"; override for hosts that
# need it, e.g.:
#   FLEET_BOXES_CMD_nanopi="echo pi | sudo -S env FREENS_HOME=/home/pi/.freens freens"
#
# upgrade-args are passed to `freens upgrade` verbatim ("-yes", or
# "-force -version v0.16.7 -yes" when the boxes carry newer dev stamps).
set -u

FLEET_BOXES="${FLEET_BOXES:-server laurent-minipc nanopi}"
CONVERGE_WAIT="${CONVERGE_WAIT:-45}"   # seconds between restart and checks
DIG_WAIT="${DIG_WAIT:-8}"              # per-dig timeout

die() { echo "fleet-upgrade: $*" >&2; exit 1; }
remote() { # remote <box> <command…> — run through the box's freens CLI
    local box=$1; shift
    local var="FLEET_BOXES_CMD_${box//-/_}"
    local cmd="${!var:-freens}"
    if [ "$box" = "${FLEET_LOCAL_BOX:-}" ]; then
        env FREENS_HOME="${FLEET_LOCAL_HOME:-$HOME/.local/share/freens}" $cmd "$@"
    else
        ssh -o ControlPath=none "$box" "$cmd $*"
    fi
}
onbox() { # onbox <box> <shell-command…> — run a PLAIN SHELL command on the
          # box (digs, curls: NOT through the freens CLI — the v0.18.0 roll
          # found the checks running as `freens sh -c …` and failing on
          # every box while the upgrades themselves were green).
    local box=$1; shift
    if [ "$box" = "${FLEET_LOCAL_BOX:-}" ]; then
        bash -c "$*"
    else
        ssh -o ControlPath=none "$box" "$*"
    fi
}

command -v dig >/dev/null || die "dig not found"

echo "════ PRE-FLIGHT ════"
declare -A PRE
for box in $FLEET_BOXES; do
    out=$(remote "$box" doctor 2>&1 | tail -1)
    PRE[$box]="$out"
    printf "%-16s %s\n" "$box" "$out"
done
first_alias=$(remote "${FLEET_BOXES%% *}" status 2>/dev/null | grep -oE "^([a-z0-9-]+) →" | head -1 | cut -d' ' -f1)
[ -n "$first_alias" ] || first_alias=$(remote "${FLEET_BOXES%% *}" keys 2>/dev/null | grep -oE "^  [a-z0-9-]+\.key" | head -1 | tr -d ' .k ey')
echo "verification alias: ${first_alias:-(none found — TLS checks will be skipped)}"

echo
echo "════ UPGRADE ════"
for box in $FLEET_BOXES; do
    echo "── $box:"
    remote "$box" upgrade "$@" || die "$box upgrade failed — STOPPED (remaining boxes untouched; check the failed box before retrying)"
done

echo
echo "waiting ${CONVERGE_WAIT}s for convergence (boot warm-up + walks)…"
sleep "$CONVERGE_WAIT"

echo
echo "════ POST-ROLL VERIFICATION ════"
fail=0
for box in $FLEET_BOXES; do
    echo "── $box:"
    # Version.
    v=$(remote "$box" version 2>/dev/null | head -1)
    printf "  %-12s %s\n" "version:" "$v"
    # Resolution through THE RESOLVER (never --resolve): own name + the
    # verification alias. A timeout here is the cold-walk/wedge tripwire.
    for name in "$first_alias"; do
        [ -n "$name" ] || continue
        ans=$(onbox "$box" "dig @127.0.0.1 -p 5300 $name +time=$DIG_WAIT +tries=1 +short 2>/dev/null | head -1")
        if [ -n "$ans" ]; then
            printf "  %-12s %s (%s)\n" "dns $name:" "ANSWER" "$ans"
        else
            printf "  %-12s %s\n" "dns $name:" "NO ANSWER ← investigate before trusting this upgrade"
            fail=1
        fi
    done
    # TLS through the OS path (system trust + resolver): exactly what an
    # application experiences. www.<alias> exercises the §9.5 chain.
    if [ -n "$first_alias" ]; then
        tls=$(onbox "$box" "curl -s -o /dev/null -w '%{http_code}/v%{ssl_verify_result}' --max-time 15 https://www.$first_alias/ 2>/dev/null")
        printf "  %-12s %s\n" "tls www:" "$tls"
        case "$tls" in
            200/v0) ;;
            *) echo "  ↑ TLS not green — resolver or trust store issue; NOT an upgrade artifact. Run \`freens doctor\` on the box."
               fail=1 ;;
        esac
    fi
    # Doctor (now includes the TLS expiry watch + network lease).
    out=$(remote "$box" doctor 2>&1 | tail -1)
    printf "  %-12s %s\n" "doctor:" "$out"
    case "$out" in *passed*) ;; *) fail=1 ;; esac
done

echo
if [ "$fail" = 0 ]; then
    echo "fleet-upgrade: ALL GREEN — every box answers, TLS verifies, doctors pass."
else
    echo "fleet-upgrade: $fail CHECK(S) FLAGGED — see above. Do NOT assume the upgrade caused it:"
    echo "  compare with the pre-flight snapshot (the usual suspects: keyspace convergence on a"
    echo "  restarted box, a swept cross-cert on a quiet box — both self-heal via the boot warm-up"
    echo "  and the trust keeper; give it one keeper tick / a repeated dig before diving in)."
    exit 1
fi
