#!/usr/bin/env bash
#
# unidiag — universal Linux diagnostic tool (Phase 0 PoC, plugin architecture)
#
# Usage:
#   unidiag.sh profile [--json]                    what IS this host? roles + focus
#   unidiag.sh triage [--since 1h] [--no-color]   host-first health checks
#   unidiag.sh scan   [--since 1h] [--digest] [--json] [--no-color]
#   unidiag.sh collectors                          plugin detection status
#
# Troubleshooting order this tool encodes: profile → triage → scan.
# Know what the host is, check the host is sound, then read the app layer.
# An app error on a sick host is a symptom, not the disease.
#
# All host-specific logic lives in plugins/ (see the TEMPLATE.sh files);
# this file only parses arguments, loads plugins, and renders output.
# Event contract shared with the analysis layer and the future Rust port:
# ../spec/event-schema.md
set -uo pipefail

UNIDIAG_HOME=$(cd "$(dirname "$0")" && pwd)
. "$UNIDIAG_HOME/lib/core.sh"

SINCE="1h"
MODE=""
DIGEST=0
JSON=0
COLOR=1
[[ -t 1 ]] || COLOR=0

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ---------------------------------------------------------------- arg parsing
[[ $# -ge 1 ]] || usage 1
MODE=$1; shift
while [[ $# -gt 0 ]]; do
    case $1 in
        --since)    SINCE=${2:?--since needs a value}; shift 2 ;;
        --digest)   DIGEST=1; shift ;;
        --json)     JSON=1; shift ;;
        --no-color) COLOR=0; shift ;;
        -h|--help)  usage ;;
        *)          die "unknown option: $1" ;;
    esac
done

# Parse --since like 30m / 2h / 1d into the dialect each collector speaks.
[[ $SINCE =~ ^([0-9]+)([mhd])$ ]] || die "--since must look like 30m, 2h, or 1d (got: $SINCE)"
SINCE_N=${BASH_REMATCH[1]}
case ${BASH_REMATCH[2]} in
    m) SINCE_SECS=$(( SINCE_N * 60 )) ;;
    h) SINCE_SECS=$(( SINCE_N * 3600 )) ;;
    d) SINCE_SECS=$(( SINCE_N * 86400 )) ;;
esac
SINCE_JOURNAL="-${SINCE}"                                     # journalctl: -2h
SINCE_DOCKER="$SINCE"                                         # docker logs: 2h
CUTOFF_EPOCH=$(( $(date +%s) - SINCE_SECS ))
# "date -d @epoch" works on GNU and busybox; fall back to epoch 0 (no filter)
CUTOFF_ISO=$(date -u -d "@${CUTOFF_EPOCH}" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null \
             || echo "1970-01-01T00:00:00.000Z")

HAS_JQ=0
have jq && HAS_JQ=1

load_plugins

# --------------------------------------------------------------------- render

render_timeline() {
    awk -F '\t' -v color="$COLOR" '
        BEGIN {
            if (color) {
                C["crit"]  = "\033[1;37;41m"; C["error"] = "\033[31m"
                C["warn"]  = "\033[33m";      DIM = "\033[2m"; R = "\033[0m"
            } else { DIM = ""; R = "" }
        }
        {
            day = substr($1, 1, 10); tod = substr($1, 12, 12)
            if (day != lastday) { printf "%s—— %s ——%s\n", DIM, day, R; lastday = day }
            sevfmt = (color && ($2 in C)) ? C[$2] $2 R : $2
            printf "%s%s%s %-5s %s%-8s%s %-28s %s\n", DIM, tod, R, sevfmt, DIM, $3, R, substr($4, 1, 28), $5
            n++; s[$2]++
        }
        END {
            printf "\n%d events", n
            sep = " ("
            for (k in s) { printf "%s%d %s", sep, s[k], k; sep = ", " }
            if (n) printf ")"
            printf "\n"
        }'
}

render_json() {
    jq -R -r 'split("\t") | {ts: .[0], severity: .[1], source: .[2], origin: .[3], message: .[4]}'
}

# Fingerprint digest: mask the variable parts of each message so repeated
# patterns collapse, then rank by count. Masking tokens are part of the
# event contract (spec/event-schema.md) — keep in sync with the analysis
# layer and the Rust port.
render_digest() {
    cut -f2,4,5 | sed -E '
        s/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/<uuid>/g
        s/([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?/<ip>/g
        s/0x[0-9a-fA-F]+/<hex>/g
        s/\b[0-9a-fA-F]{12,64}\b/<hash>/g
        s/[0-9]+/<n>/g
    ' | sort | uniq -c | sort -rn | awk -F '\t' -v color="$COLOR" '
        BEGIN {
            if (color) {
                C["crit"]  = "\033[1;37;41m"; C["error"] = "\033[31m"
                C["warn"]  = "\033[33m";      DIM = "\033[2m"; R = "\033[0m"
            } else { DIM = ""; R = "" }
            print "distinct error patterns (most frequent first):\n"
        }
        {
            split($1, a, " ")                 # $1 = "   <count> <sev>" from uniq -c
            count = a[1]; sev = a[2]
            sevfmt = (color && (sev in C)) ? C[sev] sev R : sev
            printf "%5d× %-5s %s%-28s%s %s\n", count, sevfmt, DIM, substr($2, 1, 28), R, $3
        }'
}

# ------------------------------------------------------------------- commands

cmd_collectors() {
    local p
    printf 'collection plugins:\n'
    for p in "${PLUGINS_COLLECT[@]}"; do
        printf '  %-12s %s\n' "$p" "${PLUGIN_DETAIL[$p]:-unknown}"
    done
    printf '\ntriage plugins:\n'
    for p in "${PLUGINS_TRIAGE[@]}"; do
        printf '  %-12s %s\n' "$p" "${PLUGIN_DETAIL[$p]:-unknown}"
    done
    return 0
}

cmd_scan() {
    [[ $HAS_JQ -eq 1 ]] || printf 'unidiag: jq not found — journald and k8s collectors disabled\n' >&2
    local events
    events=$(run_collectors | sort -t $'\t' -k1,1)
    if [[ -z $events ]]; then
        printf 'no warn+ events in the last %s — clean bill of health\n' "$SINCE"
        return 0
    fi
    if [[ $JSON -eq 1 ]]; then
        printf '%s\n' "$events" | render_json
    elif [[ $DIGEST -eq 1 ]]; then
        printf '%s\n' "$events" | render_digest
    else
        printf '%s\n' "$events" | render_timeline
    fi
}

cmd_profile() {
    run_profile
    local role
    if [[ $JSON -eq 1 ]]; then
        # role names/confidence come from a fixed vocabulary and hints are
        # process comm names — safe to emit without a JSON library
        printf '{\n  "host": "%s",\n  "roles": {\n' "$(hostname_)"
        local sep=""
        for role in "${!PROFILE_ROLES[@]}"; do
            printf '%s    "%s": {"confidence": "%s", "evidence": "%s"}' \
                   "$sep" "$role" "${PROFILE_ROLES[$role]}" "${PROFILE_EVIDENCE[$role]}"
            sep=$',\n'
        done
        printf '\n  },\n  "hints": {\n'
        sep=""
        local hint
        for hint in "${!PROFILE_HINT[@]}"; do
            printf '%s    "%s": "%s"' "$sep" "$hint" "${PROFILE_HINT[$hint]}"
            sep=$',\n'
        done
        printf '\n  }\n}\n'
        return 0
    fi
    printf 'host profile: %s\n\n' "$(hostname_)"
    printf '%-18s %-8s %s\n' "role" "conf" "evidence"
    for role in "${!PROFILE_ROLES[@]}"; do
        printf '%-18s %-8s %s\n' "$role" "${PROFILE_ROLES[$role]}" "${PROFILE_EVIDENCE[$role]}"
    done
    printf '\ncollection focus:\n'
    for role in "${!PROFILE_ROLES[@]}"; do
        [[ -n ${PROFILE_FOCUS[$role]:-} ]] && printf '  %-16s %s\n' "$role" "${PROFILE_FOCUS[$role]}"
    done
    printf '\nfeed the analysis layer: %s profile --json > profile.json, then diagnose --profile profile.json\n' "$(basename "$0")"
    return 0
}

cmd_triage() {
    printf 'host triage: %s (kernel %s)\n' "$(hostname_)" "$(uname -r)"
    run_triage
    printf '\n'
    case $TRIAGE_WORST in
        0) printf 'host layer clean — problems are likely in the application layer. Next: %s scan --since %s\n' "$(basename "$0")" "$SINCE" ;;
        1) printf 'host layer has warnings — weigh them against app symptoms before diving into app logs.\n' ;;
        2) printf 'host layer has CRITICAL findings — fix these first; application errors are likely downstream symptoms.\n' ;;
    esac
    return 0
}

case $MODE in
    profile)    cmd_profile ;;
    triage)     cmd_triage ;;
    scan)       cmd_scan ;;
    collectors) cmd_collectors ;;
    -h|--help)  usage ;;
    *)          die "unknown command: $MODE (try: profile, triage, scan, collectors)" ;;
esac
