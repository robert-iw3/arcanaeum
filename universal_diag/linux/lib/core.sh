# lib/core.sh — shared helpers for unidiag and its plugins.
# Sourced by linux/unidiag.sh before any plugin loads. Everything here must
# stay portable: any distro, systemd or not, GNU coreutils or busybox.

die()  { printf 'unidiag: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# portability shims
ncpus()     { nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1; }
hostname_() { uname -n; }

# ------------------------------------------------------------- plugin loader
# A plugin is plugins/<kind>/NN-<name>.sh defining <name>_detect plus the
# kind's work function: <name>_collect, <name>_triage, or <name>_profile.
# NN orders loading; detect runs at load time so later plugins can consult
# PLUGIN_ACTIVE (e.g. syslog activates only when journald is absent).
# detect should record a human-readable status in PLUGIN_DETAIL[<name>].
declare -A PLUGIN_ACTIVE PLUGIN_DETAIL
PLUGINS_COLLECT=()
PLUGINS_TRIAGE=()
PLUGINS_PROFILE=()

# populated by profile plugins: what this host IS, so collection and
# analysis spend effort where it matters (=() keeps set -u happy when empty)
declare -A PROFILE_ROLES=()     # role -> confidence (high|medium|low)
declare -A PROFILE_EVIDENCE=()  # role -> comma-separated evidence
declare -A PROFILE_FOCUS=()     # role -> what to prioritize when collecting
declare -A PROFILE_HINT=()      # origin-substring -> role (fed to analysis)

load_plugins() {
    local kind f name
    for kind in collect triage profile; do
        for f in "$UNIDIAG_HOME/plugins/$kind"/[0-9]*-*.sh; do
            [[ -e $f ]] || continue
            . "$f"
            name=${f##*/}; name=${name%.sh}; name=${name#*-}
            case $kind in
                collect) PLUGINS_COLLECT+=("$name") ;;
                triage)  PLUGINS_TRIAGE+=("$name") ;;
                profile) PLUGINS_PROFILE+=("$name") ;;
            esac
            if "${name}_detect"; then PLUGIN_ACTIVE[$name]=1; fi
        done
    done
}

run_collectors() {
    local p
    for p in "${PLUGINS_COLLECT[@]}"; do
        [[ ${PLUGIN_ACTIVE[$p]:-0} -eq 1 ]] && "${p}_collect"
    done
    return 0
}

run_triage() {
    local p
    for p in "${PLUGINS_TRIAGE[@]}"; do
        [[ ${PLUGIN_ACTIVE[$p]:-0} -eq 1 ]] && "${p}_triage"
    done
    return 0
}

run_profile() {
    local p
    for p in "${PLUGINS_PROFILE[@]}"; do
        [[ ${PLUGIN_ACTIVE[$p]:-0} -eq 1 ]] && "${p}_profile"
    done
    return 0
}

# ------------------------------------------------------------ triage output
TRIAGE_WORST=0   # 0=ok 1=warn 2=crit

verdict() {  # verdict <ok|warn|crit> <check-name> <detail>
    local v=$1 name=$2 detail=$3 tag
    case $v in
        ok)   tag="  OK "; [[ $COLOR -eq 1 ]] && tag=$'\033[32m'"  OK "$'\033[0m' ;;
        warn) tag="WARN "; [[ $COLOR -eq 1 ]] && tag=$'\033[33m'"WARN "$'\033[0m'
              (( TRIAGE_WORST < 1 )) && TRIAGE_WORST=1 ;;
        crit) tag="CRIT "; [[ $COLOR -eq 1 ]] && tag=$'\033[1;37;41m'"CRIT "$'\033[0m'
              TRIAGE_WORST=2 ;;
    esac
    printf '%s %-22s %s\n' "$tag" "$name" "$detail"
}

section() {
    if [[ $COLOR -eq 1 ]]; then printf '\n\033[2m── %s ──\033[0m\n' "$1"
    else printf '\n── %s ──\n' "$1"; fi
}
