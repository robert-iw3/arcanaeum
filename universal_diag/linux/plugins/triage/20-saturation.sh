# triage/saturation — is the host out of headroom right now?
# Memory, swap, PSI stall percentages, and load vs. cores. All read from
# /proc, so this works on every distro.

saturation_detect() {
    PLUGIN_DETAIL[saturation]="ready"
    return 0
}

saturation_triage() {
    section "saturation"
    # memory
    local mt ma pct
    mt=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
    ma=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
    pct=$(( ma * 100 / mt ))
    if   (( pct < 5 ));  then verdict crit "memory" "${pct}% available — OOM killer is imminent"
    elif (( pct < 15 )); then verdict warn "memory" "${pct}% available"
    else                      verdict ok   "memory" "${pct}% available"; fi
    # swap
    local st sf
    st=$(awk '/^SwapTotal:/{print $2}' /proc/meminfo)
    if (( st > 0 )); then
        sf=$(awk '/^SwapFree:/{print $2}' /proc/meminfo)
        pct=$(( (st - sf) * 100 / st ))
        if (( pct > 50 )); then verdict warn "swap" "${pct}% used — host is under memory pressure or was recently"
        else                    verdict ok   "swap" "${pct}% used"; fi
    fi
    # PSI (kernel 4.20+): the single best "is anything stalling" signal
    local res
    for res in cpu memory io; do
        [[ -r /proc/pressure/$res ]] || continue
        local avg10
        avg10=$(awk -F 'avg10=' '/^some/{split($2,a," "); print a[1]}' "/proc/pressure/$res")
        if awk -v v="$avg10" 'BEGIN{exit !(v > 25)}'; then
            verdict crit "psi $res" "some avg10=${avg10}% — tasks are stalling on $res right now"
        elif awk -v v="$avg10" 'BEGIN{exit !(v > 5)}'; then
            verdict warn "psi $res" "some avg10=${avg10}%"
        else
            verdict ok   "psi $res" "some avg10=${avg10}%"
        fi
    done
    # load vs cores
    local load1 cores
    load1=$(awk '{print $1}' /proc/loadavg)
    cores=$(ncpus)
    if awk -v l="$load1" -v c="$cores" 'BEGIN{exit !(l > 2*c)}'; then
        verdict warn "load" "load1 $load1 on $cores cores — runnable/blocked backlog"
    else
        verdict ok "load" "load1 $load1 on $cores cores"
    fi
}
