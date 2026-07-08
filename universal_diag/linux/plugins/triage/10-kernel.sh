# triage/kernel — what the kernel itself is complaining about.
# First triage plugin by design: OOM kills, hardware faults, and I/O errors
# make everything downstream a symptom.
# journald when present; plain dmesg otherwise (window becomes "since boot").

kernel_detect() {
    PLUGIN_DETAIL[kernel]="ready"
    return 0
}

kernel_triage() {
    local klog window="last $SINCE"
    if [[ ${PLUGIN_ACTIVE[journald]:-0} -eq 1 ]]; then
        klog=$(journalctl -k --no-pager --since "$SINCE_JOURNAL" -p err -o cat 2>/dev/null)
    else
        window="since boot (no journald)"
        klog=$(dmesg --level=err,crit,alert,emerg 2>/dev/null) \
            || klog=$(dmesg 2>/dev/null | grep -iE 'error|fail|panic|oom|segfault|i/o' || true)
        if [[ -z $klog ]] && ! dmesg >/dev/null 2>&1; then
            section "kernel ring buffer"
            verdict warn "kernel log" "dmesg unreadable (kernel.dmesg_restrict? try as root)"
            return
        fi
    fi
    section "kernel ring buffer ($window)"
    if [[ -z $klog ]]; then
        verdict ok "kernel errors" "no err+ kernel messages in window"
        return
    fi
    local total; total=$(wc -l <<<"$klog")
    check_kpattern() {  # <name> <regex> <verdict-if-hit> <meaning>
        local n; n=$(grep -icE "$2" <<<"$klog" || true)
        [[ $n -gt 0 ]] && verdict "$3" "$1" "$n hit(s) — $4"
    }
    check_kpattern "oom killer"    "out of memory|oom-kill|killed process"              crit "a process was killed for memory; whatever died after this is a symptom"
    check_kpattern "hardware/MCE"  "machine check|hardware error|mce:"                  crit "CPU/memory hardware fault — stop debugging software"
    check_kpattern "storage I/O"   "i/o error|blk_update_request|critical medium|ata[0-9]+.*(error|failed)" crit "failing disk or controller — check SMART before anything else"
    check_kpattern "filesystem"    "ext4-fs error|xfs.*corrupt|btrfs.*error|remount.*read-only" crit "fs corruption or forced read-only — apps will fail mysteriously"
    check_kpattern "segfaults"     "segfault|general protection fault"                  warn "crashing binaries — note which, correlate with app errors"
    check_kpattern "thermal"       "thermal|throttl"                                    warn "thermal throttling — 'slow app' reports may be this"
    check_kpattern "network"       "link is down|nic link|netdev watchdog"              warn "link flaps — timeouts in app logs may trace here"
    verdict ok "kernel err+ total" "$total message(s) in window — categorized above; see journalctl -k -p err (or dmesg) for the rest"
}
