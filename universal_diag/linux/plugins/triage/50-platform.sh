# triage/platform — is the machinery under the apps sound?
# Failed service units, zombie accumulation, clock sync.

platform_detect() {
    PLUGIN_DETAIL[platform]="ready"
    return 0
}

platform_triage() {
    section "platform"
    # failed systemd units (skipped silently on non-systemd hosts)
    if have systemctl; then
        local failed
        failed=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | paste -sd ', ' -)
        if [[ -n $failed ]]; then verdict warn "systemd units" "failed: $failed"
        else                      verdict ok   "systemd units" "no failed units"; fi
    fi
    # zombies (a leaking parent; cosmetic until PID/thread limits are hit).
    # Read /proc directly — busybox ps has no -eo. State is the field after
    # the ")" because comm may contain spaces.
    local z
    z=$(sed 's/.*) //' /proc/[0-9]*/stat 2>/dev/null | awk '$1 == "Z"' | wc -l)
    if (( z > 10 )); then verdict warn "zombies" "$z zombie processes — some parent is not reaping"
    else                  verdict ok   "zombies" "$z"; fi
    # clock sync: skewed clocks corrupt every correlation this tool does
    if have timedatectl; then
        local sync
        sync=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
        if [[ $sync == "yes" ]]; then verdict ok   "clock" "NTP synchronized"
        else                          verdict warn "clock" "not NTP-synchronized — log timestamps cannot be trusted for correlation"; fi
    fi
}
