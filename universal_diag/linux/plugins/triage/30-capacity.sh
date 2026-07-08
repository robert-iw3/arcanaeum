# triage/capacity — what is quietly running out?
# Disk space, inodes, and system-wide file descriptors.

capacity_detect() {
    PLUGIN_DETAIL[capacity]="ready"
    return 0
}

capacity_triage() {
    section "capacity"
    # disk space + inodes per real filesystem. POSIX df only (-P/-i); GNU
    # -x/--local are not portable, so pseudo-filesystems are filtered by
    # device name: keep /dev/* block devices and host:/path network mounts.
    local line
    while read -r line; do
        set -- $line
        local mnt=$6 use=${5%\%}
        if   (( use >= 95 )); then verdict crit "disk $mnt" "${use}% full — writes will start failing"
        elif (( use >= 85 )); then verdict warn "disk $mnt" "${use}% full"
        else                       verdict ok   "disk $mnt" "${use}% full"; fi
    done < <(df -P 2>/dev/null | awk 'NR > 1 && ($1 ~ /^\/dev\// || $1 ~ /^[^ ]+:\//)')
    while read -r line; do
        set -- $line
        local mnt=$6 use=${5%\%}
        [[ $use == "-" ]] && continue
        if (( use >= 90 )); then verdict crit "inodes $mnt" "${use}% used — 'no space left' with free GB is this"
        elif (( use >= 80 )); then verdict warn "inodes $mnt" "${use}% used"; fi
    done < <(df -Pi 2>/dev/null | awk 'NR > 1 && ($1 ~ /^\/dev\// || $1 ~ /^[^ ]+:\//)')
    # system-wide file descriptors
    if [[ -r /proc/sys/fs/file-nr ]]; then
        local alloc max
        read -r alloc _ max < /proc/sys/fs/file-nr
        local pct=$(( alloc * 100 / max ))
        if (( pct > 80 )); then verdict warn "file descriptors" "${alloc}/${max} (${pct}%) — an fd leak somewhere"
        else                    verdict ok   "file descriptors" "${alloc}/${max} (${pct}%)"; fi
    fi
}
