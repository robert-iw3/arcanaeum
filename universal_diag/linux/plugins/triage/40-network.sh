# triage/network — host network health below the application layer.
# Link state and error/drop rates per interface (from /sys/class/net, so no
# iproute2/net-tools dependency), plus conntrack table saturation, which
# silently drops new connections on busy container hosts.

network_detect() {
    PLUGIN_DETAIL[network]="ready"
    return 0
}

network_triage() {
    section "network"
    local ifdir ifname oper
    for ifdir in /sys/class/net/*; do
        ifname=${ifdir##*/}
        [[ $ifname == lo ]] && continue
        [[ -r $ifdir/operstate ]] || continue
        oper=$(cat "$ifdir/operstate" 2>/dev/null)
        # virtual/veth interfaces flap by design; only judge real links
        if [[ -e $ifdir/device ]]; then
            case $oper in
                up) : ;;
                down) verdict warn "link $ifname" "operstate down" ; continue ;;
                *)  verdict warn "link $ifname" "operstate $oper" ; continue ;;
            esac
        fi
        # error/drop counters (since boot) relative to packet volume
        local rxp txp errs drops pkts
        rxp=$(cat "$ifdir/statistics/rx_packets" 2>/dev/null || echo 0)
        txp=$(cat "$ifdir/statistics/tx_packets" 2>/dev/null || echo 0)
        errs=$(( $(cat "$ifdir/statistics/rx_errors" 2>/dev/null || echo 0) \
               + $(cat "$ifdir/statistics/tx_errors" 2>/dev/null || echo 0) ))
        drops=$(( $(cat "$ifdir/statistics/rx_dropped" 2>/dev/null || echo 0) \
                + $(cat "$ifdir/statistics/tx_dropped" 2>/dev/null || echo 0) ))
        pkts=$(( rxp + txp ))
        (( pkts == 0 )) && continue
        if (( errs * 1000 / pkts >= 1 )); then        # >= 0.1% error rate
            verdict warn "iface $ifname" "$errs errors / $pkts packets since boot — cabling, driver, or duplex"
        elif (( drops * 100 / pkts >= 1 )); then      # >= 1% drop rate
            verdict warn "iface $ifname" "$drops drops / $pkts packets since boot — ring buffer or qdisc pressure"
        else
            verdict ok "iface $ifname" "$oper, $pkts packets, $errs errors, $drops drops"
        fi
    done
    # conntrack saturation (only present when the module is loaded)
    if [[ -r /proc/sys/net/netfilter/nf_conntrack_count ]]; then
        local cc cm pct
        cc=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
        cm=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
        pct=$(( cc * 100 / cm ))
        if (( pct > 80 )); then verdict crit "conntrack" "${cc}/${cm} (${pct}%) — new connections will be dropped at 100%"
        else                    verdict ok   "conntrack" "${cc}/${cm} (${pct}%)"; fi
    fi
}
