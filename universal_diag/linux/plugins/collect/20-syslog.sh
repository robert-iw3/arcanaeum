# collect/syslog — classic /var/log files for non-systemd hosts (Alpine,
# sysvinit, openrc). Activates only when journald is not covering the host.
#
# RFC3164 timestamps carry no year/zone, so lines are emitted in local time
# and bounded by tail depth rather than the --since window — a PoC trade-off
# the Rust version resolves properly (ROADMAP A3).

SYSLOG_FILE=""

syslog_detect() {
    if [[ ${PLUGIN_ACTIVE[journald]:-0} -eq 1 ]]; then
        PLUGIN_DETAIL[syslog]="standby (journald covers it)"; return 1
    fi
    local f
    for f in /var/log/syslog /var/log/messages; do
        if [[ -r $f ]]; then
            SYSLOG_FILE=$f
            PLUGIN_DETAIL[syslog]="active ($f)"; return 0
        fi
    done
    PLUGIN_DETAIL[syslog]="unavailable (no readable syslog file)"; return 1
}

syslog_collect() {
    tail -n 5000 "$SYSLOG_FILE" 2>/dev/null | awk -v yr="$(date +%Y)" '
        BEGIN {
            split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", M, " ")
            for (i in M) mon[M[i]] = i
        }
        {
            if ($1 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/) {       # rsyslog ISO format
                ts = substr($1, 1, 23); first = 3
            } else if ($1 in mon) {                          # RFC3164: "Jul  2 18:00:00"
                ts = sprintf("%s-%02d-%02dT%s.000", yr, mon[$1], $2, $3); first = 5
            } else next
            tag = $(first)
            sub(/[\[:].*$/, "", tag)
            msg = ""
            for (i = first; i <= NF; i++) msg = msg (i > first ? " " : "") $i
            gsub(/\t/, " ", msg)
            low = tolower(msg)
            sev = ""
            if      (low ~ /fatal|panic|critical|emerg/)                              sev = "crit"
            else if (low ~ /error|failed|failure|refused|denied|exception|traceback/) sev = "error"
            else if (low ~ /warn/)                                                    sev = "warn"
            if (sev == "") next
            print ts "\t" sev "\t" "syslog" "\t" (tag == "" ? "-" : tag) "\t" msg
        }'
}
