# collect/journald — systemd journal, including the kernel ring buffer.
# Primary collector on systemd distros; requires jq for JSON parsing.

journald_detect() {
    if [[ $HAS_JQ -eq 0 ]]; then
        PLUGIN_DETAIL[journald]="unavailable (jq missing)"; return 1
    fi
    if have journalctl && journalctl -n 1 -q >/dev/null 2>&1; then
        PLUGIN_DETAIL[journald]="active (includes kernel ring buffer)"; return 0
    fi
    PLUGIN_DETAIL[journald]="unavailable"; return 1
}

journald_collect() {
    journalctl --no-pager --since "$SINCE_JOURNAL" -p warning -o json 2>/dev/null | jq -r '
        def sev: {"0":"crit","1":"crit","2":"crit","3":"error","4":"warn"}[.] // "warn";
        def msg: if type == "array" then implode else tostring end
                 | gsub("[\t\n]"; " ");
        (.__REALTIME_TIMESTAMP | tonumber) as $us |
        [ ( ($us / 1000000 | floor | strftime("%Y-%m-%dT%H:%M:%S"))
            + "." + ("00" + (($us % 1000000 / 1000 | floor) | tostring) | .[-3:]) + "Z" ),
          ( .PRIORITY // "4" | sev ),
          ( if ._TRANSPORT == "kernel" then "kernel" else "journald" end ),
          ( ._SYSTEMD_UNIT // .SYSLOG_IDENTIFIER // "-" ),
          ( .MESSAGE // "" | msg )
        ] | @tsv'
}
