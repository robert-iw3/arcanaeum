# collect/container — docker or podman container logs.
# Container logs have no severity field: classify by message content.

CONTAINER_BIN=""

container_detect() {
    if have docker && docker ps >/dev/null 2>&1; then
        CONTAINER_BIN=docker
    elif have podman && podman ps >/dev/null 2>&1; then
        CONTAINER_BIN=podman
    fi
    if [[ -n $CONTAINER_BIN ]]; then
        PLUGIN_DETAIL[container]="active via $CONTAINER_BIN ($("$CONTAINER_BIN" ps -q 2>/dev/null | wc -l) running)"
        return 0
    fi
    PLUGIN_DETAIL[container]="unavailable"; return 1
}

container_collect() {
    local name
    "$CONTAINER_BIN" ps --format '{{.Names}}' 2>/dev/null | while read -r name; do
        "$CONTAINER_BIN" logs --since "$SINCE_DOCKER" --timestamps "$name" 2>&1 \
        | awk -v origin="$name" -v src="$CONTAINER_BIN" '
            {
                ts = $1
                if (ts !~ /^[0-9]{4}-/) next          # skip lines with no timestamp
                msg = substr($0, length(ts) + 2)
                gsub(/[\t]/, " ", msg)
                low = tolower(msg)
                sev = ""
                if      (low ~ /fatal|panic|critical|emerg/)                              sev = "crit"
                else if (low ~ /error|failed|failure|refused|denied|exception|traceback/) sev = "error"
                else if (low ~ /warn/)                                                    sev = "warn"
                if (sev == "") next
                # trim ns precision to ms so all sources sort together
                if (length(ts) > 24) ts = substr(ts, 1, 23) "Z"
                print ts "\t" sev "\t" src "\t" origin "\t" msg
            }'
    done
}
