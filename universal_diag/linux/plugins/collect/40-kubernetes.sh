# collect/kubernetes — cluster warning events via kubectl.
# Pod log collection is Phase A territory (ROADMAP A1); events only for now.

kubernetes_detect() {
    if [[ $HAS_JQ -eq 0 ]]; then
        PLUGIN_DETAIL[kubernetes]="unavailable (jq missing)"; return 1
    fi
    if have kubectl && kubectl version --request-timeout=2s >/dev/null 2>&1; then
        PLUGIN_DETAIL[kubernetes]="active"; return 0
    fi
    PLUGIN_DETAIL[kubernetes]="unavailable"; return 1
}

kubernetes_collect() {
    kubectl get events -A --field-selector type=Warning -o json 2>/dev/null \
    | jq -r --arg cutoff "$CUTOFF_ISO" '
        .items[]
        | (.lastTimestamp // .eventTime // empty) as $ts
        | select($ts >= $cutoff)
        | [ ($ts | sub("Z$"; ".000Z") | sub("\\.000\\.000Z$"; ".000Z")),
            "warn",
            "k8s",
            (.involvedObject.namespace // "-") + "/" + (.involvedObject.name // "-"),
            ((.reason // "-") + ": " + (.message // "" | gsub("[\t\n]"; " ")))
          ] | @tsv'
}
