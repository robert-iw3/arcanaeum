# profile/roles — what IS this host? Cast a wide net (listening sockets +
# running processes), narrow to roles with evidence. The roles decide where
# collection effort goes and give the analysis layer causal priors: a
# database is upstream of a web app, so when both appear in one incident
# the database ranks higher as culprit.
#
# Everything reads /proc directly — no ss/netstat/lsof dependency, works
# unprivileged (port->process mapping needs root, so roles are inferred
# from ports and process names independently and merged).
#
# Test hooks: PROFILE_PORTS_OVERRIDE / PROFILE_COMMS_OVERRIDE inject
# fake observations so role inference is testable on any machine.

roles_detect() {
    PLUGIN_DETAIL[roles]="ready"
    return 0
}

# listening TCP ports (state 0A) from /proc/net/tcp{,6}; hex port field
roles_ports() {
    if [[ -n ${PROFILE_PORTS_OVERRIDE:-} ]]; then
        tr ' ' '\n' <<<"$PROFILE_PORTS_OVERRIDE"; return
    fi
    local f
    for f in /proc/net/tcp /proc/net/tcp6; do
        [[ -r $f ]] || continue
        awk 'function hex2dec(h,  i,c,n) {
                 n = 0; h = toupper(h)
                 for (i = 1; i <= length(h); i++) {
                     c = index("0123456789ABCDEF", substr(h, i, 1)) - 1
                     n = n * 16 + c
                 }
                 return n
             }
             NR > 1 && $4 == "0A" { split($2, a, ":"); print hex2dec(a[2]) }' "$f"
    done | sort -un
}

roles_comms() {
    if [[ -n ${PROFILE_COMMS_OVERRIDE:-} ]]; then
        tr ' ' '\n' <<<"$PROFILE_COMMS_OVERRIDE"; return
    fi
    cat /proc/[0-9]*/comm 2>/dev/null | sort -u
}

# add_role <role> <confidence> <evidence> — merge evidence, keep max confidence
roles_add() {
    local role=$1 conf=$2 ev=$3
    if [[ -n ${PROFILE_ROLES[$role]:-} ]]; then
        PROFILE_EVIDENCE[$role]="${PROFILE_EVIDENCE[$role]}, $ev"
        [[ ${PROFILE_ROLES[$role]} == low && $conf != low ]] && PROFILE_ROLES[$role]=$conf
        [[ $conf == high ]] && PROFILE_ROLES[$role]=high
    else
        PROFILE_ROLES[$role]=$conf
        PROFILE_EVIDENCE[$role]=$ev
    fi
}

roles_profile() {
    # process-name signatures: comm -> role (high confidence: it IS running).
    # comm is truncated to 15 chars by the kernel — match accordingly.
    local -A COMM_SIG=(
        [nginx]=web [apache2]=web [httpd]=web [caddy]=web [lighttpd]=web
        [haproxy]=proxy [envoy]=proxy [traefik]=proxy [varnishd]=proxy
        [postgres]=database [mysqld]=database [mariadbd]=database
        [mongod]=database [clickhouse-serv]=database
        [redis-server]=cache [memcached]=cache
        [rabbitmq-server]=queue [beam.smp]=queue [kafka]=queue
        [dockerd]=container-host [containerd]=container-host [podman]=container-host
        [kubelet]=kubernetes-node [kube-apiserver]=kubernetes-node [k3s]=kubernetes-node
        [named]=dns [dnsmasq]=dns [unbound]=dns
        [postfix]=mail [exim4]=mail [dovecot]=mail [master]=mail
        [smbd]=file-server [nfsd]=file-server
        [prometheus]=monitoring [grafana]=monitoring [grafana-server]=monitoring
        [php-fpm]=app-runtime [gunicorn]=app-runtime [uwsgi]=app-runtime [node]=app-runtime
        [gnome-shell]=workstation [Xorg]=workstation [plasmashell]=workstation
        [sshd]=ssh-access
    )
    # port signatures: weaker evidence (medium) — something listens there
    local -A PORT_SIG=(
        [80]=web [443]=web [8080]=web [8443]=web
        [5432]=database [3306]=database [1433]=database [27017]=database
        [6379]=cache [11211]=cache
        [5672]=queue [9092]=queue
        [53]=dns [25]=mail [587]=mail [993]=mail
        [2049]=file-server [445]=file-server
        [6443]=kubernetes-node [10250]=kubernetes-node
        [9090]=monitoring [3000]=monitoring
    )

    local comm port
    while read -r comm; do
        [[ -n ${COMM_SIG[$comm]:-} ]] || continue
        roles_add "${COMM_SIG[$comm]}" high "$comm (process)"
        PROFILE_HINT[$comm]=${COMM_SIG[$comm]}
    done < <(roles_comms)
    while read -r port; do
        [[ -n ${PORT_SIG[$port]:-} ]] || continue
        roles_add "${PORT_SIG[$port]}" medium "port $port"
    done < <(roles_ports)

    [[ ${#PROFILE_ROLES[@]} -eq 0 ]] && roles_add general low "no known signatures matched"

    # what each role means for collection focus (feeds the human report)
    PROFILE_FOCUS[web]="prioritize web-server units/containers; watch for upstream connect failures and 5xx bursts"
    PROFILE_FOCUS[proxy]="proxy sits in front of everything — its errors usually point downstream, low culprit prior"
    PROFILE_FOCUS[database]="database is upstream of most services — collect its logs first; slow-query/connection-limit patterns"
    PROFILE_FOCUS[cache]="evictions and OOM here cascade to app latency"
    PROFILE_FOCUS[queue]="consumer lag and rejected publishes precede downstream timeouts"
    PROFILE_FOCUS[container-host]="collect container logs + runtime daemon; conntrack and overlay-fs triage matter here"
    PROFILE_FOCUS[kubernetes-node]="k8s events + kubelet + container runtime; watch evictions and image pulls"
    PROFILE_FOCUS[dns]="upstream of everything that resolves names — high culprit prior on timeout storms"
    PROFILE_FOCUS[mail]="queue growth and deferred delivery patterns"
    PROFILE_FOCUS[file-server]="storage triage (disk/inode/io) weighs double here"
    PROFILE_FOCUS[monitoring]="scrape failures here are usually symptoms, not causes"
    PROFILE_FOCUS[app-runtime]="application-level logs; correlate with whatever this host's upstream roles report"
    PROFILE_FOCUS[workstation]="desktop session noise is normal — raise digest thresholds"
    PROFILE_FOCUS[ssh-access]="auth failures and lockouts; btmp growth"
    PROFILE_FOCUS[general]="no role detected — collect everything, let frequency baselines find what matters"
}
