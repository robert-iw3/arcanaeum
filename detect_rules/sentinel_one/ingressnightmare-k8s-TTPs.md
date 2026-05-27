### IngressNightmare Vulnerabilities in Kubernetes NGINX Ingress Controller
---

IngressNightmare refers to a set of critical vulnerabilities, most notably CVE-2025-1974, affecting the Kubernetes NGINX Ingress Controller that can lead to unauthenticated remote code execution (RCE) and potential cluster takeover. These vulnerabilities arise from improper input validation and a design flaw in how the admission controller processes and validates incoming ingress objects, allowing attackers to inject malicious NGINX configurations.

Recent intelligence highlights that while CVE-2025-1974 is the most severe, it is often chained with other vulnerabilities like CVE-2025-24514, CVE-2025-1097, and CVE-2025-1098, which enable configuration injection, to achieve unauthenticated RCE and full cluster compromise. This multi-stage attack emphasizes the importance of addressing all related CVEs and not just the critical RCE.

### Actionable Threat Data
---

Monitor for attempts to access the NGINX Ingress Controller's admission webhook, especially if it's exposed externally, as this is a primary attack vector for IngressNightmare exploitation.

Detect the loading of shared libraries from `/proc` within the NGINX Ingress container, specifically by searching for activity in `/proc/*/fd/*`, as this is a key indicator of CVE-2025-1974 exploitation.

Look for suspicious NGINX configuration changes or injections via ingress annotations (`auth-url`, `auth-tls-match-cn`, `mirror-target`, `mirror-host`) that could indicate attempts to leverage CVE-2025-24514, CVE-2025-1097, or CVE-2025-1098.

Identify and alert on any unexpected process execution or shell activity originating from the `ingress-nginx` controller pod, as successful exploitation grants attackers arbitrary code execution within this highly privileged context.

Implement detections for outbound connections from the `ingress-nginx` namespace to unusual or external IP addresses, which could signify lateral movement or data exfiltration post-exploitation.

### IngressNightmare Webhook Access
---
```sql
event.type:kubernetes.audit AND kubernetes.resource:ingresses AND event.action IN (create, update)
| LET client_ip = array_index(split(source.ip, ","), 0)
| WHERE NOT (client_ip MATCHES "10.0.0.0/8" OR client_ip MATCHES "172.16.0.0/12" OR client_ip MATCHES "192.168.0.0/16" OR client_ip MATCHES "127.0.0.1/32")
| GROUP BY timestamp, user.name, source.ip, client_ip, event.action, kubernetes.object.name, kubernetes.namespace, http.request.uri
| SELECT timestamp, user.name AS user, source.ip AS all_source_ips, client_ip AS src_ip, kubernetes.object.name AS ingress_name, kubernetes.namespace AS k8s_namespace, http.request.uri AS api_request
```

### Shared Library Loading from /proc
---
```sql
event.type IN (sysmon.process_create, falco, linux.audit)
AND (kubernetes.pod.name MATCHES "*ingress-nginx*" OR kubernetes.pod.name MATCHES "*nginx-ingress-controller*" OR container.name MATCHES "*ingress-nginx*" OR container.name MATCHES "*nginx-ingress-controller*")
AND (process.executable MATCHES "*/proc/*/fd/*" OR process.command_line MATCHES "*/proc/*/fd/*" OR file.path MATCHES "*/proc/*/fd/*")
| GROUP BY host.name, user.name, kubernetes.pod.name, container.name, process.name
| SELECT MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen, ARRAY_DISTINCT(process.command_line) AS cmd_line, ARRAY_DISTINCT(process.executable) AS proc_path, host.name AS dest, user.name AS user, kubernetes.pod.name AS pod, container.name AS container, process.name AS process
```

### Suspicious NGINX Config Changes
---
```sql
event.type:kubernetes.audit AND kubernetes.resource:ingresses AND event.action IN (create, update, patch)
AND (kubernetes.request_object MATCHES "*nginx.ingress.kubernetes.io/auth-url*" OR kubernetes.request_object MATCHES "*nginx.ingress.kubernetes.io/auth-tls-match-cn*" OR kubernetes.request_object MATCHES "*nginx.ingress.kubernetes.io/mirror-target*" OR kubernetes.request_object MATCHES "*nginx.ingress.kubernetes.io/mirror-host*")
| GROUP BY user.name, source.ip, kubernetes.object.name, kubernetes.namespace
| SELECT MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen, ARRAY_DISTINCT(event.action) AS actions, ARRAY_DISTINCT(kubernetes.request_object) AS request_body, user.name AS user, source.ip AS src_ip, kubernetes.object.name AS ingress_name, kubernetes.namespace AS k8s_namespace
```

### Unexpected Process/Shell in Ingress
---
```sql
event.type IN (sysmon.process_create, falco, linux.audit)
AND (kubernetes.pod.name MATCHES "*ingress-nginx*" OR kubernetes.pod.name MATCHES "*nginx-ingress-controller*" OR container.name MATCHES "*ingress-nginx*" OR container.name MATCHES "*nginx-ingress-controller*")
AND (process.name IN (sh, bash, ash, zsh, ksh, curl, wget, nc, netcat, ncat, socat, whoami, id, uname, hostname, pwd, "python*", perl, ruby) OR process.command_line MATCHES "* /dev/tcp/*" OR process.command_line MATCHES "* /dev/udp/*")
AND NOT (process.name IN (nginx, nginx-ingress-controller, wait-shutdown, tini, dumb-init) OR process.executable = "/dbg")
| GROUP BY host.name, user.name, kubernetes.pod.name, container.name, process.parent.name
| SELECT MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen, ARRAY_DISTINCT(process.name) AS suspicious_processes, ARRAY_DISTINCT(process.command_line) AS cmd_lines, host.name AS host, user.name AS user, kubernetes.pod.name AS pod, container.name AS container, process.parent.name AS parent_process
```

### Outbound from Ingress Namespace
---
```sql
event.type IN (falco, sysmon.network_connection, corelight_conn, zeek_conn) OR (event.category:network AND event.type:connection)
AND kubernetes.namespace IN (ingress-nginx, nginx-ingress)
AND NOT (destination.ip MATCHES "10.0.0.0/8" OR destination.ip MATCHES "172.16.0.0/12" OR destination.ip MATCHES "192.168.0.0/16" OR destination.ip MATCHES "127.0.0.0/8" OR destination.ip MATCHES "169.254.0.0/16")
| GROUP BY source.ip, process.name, user.name, kubernetes.pod.name, kubernetes.namespace
| SELECT MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen, COUNT_DISTINCT(destination.ip) AS distinct_dest_count, ARRAY_DISTINCT(destination.ip) AS dest_ip, ARRAY_DISTINCT(destination.port) AS dest_port, source.ip AS src_ip, process.name, user.name, kubernetes.pod.name AS pod, kubernetes.namespace AS namespace
```