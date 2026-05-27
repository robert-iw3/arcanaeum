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
FROM *
| WHERE event.dataset == "kubernetes.audit" AND kubernetes.resource == "ingresses" AND event.action IN ("create", "update")
| EVAL client_ip = MV_EXTRACT(SPLIT(source.ip, ","), 0)
| WHERE NOT (client_ip LIKE "10.0.0.0/8" OR client_ip LIKE "172.16.0.0/12" OR client_ip LIKE "192.168.0.0/16" OR client_ip LIKE "127.0.0.1/32")
| STATS count = COUNT(*) BY @timestamp, user.name, source.ip, client_ip, event.action, kubernetes.name, kubernetes.namespace, http.request.path
| EVAL user = user.name, all_source_ips = source.ip, src_ip = client_ip, ingress_name = kubernetes.name, k8s_namespace = kubernetes.namespace, api_request = http.request.path
| KEEP @timestamp, user, all_source_ips, src_ip, ingress_name, k8s_namespace, api_request
```

### Shared Library Loading from /proc
---
```sql
FROM *
| WHERE event.dataset IN ("sysmon.process_create", "falco", "linux.audit")
  AND (kubernetes.pod.name LIKE "*ingress-nginx*" OR kubernetes.pod.name LIKE "*nginx-ingress-controller*" OR container.name LIKE "*ingress-nginx*" OR container.name LIKE "*nginx-ingress-controller*")
  AND (process.executable LIKE "*/proc/*/fd/*" OR process.args LIKE "*/proc/*/fd/*" OR file.path LIKE "*/proc/*/fd/*")
| STATS count = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), cmd_line = ARRAY_DISTINCT(process.args), proc_path = ARRAY_DISTINCT(process.executable) BY host.name, user.name, kubernetes.pod.name, container.name, process.name
| EVAL dest = host.name, pod = kubernetes.pod.name, container = container.name, process = process.name
| KEEP first_seen, last_seen, cmd_line, proc_path, dest, user.name, pod, container, process
```

### Suspicious NGINX Config Changes
---
```sql
FROM *
| WHERE event.dataset == "kubernetes.audit" AND kubernetes.resource == "ingresses" AND event.action IN ("create", "update", "patch")
  AND (kubernetes.request_object LIKE "*nginx.ingress.kubernetes.io/auth-url*" OR kubernetes.request_object LIKE "*nginx.ingress.kubernetes.io/auth-tls-match-cn*" OR kubernetes.request_object LIKE "*nginx.ingress.kubernetes.io/mirror-target*" OR kubernetes.request_object LIKE "*nginx.ingress.kubernetes.io/mirror-host*")
| STATS count = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), actions = ARRAY_DISTINCT(event.action), request_body = ARRAY_DISTINCT(kubernetes.request_object) BY user.name, source.ip, kubernetes.name, kubernetes.namespace
| EVAL user = user.name, src_ip = source.ip, ingress_name = kubernetes.name, k8s_namespace = kubernetes.namespace
| KEEP first_seen, last_seen, actions, request_body, user, src_ip, ingress_name, k8s_namespace
```

### Unexpected Process/Shell in Ingress
---
```sql
FROM *
| WHERE event.dataset IN ("sysmon.process_create", "falco", "linux.audit")
  AND (kubernetes.pod.name LIKE "*ingress-nginx*" OR kubernetes.pod.name LIKE "*nginx-ingress-controller*" OR container.name LIKE "*ingress-nginx*" OR container.name LIKE "*nginx-ingress-controller*")
  AND (process.name IN ("sh", "bash", "ash", "zsh", "ksh", "curl", "wget", "nc", "netcat", "ncat", "socat", "whoami", "id", "uname", "hostname", "pwd", "python*", "perl", "ruby") OR process.args LIKE "* /dev/tcp/*" OR process.args LIKE "* /dev/udp/*")
  AND NOT (process.name IN ("nginx", "nginx-ingress-controller", "wait-shutdown", "tini", "dumb-init") OR process.executable == "/dbg")
| STATS count = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), suspicious_processes = ARRAY_DISTINCT(process.name), cmd_lines = ARRAY_DISTINCT(process.args) BY host.name, user.name, kubernetes.pod.name, container.name, process.parent.name
| EVAL host = host.name, pod = kubernetes.pod.name, container = container.name, parent_process = process.parent.name
| KEEP first_seen, last_seen, suspicious_processes, cmd_lines, host, user.name, pod, container, parent_process
```

### Outbound from Ingress Namespace
---
```sql
FROM *
| WHERE event.dataset IN ("falco", "sysmon.network_connection", "corelight_conn", "zeek_conn") OR (event.category == "network" AND event.type == "connection")
  AND kubernetes.namespace IN ("ingress-nginx", "nginx-ingress")
  AND NOT (destination.ip LIKE "10.0.0.0/8" OR destination.ip LIKE "172.16.0.0/12" OR destination.ip LIKE "192.168.0.0/16" OR destination.ip LIKE "127.0.0.0/8" OR destination.ip LIKE "169.254.0.0/16")
| STATS count = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), distinct_dest_count = COUNT_DISTINCT(destination.ip), dest_ip = ARRAY_DISTINCT(destination.ip), dest_port = ARRAY_DISTINCT(destination.port) BY source.ip, process.name, user.name, kubernetes.pod.name, kubernetes.namespace
| EVAL src_ip = source.ip, pod = kubernetes.pod.name, namespace = kubernetes.namespace
| KEEP first_seen, last_seen, distinct_dest_count, dest_ip, dest_port, src_ip, process.name, user.name, pod, namespace
```