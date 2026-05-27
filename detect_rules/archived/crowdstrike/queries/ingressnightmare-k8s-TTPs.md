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
event_platform="Kubernetes" event_type="Audit" resource_type="ingresses" verb IN ("create", "update")
| project client_ip = array_element(split(sourceIPs, ","), 0)
| ! (client_ip LIKE "10.0.0.0/8" OR client_ip LIKE "172.16.0.0/12" OR client_ip LIKE "192.168.0.0/16" OR client_ip LIKE "127.0.0.1/32")
| group by timestamp, user_username, sourceIPs, client_ip, verb, object_name, object_namespace, request_uri
| project timestamp, user_username as user, sourceIPs as all_source_ips, client_ip as src_ip, object_name as ingress_name, object_namespace as k8s_namespace, request_uri as api_request
```

### Shared Library Loading from /proc
---
```sql
event_platform IN ("Sysmon", "Falco", "LinuxAudit") event_type="ProcessCreate"
| (k8s_pod_name LIKE "*ingress-nginx*" OR k8s_pod_name LIKE "*nginx-ingress-controller*" OR container_name LIKE "*ingress-nginx*" OR container_name LIKE "*nginx-ingress-controller*")
| (process_path LIKE "*/proc/*/fd/*" OR command_line LIKE "*/proc/*/fd/*" OR file_path LIKE "*/proc/*/fd/*")
| group by host, user, k8s_pod_name, container_name, process_name
| project earliest(timestamp) as first_seen, latest(timestamp) as last_seen, array_distinct(command_line) as cmd_line, array_distinct(process_path) as proc_path, host as dest, user, k8s_pod_name as pod, container_name as container, process_name as process
```

### Suspicious NGINX Config Changes
---
```sql
event_platform="Kubernetes" event_type="Audit" resource_type="ingresses" verb IN ("create", "update", "patch")
| request_object LIKE "*nginx.ingress.kubernetes.io/auth-url*" OR request_object LIKE "*nginx.ingress.kubernetes.io/auth-tls-match-cn*" OR request_object LIKE "*nginx.ingress.kubernetes.io/mirror-target*" OR request_object LIKE "*nginx.ingress.kubernetes.io/mirror-host*"
| group by user_username, sourceIPs, object_name, object_namespace
| project earliest(timestamp) as first_seen, latest(timestamp) as last_seen, array_distinct(verb) as actions, array_distinct(request_object) as request_body, user_username as user, sourceIPs as src_ip, object_name as ingress_name, object_namespace as k8s_namespace
```

### Unexpected Process/Shell in Ingress
---
```sql
event_platform IN ("Sysmon", "Falco", "LinuxAudit") event_type="ProcessCreate"
| (k8s_pod_name LIKE "*ingress-nginx*" OR k8s_pod_name LIKE "*nginx-ingress-controller*" OR container_name LIKE "*ingress-nginx*" OR container_name LIKE "*nginx-ingress-controller*")
| (process_name IN ("sh", "bash", "ash", "zsh", "ksh", "curl", "wget", "nc", "netcat", "ncat", "socat", "whoami", "id", "uname", "hostname", "pwd", "python*", "perl", "ruby") OR command_line LIKE "* /dev/tcp/*" OR command_line LIKE "* /dev/udp/*")
| ! (process_name IN ("nginx", "nginx-ingress-controller", "wait-shutdown", "tini", "dumb-init") OR process_path="/dbg")
| group by host, user, k8s_pod_name, container_name, parent_process_name
| project earliest(timestamp) as first_seen, latest(timestamp) as last_seen, array_distinct(process_name) as suspicious_processes, array_distinct(command_line) as cmd_lines, host, user, k8s_pod_name as pod, container_name as container, parent_process_name as parent_process
```

### Outbound from Ingress Namespace
---
```sql
event_platform IN ("Falco", "Sysmon", "CorelightConn", "ZeekConn") event_type="NetworkConnection"
| k8s_namespace_name IN ("ingress-nginx", "nginx-ingress")
| ! (dest_ip LIKE "10.0.0.0/8" OR dest_ip LIKE "172.16.0.0/12" OR dest_ip LIKE "192.168.0.0/16" OR dest_ip LIKE "127.0.0.0/8" OR dest_ip LIKE "169.254.0.0/16")
| group by src_ip, process_name, user, k8s_pod_name, k8s_namespace_name
| project earliest(timestamp) as first_seen, latest(timestamp) as last_seen, count_distinct(dest_ip) as distinct_dest_count, array_distinct(dest_ip) as dest_ip, array_distinct(dest_port) as dest_port, src_ip, process_name, user, k8s_pod_name as pod, k8s_namespace_name as namespace
```