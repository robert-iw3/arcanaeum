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
source:kubernetes.audit resource:ingresses verb:(create OR update)
| eval client_ip = mvindex(split(sourceIPs, ","), 0)
| where !(client_ip IN 10.0.0.0/8 OR client_ip IN 172.16.0.0/12 OR client_ip IN 192.168.0.0/16 OR client_ip IN 127.0.0.1/32)
| stats count by @timestamp, @user.username, @sourceIPs, client_ip, @verb, @objectRef.name, @objectRef.namespace, @requestURI
| rename @user.username as user, @sourceIPs as all_source_ips, client_ip as src_ip, @objectRef.name as ingress_name, @objectRef.namespace as k8s_namespace, @requestURI as api_request
| fields -count
```

### Shared Library Loading from /proc
---
```sql
source:(sysmon.process_create OR falco OR linux.audit)
(k8s.pod.name:(*ingress-nginx* OR *nginx-ingress-controller*) OR container.name:(*ingress-nginx* OR *nginx-ingress-controller*))
(process.path:*/proc/*/fd/* OR process.command_line:*/proc/*/fd/* OR file.path:*/proc/*/fd/*)
| stats count, min(@timestamp) as first_seen, max(@timestamp) as last_seen, values(process.command_line) as cmd_line, values(process.path) as proc_path by host, user, k8s.pod.name, container.name, process.name
| rename host as dest, k8s.pod.name as pod, container.name as container, process.name as process
```

### Suspicious NGINX Config Changes
---
```sql
source:kubernetes.audit resource:ingresses verb:(create OR update OR patch)
(requestObject:*nginx.ingress.kubernetes.io/auth-url* OR requestObject:*nginx.ingress.kubernetes.io/auth-tls-match-cn* OR requestObject:*nginx.ingress.kubernetes.io/mirror-target* OR requestObject:*nginx.ingress.kubernetes.io/mirror-host*)
| stats count, min(@timestamp) as first_seen, max(@timestamp) as last_seen, values(@verb) as actions, values(@requestObject) as request_body by @user.username, @sourceIPs, @objectRef.name, @objectRef.namespace
| rename @user.username as user, @sourceIPs as src_ip, @objectRef.name as ingress_name, @objectRef.namespace as k8s_namespace
```

### Unexpected Process/Shell in Ingress
---
```sql
source:(sysmon.process_create OR falco OR linux.audit)
(k8s.pod.name:(*ingress-nginx* OR *nginx-ingress-controller*) OR container.name:(*ingress-nginx* OR *nginx-ingress-controller*))
(process.name:(sh OR bash OR ash OR zsh OR ksh OR curl OR wget OR nc OR netcat OR ncat OR socat OR whoami OR id OR uname OR hostname OR pwd OR python* OR perl OR ruby) OR process.command_line:(* /dev/tcp/* OR * /dev/udp/*))
NOT (process.name:(nginx OR nginx-ingress-controller OR wait-shutdown OR tini OR dumb-init) OR process.path:/dbg)
| stats count, min(@timestamp) as first_seen, max(@timestamp) as last_seen, values(process.name) as suspicious_processes, values(process.command_line) as cmd_lines by host, user, k8s.pod.name, container.name, process.parent.name
| rename host as host, k8s.pod.name as pod, container.name as container, process.parent.name as parent_process
```

### Outbound from Ingress Namespace
---
```sql
source:(falco OR sysmon.network_connection OR corelight_conn OR zeek_conn) tags:(network AND communicate) namespace:(ingress-nginx OR nginx-ingress)
NOT (dest.ip:10.0.0.0/8 OR dest.ip:172.16.0.0/12 OR dest.ip:192.168.0.0/16 OR dest.ip:127.0.0.0/8 OR dest.ip:169.254.0.0/16)
| stats count, min(@timestamp) as first_seen, max(@timestamp) as last_seen, dc(dest.ip) as distinct_dest_count, values(dest.ip) as dest_ip, values(dest.port) as dest_port by src.ip, process.name, user, k8s.pod.name, k8s.namespace.name
| rename src.ip as src_ip, k8s.pod.name as pod, k8s.namespace.name as namespace
```