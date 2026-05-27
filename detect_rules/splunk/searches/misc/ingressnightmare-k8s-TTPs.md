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
`comment("This detection rule identifies attempts to create or update a Kubernetes Ingress object from a public IP address, which is a primary attack vector for exploiting vulnerabilities like IngressNightmare (CVE-2025-1974).")`
(index=k8s_audit OR sourcetype=kube:audit) objectRef.resource="ingresses" verb IN ("create", "update")

| `comment("The sourceIPs field can contain multiple IPs (e.g., proxy chains). We will evaluate the first IP in the list as the most likely client IP.")`
  eval client_ip=mvindex(split(sourceIPs,","),0)

| `comment("Filter out requests originating from private/internal IP address ranges (RFC1918) to focus on external access.")`
  where NOT (cidrmatch("10.0.0.0/8", client_ip) OR cidrmatch("172.16.0.0/12", client_ip) OR cidrmatch("192.168.0.0/16", client_ip) OR cidrmatch("127.0.0.1/32", client_ip))

`comment("FP Note: Legitimate administrative actions or CI/CD pipelines may originate from non-private IP addresses. To reduce noise, create an allowlist of trusted external IPs.")`
`comment("Example allowlist lookup: | lookup trusted_external_ips.csv ip as client_ip OUTPUT ip as trusted_ip | where isnull(trusted_ip)")`

| `comment("Format the results for alerting and investigation.")`
  stats count by _time, user.username, sourceIPs, client_ip, verb, objectRef.name, objectRef.namespace, requestURI
| rename user.username as user, sourceIPs as all_source_ips, client_ip as src_ip, objectRef.name as ingress_name, objectRef.namespace as k8s_namespace, requestURI as api_request
| fields - count
```

### Shared Library Loading from /proc
---
```sql
`comment("This detection rule identifies a key indicator of IngressNightmare (CVE-2025-1974) exploitation by looking for shared library loading from a /proc file descriptor within an NGINX Ingress container.")`
(index=* sourcetype IN (sysmon:process_create, falco, linux:audit))
`comment("Filter for events originating from NGINX Ingress Controller pods or containers.")`
(k8s.pod.name IN ("*ingress-nginx*", "*nginx-ingress-controller*") OR container.name IN ("*ingress-nginx*", "*nginx-ingress-controller*"))
`comment("Identify the specific fileless execution pattern in the process command line or file path.")`
(process_path="*/proc/*/fd/*" OR process_command_line="*/proc/*/fd/*" OR file_path="*/proc/*/fd/*")

| `comment("FP Note: This activity is highly anomalous. If FPs occur, it may be necessary to tune the container/pod name filter to match your specific environment's naming convention.")`

| `comment("Aggregate results for alerting and investigation.")`
  stats count earliest(_time) as first_seen latest(_time) as last_seen values(process_command_line) as cmd_line values(process_path) as proc_path by dest, user, k8s.pod.name, container.name, process_name

| `comment("Rename fields for clarity and CIM compliance.")`
  rename k8s.pod.name as pod, container.name as container, process_name as process
```

### Suspicious NGINX Config Changes
---
```sql
`comment("This rule detects the creation or modification of a Kubernetes Ingress object that includes potentially risky NGINX annotations. These annotations can be abused in exploits like IngressNightmare to achieve remote code execution or bypass security controls.")`
(index=k8s_audit OR sourcetype=kube:audit) objectRef.resource="ingresses" verb IN ("create", "update", "patch")
`comment("Search the request object for specific annotations that can be leveraged for malicious purposes.")`
(requestObject LIKE "%nginx.ingress.kubernetes.io/auth-url%" OR requestObject LIKE "%nginx.ingress.kubernetes.io/auth-tls-match-cn%" OR requestObject LIKE "%nginx.ingress.kubernetes.io/mirror-target%" OR requestObject LIKE "%nginx.ingress.kubernetes.io/mirror-host%")

| `comment("FP Note: These annotations are legitimate NGINX Ingress features. This alert flags their use for security review. Investigate the values set for these annotations. Malicious use may involve pointing to internal services (e.g., kubernetes.default.svc), using wildcards to bypass auth, or pointing to attacker-controlled domains. Consider creating an allowlist of known-good user agents or source IPs for legitimate changes.")`

| `comment("Aggregate results to summarize the activity for investigation.")`
  stats count earliest(_time) as first_seen latest(_time) as last_seen values(verb) as actions values(requestObject) as request_body by user.username, sourceIPs, objectRef.name, objectRef.namespace

| `comment("Rename fields for clarity.")`
  rename user.username as user, sourceIPs as src_ip, objectRef.name as ingress_name, objectRef.namespace as k8s_namespace
```

### Unexpected Process/Shell in Ingress
---
```sql
`comment("This rule detects unexpected process execution or shell activity originating from an NGINX Ingress Controller pod, which is a strong indicator of post-exploitation activity for vulnerabilities like IngressNightmare.")`
(index=* sourcetype IN (sysmon:process_create, falco, linux:audit))
`comment("Filter for events originating from NGINX Ingress Controller pods or containers based on common naming conventions.")`
(k8s.pod.name IN ("*ingress-nginx*", "*nginx-ingress-controller*") OR container.name IN ("*ingress-nginx*", "*nginx-ingress-controller*"))

`comment("Identify common shell, interpreter, and reconnaissance tools an attacker might use. Exclude known legitimate processes.")`
(process_name IN ("sh", "bash", "ash", "zsh", "ksh", "curl", "wget", "nc", "netcat", "ncat", "socat", "whoami", "id", "uname", "hostname", "pwd", "python*", "perl", "ruby") OR process_command_line IN ("* /dev/tcp/*", "* /dev/udp/*"))
NOT (process_name IN ("nginx", "nginx-ingress-controller", "wait-shutdown", "tini", "dumb-init") OR process_path="/dbg")

| `comment("FP Note: Legitimate administrative or debugging activity (e.g., using 'kubectl exec') can trigger this alert. Consider creating an allowlist for specific users or parent processes if this is common practice in your environment.")`

| `comment("Aggregate results to summarize the activity for investigation.")`
  stats count earliest(_time) as first_seen latest(_time) as last_seen values(process_name) as suspicious_processes values(process_command_line) as cmd_lines by dest, user, k8s.pod.name, container.name, parent_process_name

| `comment("Rename fields for clarity and CIM compliance.")`
  rename dest as host, k8s.pod.name as pod, container.name as container, parent_process_name as parent_process
```

### Outbound from Ingress Namespace
---
```sql
`comment("This rule detects outbound network connections from the NGINX Ingress Controller namespace to external IP addresses. This can be an indicator of post-exploitation activity like C2 communication, lateral movement, or data exfiltration following a compromise like IngressNightmare. MITRE TTP: T1071. Intel ID: 3b5821146b531d558673907ad5e84ec063c148becdeda2ed059c0241270eb934")`
(index=* sourcetype IN (falco, sysmon:network_connection, corelight_conn, zeek_conn) OR (tag=network tag=communicate))
`comment("Filter for events originating from the ingress-nginx namespace.")`
(k8s.namespace.name IN ("ingress-nginx", "nginx-ingress"))

`comment("Exclude connections to internal, private, loopback, and link-local IP addresses.")`
NOT (cidrmatch("10.0.0.0/8", dest) OR cidrmatch("172.16.0.0/12", dest) OR cidrmatch("192.168.0.0/16", dest) OR cidrmatch("127.0.0.0/8", dest) OR cidrmatch("169.254.0.0/16", dest))

| `comment("FP Note: The ingress controller may make legitimate external connections for OCSP/CRL checks, to external auth providers, or to cloud metadata services (e.g., 169.254.169.254). Consider excluding your cluster's internal service CIDR (e.g., 10.96.0.0/12). Create an allowlist of known-good destination IPs or domains to reduce noise.")`

| `comment("Aggregate results to summarize the connections for investigation.")`
  stats count earliest(_time) as first_seen latest(_time) as last_seen dc(dest) as distinct_dest_count values(dest) as dest_ips values(dest_port) as dest_ports by src, process_name, user, k8s.pod.name, k8s.namespace.name

| `comment("Rename fields for clarity and CIM compliance.")`
  rename src as src_ip, k8s.pod.name as pod, k8s.namespace.name as namespace, dest_ips as dest_ip, dest_ports as dest_port
```