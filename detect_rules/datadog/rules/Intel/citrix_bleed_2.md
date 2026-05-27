### CitrixBleed 2 (CVE-2025-5777) Threat Intelligence Report
---

CVE-2025-5777, dubbed "CitrixBleed 2," is a critical memory disclosure vulnerability in Citrix NetScaler ADC and Gateway appliances that allows attackers to leak sensitive memory content, including session tokens and plaintext credentials, by sending specially crafted HTTP requests. This vulnerability is actively exploited in the wild, enabling attackers to bypass multi-factor authentication (MFA) and hijack user sessions, posing a significant risk to affected organizations.


Exploitation of CVE-2025-5777 began as early as June 23, 2025, nearly two weeks before a public Proof-of-Concept (PoC) was released on July 4, 2025, and despite initial denials of in-the-wild exploitation by Citrix. This early and unacknowledged exploitation highlights a critical gap in vendor transparency and significantly hampered defenders' ability to proactively detect and mitigate attacks, forcing security teams to rely on third-party research for actionable intelligence.

### Actionable Threat Data
---

Monitor Citrix NetScaler logs for HTTP `POST` requests to the `/p/u/doAuthentication.do` endpoint that contain malformed "login" parameters or other incomplete structures, as these indicate attempts to trigger the memory disclosure vulnerability.

Look for log entries from NetScaler appliances containing non-printable characters, particularly within debug logs (e.g., ns.log), as this can indicate leaked memory content, including session tokens or credentials. This requires debug-level logging to be enabled on the NetScaler.

Detect instances where a single user account has concurrent active sessions originating from multiple distinct IP addresses, especially if those IPs are associated with consumer VPN services or known malicious infrastructure, which may indicate session hijacking.

Audit NetScaler configurations for newly added backdoor accounts or unauthorized modifications to existing configurations, which could indicate post-exploitation activity. Compare current running configurations (show ns runningConfig) against known good baselines.

Investigate any suspicious activity originating from published systems or resources accessible through NetScaler appliances, such as unusual LDAP queries or the use of reconnaissance tools (e.g., `ADExplorer64.exe`), as these may signal lateral movement after successful session hijacking.

### Malformed Login Requests
---
```sql
-- Rule Title: CitrixBleed 2 (CVE-2025-5777) Malformed Login Request
-- Rule Description: This detection identifies potential exploitation attempts of the CitrixBleed 2 vulnerability (CVE-2025-5777). The exploit involves sending a -- specially crafted HTTP POST request to the '/p/u/doAuthentication.do' endpoint with a 'login' parameter that has no value. This causes the server to leak -- memory in its response. This search looks for this specific pattern in web traffic logs.
-- Date: 2025-07-24")`

(source:pan* OR source:stream_http OR source:suricata OR source:cisco_ftd) http.method:POST http.url:*/p/u/doAuthentication.do
| select http.form_data AS form_data, ip.src AS src_ip, ip.dst AS dest_ip, http.user_agent AS user_agent, user
| where form_data:/login=(?:&|$)/
| aggregate count, min(timestamp) AS first_seen, max(timestamp) AS last_seen, collect(http.url) AS urls, collect(form_data) AS sample_post_bodies by src_ip, dest_ip, user, user_agent
```

### Non-Printable Characters in Logs
---
```sql
-- Rule Title: CitrixBleed 2 (CVE-2025-5777) - Non-Printable Characters in Logs
-- Rule Description: This rule detects the presence of non-printable characters in Citrix NetScaler logs. This can be an indicator of successful memory disclosure from vulnerabilities like CitrixBleed 2 (CVE-2025-5777), where leaked memory content, which may not be valid text, is written to log files such as ns.log.
-- Date: 2025-07-24")`

source:citrix_netscaler_ns
| where raw:/[^\x20-\x7E\r\n\t]/
| aggregate count, min(timestamp) AS first_seen, max(timestamp) AS last_seen, collect(raw) AS sample_logs by host, source
```

### Multiple Sessions from Distinct IPs
---
```sql
-- Rule Title: CitrixBleed 2 (CVE-2025-5777) - Multiple Sessions From Distinct IPs
-- Rule Description: This rule detects a single user account establishing sessions from multiple distinct IP addresses within a short time frame. This can be an indicator of session hijacking, a common post-exploitation technique following vulnerabilities like CitrixBleed 2 (CVE-2025-5777), where an attacker uses a stolen session token to access the environment.
-- Date: 2025-07-24")`

source:citrix_netscaler_ns "SSLVPN TCPCONNSTAT"
| aggregate distinct_count(client_ip) AS distinct_ip_count, collect(client_ip) AS client_ips by user, timestamp window 10m
| where distinct_ip_count > 1
| select user, timestamp AS _time, distinct_ip_count, client_ips
```

### Unauthorized Config Modifications
---
```sql
-- Rule Title: Citrix NetScaler Unauthorized Configuration Modification
-- Rule Description: Detects commands executed on a Citrix NetScaler device that add or modify user accounts, policies, or save the configuration. This activity could represent a persistence mechanism established by an attacker following exploitation of a vulnerability like CitrixBleed 2 (CVE-2025-5777).
-- Date: 2025-07-24")`

source:citrix_netscaler_ns "CMD_EXECUTED" command:("add aaa user*" OR "add system user*" OR "set aaa user*" OR "set system user*" OR "add system cmdpolicy*" OR "bind system user*" OR "save ns config*" OR shell)
| aggregate count, collect(command) AS executed_commands by timestamp, host, user, client_ip
| select timestamp AS _time, host, user, client_ip AS src_ip, executed_commands, count
```

### Suspicious Activity from NetScaler
---
```sql
-- Rule Title: Suspicious Lateral Movement from Citrix NetScaler
-- Rule Description: Detects network traffic originating from a Citrix NetScaler internal IP (SNIP) to internal systems over ports commonly used for lateral movement and reconnaissance (e.g., SMB, RPC, LDAP). This could indicate an attacker has compromised the NetScaler (e.g., via CVE-2025-5777) and is moving laterally within the network.
-- Date: 2025-07-24")`

(source:pan* OR source:cisco_asa OR source:zeek_conn OR source:corelight_conn) ip.src:(10.0.0.5 OR 10.0.0.6) port.dst:(135 OR 389 OR 445 OR 636 OR 3389 OR 5985 OR 5986)
| aggregate count, collect(port.dst) AS accessed_ports, distinct_count(port.dst) AS distinct_ports_count by timestamp, ip.src, ip.dst, user
```
