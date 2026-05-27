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
`comment("
Rule Title: CitrixBleed 2 (CVE-2025-5777) Malformed Login Request
Rule Description: This detection identifies potential exploitation attempts of the CitrixBleed 2 vulnerability (CVE-2025-5777). The exploit involves sending a specially crafted HTTP POST request to the '/p/u/doAuthentication.do' endpoint with a 'login' parameter that has no value. This causes the server to leak memory in its response. This search looks for this specific pattern in web traffic logs.
Date: 2025-07-24")`

`comment("This search targets web traffic data. Update the index and sourcetype to match your environment's data sources, such as proxy, WAF, or web server logs.")`
(index=* (sourcetype=pan:traffic OR sourcetype=stream:http OR sourcetype=suricata OR sourcetype=cisco:ftd:file_event))
http_method="POST"
url="*/p/u/doAuthentication.do"

`comment("The core detection logic uses a regex to find a 'login' parameter with an empty value in the POST body. The field 'form_data' may need to be changed to match your data source (e.g., http_post_data, post_content).")`
| rex field=form_data "login=(?:&|$)"
| where isnotnull(_match)

`comment("Group the results to summarize the activity from a potential attacker.")`
| stats
  count
  min(_time) as first_seen
  max(_time) as last_seen
  values(url) as urls
  values(form_data) as sample_post_bodies
  by
  src_ip
  dest_ip
  user
  user_agent

`comment("This detection has a medium false positive sensitivity. Legitimate but poorly-formed requests from custom clients could trigger this alert. If false positives occur, consider excluding trusted internal scanners or specific user agents.")`
| `citrix_bleed_2_cve_2025_5777_malformed_login_request_filter`
```

### Non-Printable Characters in Logs
---
```sql
`comment("
Rule Title: CitrixBleed 2 (CVE-2025-5777) - Non-Printable Characters in Logs
Rule Description: This rule detects the presence of non-printable characters in Citrix NetScaler logs. This can be an indicator of successful memory disclosure from vulnerabilities like CitrixBleed 2 (CVE-2025-5777), where leaked memory content, which may not be valid text, is written to log files such as ns.log.
Date: 2025-07-24")`

`comment("This search targets Citrix NetScaler logs. Update the index and sourcetype to match your environment. The 'ns.log' file is a primary target for this activity.")`
(index=* sourcetype=citrix:netscaler:ns)

`comment("The regex identifies events containing characters that are not standard printable ASCII characters or common whitespace, which is indicative of binary data or memory corruption in the log.")`
| regex _raw="[^\\x20-\\x7E\\r\\n\\t]"

`comment("Group the results to summarize the activity from an affected device.")`
| stats
  count
  min(_time) as first_seen
  max(_time) as last_seen
  values(_raw) as sample_logs
  by
  host
  sourcetype

`comment("This detection has a medium false positive sensitivity. Corrupted log files or legitimate binary data being logged for other reasons could trigger this alert. If false positives occur, consider adding filters to exclude specific log messages or hosts.")`
| `citrixbleed_2_cve_2025_5777_non_printable_chars_in_logs_filter`
```

### Multiple Sessions from Distinct IPs
---
```sql
`comment("
Rule Title: CitrixBleed 2 (CVE-2025-5777) - Multiple Sessions From Distinct IPs
Rule Description: This rule detects a single user account establishing sessions from multiple distinct IP addresses within a short time frame. This can be an indicator of session hijacking, a common post-exploitation technique following vulnerabilities like CitrixBleed 2 (CVE-2025-5777), where an attacker uses a stolen session token to access the environment.
Date: 2025-07-24")`

`comment("This search targets Citrix NetScaler session logs. Update the index and sourcetype to match your environment. The 'SSLVPN TCPCONNSTAT' message type contains the necessary user, IP, and time information.")`
(index=* sourcetype=citrix:netscaler:ns) "SSLVPN TCPCONNSTAT"

`comment("Group events into 10-minute windows to define a 'concurrent' session period.")`
| bin _time span=10m

`comment("For each user within each time window, count the number of unique client IPs.")`
| stats
  dc(Client_ip) as distinct_ip_count
  values(Client_ip) as client_ips
  by
  _time
  User

`comment("Filter for users who have connected from more than one IP address in the same 10-minute window.")`
| where distinct_ip_count > 1

`comment("This detection has a medium false positive sensitivity. Legitimate scenarios, such as a user switching from a corporate network to a mobile hotspot, or using a VPN that changes IPs, could trigger this alert. Consider tuning the time span or excluding specific users or IP ranges known for this behavior.")`
| rename User as user
| `citrixbleed_2_cve_2025_5777_multiple_sessions_from_distinct_ips_filter`
```

### Unauthorized Config Modifications
---
```sql
`comment("
Rule Title: Citrix NetScaler Unauthorized Configuration Modification
Rule Description: Detects commands executed on a Citrix NetScaler device that add or modify user accounts, policies, or save the configuration. This activity could represent a persistence mechanism established by an attacker following exploitation of a vulnerability like CitrixBleed 2 (CVE-2025-5777).
Date: 2025-07-24")`

`comment("This search targets Citrix NetScaler command execution logs. Update the index and sourcetype to match your environment.")`
(index=* sourcetype=citrix:netscaler:ns) "CMD_EXECUTED"

`comment("Filter for potentially malicious commands related to user management, policy changes, or saving the configuration. The wildcard '*' is used to capture full command strings.")`
| search Command IN (
    "add aaa user*",
    "add system user*",
    "set aaa user*",
    "set system user*",
    "add system cmdpolicy*",
    "bind system user*",
    "save ns config*",
    "shell"
)

`comment("Summarize the suspicious commands executed by user and source IP.")`
| stats
  count
  values(Command) as executed_commands
  by
  _time
  host
  User
  Client_ip

`comment("This detection has a medium false positive sensitivity. Legitimate administrative activity will trigger this alert. It is crucial to baseline normal administrative behavior and investigate changes made by unexpected users or from unusual source IPs.")`
| rename User as user, Client_ip as src_ip
| `citrix_netscaler_unauthorized_configuration_modification_filter`
```

### Suspicious Activity from NetScaler
---
```sql
`comment("
Rule Title: Suspicious Lateral Movement from Citrix NetScaler
Rule Description: Detects network traffic originating from a Citrix NetScaler internal IP (SNIP) to internal systems over ports commonly used for lateral movement and reconnaissance (e.g., SMB, RPC, LDAP). This could indicate an attacker has compromised the NetScaler (e.g., via CVE-2025-5777) and is moving laterally within the network.
Date: 2025-07-24")`

`comment("This search requires a macro named 'netscaler_internal_ips' that returns the internal-facing IP addresses (SNIPs) of your NetScaler appliances. e.g., 'src_ip IN (10.0.0.5, 10.0.0.6)'")`
`comment("Target network traffic logs from sources like firewalls or Zeek. Update index and sourcetypes as needed.")`
(index=* (sourcetype=pan:traffic OR sourcetype=cisco:asa OR sourcetype=zeek:conn OR sourcetype=corelight:conn)) `netscaler_internal_ips`

`comment("Filter for destination ports commonly used for reconnaissance and lateral movement.")`
| search dest_port IN (
    135,  `comment("RPC for tools like PsService, Task Scheduler")`
    389,  `comment("LDAP for Active Directory enumeration")`
    445,  `comment("SMB for file sharing, PsExec, etc.")`
    636,  `comment("LDAPS for encrypted AD enumeration")`
    3389, `comment("RDP for interactive logon")`
    5985, `comment("WinRM for remote management")`
    5986  `comment("WinRM for encrypted remote management")`
)

`comment("Summarize the activity by source (NetScaler SNIP) and destination (internal host).")`
| stats
  count
  values(dest_port) as accessed_ports
  dc(dest_port) as distinct_ports_count
  by
  _time
  src_ip
  dest_ip
  user

`comment("This detection has a medium false positive sensitivity. NetScalers legitimately communicate with Domain Controllers for authentication (LDAP) and with backend servers. It is crucial to baseline this traffic and exclude it using the filter macro below. Focus on destinations that are not DCs or backend application servers.")`
| `suspicious_lateral_movement_from_citrix_netscaler_filter`
```
