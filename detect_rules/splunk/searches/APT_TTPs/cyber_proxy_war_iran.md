### Cyber Proxy War in the Shadows
---

This report details the escalating cyber conflict between Iranian state-backed actors and affiliated hacktivist groups, and their Western and Israeli counterparts, particularly in the context of potential U.S. military action against Iran. The conflict involves a range of cyber operations, from espionage and data exfiltration to destructive attacks on critical infrastructure and widespread disinformation campaigns.

Recent intelligence indicates a significant increase in the sophistication and coordination of Iranian cyber operations, with groups like Charming Kitten (APT35) now employing AI-generated phishing emails for enhanced social engineering and hacktivist groups like Dark Storm Team offering "DDoS-as-a-Service" for profit, signifying a more professionalized and financially motivated aspect to their activities.

### Actionable Threat Data
---

Exploitation of Public-Facing Applications for Initial Access (T1190): Iranian threat actors, including state-sponsored groups and hacktivists, continue to exploit vulnerabilities in public-facing applications, particularly VPNs and network devices (e.g., Citrix Netscaler, F5 BIG-IP, Pulse Secure, Palo Alto Networks PAN-OS, Check Point Security Gateways), to gain initial access to victim networks.

Credential Access via Brute Force and Phishing (T1110, T1566.001): Iranian actors frequently use brute force attacks, such as password spraying and MFA push bombing, to compromise user accounts and gain access. Additionally, sophisticated spear-phishing campaigns, often leveraging social engineering and impersonation, are used to steal credentials from high-value targets.

Industrial Control System (ICS) Targeting (T0857): Groups like Cyber Av3ngers, linked to the IRGC, actively target ICS and SCADA systems in critical infrastructure sectors (water, energy, oil & gas) for disruption and sabotage, including manipulating physical systems.

Destructive Malware and Data Wiper Campaigns (T1485, T1490): Iranian-linked groups, such as Handala Hack, have deployed wiper malware to destroy data on compromised systems, aiming to render them inoperable and hinder forensic analysis.

Distributed Denial of Service (DDoS) Attacks (T1498): Pro-Iranian hacktivist groups like Dark Storm Team are known for large-scale DDoS attacks against government websites, transportation hubs, financial institutions, and media outlets to cause disruption and psychological impact.

### Exploitation Attempts Against Public-Facing Network Appliances
---
```sql
`comment(
-- Exploitation of Public-Facing Network Appliances

-- Detects potential exploitation attempts, such as directory traversal or command injection, against common public-facing network appliances like VPNs and security gateways. This activity is consistent with TTPs used by various threat actors, including those linked to Iran, for initial access.

-- tags:
   - attack.initial_access
   - attack.t1190

-- Note: The field for URI might be 'uri_path', 'url', or another field depending on your data source.
-- Common sourcetypes include: suricata, zeek:http, pan:traffic, zscaler, cisco:asa, etc.
)`

(index=proxy OR sourcetype=web)
# --- Selection: Appliance Paths ---
# Detects common URL paths associated with network security appliances.
(uri IN ("/vpns/*", "/netscaler/*", "/dana-na/*", "/remote/*", "/sslvpn/*", "/global-protect/*", "/tmui/*", "/CSHELL/*"))
# --- Combined Logic: Exploitation Patterns ---
AND
(
  # --- Traversal and Sensitive File Access ---
  (
    (uri="*../*" OR uri="*..\\*" OR uri="*%2e%2e/*" OR uri="*%2e%2e%5c*" OR uri="*..%2f*")
    AND
    (uri="*/etc/passwd*" OR uri="*/etc/shadow*" OR uri="*win.ini*" OR uri="*web.config*" OR uri="*smb.conf*")
  )
  OR
  # --- Command Injection ---
  (
    uri="*cmd.exe*" OR uri="*/bin/sh*" OR uri="*/bin/bash*" OR uri="*powershell*" OR uri="*whoami*" OR uri="*uname*" OR uri="*id*" OR uri="*cat%20/etc/passwd*" OR uri="*wget%20*" OR uri="*curl%20*" OR uri="*bash%20-c*"
  )
)
# --- Aggregation and Output ---
# Groups results for analysis and alerting.
| stats count min(_time) as firstTime max(_time) as lastTime values(uri) as uri by src, dest, user, http_user_agent
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
# --- False Positive Tuning ---
# The following line is commented out but can be used to filter known vulnerability scanners.
# | search NOT (src IN (known_scanner_ip_1, known_scanner_ip_2))
# --- Metadata ---
# level: high
# falsepositives:
#   - Legitimate vulnerability scanning tools may trigger this rule. Consider filtering scanner source IPs.
#   - Some administrative actions on the appliances might generate similar patterns.
```

### Multi-Cloud Password Spraying Attack
---
```sql
`comment(
Detects a potential password spraying attack across multiple cloud environments (Azure, AWS, GCP), where a single source attempts to authenticate against multiple user accounts with a limited number of passwords. This technique is commonly used by threat actors for initial credential access.

tags:
   - attack.credential_access
   - attack.t1110
   - attack.t1110.003

Note: This query is written for Azure, AWS, and GCP logs.
You may need to adapt sourcetypes and field names for your specific environment.
)`

(sourcetype="mscs:azure:signin" operationName="Sign-in activity" status.errorCode=50126) OR (sourcetype="aws:cloudtrail" eventName=ConsoleLogin errorMessage="Failed authentication") OR (sourcetype="google:gcp:audit" protoPayload.methodName="google.login.LoginService.login" protoPayload.metadata.outcome="fail")
# --- Field Normalization ---
# Normalize user, source IP, and cloud provider fields across different log sources.
| eval auth_user=case(sourcetype="mscs:azure:signin", user, sourcetype="aws:cloudtrail", 'userIdentity.userName', sourcetype="google:gcp:audit", 'protoPayload.authenticationInfo.principalEmail'),
       auth_source_ip=case(sourcetype="mscs:azure:signin", src_ip, sourcetype="aws:cloudtrail", sourceIPAddress, sourcetype="google:gcp:audit", 'protoPayload.requestMetadata.callerIp'),
       cloud_provider=case(sourcetype="mscs:azure:signin", "Azure", sourcetype="aws:cloudtrail", "AWS", sourcetype="google:gcp:audit", "GCP")
# Bucket events into 10-minute windows for analysis.
| bucket _time span=10m
# Count distinct users attempted from a single source IP in each window.
| stats dc(auth_user) as distinct_user_count, values(auth_user) as users, values(cloud_provider) as cloud_providers, min(_time) as firstTime, max(_time) as lastTime by auth_source_ip, _time
# The threshold for distinct users can be tuned based on your environment's baseline to balance noise and detection capability.
| where distinct_user_count > 15
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
# --- Metadata ---
# level: high
# falsepositives:
#   - Misconfigured applications or services that attempt to authenticate for multiple users from a central IP.
#   - Legitimate penetration testing or red team exercises.
#   - A large number of users behind a single NAT gateway, although the diversity of usernames should still be anomalous.
```

### ICS Write Command Detected from Untrusted Source
---
```sql
`comment(
Industrial Control System (ICS) Write Command from Unexpected Source

Detects potentially malicious write commands sent over common ICS protocols (like Modbus) from an unexpected network source (e.g., IT network, external IP) to a protected OT network. This activity is consistent with TTPs used by groups like Cyber Av3ngers to manipulate or sabotage industrial processes.

tags:
   - attack.impact
   - attack.ics
   - attack.t0857
   - attack.t0855

This query is designed for ICS network traffic logs, particularly Zeek Modbus logs.
Field names (e.g., src, dest, dest_port, modbus_function_code) should be mapped to your specific data source using CIM or field aliases.
)`

(sourcetype=zeek:modbus:* OR tag=ics)
# --- Selection: ICS Write Commands ---
# This section identifies write/modify commands specific to Modbus (port 502).
# The field for function code might be 'func' in raw Zeek logs.
# To detect attacks on other protocols (DNP3, S7, etc.), add OR conditions with their respective write command indicators.
| where dest_port=502 AND modbus_function_code IN (5, 6, 15, 16, 22, 23)
# --- Filter: Authorized Sources ---
# This filter is critical for reducing false positives.
# You MUST populate this with your authorized OT/ICS management subnets and host IPs.
| where NOT (cidrmatch("10.100.0.0/16", src) OR cidrmatch("192.168.50.0/24", src) OR cidrmatch("172.16.0.0/12", src))
# For better performance, consider using a lookup for authorized IPs:
# | lookup authorized_ics_sources.csv source_ip as src OUTPUT source_ip as is_authorized | where isnull(is_authorized)
# --- Aggregation and Output ---
# Groups results for analysis and alerting.
| stats count min(_time) as firstTime max(_time) as lastTime values(modbus_function_name) as modbus_function_name by src, dest, dest_port, modbus_function_code
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
# --- Metadata ---
# level: high
# falsepositives:
#   - Legitimate administrative or maintenance activity from an unlisted IP address. This rule requires careful tuning of the 'filter_known_source' section to match your environment's architecture.
#   - Misconfigured network segmentation or firewall rules allowing unintended traffic.
#   - Authorized third-party or vendor connections that have not been added to the filter.
```

### Suspicious Process Execution from Temporary or Unusual Paths
---
```sql
`comment(
Destructive Malware and Data Wiper Campaigns

Detects processes executing from unusual or temporary file paths, a common TTP for wiper malware like that used by Iranian-linked groups such as Handala Hack. Wipers often drop their payload in these locations to evade detection before executing their destructive routines.

tags:
   - attack.impact
   - attack.t1485
   - attack.t1490

Use tstats for performance against the Endpoint data model.
)`

`tstats` summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
# Selection: Look for processes executing from suspicious/temporary paths.
where (Processes.process_path LIKE "%\\windows\\fonts\\%" OR Processes.process_path LIKE "%\\windows\\temp\\%" OR Processes.process_path LIKE "%\\users\\public\\%" OR Processes.process_path LIKE "%\\windows\\debug\\%" OR Processes.process_path LIKE "%\\Users\\Administrator\\Music\\%" OR Processes.process_path LIKE "%\\Windows\\servicing\\%" OR Processes.process_path LIKE "%\\Users\\Default\\%" OR Processes.process_path LIKE "%\\Recycle.bin\\%" OR Processes.process_path LIKE "%\\Windows\\Media\\%" OR Processes.process_path LIKE "%\\Windows\\repair\\%" OR Processes.process_path LIKE "%\\temp\\%" OR Processes.process_path LIKE "%\\PerfLogs\\%")
# Filter: Exclude common legitimate installers and updaters to reduce noise.
AND NOT (Processes.process_name IN ("msiexec.exe", "setup.exe", "updater.exe", "install.exe"))
# Group by relevant fields for context and alerting.
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process_id Processes.parent_process_id
# Standard macros for CIM compliance and time formatting.
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
# --- Metadata ---
# level: high
# falsepositives:
#   - Legitimate software installers, updaters, or scripts that use temporary directories for execution.
#   - Some poorly written or legacy applications may execute from these paths.
#   - The filter may need to be expanded with legitimate applications specific to the environment.
```

### DDoS Attack - High Number of Unique Source IPs to Single Destination
---
```sql
`comment(
Distributed Denial of Service (DDoS) Attacks

Detects a potential Distributed Denial of Service (DDoS) attack by identifying an anomalously high number of unique source IP addresses connecting to a single destination host or service within a short time frame. This TTP is used by hacktivists groups like Dark Storm Team to disrupt services at critical organizations such as airports, financial institutions, and government agencies.

tags:
   - attack.impact
   - attack.t1498

This query is best run on firewall, WAF, or NSM logs mapped to the Network_Traffic CIM data model.
)`

`tstats` summariesonly=true dc(All_Traffic.src) as distinct_source_count from datamodel=Network_Traffic
# Set the time window for aggregation to 5 minutes.
span=5m
# Group by the destination IP address.
by All_Traffic.dest
# Rename fields for better readability in the output.
| rename "All_Traffic.dest" as dest
# The threshold of 1000 is a starting point and MUST be tuned for your environment.
# For a public-facing web server, this might be normal, but for an internal server, it would be highly anomalous.
| where distinct_source_count > 1000
# Add time fields for context.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
# --- Metadata ---
# level: high
# falsepositives:
#   - Legitimate high-traffic services, such as large public web servers, CDNs, or load balancers, may generate a high number of unique source IPs.
#   - The threshold for the number of unique source IPs needs to be carefully tuned to the baseline of the monitored network. Consider creating different rules with different thresholds for different network segments (e.g., DMZ vs. internal).
```