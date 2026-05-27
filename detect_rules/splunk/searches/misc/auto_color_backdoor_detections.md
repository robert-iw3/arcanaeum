### Auto-Color Backdoor: A Stealthy Linux Intrusion
---

This report details the Auto-Color backdoor, a sophisticated Linux Remote Access Trojan (RAT) that leverages the critical SAP NetWeaver vulnerability CVE-2025-31324 for initial access. The malware exhibits advanced evasion tactics, including dynamic self-renaming, shared object injection for persistence, and a unique C2 suppression mechanism to avoid detection in sandboxed environments.

A significant new finding is the observed pairing of Auto-Color malware with the exploitation of CVE-2025-31324, a critical SAP NetWeaver vulnerability, marking a novel initial access vector for this malware. Additionally, Auto-Color now employs a suppression tactic where it stalls its malicious behavior if C2 communication fails, making it appear benign in analysis environments.

### Actionable Threat Data
---

Monitor for incoming connections to SAP NetWeaver systems containing the URI `/developmentserver/metadatauploader`, especially those associated with ZIP file downloads, as this indicates attempted exploitation of CVE-2025-31324.

Detect the creation or modification of `/etc/ld.so.preload` to include references to new or unusual shared objects, particularly `libcext.so.2`, which Auto-Color uses for persistence.

Look for the creation of the directory `/var/log/cross/` and the presence of an `executable named auto-color` within it, as this is where the malware renames and copies itself for stealth.

Identify outbound TLS connections to unusual or `rare IP addresses over port 443`, as Auto-Color attempts to establish C2 communication using a hardcoded IP.

Monitor for DNS requests to Out-of-Band Application Security Testing (OAST) domains (e.g., `oast.me`), which can indicate vulnerability testing or DNS tunneling by threat actors.

### SAP NetWeaver Exploit
---
```sql
(index=* sourcetype=stream:http OR sourcetype=pan:traffic OR sourcetype=suricata OR sourcetype=zeek_http) uri="*/developmentserver/metadatauploader?CONTENTTYPE=MODEL*"

# Key logic: Search for the specific URI path and query parameters used in the exploit.
# The presence of a .zip file in the request would increase fidelity but may not always be logged.
| stats count min(_time) as firstTime max(_time) as lastTime values(url) as url by src, dest, http_user_agent

# Grouping by source, destination, and user agent to create a single alert for a given session.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "The following line is a placeholder for any additional filtering or tuning specific to your environment. For example: | search NOT (src IN (known_scanner_ips) OR http_user_agent IN (known_scanner_user_agents))"
| fields - _*
```

### Auto-Color Persistence via ld.so.preload Hijacking
---
```sql
# Search across common endpoint data sources for process creation events.
(index=* (sourcetype=osqueryd OR sourcetype=linux:audit OR sourcetype="Sysmon:Microsoft-Windows-Sysmon/Operational" OR sourcetype=crowdstrike:event:stream))
# Filter for command lines that show modification of ld.so.preload and the specific malicious library.
(process_command_line LIKE "%/etc/ld.so.preload%" OR CommandLine LIKE "%/etc/ld.so.preload%")
AND (process_command_line LIKE "%libcext.so.2%" OR CommandLine LIKE "%libcext.so.2%")

# Normalize common field names for consistent output.
| eval dest=coalesce(host, dest_host, dvc_host, ComputerName), user=coalesce(user, UserName), process_name=coalesce(process_name, ProcessName), process_command_line=coalesce(process_command_line, CommandLine)

# Aggregate results to provide a summary of the activity.
| stats count min(_time) as firstTime max(_time) as lastTime values(process_command_line) as cmdlines by dest, user, process_name

# Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "This search identifies a specific persistence mechanism of the Auto-Color backdoor. Review the command line on the affected host to confirm malicious activity."
```

### Auto-Color Stealth Execution
---
```sql
# Search across common endpoint data sources for process creation events.
(index=* (sourcetype=osqueryd OR sourcetype=linux:audit OR sourcetype="Sysmon:Microsoft-Windows-Sysmon/Operational" OR sourcetype=crowdstrike:event:stream))
# Key logic: Filter for process execution from the specific malicious path.
(process_path="*/var/log/cross/auto-color" OR Image="*/var/log/cross/auto-color" OR process_command_line="*/var/log/cross/auto-color*")

# Normalize common field names for consistent output.
| eval dest=coalesce(host, dest_host, dvc_host, ComputerName), user=coalesce(user, UserName), process_name=coalesce(process_name, ProcessName), process_path=coalesce(process_path, Image), process_command_line=coalesce(process_command_line, CommandLine)

# Aggregate results to provide a summary of the activity.
| stats count min(_time) as firstTime max(_time) as lastTime values(process_command_line) as cmdlines by dest, user, process_name, process_path

# Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "This search identifies the execution of the Auto-Color backdoor from a masqueraded path. Investigate the affected host immediately."
```

### Auto-Color C2 Communication
---
```sql
# Search across common network data sources.
(index=* (sourcetype=pan:traffic OR sourcetype=suricata OR sourcetype=zeek_conn OR sourcetype=stream:ip))
# Key logic: Filter for connections to the known malicious IP on the C2 port.
(dest_ip="146.70.41.178" OR destination_ip="146.70.41.178" OR id.resp_h="146.70.41.178") (dest_port="443" OR destination_port="443" OR id.resp_p="443")

# Normalize common field names for consistent output.
| eval src=coalesce(src_ip, source_ip, id.orig_h), dest=coalesce(dest_ip, destination_ip, id.resp_h), dest_port=coalesce(dest_port, destination_port, id.resp_p)

# Aggregate results to provide a summary of the activity.
| stats count min(_time) as firstTime max(_time) as lastTime by src, dest, dest_port

# Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "This search identifies C2 traffic associated with the Auto-Color backdoor. Investigate the source host for signs of compromise."
```

### OAST Domain DNS Request
---
```sql
# Search across common DNS data sources.
(index=* (sourcetype=stream:dns OR sourcetype=suricata OR sourcetype=zeek_dns OR sourcetype=pan:traffic))
# Key logic: Filter for DNS queries to the *.oast.me domain.
(query="*.oast.me" OR query_name="*.oast.me")

# Normalize common field names for consistent output.
| eval src=coalesce(src_ip, src), query=coalesce(query, query_name)

# Aggregate results to provide a summary of the activity.
| stats count min(_time) as firstTime max(_time) as lastTime values(query) as queries by src

# Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "This search identifies DNS queries to OAST domains, often used for vulnerability testing or data exfiltration. Investigate the source host for suspicious activity. If this is from authorized scanning, consider adding the source IP to an exclusion list."
```

### Supershell C2 Communication
---
```sql
# Search across common network data sources.
(index=* (sourcetype=pan:traffic OR sourcetype=suricata OR sourcetype=zeek_conn OR sourcetype=stream:ip))
# Key logic: Filter for connections to the known malicious IP on the C2 port (3232).
(dest_ip="47.97.42.177" OR destination_ip="47.97.42.177" OR id.resp_h="47.97.42.177") (dest_port="3232" OR destination_port="3232" OR id.resp_p="3232")

# Normalize common field names for consistent output.
| eval src=coalesce(src_ip, source_ip, id.orig_h), dest=coalesce(dest_ip, destination_ip, id.resp_h), dest_port=coalesce(dest_port, destination_port, id.resp_p)

# Aggregate results to provide a summary of the activity.
| stats count min(_time) as firstTime max(_time) as lastTime by src, dest, dest_port

# Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "This search identifies C2 traffic associated with the Supershell C2 platform. Investigate the source host for signs of compromise."
```

### Auto-Color Malware File Hash
---
```sql
# Search across common endpoint data sources that contain file hash information.
(index=* (sourcetype="Sysmon:Microsoft-Windows-Sysmon/Operational" OR sourcetype=crowdstrike:event:stream OR sourcetype=carbonblack:event))
# Key logic: Filter for the specific SHA256 hash of the Auto-Color malware sample.
(sha256="270fc72074c697ba5921f7b61a6128b968ca6ccbf8906645e796cfc3072d4c43" OR file_hash="270fc72074c697ba5921f7b61a6128b968ca6ccbf8906645e796cfc3072d4c43" OR Hashes="*SHA256=270fc72074c697ba5921f7b61a6128b968ca6ccbf8906645e796cfc3072d4c43*")

# Normalize common field names for consistent output.
| eval dest=coalesce(host, dest_host, dvc_host, ComputerName), file_path=coalesce(file_path, Image, TargetFilename), process_name=coalesce(process_name, ProcessName, process_path), user=coalesce(user, UserName)

# Aggregate results to provide a summary of the activity.
| stats count min(_time) as firstTime max(_time) as lastTime by dest, file_path, process_name, user

# Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "This search identifies a known malicious file associated with the Auto-Color backdoor. Immediate investigation of the affected host is required."
```

### Malicious Shell Script Download from Known Domain
---
```sql
# Search across common network and DNS data sources.
(index=* (sourcetype=stream:dns OR sourcetype=pan:traffic OR sourcetype=suricata OR sourcetype=zeek* OR sourcetype=cisco:asa OR sourcetype=fortinet*))
# Key logic: Filter for connections or queries to the specific malicious domain.
(query="ocr-freespace.oss-cn-beijing.aliyuncs.com" OR url="*ocr-freespace.oss-cn-beijing.aliyuncs.com*")

# Normalize common field names for consistent output.
| eval src=coalesce(src_ip, src, source_ip), dest_host=coalesce(dest_host, dest, destination_host)

# Aggregate results to provide a summary of the activity.
| stats count min(_time) as firstTime max(_time) as lastTime values(url) as urls values(query) as queries by src, dest_host

# Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "This search identifies connections to a domain known for hosting malicious scripts. Investigate the source host for signs of compromise, including downloaded and executed files."
```

### Inbound Connection from Auto-Color Initial Exploit IP
---
```sql
# Search across common network data sources.
(index=* (sourcetype=pan:traffic OR sourcetype=suricata OR sourcetype=zeek_conn OR sourcetype=cisco:asa OR sourcetype=fortinet*))
# Key logic: Filter for inbound connections from the known malicious IP.
(src_ip="91.193.19.109" OR source_ip="91.193.19.109" OR id.orig_h="91.193.19.109")

# Normalize common field names for consistent output.
| eval src=coalesce(src_ip, source_ip, id.orig_h), dest=coalesce(dest_ip, destination_ip, id.resp_h), dest_port=coalesce(dest_port, destination_port, id.resp_p)

# Aggregate results to provide a summary of the activity.
| stats count min(_time) as firstTime max(_time) as lastTime by src, dest, dest_port

# Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "This search identifies inbound traffic from an IP associated with the Auto-Color campaign. Investigate the destination host for signs of compromise, paying close attention to web server logs for exploit attempts."
```