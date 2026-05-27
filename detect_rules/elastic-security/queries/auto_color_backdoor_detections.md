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
from *
| where event.dataset IN ("stream.http", "pan.traffic", "suricata", "zeek.http")
  and http.url like "*/developmentserver/metadatauploader?CONTENTTYPE=MODEL*"
| stats COUNT, MIN(@timestamp) AS firstTime, MAX(@timestamp) AS lastTime, VALUES(http.url) AS url
  by source.ip, destination.ip, http.user_agent
| rename source.ip AS src, destination.ip AS dest, http.user_agent AS http_user_agent
```

### Auto-Color Persistence via ld.so.preload Hijacking
---
```sql
from *
| where event.dataset IN ("osqueryd", "linux.audit", "sysmon.microsoft-windows-sysmon/operational", "crowdstrike.event.stream")
  and (process.command_line like "%/etc/ld.so.preload%" and process.command_line like "%libcext.so.2%")
| eval dest = COALESCE(host.name, destination.host, device.host, computer.name),
        user = COALESCE(user.name, user.name),
        process_name = COALESCE(process.name, process.name),
        process_command_line = COALESCE(process.command_line, process.command_line)
| stats COUNT, MIN(@timestamp) AS firstTime, MAX(@timestamp) AS lastTime, VALUES(process_command_line) AS cmdlines
  by dest, user, process_name
```

### Auto-Color Stealth Execution
---
```sql
from *
| where event.dataset IN ("osqueryd", "linux.audit", "sysmon.microsoft-windows-sysmon/operational", "crowdstrike.event.stream")
  and (process.executable like "*/var/log/cross/auto-color*" OR process.command_line like "*/var/log/cross/auto-color*")
| eval dest = COALESCE(host.name, destination.host, device.host, computer.name),
        user = COALESCE(user.name, user.name),
        process_name = COALESCE(process.name, process.name),
        process_path = COALESCE(process.executable, process.executable),
        process_command_line = COALESCE(process.command_line, process.command_line)
| stats COUNT, MIN(@timestamp) AS firstTime, MAX(@timestamp) AS lastTime, VALUES(process_command_line) AS cmdlines
  by dest, user, process_name, process_path
```

### Auto-Color C2 Communication
---
```sql
from *
| where event.dataset IN ("pan.traffic", "suricata", "zeek.conn", "stream.ip")
  and (destination.ip == "146.70.41.178")
  and (destination.port == "443")
| eval src = COALESCE(source.ip, source.ip, source.ip),
        dest = COALESCE(destination.ip, destination.ip, destination.ip),
        dest_port = COALESCE(destination.port, destination.port, destination.port)
| stats COUNT, MIN(@timestamp) AS firstTime, MAX(@timestamp) AS lastTime
  by src, dest, dest_port
```

### OAST Domain DNS Request
---
```sql
from *
| where event.dataset IN ("stream.dns", "suricata", "zeek.dns", "pan.traffic")
  and (dns.query like "*.oast.me")
| eval src = COALESCE(source.ip, source.ip),
        query = COALESCE(dns.query, dns.query)
| stats COUNT, MIN(@timestamp) AS firstTime, MAX(@timestamp) AS lastTime, VALUES(query) AS queries
  by src
```

### Supershell C2 Communication
---
```sql
from *
| where event.dataset IN ("pan.traffic", "suricata", "zeek.conn", "stream.ip")
  and (destination.ip == "47.97.42.177")
  and (destination.port == "3232")
| eval src = COALESCE(source.ip, source.ip, source.ip),
        dest = COALESCE(destination.ip, destination.ip, destination.ip),
        dest_port = COALESCE(destination.port, destination.port, destination.port)
| stats COUNT, MIN(@timestamp) AS firstTime, MAX(@timestamp) AS lastTime
  by src, dest, dest_port
```

### Auto-Color Malware File Hash
---
```sql
from *
| where event.dataset IN ("sysmon.microsoft-windows-sysmon/operational", "crowdstrike.event.stream", "carbonblack.event")
  and (file.hash.sha256 == "270fc72074c697ba5921f7b61a6128b968ca6ccbf8906645e796cfc3072d4c43")
| eval dest = COALESCE(host.name, destination.host, device.host, computer.name),
        file_path = COALESCE(file.path, process.executable, file.target_path),
        process_name = COALESCE(process.name, process.name, process.executable),
        user = COALESCE(user.name, user.name)
| stats COUNT, MIN(@timestamp) AS firstTime, MAX(@timestamp) AS lastTime
  by dest, file_path, process_name, user
```

### Malicious Shell Script Download from Known Domain
---
```sql
from *
| where event.dataset IN ("stream.dns", "pan.traffic", "suricata", "zeek.*", "cisco.asa", "fortinet.*")
  and (dns.query == "ocr-freespace.oss-cn-beijing.aliyuncs.com" OR http.url like "*ocr-freespace.oss-cn-beijing.aliyuncs.com*")
| eval src = COALESCE(source.ip, source.ip, source.ip),
        dest_host = COALESCE(destination.host, destination.host, destination.host)
| stats COUNT, MIN(@timestamp) AS firstTime, MAX(@timestamp) AS lastTime, VALUES(http.url) AS urls, VALUES(dns.query) AS queries
  by src, dest_host
```

### Inbound Connection from Auto-Color Initial Exploit IP
---
```sql
from *
| where event.dataset IN ("pan.traffic", "suricata", "zeek.conn", "cisco.asa", "fortinet.*")
  and (source.ip == "91.193.19.109")
| eval src = COALESCE(source.ip, source.ip, source.ip),
        dest = COALESCE(destination.ip, destination.ip, destination.ip),
        dest_port = COALESCE(destination.port, destination.port, destination.port)
| stats COUNT, MIN(@timestamp) AS firstTime, MAX(@timestamp) AS lastTime
  by src, dest, dest_port
```