### PLC Playground: Hands-On Industrial Control Systems Attacks
---

This report summarizes the threats and attack techniques targeting Programmable Logic Controllers (PLCs) within Industrial Control Systems (ICS) environments, emphasizing the increasing integration of IT and OT networks and the resulting expansion of the attack surface. It highlights how adversaries exploit vulnerabilities in PLCs and associated systems, including the use of internet-exposed devices and novel attack methods like weaponizing PLCs to compromise engineering workstations.

Recent intelligence indicates a rise in sophisticated, multi-stage attacks targeting ICS, including the weaponization of PLCs to compromise engineering workstations (Evil PLC Attack) and the emergence of web-based PLC malware that exploits embedded web servers. These developments are noteworthy as they demonstrate a shift towards more complex attack vectors that leverage the increasing internet exposure of ICS components and the convergence of IT and OT networks.

### Actionable Threat Data
---

Monitor for unauthorized access attempts and anomalous activity on internet-facing ICS devices, particularly those using common protocols like Modbus and EtherNet/IP, as these are frequently targeted for initial reconnaissance and exploitation.

Implement network segmentation between IT and OT networks to limit lateral movement, and enforce strict access controls, including multi-factor authentication, for all connections to ICS environments.

Detect attempts to modify PLC ladder logic or firmware, as this indicates a high-impact attack aimed at disrupting physical processes or establishing persistence.

Monitor for unusual network traffic patterns or communication attempts from PLCs to IT networks or external destinations, which could indicate an "Evil PLC Attack" or data exfiltration.

Prioritize patching and updating ICS software and firmware, especially for known vulnerabilities in Human-Machine Interfaces (HMIs) and PLCs, to mitigate risks from publicly disclosed exploits and prevent the use of web-based PLC malware.

### Unauthorized ICS Access
---
Name: Unauthorized External Access to ICS Devices

Author: RW

Date: 2025-08-11

Description: This rule detects successful network connections from the public internet to common Industrial Control System (ICS) ports, such as Modbus (502) and EtherNet/IP (44818). This could indicate unauthorized access attempts, reconnaissance, or exploitation of internet-exposed ICS assets.

Tactic: Initial Access

Technique: T1190 - Exploit Public-Facing Application

False Positive Sensitivity: Medium

splunk:
```sql
-- Data source: This rule is designed for CIM-compliant network traffic data.
-- You may need to adjust field names (e.g., src, dest, dest_port, action) for your specific data source.
`cim_Network_Traffic_all`
-- Filter for successful connections. Adjust values as needed for your environment (e.g., "permit", "accept").
| where action="allowed"
-- Filter for traffic targeting common ICS ports. Customize this list for your OT environment.
| where dest_port IN (
    502,    -- Modbus
    44818,  -- EtherNet/IP (TCP)
    2222,   -- EtherNet/IP (UDP)
    20000,  -- DNP3
    47808,  -- BACnet
    102,    -- S7 Communication
    1911,   -- Niagara Fox
    2404    -- IEC 60870-5-104
)
-- Ensure the source is an external (non-RFC1918) IP address.
| where NOT (cidrmatch("10.0.0.0/8", src) OR cidrmatch("172.16.0.0/12", src) OR cidrmatch("192.168.0.0/16", src))
-- **CRITICAL TUNING STEP**: Exclude connections from known, authorized external sources.
-- Create a lookup file (e.g., authorized_ics_ips.csv) with a single column 'src'
-- and populate it with the public IPs of vendors, partners, or remote maintenance services.
| where NOT [| inputlookup authorized_ics_ips.csv | fields src]
-- Summarize the activity to reduce alert volume and provide context.
| stats earliest(_time) as first_seen, latest(_time) as last_seen, count, values(app) as app by src, dest, dest_port, user
| `convert_time(first_seen)`
| `convert_time(last_seen)`
-- Provide a clear name for the detection.
| rename src as source_ip, dest as destination_ip, dest_port as destination_port, count as connection_count
```

crowdstrike fql:
```sql
event_type="NetworkConnection"
| action="allowed"
| dest_port IN (502, 44818, 2222, 20000, 47808, 102, 1911, 2404)
| NOT (src_ip MATCHES "10.0.0.0/8" OR src_ip MATCHES "172.16.0.0/12" OR src_ip MATCHES "192.168.0.0/16")
| NOT src_ip IN (LOOKUP("authorized_ics_ips.csv", "src"))
| group by src_ip, dest_ip, dest_port, user_name
| aggregate first_seen=MIN(timestamp), last_seen=MAX(timestamp), connection_count=COUNT(), app=VALUES(app)
| format_time(first_seen), format_time(last_seen)
| rename src_ip as source_ip, dest_ip as destination_ip, dest_port as destination_port, user_name as user
```

datadog:
```sql
source:network action:allowed
dest_port:(502 OR 44818 OR 2222 OR 20000 OR 47808 OR 102 OR 1911 OR 2404)
-src_ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)
| where NOT src_ip IN (lookup:authorized_ics_ips.csv, src)
| stats min(@timestamp) as first_seen, max(@timestamp) as last_seen, count as connection_count, values(app) as app by src_ip, dest_ip, dest_port, user
| eval first_seen = strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen = strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| rename src_ip as source_ip, dest_ip as destination_ip, dest_port as destination_port
```

elastic:
```sql
FROM logs-network*
| WHERE event.outcome == "success"
  AND destination.port IN (502, 44818, 2222, 20000, 47808, 102, 1911, 2404)
  AND NOT (source.ip MATCHES "10.0.0.0/8" OR source.ip MATCHES "172.16.0.0/12" OR source.ip MATCHES "192.168.0.0/16")
  AND source.ip NOT IN (SELECT src FROM authorized_ics_ips.csv)
| STATS first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp),
        connection_count = COUNT(),
        app = MV_DEDUP(network.application)
  BY source.ip, destination.ip, destination.port, user.name
| EVAL first_seen = TO_STRING(first_seen, "yyyy-MM-dd HH:mm:ss"),
      last_seen = TO_STRING(last_seen, "yyyy-MM-dd HH:mm:ss")
| RENAME source.ip AS source_ip,
         destination.ip AS destination_ip,
         destination.port AS destination_port,
         user.name AS user
```

sentinel one:
```sql
event.type = "NetworkConnection"
AND network.action = "allowed"
AND network.destination.port IN (502, 44818, 2222, 20000, 47808, 102, 1911, 2404)
AND NOT (
  network.source.ip MATCHES "10.0.0.0/8"
  OR network.source.ip MATCHES "172.16.0.0/12"
  OR network.source.ip MATCHES "192.168.0.0/16"
)
AND network.source.ip NOT IN (SELECT src FROM authorized_ics_ips.csv)
| GROUP BY network.source.ip, network.destination.ip, network.destination.port, user.name
| SELECT MIN(event.timestamp) AS first_seen,
         MAX(event.timestamp) AS last_seen,
         COUNT() AS connection_count,
         VALUES(network.application) AS app,
         network.source.ip AS source_ip,
         network.destination.ip AS destination_ip,
         network.destination.port AS destination_port,
         user.name AS user
| EVAL first_seen = FORMAT_TIME(first_seen, "YYYY-MM-DD HH:mm:ss"),
      last_seen = FORMAT_TIME(last_seen, "YYYY-MM-DD HH:mm:ss")
```

### PLC Logic/Firmware Modification
---
Name: PLC Logic or Firmware Modification Detected

Author: RW

Date: 2025-08-11

Description: Detects attempts to modify Programmable Logic Controller (PLC) ladder logic or firmware. Such modifications can indicate a high-impact attack aimed at disrupting physical processes, damaging equipment, or establishing persistence within the Operational Technology (OT) network.

Tactic: Impair Process Control

Technique: T0855 - Inhibit Response Function

False Positive Sensitivity: Medium

- This rule will trigger on legitimate PLC programming and maintenance activities.

- It is CRITICAL to populate the 'authorized_engineering_workstations' list with the IP addresses of devices approved for PLC programming to reduce false positives.

- Consider scheduling this rule to run outside of planned maintenance windows.

splunk:
```sql
-- Data source: This rule requires logs from an OT/ICS security monitoring solution (e.g., Nozomi, Dragos, Claroty)
-- that provides deep packet inspection of industrial protocols.
-- Replace the macro `ot_security_events` with the appropriate index and sourcetype for your environment.
`ot_security_events`
-- Filter for commands that indicate a modification or state change.
-- This list is not exhaustive and should be tailored to your specific environment.
| where command IN (
    -- EtherNet/IP (CIP)
    "Download", "Write Tag", "Modify", "Program",
    -- S7
    "S7_WRITE", "SZL_WRITE", "DOWNLOAD", "BLOCK_DOWNLOAD",
    -- Modbus Function Codes (as strings or numbers)
    "5", "6", "15", "16",
    -- DNP3
    "WRITE", "OPERATE", "DIRECT_OPERATE",
    -- General Commands
    "Stop PLC", "Run PLC", "PLC Stop", "PLC Run", "Force On", "Force Off", "Upload/download"
)
-- **CRITICAL TUNING STEP**: Exclude activity from known, authorized engineering workstations.
-- Create a lookup file (e.g., authorized_engineering_workstations.csv) with a single column 'src'
-- and populate it with the IP addresses of devices approved for PLC programming.
| where NOT [| inputlookup authorized_engineering_workstations.csv | fields src]
-- Optional Tuning: Focus on PLCs if device type information is available in your logs.
-- | where dest_device_type="PLC"
-- Summarize the activity to create a single alert per source/destination pair.
| stats earliest(_time) as first_seen, latest(_time) as last_seen, count, values(command) as commands_used by src, dest, user, protocol
| `convert_time(first_seen)`
| `convert_time(last_seen)`
-- Rename fields for clarity in the final alert.
| rename src as source_ip, dest as plc_ip, user as programming_user, count as modification_attempts, commands_used as commands
```

crowdstrike fql:
```sql
event_type="OTSecurityEvent"
| command IN ("Download", "Write Tag", "Modify", "Program", "S7_WRITE", "SZL_WRITE", "DOWNLOAD", "BLOCK_DOWNLOAD", "5", "6", "15", "16", "WRITE", "OPERATE", "DIRECT_OPERATE", "Stop PLC", "Run PLC", "PLC Stop", "PLC Run", "Force On", "Force Off", "Upload/download")
| NOT src_ip IN (LOOKUP("authorized_engineering_workstations.csv", "src"))
| group by src_ip, dest_ip, user_name, protocol
| aggregate first_seen=MIN(timestamp), last_seen=MAX(timestamp), modification_attempts=COUNT(), commands=VALUES(command)
| format_time(first_seen), format_time(last_seen)
| rename src_ip as source_ip, dest_ip as plc_ip, user_name as programming_user
```

datadog:
```sql
source:ot_security
command:(Download OR "Write Tag" OR Modify OR Program OR S7_WRITE OR SZL_WRITE OR DOWNLOAD OR BLOCK_DOWNLOAD OR 5 OR 6 OR 15 OR 16 OR WRITE OR OPERATE OR DIRECT_OPERATE OR "Stop PLC" OR "Run PLC" OR "PLC Stop" OR "PLC Run" OR "Force On" OR "Force Off" OR "Upload/download")
-src_ip:(lookup:authorized_engineering_workstations.csv, src)
| stats min(@timestamp) as first_seen, max(@timestamp) as last_seen, count as modification_attempts, values(command) as commands by src_ip, dest_ip, user, protocol
| eval first_seen = strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen = strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| rename src_ip as source_ip, dest_ip as plc_ip, user as programming_user, commands as commands_used
```

elastic:
```sql
FROM logs-ot_security*
| WHERE event.action IN (
    "Download", "Write Tag", "Modify", "Program",
    "S7_WRITE", "SZL_WRITE", "DOWNLOAD", "BLOCK_DOWNLOAD",
    "5", "6", "15", "16",
    "WRITE", "OPERATE", "DIRECT_OPERATE",
    "Stop PLC", "Run PLC", "PLC Stop", "PLC Run", "Force On", "Force Off", "Upload/download"
  )
  AND source.ip NOT IN (SELECT src FROM authorized_engineering_workstations.csv)
| STATS first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp),
        modification_attempts = COUNT(),
        commands_used = MV_DEDUP(event.action)
  BY source.ip, destination.ip, user.name, network.protocol
| EVAL first_seen = TO_STRING(first_seen, "yyyy-MM-dd HH:mm:ss"),
      last_seen = TO_STRING(last_seen, "yyyy-MM-dd HH:mm:ss")
| RENAME source.ip AS source_ip,
         destination.ip AS plc_ip,
         user.name AS programming_user
```

sentinel one:
```sql
event.type = "OTSecurityEvent"
AND network.command IN (
  "Download", "Write Tag", "Modify", "Program",
  "S7_WRITE", "SZL_WRITE", "DOWNLOAD", "BLOCK_DOWNLOAD",
  "5", "6", "15", "16",
  "WRITE", "OPERATE", "DIRECT_OPERATE",
  "Stop PLC", "Run PLC", "PLC Stop", "PLC Run", "Force On", "Force Off", "Upload/download"
)
AND network.source.ip NOT IN (SELECT src FROM authorized_engineering_workstations.csv)
| GROUP BY network.source.ip, network.destination.ip, user.name, network.protocol
| SELECT MIN(event.timestamp) AS first_seen,
         MAX(event.timestamp) AS last_seen,
         COUNT() AS modification_attempts,
         VALUES(network.command) AS commands_used,
         network.source.ip AS source_ip,
         network.destination.ip AS plc_ip,
         user.name AS programming_user
| EVAL first_seen = FORMAT_TIME(first_seen, "YYYY-MM-DD HH:mm:ss"),
      last_seen = FORMAT_TIME(last_seen, "YYYY-MM-DD HH:mm:ss")
```

### Evil PLC Attack/Data Exfiltration
---
Name: Evil PLC Attack or Data Exfiltration Detected

Author: RW

Date: 2025-08-11

Description: Detects network traffic originating from a Programmable Logic Controller (PLC) to an external (public) IP address or an internal IT network. This is highly anomalous as PLCs should typically only communicate with other devices within the OT network segment. This activity could indicate an "Evil PLC" attack attempting to pivot into the IT network, or data exfiltration from the OT environment.

Tactic: Command and Control, Exfiltration

Technique: T0869 - Standard Application Layer Protocol

False Positive Sensitivity: Medium

- This rule may trigger on legitimate, albeit rare, communications from PLCs to IT-based systems like data historians or Manufacturing Execution Systems (MES).

- It is CRITICAL to populate the 'plc_ips' list and the 'authorized_it_destinations' allowlist for your environment to ensure high fidelity.

splunk:
```sql
-- Data source: This rule is designed for CIM-compliant network traffic data.
-- You may need to adjust field names (e.g., src, dest, dest_port) for your specific data source.
`cim_Network_Traffic_all`
-- **CRITICAL TUNING STEP 1**: Filter for traffic originating from a known PLC.
-- Create a lookup file named 'plc_ips.csv' with a single column 'ip' containing the IP addresses of your PLCs.
| where `is_plc_ip(src)`
-- **CRITICAL TUNING STEP 2**: Filter for traffic going to a destination that is NOT in the defined OT subnets.
-- Create a lookup file named 'ot_subnets.csv' with a single column 'cidr' containing your OT network ranges (e.g., 192.168.100.0/24).
| where NOT `is_in_ot_subnet(dest)`
-- **CRITICAL TUNING STEP 3**: Exclude traffic to known-good IT destinations.
-- Create a lookup file named 'authorized_it_destinations.csv' with a single column 'ip' containing the IPs of authorized destinations like data historians or MES servers.
| where NOT `is_authorized_it_dest(dest)`
-- Optional: Filter out expected broadcast/multicast traffic if noisy.
| where NOT (cidrmatch("224.0.0.0/4", dest) OR cidrmatch("255.255.255.255", dest))
-- Summarize the anomalous connections to create a single alert per unique flow.
| stats earliest(_time) as first_seen, latest(_time) as last_seen, count, values(dest_port) as destination_ports, values(app) as applications by src, dest, user
| `convert_time(first_seen)`
| `convert_time(last_seen)`
-- Provide a clear name for the detection.
| rename src as plc_ip, dest as destination_ip, count as connection_count
```

crowdstrike fql:
```sql
event_type="NetworkConnection"
| src_ip IN (LOOKUP("plc_ips.csv", "ip"))
| NOT dest_ip IN (LOOKUP("ot_subnets.csv", "cidr"))
| NOT dest_ip IN (LOOKUP("authorized_it_destinations.csv", "ip"))
| NOT (dest_ip MATCHES "224.0.0.0/4" OR dest_ip="255.255.255.255")
| group by src_ip, dest_ip, user_name
| aggregate first_seen=MIN(timestamp), last_seen=MAX(timestamp), connection_count=COUNT(), destination_ports=VALUES(dest_port), applications=VALUES(app)
| format_time(first_seen), format_time(last_seen)
| rename src_ip as plc_ip, dest_ip as destination_ip, user_name as user
```

datadog:
```sql
source:network
src_ip:(lookup:plc_ips.csv, ip)
-dest_ip:(lookup:ot_subnets.csv, cidr OR lookup:authorized_it_destinations.csv, ip OR 224.0.0.0/4 OR 255.255.255.255)
| stats min(@timestamp) as first_seen, max(@timestamp) as last_seen, count as connection_count, values(dest_port) as destination_ports, values(app) as applications by src_ip, dest_ip, user
| eval first_seen = strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen = strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| rename src_ip as plc_ip, dest_ip as destination_ip
```

elastic:
```sql
FROM logs-network*
| WHERE source.ip IN (SELECT ip FROM plc_ips.csv)
  AND destination.ip NOT IN (SELECT cidr FROM ot_subnets.csv)
  AND destination.ip NOT IN (SELECT ip FROM authorized_it_destinations.csv)
  AND NOT (destination.ip MATCHES "224.0.0.0/4" OR destination.ip == "255.255.255.255")
| STATS first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp),
        connection_count = COUNT(),
        destination_ports = MV_DEDUP(destination.port),
        applications = MV_DEDUP(network.application)
  BY source.ip, destination.ip, user.name
| EVAL first_seen = TO_STRING(first_seen, "yyyy-MM-dd HH:mm:ss"),
      last_seen = TO_STRING(last_seen, "yyyy-MM-dd HH:mm:ss")
| RENAME source.ip AS plc_ip,
         destination.ip AS destination_ip,
         user.name AS user
```

sentinel one:
```sql
event.type = "NetworkConnection"
AND network.source.ip IN (SELECT ip FROM plc_ips.csv)
AND network.destination.ip NOT IN (SELECT cidr FROM ot_subnets.csv)
AND network.destination.ip NOT IN (SELECT ip FROM authorized_it_destinations.csv)
AND NOT (
  network.destination.ip MATCHES "224.0.0.0/4"
  OR network.destination.ip = "255.255.255.255"
)
| GROUP BY network.source.ip, network.destination.ip, user.name
| SELECT MIN(event.timestamp) AS first_seen,
         MAX(event.timestamp) AS last_seen,
         COUNT() AS connection_count,
         VALUES(network.destination.port) AS destination_ports,
         VALUES(network.application) AS applications,
         network.source.ip AS plc_ip,
         network.destination.ip AS destination_ip,
         user.name AS user
| EVAL first_seen = FORMAT_TIME(first_seen, "YYYY-MM-DD HH:mm:ss"),
      last_seen = FORMAT_TIME(last_seen, "YYYY-MM-DD HH:mm:ss")
```

### Web-based PLC Malware
---
Name: Web-Based PLC Malware or Exploitation Attempt

Author: RW

Date: 2025-08-11

Description: Detects suspicious web requests to Programmable Logic Controllers (PLCs) that could indicate exploitation of embedded web servers by malware or an attacker. The rule looks for common hacking tools in the User-Agent string and patterns associated with exploits (e.g., directory traversal, command injection) in the URL.

Tactic: Initial Access, Execution

Technique: T1190 - Exploit Public-Facing Application

False Positive Sensitivity: Medium

- This rule may generate false positives from legitimate vulnerability scanning or administrative scripts.

- It is CRITICAL to populate the 'plc_ips' list with your assets and the 'authorized_sources' list with any approved scanners or management tools to ensure high fidelity.

splunk:
```sql
-- Data source: This rule is designed for CIM-compliant web traffic data (datamodel: Web).
-- You may need to adjust field names (e.g., url, http_user_agent, dest, src) for your specific data source.
`cim_Web_Web`
-- **CRITICAL TUNING STEP 1**: Filter for traffic destined for a known PLC.
-- Create a lookup file named 'plc_ips.csv' with a single column 'dest' containing the IP addresses of your PLCs with web interfaces.
| search dest IN (lookup plc_ips.csv dest)
-- Focus on common web ports. Add others if your PLCs use non-standard ports.
| search dest_port IN (80, 443, 8000, 8080)
-- **CRITICAL TUNING STEP 2**: Exclude traffic from authorized sources.
-- Create a lookup file named 'authorized_sources.csv' with a single column 'src' containing the IPs of approved scanners or management tools.
| search NOT src IN (lookup authorized_sources.csv src)
-- Core detection logic: Look for suspicious patterns in the User Agent or the URL.
| search (
    (http_user_agent IN ("*curl*", "*wget*", "*python-requests*", "*nmap*", "*sqlmap*", "*masscan*", "*Go-http-client*", "*zgrab*", "*metasploit*"))
    OR
    (url IN ("*../*", "*/etc/passwd*", "*win.ini*", "*cmd.exe*", "*/bin/sh*", "*powershell.exe*", "*SELECT*", "*UNION*", "*--*", "*<script>*", "*%3Cscript%3E*", "*rce.php*", "*shell.php*", "*upload.php*"))
)
-- Summarize the activity to reduce alert volume and provide context.
| stats
    earliest(_time) as first_seen,
    latest(_time) as last_seen,
    count as attempt_count,
    values(http_user_agent) as user_agents,
    values(url) as urls,
    values(http_method) as http_methods
    by dest, src
| `convert_time(first_seen)`
| `convert_time(last_seen)`
-- Provide a clear name for the detection.
| rename dest as plc_ip, src as source_ip
```

crowdstrike fql:
```sql
event_type="WebTraffic"
| dest_ip IN (LOOKUP("plc_ips.csv", "dest"))
| dest_port IN (80, 443, 8000, 8080)
| NOT src_ip IN (LOOKUP("authorized_sources.csv", "src"))
| (
    http_user_agent LIKE "*curl*" OR http_user_agent LIKE "*wget*" OR http_user_agent LIKE "*python-requests*"
    OR http_user_agent LIKE "*nmap*" OR http_user_agent LIKE "*sqlmap*" OR http_user_agent LIKE "*masscan*"
    OR http_user_agent LIKE "*Go-http-client*" OR http_user_agent LIKE "*zgrab*" OR http_user_agent LIKE "*metasploit*"
    OR url LIKE "*../*" OR url LIKE "*/etc/passwd*" OR url LIKE "*win.ini*" OR url LIKE "*cmd.exe*"
    OR url LIKE "*/bin/sh*" OR url LIKE "*powershell.exe*" OR url LIKE "*SELECT*" OR url LIKE "*UNION*"
    OR url LIKE "*--*" OR url LIKE "*<script>*" OR url LIKE "*%3Cscript%3E*" OR url LIKE "*rce.php*"
    OR url LIKE "*shell.php*" OR url LIKE "*upload.php*"
)
| group by dest_ip, src_ip
| aggregate first_seen=MIN(timestamp), last_seen=MAX(timestamp), attempt_count=COUNT(),
           user_agents=VALUES(http_user_agent), urls=VALUES(url), http_methods=VALUES(http_method)
| format_time(first_seen), format_time(last_seen)
| rename dest_ip as plc_ip, src_ip as source_ip
```

datadog:
```sql
source:web
dest_ip:(lookup:plc_ips.csv, dest)
dest_port:(80 OR 443 OR 8000 OR 8080)
-src_ip:(lookup:authorized_sources.csv, src)
(
  http_user_agent:(*curl* OR *wget* OR *python-requests* OR *nmap* OR *sqlmap* OR *masscan* OR *Go-http-client* OR *zgrab* OR *metasploit*)
  OR url:(*../* OR */etc/passwd* OR *win.ini* OR *cmd.exe* OR */bin/sh* OR *powershell.exe* OR *SELECT* OR *UNION* OR *--* OR *<script>* OR *%3Cscript%3E* OR *rce.php* OR *shell.php* OR *upload.php*)
)
| stats min(@timestamp) as first_seen, max(@timestamp) as last_seen, count as attempt_count,
        values(http_user_agent) as user_agents, values(url) as urls, values(http_method) as http_methods
        by dest_ip, src_ip
| eval first_seen = strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen = strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| rename dest_ip as plc_ip, src_ip as source_ip
```

elastic:
```sql
FROM logs-web*
| WHERE destination.ip IN (SELECT dest FROM plc_ips.csv)
  AND destination.port IN (80, 443, 8000, 8080)
  AND source.ip NOT IN (SELECT src FROM authorized_sources.csv)
  AND (
    http.request.user_agent LIKE "*curl*" OR http.request.user_agent LIKE "*wget*" OR http.request.user_agent LIKE "*python-requests*"
    OR http.request.user_agent LIKE "*nmap*" OR http.request.user_agent LIKE "*sqlmap*" OR http.request.user_agent LIKE "*masscan*"
    OR http.request.user_agent LIKE "*Go-http-client*" OR http.request.user_agent LIKE "*zgrab*" OR http.request.user_agent LIKE "*metasploit*"
    OR url.full LIKE "*../*" OR url.full LIKE "*/etc/passwd*" OR url.full LIKE "*win.ini*" OR url.full LIKE "*cmd.exe*"
    OR url.full LIKE "*/bin/sh*" OR url.full LIKE "*powershell.exe*" OR url.full LIKE "*SELECT*" OR url.full LIKE "*UNION*"
    OR url.full LIKE "*--*" OR url.full LIKE "*<script>*" OR url.full LIKE "*%3Cscript%3E*" OR url.full LIKE "*rce.php*"
    OR url.full LIKE "*shell.php*" OR url.full LIKE "*upload.php*"
  )
| STATS first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp),
        attempt_count = COUNT(),
        user_agents = MV_DEDUP(http.request.user_agent),
        urls = MV_DEDUP(url.full),
        http_methods = MV_DEDUP(http.request.method)
  BY destination.ip, source.ip
| EVAL first_seen = TO_STRING(first_seen, "yyyy-MM-dd HH:mm:ss"),
      last_seen = TO_STRING(last_seen, "yyyy-MM-dd HH:mm:ss")
| RENAME destination.ip AS plc_ip, source.ip AS source_ip
```

sentinel one:
```sql
event.type = "WebTraffic"
AND network.destination.ip IN (SELECT dest FROM plc_ips.csv)
AND network.destination.port IN (80, 443, 8000, 8080)
AND network.source.ip NOT IN (SELECT src FROM authorized_sources.csv)
AND (
  network.http.user_agent LIKE "%curl%" OR network.http.user_agent LIKE "%wget%" OR network.http.user_agent LIKE "%python-requests%"
  OR network.http.user_agent LIKE "%nmap%" OR network.http.user_agent LIKE "%sqlmap%" OR network.http.user_agent LIKE "%masscan%"
  OR network.http.user_agent LIKE "%Go-http-client%" OR network.http.user_agent LIKE "%zgrab%" OR network.http.user_agent LIKE "%metasploit%"
  OR network.url LIKE "%../%" OR network.url LIKE "%/etc/passwd%" OR network.url LIKE "%win.ini%" OR network.url LIKE "%cmd.exe%"
  OR network.url LIKE "%/bin/sh%" OR network.url LIKE "%powershell.exe%" OR network.url LIKE "%SELECT%" OR network.url LIKE "%UNION%"
  OR network.url LIKE "%--%" OR network.url LIKE "%<script>%" OR network.url LIKE "%%3Cscript%3E%" OR network.url LIKE "%rce.php%"
  OR network.url LIKE "%shell.php%" OR network.url LIKE "%upload.php%"
)
| GROUP BY network.destination.ip, network.source.ip
| SELECT MIN(event.timestamp) AS first_seen,
         MAX(event.timestamp) AS last_seen,
         COUNT() AS attempt_count,
         VALUES(network.http.user_agent) AS user_agents,
         VALUES(network.url) AS urls,
         VALUES(network.http.method) AS http_methods,
         network.destination.ip AS plc_ip,
         network.source.ip AS source_ip
| EVAL first_seen = FORMAT_TIME(first_seen, "YYYY-MM-DD HH:mm:ss"),
      last_seen = FORMAT_TIME(last_seen, "YYYY-MM-DD HH:mm:ss")
```

### Compromised Engineering Workstation
---
Name: Evil PLC Attack - PLC to Engineering Workstation Connection

Author: RW

Date: 2025-08-11

Description: Detects a Programmable Logic Controller (PLC) initiating a network connection to an Engineering Workstation (EWS). This is highly anomalous behavior and a key indicator of an "Evil PLC" attack, where a compromised PLC is weaponized to attack the EWS that programs or manages it.

Tactic: Lateral Movement

Technique: T0840 - Exploitation of Remote Services

False Positive Sensitivity: Medium

- This rule may trigger on legitimate, albeit rare, communications from PLCs to IT-based systems like data historians or specific management applications running on an EWS.

- It is CRITICAL to accurately populate the 'plc_ips' and 'engineering_workstation_ips' lists. An incomplete or inaccurate asset inventory will lead to missed detections or false positives.

splunk:
```sql
-- Data source: This rule is designed for CIM-compliant network traffic data.
`cim_Network_Traffic_all`
-- The connection must originate from a known PLC.
-- **CRITICAL TUNING STEP 1**: Create a lookup file named 'plc_ips.csv' with a single column 'ip' containing the IP addresses of your PLCs.
| search src IN ( `get_plc_ips` )
-- The connection must be destined for a known Engineering Workstation.
-- **CRITICAL TUNING STEP 2**: Create a lookup file named 'engineering_workstation_ips.csv' with a single column 'ip' containing the IP addresses of your EWS.
| search dest IN ( `get_ews_ips` )
-- Filter for connections to suspicious ports to increase fidelity.
-- This list targets common remote service exploitation vectors.
| search dest_port IN (21, 22, 135, 139, 445, 3389, 5985, 5986)
-- **TUNING**: If there are legitimate ports/protocols for PLC->EWS communication, exclude them here using a lookup or by adding `NOT dest_port IN (...)`.
-- Summarize the activity to create a single, high-context alert.
| stats earliest(_time) as first_seen, latest(_time) as last_seen, count, values(dest_port) as destination_ports, values(app) as applications by src, dest, user
| `convert_time(first_seen)`
| `convert_time(last_seen)`
-- Provide a clear name for the detection.
| rename src as plc_ip, dest as engineering_workstation_ip, count as connection_count
```

crowdstrike fql:
```sql
event_type="NetworkConnection"
| src_ip IN (LOOKUP("plc_ips.csv", "ip"))
| dest_ip IN (LOOKUP("engineering_workstation_ips.csv", "ip"))
| dest_port IN (21, 22, 135, 139, 445, 3389, 5985, 5986)
| group by src_ip, dest_ip, user_name
| aggregate first_seen=MIN(timestamp), last_seen=MAX(timestamp), connection_count=COUNT(),
           destination_ports=VALUES(dest_port), applications=VALUES(app)
| format_time(first_seen), format_time(last_seen)
| rename src_ip as plc_ip, dest_ip as engineering_workstation_ip, user_name as user
```

datadog:
```sql
source:network
src_ip:(lookup:plc_ips.csv, ip)
dest_ip:(lookup:engineering_workstation_ips.csv, ip)
dest_port:(21 OR 22 OR 135 OR 139 OR 445 OR 3389 OR 5985 OR 5986)
| stats min(@timestamp) as first_seen, max(@timestamp) as last_seen, count as connection_count,
        values(dest_port) as destination_ports, values(app) as applications
        by src_ip, dest_ip, user
| eval first_seen = strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen = strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| rename src_ip as plc_ip, dest_ip as engineering_workstation_ip
```

elastic:
```sql
FROM logs-network*
| WHERE source.ip IN (SELECT ip FROM plc_ips.csv)
  AND destination.ip IN (SELECT ip FROM engineering_workstation_ips.csv)
  AND destination.port IN (21, 22, 135, 139, 445, 3389, 5985, 5986)
| STATS first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp),
        connection_count = COUNT(),
        destination_ports = MV_DEDUP(destination.port),
        applications = MV_DEDUP(network.application)
  BY source.ip, destination.ip, user.name
| EVAL first_seen = TO_STRING(first_seen, "yyyy-MM-dd HH:mm:ss"),
      last_seen = TO_STRING(last_seen, "yyyy-MM-dd HH:mm:ss")
| RENAME source.ip AS plc_ip,
         destination.ip AS engineering_workstation_ip,
         user.name AS user
```

sentinel one:
```sql
event.type = "NetworkConnection"
AND network.source.ip IN (SELECT ip FROM plc_ips.csv)
AND network.destination.ip IN (SELECT ip FROM engineering_workstation_ips.csv)
AND network.destination.port IN (21, 22, 135, 139, 445, 3389, 5985, 5986)
| GROUP BY network.source.ip, network.destination.ip, user.name
| SELECT MIN(event.timestamp) AS first_seen,
         MAX(event.timestamp) AS last_seen,
         COUNT() AS connection_count,
         VALUES(network.destination.port) AS destination_ports,
         VALUES(network.application) AS applications,
         network.source.ip AS plc_ip,
         network.destination.ip AS engineering_workstation_ip,
         user.name AS user
| EVAL first_seen = FORMAT_TIME(first_seen, "YYYY-MM-DD HH:mm:ss"),
      last_seen = FORMAT_TIME(last_seen, "YYYY-MM-DD HH:mm:ss")
```