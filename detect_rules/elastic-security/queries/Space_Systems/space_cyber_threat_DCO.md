### Moonlight Defender: Space Cyber Threat Intelligence
---

The Moonlight Defender exercise series focuses on enhancing the U.S. Space Force's defensive cyber operations (DCO) capabilities against advanced space-cyber threats, utilizing the Moonlighter cyber test satellite and the Dark Sky cyber range. The exercises highlight the critical vulnerabilities within satellite ground systems and the importance of real-time threat detection and response in the space domain.

Recent intelligence emphasizes the increasing sophistication of cyberattacks targeting satellite ground stations, with a focus on exploiting vulnerabilities in widely used open-source frameworks like OpenC3 Cosmos, which has multiple recently disclosed CVEs, including remote code execution and path traversal. This highlights a critical and evolving attack surface beyond the satellite itself.

### Actionable Threat Data
---

Monitor for unusual network traffic patterns and connections to and from satellite ground station systems, especially those involving OpenC3 Cosmos, given its identified vulnerabilities.

Implement robust logging and anomaly detection for activities related to RabbitMQ servers within ground systems, as these are used for critical data transfer and can be targeted for disruption or data exfiltration.

Establish detections for the presence and activity of Cobalt Strike beacons or similar post-exploitation frameworks within ground system networks, as these are commonly used by advanced threat actors for command and control.

Prioritize patching and vulnerability management for all software and systems used in satellite ground operations, particularly open-source components like OpenC3 Cosmos, to mitigate known exploitation vectors.

Develop and refine detection rules for attempts to manipulate or exfiltrate mission-critical data from ground systems, focusing on data flows related to satellite imaging and command operations.

### OpenC3 Vulnerability Exploitation
---
```sql
-- Name: Potential OpenC3 Cosmos Vulnerability Exploitation
-- Author: RW
-- Date: 2025-08-15
-- Description: Detects potential exploitation attempts against OpenC3 Cosmos, a framework often used in satellite ground systems. The rule looks for web requests targeting known OpenC3 paths that also contain indicators of path traversal, command injection, or XSS. This activity could represent reconnaissance or an attempt to exploit known vulnerabilities like CVE-2025-28382.
-- Tactic: Initial Access
-- Technique: T1190 - Exploit Public-Facing Application
-- False Positive Sensitivity: Medium. This rule may trigger on legitimate but poorly-formed URLs or aggressive vulnerability scanners. Consider adding known scanner IPs to an exclusion list to improve fidelity.
-- References:
-- - https://github.com/advisories/GHSA-cf8v-5mrc-jv7f
-- - https://visionspace.com/openc3-cosmos-a-security-assessment-of-an-open-source-mission-framework/
-- - https://vulert.com/vuln-db/pypi-openc3-172070

FROM *  -- Adjust this to your specific web/proxy/firewall log index patterns.
| WHERE event.category == "web"  --  Focuses on events categorized as web traffic.
| WHERE
    http.request.url.path LIKE '%/openc3-api/tables%' OR  -- Checks for known OpenC3 paths.
    http.request.url.path LIKE '%/CmdTlmServer%' OR
    http.request.url.path LIKE '%/ScriptRunner%'
| WHERE
    http.request.url.path LIKE '%../%' OR  -- Filters for common web attack indicators in the URL, such as path traversal.
    http.request.url.path LIKE '%..\\%' OR
    http.request.url.path LIKE '%..%2f%' OR
    http.request.url.path LIKE '%..%5c%' OR
    http.request.url.path LIKE '%%2e%2e%2f%' OR
    http.request.url.path LIKE '%/etc/passwd%' OR  -- Filters for known command injection and XSS indicators.
    http.request.url.path LIKE '%win.ini%' OR
    http.request.url.path LIKE '%cmd.exe%' OR
    http.request.url.path LIKE '%/bin/sh%' OR
    http.request.url.path LIKE '%<script>%' OR
    http.request.url.path LIKE '%alert(%)' OR
    http.request.url.path LIKE '%onload=%'
-- FP Tuning: Exclude known vulnerability scanners or trusted IPs if necessary.
-- | WHERE NOT (source.ip IN ('<scanner_ip_1>', '<scanner_ip_2>'))
| SELECT
    @timestamp AS time,  --  Selects the timestamp of the event.
    source.ip,  --  Selects the source IP address.
    destination.ip AS dest_ip,  -- Selects the destination IP address and renames it.
    http.request.url.original AS url,  -- Selects the original URL.
    user_agent.original AS user_agent  -- Selects the original user agent string.
```

### RabbitMQ Server Anomalies
---
```sql
-- Name: Anomalous RabbitMQ Server Activity
-- Author: RW
-- Date: 2025-08-15
-- Description: Detects suspicious activity related to RabbitMQ servers, which are often used for critical data transfer in satellite ground systems. The rule looks for connections from non-standard processes or from external IP addresses to the management interface. This could indicate reconnaissance, lateral movement, or data exfiltration attempts.
-- Tactic: Exfiltration, Lateral Movement
-- Technique: T1041, T1567, T1071.001
-- False Positive Sensitivity: Medium. Legitimate administrative scripts or monitoring tools might cause false positives. Exclude known tools or source IPs to improve fidelity.
-- References:
-- - https://www.ssec.wisc.edu/datacenter/amqpfind/
-- - https://www.rabbitmq.com/networking.html

-- Part 1: Detect connections to RabbitMQ ports from suspicious processes
FROM *  -- Adjust this to your specific endpoint log index patterns.
| WHERE event.category == "process" AND event.type == "start" -- Looking for process start events.
| WHERE destination.port IN (5672, 5671, 15672, 15671)  -- Targets common RabbitMQ ports.
| WHERE process.executable IN ("powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "cscript.exe", "wscript.exe", "bash", "sh", "zsh", "python.exe", "python3.exe", "perl.exe", "ncat.exe", "netcat.exe", "nc.exe")  -- Filters for known suspicious processes.
| SELECT
    @timestamp AS firstTime,  --  Timestamp of the event as "firstTime".
    @timestamp AS lastTime,   --  Timestamp of the event as "lastTime".
    'Suspicious process connected to RabbitMQ port.' AS reason,  --  Reason for the detection.
    source.ip AS src_ip,  -- Source IP address.
    destination.ip AS dest_ip,  -- Destination IP address.
    destination.port AS dest_port,  -- Destination port.
    user.name AS user,  -- User associated with the process.
    process.executable AS process_name,  -- Executable name of the process.
    process.args AS process,  -- Full command-line arguments of the process.
    process.parent.executable AS parent_process_name  -- Parent process executable name.

UNION ALL  -- Combines the results of the two parts.

-- Part 2: Detect connections to the management UI (port 15672) from external IPs
FROM logs-network.flow.*  -- Adjust this to your specific network flow log index patterns.
| WHERE event.category == "network" AND event.type == "connection" -- Filters for network connection events.
| WHERE destination.port == 15672  -- Targets the RabbitMQ management UI port.
| WHERE NOT cidr_match(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '::1/128', 'fe80::/10'], source.ip)  -- Excludes private and reserved IP ranges.
-- FP Tuning: Exclude known/trusted external IPs that need to access the management UI.
-- | WHERE NOT (source.ip IN ('<trusted_partner_ip>'))
| SELECT
    @timestamp AS firstTime,
    @timestamp AS lastTime,
    'External IP connected to RabbitMQ management port.' AS reason,
    source.ip AS src_ip,
    destination.ip AS dest_ip,
    destination.port AS dest_port,
    NULL AS user,  --  These fields may not be available in network flow logs.
    NULL AS process_name,
    NULL AS process,
    NULL AS parent_process_name
```

### Cobalt Strike Beacon Activity
---
```sql
-- Name: Cobalt Strike Beacon Activity
-- Author: RW
-- Date: 2025-08-15
-- Description: Detects indicators of Cobalt Strike beacon activity on both the host and network. The rule looks for the creation of default named pipes used for C2 session passing and for network connections to default URIs used by Malleable C2 profiles. This activity is common in post-exploitation frameworks used by advanced threat actors.
-- Tactic: Command and Control, Ingress Tool Transfer
-- Technique: T1071.001, T1105
-- False Positive Sensitivity: Medium. Default Cobalt Strike artifacts are often changed by sophisticated attackers. However, their presence is a high-fidelity indicator of compromise. Legitimate tools are unlikely to use these specific patterns.

-- Part 1: Detect network connections to default Cobalt Strike C2 URIs.
FROM *  -- Adjust this to your specific web/proxy/firewall log index patterns.
| WHERE event.category == "network" AND event.type == "connection" AND http.request.method != NULL
| WHERE
    http.request.url.path == '/jquery.js' OR http.request.url.path == '/jquery.min.js' OR
    http.request.url.path == '/jquery-3.3.1.js' OR http.request.url.path == '/jquery-3.3.1.min.js' OR
    http.request.url.path == '/jquery-3.6.0.min.js' OR http.request.url.path == '/jquery-3.6.0.js' OR
    http.request.url.path == '/ga.js' OR http.request.url.path == '/pixel.gif' OR
    http.request.url.path == '/submit.php' OR http.request.url.path == '/__utm.gif' OR
    http.request.url.path == '/cdn.jquery-3.3.1.min.js' OR http.request.url.path == '/load.js'
| GROUP BY source.ip, destination.ip, user.name, process.name, @timestamp
| SELECT
    @timestamp AS firstTime,
    @timestamp AS lastTime,
    source.ip AS src_ip,
    destination.ip AS host,
    user.name AS user,
    process.name AS process,
    NULL AS process_guid, -- Not applicable for network indicators
    'Cobalt Strike C2 Network Indicator (Default URI)' AS detection_method,
    COLLECT_SET(http.request.url.path) AS matched_indicators

UNION ALL

-- Part 2: Detect the creation of default Cobalt Strike named pipes.
FROM logs-endpoint.events.sysmon_event_17.*  -- Adjust this to your Sysmon Event Code 17 log index pattern.
| WHERE event.code == 17  -- Sysmon Event Code 17: Pipe Created.
| WHERE file.path =~ '\\\\.\\pipe\\(msagent|postex|status)_[a-f0-9]{4,6}'  -- Uses regex to match pipe names.
| GROUP BY host.name, user.name, process.name, process.entity_id, @timestamp
| SELECT
    @timestamp AS firstTime,
    @timestamp AS lastTime,
    NULL AS src_ip,  -- Not applicable for host-based indicators
    host.name AS host,
    user.name AS user,
    process.name AS process,
    process.entity_id AS process_guid,  -- Maps ProcessGuid to ECS process.entity_id.
    'Cobalt Strike Named Pipe Creation' AS detection_method,
    COLLECT_SET(file.path) AS matched_indicators
```

### Mission Data Manipulation/Exfiltration
---
```sql
-- Name: Mission Data Manipulation or Exfiltration from Ground Systems
-- Author: RW
-- Date: 2025-08-15
-- Description: Detects a two-stage attack pattern indicative of mission data exfiltration from critical ground systems. The first stage detects the creation of large archive files (data staging). The second stage detects large data transfers from the same systems to external destinations.
-- Tactic: Collection, Exfiltration
-- Technique: T1074, T1041, T1030, T1052
-- False Positive Sensitivity: Medium. Legitimate activities, such as system backups, software distribution, or authorized large data transfers, may trigger this alert.
-- References:
-- - https://attack.mitre.org/techniques/T1074/
-- - https://attack.mitre.org/techniques/T1041/
-- - https://attack.mitre.org/techniques/T1030/
-- - https://attack.mitre.org/techniques/T1052/

-- Part 1: Detect potential data staging (creation of large archive files)
FROM logs-endpoint.events.*  -- Adjust this to your specific endpoint log index patterns.
| WHERE event.category == "file" AND event.type == "creation"  -- Filters for file creation events.
| WHERE host.name IN (<critical_systems_host_list>)  -- Replace with a list of your critical system hostnames.
| WHERE file.extension IN ("zip", "rar", "7z", "tar", "gz", "tgz", "iso")  -- Filters for common archive file extensions.
| WHERE file.size > (<exfil_threshold_bytes> / 2)  -- Filters for files exceeding half the defined exfiltration threshold in bytes.
| GROUP BY host.name, process.name, process.args, @timestamp  -- Groups events by host, process, and timestamp.
| SELECT
    @timestamp AS firstTime,  -- Timestamp of the event as "firstTime".
    @timestamp AS lastTime,   -- Timestamp of the event as "lastTime".
    host.name AS host,  -- Hostname of the system.
    process.name AS process_name,  -- Name of the process creating the file.
    process.args AS process,  -- Command-line arguments of the process.
    0 AS total_bytes_out,  -- Placeholder for network egress bytes (Part 2).
    NULL AS remote_ip,  -- Placeholder for the remote IP (Part 2).
    NULL AS dest_port,  -- Placeholder for the destination port (Part 2).
    COLLECT_SET(file.path) AS staged_files,  -- Collects distinct paths of staged files.
    COLLECT_SET(file.size) AS file_sizes,  -- Collects distinct sizes of staged files.
    'Potential Data Staging Detected' AS detection_method  -- Description of the detection.

UNION ALL  -- Combines the results of the two parts.

-- Part 2: Detect large data egress from critical systems
FROM logs-network.flow.*  -- Adjust this to your specific network flow log index patterns.
| WHERE event.category == "network" AND event.type == "connection" -- Filters for network connection events.
| WHERE source.ip IN (<critical_systems_ip_list>)  -- Replace with a list of your critical system IP addresses.
| WHERE network.bytes_out > <exfil_threshold_bytes>  -- Filters for outbound network traffic exceeding the exfiltration threshold in bytes.
| WHERE NOT cidr_match(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '::1/128', 'fe80::/10'], destination.ip)  -- Excludes private and reserved IP ranges.
-- FP Tuning: Exclude connections to known good destinations like backup servers or partner networks.
-- | WHERE NOT (destination.ip IN ('<trusted_ip_1>', '<trusted_ip_2>'))
| GROUP BY source.ip, destination.ip, process.name, process.args, @timestamp, destination.port  -- Groups events by source, destination, process, and port.
| SELECT
    @timestamp AS firstTime,
    @timestamp AS lastTime,
    source.ip AS host,
    process.name AS process_name,
    process.args AS process,
    SUM(network.bytes_out) AS total_bytes_out,  -- Calculates the sum of outbound bytes.
    destination.ip AS remote_ip,  -- Destination IP address as "remote_ip".
    destination.port AS dest_port,  -- Destination port.
    NULL AS staged_files,  -- Placeholder for staged files (Part 1).
    NULL AS file_sizes,  -- Placeholder for file sizes (Part 1).
    'Large Data Egress Detected' AS detection_method  -- Description of the detection.
```
