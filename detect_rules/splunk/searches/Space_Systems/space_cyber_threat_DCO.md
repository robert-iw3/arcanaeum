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

-- This macro should be defined to search your web, proxy, or firewall logs and should be CIM compliant.
-- Example: `tstats` count from datamodel=Web where (nodename=Web.Proxy OR nodename=Web.Web) by _time, Web.url, Web.src, Web.dest, Web.user_agent | `drop_dm_object_name("Web")`
`web_proxy_dm`

-- Filter for requests containing known OpenC3 paths. Customize this list for your environment.
| where
    like(url, "%/openc3-api/tables%") OR
    like(url, "%/CmdTlmServer%") OR
    like(url, "%/ScriptRunner%")

-- Filter for common web attack indicators in the URL.
| where
    like(url, "%../%") OR
    like(url, "%..\\%") OR
    like(url, "%..%2f%") OR
    like(url, "%..%5c%") OR
    like(url, "%%2e%2e%2f%") OR
    like(url, "%/etc/passwd%") OR
    like(url, "%win.ini%") OR
    like(url, "%cmd.exe%") OR
    like(url, "%/bin/sh%") OR
    like(url, "%<script>%") OR
    like(url, "%alert(%)") OR
    like(url, "%onload=%")

-- FP Tuning: Exclude known vulnerability scanners or trusted IPs if necessary.
-- | where NOT (src IN ("<scanner_ip_1>", "<scanner_ip_2>"))

-- Create a table of the results for review.
| table _time, src, dest, url, user_agent

-- Rename fields for consistency (CIM).
| rename src AS src_ip, dest AS dest_ip, user_agent AS http_user_agent, url as http_url
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

-- This macro defines the data models to search. It's typically Endpoint and Network_Traffic.
`cim_summary_indexes`

-- The core logic identifies two suspicious conditions which are appended together.
-- 1. A connection to any RabbitMQ port from a suspicious process (like a shell or script interpreter).
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (nodename=Processes) (Processes.dest_port IN (5672, 5671, 15672, 15671)) AND (Processes.process_name IN ("powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "cscript.exe", "wscript.exe", "bash", "sh", "zsh", "python.exe", "python3.exe", "perl.exe", "ncat.exe", "netcat.exe", "nc.exe")) by Processes.dest, Processes.src, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name, Processes.dest_port
| `drop_dm_object_name("Processes")`
| rename dest as dest_ip, src as src_ip
| eval reason="Suspicious process connected to RabbitMQ port."

-- 2. A connection to the management UI (port 15672) from an external, non-private IP address.
| append [
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (nodename=All_Traffic) (All_Traffic.dest_port=15672) by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
    | `drop_dm_object_name("All_Traffic")`
    | rename dest as dest_ip, src as src_ip
    -- FP Tuning: Filter out private and reserved IP ranges.
    | where NOT (cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("172.16.0.0/12", src_ip) OR cidrmatch("192.168.0.0/16", src_ip) OR cidrmatch("127.0.0.0/8", src_ip) OR cidrmatch("::1/128", src_ip) OR cidrmatch("fe80::/10", src_ip))
    -- FP Tuning: Exclude known/trusted external IPs that need to access the management UI.
    -- AND NOT (src_ip IN ("<trusted_partner_ip>"))
    | eval reason="External IP connected to RabbitMQ management port."
]

-- Format the results for review.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, reason, src_ip, dest_ip, dest_port, user, process_name, process, parent_process_name
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

-- Logic Part 1: Detect network connections to default Cobalt Strike C2 URIs.
-- This part of the query requires web, proxy, or firewall logs, mapped to the CIM Web datamodel.
`tstats` `summariesonly` values(Web.url) as matched_indicators, count min(_time) as firstTime, max(_time) as lastTime from datamodel=Web where
    (
        Web.url="*/jquery.js" OR Web.url="*/jquery.min.js" OR Web.url="*/jquery-3.3.1.js" OR Web.url="*/jquery-3.3.1.min.js" OR
        Web.url="*/jquery-3.6.0.min.js" OR Web.url="*/jquery-3.6.0.js" OR Web.url="*/ga.js" OR Web.url="*/pixel.gif" OR
        Web.url="*/submit.php" OR Web.url="*/__utm.gif" OR Web.url="*/cdn.jquery-3.3.1.min.js" OR Web.url="*/load.js"
    )
    by Web.src, Web.dest, Web.user, Web.process_name
| `drop_dm_object_name("Web")`
| rename src as src_ip, dest as host, process_name as process
| eval detection_method="Cobalt Strike C2 Network Indicator (Default URI)"

-- Logic Part 2: Detect the creation of default Cobalt Strike named pipes.
-- This part requires Sysmon Event Code 17 (Pipe Created). Ensure you have a macro or sourcetype for Sysmon logs.
| append [
    search `sysmon` EventCode=17
    | `regex` field=PipeName "\\\\.\\pipe\\(msagent|postex|status)_[a-f0-9]{4,6}"
    | stats values(PipeName) as matched_indicators, count min(_time) as firstTime, max(_time) as lastTime by host, user, process, ProcessGuid
    | eval detection_method="Cobalt Strike Named Pipe Creation", src_ip=""
    | rename ProcessGuid as process_guid
]

-- Format and present the combined results.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, detection_method, host, src_ip, user, process, process_guid, matched_indicators
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
-- False Positive Sensitivity: Medium. Legitimate activities, such as system backups, software distribution, or authorized large data transfers, may trigger this alert. It is crucial to tune the macros to match your environment's baseline.
-- References:
-- - https://attack.mitre.org/techniques/T1074/
-- - https://attack.mitre.org/techniques/T1041/
-- - https://attack.mitre.org/techniques/T1030/
-- - https://attack.mitre.org/techniques/T1052/

-- --- MACRO DEFINITIONS ---
-- `critical_systems_host_macro`: This macro should be defined to filter for your critical ground systems.
--      Example: `(host IN ("SAT-CONTROL-01", "IMAGE-PROCESSOR-5", "GROUND-STATION-7"))`
-- `exfil_threshold_bytes`: This macro should define the size in bytes for a large data transfer. Default is 50MB.
--      Example: `52428800`

-- Logic Part 1: Detect potential data staging on critical systems (T1074)
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime, values(Filesystem.file_path) as staged_files, values(Filesystem.file_size) as file_sizes from datamodel=Endpoint.Filesystem where `critical_systems_host_macro` (Filesystem.action=created) AND (Filesystem.file_name IN ("*.zip", "*.rar", "*.7z", "*.tar", "*.gz", "*.tgz", "*.iso")) AND Filesystem.file_size > (`exfil_threshold_bytes`/2) by Filesystem.dest, Filesystem.process_name, Filesystem.process
| `drop_dm_object_name("Filesystem")`
| rename dest as host
| eval detection_method="Potential Data Staging Detected"
-- Add empty fields for aligning with the egress search
| eval remote_ip="", dest_port="", total_bytes_out=0

-- Logic Part 2: Detect large data egress from critical systems (T1041, T1030)
| append [
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime, sum(All_Traffic.bytes_out) as total_bytes_out, values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic where `critical_systems_host_macro` All_Traffic.bytes_out > `exfil_threshold_bytes` by All_Traffic.src, All_Traffic.dest, All_Traffic.process_name, All_Traffic.process
    | `drop_dm_object_name("All_Traffic")`
    -- Filter for connections to external, non-private IP addresses
    | where NOT (cidrmatch("10.0.0.0/8", dest) OR cidrmatch("172.16.0.0/12", dest) OR cidrmatch("192.168.0.0/16", dest) OR cidrmatch("127.0.0.0/8", dest))
    -- FP Tuning: Exclude connections to known good destinations like backup servers or partner networks.
    -- | where NOT (dest IN ("<trusted_ip_1>", "<trusted_ip_2>"))
    | rename src as host, dest as remote_ip
    | eval detection_method="Large Data Egress Detected"
    -- Add empty fields for aligning with the staging search
    | eval staged_files="", file_sizes=""
]

-- Combine and format results
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, detection_method, host, process_name, process, total_bytes_out, remote_ip, dest_port, staged_files, file_sizes
```