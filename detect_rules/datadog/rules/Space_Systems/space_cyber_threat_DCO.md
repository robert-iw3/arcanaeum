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

-- Data Source: Web proxy, firewall, or application logs with HTTP request data.
-- Query Strategy: Filter for requests to OpenC3 paths with attack indicators, exclude known scanners, and aggregate by source and destination.
-- False Positive Tuning: Exclude legitimate scanners or trusted IPs.

logs(
  source:(web OR proxy OR firewall)
  @host:(sat-control* OR ground-station*)
  (
    http.url:(*/openc3-api/tables* OR */CmdTlmServer* OR */ScriptRunner*) AND
    http.url:(*../* OR *..\\* OR *..%2f* OR *..%5c* OR *%2e%2e%2f* OR */etc/passwd* OR *win.ini* OR *cmd.exe* OR */bin/sh* OR *<script>* OR *alert(* OR *onload=*)
  )
  -network.src_ip:(@scanner_ip_allowlist)
)
| group by @timestamp, network.src_ip, network.dest_ip, http.url, http.user_agent
| select
    @timestamp as Time,
    network.src_ip as SrcIp,
    network.dest_ip as DestIp,
    http.url as HttpUrl,
    http.user_agent as HttpUserAgent
| display Time, SrcIp, DestIp, HttpUrl, HttpUserAgent
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

-- Data Source: Endpoint and network logs from ground station systems.
-- Query Strategy: Identify suspicious process connections to RabbitMQ ports and external connections to the management UI, exclude trusted IPs, and aggregate by source and destination.
-- False Positive Tuning: Exclude known administrative tools and IPs.

-- Suspicious Process Connections
logs(
  source:endpoint
  @host:(sat-control* OR ground-station*)
  network.dest_port:(5672 OR 5671 OR 15672 OR 15671)
  process.name:(powershell.exe OR pwsh.exe OR cmd.exe OR rundll32.exe OR cscript.exe OR wscript.exe OR bash OR sh OR zsh OR python.exe OR python3.exe OR perl.exe OR ncat.exe OR netcat.exe OR nc.exe)
)
| group by @host, network.src_ip, network.dest_ip, @user, process.name, process.command_line, process.parent.name, network.dest_port
| select
    min(@timestamp) as FirstTime,
    max(@timestamp) as LastTime,
    "Suspicious process connected to RabbitMQ port." as Reason,
    network.src_ip as SrcIp,
    network.dest_ip as DestIp,
    network.dest_port as DestPort,
    @user as User,
    process.name as ProcessName,
    process.command_line as Process,
    process.parent.name as ParentProcessName

-- External Connections to Management UI
| union(
  logs(
    source:network
    @host:(sat-control* OR ground-station*)
    network.dest_port:15672
    -network.src_ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16 OR 127.0.0.0/8 OR ::1/128 OR fe80::/10)
    -network.src_ip:(@trusted_partner_ip)
  )
  | group by network.src_ip, network.dest_ip, network.dest_port
  | select
      min(@timestamp) as FirstTime,
      max(@timestamp) as LastTime,
      "External IP connected to RabbitMQ management port." as Reason,
      network.src_ip as SrcIp,
      network.dest_ip as DestIp,
      network.dest_port as DestPort,
      "" as User,
      "" as ProcessName,
      "" as Process,
      "" as ParentProcessName
)

| display FirstTime, LastTime, Reason, SrcIp, DestIp, DestPort, User, ProcessName, Process, ParentProcessName
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

-- Data Source: Web proxy/firewall logs for C2 URIs and endpoint logs for named pipe creation (e.g., Sysmon Event ID 17).
-- Query Strategy: Identify network connections to Cobalt Strike URIs and named pipe creation, aggregate by host and user, and combine results.
-- False Positive Tuning: Default Cobalt Strike patterns are high-fidelity but may be altered by sophisticated attackers.

-- Network C2 Indicators
logs(
  source:(web OR proxy OR firewall)
  @host:(sat-control* OR ground-station*)
  http.url:(
    */jquery.js OR */jquery.min.js OR */jquery-3.3.1.js OR */jquery-3.3.1.min.js OR
    */jquery-3.6.0.min.js OR */jquery-3.6.0.js OR */ga.js OR */pixel.gif OR
    */submit.php OR */__utm.gif OR */cdn.jquery-3.3.1.min.js OR */load.js
  )
)
| group by network.src_ip, @host, @user, process.name
| select
    min(@timestamp) as FirstTime,
    max(@timestamp) as LastTime,
    "Cobalt Strike C2 Network Indicator (Default URI)" as DetectionMethod,
    @host as Host,
    network.src_ip as SrcIp,
    @user as User,
    process.name as Process,
    "" as ProcessGuid,
    values(http.url) as MatchedIndicators

-- Named Pipe Creation
| union(
  logs(
    source:sysmon
    @host:(sat-control* OR ground-station*)
    event.code:17
    pipe.name:/\\\\.\\pipe\\(msagent|postex|status)_[a-f0-9]{4,6}/
  )
  | group by @host, @user, process.name, process.guid
  | select
      min(@timestamp) as FirstTime,
      max(@timestamp) as LastTime,
      "Cobalt Strike Named Pipe Creation" as DetectionMethod,
      @host as Host,
      "" as SrcIp,
      @user as User,
      process.name as Process,
      process.guid as ProcessGuid,
      values(pipe.name) as MatchedIndicators
)

| display FirstTime, LastTime, DetectionMethod, Host, SrcIp, User, Process, ProcessGuid, MatchedIndicators
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

-- Data Source: Endpoint logs for file creation (e.g., Sysmon Event ID 11) and network logs for data transfers.
-- Query Strategy: Identify large archive file creation and external data egress, exclude trusted destinations, and aggregate by host and process.
-- False Positive Tuning: Exclude legitimate backup or transfer activities.

-- Data Staging
logs(
  source:endpoint
  @host:(@critical_systems_host)
  file.action:created
  file.name:(*.zip OR *.rar OR *.7z OR *.tar OR *.gz OR *.tgz OR *.iso)
  file.size > (@exfil_threshold_bytes/2)
)
| group by @host, process.name, process.command_line
| select
    min(@timestamp) as FirstTime,
    max(@timestamp) as LastTime,
    "Potential Data Staging Detected" as DetectionMethod,
    @host as Host,
    process.name as ProcessName,
    process.command_line as Process,
    values(file.path) as StagedFiles,
    values(file.size) as FileSizes,
    0 as TotalBytesOut,
    "" as RemoteIp,
    "" as DestPort

-- Large Data Egress
| union(
  logs(
    source:network
    @host:(@critical_systems_host)
    network.bytes_out > @exfil_threshold_bytes
    -network.dest_ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16 OR 127.0.0.0/8)
    -network.dest_ip:(@trusted_dest_ip)
  )
  | group by @host, network.dest_ip, process.name, process.command_line
  | select
      min(@timestamp) as FirstTime,
      max(@timestamp) as LastTime,
      "Large Data Egress Detected" as DetectionMethod,
      @host as Host,
      process.name as ProcessName,
      process.command_line as Process,
      "" as StagedFiles,
      "" as FileSizes,
      sum(network.bytes_out) as TotalBytesOut,
      network.dest_ip as RemoteIp,
      values(network.dest_port) as DestPort
)

| display FirstTime, LastTime, DetectionMethod, Host, ProcessName, Process, TotalBytesOut, RemoteIp, DestPort, StagedFiles, FileSizes
```