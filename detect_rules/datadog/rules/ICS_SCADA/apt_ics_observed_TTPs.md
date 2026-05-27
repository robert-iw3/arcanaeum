### The Worst ICS/OT Cybersecurity Love Story
---

This report summarizes the evolving landscape of ICS/OT threats, highlighting the increasing convergence of state-sponsored adversaries and hacktivist groups, particularly those aligned with Russia. It emphasizes the growing threat of ransomware attacks against industrial organizations and the persistent vulnerabilities in remote access to OT environments.

The 2025 Dragos Year in Review report indicates a significant 87% increase in ransomware attacks against industrial organizations and a 60% rise in active ransomware groups impacting OT/ICS in 2024. Additionally, new intelligence reveals that state-sponsored APT44 (Sandworm) is leveraging hacktivist personas like Cyber Army of Russia Reborn (CARR), XakNet, and Solntsepek to manipulate critical infrastructure, blurring the lines between state-backed and hacktivist operations.

### Actionable Threat Data
---

Monitor for increased ransomware activity, specifically targeting industrial control systems and manufacturing entities, as these have seen a significant surge in attacks.

Implement robust security measures for remote access to OT/ICS environments, addressing insecure configurations, unpatched systems, and poor network architecture, as 65% of assessed sites had such vulnerabilities.

Detect and prevent the use of SSH for general-purpose encrypted communication to publicly routable addresses, as 45% of OT Watch customers had this vulnerability, which can be leveraged for C2 tunnels and proxies.

Focus on detecting initial access attempts by groups like KAMACITE (APT44), which often target IT networks to gain footholds in OT/ICS infrastructure, and look for credential harvesting activities.

Be aware of hacktivist groups like Cyber Army of Russia Reborn (CARR), KillNet, XakNet, and Solntsepek, especially their use of DDoS attacks, data leaks, and attempts to manipulate SCADA systems, as they may act as fronts for more advanced state-sponsored operations.

### Search
---
```sql
-- Name: Ransomware Activity in ICS/OT Environment
-- Author: RW
-- Date: 2025-08-17
-- Description: Detects common ransomware TTPs that are highly anomalous in an Industrial Control Systems (ICS) or Operational Technology (OT) environment. The query identifies shadow copy deletion, disabling of recovery features, and mass file renaming indicative of encryption. The detection is focused on behaviors that are particularly suspicious on critical assets like Engineering Workstations (EWS) or Human-Machine Interfaces (HMI).
-- False Positive Sensitivity: Medium
-- Tactic: Impact
-- Technique: T1490, T1486

-- Data Source: Logs from endpoint security tools (e.g., Sysmon, CrowdStrike) ingested into Datadog Logs.
-- Query Strategy: Use Datadog Log Search to detect specific process executions (e.g., vssadmin.exe, bcdedit.exe) and file rename patterns. Aggregate file rename events over a time window to identify mass renaming.
-- False Positive Tuning: Filter for OT assets using tags (e.g., host:hmi* or host:ews*) and adjust thresholds for file rename counts.

-- Pattern 1 & 2: Inhibit System Recovery (T1490)
logs(
  source:endpoint
  (process.name:vssadmin.exe "delete shadows" OR
   process.name:bcdedit.exe ("recoveryenabled no" OR "bootstatuspolicy ignoreallfailures"))
  @host:(hmi* OR ews* OR historian*)
)
| group by @host, process.name, process.command_line, @user
| select
    min(@timestamp) as firstTime,
    max(@timestamp) as lastTime,
    @host as DeviceName,
    @user as UserName,
    process.name as ProcessName,
    process.command_line as ProcessCommandLine,
    case(
      process.name:vssadmin.exe => "Shadow Copy Deletion",
      process.name:bcdedit.exe => "System Recovery Disabled"
    ) as Pattern,
    "T1490" as Technique,
    "Impact" as Tactic
| display firstTime, lastTime, DeviceName, UserName, ProcessName, ProcessCommandLine, Pattern, Technique, Tactic

-- Pattern 3: Mass File Renaming (T1486)
| union(
  logs(
    source:endpoint file.action:renamed @host:(hmi* OR ews* OR historian*)
  )
  | group by @host, @user, process.name, file.extension within 5m
  | select
      min(@timestamp) as firstTime,
      max(@timestamp) as lastTime,
      @host as DeviceName,
      @user as UserName,
      process.name as ProcessName,
      "N/A (File System Activity)" as ProcessCommandLine,
      count as RenamedFileCount,
      file.extension as NewExtension,
      "Mass File Renaming" as Pattern,
      "T1486" as Technique,
      "Impact" as Tactic
  | where RenamedFileCount > 100 AND count_distinct(file.extension) = 1
)
| display firstTime, lastTime, DeviceName, UserName, ProcessName, ProcessCommandLine, Pattern, Technique, Tactic, RenamedFileCount, NewExtension
```
---
```sql
-- Name: Insecure Remote Access Pattern in ICS/OT Environment
-- Author: RW
-- Date: 2025-08-17
-- Description: Detects multiple patterns of insecure or highly anomalous remote access to or from critical Industrial Control Systems (ICS) or Operational Technology (OT) assets. This includes inbound RDP/VNC from the internet, outbound SSH to the internet, and the use of common remote administration software. Such activity is often forbidden by policy in OT environments and can be an indicator of misconfiguration or malicious activity. This detection is based on intelligence indicating that 65% of assessed OT sites have insecure remote conditions.
-- False Positive Sensitivity: Medium
-- Tactic: Initial Access, Command and Control
-- Technique: T1133, T1219

-- Data Source: Datadog Network Performance Monitoring (NPM) for network traffic and Logs for process execution.
-- Query Strategy: Use NPM to detect inbound/outbound connections on specific ports (3389, 5900, 22) and Logs to identify remote admin tool execution. Filter for OT assets using tags.
-- False Positive Tuning: Exclude corporate IP ranges using Datadog’s network filters and define a list of remote admin tools as a tag or facet.

-- Pattern 1: Inbound RDP/VNC from Internet
logs(
  source:network
  network.direction:inbound
  network.dest_port:(3389 OR 5800 OR 5900 OR 5901)
  @host:(hmi* OR ews* OR historian*)
  -network.src_ip:(10.0.0.0/8 OR 192.168.0.0/16)
)
| group by @host, network.src_ip, network.dest_port
| select
    min(@timestamp) as firstTime,
    max(@timestamp) as lastTime,
    @host as DeviceName,
    network.src_ip as RemoteIP,
    network.dest_port as RemotePort,
    "Inbound RDP/VNC from Internet" as Pattern,
    "Initial Access" as Tactic,
    "T1133" as Technique,
    "N/A" as ProcessName,
    "N/A" as ProcessCommandLine,
    "N/A" as UserName

-- Pattern 2: Outbound SSH to Internet
| union(
  logs(
    source:network
    network.direction:outbound
    network.dest_port:22
    @host:(hmi* OR ews* OR historian*)
    -network.dest_ip:(10.0.0.0/8 OR 192.168.0.0/16)
  )
  | group by @host, network.dest_ip, network.application
  | select
      min(@timestamp) as firstTime,
      max(@timestamp) as lastTime,
      @host as DeviceName,
      network.dest_ip as RemoteIP,
      22 as RemotePort,
      network.application as ProcessName,
      "Outbound SSH to Internet" as Pattern,
      "Command and Control" as Tactic,
      "T1133" as Technique,
      "N/A" as ProcessCommandLine,
      "N/A" as UserName
)

-- Pattern 3: Remote Administration Software Execution
| union(
  logs(
    source:endpoint
    process.name:(TeamViewer.exe OR AnyDesk.exe OR tv_w32.exe OR tv_x64.exe OR LogMeIn.exe OR ScreenConnect.exe OR splashtop.exe OR vncviewer.exe)
    @host:(hmi* OR ews* OR historian*)
  )
  | group by @host, process.name, process.command_line, @user
  | select
      min(@timestamp) as firstTime,
      max(@timestamp) as lastTime,
      @host as DeviceName,
      process.name as ProcessName,
      process.command_line as ProcessCommandLine,
      @user as UserName,
      "Remote Administration Software Execution" as Pattern,
      "Command and Control" as Tactic,
      "T1219" as Technique,
      "N/A" as RemoteIP,
      "N/A" as RemotePort
)
| display firstTime, lastTime, DeviceName, Pattern, Tactic, Technique, RemoteIP, RemotePort, ProcessName, ProcessCommandLine, UserName
```
---
```sql
-- Name: Outbound SSH Tunneling or High Data Transfer from ICS/OT Asset
-- Author: RW
-- Date: 2025-08-17
-- Description: Detects outbound SSH from critical ICS/OT assets to the public internet that exhibits signs of being used for C2 or proxying. The rule looks for either explicit command-line flags used for tunneling or high-volume data transfers over SSH. According to intelligence, 45% of assessed OT environments have SSH communicating to public addresses, which can be leveraged by adversaries for C2 tunnels and proxies.
-- False Positive Sensitivity: Medium
-- Tactic: Command and Control
-- Technique: T1090, T1572

-- Data Source: Endpoint logs for SSH process commands and NPM for network traffic volume.
-- Query Strategy: Search for SSH processes with tunneling flags (-D, -L, -R) and aggregate network bytes for high data transfers over port 22.
-- False Positive Tuning: Use tags for OT assets and exclude corporate IPs. Adjust data transfer thresholds based on environment baselines.

-- Pattern 1: SSH Tunneling Command Detected
logs(
  source:endpoint
  process.name:(ssh.exe OR plink.exe OR putty.exe)
  (process.command_line:*-D* OR process.command_line:*-L* OR process.command_line:*-R*)
  @host:(hmi* OR ews* OR historian*)
)
| group by @host, @user, process.name, process.command_line
| select
    min(@timestamp) as firstTime,
    max(@timestamp) as lastTime,
    @host as DeviceName,
    @user as UserName,
    process.name as ProcessName,
    process.command_line as ProcessCommandLine,
    "SSH Tunneling Command Detected" as Pattern,
    "N/A (check command line)" as RemoteIP,
    "N/A" as TotalBytesTransferred,
    "Command and Control" as Tactic,
    "T1090,T1572" as Technique

-- Pattern 2: High Data Transfer over SSH to Public IP
| union(
  metrics(
    network.bytes_written{host:(hmi* OR ews* OR historian*) AND dest_port:22 AND -dest_ip:(10.0.0.0/8 OR 192.168.0.0/16)}
  )
  | group by host, dest_ip, process.name within 1h
  | select
      min(timestamp) as firstTime,
      max(timestamp) as lastTime,
      host as DeviceName,
      "N/A" as UserName,
      process.name as ProcessName,
      "N/A" as ProcessCommandLine,
      dest_ip as RemoteIP,
      round(sum(network.bytes_written) / 1024 / 1024, 2) + " MB" as TotalBytesTransferred,
      "High Data Transfer over SSH to Public IP" as Pattern,
      "Command and Control" as Tactic,
      "T1090,T1572" as Technique
  | where sum(network.bytes_written) > (10 * 1024 * 1024)
)
| display firstTime, lastTime, DeviceName, UserName, Pattern, ProcessName, ProcessCommandLine, RemoteIP, TotalBytesTransferred, Tactic, Technique
```
---
```sql
-- Name: KAMACITE Initial Access and Credential Harvesting
-- Author: RW
-- Date: 2025-08-17
-- Description: Detects credential harvesting techniques commonly used by threat actors like KAMACITE (APT44) after gaining initial access to IT networks that bridge to OT/ICS environments. This rule identifies LSASS memory dumping and registry hive dumping, which are critical steps for adversaries to escalate privileges and move laterally. Detecting these activities is crucial to preventing deeper compromise of OT/ICS environments.
-- False Positive Sensitivity: Medium
-- Tactic: Credential Access
-- Technique: T1003.001, T1003.002

-- Data Source: Endpoint logs capturing process execution details.
-- Query Strategy: Search for specific process names and command-line patterns indicative of LSASS dumping or registry hive extraction.
-- False Positive Tuning: Filter for critical systems (e.g., jump servers, EWS) using tags and exclude known administrative tools.

logs(
  source:endpoint
  @host:(hmi* OR ews* OR historian* OR jumpserver*)
  (
    (process.name:procdump.exe *-ma* *lsass.exe*) OR
    (process.name:rundll32.exe *comsvcs.dll*MiniDump*) OR
    (process.name:reg.exe *save* (*hklm\sam* OR *hklm\security* OR *hklm\system*))
  )
)
| group by @host, @user, process.parent.name, process.name, process.command_line
| select
    min(@timestamp) as firstTime,
    max(@timestamp) as lastTime,
    @host as DeviceName,
    @user as AccountName,
    process.parent.name as InitiatingProcessFileName,
    process.name as FileName,
    process.command_line as ProcessCommandLine,
    case(
      (process.name:procdump.exe OR process.name:rundll32.exe) => "LSASS Memory Dumping",
      process.name:reg.exe => "Registry Hive Dumping"
    ) as Pattern,
    case(
      (process.name:procdump.exe OR process.name:rundll32.exe) => "T1003.001",
      process.name:reg.exe => "T1003.002"
    ) as TechniqueId,
    "Credential Access" as Tactic
| display firstTime, lastTime, DeviceName, AccountName, Pattern, TechniqueId, InitiatingProcessFileName, FileName, ProcessCommandLine
```
---
```sql
-- Name: Hacktivist Activity on SCADA/OT Systems
-- Author: RW
-- Date: 2025-08-17
-- Description: This rule detects TTPs associated with hacktivist groups like CARR and KillNet targeting ICS/OT environments. It identifies potential DDoS symptoms, anomalous administrative tool usage on critical OT assets (HMIs, EWS), and large-scale data exfiltration. These activities can indicate attempts to manipulate SCADA systems or serve as a distraction for other malicious actions.
-- False Positive Sensitivity: Medium
-- Tactic: Impact, Execution, Exfiltration
-- Technique: T1498, T1059, T1048

-- Data Source: NPM for DDoS detection, endpoint logs for process execution, and network metrics for data exfiltration.
-- Query Strategy: Aggregate inbound connections for DDoS, search for anomalous processes on OT assets, and monitor outbound data transfers.
-- False Positive Tuning: Use tags for OT assets, exclude corporate IPs, and adjust thresholds for connection counts and data transfers.

-- Pattern 1: Potential DDoS Symptom (High Inbound Connections)
metrics(
  network.connections{host:(hmi* OR ews* OR historian*) AND direction:inbound AND -src_ip:(10.0.0.0/8 OR 192.168.0.0/16)}
)
| group by host within 5m
| select
    min(timestamp) as Time,
    host as DeviceName,
    count_distinct(src_ip) as DistinctRemoteIPs,
    "Potential DDoS Symptom (High Inbound Connections)" as Pattern,
    "Impact" as Tactic,
    "T1498" as Technique,
    "Host " + host + " received connections from " + count_distinct(src_ip) + " distinct external IPs in 5 minutes." as Details
| where count_distinct(src_ip) > 200

-- Pattern 2: Anomalous Process on Critical OT Asset
| union(
  logs(
    source:endpoint
    process.name:(powershell.exe OR cmd.exe OR cscript.exe OR wscript.exe OR nmap.exe OR netcat.exe OR nc.exe OR net.exe OR netsh.exe OR plink.exe OR putty.exe OR mstsc.exe)
    @host:(hmi* OR ews* OR historian*)
    -process.parent.name:monitoring_agent.exe
  )
  | group by @host, @user, process.parent.name, process.name, process.command_line
  | select
      min(@timestamp) as Time,
      @host as DeviceName,
      @user as User,
      process.parent.name as ParentProcess,
      process.name as ProcessName,
      process.command_line as ProcessCommandLine,
      "Anomalous Process on Critical OT Asset" as Pattern,
      "Execution" as Tactic,
      "T1059" as Technique,
      "Process: " + process.name + ", CommandLine: " + process.command_line + ", Initiated by: " + process.parent.name as Details
)

-- Pattern 3: Large Data Exfiltration from OT Asset
| union(
  metrics(
    network.bytes_written{host:(hmi* OR ews* OR historian*) AND direction:outbound AND -dest_ip:(10.0.0.0/8 OR 192.168.0.0/16)}
  )
  | group by host, dest_ip, process.name within 1h
  | select
      min(timestamp) as Time,
      host as DeviceName,
      dest_ip as RemoteIP,
      process.name as ProcessName,
      "Large Data Exfiltration from OT Asset" as Pattern,
      "Exfiltration" as Tactic,
      "T1048" as Technique,
      "Transferred " + round(sum(network.bytes_written) / 1024 / 1024, 2) + " MB from " + host + " to " + dest_ip + " via process " + process.name as Details
  | where sum(network.bytes_written) > (50 * 1024 * 1024)
)
| display Time, DeviceName, Pattern, Tactic, Technique, Details
```