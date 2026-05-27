### Cyber Threat Intelligence Report: Maritime Industrial Control Systems
---

This report summarizes the evolving cyber threats targeting maritime Industrial Control Systems (ICS) and highlights the need for enhanced detection and response capabilities. The increasing digitalization and connectivity of maritime systems have expanded the attack surface, making vessels and port infrastructure vulnerable to various cyberattacks, including ransomware and sophisticated exploits against critical operational technologies.

Recent intelligence indicates a significant increase in the use of generative AI by threat actors to accelerate malware development, automate phishing campaigns, and refine social engineering tactics, leading to a surge in AI-assisted cyberattacks targeting ICS environments. Additionally, the maritime industry's appetite for cyber risk is notably higher than other key industries, with a false sense of security regarding their cybersecurity posture, particularly concerning operational technology (OT) security.

### Actionable Threat Data
---

Monitor for unusual network traffic patterns or unauthorized access attempts to ICS networks, especially those connected to navigation, propulsion, cargo management, or safety systems, as these are prime targets for disruption and control.

Implement robust endpoint detection and response (EDR) solutions on all IT and OT systems to detect and prevent the execution of ransomware and other malicious software, which are increasingly prevalent in maritime attacks and can spread from IT to OT networks.

Prioritize patching and vulnerability management for ICS components, particularly those identified in recent CISA advisories (e.g., mySCADA, Hitachi Energy, Schneider Electric, Siemens), as unpatched vulnerabilities can lead to unauthorized access, system compromise, or data exposure.

Enhance monitoring for social engineering attempts, such as phishing, which remain a primary initial access vector for maritime organizations, and consider user behavior analytics to detect anomalous activity indicative of compromised credentials.

Establish baselines for normal ICS operation and continuously monitor for deviations, such as unexpected changes in control system configurations, unusual commands, or abnormal sensor readings, which could indicate a cyberattack aimed at manipulating physical processes.

### Search
---
```sql
-- Rule Title: Unusual ICS Network Traffic
-- Description: This rule detects network traffic to or from a designated Industrial Control System (ICS) / Operational Technology (OT)
-- network segment that does not originate from or go to an authorized source. The increasing digitalization and connectivity of maritime
-- and other critical infrastructure systems expand the attack surface, making this monitoring crucial for early detection of compromise.
-- Such activity can indicate unauthorized access attempts, lateral movement from a compromised IT system, or data exfiltration.
-- Author: RW
-- Date: 2025-08-17
-- References:
-- - https://www.marinelink.com/news/maritime-cyber-threats-grow-increasingly-525922
-- False Positive Sensitivity: Medium

-- Data Source: Logs from network monitoring tools or Datadog NPM.
-- Query Strategy: Filter for traffic involving ICS networks, exclude authorized sources, and aggregate by source/destination IPs.
-- False Positive Tuning: Use tags for ICS networks and authorized sources.

logs(
  source:network
  @host:(ship-nav* OR plc* OR ot*)
  (
    (network.dest_ip:(@ics_networks) AND -network.src_ip:(@ics_networks OR @authorized_sources)) OR
    (network.src_ip:(@ics_networks) AND -network.dest_ip:(@ics_networks OR @authorized_sources))
  )
)
| group by network.src_ip, network.dest_ip, @user
| select
    min(@timestamp) as StartTime,
    max(@timestamp) as EndTime,
    network.src_ip as SourceIp,
    network.dest_ip as DestinationIp,
    values(network.dest_port) as DestinationPorts,
    values(network.action) as Actions,
    count as TotalEvents,
    @user as User,
    "Unusual ICS Network Traffic" as RuleTitle,
    "Unauthorized network traffic detected between " + network.src_ip + " and " + network.dest_ip + ". This could indicate an unauthorized access attempt or policy violation involving the ICS/OT network." as Description
| display RuleTitle, StartTime, EndTime, SourceIp, DestinationIp, DestinationPorts, Actions, TotalEvents, User, Description
```
---
```sql
-- Rule Title: Potential Ransomware Activity on IT/OT System
-- Description: This rule detects common ransomware behaviors, such as deleting volume shadow copies or creating ransom notes, occurring on designated Industrial Control System (ICS) or Operational Technology (OT) assets. Ransomware is increasingly prevalent in maritime and other critical infrastructure attacks and can spread from IT to OT networks, causing significant disruption.
-- Author: RW
-- Date: 2025-08-17
-- References:
-- - https://www.marinelink.com/news/maritime-cyber-threats-grow-increasingly-525922
-- False Positive Sensitivity: Medium

-- Data Source: Endpoint logs from EDR tools (e.g., Sysmon, CrowdStrike).
-- Query Strategy: Search for processes inhibiting system recovery and file creation events matching ransom note patterns, aggregate by device and user.
-- False Positive Tuning: Filter for OT assets and exclude authorized admin accounts.

-- Part 1: Inhibit System Recovery
logs(
  source:endpoint
  @host:(ship-nav* OR plc* OR ot*)
  (
    (process.name:(vssadmin.exe OR vssadmin) *delete* *shadows*) OR
    (process.name:(wbadmin.exe OR wbadmin) *delete* *catalog*) OR
    (process.name:(bcdedit.exe OR bcdedit) *recoveryenabled*no*)
  )
)
| group by @timestamp, process.command_line, @user, @host
| select
    @timestamp as Time,
    process.command_line as SuspiciousEntity,
    @user as AccountName,
    @host as DeviceName,
    "Inhibit System Recovery" as Activity

-- Part 2: Ransom Note Creation
| union(
  logs(
    source:endpoint
    file.action:created
    file.name:(*readme.txt OR *decrypt*.txt OR *recover*.txt OR *help*.txt)
    @host:(ship-nav* OR plc* OR ot*)
  )
  | group by @timestamp, file.name, @user, @host
  | select
      @timestamp as Time,
      file.name as SuspiciousEntity,
      @user as AccountName,
      @host as DeviceName,
      "Ransom Note Created: " + file.name as Activity
)

-- Summarize and Format
| group by AccountName, DeviceName
| select
    min(Time) as StartTime,
    max(Time) as EndTime,
    values(Activity) as Activities,
    values(SuspiciousEntity) as SuspiciousEntities,
    "Potential Ransomware Activity on IT/OT System" as RuleTitle,
    "Potential ransomware activity detected on critical system '" + DeviceName + "' by account '" + coalesce(AccountName, "N/A") + "'. Observed activities: " + mvjoin(Activities, "; ") + "." as Description
| display RuleTitle, StartTime, EndTime, DeviceName, AccountName, Activities, SuspiciousEntities, Description
```
---
```sql
-- Rule Title: Suspicious Child Process of ICS/OT Application
-- Description: This rule detects when a known Industrial Control System (ICS) or Operational Technology (OT) application process spawns a suspicious child process, such as a command shell or scripting engine. This behavior is a strong indicator of post-exploitation activity, where an attacker, having exploited a vulnerability in the ICS software, is attempting to gain further control of the host.
-- Author: RW
-- Date: 2025-08-17
-- References:
-- - https://cybersecuritynews.com/cisa-releases-six-ics-advisories/
-- - https://foxguardsolutions.com/blog/ics-patch-update-february-2024/
-- - https://cyble.com/blog/latest-ics-vulnerabilities/
-- False Positive Sensitivity: Medium
-- - Legitimate administrative or automated scripts related to the ICS application could trigger this alert.

-- Data Source: Endpoint logs capturing process creation events.
-- Query Strategy: Filter for ICS parent processes spawning suspicious child processes, aggregate by device and parent process.
-- False Positive Tuning: Exclude known administrative scripts and tune process lists.

logs(
  source:endpoint
  @host:(ship-nav* OR plc* OR ot*)
  process.parent.name:(UAGRoot.exe OR Vijeo-Designer.exe OR Citect32.exe OR StruxureWare.exe OR PowerSCADA.exe OR s7oiehsx.exe OR CCMyAsserver.exe OR WinCCExplorer.exe OR S7tgtopx.exe OR mySCADA.exe OR myPRO.exe OR AdvDsopc.exe OR AdvAeSrv.exe OR RSLinx.exe OR FTView.exe OR LogixDesigner.exe)
  process.name:(powershell.exe OR pwsh.exe OR cmd.exe OR wscript.exe OR cscript.exe OR bitsadmin.exe OR certutil.exe OR rundll32.exe OR sh.exe OR bash.exe)
)
| group by @timestamp, @host, @user, process.parent.name, process.name, process.command_line
| select
    min(@timestamp) as StartTime,
    max(@timestamp) as EndTime,
    @host as DeviceName,
    @user as AccountName,
    process.parent.name as InitiatingProcessFileName,
    values(process.name) as SuspiciousChildProcess,
    values(process.command_line) as SuspiciousChildProcessCommandLine,
    "Suspicious Child Process of ICS/OT Application" as RuleTitle,
    "A known ICS/OT process '" + process.parent.name + "' on host '" + @host + "' spawned a suspicious child process: " + mvjoin(SuspiciousChildProcess, ", ") + ". This may indicate exploitation of a vulnerability in the ICS software." as Description
| display RuleTitle, StartTime, EndTime, DeviceName, AccountName, InitiatingProcessFileName, SuspiciousChildProcess, SuspiciousChildProcessCommandLine, Description
```
---
```sql
-- Rule Title: Suspicious Process Spawned by User-Facing Application
-- Description: This rule detects when a common user-facing application (like an email client, web browser, or office suite application) spawns a suspicious child process, such as a command shell or scripting engine. This behavior is a strong indicator of a successful social engineering or phishing attempt, where a user has been tricked into opening a malicious link or document, leading to code execution.
-- Author: RW
-- Date: 2025-08-17
-- References:
-- - https://www.porttechnology.org/news/maritime-cybersecurity-threats-and-challenges/
-- False Positive Sensitivity: Medium

-- Data Source: Endpoint logs capturing process creation events.
-- Query Strategy: Filter for user-facing applications spawning suspicious child processes, exclude benign executions, and aggregate by device and user.
-- False Positive Tuning: Exclude known legitimate add-ins or installers.

logs(
  source:endpoint
  process.parent.name:(outlook.exe OR winword.exe OR excel.exe OR powerpnt.exe OR acrord32.exe OR acrordr32.exe OR chrome.exe OR msedge.exe OR firefox.exe OR iexplore.exe)
  process.name:(powershell.exe OR pwsh.exe OR cmd.exe OR wscript.exe OR cscript.exe OR mshta.exe OR rundll32.exe)
  -(process.name:rundll32.exe *C:\\Windows\\System32*)
  -(process.name:cmd.exe *"/c exit"*)
)
| group by @timestamp, @host, @user, process.parent.name, process.name, process.command_line
| select
    min(@timestamp) as StartTime,
    max(@timestamp) as EndTime,
    @host as DeviceName,
    @user as AccountName,
    values(process.parent.name) as ParentProcesses,
    values(process.name) as SuspiciousChildProcesses,
    values(process.command_line) as SuspiciousCommandLines,
    "Suspicious Process Spawned by User-Facing Application" as RuleTitle,
    "A user-facing application (" + mvjoin(ParentProcesses, ", ") + ") spawned a suspicious child process (" + mvjoin(SuspiciousChildProcesses, ", ") + ") on host '" + @host + "' by user '" + coalesce(AccountName, "N/A") + "'. This is a strong indicator of a successful phishing attempt." as Description
| display RuleTitle, StartTime, EndTime, DeviceName, AccountName, ParentProcesses, SuspiciousChildProcesses, SuspiciousCommandLines, Description
```
---
```sql
-- Rule Title: ICS Operational Deviation Detected
-- Description: This rule detects potential manipulation of Industrial Control Systems (ICS) by monitoring for two types of host-level artifacts: modifications to critical configuration files and the appearance of high-risk commands in application logs. Cyberattacks targeting physical processes often involve altering system configurations or issuing unauthorized commands. This rule provides a framework for detecting such deviations from normal operations.
-- Author: RW
-- Date: 2025-08-17
-- References:
-- - https://www.cisa.gov/news-events/ics-advisories/icsa-25-226-03
-- False Positive Sensitivity: Medium
-- - Legitimate maintenance, software updates, or engineering changes will trigger this alert. It is crucial to correlate alerts with planned work.

-- Data Source: Endpoint logs for file modifications and ICS application logs for critical commands.
-- Query Strategy: Search for file creation/modification events and critical command patterns, aggregate by device and user.
-- False Positive Tuning: Exclude temporary files and correlate with planned maintenance.

-- Part 1: ICS Config File Modifications
logs(
  source:endpoint
  file.action:(created OR modified OR renamed)
  file.name:(*.ACD OR *.L5K OR *.L5X OR *.S7P OR *.AP* OR *.MCP OR *.XEF OR *.PCX OR *.STU OR *project.cfg OR *config.ini OR *backup.zip)
  @host:(ship-nav* OR plc* OR ot*)
  -file.path:(*\\Temp\\* OR *\\AppData\\Local\\*)
)
| group by @timestamp, @host, @user, file.name, file.path
| select
    @timestamp as Time,
    @host as DeviceName,
    @user as User,
    "ICS Config File Modified: " + file.name as Activity

-- Part 2: Critical OT Commands
| union(
  logs(
    source:ics_logs
    message:(STOP_PROCESS OR EMERGENCY_SHUTDOWN OR SETPOINT_OVERRIDE OR DOWNLOAD_PROJECT OR "Forcing I/O" OR "Controller mode change" OR "Logic Download" OR "Firmware Update")
    @host:(ship-nav* OR plc* OR ot*)
  )
  | group by @timestamp, @host, @user, message
  | select
      @timestamp as Time,
      @host as DeviceName,
      @user as User,
      "Critical OT Command Detected: " + message as Activity
)

-- Summarize and Format
| group by DeviceName
| select
    min(Time) as StartTime,
    max(Time) as EndTime,
    values(Activity) as Activities,
    values(User) as Accounts,
    "ICS Operational Deviation Detected" as RuleTitle,
    "Potential ICS operational deviation detected on host '" + DeviceName + "'. This may indicate unauthorized configuration changes or commands. Observed activities: " + mvjoin(Activities, "; ") as Description
| display RuleTitle, StartTime, EndTime, DeviceName, Accounts, Activities, Description
```