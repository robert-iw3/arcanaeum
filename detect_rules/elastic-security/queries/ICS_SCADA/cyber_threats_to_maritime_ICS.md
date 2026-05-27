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
-- Description: Detects network traffic to or from a designated ICS/OT network segment that does not originate from or go to an authorized source, indicating potential unauthorized access or lateral movement.
-- Author: RW
-- Date: 2025-08-17
-- References: https://www.marinelink.com/news/maritime-cyber-threats-grow-increasingly-525922
-- False Positive Sensitivity: Medium
-- Tags: ICS, OT, Maritime, Unauthorized Access, Lateral Movement
-- Rule: Assumes network traffic logs with ECS fields, requiring definition of ICS networks and authorized sources.

FROM *
| WHERE network.transport == "tcp" OR network.transport == "udp"
| EVAL is_src_ics = CASE(
    CIDR_MATCH("192.168.1.0/24", source.ip) OR CIDR_MATCH("10.100.0.0/16", source.ip), 1,
    true, 0
  ),
  is_dest_ics = CASE(
    CIDR_MATCH("192.168.1.0/24", destination.ip) OR CIDR_MATCH("10.100.0.0/16", destination.ip), 1,
    true, 0
  ),
  is_src_authorized = CASE(
    CIDR_MATCH("172.16.1.10/32", source.ip) OR CIDR_MATCH("172.16.2.0/24", source.ip), 1,
    true, 0
  ),
  is_dest_authorized = CASE(
    CIDR_MATCH("172.16.1.10/32", destination.ip) OR CIDR_MATCH("172.16.2.0/24", destination.ip), 1,
    true, 0
  )
| WHERE (
    -- Case 1: Traffic from an external, unauthorized source INTO the ICS network
    (is_dest_ics == 1 AND is_src_ics == 0 AND is_src_authorized == 0)
    OR
    -- Case 2: Traffic FROM the ICS network to an external, unauthorized destination
    (is_src_ics == 1 AND is_dest_ics == 0 AND is_dest_authorized == 0)
  )
| STATS start_time = MIN(@timestamp), end_time = MAX(@timestamp), dest_ports = VALUES(destination.port), actions = VALUES(event.action), TotalEvents = COUNT() BY source.ip, destination.ip, user.name
| EVAL start_time = TO_STRING(start_time), end_time = TO_STRING(end_time)
| RENAME source.ip AS SourceIp, destination.ip AS DestinationIp, dest_ports AS DestinationPorts, user.name AS User, actions AS Actions
| EVAL RuleTitle = "Unusual ICS Network Traffic",
       Description = CONCAT("Unauthorized network traffic detected between ", SourceIp, " and ", DestinationIp, ". This could indicate an unauthorized access attempt or policy violation involving the ICS/OT network.")
| KEEP RuleTitle, start_time AS StartTime, end_time AS EndTime, SourceIp, DestinationIp, User, Actions, TotalEvents, Description
-- Potential False Positives:
-- Legitimate but unlisted systems (e.g., new workstations, vendor access) may trigger alerts.
-- Example: Update authorized sources with IPs like "172.16.1.11" or use a lookup table.
-- | WHERE NOT (SourceIp IN (SELECT ip FROM authorized_sources))
```
---
```sql
-- Rule Title: Potential Ransomware Activity on IT/OT System
-- Description: Detects ransomware behaviors, such as deleting volume shadow copies or creating ransom notes, on ICS/OT assets, indicating potential compromise.
-- Author: RW
-- Date: 2025-08-17
-- References: https://www.marinelink.com/news/maritime-cyber-threats-grow-increasingly-525922
-- False Positive Sensitivity: Medium
-- Tags: ICS, OT, Maritime, Ransomware, Endpoint Detection
-- Rule: Requires process and file creation events with ECS fields, typically from EDR solutions.

FROM *
| WHERE (
    -- Part 1: Detect processes that inhibit system recovery
    (event.category == "process" AND host.name IN ("SHIP-NAV-CONSOLE", "PLC-PROD-LINE-A", "10.100.50.10") AND (
      (process.name IN ("vssadmin.exe", "vssadmin") AND process.command_line LIKE "*delete*shadows*") OR
      (process.name IN ("wbadmin.exe", "wbadmin") AND process.command_line LIKE "*delete*catalog*") OR
      (process.name IN ("bcdedit.exe", "bcdedit") AND process.command_line LIKE "*recoveryenabled*no*")
    ))
    OR
    -- Part 2: Detect creation of ransom note files
    (event.category == "file" AND event.action == "creation" AND host.name IN ("SHIP-NAV-CONSOLE", "PLC-PROD-LINE-A", "10.100.50.10") AND
      file.name RLIKE "(?i)(readme\\.txt|decrypt.*\\.txt|recover.*\\.txt|help.*\\.txt)")
  )
| EVAL Activity = CASE(
    event.category == "process", "Inhibit System Recovery",
    event.category == "file", CONCAT("Ransom Note Created: ", file.name)
  ),
  SuspiciousEntity = COALESCE(process.command_line, file.name),
  AccountName = user.name,
  DeviceName = host.name
| STATS StartTime = MIN(@timestamp), EndTime = MAX(@timestamp), Activities = VALUES(Activity), SuspiciousEntities = VALUES(SuspiciousEntity) BY AccountName, DeviceName
| EVAL StartTime = TO_STRING(StartTime), EndTime = TO_STRING(EndTime)
| EVAL RuleTitle = "Potential Ransomware Activity on IT/OT System",
       Description = CONCAT("Potential ransomware activity detected on critical system '", DeviceName, "' by account '", COALESCE(AccountName, "N/A"), "'. Observed activities: ", MVJOIN(Activities, "; "), ".")
| KEEP RuleTitle, StartTime, EndTime, DeviceName, AccountName, Activities, SuspiciousEntities, Description
-- Potential False Positives:
-- Legitimate admin activity may trigger shadow copy deletion logic.
-- Example: | WHERE NOT (AccountName IN ("admin1", "backup_admin"))
```
---
```sql
-- Rule Title: Suspicious Child Process of ICS/OT Application
-- Description: Detects suspicious child processes (e.g., command shells, scripting engines) spawned by known ICS/OT application processes, indicating potential post-exploitation activity.
-- Author: RW
-- Date: 2025-08-17
-- References: https://cybersecuritynews.com/cisa-releases-six-ics-advisories/, https://foxguardsolutions.com/blog/ics-patch-update-february-2024/, https://cyble.com/blog/latest-ics-vulnerabilities/
-- False Positive Sensitivity: Medium
-- Tags: ICS, OT, Maritime, Exploitation, Post-Exploitation
-- Rule: Requires process creation events with ECS fields.

FROM *
| WHERE event.category == "process" AND
  process.parent.name IN ("UAGRoot.exe", "Vijeo-Designer.exe", "Citect32.exe", "StruxureWare.exe", "PowerSCADA.exe", "s7oiehsx.exe", "CCMyAsserver.exe", "WinCCExplorer.exe", "S7tgtopx.exe", "mySCADA.exe", "myPRO.exe", "AdvDsopc.exe", "AdvAeSrv.exe", "RSLinx.exe", "FTView.exe", "LogixDesigner.exe") AND
  process.name IN ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe", "certutil.exe", "rundll32.exe", "sh.exe", "bash.exe")
| STATS StartTime = MIN(@timestamp), EndTime = MAX(@timestamp), SuspiciousChildProcess = VALUES(process.name), SuspiciousChildProcessCommandLine = VALUES(process.command_line), AccountName = VALUES(user.name) BY host.name, process.parent.name
| EVAL StartTime = TO_STRING(StartTime), EndTime = TO_STRING(EndTime)
| RENAME host.name AS DeviceName, process.parent.name AS InitiatingProcessFileName
| EVAL RuleTitle = "Suspicious Child Process of ICS/OT Application",
       Description = CONCAT("A known ICS/OT process '", InitiatingProcessFileName, "' on host '", DeviceName, "' spawned a suspicious child process: ", MVJOIN(SuspiciousChildProcess, ", "), ". This may indicate exploitation of a vulnerability in the ICS software.")
| KEEP RuleTitle, StartTime, EndTime, DeviceName, InitiatingProcessFileName, AccountName, SuspiciousChildProcess, SuspiciousChildProcessCommandLine, Description
-- Potential False Positives:
-- Legitimate administrative or automated scripts may trigger alerts.
-- Example: | WHERE NOT (SuspiciousChildProcessCommandLine LIKE "%known_safe_script%")
```
---
```sql
-- Rule Title: Suspicious Process Spawned by User-Facing Application
-- Description: Detects suspicious child processes (e.g., command shells, scripting engines) spawned by user-facing applications, indicating potential phishing or social engineering attacks.
-- Author: RW
-- Date: 2025-08-17
-- References: https://www.porttechnology.org/news/maritime-cybersecurity-threats-and-challenges/
-- False Positive Sensitivity: Medium
-- Tags: ICS, OT, Maritime, Phishing, Social Engineering
-- Rule: Requires process creation events with ECS fields.

FROM *
| WHERE event.category == "process" AND
  process.parent.name IN ("outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe", "acrord32.exe", "acrordr32.exe", "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe") AND
  process.name IN ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe")
| WHERE NOT (process.name == "rundll32.exe" AND process.command_line RLIKE "rundll32\\.exe\\s*\"?C:\\\\Windows\\\\System32") AND
        NOT (process.name == "cmd.exe" AND process.command_line RLIKE "cmd\\.exe\\s*/c\\s+exit")
| STATS StartTime = MIN(@timestamp), EndTime = MAX(@timestamp), ParentProcesses = VALUES(process.parent.name), SuspiciousChildProcesses = VALUES(process.name), SuspiciousCommandLines = VALUES(process.command_line) BY host.name, user.name
| EVAL StartTime = TO_STRING(StartTime), EndTime = TO_STRING(EndTime)
| RENAME host.name AS DeviceName, user.name AS AccountName
| EVAL RuleTitle = "Suspicious Process Spawned by User-Facing Application",
       Description = CONCAT("A user-facing application (", MVJOIN(ParentProcesses, ", "), ") spawned a suspicious child process (", MVJOIN(SuspiciousChildProcesses, ", "), ") on host '", DeviceName, "' by user '", COALESCE(AccountName, "N/A"), "'. This is a strong indicator of a successful phishing attempt.")
| KEEP RuleTitle, StartTime, EndTime, DeviceName, AccountName, ParentProcesses, SuspiciousChildProcesses, SuspiciousCommandLines, Description
-- Potential False Positives:
-- Legitimate add-ins, macros, or "open with" actions may trigger alerts.
-- Example: | WHERE NOT (SuspiciousCommandLines LIKE "%known_safe_macro%")
```
---
```sql
-- Rule Title: ICS Operational Deviation Detected
-- Description: Detects potential ICS manipulation by monitoring modifications to critical configuration files and high-risk commands in application logs.
-- Author: RW
-- Date: 2025-08-17
-- References: https://www.cisa.gov/news-events/ics-advisories/icsa-25-226-03
-- False Positive Sensitivity: Medium
-- Tags: ICS, OT, Maritime, Configuration Change, Unauthorized Command
-- Rule: Requires file and application log events with ECS fields.

FROM *
| WHERE (
    -- Part 1: Detect modifications to critical ICS configuration files
    (event.category == "file" AND (event.action IN ("creation", "modified", "rename")) AND
      file.name RLIKE "(?i)(\\.ACD|\\.L5K|\\.L5X|\\.S7P|\\.AP.*|\\.MCP|\\.XEF|\\.PCX|\\.STU|project\\.cfg|config\\.ini|backup\\.zip)" AND
      NOT (file.path RLIKE "(?i)\\\\Temp\\\\" OR file.path RLIKE "(?i)\\\\AppData\\\\Local\\\\"))
    OR
    -- Part 2: Detect high-risk commands in ICS application logs
    (event.dataset == "ics_logs" AND event.message RLIKE "(?i)(STOP_PROCESS|EMERGENCY_SHUTDOWN|SETPOINT_OVERRIDE|DOWNLOAD_PROJECT|Forcing I/O|Controller mode change|Logic Download|Firmware Update)")
  )
| EVAL activity = CASE(
    event.category == "file", CONCAT("ICS Config File Modified: ", file.name),
    event.dataset == "ics_logs", CONCAT("Critical OT Command Detected: ", event.message)
  ),
  user = COALESCE(user.name, event.user),
  dest = COALESCE(host.name, event.host)
| STATS start_time = MIN(@timestamp), end_time = MAX(@timestamp), Activities = VALUES(activity), Accounts = VALUES(user) BY dest
| EVAL start_time = TO_STRING(start_time), end_time = TO_STRING(end_time)
| RENAME dest AS DeviceName
| EVAL RuleTitle = "ICS Operational Deviation Detected",
       Description = CONCAT("Potential ICS operational deviation detected on host '", DeviceName, "'. This may indicate unauthorized configuration changes or commands. Observed activities: ", MVJOIN(Activities, "; "))
| KEEP RuleTitle, start_time AS StartTime, end_time AS EndTime, DeviceName, Accounts, Activities, Description
-- Potential False Positives:
-- Legitimate maintenance or updates may trigger alerts.
-- Example: | WHERE NOT (Accounts IN ("maintenance_user", "ot_engineer"))
```