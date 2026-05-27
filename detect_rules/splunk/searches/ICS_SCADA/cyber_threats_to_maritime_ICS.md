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
-- - This detection is highly dependent on the accurate and complete definition of the `ics_networks` and `authorized_sources` macros.
-- - Legitimate but unlisted systems (e.g., new administrative workstations, temporary vendor access) communicating with the ICS network will trigger alerts.
-- - Recommendation: Ensure the macros are populated correctly. For large lists, have the macros use a lookup file for better performance and manageability.
-- Detection Comment Level: Medium
-- How to implement the macros:
-- 1. In Splunk, go to Settings -> Advanced search -> Search macros.
-- 2. Create a new macro named `ics_networks` and define it. Example definition: `("192.168.1.0/24" OR "10.100.0.0/16")`
-- 3. Create a new macro named `authorized_sources` and define it. Example definition: `("172.16.1.10" OR "172.16.2.0/24")`

-- Start with CIM-compliant network traffic data.
`cim_Network_Traffic_v1_1_0`
| `comment("Define boolean fields based on whether IPs match the defined macros.")`
| eval is_src_ics = if(cidrmatch(`ics_networks`, src_ip), 1, 0)
| eval is_dest_ics = if(cidrmatch(`ics_networks`, dest_ip), 1, 0)
| eval is_src_authorized = if(cidrmatch(`authorized_sources`, src_ip), 1, 0)
| eval is_dest_authorized = if(cidrmatch(`authorized_sources`, dest_ip), 1, 0)

| `comment("Core detection logic: Identify traffic crossing the IT/OT boundary from/to an unauthorized source.")`
| where
    -- Case 1: Traffic from an external, unauthorized source INTO the ICS network.
    (is_dest_ics=1 AND is_src_ics=0 AND is_src_authorized=0)
    OR
    -- Case 2: Traffic FROM the ICS network to an external, unauthorized destination.
    (is_src_ics=1 AND is_dest_ics=0 AND is_dest_authorized=0)

| `comment("Summarize events to reduce alert volume and provide a concise overview.")`
| stats earliest(_time) as start_time, latest(_time) as end_time, values(dest_port) as dest_ports, values(action) as actions, count by src_ip, dest_ip, user
| `ctime(start_time)`
| `ctime(end_time)`

| `comment("Format the output for clear and actionable alerting.")`
| rename src_ip as SourceIp, dest_ip as DestinationIp, dest_ports as DestinationPorts, user as User, actions as Actions, count as TotalEvents, start_time as StartTime, end_time as EndTime
| eval RuleTitle = "Unusual ICS Network Traffic"
| eval Description = "Unauthorized network traffic detected between " + SourceIp + " and " + DestinationIp + ". This could indicate an unauthorized access attempt or policy violation involving the ICS/OT network."
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
-- - The effectiveness of this rule is highly dependent on the accurate population of the `ot_systems` macro. Without it, the rule will not fire.
-- - Legitimate administrative activity could potentially trigger the shadow copy deletion logic. Consider adding authorized admin accounts to an exclusion list within the search if needed.
-- - The `ransom_note_patterns` macro should be reviewed and customized for your environment and the latest threats.
-- Detection Comment Level: Medium
-- How to implement the macros:
-- 1. In Splunk, go to Settings -> Advanced search -> Search macros.
-- 2. Create a new macro named `ot_systems` and define it with your critical asset hostnames/IPs.
--    Example definition: `(host="SHIP-NAV-CONSOLE" OR host="PLC-PROD-LINE-A" OR host="10.100.50.10")`
-- 3. Create a new macro named `inhibit_recovery_commands` for the process logic.
--    Example definition: `((Processes.process_name IN ("vssadmin.exe","vssadmin") AND Processes.process="*delete*" AND Processes.process="*shadows*") OR (Processes.process_name IN ("wbadmin.exe","wbadmin") AND Processes.process="*delete*" AND Processes.process="*catalog*") OR (Processes.process_name IN ("bcdedit.exe","bcdedit") AND Processes.process="*recoveryenabled*no*"))`
-- 4. Create a new macro named `ransom_note_patterns` for the file name logic.
--    Example definition: `(Filesystem.file_name="*readme.txt" OR Filesystem.file_name="*decrypt*.txt" OR Filesystem.file_name="*recover*.txt" OR Filesystem.file_name="*help*.txt")`

-- Find processes that attempt to inhibit system recovery.
| tstats `summariesonly` count from datamodel=Endpoint.Processes where `ot_systems` AND `inhibit_recovery_commands` by _time, Processes.process, Processes.user, Processes.host
| rename Processes.process as SuspiciousEntity, Processes.user as AccountName, Processes.host as DeviceName
| eval Activity="Inhibit System Recovery"

-- Append file creation events that match known ransom note patterns.
| append [
    | tstats `summariesonly` count from datamodel=Endpoint.Filesystem where `ot_systems` AND Filesystem.action=created AND `ransom_note_patterns` by _time, Filesystem.file_name, Filesystem.user, Filesystem.host
    | rename Filesystem.file_name as SuspiciousEntity, Filesystem.user as AccountName, Filesystem.host as DeviceName
    | eval Activity="Ransom Note Created: " + SuspiciousEntity
]

-- Summarize alerts to reduce noise, grouping by the affected device and account.
| stats earliest(_time) as StartTime, latest(_time) as EndTime, values(Activity) as Activities, values(SuspiciousEntity) as SuspiciousEntities by AccountName, DeviceName
| `ctime(StartTime)`
| `ctime(EndTime)`

-- Format the final alert output.
| eval RuleTitle = "Potential Ransomware Activity on IT/OT System"
| eval Description = "Potential ransomware activity detected on critical system '" + DeviceName + "' by account '" + coalesce(AccountName, "N/A") + "'. Observed activities: " + mvjoin(Activities, "; ") + "."
| fields RuleTitle, StartTime, EndTime, DeviceName, AccountName, Activities, SuspiciousEntities, Description
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
-- - It is crucial to tune the 'ics_parent_processes' and 'suspicious_child_processes' macros to match the specific software and administrative tools used in your environment.
-- - Consider adding exclusions for known administrative scripts or specific command lines if they are part of normal operations.
-- Detection Comment Level: Medium
-- How to implement the macros:
-- 1. In Splunk, go to Settings -> Advanced search -> Search macros.
-- 2. Create a new macro named `ics_parent_processes` and define it with the process names of your ICS software.
--    Example definition: `(Processes.parent_process_name IN ("UAGRoot.exe", "Vijeo-Designer.exe", "Citect32.exe", "StruxureWare.exe", "PowerSCADA.exe", "s7oiehsx.exe", "CCMyAsserver.exe", "WinCCExplorer.exe", "S7tgtopx.exe", "mySCADA.exe", "myPRO.exe", "AdvDsopc.exe", "AdvAeSrv.exe", "RSLinx.exe", "FTView.exe", "LogixDesigner.exe"))`
-- 3. Create a new macro named `suspicious_child_processes` and define it with suspicious process names.
--    Example definition: `(Processes.process_name IN ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe", "certutil.exe", "rundll32.exe", "sh.exe", "bash.exe"))`

| tstats `summariesonly` count from datamodel=Endpoint.Processes where `ics_parent_processes` AND `suspicious_child_processes` by _time, Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
`comment("Summarize the findings to create a concise alert.")`
| stats
    earliest(_time) as StartTime,
    latest(_time) as EndTime,
    values(Processes.process_name) as SuspiciousChildProcess,
    values(Processes.process) as SuspiciousChildProcessCommandLine,
    values(Processes.user) as AccountName
    by Processes.dest, Processes.parent_process_name
| `ctime(StartTime)`
| `ctime(EndTime)`

`comment("Format the final alert output.")`
| rename Processes.dest as DeviceName, Processes.parent_process_name as InitiatingProcessFileName
| eval RuleTitle = "Suspicious Child Process of ICS/OT Application"
| eval Description = "A known ICS/OT process '" . InitiatingProcessFileName . "' on host '" . DeviceName . "' spawned a suspicious child process: " . mvjoin(SuspiciousChildProcess, ", ") . ". This may indicate exploitation of a vulnerability in the ICS software."
| fields RuleTitle, StartTime, EndTime, DeviceName, InitiatingProcessFileName, AccountName, SuspiciousChildProcess, SuspiciousChildProcessCommandLine, Description
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
-- - Legitimate add-ins, macros, or "open with" actions can sometimes cause this behavior.
-- - The rule includes basic filtering to reduce noise, but environment-specific command lines may need to be excluded.
-- - For example, a legitimate software installer launched from a browser might trigger this. Tuning may be required to exclude known good parent-child process relationships or command lines.
-- Detection Comment Level: Medium
-- How to implement the macros:
-- 1. In Splunk, go to Settings -> Advanced search -> Search macros.
-- 2. Create a new macro named `user_facing_parent_processes` and define it with the process names of common user-facing applications.
--    Example definition: `(Processes.parent_process_name IN ("outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe", "acrord32.exe", "acrordr32.exe", "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe"))`
-- 3. Create a new macro named `suspicious_initial_access_child_processes` and define it with suspicious child process names.
--    Example definition: `(Processes.process_name IN ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"))`

| tstats `summariesonly` count from datamodel=Endpoint.Processes where `user_facing_parent_processes` AND `suspicious_initial_access_child_processes` by _time, Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
`comment("FP Reduction: Filter out some potentially benign rundll32 and cmd.exe executions.")`
| where NOT (Processes.process_name="rundll32.exe" AND match(Processes.process, "rundll32\.exe\s*\"?C:\\Windows\\System32"))
| where NOT (Processes.process_name="cmd.exe" AND match(Processes.process, "cmd\.exe\s*\/c\s+exit"))

`comment("Summarize the findings to create a concise alert.")`
| stats
    earliest(_time) as StartTime,
    latest(_time) as EndTime,
    values(Processes.parent_process_name) as ParentProcesses,
    values(Processes.process_name) as SuspiciousChildProcesses,
    values(Processes.process) as SuspiciousCommandLines
    by Processes.dest, Processes.user
| `ctime(StartTime)`
| `ctime(EndTime)`

`comment("Format the final alert output.")`
| rename Processes.dest as DeviceName, Processes.user as AccountName
| eval RuleTitle = "Suspicious Process Spawned by User-Facing Application"
| eval Description = "A user-facing application (" . mvjoin(ParentProcesses, ", ") . ") spawned a suspicious child process (" . mvjoin(SuspiciousChildProcesses, ", ") . ") on host '" . DeviceName . "' by user '" . coalesce(AccountName, "N/A") . "'. This is a strong indicator of a successful phishing attempt."
| fields RuleTitle, StartTime, EndTime, DeviceName, AccountName, ParentProcesses, SuspiciousChildProcesses, SuspiciousCommandLines, Description
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
-- - The rule's effectiveness is highly dependent on the accurate and comprehensive population of the `ics_config_files` and `critical_ot_commands` macros. These must be tailored to your specific ICS/OT environment.
-- - The application log portion of this rule requires that ICS/OT application logs are being ingested into your SIEM and are properly parsed with CIM-compliant field names.
-- Detection Comment Level: Medium
-- How to implement the macros:
-- 1. In Splunk, go to Settings -> Advanced search -> Search macros.
-- 2. Create a new macro named `ics_config_files` and define it with your critical file types.
--    Example definition: `(Filesystem.file_name IN ("*.ACD", "*.L5K", "*.L5X", "*.S7P", "*.AP*", "*.MCP", "*.XEF", "*.PCX", "*.STU", "*project.cfg", "*config.ini", "*backup.zip"))`
-- 3. Create a new macro named `critical_ot_commands` and define it with high-risk command keywords.
--    Example definition: `("STOP_PROCESS" OR "EMERGENCY_SHUTDOWN" OR "SETPOINT_OVERRIDE" OR "DOWNLOAD_PROJECT" OR "Forcing I/O" OR "Controller mode change" OR "Logic Download" OR "Firmware Update")`

`comment("Part 1: Detect modifications to critical ICS configuration files using the Endpoint data model.")`
| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where `ics_config_files` AND (Filesystem.action=created OR Filesystem.action=modified OR Filesystem.action=renamed) by _time, Filesystem.dest, Filesystem.user, Filesystem.file_name, Filesystem.file_path
| `comment("FP Reduction: Exclude temporary files created by legitimate applications if they cause noise.")`
| where NOT (match(Filesystem.file_path, "(?i)\\\\Temp\\\\") OR match(Filesystem.file_path, "(?i)\\\\AppData\\\\Local\\\\"))
| `comment("Format data for aggregation.")`
| rename Filesystem.dest as dest, Filesystem.user as user
| eval activity = "ICS Config File Modified: " + Filesystem.file_name
| fields _time, dest, user, activity

| `comment("Part 2: Detect high-risk commands in ingested ICS application logs.")`
| append [
    `comment("Replace 'index=ics_logs' with the actual index/sourcetype for your ICS application logs.")`
    | search index=ics_logs `critical_ot_commands`
    `comment("The fields 'user' and 'dest' should be mapped to your log source's user and host fields respectively (e.g., rename UserName as user).")`
    | eval activity = "Critical OT Command Detected: " + _raw
    | fields _time, dest, user, activity
]

| `comment("Combine findings and create a concise alert for each affected device.")`
| stats earliest(_time) as start_time, latest(_time) as end_time, values(activity) as Activities, values(user) as Accounts by dest
| `ctime(start_time)`
| `ctime(end_time)`
| rename dest as DeviceName

| `comment("Format the final alert output.")`
| eval RuleTitle = "ICS Operational Deviation Detected"
| eval Description = "Potential ICS operational deviation detected on host '" + DeviceName + "'. This may indicate unauthorized configuration changes or commands. Observed activities: " + mvjoin(Activities, "; ")
| fields RuleTitle, start_time, end_time, DeviceName, Accounts, Activities, Description
```