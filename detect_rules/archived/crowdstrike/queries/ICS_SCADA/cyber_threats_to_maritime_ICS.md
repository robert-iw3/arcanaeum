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

-- Rule: Uses Falcon network events (NetworkConnectTCPv4, NetworkAcceptTCPv4). Filters for ICS network segments and unauthorized sources using IP ranges. Optimizes by aggregating over time and using early filtering for OT assets (e.g., via ComputerName regex).
event_simpleName IN ("NetworkConnectTCPv4", "NetworkAcceptTCPv4") ((LocalAddressIP4:/^(10.|192.168.|172.(1[6-9]|2[0-9]|3[0-1]).)/ AND !RemoteAddressIP4 IN ("172.16.1.10", "172.16.2.0/24")) OR (RemoteAddressIP4:/^(10.|192.168.|172.(1[6-9]|2[0-9]|3[0-1]).)/ AND !LocalAddressIP4 IN ("172.16.1.10", "172.16.2.0/24")))
| stats earliest(@timestamp) as StartTime latest(@timestamp) as EndTime values(RemotePort) as DestinationPorts values(event_simpleName) as Actions count by LocalAddressIP4 RemoteAddressIP4 LocalUserName
| rename LocalAddressIP4 as SourceIp RemoteAddressIP4 as DestinationIp LocalUserName as User
| eval RuleTitle="Unusual ICS Network Traffic" Description="Unauthorized network traffic detected between " + SourceIp + " and " + DestinationIp + ". This could indicate an unauthorized access attempt or policy violation involving the ICS/OT network."
| table RuleTitle StartTime EndTime SourceIp DestinationIp User DestinationPorts Actions count Description
-- Potential False Positives: New administrative workstations or vendor access not in the allowlist. Maintain dynamic allowlists (e.g., authorized IPs). Filter OT assets with +ComputerName:/(SHIP-NAV|PLC-PROD)/i for maritime systems.
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

-- Rule: Uses ProcessRollup2 for system recovery inhibition and FileWrite for ransom note detection. Filters for OT assets via ComputerName. Optimizes with specific command-line regex and file patterns.
event_platform=Win (
    (event_simpleName=ProcessRollup2 (
        (ImageFileName IN ("vssadmin.exe", "vssadmin") CommandLine=/delete.*shadows/i) OR
        (ImageFileName IN ("wbadmin.exe", "wbadmin") CommandLine=/delete.*catalog/i) OR
        (ImageFileName IN ("bcdedit.exe", "bcdedit") CommandLine=/recoveryenabled.*no/i)
    )
| eval Activity="Inhibit System Recovery" SuspiciousEntity=CommandLine)
| append [
        event_simpleName=FileWrite TargetFileName IN ("*readme.txt", "decrypt.txt", "recover.txt", "help.txt")
        | eval Activity="Ransom Note Created: " + TargetFileName SuspiciousEntity=TargetFileName
    ]
) +ComputerName:/(SHIP-NAV|PLC-PROD)/i
| stats earliest(@timestamp) as StartTime latest(@timestamp) as EndTime values(Activity) as Activities values(SuspiciousEntity) as SuspiciousEntities by LocalUserName ComputerName
| rename LocalUserName as AccountName ComputerName as DeviceName
| eval RuleTitle="Potential Ransomware Activity on IT/OT System" Description="Potential ransomware activity detected on critical system '" + DeviceName + "' by account '" + coalesce(AccountName, "N/A") + "'. Observed activities: " + mvjoin(Activities, "; ") + "."
| table RuleTitle StartTime EndTime DeviceName AccountName Activities SuspiciousEntities Description
-- Potential False Positives: Legitimate admin actions (e.g., vssadmin by backup tools). Exclude known admin accounts or tune ransom note patterns. Filter for maritime OT assets (e.g., +ComputerName:/(SHIP-NAV|PLC)/i).
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

-- Rule: Uses ProcessRollup2 with parent-child process relationships. Filters for ICS parent processes and suspicious children. Optimizes by excluding known benign parents and focusing on OT assets.
event_simpleName=ProcessRollup2 ParentBaseFileName IN ("UAGRoot.exe", "Vijeo-Designer.exe", "Citect32.exe", "StruxureWare.exe", "PowerSCADA.exe", "s7oiehsx.exe", "CCMyAsserver.exe", "WinCCExplorer.exe", "S7tgtopx.exe", "mySCADA.exe", "myPRO.exe", "AdvDsopc.exe", "AdvAeSrv.exe", "RSLinx.exe", "FTView.exe", "LogixDesigner.exe") ImageFileName IN ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe", "certutil.exe", "rundll32.exe", "sh.exe", "bash.exe") +ComputerName:/(SHIP-NAV|PLC-PROD)/i
| stats earliest(@timestamp) as StartTime latest(@timestamp) as EndTime values(ImageFileName) as SuspiciousChildProcess values(CommandLine) as SuspiciousChildProcessCommandLine values(LocalUserName) as AccountName by ComputerName ParentBaseFileName
| rename ComputerName as DeviceName ParentBaseFileName as InitiatingProcessFileName
| eval RuleTitle="Suspicious Child Process of ICS/OT Application" Description="A known ICS/OT process '" + InitiatingProcessFileName + "' on host '" + DeviceName + "' spawned a suspicious child process: " + mvjoin(SuspiciousChildProcess, ", ") + ". This may indicate exploitation of a vulnerability in the ICS software."
| table RuleTitle StartTime EndTime DeviceName InitiatingProcessFileName AccountName SuspiciousChildProcess SuspiciousChildProcessCommandLine Description
-- Potential False Positives: Legitimate admin scripts or automation. Exclude known benign parent-child pairs or tune suspicious child list. Focus on maritime OT assets (e.g., +ComputerName:/(SHIP-NAV|PLC)/i).
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

-- Rule: Uses ProcessRollup2 for parent-child relationships. Filters out benign rundll32/cmd executions. Optimizes with specific parent/child lists and OT asset filtering.
event_simpleName=ProcessRollup2 ParentBaseFileName IN ("outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe", "acrord32.exe", "acrordr32.exe", "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe") ImageFileName IN ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe") !CommandLine:/rundll32.exe\s*"?C:\Windows\System32/i !CommandLine:/cmd.exe\s*/c\s+exit/i
| stats earliest(@timestamp) as StartTime latest(@timestamp) as EndTime values(ParentBaseFileName) as ParentProcesses values(ImageFileName) as SuspiciousChildProcesses values(CommandLine) as SuspiciousCommandLines by ComputerName LocalUserName
| rename ComputerName as DeviceName LocalUserName as AccountName
| eval RuleTitle="Suspicious Process Spawned by User-Facing Application" Description="A user-facing application (" + mvjoin(ParentProcesses, ", ") + ") spawned a suspicious child process (" + mvjoin(SuspiciousChildProcesses, ", ") + ") on host '" + DeviceName + "' by user '" + coalesce(AccountName, "N/A") + "'. This is a strong indicator of a successful phishing attempt."
| table RuleTitle StartTime EndTime DeviceName AccountName ParentProcesses SuspiciousChildProcesses SuspiciousCommandLines Description
-- Potential False Positives: Legitimate add-ins, macros, or installers. Tune exclusions for specific command lines or parent-child pairs. Apply OT filter if targeting maritime systems (e.g., +ComputerName:/(SHIP-NAV|PLC)/i).
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

-- Rule: Uses FileWrite for config file changes and ProcessRollup2 for command execution. Approximates application log commands with process command lines. Filters for OT assets and excludes temp files.
event_platform=Win (
    (event_simpleName=FileWrite TargetFileName IN (".ACD", ".L5K", ".L5X", ".S7P", ".AP", ".MCP", ".XEF", ".PCX", ".STU", "*project.cfg", "*config.ini", "*backup.zip") !TargetFileName:/\(Temp|AppData\Local)\/i
    | eval activity="ICS Config File Modified: " + TargetFileName)
| append [
        event_simpleName=ProcessRollup2 CommandLine IN ("STOP_PROCESS", "EMERGENCY_SHUTDOWN", "SETPOINT_OVERRIDE", "DOWNLOAD_PROJECT", "Forcing I/O", "Controller mode change", "Logic Download", "Firmware Update")
        | eval activity="Critical OT Command Detected: " + CommandLine
    ]
) +ComputerName:/(SHIP-NAV|PLC-PROD)/i
| stats earliest(@timestamp) as start_time latest(@timestamp) as end_time values(activity) as Activities values(LocalUserName) as Accounts by ComputerName
| rename ComputerName as DeviceName
| eval RuleTitle="ICS Operational Deviation Detected" Description="Potential ICS operational deviation detected on host '" + DeviceName + "'. This may indicate unauthorized configuration changes or commands. Observed activities: " + mvjoin(Activities, "; ")
| table RuleTitle start_time end_time DeviceName Accounts Activities Description
-- Potential False Positives: Legitimate maintenance or updates. Correlate with planned work schedules. Tune file/command lists and filter for maritime OT assets (e.g., +ComputerName:/(SHIP-NAV|PLC)/i).
```