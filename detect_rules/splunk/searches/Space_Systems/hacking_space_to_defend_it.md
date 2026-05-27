### Hacking Space to Defend It
---

This report summarizes the Aerospace Corporation's efforts in developing the Space Attack Research & Tactic Analysis (SPARTA) framework and associated Indicators of Behavior (IOBs) to enhance cybersecurity for spacecraft and space systems. The core takeaway is the shift from traditional Indicators of Compromise (IOCs) to behavior-based detection for proactive threat identification in the unique space domain.

SPARTA v3.0, launched in April 2025, introduces a comprehensive set of ~200 Indicators of Behavior (IOBs) specifically designed for onboard spacecraft activity, a significant advancement beyond traditional ground-system focused cybersecurity frameworks. This development is noteworthy as it addresses a critical gap in space cybersecurity by enabling proactive detection of suspicious activities and emerging threats directly on the spacecraft, rather than relying solely on post-compromise indicators.

### Actionable Threat Data
---

Unauthorized and Anomalous Command Execution (UACE): Monitor for hardware commands executed outside predefined authorized time windows or deviations from established baseline configurations. This includes detecting commands that reconfigure system components or legitimate commands with malicious parameters exceeding safe thresholds for subsystems like power distribution or attitude control.

GNSS and Time Manipulation Threats (GNTM): Detect unexpected and large time deltas, GNSS jamming, spoofing, or time desynchronization attempts that could threaten navigation accuracy and mission synchronization.

Spacecraft Memory Integrity and Resource Exploitation (MIRE): Look for memory corruption, unauthorized access, or resource exhaustion that could degrade performance or introduce malicious code. This includes monitoring for abnormal process forking leading to resource exhaustion or system freezes/crashes after high resource consumption.

Software Integrity and Unauthorized Updates (SIUU): Identify unauthorized flight software changes, unvalidated updates, or firmware tampering that may introduce backdoors or disrupt operations. This includes detecting invalid digital signatures in on-orbit update packages or unscheduled software updates.

Data Integrity and Storage Exploitation (DISE): Monitor file systems and storage for corruption, unauthorized deletions, or data manipulation that threaten mission data and continuity. This includes detecting file or data integrity check failures, unusual file encryption activity, or suspicious activity leading to storage exhaustion.

### Search
---
```sql
-- Name: Unauthorized or Anomalous Command Execution (SPARTA UACE)
-- Author: RW
-- Date: 2025-08-15
-- Description: Detects the execution of commands that may reconfigure system components or alter security settings, aligned with the SPARTA UACE threat pattern. Such activity could indicate unauthorized access or system compromise.
-- References:
-- - https://medium.com/the-aerospace-corporation/indicators-of-behavior-iobs-in-sparta-v3-0-c42ab0683100
-- - https://sparta.aerospace.org/related-work/iob
-- Tactic: Defense Evasion, Persistence, Execution
-- Technique: T1562, T1543, T1059
-- False Positive Sensitivity: Medium

`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("sc.exe", "netsh.exe", "reg.exe", "bcdedit.exe", "wevtutil.exe", "wmic.exe", "fsutil.exe", "systemctl", "service", "iptables", "ufw", "sysctl", "chmod", "chown", "setfacl", "sestatus", "setenforce") OR (Processes.process_name IN ("powershell.exe", "pwsh.exe") AND (Processes.process="*Set-MpPreference*" OR Processes.process="*DisableRealtimeMonitoring*" OR Processes.process="*New-NetFirewallRule*" OR Processes.process="*Set-NetFirewallRule*" OR Processes.process="*Set-ItemProperty -Path \"HKLM:*"))) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name("Processes")`
-- FP Mitigation: Exclude common legitimate parent processes and system accounts.
-- This list should be customized to your environment.
| where NOT (parent_process IN ("MsMpEng.exe", "System", "services.exe", "svchost.exe", "TiWorker.exe") OR user IN ("SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE", "root"))
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process, process_name, process

---

-- Name: System Time Manipulation (SPARTA GNTM)
-- Author: RW
-- Date: 2025-08-15
-- Description: Aligned with the SPARTA GNTM (GNSS and Time Manipulation Threats) pattern, this rule detects processes used to manually change the system time. Adversaries may manipulate system time to disrupt time-sensitive operations or affect log timestamps for evasion.
-- References:
-- - https://medium.com/the-aerospace-corporation/indicators-of-behavior-iobs-in-sparta-v3-0-c42ab0683100
-- - https://sparta.aerospace.org/related-work/iob
-- Tactic: Defense Evasion
-- Technique: T1562.001
-- False Positive Sensitivity: Medium

`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.process_name="net.exe" AND Processes.process="* time *" AND Processes.process="* /set*") OR (Processes.process_name IN ("powershell.exe", "pwsh.exe") AND Processes.process="*Set-Date*") OR (Processes.process_name="w32tm.exe" AND Processes.process="*/resync*") OR (Processes.process_name="date" AND (Processes.process="* -s *" OR Processes.process="* --set *")) OR (Processes.process_name="timedatectl" AND Processes.process="* set-time *") OR (Processes.process_name="hwclock" AND (Processes.process="* --set *" OR Processes.process="* --systohc *")) OR (Processes.process_name="ntpdate")) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name("Processes")`
-- FP Mitigation: Legitimate time changes are often performed by high-privileged system accounts or specific services.
| where NOT (user IN ("SYSTEM", "LOCAL SERVICE", "root") AND parent_process IN ("svchost.exe", "services.exe", "chronyd", "ntpd"))
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process, process_name, process

---

-- Name: Memory and Resource Exploitation (SPARTA MIRE) - Part 1: Memory Dumping
-- Author: RW
-- Date: 2025-08-15
-- Description: Aligned with the SPARTA MIRE pattern, this rule detects memory dumping of sensitive processes like LSASS.
-- References:
-- - https://medium.com/the-aerospace-corporation/indicators-of-behavior-iobs-in-sparta-v3-0-c42ab0683100
-- - https://sparta.aerospace.org/related-work/iob
-- Tactic: Credential Access
-- Technique: T1003.001
-- False Positive Sensitivity: Medium

`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="procdump.exe" AND Processes.process="*lsass*") OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs.dll*" AND Processes.process="*MiniDump*" AND Processes.process="*lsass*") OR (Processes.process_name IN ("powershell.exe", "pwsh.exe") AND (Processes.process="*Out-Minidump*" OR (Processes.process="*Get-Process*" AND Processes.process="*lsass*"))) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name("Processes")`
-- FP Mitigation: Some security tools or crash dump utilities may perform this action legitimately. Exclude them by parent process name.
| where NOT parent_process IN ("Sysmon.exe", "MsMpEng.exe")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process, process_name, process

---

-- Name: Memory and Resource Exploitation (SPARTA MIRE) - Part 2: Resource Exhaustion
-- Author: RW
-- Date: 2025-08-15
-- Description: Aligned with the SPARTA MIRE pattern, this rule detects potential "fork bomb" activity where a process rapidly creates numerous child processes to exhaust system resources.
-- References:
-- - https://medium.com/the-aerospace-corporation/indicators-of-behavior-iobs-in-sparta-v3-0-c42ab0683100
-- - https://sparta.aerospace.org/related-work/iob
-- Tactic: Impact
-- Technique: T1499.003
-- False Positive Sensitivity: Medium

`tstats` dc(Processes.process_id) as child_process_count from datamodel=Endpoint.Processes where Processes.parent_process_id!=0 by _time span=1m Processes.dest Processes.user Processes.parent_process Processes.parent_process_id
| `drop_dm_object_name("Processes")`
| where child_process_count > 100
-- FP Mitigation: Exclude common software installers and updaters that can be noisy.
| where NOT parent_process IN ("setup.exe", "installer.exe", "update.exe", "msiexec.exe", "TiWorker.exe", "GoogleUpdate.exe")
| `security_content_ctime(_time)`
| rename _time as time
| table time, dest, user, parent_process, parent_process_id, child_process_count

---

-- Name: Unauthorized Software/Firmware Update (SPARTA SIUU)
-- Author: RW
-- Date: 2025-08-15
-- Description: Aligned with the SPARTA SIUU pattern, this rule detects the execution of unsigned software or loading of unsigned drivers, which could indicate the introduction of malicious code.
-- References:
-- - https://medium.com/the-aerospace-corporation/indicators-of-behavior-iobs-in-sparta-v3-0-c42ab0683100
-- - https://sparta.aerospace.org/related-work/iob
-- Tactic: Persistence, Privilege Escalation, Defense Evasion
-- Technique: T1553.002
-- False Positive Sensitivity: Medium

`tstats` count from datamodel=Endpoint.Processes where Processes.signature_status="unsigned" AND Processes.process_name="*.exe" AND (Processes.process_path IN ("*\\Windows\\Temp\\*", "*\\PerfLogs\\*", "*\\AppData\\Local\\Temp*", "*\\Users\\Public\\*", "*\\Downloads\\*") OR Processes.process_name IN ("*install*", "*setup*", "*update*", "*patch*", "*hotfix*")) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process_path Processes.process
| `drop_dm_object_name("Processes")`
-- FP Mitigation: Exclude known legitimate but unsigned applications. This list is critical for tuning.
| where NOT (process_name IN ("putty.exe", "7z.exe") OR parent_process IN ("sccm.exe", "Choco.exe"))
| `security_content_ctime(_time)`
| rename _time as time
| table time, dest, user, parent_process, process_name, process_path, process

---

-- Name: Data Integrity and Storage Exploitation (SPARTA DISE) - Part 1: System Recovery Inhibition
-- Author: RW
-- Date: 2025-08-15
-- Description: Aligned with the SPARTA DISE pattern, this rule detects deletion of volume shadow copies or clearing of critical event logs to inhibit system recovery and cover tracks.
-- References:
-- - https://medium.com/the-aerospace-corporation/indicators-of-behavior-iobs-in-sparta-v3-0-c42ab0683100
-- - https://sparta.aerospace.org/related-work/iob
-- Tactic: Impact, Defense Evasion
-- Technique: T1490, T1070.001
-- False Positive Sensitivity: Medium

`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="vssadmin.exe" AND Processes.process="*delete*" AND Processes.process="*shadows*") OR (Processes.process_name="wevtutil.exe" AND (Processes.process="*clear-log*" OR Processes.process="*cl*")) OR (Processes.process_name IN ("powershell.exe", "pwsh.exe") AND Processes.process="*Clear-EventLog*") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name("Processes")`
-- FP Mitigation: Exclude known administrative scripts or system maintenance activities.
| where NOT parent_process IN ("sccm.exe", "tanium.exe")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process, process_name, process

---

-- Name: Data Integrity and Storage Exploitation (SPARTA DISE) - Part 2: Mass File Deletion/Modification
-- Author: RW
-- Date: 2025-08-15
-- Description: Aligned with the SPARTA DISE pattern, this rule detects mass file modification or renaming indicative of ransomware or wiper malware.
-- References:
-- - https://medium.com/the-aerospace-corporation/indicators-of-behavior-iobs-in-sparta-v3-0-c42ab0683100
-- - https://sparta.aerospace.org/related-work/iob
-- Tactic: Impact
-- Technique: T1485, T1486
-- False Positive Sensitivity: Medium

`tstats` count as ActivityCount, dc(Filesystem.file_path) as DistinctFolders from datamodel=Endpoint.Filesystem where Filesystem.action IN ("renamed", "modified") by _time span=5m Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process
| `drop_dm_object_name("Filesystem")`
| where ActivityCount > 200 AND DistinctFolders > 3
-- FP Mitigation: Exclude common system processes, software installers, and backup tools. This list requires tuning.
| where NOT process_name IN ("svchost.exe", "TiWorker.exe", "MsMpEng.exe", "setup.exe", "msiexec.exe", "SearchIndexer.exe")
| `security_content_ctime(_time)`
| rename _time as time
| table time, dest, user, process_name, process, ActivityCount, DistinctFolders
```