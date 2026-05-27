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

-- Data Source: Endpoint logs with process creation events (e.g., Sysmon Event ID 1 or spacecraft telemetry).
-- Query Strategy: Filter for processes executing system configuration commands, exclude legitimate system processes, and aggregate by host and user.
-- False Positive Tuning: Exclude known system accounts and parent processes.

logs(
  source:endpoint
  @host:(satellite* OR spacecraft*)
  (
    process.name:(sc.exe OR netsh.exe OR reg.exe OR bcdedit.exe OR wevtutil.exe OR wmic.exe OR fsutil.exe OR systemctl OR service OR iptables OR ufw OR sysctl OR chmod OR chown OR setfacl OR sestatus OR setenforce) OR
    (process.name:(powershell.exe OR pwsh.exe) AND process.command_line:(*Set-MpPreference* OR *DisableRealtimeMonitoring* OR *New-NetFirewallRule* OR *Set-NetFirewallRule* OR *Set-ItemProperty -Path \"HKLM:*))
  )
  -process.parent.name:(MsMpEng.exe OR System OR services.exe OR svchost.exe OR TiWorker.exe)
  -@user:(SYSTEM OR "NETWORK SERVICE" OR "LOCAL SERVICE" OR root)
)
| group by @host, @user, process.parent.name, process.name, process.command_line
| select
    min(@timestamp) as FirstTime,
    max(@timestamp) as LastTime,
    @host as Dest,
    @user as User,
    process.parent.name as ParentProcess,
    process.name as ProcessName,
    process.command_line as Process
| display FirstTime, LastTime, Dest, User, ParentProcess, ProcessName, Process
```
---
```sql
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

-- Data Source: Endpoint logs with process creation events.
-- Query Strategy: Filter for time manipulation commands, exclude legitimate system accounts, and aggregate by host and user.
-- False Positive Tuning: Exclude known time synchronization services.

logs(
  source:endpoint
  @host:(satellite* OR spacecraft*)
  (
    (process.name:net.exe AND process.command_line:(* time * AND * /set*)) OR
    (process.name:(powershell.exe OR pwsh.exe) AND process.command_line:*Set-Date*) OR
    (process.name:w32tm.exe AND process.command_line:*/resync*) OR
    (process.name:date AND process.command_line:(* -s * OR * --set *)) OR
    (process.name:timedatectl AND process.command_line:* set-time *) OR
    (process.name:hwclock AND process.command_line:(* --set * OR * --systohc *)) OR
    (process.name:ntpdate)
  )
  -@user:(SYSTEM OR "LOCAL SERVICE" OR root)
  -process.parent.name:(svchost.exe OR services.exe OR chronyd OR ntpd)
)
| group by @host, @user, process.parent.name, process.name, process.command_line
| select
    min(@timestamp) as FirstTime,
    max(@timestamp) as LastTime,
    @host as Dest,
    @user as User,
    process.parent.name as ParentProcess,
    process.name as ProcessName,
    process.command_line as Process
| display FirstTime, LastTime, Dest, User, ParentProcess, ProcessName, Process
```
---
```sql
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

-- Data Source: Endpoint logs with process creation events.
-- Query Strategy: Filter for memory dumping activities targeting sensitive processes, exclude legitimate tools, and aggregate by host and user.
-- False Positive Tuning: Exclude known security tools.

logs(
  source:endpoint
  @host:(satellite* OR spacecraft*)
  (
    (process.name:procdump.exe AND process.command_line:*lsass*) OR
    (process.name:rundll32.exe AND process.command_line:(*comsvcs.dll* AND *MiniDump* AND *lsass*)) OR
    (process.name:(powershell.exe OR pwsh.exe) AND process.command_line:(*Out-Minidump* OR (*Get-Process* AND *lsass*)))
  )
  -process.parent.name:(Sysmon.exe OR MsMpEng.exe)
)
| group by @host, @user, process.parent.name, process.name, process.command_line
| select
    min(@timestamp) as FirstTime,
    max(@timestamp) as LastTime,
    @host as Dest,
    @user as User,
    process.parent.name as ParentProcess,
    process.name as ProcessName,
    process.command_line as Process
| display FirstTime, LastTime, Dest, User, ParentProcess, ProcessName, Process
```
---
```sql
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

-- Data Source: Endpoint logs with process creation events.
-- Query Strategy: Identify processes with high child process counts, exclude legitimate installers, and aggregate by host and parent process.
-- False Positive Tuning: Exclude known noisy processes.

logs(
  source:endpoint
  @host:(satellite* OR spacecraft*)
  process.parent.id != 0
)
| group by @timestamp span=1m, @host, @user, process.parent.name, process.parent.id
| select
    @timestamp as Time,
    @host as Dest,
    @user as User,
    process.parent.name as ParentProcess,
    process.parent.id as ParentProcessId,
    count_distinct(process.id) as ChildProcessCount
| where ChildProcessCount > 100
| exclude process.parent.name:(setup.exe OR installer.exe OR update.exe OR msiexec.exe OR TiWorker.exe OR GoogleUpdate.exe)
| display Time, Dest, User, ParentProcess, ParentProcessId, ChildProcessCount
```
---
```sql
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

-- Data Source: Endpoint logs with process creation events.
-- Query Strategy: Filter for unsigned executables in suspicious paths, exclude known legitimate unsigned apps, and aggregate by host and user.
-- False Positive Tuning: Exclude legitimate unsigned applications.

logs(
  source:endpoint
  @host:(satellite* OR spacecraft*)
  process.signature_status:unsigned
  process.name:*.exe
  (
    process.path:(*\\Windows\\Temp\\* OR *\\PerfLogs\\* OR *\\AppData\\Local\\Temp* OR *\\Users\\Public\\* OR *\\Downloads\\*) OR
    process.name:(*install* OR *setup* OR *update* OR *patch* OR *hotfix*)
  )
  -process.name:(putty.exe OR 7z.exe)
  -process.parent.name:(sccm.exe OR Choco.exe)
)
| group by @host, @user, process.parent.name, process.name, process.path, process.command_line
| select
    @timestamp as Time,
    @host as Dest,
    @user as User,
    process.parent.name as ParentProcess,
    process.name as ProcessName,
    process.path as ProcessPath,
    process.command_line as Process
| display Time, Dest, User, ParentProcess, ProcessName, ProcessPath, Process
```
---
```sql
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

-- Data Source: Endpoint logs with process creation events.
-- Query Strategy: Filter for processes inhibiting system recovery, exclude administrative tools, and aggregate by host and user.
-- False Positive Tuning: Exclude known maintenance scripts.

logs(
  source:endpoint
  @host:(satellite* OR spacecraft*)
  (
    (process.name:vssadmin.exe AND process.command_line:(*delete* AND *shadows*)) OR
    (process.name:wevtutil.exe AND process.command_line:(*clear-log* OR *cl*)) OR
    (process.name:(powershell.exe OR pwsh.exe) AND process.command_line:*Clear-EventLog*)
  )
  -process.parent.name:(sccm.exe OR tanium.exe)
)
| group by @host, @user, process.parent.name, process.name, process.command_line
| select
    min(@timestamp) as FirstTime,
    max(@timestamp) as LastTime,
    @host as Dest,
    @user as User,
    process.parent.name as ParentProcess,
    process.name as ProcessName,
    process.command_line as Process
| display FirstTime, LastTime, Dest, User, ParentProcess, ProcessName, Process
```
---
```sql
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

-- Data Source: Endpoint logs with file modification events (e.g., Sysmon Event ID 11).
-- Query Strategy: Identify processes with high file modification counts across multiple folders, exclude legitimate processes, and aggregate by host and user.
-- False Positive Tuning: Exclude system processes and backup tools.

logs(
  source:endpoint
  @host:(satellite* OR spacecraft*)
  file.action:(renamed OR modified)
)
| group by @timestamp span=5m, @host, @user, process.name, process.command_line
| select
    @timestamp as Time,
    @host as Dest,
    @user as User,
    process.name as ProcessName,
    process.command_line as Process,
    count as ActivityCount,
    count_distinct(file.path) as DistinctFolders
| where ActivityCount > 200 AND DistinctFolders > 3
| exclude process.name:(svchost.exe OR TiWorker.exe OR MsMpEng.exe OR setup.exe OR msiexec.exe OR SearchIndexer.exe)
| display Time, Dest, User, ProcessName, Process, ActivityCount, DistinctFolders
```