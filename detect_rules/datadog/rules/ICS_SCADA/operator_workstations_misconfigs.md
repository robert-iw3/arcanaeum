### Secure Operator Workstation Escapes: A Review of Common Misconfigurations
---

This report summarizes common misconfigurations in "secure" operator workstations that allow for bypasses of security controls, emphasizing that "locked down" does not equate to "secure." It highlights that these vulnerabilities are often due to day-one misconfigurations rather than zero-day exploits, stressing the importance of validation and testing over mere deployment.

Recent intelligence continues to show that adversaries frequently exploit misconfigurations and weak security practices, such as the misuse of legitimate tools (LOLBins) and default credentials, rather than relying solely on novel exploits. This reinforces the presentation's core message that fundamental security hygiene and continuous validation are critical for effective defense.

### Actionable Threat Data

Monitor for the execution of renamed system binaries (e.g., cmd.exe renamed to alarms.exe) to bypass Group Policy Object (GPO) restrictions.

Detect the use of LOLBins (Living Off the Land Binaries) such as regsvr32, msbuild, and bitsadmin for purposes outside of their typical administrative functions, especially when allowlisting is in place.

Identify attempts to use shared or default local administrator credentials, which can indicate lateral movement or privilege escalation.

Analyze login script modifications or executions that expose sensitive information like drive paths, secrets, or provide unauthorized tool access.

Look for instances where signed tools are misused to perform malicious activities, as these often bypass traditional allowlisting alerts.

### Search
---
```sql
-- Name: Renamed System Binary Execution
-- Author: RW
-- Date: 2025-08-17

-- Adversaries may rename legitimate system utilities to execute them from non-standard paths.
-- This technique, often called Masquerading (T1036.003), can be used to bypass application control
-- solutions, such as AppLocker or GPOs, that are configured with path-based or name-based rules.
-- This query identifies when a process is launched with a filename that differs from its
-- internal "OriginalFileName" metadata, indicating it has been renamed.

-- Data Source: Endpoint logs with process creation events (e.g., Sysmon Event ID 1).
-- Query Strategy: Filter for processes with mismatched process.name and process.original_file_name, exclude system paths, and aggregate by host and user.
-- False Positive Tuning: Exclude known legitimate software paths.

logs(
  source:endpoint
  @host:(workstation* OR ops*)
  process.name:(cmd.exe OR powershell.exe OR pwsh.exe OR cscript.exe OR wscript.exe OR mshta.exe OR rundll32.exe OR regsvr32.exe OR bitsadmin.exe OR certutil.exe OR msiexec.exe)
  process.original_file_name != process.name
  -process.path:(C:\\Windows\\System32\\* OR C:\\Windows\\SysWOW64\\* OR C:\\Windows\\WinSxS\\*)
)
| group by @host, @user, process.parent.name, process.name, process.command_line, process.path
| select
    @host as Host,
    @user as User,
    process.parent.name as ParentProcess,
    process.name as OriginalFileName,
    process.command_line as ExecutedProcessName,
    process.path as ExecutionPath
| display Host, User, ParentProcess, OriginalFileName, ExecutedProcessName, ExecutionPath
```
---
```sql
-- Name: Suspicious LOLBin Execution
-- Author: RW
-- Date: 2025-08-17

-- Adversaries abuse legitimate "Living Off the Land Binaries" (LOLBins) to execute malicious code,
-- download payloads, or bypass application control. This can be difficult to detect as the binaries
-- themselves are trusted and signed by Microsoft. This rule identifies suspicious usage patterns
-- for commonly abused LOLBins like regsvr32, msbuild, and bitsadmin, as highlighted in the reference.

-- Data Source: Endpoint logs with process creation events.
-- Query Strategy: Filter for specific LOLBin patterns (e.g., regsvr32 with HTTP, msbuild from user-writable paths), aggregate by host and user.
-- False Positive Tuning: Exclude known legitimate updaters.

logs(
  source:endpoint
  @host:(workstation* OR ops*)
  (
    (process.name:regsvr32.exe */s* AND process.command_line:(*http:* OR *https:* OR *ftp:* OR *scrobj.dll*)) OR
    (process.name:msbuild.exe AND process.parent.path:(*\\Temp\\* OR *\\Users\\Public\\* OR *\\AppData\\Roaming\\* OR *\\ProgramData\\*)) OR
    (process.name:bitsadmin.exe */transfer* AND process.command_line:(*http:* OR *https:*))
  )
  -process.parent.name:(*GoogleUpdate.exe OR *AdobeARM.exe)
)
| group by @host, @user, process.name
| select
    min(@timestamp) as FirstTime,
    max(@timestamp) as LastTime,
    @host as Host,
    @user as User,
    process.name as LOLBin,
    values(process.parent.name) as ParentProcess,
    values(process.command_line) as CommandLine
| display FirstTime, LastTime, Host, User, LOLBin, ParentProcess, CommandLine
```
---
```sql
-- Name: Default or Shared Administrator Credential Usage
-- Author: RW
-- Date: 2025-08-17

-- Adversaries commonly leverage default or shared administrative credentials for initial access and lateral movement.
-- This rule detects two patterns of risky administrative logons:
-- 1. The use of the built-in administrator account (SID ending in -500), which often violates security policies.
-- 2. A single administrative account logging into an unusually high number of distinct hosts within a short timeframe,
--    which can indicate a compromised shared account or a widespread automated attack.

-- Data Source: Windows Security event logs (Event ID 4624).
-- Query Strategy: Filter for successful admin logons with specific logon types and token elevation, flag default admin SIDs or high host counts, and aggregate by user and time.
-- False Positive Tuning: Exclude known admin accounts.

logs(
  source:wineventlog
  event.code:4624
  event.outcome:success
  event.logon_type:(2 OR 3 OR 10)
  event.token_elevation_type:(%%1936 OR %%1937)
  -event.user:(*$ OR SYSTEM OR "LOCAL SERVICE" OR "NETWORK SERVICE" OR DWM-1 OR UMFD-1)
)
| group by @timestamp span=1h, event.user, event.user_id
| select
    min(@timestamp) as FirstTime,
    max(@timestamp) as LastTime,
    event.user as User,
    event.user_id as UserSid,
    count_distinct(event.dest) as DistinctHostCount,
    values(event.dest) as LogonHosts,
    case(
      event.user_id:*500 AND DistinctHostCount > 10, "Default Admin SID with Shared Behavior",
      event.user_id:*500, "Default Administrator SID Used",
      DistinctHostCount > 10, "Anomalous Shared Account Behavior"
    ) as DetectionMethod
| where event.user_id:*500 OR DistinctHostCount > 10
| exclude event.user:(AdminSvcAccount1 OR BackupAdmin)
| display FirstTime, LastTime, User, UserSid, DistinctHostCount, LogonHosts, DetectionMethod
```
---
```sql
-- Name: Login Script Abuse
-- Author: RW
-- Date: 2025-08-17

-- Adversaries may abuse login scripts for persistence or to execute malicious commands. This can involve
-- modifying existing scripts stored on a domain controller's SYSVOL share or embedding suspicious commands
-- that are executed when a user logs in. This rule detects both the modification of common login script
-- files in SYSVOL and the execution of suspicious child processes by the Group Policy script handler (gpscript.exe).

-- Data Source: Endpoint logs for file modifications and process creation events.
-- Query Strategy: Search for SYSVOL script modifications and suspicious gpscript.exe child processes, aggregate by host and user.
-- False Positive Tuning: Exclude legitimate GPO management tools and known script command lines.

-- Part 1: SYSVOL Login Script Modifications
logs(
  source:endpoint
  file.action:(created OR renamed)
  file.path:*\\SYSVOL\\*\\scripts\\*
  file.name:(*.bat OR *.cmd OR *.vbs OR *.ps1)
  -process.name:(gpmc.exe OR gpoadmin.exe OR dfsrc.exe)
)
| group by @timestamp, @host, @user, process.name, file.path, file.name
| select
    @timestamp as Time,
    @host as Host,
    @user as User,
    process.name as ParentProcess,
    "Login Script File Modified in SYSVOL" as DetectionMethod,
    file.name as SuspiciousProcess,
    "File '" + file.name + "' created/renamed in " + file.path as SuspiciousCommandLine

-- Part 2: Suspicious gpscript.exe Child Processes
| union(
  logs(
    source:endpoint
    process.parent.name:gpscript.exe
    process.name:(powershell.exe OR pwsh.exe OR cmd.exe OR cscript.exe OR wscript.exe OR whoami.exe OR net.exe OR net1.exe OR nltest.exe OR systeminfo.exe OR quser.exe OR qwinsta.exe OR reg.exe OR certutil.exe OR bitsadmin.exe)
  )
  | group by @timestamp, @host, @user, process.parent.name, process.name
  | select
      @timestamp as Time,
      @host as Host,
      @user as User,
      process.parent.name as ParentProcess,
      "Suspicious Process Launched by Login Script" as DetectionMethod,
      process.name as SuspiciousProcess,
      process.command_line as SuspiciousCommandLine
  | exclude process.command_line:*net use X: \\\\server\\share*
)

-- Aggregate and Summarize
| group by Host, User, ParentProcess
| select
    min(Time) as FirstTime,
    max(Time) as LastTime,
    values(DetectionMethod) as Detections,
    values(SuspiciousProcess) as SuspiciousProcesses,
    values(SuspiciousCommandLine) as CommandLines
| display FirstTime, LastTime, Host, User, ParentProcess, Detections, SuspiciousProcesses, CommandLines
```
---
```sql
-- Name: Misuse of Signed Tools
-- Author: RW
-- Date: 2025-08-17

-- Adversaries misuse legitimate, signed binaries (LOLBins) to bypass application control, evade defenses, and execute malicious code.
-- As highlighted in the reference material, this can include renaming system utilities to circumvent name-based policies (Masquerading, T1036.003),
-- using tools like regsvr32 or bitsadmin with suspicious command-line arguments for proxy execution (T1218) or downloads (T1197),
-- or abusing logon script handlers like gpscript.exe to run malicious commands for persistence (T1037.001).
-- This rule combines these patterns to detect various methods of signed tool abuse.

-- Data Source: Endpoint logs with process creation events.
-- Query Strategy: Combine patterns for renamed binaries, suspicious LOLBin usage, and login script abuse, aggregate by host and user.
-- False Positive Tuning: Exclude known legitimate updaters and script command lines.

logs(
  source:endpoint
  @host:(workstation* OR ops*)
  (
    -- Pattern 1: Renamed System Binary
    (
      process.name:(cmd.exe OR powershell.exe OR pwsh.exe OR cscript.exe OR wscript.exe OR mshta.exe OR rundll32.exe OR regsvr32.exe)
      process.name != process.command_line
      -process.path:(C:\\Windows\\System32\\* OR C:\\Windows\\SysWOW64\\* OR C:\\Windows\\WinSxS\\*)
    ) OR
    -- Pattern 2: Suspicious LOLBin Command-line
    (
      (process.name:regsvr32.exe */s* AND process.command_line:(*http:* OR *https:* OR *scrobj.dll*)) OR
      (process.name:bitsadmin.exe */transfer* AND process.command_line:(*http:* OR *https:*)) OR
      (process.name:msbuild.exe AND process.parent.path:(*\\Temp\\* OR *\\Users\\Public\\* OR *\\AppData\\Roaming\\* OR *\\ProgramData\\*))
    ) OR
    -- Pattern 3: Login Script Abuse
    (
      process.parent.name:gpscript.exe
      process.name:(powershell.exe OR pwsh.exe OR cmd.exe OR cscript.exe OR wscript.exe OR whoami.exe OR net.exe OR net1.exe OR systeminfo.exe OR reg.exe OR certutil.exe OR bitsadmin.exe)
    )
  )
  -process.parent.name:(*GoogleUpdate.exe OR *AdobeARM.exe)
  -process.command_line:*net use X: \\\\server\\share*
)
| group by @host, @user, process.parent.name
| select
    min(@timestamp) as FirstTime,
    max(@timestamp) as LastTime,
    @host as Host,
    @user as User,
    process.parent.name as ParentProcess,
    values(process.command_line) as CommandLine,
    values(process.name) as OriginalProcessName,
    values(process.command_line) as ExecutedProcess,
    case(
      process.name != process.command_line AND process.path !~ "C:\\Windows\\(System32|SysWOW64|WinSxS)\\.*", "Renamed Signed Tool Execution (Masquerading)",
      process.name = "regsvr32.exe", "Suspicious Regsvr32 Execution",
      process.name = "bitsadmin.exe", "Suspicious Bitsadmin Download",
      process.name = "msbuild.exe", "Suspicious MSBuild Execution",
      process.parent.name = "gpscript.exe", "Suspicious Process Launched by Login Script"
    ) as DetectionMethod
| display FirstTime, LastTime, Host, User, ParentProcess, ExecutedProcess, OriginalProcessName, CommandLine, DetectionMethod
```