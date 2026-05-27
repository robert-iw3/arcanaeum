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

-- Data Source:
-- Requires process creation events with OriginalFileName metadata, such as Sysmon EventCode 1.
-- This query is written for Elastic Common Schema (ECS) fields, assuming indices like logs-endpoint.events.process-* or similar.

FROM *
| WHERE process.pe.original_file_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe", "certutil.exe", "msiexec.exe")
  AND process.name != process.pe.original_file_name
  AND NOT (process.executable LIKE "C:\\Windows\\System32\\%" OR process.executable LIKE "C:\\Windows\\SysWOW64\\%" OR process.executable LIKE "C:\\Windows\\WinSxS\\%")
| STATS count = COUNT() BY host.name, user.name, process.parent.executable, process.pe.original_file_name, process.name, process.executable
| RENAME host.name AS host, user.name AS user, process.parent.executable AS parent_process, process.pe.original_file_name AS original_file_name, process.name AS executed_process_name, process.executable AS execution_path
| KEEP host, user, parent_process, original_file_name, executed_process_name, execution_path

-- FP Tuning:
-- Some legitimate software installers or updaters may rename and drop copies of system tools.
-- If you see FPs from a specific application, consider excluding its path or parent process.
-- For example: | WHERE NOT (execution_path LIKE "C:\\Program Files\\SomeLegitApp\\%")```
---
```
```sql
-- Name: Suspicious LOLBin Execution
-- Author: RW
-- Date: 2025-08-17

-- Adversaries abuse legitimate "Living Off the Land Binaries" (LOLBins) to execute malicious code,
-- download payloads, or bypass application control. This can be difficult to detect as the binaries
-- themselves are trusted and signed by Microsoft. This rule identifies suspicious usage patterns
-- for commonly abused LOLBins like regsvr32, msbuild, and bitsadmin, as highlighted in the reference.

-- Data Source:
-- Requires process creation events (e.g., Sysmon EventCode 1, CrowdStrike, etc.).
-- This query is written for Elastic Common Schema (ECS) fields, assuming indices like logs-endpoint.events.process-* or similar.

FROM *
| WHERE (
    -- T1218.010: Regsvr32 - Used for proxy execution of code.
    (process.name == "regsvr32.exe" AND process.command_line LIKE "%/s%" AND (process.command_line LIKE "%http:%" OR process.command_line LIKE "%https:%" OR process.command_line LIKE "%ftp:%" OR process.command_line LIKE "%scrobj.dll%"))
    OR
    -- T1127.001: MSBuild - Looks for execution from unusual, user-writable locations.
    (process.name == "msbuild.exe" AND (process.parent.executable LIKE "%\\Temp\\%" OR process.parent.executable LIKE "%\\Users\\Public\\%" OR process.parent.executable LIKE "%\\AppData\\Roaming\\%" OR process.parent.executable LIKE "%\\ProgramData\\%"))
    OR
    -- T1197: BITS Jobs - Looks for bitsadmin downloading files from the internet.
    (process.name == "bitsadmin.exe" AND process.command_line LIKE "%/transfer%" AND (process.command_line LIKE "%http:%" OR process.command_line LIKE "%https:%"))
  )
| STATS command_line = VALUES(process.command_line), parent_process = VALUES(process.parent.name), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp) BY host.name, user.name, process.name
| EVAL firstTime = TO_STRING(firstTime), lastTime = TO_STRING(lastTime)
| RENAME process.name AS lolbin, host.name AS host, user.name AS user
| KEEP firstTime, lastTime, host, user, lolbin, parent_process, command_line

-- FP Tuning:
-- - Legitimate software updaters (e.g., Google Update, Adobe Updater) may use bitsadmin.exe to download files.
--   Consider excluding known safe parent processes if FPs occur.
--   Example: | WHERE NOT (parent_process IN ("%\\GoogleUpdate.exe", "%\\AdobeARM.exe"))
-- - MSBuild may be used by legitimate developer tools or scripts. If you have developers, you may need to
--   tune the parent_process filter to be more specific to your environment.
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

-- Data Source:
-- Requires Windows Security Event Logs (EventCode=4624) mapped to Elastic Common Schema (ECS) fields.

FROM *
| WHERE event.category == "authentication" AND event.outcome == "success"
  AND winlog.event_id == 4624
  -- Filter for interactive, remote interactive, and network logons
  AND winlog.event_data.LogonType IN ("2", "3", "10")
  -- Identify administrative logons by checking the token elevation type
  AND winlog.event_data.TokenElevationType IN ("%%1936", "%%1937")
  -- Exclude common system and machine accounts to reduce noise
  AND NOT ENDS_WITH(user.name, "$") AND user.name NOT IN ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "UMFD-1")
| EVAL time_bucket = DATE_TRUNC("hour", @timestamp)
| STATS distinct_host_count = COUNT_DISTINCT(host.name), logon_hosts = VALUES(host.name), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp) BY time_bucket, user.name, user.id
-- Apply detection logic for default or shared accounts
| WHERE ENDS_WITH(user.id, "-500") OR distinct_host_count > 10
-- Add context for why the alert fired
| EVAL detection_method = CASE(
    ENDS_WITH(user.id, "-500") AND distinct_host_count > 10, "Default Admin SID with Shared Behavior",
    ENDS_WITH(user.id, "-500"), "Default Administrator SID Used",
    distinct_host_count > 10, "Anomalous Shared Account Behavior",
    true, null
  ),
  firstTime = TO_STRING(firstTime),
  lastTime = TO_STRING(lastTime)
| RENAME user.name AS user, user.id AS user_sid
| KEEP firstTime, lastTime, user, user_sid, distinct_host_count, logon_hosts, detection_method

-- FP Tuning:
-- - The 'distinct_host_count' threshold (currently 10) may need to be adjusted based on your environment's
--   baseline administrative activity.
-- - Legitimate administrative tools or scripts may trigger the shared account logic.
--   Consider excluding known administrative or service accounts if they cause false positives.
--   Example: | WHERE NOT (user IN ("AdminSvcAccount1", "BackupAdmin"))
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

-- Data Source:
-- Requires file modification and process creation events, mapped to Elastic Common Schema (ECS) fields.

FROM *
| WHERE (
    -- Part 1: Detect modification of GPO-defined login scripts in SYSVOL
    (event.category == "file" AND event.action IN ("creation", "rename")
      AND file.path LIKE "%\\SYSVOL\\%\\scripts\\%"
      -- Filter for common script file types
      AND (file.name LIKE "%.bat" OR file.name LIKE "%.cmd" OR file.name LIKE "%.vbs" OR file.name LIKE "%.ps1")
      -- FP Tuning: Exclude known administrative tools that manage GPOs and file replication services.
      AND process.name NOT IN ("gpmc.exe", "gpoadmin.exe", "dfsrc.exe"))
    OR
    -- Part 2: Detect suspicious processes launched by the GPO script handler
    (event.category == "process" AND process.parent.name == "gpscript.exe"
      -- Look for suspicious child processes being launched by the script
      AND process.name IN ("powershell.exe", "pwsh.exe", "cmd.exe", "cscript.exe", "wscript.exe", "whoami.exe", "net.exe", "net1.exe", "nltest.exe", "systeminfo.exe", "quser.exe", "qwinsta.exe", "reg.exe", "certutil.exe", "bitsadmin.exe"))
  )
| EVAL detection_method = CASE(
    event.category == "file", "Login Script File Modified in SYSVOL",
    event.category == "process", "Suspicious Process Launched by Login Script"
  ),
  suspicious_process = CASE(
    event.category == "file", file.name,
    event.category == "process", process.name
  ),
  suspicious_command_line = CASE(
    event.category == "file", CONCAT("File '", file.name, "' created/renamed in ", file.path),
    event.category == "process", process.command_line
  ),
  parent_process = CASE(
    event.category == "file", process.name,
    event.category == "process", process.parent.name
  ),
  host = host.name,
  user = user.name
-- Aggregate related events into a single alert
| STATS detections = VALUES(detection_method), suspicious_processes = VALUES(suspicious_process), command_lines = VALUES(suspicious_command_line), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp) BY host, user, parent_process
| EVAL firstTime = TO_STRING(firstTime), lastTime = TO_STRING(lastTime)

-- FP Tuning:
-- Legitimate scripts may call these tools. Exclude known good command lines if they cause noise.
-- Example: | WHERE NOT (suspicious_command_line LIKE "%net use X: \\\\server\\share%")
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

-- Data Source:
-- Requires process creation events (e.g., Sysmon EventCode 1) mapped to Elastic Common Schema (ECS) fields.

FROM *
| WHERE (
    -- Pattern 1: Renamed System Binary (Masquerading)
    -- Detects when a common system utility's internal name does not match its executed filename.
    (process.pe.original_file_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
      AND process.name != process.pe.original_file_name
      AND NOT (process.executable LIKE "C:\\Windows\\System32\\%" OR process.executable LIKE "C:\\Windows\\SysWOW64\\%" OR process.executable LIKE "C:\\Windows\\WinSxS\\%"))
    OR
    -- Pattern 2: Suspicious LOLBin Command-line Usage
    -- Detects known malicious patterns for specific LOLBins.
    ((process.name == "regsvr32.exe" AND process.command_line LIKE "%/s%" AND (process.command_line LIKE "%http:%" OR process.command_line LIKE "%https:%" OR process.command_line LIKE "%scrobj.dll%"))
      OR
      (process.name == "bitsadmin.exe" AND process.command_line LIKE "%/transfer%" AND (process.command_line LIKE "%http:%" OR process.command_line LIKE "%https:%"))
      OR
      (process.name == "msbuild.exe" AND (process.parent.executable LIKE "%\\Temp\\%" OR process.parent.executable LIKE "%\\Users\\Public\\%" OR process.parent.executable LIKE "%\\AppData\\Roaming\\%" OR process.parent.executable LIKE "%\\ProgramData\\%")))
    OR
    -- Pattern 3: Login Script Abuse
    -- Detects the GPO script handler spawning suspicious reconnaissance or execution tools.
    (process.parent.name == "gpscript.exe"
      AND process.name IN ("powershell.exe", "pwsh.exe", "cmd.exe", "cscript.exe", "wscript.exe", "whoami.exe", "net.exe", "net1.exe", "systeminfo.exe", "reg.exe", "certutil.exe", "bitsadmin.exe"))
  )
| EVAL detection_method = CASE(
    process.pe.original_file_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe") AND process.name != process.pe.original_file_name AND NOT (process.executable LIKE "C:\\Windows\\System32\\%" OR process.executable LIKE "C:\\Windows\\SysWOW64\\%" OR process.executable LIKE "C:\\Windows\\WinSxS\\%"), "Renamed Signed Tool Execution (Masquerading)",
    process.name == "regsvr32.exe" AND process.command_line LIKE "%/s%" AND (process.command_line LIKE "%http:%" OR process.command_line LIKE "%https:%" OR process.command_line LIKE "%scrobj.dll%"), "Suspicious Regsvr32 Execution",
    process.name == "bitsadmin.exe" AND process.command_line LIKE "%/transfer%" AND (process.command_line LIKE "%http:%" OR process.command_line LIKE "%https:%"), "Suspicious Bitsadmin Download",
    process.name == "msbuild.exe" AND (process.parent.executable LIKE "%\\Temp\\%" OR process.parent.executable LIKE "%\\Users\\Public\\%" OR process.parent.executable LIKE "%\\AppData\\Roaming\\%" OR process.parent.executable LIKE "%\\ProgramData\\%"), "Suspicious MSBuild Execution",
    process.parent.name == "gpscript.exe", "Suspicious Process Launched by Login Script",
    true, null
  )
| STATS command_line = VALUES(process.command_line), executed_process = VALUES(process.executable), original_process_name = VALUES(process.pe.original_file_name), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp) BY host.name, user.name, process.parent.name, detection_method
| EVAL firstTime = TO_STRING(firstTime), lastTime = TO_STRING(lastTime)
| RENAME host.name AS host, process.parent.name AS parent_process
| KEEP firstTime, lastTime, host, user.name AS user, parent_process, executed_process, original_process_name, command_line, detection_method

-- FP Tuning:
-- - Legitimate software installers or updaters may rename tools or use bitsadmin for downloads.
--   If FPs occur, consider excluding known safe parent processes.
--   Example: | WHERE NOT (parent_process IN ("%\\GoogleUpdate.exe", "%\\AdobeARM.exe"))
-- - Legitimate login scripts may call tools like 'net.exe'. If this is common, exclude specific known-good command lines.
--   Example: | WHERE NOT (command_line LIKE "%net use X: \\\\server\\share%")
```