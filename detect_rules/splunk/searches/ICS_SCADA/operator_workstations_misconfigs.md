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
-- This query is written for the Splunk CIM Endpoint.Processes data model.

`tstats` count from datamodel=Endpoint.Processes where
    -- The OriginalFileName from the PE header should be one of our target system binaries
    (Processes.process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe", "certutil.exe", "msiexec.exe"))
    -- The actual filename on disk must be different from the original name
    AND (Processes.process != Processes.process_name)
    -- Exclude executions from legitimate system folders to reduce noise
    AND (Processes.process_path NOT IN ("C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*", "C:\\Windows\\WinSxS\\*"))
    by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process, Processes.process_path
| `drop_dm_object_name("Processes")`
| rename
    dest as host,
    user as user,
    parent_process as parent_process,
    process_name as original_file_name,
    process as executed_process_name,
    process_path as execution_path
| fields host, user, parent_process, original_file_name, executed_process_name, execution_path

-- FP Tuning:
-- Some legitimate software installers or updaters may rename and drop copies of system tools.
-- If you see FPs from a specific application, consider excluding its path or parent process.
-- For example: | search NOT (execution_path="C:\\Program Files\\SomeLegitApp\\*")
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

-- Data Source:
-- Requires process creation events (e.g., Sysmon EventCode 1, CrowdStrike, etc.).
-- This query is written for the Splunk CIM Endpoint.Processes data model.

`tstats` summariesonly=true values(Processes.process_command_line) as command_line, values(Processes.parent_process) as parent_process, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where
(
    (*-- T1218.010: Regsvr32 - Used for proxy execution of code. --*)
    (Processes.process_name="regsvr32.exe" AND Processes.process_command_line="*/s*" AND (Processes.process_command_line="*http:*" OR Processes.process_command_line="*https:*" OR Processes.process_command_line="*ftp:*" OR Processes.process_command_line="*scrobj.dll*"))
    OR
    (*-- T1127.001: MSBuild - Looks for execution from unusual, user-writable locations. --*)
    (Processes.process_name="msbuild.exe" AND Processes.parent_process_path IN ("*\\Temp\\*", "*\\Users\\Public\\*", "*\\AppData\\Roaming\\*", "*\\ProgramData\\*"))
    OR
    (*-- T1197: BITS Jobs - Looks for bitsadmin downloading files from the internet. --*)
    (Processes.process_name="bitsadmin.exe" AND Processes.process_command_line="*/transfer*" AND (Processes.process_command_line="*http:*" OR Processes.process_command_line="*https:*" ))
)
by Processes.dest, Processes.user, Processes.process_name
| `drop_dm_object_name("Processes")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| rename
    process_name as lolbin,
    dest as host,
    user as user
| fields firstTime, lastTime, host, user, lolbin, parent_process, command_line

-- FP Tuning:
-- - Legitimate software updaters (e.g., Google Update, Adobe Updater) may use bitsadmin.exe to download files.
--   Consider excluding known safe parent processes if FPs occur.
--   Example: | search NOT (parent_process IN ("*\\GoogleUpdate.exe", "*\\AdobeARM.exe"))
-- - MSBuild may be used by legitimate developer tools or scripts. If you have developers, you may need to
--   tune the parent_process_path filter to be more specific to your environment.
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
-- Requires Windows Security Event Logs (EventCode=4624) mapped to the Splunk CIM Authentication data model.

`tstats` summariesonly=true dc(Authentication.dest) as distinct_host_count, values(Authentication.dest) as logon_hosts, min(_time) as firstTime, max(_time) as lastTime from datamodel=Authentication where
    (nodename=All_Authentication Authentication.action=success)
    -- Filter for interactive, remote interactive, and network logons
    AND (Authentication.logon_type IN (2, 3, 10))
    -- Identify administrative logons by checking the token elevation type
    AND (Authentication.token_elevation_type IN ("%%1936", "%%1937"))
    -- Exclude common system and machine accounts to reduce noise
    AND (Authentication.user!="*$") AND (Authentication.user NOT IN ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "UMFD-1"))
    by _time span=1h, Authentication.user, Authentication.user_id
| `drop_dm_object_name("Authentication")`
-- Apply detection logic for default or shared accounts
| where (like(user_id, "%-500") OR distinct_host_count > 10)
-- Add context for why the alert fired
| eval detection_method=case(
    like(user_id, "%-500") AND distinct_host_count > 10, "Default Admin SID with Shared Behavior",
    like(user_id, "%-500"), "Default Administrator SID Used",
    distinct_host_count > 10, "Anomalous Shared Account Behavior"
  )
| `ctime(firstTime)`
| `ctime(lastTime)`
| rename user as user, user_id as user_sid
| fields firstTime, lastTime, user, user_sid, distinct_host_count, logon_hosts, detection_method

-- FP Tuning:
-- - The 'distinct_host_count' threshold (currently 10) may need to be adjusted based on your environment's
--   baseline administrative activity.
-- - Legitimate administrative tools or scripts may trigger the shared account logic.
--   Consider excluding known administrative or service accounts if they cause false positives.
--   Example: | search NOT (user IN ("AdminSvcAccount1", "BackupAdmin"))
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
-- Requires file modification and process creation events, mapped to the Splunk CIM
-- for Endpoint.Filesystem and Endpoint.Processes data models (e.g., from Sysmon).

(
    -- Part 1: Detect modification of GPO-defined login scripts in SYSVOL
    `tstats` count from datamodel=Endpoint.Filesystem where
        (Filesystem.action IN ("created", "renamed"))
        -- Login scripts are often stored in the SYSVOL share for domain-wide execution
        AND (Filesystem.file_path="*\\SYSVOL\\*\\scripts\\*")
        -- Filter for common script file types
        AND (Filesystem.file_name IN ("*.bat", "*.cmd", "*.vbs", "*.ps1"))
        -- FP Tuning: Exclude known administrative tools that manage GPOs and file replication services.
        AND (Filesystem.process_name NOT IN ("gpmc.exe", "gpoadmin.exe", "dfsrc.exe"))
        by _time, Filesystem.dest, Filesystem.user, Filesystem.process_name, Filesystem.file_path, Filesystem.file_name
    | `drop_dm_object_name("Filesystem")`
    | eval detection_method="Login Script File Modified in SYSVOL", suspicious_process=file_name, suspicious_command_line="File '" + file_name + "' created/renamed in " + file_path
    | rename process_name as parent_process, dest as host
    | fields _time, host, user, parent_process, detection_method, suspicious_process, suspicious_command_line
)
| append [
    -- Part 2: Detect suspicious processes launched by the GPO script handler
    `tstats` values(Processes.process_command_line) as suspicious_command_line from datamodel=Endpoint.Processes where
        -- gpscript.exe is the engine that processes GPO-based login scripts
        (Processes.parent_process_name="gpscript.exe")
        -- Look for suspicious child processes being launched by the script
        AND (Processes.process_name IN ("powershell.exe", "pwsh.exe", "cmd.exe", "cscript.exe", "wscript.exe", "whoami.exe", "net.exe", "net1.exe", "nltest.exe", "systeminfo.exe", "quser.exe", "qwinsta.exe", "reg.exe", "certutil.exe", "bitsadmin.exe"))
        by _time, Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name
    | `drop_dm_object_name("Processes")`
    | eval detection_method="Suspicious Process Launched by Login Script"
    | rename process_name as suspicious_process, parent_process_name as parent_process, dest as host
    -- FP Tuning: Legitimate scripts may call these tools. Exclude known good command lines if they cause noise.
    -- Example: | where NOT (suspicious_command_line LIKE "%net use X: \\\\server\\share%")
    | fields _time, host, user, parent_process, detection_method, suspicious_process, suspicious_command_line
]
-- Aggregate related events into a single alert
| stats values(detection_method) as detections, values(suspicious_process) as suspicious_processes, values(suspicious_command_line) as command_lines, min(_time) as firstTime, max(_time) as lastTime by host, user, parent_process
| `ctime(firstTime)`
| `ctime(lastTime)`
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
-- Requires process creation events (e.g., Sysmon EventCode 1) mapped to the Splunk CIM Endpoint.Processes data model.

`tstats` summariesonly=true values(Processes.process_command_line) as command_line, values(Processes.process) as executed_process, values(Processes.process_name) as original_process_name, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where
(
    -- Pattern 1: Renamed System Binary (Masquerading)
    -- Detects when a common system utility's internal name does not match its executed filename.
    (
        (Processes.process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"))
        AND (Processes.process != Processes.process_name)
        AND (Processes.process_path NOT IN ("C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*", "C:\\Windows\\WinSxS\\*"))
    )
    OR
    -- Pattern 2: Suspicious LOLBin Command-line Usage
    -- Detects known malicious patterns for specific LOLBins.
    (
        (Processes.process_name="regsvr32.exe" AND Processes.process_command_line="*/s*" AND (Processes.process_command_line="*http:*" OR Processes.process_command_line="*https:*" OR Processes.process_command_line="*scrobj.dll*"))
        OR
        (Processes.process_name="bitsadmin.exe" AND Processes.process_command_line="*/transfer*" AND (Processes.process_command_line="*http:*" OR Processes.process_command_line="*https:*" ))
        OR
        (Processes.process_name="msbuild.exe" AND Processes.parent_process_path IN ("*\\Temp\\*", "*\\Users\\Public\\*", "*\\AppData\\Roaming\\*", "*\\ProgramData\\*"))
    )
    OR
    -- Pattern 3: Login Script Abuse
    -- Detects the GPO script handler spawning suspicious reconnaissance or execution tools.
    (
        (Processes.parent_process_name="gpscript.exe")
        AND (Processes.process_name IN ("powershell.exe", "pwsh.exe", "cmd.exe", "cscript.exe", "wscript.exe", "whoami.exe", "net.exe", "net1.exe", "systeminfo.exe", "reg.exe", "certutil.exe", "bitsadmin.exe"))
    )
)
by Processes.dest, Processes.user, Processes.parent_process_name
| `drop_dm_object_name("Processes")`
-- Add a field to provide context on which pattern triggered the alert.
| eval detection_method = case(
    mvcount(original_process_name) > 0 AND mvfilter(original_process_name != executed_process), "Renamed Signed Tool Execution (Masquerading)",
    mvfilter(like(executed_process, "%regsvr32.exe")), "Suspicious Regsvr32 Execution",
    mvfilter(like(executed_process, "%bitsadmin.exe")), "Suspicious Bitsadmin Download",
    mvfilter(like(executed_process, "%msbuild.exe")), "Suspicious MSBuild Execution",
    parent_process_name="gpscript.exe", "Suspicious Process Launched by Login Script"
)
| `ctime(firstTime)`
| `ctime(lastTime)`
| rename dest as host, parent_process_name as parent_process
| fields firstTime, lastTime, host, user, parent_process, executed_process, original_process_name, command_line, detection_method

-- FP Tuning:
-- - Legitimate software installers or updaters may rename tools or use bitsadmin for downloads.
--   If FPs occur, consider excluding known safe parent processes.
--   Example: | search NOT (parent_process IN ("*\\GoogleUpdate.exe", "*\\AdobeARM.exe"))
-- - Legitimate login scripts may call tools like 'net.exe'. If this is common, exclude specific known-good command lines.
--   Example: | where NOT (like(command_line, "%net use X: \\\\server\\share%"))
```