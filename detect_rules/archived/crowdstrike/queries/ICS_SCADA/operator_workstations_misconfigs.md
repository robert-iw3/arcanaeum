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

-- Rule: Uses ProcessRollup2 to compare ImageFileName with OriginalFileName for system binaries executed from non-standard paths. Filters for OT workstations and excludes legitimate system folders.
event_platform=Win event_simpleName=ProcessRollup2 ImageFileName IN ("cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe", "certutil.exe", "msiexec.exe") OriginalFileName!=ImageFileName !ImageFileName:/(C:\Windows\System32\|C:\Windows\SysWOW64\|C:\Windows\WinSxS\)/i +ComputerName:/(EWS|HMI|GRID-WKS)/i
| rename ComputerName as host LocalUserName as user ParentBaseFileName as parent_process ImageFileName as original_file_name CommandLine as executed_process_name
| eval execution_path=ImageFileName
| fields @timestamp host user parent_process original_file_name executed_process_name execution_path
-- Potential False Positives: Legitimate software installers or updaters renaming system tools. Exclude known application paths (e.g., !execution_path:/C:\Program Files\SomeLegitApp\/i). Filter for OT workstations (e.g., +ComputerName:/(EWS|HMI)/i).
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

-- Rule: Uses ProcessRollup2 to detect regsvr32, msbuild, and bitsadmin with suspicious command-line patterns or parent process paths. Filters for OT workstations and excludes known legitimate parents.
event_platform=Win event_simpleName=ProcessRollup2 (
    (ImageFileName="regsvr32.exe" CommandLine://s/i (CommandLine:/(http:|https:|ftp:|scrobj.dll)/i)) OR
    (ImageFileName="msbuild.exe" ParentBaseFileName:/(\\Temp\|\Users\Public\|\AppData\Roaming\|\ProgramData\)/i) OR
    (ImageFileName="bitsadmin.exe" CommandLine://transfer/i CommandLine:/(http:|https:)/i)
) +ComputerName:/(EWS|HMI|GRID-WKS)/i !ParentBaseFileName IN ("GoogleUpdate.exe", "AdobeARM.exe")
| stats min(@timestamp) as firstTime max(@timestamp) as lastTime values(CommandLine) as command_line values(ParentBaseFileName) as parent_process by ComputerName LocalUserName ImageFileName
| rename ComputerName as host LocalUserName as user ImageFileName as lolbin
| table firstTime lastTime host user lolbin parent_process command_line
-- Potential False Positives: Legitimate updaters (e.g., Google, Adobe) using bitsadmin, or developer tools using msbuild. Exclude known parent processes (e.g., !ParentBaseFileName IN ("GoogleUpdate.exe")). Tune parent path filters and filter for OT workstations (e.g., +ComputerName:/(EWS|HMI)/i).
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

-- Rule: Uses UserLogin to detect successful logins with administrative SIDs or high host counts. Filters for interactive/network logons and OT workstations. Optimizes with time aggregation and threshold tuning.
event_platform=Win event_simpleName=UserLogin Success=true LogonType IN (2, 3, 10) TokenElevationType IN ("%%1936", "%%1937") !LocalUserName IN ("*$", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "UMFD-1") +ComputerName:/(EWS|HMI|GRID-WKS)/i
| stats dc(ComputerName) as distinct_host_count values(ComputerName) as logon_hosts min(@timestamp) as firstTime max(@timestamp) as lastTime by @timestamp span=1h LocalUserName SID
| where SID:/-500$/ OR distinct_host_count > 10
| eval detection_method=case(SID:/-500$/ AND distinct_host_count > 10, "Default Admin SID with Shared Behavior", SID:/-500$, "Default Administrator SID Used", distinct_host_count > 10, "Anomalous Shared Account Behavior")
| rename LocalUserName as user SID as user_sid
| table firstTime lastTime user user_sid distinct_host_count logon_hosts detection_method
-- Potential False Positives: Legitimate admin tools or scripts using shared accounts. Tune the distinct_host_count > 10 threshold based on environment. Exclude known admin accounts (e.g., !user IN ("AdminSvcAccount1")). Filter for OT workstations (e.g., +ComputerName:/(EWS|HMI)/i).
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

-- Rule: Uses FileWrite for SYSVOL script modifications and ProcessRollup2 for gpscript.exe child processes. Filters for OT workstations and excludes legitimate GPO tools.
(
    (event_platform=Win event_simpleName=FileWrite FileWriteAction IN ("created", "renamed") TargetFileName IN (".bat", ".cmd", ".vbs", ".ps1") TargetFileName:/\SYSVOL\.*\scripts\/i !ImageFileName IN ("gpmc.exe", "gpoadmin.exe", "dfsrc.exe") +ComputerName:/(EWS|HMI|GRID-WKS)/i
    | eval detection_method="Login Script File Modified in SYSVOL" suspicious_process=TargetFileName suspicious_command_line="File '" + TargetFileName + "' created/renamed in " + TargetFileName)
| append [
        event_platform=Win event_simpleName=ProcessRollup2 ParentBaseFileName="gpscript.exe" ImageFileName IN ("powershell.exe", "pwsh.exe", "cmd.exe", "cscript.exe", "wscript.exe", "whoami.exe", "net.exe", "net1.exe", "nltest.exe", "systeminfo.exe", "quser.exe", "qwinsta.exe", "reg.exe", "certutil.exe", "bitsadmin.exe") +ComputerName:/(EWS|HMI|GRID-WKS)/i !CommandLine:/net use [A-Z]: \\server\share/i
        | eval detection_method="Suspicious Process Launched by Login Script" suspicious_process=ImageFileName suspicious_command_line=CommandLine
    ]
)
| stats values(detection_method) as detections values(suspicious_process) as suspicious_processes values(suspicious_command_line) as command_lines min(@timestamp) as firstTime max(@timestamp) as lastTime by ComputerName LocalUserName ParentBaseFileName
| rename ComputerName as host LocalUserName as user ParentBaseFileName as parent_process
| table firstTime lastTime host user parent_process detections suspicious_processes command_lines
-- Potential False Positives: Legitimate GPO script modifications or benign gpscript.exe child processes (e.g., net use for drive mapping). Exclude known good command lines (e.g., !CommandLine:/net use/i). Filter for OT workstations (e.g., +ComputerName:/(EWS|HMI)/i).
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

-- Rule: Uses ProcessRollup2 to detect renamed binaries, suspicious LOLBin command-line patterns, and gpscript.exe child processes. Filters for OT workstations and excludes legitimate parents.
event_platform=Win event_simpleName=ProcessRollup2 (
    -- Pattern 1: Renamed System Binary (Masquerading)
    (ImageFileName IN ("cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe") OriginalFileName!=ImageFileName !ImageFileName:/(C:\Windows\System32\|C:\Windows\SysWOW64\|C:\Windows\WinSxS\)/i
    | eval detection_method="Renamed Signed Tool Execution (Masquerading)") OR
    -- Pattern 2: Suspicious LOLBin Command-line Usage
    ((ImageFileName="regsvr32.exe" CommandLine://s/i CommandLine:/(http:|https:|scrobj.dll)/i
    | eval detection_method="Suspicious Regsvr32 Execution") OR (ImageFileName="bitsadmin.exe" CommandLine://transfer/i CommandLine:/(http:|https:)/i
    | eval detection_method="Suspicious Bitsadmin Download") OR (ImageFileName="msbuild.exe" ParentBaseFileName:/(\\Temp\|\Users\Public\|\AppData\Roaming\|\ProgramData\)/i
    | eval detection_method="Suspicious MSBuild Execution")) OR
    -- Pattern 3: Login Script Abuse
    (ParentBaseFileName="gpscript.exe" ImageFileName IN ("powershell.exe", "pwsh.exe", "cmd.exe", "cscript.exe", "wscript.exe", "whoami.exe", "net.exe", "net1.exe", "systeminfo.exe", "reg.exe", "certutil.exe", "bitsadmin.exe")
    | eval detection_method="Suspicious Process Launched by Login Script")
) +ComputerName:/(EWS|HMI|GRID-WKS)/i !ParentBaseFileName IN ("GoogleUpdate.exe", "AdobeARM.exe") !CommandLine:/net use [A-Z]: \\server\share/i
| stats min(@timestamp) as firstTime max(@timestamp) as lastTime values(CommandLine) as command_line values(ImageFileName) as executed_process values(ImageFileName) as original_process_name by ComputerName LocalUserName ParentBaseFileName
| rename ComputerName as host LocalUserName as user ParentBaseFileName as parent_process
| table firstTime lastTime host user parent_process executed_process original_process_name command_line detection_method
-- Potential False Positives: Legitimate installers, updaters, or login scripts using these tools. Exclude known parent processes (e.g., !ParentBaseFileName IN ("GoogleUpdate.exe")) and command lines (e.g., !CommandLine:/net use/i). Filter for OT workstations (e.g., +ComputerName:/(EWS|HMI)/i).
```