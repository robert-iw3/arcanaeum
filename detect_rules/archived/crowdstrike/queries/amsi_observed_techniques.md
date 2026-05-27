### AMSI Bypass via Hardware Breakpoint
---
```sql
-- Name: AMSI Bypass via Hardware Breakpoint
-- Author: RW
-- Date: 2025-07-31
-- Description: Detects the use of the SetThreadContext API to set a hardware breakpoint on a function within amsi.dll. This is an emerging technique used to bypass AMSI by intercepting the scan functions execution.
-- Tags: TTPs, Defense Evasion

event_type=ProcessRollup2
| where ProcessName in ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "rundll32.exe")
| join (
    event_type=ApiCall
    | where api_name = "SetThreadContext"
    | where target_module_path LIKE "*\amsi.dll"
) on ProcessId
| select
    timestamp,
    ComputerName,
    account_name = UserName,
    ProcessName,
    CommandLine,
    target_module_path
```

### AMSI Bypass via Memory Patching
---
```sql
-- name: AMSI Bypass via Memory Patching
-- date: 2025-07-31
-- author: RW
-- description: Detects attempts to patch the AmsiScanBuffer function in memory to bypass AMSI. This technique involves a process calling VirtualProtect or a similar API to change the memory permissions of amsi.dll to be writable (e.g., PAGE_EXECUTE_READWRITE), allowing the adversary to overwrite the function and disable AMSI scanning.
-- mitre_attack_id: T1562.001

event_type=ApiCall
| where api_name in ("VirtualProtect", "NtProtectVirtualMemory")
| where target_module_path LIKE "*\amsi.dll"
| where CommandLine in ("PAGE_EXECUTE_READWRITE", "ExecuteReadWrite")
| select
    timestamp,
    ComputerName,
    ProcessName,
    ParentProcessName,
    CommandLine,
    UserName,
    target_module_path,
    api_name
```

### AMSI Bypass via NtSetContextThread
---
```sql
-- name: AMSI Bypass via NtSetContextThread
-- date: 2025-07-31
-- author: RW
-- description: Detects the use of the `NtSetContextThread` or `SetThreadContext` API call. Adversaries can leverage this API to set hardware breakpoints on sensitive functions, such as `amsi.dll!AmsiScanBuffer`, as a method of bypassing AMSI. This technique involves modifying the debug registers (Dr0-Dr7) within the threads CONTEXT structure to hook the function and redirect execution, effectively neutralizing the security control without patching it in memory. This activity can be monitored by observing Event ID 4 from the `Microsoft-Windows-Kernel-Audit-API-Calls` ETW provider.
-- mitre_attack_id: T1562.001

event_type=ApiCall
| where api_name in ("SetThreadContext", "NtSetContextThread")
| select
    timestamp,
    ComputerName,
    api_name,
    ProcessName,
    ParentProcessName,
    CommandLine,
    UserName,
    ProcessId,
    ThreadId
```

###
---
```sql
-- name: AMSI Bypass via VEH2
-- date: 2025-07-31
-- author: RW
-- description: Detects the VEH2 AMSI bypass technique, where an adversary registers multiple Vectored Exception Handlers (VEHs) and uses a `DebugBreak` call to trigger an exception chain. This allows setting a hardware breakpoint on `AmsiScanBuffer` and manipulating the execution flow to bypass AMSI scanning without calling the easily monitored `NtSetContextThread` API.
-- mitre_attack_id: T1562.001, T1055

event_type=ApiCall
| where timestamp > now(-1h)
| where api_name in ("AddVectoredExceptionHandler", "DebugBreak")
| union (
    event_type=ModuleLoad
    | where timestamp > now(-1h)
    | where module_path LIKE "*\amsi.dll"
)
| group by DeviceId, ComputerName, ProcessId, ProcessGuid, ProcessName, CommandLine, ParentProcessName
| select
    start_time = min(timestamp),
    end_time = max(timestamp),
    ComputerName,
    ProcessName,
    ParentProcessName,
    CommandLine,
    ProcessId,
    ProcessGuid,
    veh_registration_count = countif(api_name = "AddVectoredExceptionHandler"),
    debug_break_count = countif(api_name = "DebugBreak"),
    amsi_load_count = countif(event_type = "ModuleLoad" and module_path LIKE "*\amsi.dll")
| where veh_registration_count > 1 and debug_break_count > 0 and amsi_load_count > 0
| select
    timestamp = start_time,
    end_time,
    ComputerName,
    ProcessName,
    ParentProcessName,
    CommandLine,
    ProcessId,
    ProcessGuid,
    veh_registrations = veh_registration_count,
    debug_breaks = debug_break_count,
    amsi_loaded = amsi_load_count
```

### AMSI DLL Memory Patching via PowerShell
---
```sql
-- Name: AMSI DLL Memory Patching via PowerShell
-- Author: RW
-- Date: 2025-07-31
-- Description: Detects PowerShell script blocks that contain code to patch AMSI-related functions (e.g., AmsiScanBuffer) in memory. Adversaries use this technique to disable AMSI and evade detection.
-- Tags: TTPs, Defense Evasion, T1027, T1059.001

event_type=PowerShellScriptBlock
| where timestamp > now(-1h)
| where script_content contains "VirtualProtect" and script_content contains "GetProcAddress" and script_content contains "InteropServices" and script_content contains "AmsiScanBuffer" and (script_content contains "amsi.dll" or script_content contains "clr.dll")
| select
    timestamp,
    ComputerName,
    account_name = UserName,
    parent_process_name = ProcessName,
    parent_command_line = CommandLine,
    script_content
```

### PowerShell Obfuscated String Manipulation for AMSI Bypass
---
```sql
-- Name: PowerShell Obfuscated String Manipulation for AMSI Bypass
-- Author: RW
-- Date: 2025-07-31
-- Tactic: Defense Evasion
-- Technique: T1027, Obfuscated Files or Information
-- Description: Detects PowerShell using string replacement functions like `.replace()` to construct sensitive strings such as "Amsi.dll" or "AmsiScanBuffer". This is a common technique to evade static signature-based detections before performing an AMSI bypass.
-- False Positive Sensitivity: Medium.
-- Legitimate administrative or automation scripts may use string replacement in conjunction with API calls.
-- If false positives occur, consider excluding trusted script paths, parent processes, or known command line patterns.

event_type=ProcessRollup2
| where timestamp > now(-1d)
| where ProcessName in ("powershell.exe", "pwsh.exe")
| where CommandLine contains ".replace"
| where (CommandLine contains "GetModuleHandle" or CommandLine contains "GetProcAddress")
| where CommandLine contains "Add-Type" and CommandLine contains "DllImport"
| select
    timestamp,
    ComputerName,
    account_name = UserName,
    initiating_process_name = ProcessName,
    initiating_process_command_line = CommandLine,
    file_name = ProcessName,
    CommandLine,
    MD5,
    SHA1,
    SHA256
```

### Suspicious PowerShell Obfuscation Keywords
---
```sql
-- Name: Suspicious PowerShell Obfuscation Keywords
-- Author: RW
-- Date: 2025-07-31
-- Description: Detects PowerShell command lines containing keywords and patterns commonly associated with obfuscation techniques. Adversaries use obfuscation to hide malicious code from signature-based detections and security analysts.
-- Tags: TTPs, Defense Evasion, T1027

event_type=ProcessRollup2
| where ProcessName in ("powershell.exe", "pwsh.exe")
| where (
    (CommandLine contains "-encodedcommand" or CommandLine contains "-ec" or CommandLine contains "-enc" or CommandLine contains "-en" or CommandLine contains "-e ") and len(CommandLine) > 200
    or
    (CommandLine contains "iex" or CommandLine contains "invoke-expression") and (CommandLine contains "+" or CommandLine contains "-join" or CommandLine contains "[char]" or CommandLine contains "frombase64string" or len(CommandLine) > 1024)
    or
    (len(CommandLine) > 400 and (CommandLine contains "-join" or CommandLine contains "replace" or CommandLine contains "split"))
)
| select
    timestamp,
    ComputerName,
    account_name = UserName,
    file_name = ProcessName,
    CommandLine,
    initiating_process_name = ParentProcessName,
    initiating_process_command_line = ParentCommandLine
```

### PowerShell AMSI Write Raid Bypass
---
```sql
-- Name: PowerShell AMSI Write Raid Bypass
-- Author: RW
-- Date: 2025-07-31
-- Tactic: Defense Evasion
-- Technique: T1562.001, Impair Defenses: Disable or Modify Tools
-- Description: Detects a PowerShell command line that exhibits characteristics of the "AMSI Write Raid" bypass technique.
-- This method involves defining and using kernel32.dll functions via P/Invoke to find the in-memory address of AmsiScanBuffer and overwrite it,
-- thus disabling AMSI for the current process. This bypass is notable for not requiring VirtualProtect.
-- False Positive Sensitivity: Medium.
-- This detection may trigger on legitimate administrative or security research scripts that perform in-memory operations.
-- Consider excluding known-good scripts, trusted script signers, or specific parent processes if false positives occur.

event_type:ProcessStart
| ProcessName:/.(powershell.exe|pwsh.exe)./
| CommandLine:".Add-Type.DllImport.kernel32."
| CommandLine:".ReadProcessMemory.GetProcAddress."
| CommandLine:".Marshal.::Copy."
| CommandLine:"..replace."
| fields Time, MachineId, UserName, ParentProcessName, CommandLine, MD5, SHA1, SHA256
```

### PowerShell Downgraded to Version 2 for AMSI Bypass
---
```sql
-- Name: PowerShell Downgraded to Version 2 for AMSI Bypass
-- Author: RW
-- Date: 2025-07-31
-- Description: Detects PowerShell being executed in version 2.0 mode. Adversaries may use this technique to bypass the Antimalware Scan Interface (AMSI), as it is not supported in PowerShell v2.
-- Tags: TTPs, Defense Evasion

(event_type=ProcessStart
| where ProcessName in ("powershell.exe", "pwsh.exe")
| where CommandLine contains "-version 2" or CommandLine contains "-v 2"
| select timestamp, DeviceId, UserName, ParentProcessName, CommandLine, ParentCommandLine)
| union (
  event_type=PowerShellEngineStateChange
  | where CommandLine contains "2.0"
  | select timestamp, DeviceId, UserName, ParentProcessName, CommandLine="PowerShell Engine Started in Version 2.0 Mode", ParentCommandLine
)
```

### Reflection-based AMSI Bypass
---
```sql
-- Name: Reflection-based AMSI Bypass
-- Author: RW
-- Date: 2025-07-31
-- Description: Detects PowerShell scripts using .NET reflection to modify internal AMSI utility fields, such as 'amsiInitFailed', to disable AMSI. This is a highly effective bypass technique.
-- Tags: TTPs, Defense Evasion, T1027, T1059.001

event_type=PowerShellScriptBlock
| where ScriptBlockText contains "AmsiUtils" and ScriptBlockText contains "amsiInitFailed" and ScriptBlockText contains "GetField" or ScriptBlockText contains "SetValue" or ScriptBlockText contains "NonPublic" or ScriptBlockText contains "Static"
| select timestamp, DeviceId, UserName, ParentProcessName, ParentCommandLine, ScriptBlockText
```

### Suspicious AMSI.DLL Load
---
```sql
-- Name: Suspicious AMSI.DLL Load
-- Author: RW
-- Date: 2025-07-31
-- Description: Detects the loading of amsi.dll from a non-standard directory or the loading of an unsigned/improperly signed version of amsi.dll. This is indicative of DLL hijacking or other AMSI bypass techniques where an adversary replaces the legitimate AMSI provider with a malicious one.
-- Tags: TTPs, Defense Evasion, T1574.002

event_type=ImageLoad
| where FileName LIKE "*amsi.dll"
| where ProcessName in ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe")
| where (not(FilePath LIKE "C:\Windows\(System32|SysWOW64)\*") or (not(IsSigned) or (IsSigned and not(Signer LIKE "*Microsoft Windows*"))))
| select timestamp, DeviceId, ProcessName, CommandLine, FileName, FilePath, SHA1, Signer, IsSigned
```

### PowerShell Post-AMSI-Bypass Activity
---
```sql
-- Name: PowerShell Post-AMSI-Bypass Activity
-- Author: RW
-- Date: 2025-07-31
-- Tactic: Execution, Defense Evasion
-- Technique: T1059.001, PowerShell; T1562.001, Impair Defenses: Disable or Modify Tools
-- Description: Detects suspicious PowerShell commands (e.g., 'amsiutils', 'Invoke-Mimikatz') executing shortly after a separate PowerShell command indicative of an in-memory AMSI bypass, such as the 'AMSI Write Raid' technique. This correlation suggests a successful defense evasion followed by malicious command execution.
-- False Positive Sensitivity: Medium.
-- Security testing, red team exercises, or complex administrative scripts that manipulate memory could trigger this rule.
-- If false positives occur, consider tuning the 'suspicious_payload_indicators' or excluding trusted parent processes or script paths.

(event_type=ProcessStart
| where ProcessName in ("powershell.exe", "pwsh.exe")
| where CommandLine contains "Add-Type" and CommandLine contains "DllImport" and CommandLine contains "kernel32" and CommandLine contains "ReadProcessMemory" and CommandLine contains "GetProcAddress" and CommandLine contains "Marshal.::Copy"
| select BypassTime=timestamp, DeviceId, ComputerName, UserName, ParentProcessName, BypassCommandLine=CommandLine)
| join (
  event_type=ProcessStart
  | where ProcessName in ("powershell.exe", "pwsh.exe")
  | where CommandLine contains "amsiutils" or CommandLine contains "Invoke-Mimikatz" or CommandLine contains "Invoke-Expression" or CommandLine contains "DownloadString"
  | where not(CommandLine LIKE "*Add-Type*DllImport*kernel32*ReadProcessMemory*GetProcAddress*Marshal.::Copy*")
) on DeviceId
| where SuspiciousTime > BypassTime and (SuspiciousTime - BypassTime) <= 5m
| select Time=SuspiciousTime, ComputerName, UserName, BypassTime, ParentProcessName, BypassCommandLine, SuspiciousTime, SuspiciousParentProcess, SuspiciousCommandLine
```