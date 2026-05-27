### AMSI Bypass Techniques and Detections in 2025
---

This report details the evolving landscape of Antimalware Scan Interface (AMSI) bypass techniques in 2025, emphasizing that while signature-based detections remain relevant, behavioral and runtime detections are increasingly crucial. Attackers continue to leverage obfuscation and memory patching, but newer methods focus on manipulating DLL loading processes and utilizing hardware breakpoints to evade detection.

A significant new finding is the increased focus on patchless AMSI bypass techniques, particularly those leveraging hardware breakpoints and manipulating DLL loading processes, as these methods are proving more effective against modern EDRs that have improved memory scan and entry point patch detections. Additionally, while public obfuscators like Invoke-Obfuscation are still used, some EDRs now have specific AMSI-based signatures for them, rendering them less effective without further manual modification.

### Actionable Threat Data
---

PowerShell Downgrade: Monitor for PowerShell execution with the `-version 2` argument, as AMSI is not supported in PowerShell version 2.0. This can also be detected by monitoring PowerShell `Event ID 400` for an `EngineVersion` of 2.

Obfuscated PowerShell: Detect PowerShell command-line arguments containing keywords indicative of obfuscation, such as `-encoding`, `-enc`, `+`, `IEX`, or `-EncodedCommand`, especially when combined with unusual string manipulation or Base64 encoding.

Memory Patching of amsi.dll: Look for attempts to modify memory permissions or write data to `amsi.dll`, particularly around the `AmsiScanBuffer` function. While entry point patching is increasingly detected, patching at unusual offsets or in other related DLLs (like `clr.dll`) remains a viable bypass.

Hardware Breakpoints: Monitor for the use of `SetThreadContext` to manipulate debug registers (DR0-DR3) and set hardware breakpoints, especially on functions like `AmsiScanBuffer`. While less commonly detected, this technique is gaining traction among adversaries.

DLL Load Manipulation: Identify suspicious DLL loading activities, such as PowerShell processes loading unsigned amsi.dll files from non-standard directories, or attempts to prevent AMSI-related DLLs from loading before initialization or in newly spawned processes.

Reflection-based AMSI Bypass: Detect PowerShell scripts utilizing .NET reflection to modify internal AMSI fields (e.g., `System.Management.Automation.AmsiUtils.amsiInitFailed`) to disable AMSI.

### PowerShell Downgraded to Version 2 for AMSI Bypass
---
```sql
(
  source:endpoint.processes
  | where (process_name IN ("powershell.exe", "pwsh.exe")) AND (process=~".*-version 2.*" OR process=~".*-v 2.*")
  | fields timestamp, dest=host, user, parent_process_name=parent_process, process_name=process, process=process_command_line
) OR (
  source IN ("WinEventLog:Microsoft-Windows-PowerShell/Operational", "xmlwineventlog:Microsoft-Windows-PowerShell/Operational")
  | where EventID=400 AND Message=~".*EngineVersion=2\.0.*"
  | rex field=Message "HostApplication=(?<parent_process_from_msg>[^\r\n]+)"
  | eval parent_process=coalesce(parent_process, parent_process_from_msg), process="powershell.exe", process_command_line="PowerShell Engine Started in Version 2.0 Mode"
  | fields timestamp, host, user, parent_process, process, process_command_line
)
| stats values(process_command_line)=process_command_line values(parent_process)=parent_process by timestamp, host, user, process
| fields timestamp, host, user, process, parent_process, process_command_line
```

### Suspicious PowerShell Obfuscation Keywords
---
```sql
source:endpoint.processes
| where (process_name IN ("powershell.exe", "pwsh.exe"))
  AND (
    ((process=~".*-encodedcommand.*" OR process=~".*-ec.*" OR process=~".*-encoding.*" OR process=~".*-enc.*" OR process=~".*-en.*" OR process=~".*-e .*") AND length(process) > 200)
    OR
    ((process=~".*iex.*" OR process=~".*invoke-expression.*") AND (process=~".*\\+.*" OR process=~".*-join.*" OR process=~".*\\[char\\].*" OR process=~".*frombase64string.*" OR length(process) > 1024))
    OR
    (length(process) > 400 AND (process=~".*-join.*" OR process=~".*replace.*" OR process=~".*split.*"))
  )
| rename dest=host, parent_process_name=parent_process, process_name=process_name, process=process_command_line
| fields timestamp, host, user, parent_process, process_name, process_command_line
```

### AMSI DLL Memory Patching via PowerShell
---
```sql
source IN ("WinEventLog:Microsoft-Windows-PowerShell/Operational", "xmlwineventlog:Microsoft-Windows-PowerShell/Operational")
| where EventID=4104
| eval script_block_content=coalesce(Message, ScriptBlockText)
| where script_block_content IS NOT NULL
  AND script_block_content=~".*VirtualProtect.*"
  AND script_block_content=~".*GetProcAddress.*"
  AND script_block_content=~".*InteropServices.*"
  AND script_block_content=~".*AmsiScanBuffer.*"
  AND (script_block_content=~".*amsi\.dll.*" OR script_block_content=~".*clr\.dll.*")
| rex field=Message "HostApplication=(?<parent_process>[^\r\n]+)"
| rename Computer=host, User=user, script_block_content=script_block_text
| fields timestamp, host, user, parent_process, script_block_text
```

### Hardware Breakpoints for AMSI Bypass
---
```sql
source IN ("mde:DeviceEvents", "WdatpDeviceEvents")
| where ActionType="SetThreadContextApiCall"
| spath input=AdditionalFields
| where TargetModulePath=~".*\\\\amsi\.dll"
| where InitiatingProcessFileName IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "rundll32.exe")
| rename DeviceName=host, InitiatingProcessAccountName=user, InitiatingProcessFileName=process_name, InitiatingProcessCommandLine=process_command_line
| fields timestamp, host, user, process_name, process_command_line, TargetModulePath, DebugRegister, BreakpointAddress
```

### DLL Load Manipulation for AMSI Bypass
---
```sql
source:endpoint.image_loads
| where file_name="amsi.dll"
| where process_name IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe")
| rex field=file_path "(?<folder_path>.*)\\\\[^\\\\]+$"
| where (
    (folder_path IS NOT NULL AND folder_path!~"(?i)c:\\\\windows\\\\(system32|syswow64)")
    OR
    (is_signed=0 OR (is_signed=1 AND signer!~".*Microsoft Windows.*"))
  )
| rename dest=host, process=process_command_line, file_hash=sha1, file_name=loaded_dll
| fields timestamp, host, user, process_name, process_command_line, loaded_dll, folder_path, sha1, signer, is_signed
```

### Reflection-based AMSI Bypass
---
```sql
source IN ("WinEventLog:Microsoft-Windows-PowerShell/Operational", "xmlwineventlog:Microsoft-Windows-PowerShell/Operational")
| where EventID=4104
| eval script_block_text=coalesce(Message, ScriptBlockText)
| where script_block_text IS NOT NULL
  AND script_block_text=~".*AmsiUtils.*"
  AND script_block_text=~".*amsiInitFailed.*"
  AND (
    script_block_text=~".*GetField.*" OR
    script_block_text=~".*SetValue.*" OR
    script_block_text=~".*NonPublic.*" OR
    script_block_text=~".*Static.*"
  )
| rex field=Message "HostApplication=(?<parent_process>[^\r\n]+)"
| rename Computer=host, User=user
| fields timestamp, host, user, parent_process, script_block_text
```
