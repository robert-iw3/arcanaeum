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
FROM *
| WHERE
  (@timestamp IS NOT NULL AND
   (process.name IN ("powershell.exe", "pwsh.exe") AND
    process.command_line LIKE "%-version 2%" OR process.command_line LIKE "%-v 2%")
  OR
  (event.action == "PowerShellEngineStateChange" AND
   to_double(extract("EngineVersion\":\"(.*?)\"", additional_fields)) == 2.0))
| KEEP
  @timestamp,
  host.name,
  user.name,
  process.name,
  process.command_line,
  process.parent.name,
  process.parent.command_line
| EVAL
  process_command_line = CASE(
    event.action == "PowerShellEngineStateChange",
    "PowerShell Engine Started in Version 2.0 Mode",
    process.command_line
  )
| SORT @timestamp DESC
```

### Suspicious PowerShell Obfuscation Keywords
---
```sql
FROM *
| WHERE
  @timestamp IS NOT NULL
  AND process.name IN ("powershell.exe", "pwsh.exe")
  AND (
    ((process.command_line LIKE "%-encodedcommand%"
      OR process.command_line LIKE "%-ec%"
      OR process.command_line LIKE "%-enc%"
      OR process.command_line LIKE "%-en%"
      OR process.command_line LIKE "%-e %")
      AND LENGTH(process.command_line) > 200)
    OR
    ((process.command_line LIKE "%iex%"
      OR process.command_line LIKE "%invoke-expression%")
      AND (process.command_line LIKE "%+%"
           OR process.command_line LIKE "%-join%"
           OR process.command_line LIKE "%[char]%"
           OR process.command_line LIKE "%frombase64string%"
           OR LENGTH(process.command_line) > 1024))
    OR
    (LENGTH(process.command_line) > 400
     AND (process.command_line LIKE "%-join%"
          OR process.command_line LIKE "%replace%"
          OR process.command_line LIKE "%split%"))
  )
| KEEP
  @timestamp,
  host.name,
  user.name,
  process.name,
  process.command_line,
  process.parent.name,
  process.parent.command_line
| SORT @timestamp DESC
```

### AMSI DLL Memory Patching via PowerShell
---
```sql
FROM *
| WHERE
  @timestamp IS NOT NULL
  AND event.action == "PowerShellScriptBlock"
  AND powershell.script_block.text IS NOT NULL
  AND powershell.script_block.text LIKE "%VirtualProtect%"
  AND powershell.script_block.text LIKE "%GetProcAddress%"
  AND powershell.script_block.text LIKE "%InteropServices%"
  AND powershell.script_block.text LIKE "%AmsiScanBuffer%"
  AND (powershell.script_block.text LIKE "%amsi.dll%" OR powershell.script_block.text LIKE "%clr.dll%")
| KEEP
  @timestamp,
  host.name,
  user.name,
  process.parent.name,
  process.parent.command_line,
  powershell.script_block.text
| SORT @timestamp DESC
```

### Hardware Breakpoints for AMSI Bypass
---
```sql
FROM *
| WHERE
  @timestamp IS NOT NULL
  AND event.action == "SetThreadContextApiCall"
  AND process.parent.name IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "rundll32.exe")
  AND module.path LIKE "%\\amsi.dll"
| EVAL
  parsed_fields = PARSE_JSON(additional_fields),
  target_module_path = parsed_fields.TargetModulePath,
  debug_register = parsed_fields.DebugRegister,
  breakpoint_address = parsed_fields.BreakpointAddress
| KEEP
  @timestamp,
  host.name,
  user.name,
  process.parent.name,
  process.parent.command_line,
  target_module_path,
  debug_register,
  breakpoint_address
| SORT @timestamp DESC
```

### DLL Load Manipulation for AMSI Bypass
---
```sql
FROM *
| WHERE
  @timestamp IS NOT NULL
  AND file.name LIKE "%\\amsi.dll"
  AND process.name IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe")
  AND (
    NOT (file.path LIKE "%C:\\Windows\\System32\\%" OR file.path LIKE "%C:\\Windows\\SysWOW64\\%")
    OR
    (file.signature.status IS NULL OR file.signature.status != "Valid" OR file.signature.issuer NOT LIKE "%Microsoft Windows%")
  )
| KEEP
  @timestamp,
  host.name,
  process.name,
  process.command_line,
  file.name,
  file.path,
  file.hash.sha1,
  file.signature.issuer,
  file.signature.status
| EVAL
  is_signed = CASE(file.signature.status == "Valid", true, false)
| SORT @timestamp DESC
```

### Reflection-based AMSI Bypass
---
```sql
FROM *
| WHERE
  @timestamp IS NOT NULL
  AND event.action == "PowerShellScriptBlock"
  AND powershell.script_block.text IS NOT NULL
  AND powershell.script_block.text LIKE "%AmsiUtils%"
  AND powershell.script_block.text LIKE "%amsiInitFailed%"
  AND (powershell.script_block.text LIKE "%GetField%"
       OR powershell.script_block.text LIKE "%SetValue%"
       OR powershell.script_block.text LIKE "%NonPublic%"
       OR powershell.script_block.text LIKE "%Static%")
| KEEP
  @timestamp,
  host.name,
  user.name,
  process.parent.name,
  process.parent.command_line,
  powershell.script_block.text
| SORT @timestamp DESC
```
