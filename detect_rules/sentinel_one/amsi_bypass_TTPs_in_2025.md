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
SELECT
  createdAt AS Timestamp,
  AgentName AS DeviceName,
  User AS AccountName,
  ProcessName AS FileFullName,
  ProcessCmd AS ProcessCommandLine,
  ParentProcessName AS InitiatingProcessFileFullName,
  ParentProcessCmd AS InitiatingProcessCommandLine
FROM deepvisibility
WHERE
  (ProcessName IN ("powershell.exe", "pwsh.exe") AND
   (ProcessCmd LIKE "%-version 2%" OR ProcessCmd LIKE "%-v 2%"))
  OR
  (eventType == "PowerShellEngineStateChange" AND
   JSON_EXTRACT(data, "$.EngineVersion") == "2.0")
```

### Suspicious PowerShell Obfuscation Keywords
---
```sql
SELECT
  createdAt AS Timestamp,
  AgentName AS DeviceName,
  User AS AccountName,
  ProcessName AS FileFullName,
  ProcessCmd AS ProcessCommandLine,
  ParentProcessName AS InitiatingProcessFileFullName,
  ParentProcessCmd AS InitiatingProcessCommandLine
FROM deepvisibility
WHERE
  ProcessName IN ("powershell.exe", "pwsh.exe")
  AND (
    ((ProcessCmd LIKE "%-encodedcommand%"
      OR ProcessCmd LIKE "%-ec%"
      OR ProcessCmd LIKE "%-enc%"
      OR ProcessCmd LIKE "%-en%"
      OR ProcessCmd LIKE "%-e %")
      AND LENGTH(ProcessCmd) > 200)
    OR
    ((ProcessCmd LIKE "%iex%"
      OR ProcessCmd LIKE "%invoke-expression%")
      AND (ProcessCmd LIKE "%+%"
           OR ProcessCmd LIKE "%-join%"
           OR ProcessCmd LIKE "%[char]%"
           OR ProcessCmd LIKE "%frombase64string%"
           OR LENGTH(ProcessCmd) > 1024))
    OR
    (LENGTH(ProcessCmd) > 400
     AND (ProcessCmd LIKE "%-join%"
          OR ProcessCmd LIKE "%replace%"
          OR ProcessCmd LIKE "%split%"))
  )
```

### AMSI DLL Memory Patching via PowerShell
---
```sql
SELECT
  createdAt AS Timestamp,
  AgentName AS DeviceName,
  User AS AccountName,
  ParentProcessName AS ParentProcess,
  ParentProcessCmd AS ParentCommandLine,
  JSON_EXTRACT(data, "$.ScriptBlockText") AS ScriptBlockText
FROM deepvisibility
WHERE
  eventType == "PowerShellScriptBlock"
  AND JSON_EXTRACT(data, "$.ScriptBlockText") IS NOT NULL
  AND JSON_EXTRACT(data, "$.ScriptBlockText") LIKE "%VirtualProtect%"
  AND JSON_EXTRACT(data, "$.ScriptBlockText") LIKE "%GetProcAddress%"
  AND JSON_EXTRACT(data, "$.ScriptBlockText") LIKE "%InteropServices%"
  AND JSON_EXTRACT(data, "$.ScriptBlockText") LIKE "%AmsiScanBuffer%"
  AND (JSON_EXTRACT(data, "$.ScriptBlockText") LIKE "%amsi.dll%"
       OR JSON_EXTRACT(data, "$.ScriptBlockText") LIKE "%clr.dll%")
```

### Hardware Breakpoints for AMSI Bypass
---
```sql
SELECT
  createdAt AS Timestamp,
  AgentName AS DeviceName,
  User AS AccountName,
  ParentProcessName AS InitiatingProcessFileFullName,
  ParentProcessCmd AS InitiatingProcessCommandLine,
  JSON_EXTRACT(data, "$.TargetModulePath") AS TargetModulePath,
  JSON_EXTRACT(data, "$.DebugRegister") AS DebugRegister,
  JSON_EXTRACT(data, "$.BreakpointAddress") AS BreakpointAddress
FROM deepvisibility
WHERE
  eventType == "SetThreadContextApiCall"
  AND ParentProcessName IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "rundll32.exe")
  AND JSON_EXTRACT(data, "$.TargetModulePath") LIKE "%\\amsi.dll"
```

### DLL Load Manipulation for AMSI Bypass
---
```sql
SELECT
  createdAt AS Timestamp,
  AgentName AS DeviceName,
  ProcessName AS InitiatingProcessFileFullName,
  ProcessCmd AS InitiatingProcessCommandLine,
  FileFullName AS FileFullName,
  filePath AS FolderPath,
  fileSHA1 AS SHA1,
  fileSignerIdentity AS Signer,
  fileIsSigned AS IsSigned
FROM deepvisibility
WHERE
  FileFullName LIKE "%\\amsi.dll"
  AND ProcessName IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe")
  AND (
    NOT (filePath LIKE "%C:\\Windows\\System32\\%" OR filePath LIKE "%C:\\Windows\\SysWOW64\\%")
    OR
    (fileIsSigned = false OR (fileIsSigned = true AND fileSignerIdentity NOT LIKE "%Microsoft Windows%"))
  )
```

### Reflection-based AMSI Bypass
---
```sql
SELECT
  createdAt AS Timestamp,
  AgentName AS DeviceName,
  User AS AccountName,
  ParentProcessName AS ParentProcess,
  ParentProcessCmd AS ParentCommandLine,
  JSON_EXTRACT(data, "$.ScriptBlockText") AS ScriptBlockText
FROM deepvisibility
WHERE
  eventType == "PowerShellScriptBlock"
  AND JSON_EXTRACT(data, "$.ScriptBlockText") IS NOT NULL
  AND JSON_EXTRACT(data, "$.ScriptBlockText") LIKE "%AmsiUtils%"
  AND JSON_EXTRACT(data, "$.ScriptBlockText") LIKE "%amsiInitFailed%"
  AND (JSON_EXTRACT(data, "$.ScriptBlockText") LIKE "%GetField%"
       OR JSON_EXTRACT(data, "$.ScriptBlockText") LIKE "%SetValue%"
       OR JSON_EXTRACT(data, "$.ScriptBlockText") LIKE "%NonPublic%"
       OR JSON_EXTRACT(data, "$.ScriptBlockText") LIKE "%Static%")
```
