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
# Part 1: Detect downgrade via command-line arguments using process execution data.
# Assumes process creation events are in the Endpoint data model.
| tstats summariesonly=true allow_old_summaries=true count from datamodel=Endpoint.Processes where (Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe") AND (Processes.process="*-version 2*" OR Processes.process="*-v 2*") by _time Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| rename Processes.* as *
| rename dest as host, parent_process_name as parent_process, process_name as process, process as process_command_line
| fields _time, host, user, parent_process, process, process_command_line

# Part 2: Combine with PowerShell Event Log (EventCode 400) data.
| append [
    # This part searches raw logs for the specific event.
    search ((index=* (source="WinEventLog:Microsoft-Windows-PowerShell/Operational" OR sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational") EventCode=400) OR (sourcetype="xmlwineventlog" source="Microsoft-Windows-PowerShell/Operational" EventCode="400")) AND "EngineVersion=2.0"
    # Attempt to extract the parent process from the event message for context.
    | rex field=Message "HostApplication=(?<parent_process_from_msg>[^\r\n]+)"
    | eval parent_process = coalesce(parent_process, parent_process_from_msg)
    | eval process = "powershell.exe"
    | eval process_command_line = "PowerShell Engine Started in Version 2.0 Mode"
    | fields _time, host, user, parent_process, process, process_command_line
]

# FP Tuning: Some legacy applications or administrative scripts may legitimately use PowerShell v2.
# Consider excluding known benign parent processes, users, or command lines if necessary.
# For example: | where NOT (match(parent_process, "legacyscript.exe") OR user="legacy_user")

# Final aggregation and output.
| stats values(process_command_line) as process_command_line values(parent_process) as parent_process by _time, host, user, process
| rename _time as timestamp
| convert ctime(timestamp)
| table timestamp, host, user, process, parent_process, process_command_line
```

### Suspicious PowerShell Obfuscation Keywords
---
```sql
# Search process execution data from the Endpoint data model.
| tstats summariesonly=true allow_old_summaries=true count from datamodel=Endpoint.Processes
# Filter for PowerShell processes.
where (Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe")
# Combine multiple conditions to identify obfuscated commands.
AND (
    # Condition 1: Use of EncodedCommand, a common method for hiding malicious scripts.
    (
        (Processes.process="*-encodedcommand*" OR Processes.process="*-ec*" OR Processes.process="*-encoding*" OR Processes.process="*-enc*" OR Processes.process="*-en*" OR Processes.process="*-e *")
        AND len(Processes.process) > 200
    )
    OR
    # Condition 2: Use of Invoke-Expression (IEX) with other obfuscation indicators.
    (
        (Processes.process="*iex*" OR Processes.process="*invoke-expression*")
        AND (Processes.process="*+*" OR Processes.process="*-join*" OR Processes.process="*[char]*" OR Processes.process="*frombase64string*" OR len(Processes.process) > 1024)
    )
    OR
    # Condition 3: Unusual command line length combined with string manipulation functions.
    (
        len(Processes.process) > 400
        AND (Processes.process="*-join*" OR Processes.process="*replace*" OR Processes.process="*split*")
    )
)
# Group by relevant fields for context.
by _time Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
# Rename fields to be more readable and align with common schemas.
| rename Processes.dest as host, Processes.user as user, Processes.parent_process_name as parent_process, Processes.process_name as process_name, Processes.process as process_command_line
# FP Tuning: Legitimate scripts, especially from management tools (e.g., SCCM, Intune), might use encoded commands.
# Exclude known safe parent processes or command line patterns if they cause noise.
# For example: | where NOT match(parent_process, "ccmexec.exe")
| table _time, host, user, parent_process, process_name, process_command_line
| convert ctime(_time) as timestamp
| fields timestamp, host, user, parent_process, process_name, process_command_line
```

### AMSI DLL Memory Patching via PowerShell
---
```sql
# Search for PowerShell script block execution events (Event ID 4104).
((index=* (source="WinEventLog:Microsoft-Windows-PowerShell/Operational" OR sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational") EventCode=4104) OR (sourcetype="xmlwineventlog" source="Microsoft-Windows-PowerShell/Operational" EventCode="4104"))
# Unify the field containing the script block text, as it can vary based on the TA.
| eval script_block_content = coalesce(Message, ScriptBlockText)
# Filter for script blocks containing a combination of keywords indicative of in-memory patching of AMSI.
| where isnotnull(script_block_content)
  # Looks for the function used to change memory permissions.
  AND like(script_block_content, "%VirtualProtect%")
  # Looks for the function used to find the address of the target function to patch.
  AND like(script_block_content, "%GetProcAddress%")
  # Looks for the namespace often used to copy the patch into memory.
  AND like(script_block_content, "%InteropServices%")
  # Looks for the common target function and the DLLs it resides in.
  AND like(script_block_content, "%AmsiScanBuffer%") AND (like(script_block_content, "%amsi.dll%") OR like(script_block_content, "%clr.dll%"))
# Extract the parent process from the HostApplication field for better context.
| rex field=Message "HostApplication=(?<parent_process>[^\r\n]+)"
# FP Tuning: This is a highly suspicious combination of function calls.
# Legitimate software is unlikely to perform this sequence. However, some security assessment tools might.
# Exclude known tools by name or signer if they cause noise.
# For example: | where NOT match(parent_process, "pentest-tool.exe")
# Rename fields for clarity and present the results.
| rename Computer as host, User as user, script_block_content as script_block_text
| table _time, host, user, parent_process, script_block_text
| convert ctime(_time) as timestamp
| fields timestamp, host, user, parent_process, script_block_text
```

### Hardware Breakpoints for AMSI Bypass
---
```sql
# This search requires EDR data that logs SetThreadContext API calls and their parameters,
# such as Microsoft Defender for Endpoint (DeviceEvents). The field names used here
# are based on the MDE schema. Adjust field names for other data sources.
search (index=* (sourcetype="mde:DeviceEvents" OR sourcetype="WdatpDeviceEvents")) ActionType="SetThreadContextApiCall"
# Parse the JSON field containing the detailed API call information.
| spath input=AdditionalFields
# Filter for attempts to place a breakpoint within amsi.dll.
| where like(TargetModulePath, "%\\amsi.dll")
# This technique is often executed from scripting hosts or custom loaders.
# Filtering for these parent processes increases the fidelity of the detection.
| where InitiatingProcessFileName IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "rundll32.exe")

# FP Tuning: While highly suspicious, some advanced debugging or security tools might perform this action.
# Exclude known and signed tools if they generate noise.
# For example: | where InitiatingProcessSigner != "Legitimate Security Vendor"

# Rename fields for clarity and present the results.
| rename DeviceName as host, InitiatingProcessAccountName as user, InitiatingProcessFileName as process_name, InitiatingProcessCommandLine as process_command_line
| table _time, host, user, process_name, process_command_line, TargetModulePath, DebugRegister, BreakpointAddress
| convert ctime(_time) as timestamp
| fields timestamp, host, user, process_name, process_command_line, TargetModulePath, DebugRegister, BreakpointAddress
```

### DLL Load Manipulation for AMSI Bypass
---
```sql
# Search for image load events from the Endpoint data model. This requires a data source like Sysmon EventCode 7.
| tstats summariesonly=true allow_old_summaries=true count from datamodel=Endpoint.Image_Loads where Image_Loads.file_name="amsi.dll" by _time Image_Loads.dest Image_Loads.user Image_Loads.process_name Image_Loads.process Image_Loads.file_path Image_Loads.file_hash Image_Loads.is_signed Image_Loads.signer
# Rename fields for readability.
| rename Image_Loads.* as *
# Focus on processes that are common targets for this bypass.
| where process_name IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe")
# Extract the folder path from the full file path.
| rex field=file_path "(?<folder_path>.*)\\\\[^\\\\]+$"
# The core detection logic: find either a non-standard path OR an invalid signature.
| where
    # Condition 1: The DLL is loaded from a path other than the legitimate system directories.
    (isnotnull(folder_path) AND NOT (lower(folder_path) IN ("c:\\windows\\system32", "c:\\windows\\syswow64")))
    OR
    # Condition 2: The DLL is not signed, or it is signed by someone other than Microsoft.
    (is_signed=0 OR (is_signed=1 AND signer NOT LIKE "%Microsoft Windows%"))

# FP Tuning: This behavior is highly anomalous. False positives might occur with custom security tools or sandboxing environments that manipulate DLL loads.
# Exclude known legitimate tools if necessary.
# For example: | where NOT match(process, "LegitSecurityTool")

# Format the output for analysts.
| rename dest as host, process as process_command_line, file_hash as sha1, file_name as loaded_dll
| table _time, host, user, process_name, process_command_line, loaded_dll, folder_path, sha1, signer, is_signed
| convert ctime(_time) as timestamp
| fields timestamp, host, user, process_name, process_command_line, loaded_dll, folder_path, sha1, signer, is_signed
```

### Reflection-based AMSI Bypass
---
```sql
# Search for PowerShell script block execution events (Event ID 4104).
((index=* (source="WinEventLog:Microsoft-Windows-PowerShell/Operational" OR sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational") EventCode=4104) OR (sourcetype="xmlwineventlog" source="Microsoft-Windows-PowerShell/Operational" EventCode="4104"))
# Unify the field containing the script block text.
| eval script_block_text = coalesce(Message, ScriptBlockText)
# Look for the specific combination of class, field, and reflection methods used in this bypass.
| where isnotnull(script_block_text)
  AND like(script_block_text, "%AmsiUtils%")
  AND like(script_block_text, "%amsiInitFailed%")
  AND (
      like(script_block_text, "%GetField%") OR
      like(script_block_text, "%SetValue%") OR
      like(script_block_text, "%NonPublic%") OR
      like(script_block_text, "%Static%")
  )
# Extract the parent process from the event message for context.
| rex field=Message "HostApplication=(?<parent_process>[^\r\n]+)"
# FP Tuning: This is a highly specific and suspicious technique.
# False positives may occur with security assessment or red-teaming tools.
# Exclude known tools by name or signer if necessary.
# For example: | where NOT match(parent_process, "pentest-tool.exe")
# Rename fields for clarity and present the results.
| rename Computer as host, User as user
| table _time, host, user, parent_process, script_block_text
| convert ctime(_time) as timestamp
| fields timestamp, host, user, parent_process, script_block_text
```
