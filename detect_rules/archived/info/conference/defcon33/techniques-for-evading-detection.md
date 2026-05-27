### Obfuscation Reloaded: Techniques for Evading Detection
---

https://media.defcon.org/DEF%20CON%2033/DEF%20CON%2033%20workshops/DEF%20CON%2033%20-%20Workshops%20-%20Jake%20_Hubble_%20Krasnov%20-%20Obfuscation%20Reloaded_%20Modern%20Techniques%20for%20Evading%20Detection%20-%20Slides.pdf

This report summarizes common obfuscation and evasion techniques used by adversaries to bypass detection mechanisms like AMSI and ETW, with a focus on PowerShell and .NET. It highlights how these techniques aim to prevent reverse engineering and evade security controls, emphasizing the importance of behavioral analysis and robust logging for detection.

Recent intelligence indicates a continued evolution of AMSI and ETW bypasses, with new techniques emerging that focus on patchless methods and exploiting writable memory regions within system DLLs to subvert security controls without direct memory patching. This evolution is noteworthy as it makes detection more challenging by leaving fewer forensic artifacts.

### Actionable Threat Data
---

Monitor PowerShell script block logging (Event ID 4104) for highly obfuscated commands, especially those using string manipulation, concatenation, variable insertion, or encoding (e.g., Base64) to hide malicious intent. Look for unusual character sets, excessive use of escape characters, or attempts to reverse strings.

Implement robust logging for AMSI (Antimalware Scan Interface) and ETW (Event Tracing for Windows) events, specifically looking for attempts to disable or tamper with these security features. Pay close attention to calls to AmsiScanBuffer or EtwEventWrite that return immediately or have their memory protections altered.

Analyze process creation and command-line arguments for PowerShell executions that include flags like -EncodedCommand, -NoP, -NonI, -W Hidden, or -Exec Bypass, as these are frequently used in obfuscated and fileless attacks.

Monitor for reflective loading of assemblies or dynamic code execution, particularly in .NET applications, as these can be used to bypass AMSI's inspection when Assembly.Load() is called.

Establish baselines for normal system behavior and alert on anomalies, such as unusual process-parent relationships, unexpected network connections from scripting engines, or attempts to modify registry keys related to AMSI or ETW configuration.

### Obfuscated PowerShell
---
Name: Obfuscated PowerShell Execution

Author: RW

Date: 2025-08-11

Description: Detects PowerShell execution with obfuscated command-line arguments or script content, including string manipulation, concatenation, variable insertion, or encoding (e.g., Base64).

MITRE ATT&CK: T1027.004, T1059.001

splunk:
```sql
-- Define a macro for PowerShell related events for easier management.
-- This macro should include process creation events (e.g., Sysmon Event ID 1, Security Event ID 4688) and script block logs (e.g., PowerShell Operational Event ID 4104).
-- Example macro definition: `(index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1) OR (index=main sourcetype=WinEventLog:Security EventCode=4688) OR (index=main sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104)`
`powershell_events`
-- Filter for PowerShell processes or script block logs.
| where (process_name="powershell.exe" OR process_path="*\\powershell.exe" OR EventCode=4104)
-- Normalize key fields for consistent processing across different log sources.
| eval process_name = coalesce(process_name, ProcessName, NewProcessName),
       cmd_line = coalesce(process_command_line, CommandLine, NewProcessName),
       script_block = coalesce(ScriptBlockText, Message),
       event_code = coalesce(EventCode, event_code),
       parent_process = coalesce(parent_process_name, ParentProcessName)
-- Main detection logic starts here.
| where
    -- Tactic 1: Detect obfuscation in command-line arguments.
    (
        (event_code=1 OR event_code=4688) AND (
            -- High-confidence: PowerShell encoded command flags are a strong indicator of obfuscation or fileless execution.
            match(cmd_line, /(?i)\s(-enc|-encodedcommand|-e[cnopix]*)\s+[A-Za-z0-9+/=]{20,}/) OR
            -- Medium-confidence: Presence of common obfuscation keywords combined with obfuscation operators.
            ( (cmd_line LIKE "%IEX%" OR cmd_line LIKE "%Invoke-Expression%" OR cmd_line LIKE "%FromBase64String%") AND (cmd_line LIKE "%+%" OR cmd_line LIKE "%`%" OR cmd_line LIKE "%-f%") ) OR
            -- Medium-confidence: Specific and well-known AMSI bypass technique.
            (cmd_line LIKE "%AmsiUtils%" AND cmd_line LIKE "%amsiInitFailed%")
        )
    )
    OR
    -- Tactic 2: Detect obfuscation in PowerShell script blocks.
    (
        event_code=4104 AND (
            -- Medium-confidence: Presence of obfuscation keywords combined with obfuscation operators.
            ( (script_block LIKE "%IEX%" OR script_block LIKE "%Invoke-Expression%" OR script_block LIKE "%FromBase64String%" OR script_block LIKE "%VirtualProtect%" OR script_block LIKE "%GetProcAddress%") AND (script_block LIKE "%+%" OR script_block LIKE "%`%" OR script_block LIKE "%-f%" OR script_block LIKE "%[char]%" OR script_block LIKE "%-join%") ) OR
            -- Medium-confidence: Specific and well-known AMSI bypass technique.
            (script_block LIKE "%AmsiUtils%" AND script_block LIKE "%amsiInitFailed%") OR
            -- Medium-confidence: A high ratio of special characters to alphanumeric characters can indicate heavy obfuscation.
            (len(script_block) > 500 AND (mvcount(split(script_block, "")) - mvcount(match(split(script_block, ""), "[a-zA-Z0-9\s]"))) / len(script_block) > 0.4)
        )
    )
-- FP Tuning: Legitimate administration or management scripts may use encoding or other techniques that appear obfuscated.
-- Consider excluding known safe parent processes, users, or specific command lines.
-- Example: | search NOT (parent_process="C:\\AdminTools\\SafeTool.exe")

-- Group and format results for analysis.
| eval detection_tactic = if(event_code=4104, "Script-Block Obfuscation", "Command-Line Obfuscation")
| eval evidence = if(isnotnull(cmd_line), cmd_line, script_block)
| stats count, values(detection_tactic) as detection_tactic, values(evidence) as evidence by _time, dest, user, parent_process, process_name
| rename dest as host
```

crowdstrike fql:
```sql
event_type IN ("ProcessCreation", "ScriptBlock")
| (
    (event_type="ProcessCreation"
     AND (process_name="powershell.exe" OR process_path LIKE "*\\powershell.exe")
     AND (
        cmd_line MATCHES "(?i)\\s(-enc|-encodedcommand|-e[cnopix]*)\\s+[A-Za-z0-9+/=]{20,}"
        OR (
            (cmd_line LIKE "%IEX%" OR cmd_line LIKE "%Invoke-Expression%" OR cmd_line LIKE "%FromBase64String%")
            AND (cmd_line LIKE "%+%" OR cmd_line LIKE "%`%" OR cmd_line LIKE "%-f%")
        )
        OR (cmd_line LIKE "%AmsiUtils%" AND cmd_line LIKE "%amsiInitFailed%")
     ))
    OR
    (event_type="ScriptBlock"
     AND (
        (
            (script_block LIKE "%IEX%" OR script_block LIKE "%Invoke-Expression%" OR script_block LIKE "%FromBase64String%" OR script_block LIKE "%VirtualProtect%" OR script_block LIKE "%GetProcAddress%")
            AND (script_block LIKE "%+%" OR script_block LIKE "%`%" OR script_block LIKE "%-f%" OR script_block LIKE "%[char]%" OR script_block LIKE "%-join%")
        )
        OR (script_block LIKE "%AmsiUtils%" AND script_block LIKE "%amsiInitFailed%")
        OR (LENGTH(script_block) > 500 AND (LENGTH(script_block) - COUNT(MATCH(SPLIT(script_block, ""), "[a-zA-Z0-9\\s]"))) / LENGTH(script_block) > 0.4)
     ))
)
| detection_tactic=IF(event_type="ScriptBlock", "Script-Block Obfuscation", "Command-Line Obfuscation")
| evidence=IF(cmd_line IS NOT NULL, cmd_line, script_block)
| group by timestamp, hostname, user_name, parent_process_name, process_name
| aggregate count=COUNT(), detection_tactic=VALUES(detection_tactic), evidence=VALUES(evidence)
| rename timestamp as _time, hostname as host, user_name as user, parent_process_name as parent_process
```

datadog:
```sql
source:(sysmon OR windows.security OR powershell.operational)
(process_name:powershell.exe OR process_path:*\\powershell.exe OR event_code:4104)
(
  (event_code:(1 OR 4688)
   AND (
     cmd_line:/(?i)\s(-enc|-encodedcommand|-e[cnopix]*)\s+[A-Za-z0-9+/=]{20,}/
     OR (
       (cmd_line:IEX OR cmd_line:Invoke-Expression OR cmd_line:FromBase64String)
       AND (cmd_line:*+* OR cmd_line:*`* OR cmd_line:*-f*)
     )
     OR (cmd_line:AmsiUtils AND cmd_line:amsiInitFailed)
   ))
  OR
  (event_code:4104
   AND (
     (
       (script_block:IEX OR script_block:Invoke-Expression OR script_block:FromBase64String OR script_block:VirtualProtect OR script_block:GetProcAddress)
       AND (script_block:*+* OR script_block:*`* OR script_block:*-f* OR script_block:*[char]* OR script_block:*-join*)
     )
     OR (script_block:AmsiUtils AND script_block:amsiInitFailed)
     OR (length(script_block) > 500 AND (length(script_block) - count(match(split(script_block, ""), "[a-zA-Z0-9\s]"))) / length(script_block) > 0.4)
   ))
)
| eval process_name = coalesce(process_name, ProcessName, NewProcessName),
       cmd_line = coalesce(process_command_line, CommandLine, NewProcessName),
       script_block = coalesce(ScriptBlockText, Message),
       parent_process = coalesce(parent_process_name, ParentProcessName),
       detection_tactic = if(event_code == 4104, "Script-Block Obfuscation", "Command-Line Obfuscation"),
       evidence = if(cmd_line != null, cmd_line, script_block)
| stats count, values(detection_tactic) as detection_tactic, values(evidence) as evidence by @timestamp, host, user, parent_process, process_name
| rename @timestamp as _time
```

elastic:
```sql
FROM logs-windows.*
| WHERE (event.code IN ("1", "4688", "4104"))
  AND (
    process.name == "powershell.exe"
    OR process.executable LIKE "*\\powershell.exe"
    OR event.code == "4104"
  )
  AND (
    (
      event.code IN ("1", "4688")
      AND (
        process.command_line MATCHES "(?i)\\s(-enc|-encodedcommand|-e[cnopix]*)\\s+[A-Za-z0-9+/=]{20,}"
        OR (
          (process.command_line LIKE "*IEX*" OR process.command_line LIKE "*Invoke-Expression*" OR process.command_line LIKE "*FromBase64String*")
          AND (process.command_line LIKE "*+*" OR process.command_line LIKE "*`*" OR process.command_line LIKE "*-f*")
        )
        OR (process.command_line LIKE "*AmsiUtils*" AND process.command_line LIKE "*amsiInitFailed*")
      )
    )
    OR
    (
      event.code == "4104"
      AND (
        (
          (powershell.scriptblock.text LIKE "*IEX*" OR powershell.scriptblock.text LIKE "*Invoke-Expression*" OR powershell.scriptblock.text LIKE "*FromBase64String*" OR powershell.scriptblock.text LIKE "*VirtualProtect*" OR powershell.scriptblock.text LIKE "*GetProcAddress*")
          AND (powershell.scriptblock.text LIKE "*+*" OR powershell.scriptblock.text LIKE "*`*" OR powershell.scriptblock.text LIKE "*-f*" OR powershell.scriptblock.text LIKE "*[char]*" OR powershell.scriptblock.text LIKE "*-join*")
        )
        OR (powershell.scriptblock.text LIKE "*AmsiUtils*" AND powershell.scriptblock.text LIKE "*amsiInitFailed*")
        OR (LENGTH(powershell.scriptblock.text) > 500 AND (LENGTH(powershell.scriptblock.text) - COUNT(MATCH(SPLIT(powershell.scriptblock.text, ""), "[a-zA-Z0-9\\s]"))) / LENGTH(powershell.scriptblock.text) > 0.4)
      )
    )
  )
| EVAL process_name = COALESCE(process.name, process.executable),
       cmd_line = COALESCE(process.command_line, process.args),
       script_block = COALESCE(powershell.scriptblock.text, event.description),
       parent_process = COALESCE(process.parent.name, process.parent.executable),
       detection_tactic = CASE(event.code == "4104", "Script-Block Obfuscation", "Command-Line Obfuscation"),
       evidence = COALESCE(cmd_line, script_block)
| STATS count = COUNT(),
         detection_tactic = MV_DEDUP(detection_tactic),
         evidence = MV_DEDUP(evidence)
  BY @timestamp, host.hostname AS host, user.name AS user, parent_process, process_name
| RENAME @timestamp AS _time
```

sentinel one:
```sql
event.type IN ("ProcessCreation", "ScriptBlock")
AND (
  (process.name = "powershell.exe" OR process.path LIKE "*\\powershell.exe" OR event.type = "ScriptBlock")
)
AND (
  (
    event.type = "ProcessCreation"
    AND (
      process.command_line MATCHES "(?i)\\s(-enc|-encodedcommand|-e[cnopix]*)\\s+[A-Za-z0-9+/=]{20,}"
      OR (
        (process.command_line LIKE "%IEX%" OR process.command_line LIKE "%Invoke-Expression%" OR process.command_line LIKE "%FromBase64String%")
        AND (process.command_line LIKE "%+%" OR process.command_line LIKE "%`%" OR process.command_line LIKE "%-f%")
      )
      OR (process.command_line LIKE "%AmsiUtils%" AND process.command_line LIKE "%amsiInitFailed%")
    )
  )
  OR
  (
    event.type = "ScriptBlock"
    AND (
      (
        (script_block LIKE "%IEX%" OR script_block LIKE "%Invoke-Expression%" OR script_block LIKE "%FromBase64String%" OR script_block LIKE "%VirtualProtect%" OR script_block LIKE "%GetProcAddress%")
        AND (script_block LIKE "%+%" OR script_block LIKE "%`%" OR script_block LIKE "%-f%" OR script_block LIKE "%[char]%" OR script_block LIKE "%-join%")
      )
      OR (script_block LIKE "%AmsiUtils%" AND script_block LIKE "%amsiInitFailed%")
      OR (LENGTH(script_block) > 500 AND (LENGTH(script_block) - COUNT(MATCH(SPLIT(script_block, ""), "[a-zA-Z0-9\\s]"))) / LENGTH(script_block) > 0.4)
    )
  )
)
| SELECT event.timestamp AS _time,
         agent.hostname AS host,
         user.name AS user,
         COALESCE(process.name, process.executable) AS process_name,
         COALESCE(process.command_line, process.args) AS cmd_line,
         COALESCE(script_block, event.description) AS script_block,
         COALESCE(process.parent.name, process.parent.executable) AS parent_process,
         CASE
           WHEN event.type = "ScriptBlock" THEN "Script-Block Obfuscation"
           ELSE "Command-Line Obfuscation"
         END AS detection_tactic,
         COALESCE(process.command_line, script_block) AS evidence
| GROUP BY _time, host, user, parent_process, process_name
| AGGREGATE count = COUNT(),
           detection_tactic = VALUES(detection_tactic),
           evidence = VALUES(evidence)
```

### AMSI/ETW Tampering
---
Name: AMSI or ETW Tampering Detected

Author: RW

Date: 2025-08-11

Description: Detects attempts to disable or tamper with the Anti-Malware Scan Interface (AMSI) or Event Tracing for Windows (ETW) using common PowerShell techniques.

MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools), T1562.006 (Impair Defenses: Indicator Blocking)

splunk:
```sql
-- This search requires PowerShell Script Block Logging (EventCode 4104) to be enabled and ingested.
-- The macro `powershell_script_block_log` should be defined to search for these events.
-- Example macro definition: `(index=main sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational)`
`powershell_script_block_log` EventCode=4104
-- Normalize the field containing the script block content.
| eval script_block_text = coalesce(ScriptBlockText, Message)
-- Main detection logic starts here.
| where (
    -- Tactic 1: Detects the common AMSI bypass that sets 'amsiInitFailed' to true.
    (like(script_block_text, "%AmsiUtils%") AND like(script_block_text, "%amsiInitFailed%"))
    OR
    -- Tactic 2: Detects attempts to patch the AmsiScanBuffer function in memory.
    (like(script_block_text, "%amsi.dll%") AND like(script_block_text, "%GetProcAddress%") AND like(script_block_text, "%VirtualProtect%") AND like(script_block_text, "%AmsiScanBuffer%"))
    OR
    -- Tactic 3: Detects a known ETW bypass that disables the PowerShell log provider.
    (like(script_block_text, "%PSEtwLogProvider%") AND like(script_block_text, "%etwProvider%") AND like(script_block_text, "%m_enabled%"))
)
-- FP Tuning: Security research tools or advanced administration scripts might use these techniques.
-- Consider excluding known safe scripts, users, or parent processes if false positives occur.
-- Example: | search NOT (user="red_team_user" OR ParentProcessName="*\\AdminTools\\*")

-- Group and format results for analysis.
| eval technique = case(
    like(script_block_text, "%AmsiUtils%") AND like(script_block_text, "%amsiInitFailed%"), "AMSI Bypass via amsiInitFailed Flag",
    like(script_block_text, "%amsi.dll%") AND like(script_block_text, "%GetProcAddress%"), "AMSI Bypass via Memory Patching",
    like(script_block_text, "%PSEtwLogProvider%"), "ETW Logging Bypass",
    1=1, "Unknown Tampering Technique"
  )
| table _time, host, user, technique, ParentProcessName, ProcessName, CommandLine, script_block_text
| rename host as dest, user as src_user, ParentProcessName as parent_process, ProcessName as process, CommandLine as process_command_line, script_block_text as details
```

crowdstrike fql:
```sql
event_type="ScriptBlock" event_code="4104"
| script_block=COALESCE(script_block_text, message)
| (
    (script_block LIKE "%AmsiUtils%" AND script_block LIKE "%amsiInitFailed%")
    OR
    (script_block LIKE "%amsi.dll%" AND script_block LIKE "%GetProcAddress%" AND script_block LIKE "%VirtualProtect%" AND script_block LIKE "%AmsiScanBuffer%")
    OR
    (script_block LIKE "%PSEtwLogProvider%" AND script_block LIKE "%etwProvider%" AND script_block LIKE "%m_enabled%")
)
| technique=CASE(
    script_block LIKE "%AmsiUtils%" AND script_block LIKE "%amsiInitFailed%", "AMSI Bypass via amsiInitFailed Flag",
    script_block LIKE "%amsi.dll%" AND script_block LIKE "%GetProcAddress%", "AMSI Bypass via Memory Patching",
    script_block LIKE "%PSEtwLogProvider%", "ETW Logging Bypass",
    TRUE, "Unknown Tampering Technique"
)
| project timestamp, hostname, user_name, technique, parent_process_name, process_name, process_cmd_line, script_block
| rename timestamp as _time, hostname as dest, user_name as src_user, parent_process_name as parent_process, process_name as process, process_cmd_line as process_command_line, script_block as details
```

datadog:
```sql
source:powershell.operational event_code:4104
(script_block_text:(*AmsiUtils* *amsiInitFailed*) OR
 script_block_text:(*amsi.dll* *GetProcAddress* *VirtualProtect* *AmsiScanBuffer*) OR
 script_block_text:(*PSEtwLogProvider* *etwProvider* *m_enabled*))
| eval script_block = coalesce(ScriptBlockText, Message),
       technique = case(
         script_block_text:*AmsiUtils* AND script_block_text:*amsiInitFailed*, "AMSI Bypass via amsiInitFailed Flag",
         script_block_text:*amsi.dll* AND script_block_text:*GetProcAddress*, "AMSI Bypass via Memory Patching",
         script_block_text:*PSEtwLogProvider*, "ETW Logging Bypass",
         true, "Unknown Tampering Technique"
       )
| select @timestamp as _time, host as dest, user as src_user, technique, ParentProcessName as parent_process, ProcessName as process, CommandLine as process_command_line, script_block as details
```

elastic:
```sql
FROM logs-windows.powershell_operational*
| WHERE event.code == "4104"
  AND (
    (powershell.scriptblock.text LIKE "*AmsiUtils*" AND powershell.scriptblock.text LIKE "*amsiInitFailed*")
    OR
    (powershell.scriptblock.text LIKE "*amsi.dll*" AND powershell.scriptblock.text LIKE "*GetProcAddress*" AND powershell.scriptblock.text LIKE "*VirtualProtect*" AND powershell.scriptblock.text LIKE "*AmsiScanBuffer*")
    OR
    (powershell.scriptblock.text LIKE "*PSEtwLogProvider*" AND powershell.scriptblock.text LIKE "*etwProvider*" AND powershell.scriptblock.text LIKE "*m_enabled*")
  )
| EVAL script_block = COALESCE(powershell.scriptblock.text, event.description),
       technique = CASE(
         powershell.scriptblock.text LIKE "*AmsiUtils*" AND powershell.scriptblock.text LIKE "*amsiInitFailed*", "AMSI Bypass via amsiInitFailed Flag",
         powershell.scriptblock.text LIKE "*amsi.dll*" AND powershell.scriptblock.text LIKE "*GetProcAddress*", "AMSI Bypass via Memory Patching",
         powershell.scriptblock.text LIKE "*PSEtwLogProvider*", "ETW Logging Bypass",
         TRUE, "Unknown Tampering Technique"
       )
| KEEP @timestamp AS _time,
      host.hostname AS dest,
      user.name AS src_user,
      technique,
      process.parent.name AS parent_process,
      process.name AS process,
      process.command_line AS process_command_line,
      script_block AS details
```

sentinel one:
```sql
event.type = "ScriptBlock" AND event.code = "4104"
AND (
  (script_block LIKE "%AmsiUtils%" AND script_block LIKE "%amsiInitFailed%")
  OR
  (script_block LIKE "%amsi.dll%" AND script_block LIKE "%GetProcAddress%" AND script_block LIKE "%VirtualProtect%" AND script_block LIKE "%AmsiScanBuffer%")
  OR
  (script_block LIKE "%PSEtwLogProvider%" AND script_block LIKE "%etwProvider%" AND script_block LIKE "%m_enabled%")
)
| SELECT event.timestamp AS _time,
         agent.hostname AS dest,
         user.name AS src_user,
         CASE
           WHEN script_block LIKE "%AmsiUtils%" AND script_block LIKE "%amsiInitFailed%" THEN "AMSI Bypass via amsiInitFailed Flag"
           WHEN script_block LIKE "%amsi.dll%" AND script_block LIKE "%GetProcAddress%" THEN "AMSI Bypass via Memory Patching"
           WHEN script_block LIKE "%PSEtwLogProvider%" THEN "ETW Logging Bypass"
           ELSE "Unknown Tampering Technique"
         END AS technique,
         process.parent.name AS parent_process,
         process.name AS process,
         process.command_line AS process_command_line,
         COALESCE(script_block, event.description) AS details
```

### Reflective Code Loading
---
Name: Reflective Assembly Load in PowerShell

Author: RW

Date: 2025-08-11

Description: Detects reflective loading of .NET assemblies from memory within PowerShell. This technique is often used to execute malicious code while bypassing file-based detections and some AMSI features, as the assembly is loaded directly from a byte array rather than from a file on disk.

MITRE ATT&CK: T1620 (Reflective Code Loading), T1055 (Process Injection), T1622 (Debugger Evasion)

splunk:
```sql
-- This search requires PowerShell Script Block Logging (EventCode 4104).
`powershell_script_block_log` EventCode=4104
-- Normalize the field containing the script block content.
| eval script_block_text = coalesce(ScriptBlockText, Message)
-- Main detection logic: Look for Assembly.Load combined with memory-based sources.
| where (
    -- High-confidence: Loading an assembly directly from a Base64 string is a very common malware pattern.
    (like(script_block_text, "%[System.Reflection.Assembly]::Load%") AND like(script_block_text, "%FromBase64String%"))
    OR
    -- High-confidence: Loading an assembly from a byte array downloaded from the web.
    (like(script_block_text, "%[System.Reflection.Assembly]::Load%") AND like(script_block_text, "%DownloadData%"))
    OR
    -- Medium-confidence: A more generic pattern looking for Assembly.Load with a byte array.
    (like(script_block_text, "%[System.Reflection.Assembly]::Load%") AND like(script_block_text, "%[byte[]]%"))
    OR
    -- Alternative method using the current AppDomain, also combined with memory-based sources.
    (like(script_block_text, "%CurrentDomain.Load%") AND (like(script_block_text, "%FromBase64String%") OR like(script_block_text, "%DownloadData%")))
)
-- FP Tuning: Some legitimate software installers or management tools may use reflective loading.
-- Exclude known safe parent processes or scripts if false positives occur.
-- Example: | search NOT (ParentProcessName="*\\TrustedInstaller.exe" OR ParentProcessName="*\\ManagementConsole.exe")

-- Extract key information for the alert.
| eval technique = case(
    like(script_block_text, "%FromBase64String%"), "Reflective Load from Base64 String",
    like(script_block_text, "%DownloadData%"), "Reflective Load from Web Download",
    like(script_block_text, "%[byte[]]%"), "Reflective Load from Byte Array",
    1=1, "Generic Reflective Load"
  )
| table _time, host, user, technique, ParentProcessName, process, CommandLine, script_block_text
| rename host as dest, ParentProcessName as parent_process, process as process_name, CommandLine as process_command_line, script_block_text as details
```

crowdstrike fql:
```sql
event_type="ScriptBlock" event_code="4104"
| script_block=COALESCE(script_block_text, message)
| (
    (script_block LIKE "%[System.Reflection.Assembly]::Load%" AND script_block LIKE "%FromBase64String%")
    OR
    (script_block LIKE "%[System.Reflection.Assembly]::Load%" AND script_block LIKE "%DownloadData%")
    OR
    (script_block LIKE "%[System.Reflection.Assembly]::Load%" AND script_block LIKE "%[byte[]]%")
    OR
    (script_block LIKE "%CurrentDomain.Load%" AND (script_block LIKE "%FromBase64String%" OR script_block LIKE "%DownloadData%"))
)
| technique=CASE(
    script_block LIKE "%FromBase64String%", "Reflective Load from Base64 String",
    script_block LIKE "%DownloadData%", "Reflective Load from Web Download",
    script_block LIKE "%[byte[]]%", "Reflective Load from Byte Array",
    TRUE, "Generic Reflective Load"
)
| project timestamp, hostname, user_name, technique, parent_process_name, process_name, process_cmd_line, script_block
| rename timestamp as _time, hostname as dest, user_name as user, parent_process_name as parent_process, process_name as process_name, process_cmd_line as process_command_line, script_block as details
```

datadog:
```sql
source:powershell.operational event_code:4104
(script_block_text:(*[System.Reflection.Assembly]::Load* *FromBase64String*) OR
 script_block_text:(*[System.Reflection.Assembly]::Load* *DownloadData*) OR
 script_block_text:(*[System.Reflection.Assembly]::Load* *[byte[]]*) OR
 script_block_text:(*CurrentDomain.Load* (*FromBase64String* OR *DownloadData*)))
| eval script_block = coalesce(ScriptBlockText, Message),
       technique = case(
         script_block_text:*FromBase64String*, "Reflective Load from Base64 String",
         script_block_text:*DownloadData*, "Reflective Load from Web Download",
         script_block_text:*[byte[]]*, "Reflective Load from Byte Array",
         true, "Generic Reflective Load"
       )
| select @timestamp as _time, host as dest, user, technique, ParentProcessName as parent_process, ProcessName as process_name, CommandLine as process_command_line, script_block as details
```

elastic:
```sql
FROM logs-windows.powershell_operational*
| WHERE event.code == "4104"
  AND (
    (powershell.scriptblock.text LIKE "*[System.Reflection.Assembly]::Load*" AND powershell.scriptblock.text LIKE "*FromBase64String*")
    OR
    (powershell.scriptblock.text LIKE "*[System.Reflection.Assembly]::Load*" AND powershell.scriptblock.text LIKE "*DownloadData*")
    OR
    (powershell.scriptblock.text LIKE "*[System.Reflection.Assembly]::Load*" AND powershell.scriptblock.text LIKE "*[byte[]]*")
    OR
    (powershell.scriptblock.text LIKE "*CurrentDomain.Load*" AND (powershell.scriptblock.text LIKE "*FromBase64String*" OR powershell.scriptblock.text LIKE "*DownloadData*"))
  )
| EVAL script_block = COALESCE(powershell.scriptblock.text, event.description),
       technique = CASE(
         powershell.scriptblock.text LIKE "*FromBase64String*", "Reflective Load from Base64 String",
         powershell.scriptblock.text LIKE "*DownloadData*", "Reflective Load from Web Download",
         powershell.scriptblock.text LIKE "*[byte[]]*", "Reflective Load from Byte Array",
         TRUE, "Generic Reflective Load"
       )
| KEEP @timestamp AS _time,
      host.hostname AS dest,
      user.name AS user,
      technique,
      process.parent.name AS parent_process,
      process.name AS process_name,
      process.command_line AS process_command_line,
      script_block AS details
```

sentinel one:
```sql
event.type = "ScriptBlock" AND event.code = "4104"
AND (
  (script_block LIKE "%[System.Reflection.Assembly]::Load%" AND script_block LIKE "%FromBase64String%")
  OR
  (script_block LIKE "%[System.Reflection.Assembly]::Load%" AND script_block LIKE "%DownloadData%")
  OR
  (script_block LIKE "%[System.Reflection.Assembly]::Load%" AND script_block LIKE "%[byte[]]%")
  OR
  (script_block LIKE "%CurrentDomain.Load%" AND (script_block LIKE "%FromBase64String%" OR script_block LIKE "%DownloadData%"))
)
| SELECT event.timestamp AS _time,
         agent.hostname AS dest,
         user.name AS user,
         CASE
           WHEN script_block LIKE "%FromBase64String%"THEN "Reflective Load from Base64 String"
           WHEN script_block LIKE "%DownloadData%" THEN "Reflective Load from Web Download"
           WHEN script_block LIKE "%[byte[]]%" THEN "Reflective Load from Byte Array"
           ELSE "Generic Reflective Load"
         END AS technique,
         process.parent.name AS parent_process,
         process.name AS process_name,
         process.command_line AS process_command_line,
         COALESCE(script_block, event.description) AS details
```

### Unusual PowerShell Flags
---
Name: Unusual PowerShell Command-Line Flags

Author: RW

Date: 2025-08-11

Description: Detects PowerShell execution with suspicious command-line flags often used in malicious contexts to evade detection and execute fileless attacks.

MITRE ATT&CK: T1059.001 (Command and Scripting Interpreter: PowerShell), T1027 (Obfuscated Files or Information)

splunk:
```sql
-- This search requires process creation logs (e.g., Sysmon Event ID 1, Windows Security Event ID 4688).
-- The macro `process_creation` should be defined to search for these events.
`process_creation`
-- Look for PowerShell process execution events.
| where process_name IN ("powershell.exe", "pwsh.exe")
-- Main detection logic: check for various suspicious flags.
| where
    -- High-confidence: The -EncodedCommand flag is frequently used to hide malicious scripts from command-line logging.
    (like(cmd_line, "%-EncodedCommand%") OR like(cmd_line, "% -enc %") OR like(cmd_line, "% -e %"))
    OR
    -- Medium-confidence: The -WindowStyle Hidden flag is used to run PowerShell without a visible window, a common tactic for stealth.
    (like(cmd_line, "%-WindowStyle Hidden%") OR like(cmd_line, "%-W Hidden%"))
    OR
    -- Medium-confidence: The -ExecutionPolicy Bypass flag allows running of unsigned scripts, often a precursor to malicious activity.
    (like(cmd_line, "%-ExecutionPolicy Bypass%") OR like(cmd_line, "%-Exec Bypass%"))
    OR
    -- Lower-confidence: -NonInteractive and -NoProfile are common in legitimate automated scripts, but can be combined with other flags by attackers.
    -- They are included for comprehensive coverage but may require significant tuning.
    (like(cmd_line, "%-NonInteractive%") OR like(cmd_line, "%-NonI%") OR like(cmd_line, "%-NoProfile%") OR like(cmd_line, "%-NoP%"))
-- FP Tuning: Legitimate administrative scripts, software deployment tools (e.g., SCCM, Intune), and monitoring solutions
-- frequently use these flags. Exclude known-good parent processes or command lines to reduce noise.
-- Example: | search NOT (parent_process="C:\\Windows\\System32\\svchost.exe" AND user="SYSTEM")
-- Example: | search NOT (cmd_line="*\\MyGoodApp\\script.ps1*")

-- Extract the primary flag detected for easier analysis.
| eval DetectedFlag = case(
    like(cmd_line, "%-EncodedCommand%") OR like(cmd_line, "% -enc %") OR like(cmd_line, "% -e %"), "-EncodedCommand",
    like(cmd_line, "%-WindowStyle Hidden%") OR like(cmd_line, "%-W Hidden%"), "-WindowStyle Hidden",
    like(cmd_line, "%-ExecutionPolicy Bypass%") OR like(cmd_line, "%-Exec Bypass%"), "-ExecutionPolicy Bypass",
    like(cmd_line, "%-NonInteractive%") OR like(cmd_line, "%-NonI%"), "-NonInteractive",
    like(cmd_line, "%-NoProfile%") OR like(cmd_line, "%-NoP%"), "-NoProfile",
    1=1, "Unknown"
)
| table _time, host, user, parent_process, process_name, cmd_line, DetectedFlag
| rename host as dest, user as src_user, parent_process as parent_process_name, process_name as process, cmd_line as process_command_line
```

crowdstrike fql:
```sql
event_type="ProcessCreation"
| process_name IN ("powershell.exe", "pwsh.exe")
| (
    cmd_line LIKE "%-EncodedCommand%" OR cmd_line LIKE "% -enc %" OR cmd_line LIKE "% -e %"
    OR cmd_line LIKE "%-WindowStyle Hidden%" OR cmd_line LIKE "%-W Hidden%"
    OR cmd_line LIKE "%-ExecutionPolicy Bypass%" OR cmd_line LIKE "%-Exec Bypass%"
    OR cmd_line LIKE "%-NonInteractive%" OR cmd_line LIKE "%-NonI%" OR cmd_line LIKE "%-NoProfile%" OR cmd_line LIKE "%-NoP%"
)
| DetectedFlag=CASE(
    cmd_line LIKE "%-EncodedCommand%" OR cmd_line LIKE "% -enc %" OR cmd_line LIKE "% -e %", "-EncodedCommand",
    cmd_line LIKE "%-WindowStyle Hidden%" OR cmd_line LIKE "%-W Hidden%", "-WindowStyle Hidden",
    cmd_line LIKE "%-ExecutionPolicy Bypass%" OR cmd_line LIKE "%-Exec Bypass%", "-ExecutionPolicy Bypass",
    cmd_line LIKE "%-NonInteractive%" OR cmd_line LIKE "%-NonI%", "-NonInteractive",
    cmd_line LIKE "%-NoProfile%" OR cmd_line LIKE "%-NoP%", "-NoProfile",
    TRUE, "Unknown"
)
| project timestamp, hostname, user_name, parent_process_name, process_name, cmd_line, DetectedFlag
| rename timestamp as _time, hostname as dest, user_name as src_user, parent_process_name as parent_process_name, process_name as process, cmd_line as process_command_line
```

datadog:
```sql
source:(sysmon OR windows.security) process_name:(powershell.exe OR pwsh.exe)
(process_command_line:*-EncodedCommand* OR process_command_line:* -enc * OR process_command_line:* -e * OR
 process_command_line:*-WindowStyle Hidden* OR process_command_line:*-W Hidden* OR
 process_command_line:*-ExecutionPolicy Bypass* OR process_command_line:*-Exec Bypass* OR
 process_command_line:*-NonInteractive* OR process_command_line:*-NonI* OR
 process_command_line:*-NoProfile* OR process_command_line:*-NoP*)
| eval DetectedFlag = case(
  process_command_line:*EncodedCommand* OR process_command_line:* -enc * OR process_command_line:* -e *, "-EncodedCommand",
  process_command_line:*WindowStyle Hidden* OR process_command_line:*W Hidden*, "-WindowStyle Hidden",
  process_command_line:*ExecutionPolicy Bypass* OR process_command_line:*Exec Bypass*, "-ExecutionPolicy Bypass",
  process_command_line:*NonInteractive* OR process_command_line:*NonI*, "-NonInteractive",
  process_command_line:*NoProfile* OR process_command_line:*NoP*, "-NoProfile",
  true, "Unknown"
)
| select @timestamp as _time, host as dest, user as src_user, parent_process_name, process_name as process, process_command_line, DetectedFlag
```

elastic:
```sql
FROM logs-windows.*
| WHERE event.code IN ("1", "4688")
  AND process.name IN ("powershell.exe", "pwsh.exe")
  AND (
    process.command_line LIKE "*%-EncodedCommand%*" OR process.command_line LIKE "*% -enc %*" OR process.command_line LIKE "*% -e %*"
    OR process.command_line LIKE "*%-WindowStyle Hidden%*" OR process.command_line LIKE "*%-W Hidden%*"
    OR process.command_line LIKE "*%-ExecutionPolicy Bypass%*" OR process.command_line LIKE "*%-Exec Bypass%*"
    OR process.command_line LIKE "*%-NonInteractive%*" OR process.command_line LIKE "*%-NonI%*"
    OR process.command_line LIKE "*%-NoProfile%*" OR process.command_line LIKE "*%-NoP%*"
  )
| EVAL DetectedFlag = CASE(
    process.command_line LIKE "*%-EncodedCommand%*" OR process.command_line LIKE "*% -enc %*" OR process.command_line LIKE "*% -e %*", "-EncodedCommand",
    process.command_line LIKE "*%-WindowStyle Hidden%*" OR process.command_line LIKE "*%-W Hidden%*", "-WindowStyle Hidden",
    process.command_line LIKE "*%-ExecutionPolicy Bypass%*" OR process.command_line LIKE "*%-Exec Bypass%*", "-ExecutionPolicy Bypass",
    process.command_line LIKE "*%-NonInteractive%*" OR process.command_line LIKE "*%-NonI%*", "-NonInteractive",
    process.command_line LIKE "*%-NoProfile%*" OR process.command_line LIKE "*%-NoP%*", "-NoProfile",
    TRUE, "Unknown"
  )
| KEEP @timestamp AS _time,
      host.hostname AS dest,
      user.name AS src_user,
      process.parent.name AS parent_process_name,
      process.name AS process,
      process.command_line AS process_command_line,
      DetectedFlag
```

sentinel one:
```sql
event.type = "ProcessCreation"
AND process.name IN ("powershell.exe", "pwsh.exe")
AND (
  process.command_line LIKE "%-EncodedCommand%" OR process.command_line LIKE "% -enc %" OR process.command_line LIKE "% -e %"
  OR process.command_line LIKE "%-WindowStyle Hidden%" OR process.command_line LIKE "%-W Hidden%"
  OR process.command_line LIKE "%-ExecutionPolicy Bypass%" OR process.command_line LIKE "%-Exec Bypass%"
  OR process.command_line LIKE "%-NonInteractive%" OR process.command_line LIKE "%-NonI%"
  OR process.command_line LIKE "%-NoProfile%" OR process.command_line LIKE "%-NoP%"
)
| SELECT event.timestamp AS _time,
         agent.hostname AS dest,
         user.name AS src_user,
         process.parent.name AS parent_process_name,
         process.name AS process,
         process.command_line AS process_command_line,
         CASE
           WHEN process.command_line LIKE "%-EncodedCommand%" OR process.command_line LIKE "% -enc %" OR process.command_line LIKE "% -e %" THEN "-EncodedCommand"
           WHEN process.command_line LIKE "%-WindowStyle Hidden%" OR process.command_line LIKE "%-W Hidden%" THEN "-WindowStyle Hidden"
           WHEN process.command_line LIKE "%-ExecutionPolicy Bypass%" OR process.command_line LIKE "%-Exec Bypass%" THEN "-ExecutionPolicy Bypass"
           WHEN process.command_line LIKE "%-NonInteractive%" OR process.command_line LIKE "%-NonI%" THEN "-NonInteractive"
           WHEN process.command_line LIKE "%-NoProfile%" OR process.command_line LIKE "%-NoP%" THEN "-NoProfile"
           ELSE "Unknown"
         END AS DetectedFlag
```

### Anomalous System Behavior
---
Name: Anomalous System Behavior

Author: RW

Date: 2025-08-11

Description: Detects anomalous system behavior that could indicate sophisticated threats deviating from normal activity. This includes unusual process-parent relationships, unexpected network connections from scripting engines, and attempts to modify registry keys related to AMSI or ETW configuration.

MITRE ATT&CK: TA0002 (Execution), T1070 (Indicator Removal)

splunk:
```sql
-- This detection is composed of three parts, each requiring a specific data source.
-- Ensure you have process creation (e.g., Sysmon Event ID 1), network connection (e.g., Sysmon Event ID 3),
-- and registry modification (e.g., Sysmon Event IDs 12, 13, 14) logs, preferably mapped to the CIM.
-- The macros `process_creation`, `network_connections`, and `registry_changes` should be defined to point to these data sources.

-- Part 1: Detects scripting engines spawned by unusual parent processes.
`process_creation`
| where process_name IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe")
  AND parent_process_name IN ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "chrome.exe", "msedge.exe", "firefox.exe", "acrord32.exe")
-- FP Tuning: Some applications or login scripts may legitimately launch scripts from these parents.
-- Exclude known good parent-child relationships to reduce noise.
-- Example: | search NOT (parent_process_name="outlook.exe" AND process_command_line="*MyLoginScript.ps1*")
| eval AnomalyType="Unusual Parent-Process Relationship", Details="Parent: " . parent_process_name . ", Process: " . process_name
| table _time, dest, user, AnomalyType, Details, parent_process_name, process_name, process_command_line

| append [
    -- Part 2: Detects network connections initiated by scripting engines to non-private IP addresses.
    `network_connections`
    | where process_name IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe")
    | where NOT (cidrmatch("10.0.0.0/8", dest_ip) OR cidrmatch("172.16.0.0/12", dest_ip) OR cidrmatch("192.168.0.0/16", dest_ip) OR dest_ip IN ("127.0.0.1", "::1"))
    -- FP Tuning: Legitimate scripts may connect to internal servers or vendor APIs.
    -- Exclude known good destination IPs or domains.
    -- Example: | search NOT dest_ip="1.2.3.4" OR dest_url="*mycompany.sharepoint.com*"
    | eval AnomalyType="Unexpected Network Connection from Scripting Engine", Details="Process " . process_name . " connected to " . dest_ip . ":" . dest_port
    | table _time, dest, user, AnomalyType, Details, process_name, dest_ip, dest_port, url
]

| append [
    -- Part 3: Detects modification of registry keys related to AMSI or ETW logging.
    `registry_changes`
    | where (registry_path LIKE "%\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging%" OR registry_path LIKE "%\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging%" OR registry_path LIKE "%\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription%" OR registry_path LIKE "%\\SOFTWARE\\Microsoft\\AMSI\\Providers\\%")
    -- FP Tuning: Group Policy updates (gpupdate) can legitimately modify these keys, often via svchost.exe.
    -- Consider excluding known legitimate processes that manage these settings.
    -- Example: | search NOT process_name="svchost.exe"
    | eval AnomalyType="AMSI/ETW Configuration Tampering", Details="Action: " . action . ", Key: " . registry_path . ", Value: " . registry_value_data
    | table _time, dest, user, AnomalyType, Details, process_name, action, registry_path, registry_value_data
]
```

crowdstrike fql:
```sql
(
  // Part 1: Unusual Parent-Process Relationship
  event_type="ProcessCreation"
  | process_name IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe")
  | parent_process_name IN ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "chrome.exe", "msedge.exe", "firefox.exe", "acrord32.exe")
  | AnomalyType="Unusual Parent-Process Relationship"
  | Details="Parent: " + parent_process_name + ", Process: " + process_name
  | project timestamp, hostname, user_name, AnomalyType, Details, parent_process_name, process_name, cmd_line
  | rename timestamp as _time, hostname as dest, user_name as user, cmd_line as process_command_line
)
UNION
(
  // Part 2: Unexpected Network Connection
  event_type="NetworkConnection"
  | process_name IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe")
  | NOT (dest_ip MATCHES "10.0.0.0/8" OR dest_ip MATCHES "172.16.0.0/12" OR dest_ip MATCHES "192.168.0.0/16" OR dest_ip IN ("127.0.0.1", "::1"))
  | AnomalyType="Unexpected Network Connection from Scripting Engine"
  | Details="Process " + process_name + " connected to " + dest_ip + ":" + dest_port
  | project timestamp, hostname, user_name, AnomalyType, Details, process_name, dest_ip, dest_port, url
  | rename timestamp as _time, hostname as dest, user_name as user
)
UNION
(
  // Part 3: AMSI/ETW Configuration Tampering
  event_type="RegistryModification"
  | registry_path LIKE "%\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging%"
     OR registry_path LIKE "%\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging%"
     OR registry_path LIKE "%\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription%"
     OR registry_path LIKE "%\\SOFTWARE\\Microsoft\\AMSI\\Providers\\%"
  | AnomalyType="AMSI/ETW Configuration Tampering"
  | Details="Action: " + action + ", Key: " + registry_path + ", Value: " + registry_value_data
  | project timestamp, hostname, user_name, AnomalyType, Details, process_name, action, registry_path, registry_value_data
  | rename timestamp as _time, hostname as dest, user_name as user
)
```

datadog:
```sql
(
  source:sysmon process_name:(powershell.exe OR pwsh.exe OR cscript.exe OR wscript.exe OR mshta.exe)
  parent_process_name:(winword.exe OR excel.exe OR powerpnt.exe OR outlook.exe OR chrome.exe OR msedge.exe OR firefox.exe OR acrord32.exe)
  | eval AnomalyType = "Unusual Parent-Process Relationship",
         Details = concat("Parent: ", parent_process_name, ", Process: ", process_name)
  | select @timestamp as _time, host as dest, user, AnomalyType, Details, parent_process_name, process_name, process_command_line
)
OR
(
  source:sysmon event_code:3 process_name:(powershell.exe OR pwsh.exe OR cscript.exe OR wscript.exe OR mshta.exe)
  -dest_ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16 OR 127.0.0.1 OR ::1)
  | eval AnomalyType = "Unexpected Network Connection from Scripting Engine",
         Details = concat("Process ", process_name, " connected to ", dest_ip, ":", dest_port)
  | select @timestamp as _time, host as dest, user, AnomalyType, Details, process_name, dest_ip, dest_port, url
)
OR
(
  source:sysmon event_code:(12 OR 13 OR 14)
  registry_path:(*\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging* OR
                 *\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging* OR
                 *\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription* OR
                 *\\SOFTWARE\\Microsoft\\AMSI\\Providers\\*)
  | eval AnomalyType = "AMSI/ETW Configuration Tampering",
         Details = concat("Action: ", action, ", Key: ", registry_path, ", Value: ", registry_value_data)
  | select @timestamp as _time, host as dest, user, AnomalyType, Details, process_name, action, registry_path, registry_value_data
)
```

elastic:
```sql
FROM logs-windows.sysmon*
| WHERE (
  // Part 1: Unusual Parent-Process Relationship
  (
    event.code == "1"
    AND process.name IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe")
    AND process.parent.name IN ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "chrome.exe", "msedge.exe", "firefox.exe", "acrord32.exe")
  )
  OR
  // Part 2: Unexpected Network Connection
  (
    event.code == "3"
    AND process.name IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe")
    AND NOT (destination.ip MATCHES "10.0.0.0/8" OR destination.ip MATCHES "172.16.0.0/12" OR destination.ip MATCHES "192.168.0.0/16" OR destination.ip IN ("127.0.0.1", "::1"))
  )
  OR
  // Part 3: AMSI/ETW Configuration Tampering
  (
    event.code IN ("12", "13", "14")
    AND (
      registry.path LIKE "*\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging*"
      OR registry.path LIKE "*\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging*"
      OR registry.path LIKE "*\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription*"
      OR registry.path LIKE "*\\SOFTWARE\\Microsoft\\AMSI\\Providers\\*"
    )
  )
)
| EVAL AnomalyType = CASE(
    event.code == "1", "Unusual Parent-Process Relationship",
    event.code == "3", "Unexpected Network Connection from Scripting Engine",
    event.code IN ("12", "13", "14"), "AMSI/ETW Configuration Tampering",
    TRUE, "Unknown"
  ),
  Details = CASE(
    event.code == "1", CONCAT("Parent: ", process.parent.name, ", Process: ", process.name),
    event.code == "3", CONCAT("Process ", process.name, " connected to ", destination.ip, ":", TO_STRING(destination.port)),
    event.code IN ("12", "13", "14"), CONCAT("Action: ", event.action, ", Key: ", registry.path, ", Value: ", registry.data.strings),
    TRUE, "Unknown"
  )
| KEEP @timestamp AS _time,
      host.hostname AS dest,
      user.name AS user,
      AnomalyType,
      Details,
      process.parent.name AS parent_process_name,
      process.name AS process_name,
      process.command_line AS process_command_line,
      destination.ip AS dest_ip,
      destination.port AS dest_port,
      url.url AS url,
      event.action AS action,
      registry.path AS registry_path,
      registry.data.strings AS registry_value_data
```

sentinel one:
```sql
(
  // Part 1: Unusual Parent-Process Relationship
  event.type = "ProcessCreation"
  AND process.name IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe")
  AND process.parent.name IN ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "chrome.exe", "msedge.exe", "firefox.exe", "acrord32.exe")
  | SELECT event.timestamp AS _time,
           agent.hostname AS dest,
           user.name AS user,
           "Unusual Parent-Process Relationship" AS AnomalyType,
           CONCAT("Parent: ", process.parent.name, ", Process: ", process.name) AS Details,
           process.parent.name AS parent_process_name,
           process.name AS process_name,
           process.command_line AS process_command_line
)
UNION
(
  // Part 2: Unexpected Network Connection
  event.type = "NetworkConnection"
  AND process.name IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe")
  AND NOT (
    network.destination.ip MATCHES "10.0.0.0/8"
    OR network.destination.ip MATCHES "172.16.0.0/12"
    OR network.destination.ip MATCHES "192.168.0.0/16"
    OR network.destination.ip IN ("127.0.0.1", "::1")
  )
  | SELECT event.timestamp AS _time,
           agent.hostname AS dest,
           user.name AS user,
           "Unexpected Network Connection from Scripting Engine" AS AnomalyType,
           CONCAT("Process ", process.name, " connected to ", network.destination.ip, ":", network.destination.port) AS Details,
           process.name AS process_name,
           network.destination.ip AS dest_ip,
           network.destination.port AS dest_port,
           network.url AS url
)
UNION
(
  // Part 3: AMSI/ETW Configuration Tampering
  event.type = "RegistryModification"
  AND (
    registry.path LIKE "%\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging%"
    OR registry.path LIKE "%\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging%"
    OR registry.path LIKE "%\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription%"
    OR registry.path LIKE "%\\SOFTWARE\\Microsoft\\AMSI\\Providers\\%"
  )
  | SELECT event.timestamp AS _time,
           agent.hostname AS dest,
           user.name AS user,
           "AMSI/ETW Configuration Tampering" AS AnomalyType,
           CONCAT("Action: ", event.action, ", Key: ", registry.path, ", Value: ", registry.value.data) AS Details,
           process.name AS process_name,
           event.action AS action,
           registry.path AS registry_path,
           registry.value.data AS registry_value_data
)
```