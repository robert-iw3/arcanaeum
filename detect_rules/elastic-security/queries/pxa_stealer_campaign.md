### PXA Stealer Campaign Analysis
---

The PXA Stealer is a Python-based infostealer operated by Vietnamese-speaking cybercriminals, utilizing sophisticated multi-stage delivery mechanisms including DLL sideloading with legitimate applications and leveraging Telegram for C2 and data exfiltration. This campaign highlights a growing trend of threat actors weaponizing legitimate infrastructure for efficient information theft and monetization.

Recent observations in July 2025 show an evolution in the PXA Stealer's evasion techniques, including the use of legitimate Microsoft Word 2013 for DLL sideloading and the incorporation of non-malicious decoy documents to frustrate analysis and delay detection. The stealer also now targets a broader range of browsers for DLL injection, specifically including MSEdge, Chrome, Whale, and CocCoc, indicating an expanded focus on credential harvesting from diverse web environments.

### Actionable Threat Data
---

Monitor for the creation of `.cmd` scripts (e.g., `Evidence.cmd`) in user-accessible directories, especially when initiated by legitimate applications like Haihaisoft PDF Reader or Microsoft Word.

Detect `certutil.exe` being used to decode files with unusual extensions (e.g., `.pdf` into `.rar` or .pdf) or from unexpected locations, particularly when followed by archive extraction utilities.

Look for the execution of WinRAR (or executables renamed to `images.png`) from non-standard paths, especially when extracting content to `C:\Users\Public\` and followed by the execution of a Python interpreter renamed to `svchost.exe`.

Monitor for modifications to the `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` registry key that launch `cmd.exe` with a `start /min` command pointing to executables in `C:\Users\Public\`, particularly if they are Python interpreters or scripts.

Identify network connections to `paste[.]rs`, `0x0[.]st`, or `lp2tpju9yrz2fklj.lone-none-1807[.]workers[.]dev`, as these are used for staging additional payloads and exfiltrating stolen data.

### Suspicious CMD Script Creation
---
```sql
FROM *
| WHERE event.action == "create" AND file.extension == "cmd"
  AND (process.name IN ("WINWORD.EXE", "POWERPNT.EXE", "EXCEL.EXE") OR process.name ILIKE "*Haihaisoft*")
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.name, file.path, file.name
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| KEEP firstTime, lastTime, host.name, user.name, process.name, file.path, file.name, count
| RENAME process.name AS creating_process
```

### Certutil Decoding Unusual Files
---
```sql
FROM *
| WHERE process.name == "certutil.exe" AND process.command_line ILIKE "*-decode*"
  AND process.command_line RLIKE ".*\\.(pdf|jpg|png)\\s+.*\\.(rar|zip|pdf|exe)"
| EVAL input_file = REGEXP_SUBSTR(process.command_line, "-decode\\s+(\\S+)\\s+(\\S+)", 1),
        output_file = REGEXP_SUBSTR(process.command_line, "-decode\\s+(\\S+)\\s+(\\S+)", 2)
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp),
        process = ARRAY_AGG(process.command_line), parent_process = ARRAY_AGG(process.parent.name)
  BY host.name, user.name
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| KEEP firstTime, lastTime, host.name, user.name, parent_process, process, input_file, output_file, count
```

### WinRAR Execution from Non-Standard Path
---
```sql
FROM *
| WHERE process.name IN ("WinRAR.exe", "rar.exe", "images.png")
  AND process.command_line RLIKE ".*( x | e ).*"
  AND process.command_line ILIKE "*C:\\Users\\Public*"
  AND NOT (process.executable ILIKE "%\\Program Files\\%" OR process.executable ILIKE "%\\Program Files (x86)\\%")
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp),
        process_path = ARRAY_AGG(process.executable), process = ARRAY_AGG(process.command_line),
        parent_process = ARRAY_AGG(process.parent.name)
  BY host.name, user.name, process.name
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| KEEP firstTime, lastTime, host.name, user.name, parent_process, process.name, process_path, process, count
```

### Registry Run Key Modification for Persistence
---
```sql
FROM *
| WHERE registry.path ILIKE "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*"
  AND registry.data.strings RLIKE ".*cmd(\\.exe)?\\s+/c\\s+start.*C:\\\\Users\\\\Public.*"
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp),
        registry_path = ARRAY_AGG(registry.path),
        registry_key_name = ARRAY_AGG(registry.key),
        registry_value_data = ARRAY_AGG(registry.data.strings)
  BY host.name, user.name
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| KEEP firstTime, lastTime, host.name, user.name, registry_path, registry_key_name, registry_value_data, count
```

### PXA Stealer C2 and Staging Domains
---
```sql
FROM *
| WHERE network.direction == "outbound"
  AND destination.domain IN ("paste.rs", "0x0.st", "lp2tpju9yrz2fklj.lone-none-1807.workers.dev")
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY source.ip, destination.ip, user.name, destination.domain
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| KEEP firstTime, lastTime, source.ip, destination.ip, user.name, destination.domain, count
```