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
event.type = File AND file.extension = "cmd" AND event.action = "created"
AND (process.name IN ("WINWORD.EXE", "POWERPNT.EXE", "EXCEL.EXE") OR process.name LIKE "%Haihaisoft%")
| group by endpoint.name, user.name, process.name, file.path, file.name
| select min(event.time) as firstTime, max(event.time) as lastTime, count(*) as count, endpoint.name, user.name, process.name as creating_process, file.path, file.name
| format firstTime as "yyyy-MM-dd'T'HH:mm:ss.SSSZ", lastTime as "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
```

### Certutil Decoding Unusual Files
---
```sql
event.type = Process AND process.name = "certutil.exe" AND process.cmdLine LIKE "%-decode%"
AND process.cmdLine MATCHES ".*\.(pdf|jpg|png)\s+.*\.(rar|zip|pdf|exe)"
| extract input_file = ".*-decode\\s+(\\S+)\\s+\\S+", output_file = ".*-decode\\s+\\S+\\s+(\\S+)"
| group by endpoint.name, account.name
| select min(event.createdAt) as firstTime, max(event.createdAt) as lastTime, count(*) as count,
        collect(process.cmdLine) as process, collect(process.parentName) as parent_process,
        input_file, output_file
| format firstTime as "yyyy-MM-dd'T'HH:mm:ss.SSSZ", lastTime as "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
```

### WinRAR Execution from Non-Standard Path
---
```sql
event.type = Process AND process.name IN ("WinRAR.exe", "rar.exe")
AND process.cmdLine MATCHES ".*( x | e ).*"
AND process.cmdLine LIKE "%C:\\Users\\Public%"
AND NOT (process.path LIKE "%\\Program Files\\%" OR process.path LIKE "%\\Program Files (x86)\\%")
| group by endpoint.name, account.name, process.name
| select min(event.createdAt) as firstTime, max(event.createdAt) as lastTime, count(*) as count,
        collect(process.path) as process_path, collect(process.cmdLine) as process,
        collect(process.parentName) as parent_process
| format firstTime as "yyyy-MM-dd'T'HH:mm:ss.SSSZ", lastTime as "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
```

### Registry Run Key Modification for Persistence
---
```sql
event.type = Registry AND registry.path LIKE "%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run%"
AND registry.valueData MATCHES ".*cmd(\\.exe)?\\s+/c\\s+start.*C:\\\\Users\\\\Public.*"
| group by endpoint.name, account.name
| select min(event.createdAt) as firstTime, max(event.createdAt) as lastTime, count(*) as count,
        collect(registry.path) as registry_path,
        collect(registry.valueName) as registry_key_name,
        collect(registry.valueData) as registry_value_data
| format firstTime as "yyyy-MM-dd'T'HH:mm:ss.SSSZ", lastTime as "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
```

### PXA Stealer C2 and Staging Domains
---
```sql
event.type = NETWORK_HTTP AND network.destination.domain IN ("paste.rs", "0x0.st", "lp2tpju9yrz2fklj.lone-none-1807.workers.dev")
| group by network.source.ip, network.destination.ip, account.name, network.destination.domain
| select min(event.createdAt) as firstTime, max(event.createdAt) as lastTime, count(*) as count,
        network.source.ip, network.destination.ip, account.name, network.destination.domain
| format firstTime as "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", lastTime as "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
```