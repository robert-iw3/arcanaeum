### GIFTEDCROOK's Strategic Pivot to Data Exfiltration
---

The cyber-espionage group UAC-0226 has significantly evolved its GIFTEDCROOK malware from a basic browser stealer to a robust intelligence-gathering tool, primarily targeting Ukrainian governmental and military entities. This evolution, observed through versions 1.2 and 1.3, enables the exfiltration of sensitive documents and browser secrets, often coinciding with critical geopolitical events.


GIFTEDCROOK has significantly expanded its capabilities beyond browser data theft to include comprehensive document exfiltration, now targeting files modified within the last 45 days and increasing the file size limit to 7 MB. This shift indicates a strategic focus on intelligence gathering, aligning with geopolitical objectives.

### Actionable Threat Data
---

Initial Access & Execution: Spear-phishing emails with military-themed PDF lures containing weaponized links to `Mega[.]nz-hosted` malicious OLE documents (.xlsm). These documents prompt users to enable macros, which then extract and execute a portable executable (PE) file.

Persistence & Evasion: The malware drops its PE implant in `%ProgramData%\Infomaster\Infomaster` or `%ProgramData%\PhoneInfo\PhoneInfo` and employs sleep evasion techniques to bypass sandboxing.

Data Collection: GIFTEDCROOK collects browser data (cookies, login data, local state, key4.db, logins.json, places.sqlite) from Chrome, Edge, and Firefox. It also targets a wide range of file types (e.g., .doc, .docx, .pdf, .rar, .zip, .eml, .txt, .sqlite, .ovpn) up to 7 MB, modified within the last 45 days.

Data Exfiltration: Exfiltrated data is compressed into a zip archive, encrypted using a custom XOR algorithm, and then sent to attacker-controlled Telegram bot channels. If the archive exceeds 20 MB, it is split into multiple parts.

Defense Evasion (Cleanup): After exfiltration, a batch script (Infomaster_delete.bat) is executed to self-delete the original infostealer and remove traces from the system.

### Malicious Macro Execution
---
```sql
`comment("This detection rule identifies potential malicious macro execution, a common technique used by threats like GIFTEDCROOK. It detects when a Microsoft Office application spawns a command shell, scripting engine, or an executable from a suspicious, user-writable directory.")`
`comment("The specific paths used by GIFTEDCROOK (*\\ProgramData\\Infomaster\\*, *\\ProgramData\\PhoneInfo\\*) are covered by the broader *\\ProgramData\\* search and are flagged for easier identification.")`

tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where
    (Processes.parent_process_name IN ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")) AND
    (
        `comment("Detects spawning of common scripting engines and shells used to execute malicious code.")`
        Processes.process_name IN ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe") OR
        `comment("Detects execution from suspicious directories where malware often drops its payload. This may need tuning to exclude legitimate applications in your environment.")`
        Processes.process_path IN ("*\\ProgramData\\*", "*\\Users\\Public\\*", "*\\AppData\\Local\\Temp\\*")
    )
    by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path

| `drop_dm_object_name("Processes")`
`comment("Flag events that match the specific GIFTEDCROOK paths for high-fidelity alerting.")`
| eval is_giftedcrook_ioc = if(match(process_path, "(?i)(\\ProgramData\\Infomaster|\\ProgramData\\PhoneInfo)"), "True", "False")

`comment("Group the results to provide a summary of the activity.")`
| stats count, values(process) as process_commandlines by dest, user, parent_process_name, process_name, process_path, is_giftedcrook_ioc, firstTime, lastTime

`comment("Rename fields for clarity and consistency.")`
| rename dest as endpoint, user as user, parent_process_name as parent_process, process_name as child_process, process_path as child_process_path
| fields - _*

`comment("The following custom macro is a placeholder for any additional filtering or tuning specific to your environment, such as excluding known good processes or parent-child relationships.")`
| `giftedcrook_malicious_macro_execution_filter`
```

### GIFTEDCROOK PE Dropped
---
```sql
`comment("This rule detects the execution of the GIFTEDCROOK PE implant from its known installation paths, which is a strong indicator of compromise.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process_commandline from datamodel=Endpoint.Processes
where
    `comment("IOCs are based on specific file paths used by GIFTEDCROOK versions 1.2 and 1.3.")`
    (Processes.process_path="*\\ProgramData\\Infomaster\\Infomaster*" OR Processes.process_path="*\\ProgramData\\PhoneInfo\\PhoneInfo*")
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path
| `drop_dm_object_name("Processes")`

`comment("Rename fields for clarity and consistency.")`
| rename dest as endpoint, user as user, parent_process_name as parent_process, process_name as child_process, process_path as child_process_path

`comment("Placeholder for environment-specific filtering, though these IOCs are high-fidelity.")`
| `giftedcrook_pe_dropped_filter`
```

### Telegram Bot Exfiltration
---
```sql
`comment("This rule detects potential data exfiltration to the Telegram API, a technique used by malware such as GIFTEDCROOK.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.url) as url, sum(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic
where
    `comment("The destination is the primary Telegram API domain.")`
    All_Traffic.dest_host = "api.telegram.org"
by All_Traffic.src, All_Traffic.dest, All_Traffic.user, All_Traffic.process_name
| `drop_dm_object_name("All_Traffic")`

`comment("Rename fields for clarity and consistency.")`
| rename src as src_ip, dest as dest_ip

`comment("Potential for false positives exists if legitimate applications use the Telegram API. Tune this rule by filtering for unexpected processes, high data volumes, or specific source IPs.")`
| `telegram_api_exfil_filter`
```

### Browser Data Theft
---
```sql
`comment("This rule detects non-browser processes accessing sensitive browser files, a TTP associated with credential stealers like GIFTEDCROOK.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path from datamodel=Endpoint.Filesystem
where
    `comment("Exclude legitimate browser processes to reduce false positives. This list may need to be tuned for your environment.")`
    Filesystem.process_name NOT IN ("chrome.exe", "msedge.exe", "firefox.exe", "browser_broker.exe", "opera.exe", "brave.exe") AND
    (
        `comment("Paths for Chromium-based browsers (Chrome, Edge, etc.)")`
        Filesystem.file_path IN (
            "*\\Google\\Chrome\\User Data\\*\\Cookies",
            "*\\Google\\Chrome\\User Data\\*\\Login Data",
            "*\\Google\\Chrome\\User Data\\*\\Local State",
            "*\\Microsoft\\Edge\\User Data\\*\\Cookies",
            "*\\Microsoft\\Edge\\User Data\\*\\Login Data",
            "*\\Microsoft\\Edge\\User Data\\*\\Local State"
        ) OR
        `comment("Paths for Firefox browser.")`
        Filesystem.file_path IN (
            "*\\Mozilla\\Firefox\\Profiles\\*\\key4.db",
            "*\\Mozilla\\Firefox\\Profiles\\*\\logins.json",
            "*\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite",
            "*\\Mozilla\\Firefox\\Profiles\\*\\cookies.sqlite"
        )
    )
by Filesystem.dest, Filesystem.user, Filesystem.process_name
| `drop_dm_object_name("Filesystem")`

`comment("Rename fields for clarity and consistency.")`
| rename dest as endpoint, process_name as suspicious_process

`comment("This activity is highly suspicious. However, some backup or security tools might access these files. Add known-good processes to the exclusion list in the main query or filter them here.")`
| `browser_data_theft_filter`
```

### Suspicious File Deletion
---
```sql
`comment("This rule detects suspicious file deletion activity, a technique used by malware like GIFTEDCROOK for cleanup. It looks for the command prompt deleting executables or files in suspicious locations, or a batch script attempting to delete itself.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
where
    `comment("Focus on the command prompt as the executor of the deletion.")`
    Processes.process_name = "cmd.exe" AND
    (
        `comment("Detects deletion of executables or files in common malware drop locations. This covers the specific GIFTEDCROOK behavior of deleting its implant from ProgramData.")`
        (Processes.process LIKE "% del %" OR Processes.process LIKE "% erase %") AND
        (Processes.process LIKE "%*.exe%" OR Processes.process LIKE "%\\ProgramData\\%" OR Processes.process LIKE "%\\AppData\\Local\\Temp\\%")
        OR
        `comment("Detects self-deleting batch scripts, a common malware cleanup technique.")`
        Processes.process LIKE "%del%~f0%" OR Processes.process LIKE "%del%~0%"
    )
by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process
| `drop_dm_object_name("Processes")`

`comment("Rename fields for clarity and consistency.")`
| rename dest as endpoint, parent_process_name as parent_process, process as command_line

`comment("This behavior can be legitimate for some software installers/uninstallers. Filter out known-good parent processes or scripts if necessary.")`
| `suspicious_file_deletion_filter`
```
