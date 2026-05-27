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
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created AND Filesystem.file_name="*.cmd" AND (Filesystem.process_name IN ("WINWORD.EXE", "POWERPNT.EXE", "EXCEL.EXE") OR Filesystem.process_name="*Haihaisoft*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name
`comment("This search looks for the creation of command (.cmd) script files by legitimate applications like Microsoft Office or Haihaisoft PDF Reader. This behavior is a key TTP of PXA Stealer, which uses a sideloaded DLL within the legitimate application's process to drop a script that orchestrates the infection chain.")`
| `drop_dm_object_name("Filesystem")`
`comment("Legitimate enterprise tools or add-ins may rarely exhibit this behavior. If false positives occur, consider filtering by specific file paths, users, or parent processes that are known to be benign in your environment.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rename process_name as creating_process
| fields firstTime, lastTime, dest, user, creating_process, file_path, file_name, count
```

### Certutil Decoding Unusual Files
---
```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process from datamodel=Endpoint.Processes where Processes.process_name="certutil.exe" AND Processes.process="*-decode*" by Processes.dest Processes.user
`comment("Filter for certutil.exe executions that include the -decode flag, a common tool for decoding base64 data.")`
| `drop_dm_object_name("Processes")`
| rex field=process "(?i)-decode\s+(?<input_file>\S+)\s+(?<output_file>\S+)"
`comment("Extract the input and output filenames from the command line to analyze the file types involved.")`
| where (like(input_file, "%.pdf") OR like(input_file, "%.jpg") OR like(input_file, "%.png")) AND (like(output_file, "%.rar") OR like(output_file, "%.zip") OR like(output_file, "%.pdf") OR like(output_file, "%.exe"))
`comment("Identify suspicious decoding where a non-executable file (like a PDF or image) is decoded into an archive or executable. PXA Stealer specifically decodes a PDF into a RAR or another PDF to hide its payload.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| fields firstTime, lastTime, dest, user, parent_process, process, input_file, output_file, count
```

### WinRAR Execution from Non-Standard Path
---
```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process_path) as process_path values(Processes.process) as process values(Processes.parent_process_name) as parent_process from datamodel=Endpoint.Processes where (Processes.process_name IN ("WinRAR.exe", "rar.exe", "images.png")) AND (Processes.process="* x *" OR Processes.process="* e *") AND Processes.process IN ("*C:\\Users\\Public*", "*C:/Users/Public*") by Processes.dest Processes.user Processes.process_name
`comment("Look for WinRAR, rar.exe, or a masquerading process like images.png executing an extraction command to the C:\\Users\\Public directory, a TTP used by PXA Stealer.")`
| `drop_dm_object_name("Processes")`
| where NOT (like(process_path, "%\\Program Files\\%") OR like(process_path, "%\\Program Files (x86)\\%"))
`comment("Filter out executions from standard installation paths to focus on portable or dropped versions of the utility.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
`comment("While uncommon, legitimate use of portable archive utilities could trigger this alert. If false positives occur, consider filtering by parent processes or specific users known to perform such actions.")`
| fields firstTime, lastTime, dest, user, parent_process, process_name, process_path, process, count
```

### Registry Run Key Modification for Persistence
---
```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_path) as registry_path values(Registry.registry_key_name) as registry_key_name values(Registry.registry_value_data) as registry_value_data from datamodel=Endpoint.Registry where Registry.registry_path = "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" AND (Registry.registry_value_data LIKE "%cmd.exe /c start%" OR Registry.registry_value_data LIKE "%cmd /c start%") AND (Registry.registry_value_data LIKE "%C:\\Users\\Public\\%" OR Registry.registry_value_data LIKE "%C:/Users/Public/%") by Registry.dest, Registry.user
`comment("Look for modifications to the Run registry key that launch cmd.exe to start a process from the C:\\Users\\Public directory. This is a specific persistence TTP used by PXA Stealer.")`
| `drop_dm_object_name("Registry")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
`comment("While legitimate software can use Run keys, the combination of using cmd.exe to launch a process from the Public directory is highly suspicious. If false positives occur, consider excluding specific registry_key_names or processes known to be benign in your environment.")`
| fields firstTime, lastTime, dest, user, registry_path, registry_key_name, registry_value_data, count
```

### PXA Stealer C2 and Staging Domains
---
```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where Network_Traffic.dest_domain IN ("paste.rs", "0x0.st", "lp2tpju9yrz2fklj.lone-none-1807.workers.dev") by Network_Traffic.src, Network_Traffic.dest, Network_Traffic.user, Network_Traffic.dest_domain
`comment("This search looks for network traffic to domains known to be used by PXA Stealer for hosting payloads and exfiltrating data.")`
| `drop_dm_object_name("Network_Traffic")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
`comment("The domains paste.rs and 0x0.st are legitimate file-sharing services that can be abused. The Cloudflare worker domain is highly specific to this threat. Investigate the source of the traffic and any related process activity.")`
| fields firstTime, lastTime, src, dest, user, dest_domain, count
```