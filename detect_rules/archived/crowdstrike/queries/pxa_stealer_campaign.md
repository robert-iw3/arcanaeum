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
event_platform=Win event_simpleName=ProcessRollup2 FileName=/.*\.cmd$/ (ParentBaseFileName=WINWORD.EXE OR ParentBaseFileName=POWERPNT.EXE OR ParentBaseFileName=EXCEL.EXE OR ParentBaseFileName=/.*Haihaisoft.*/)
| stats min(timestamp) as firstTime, max(timestamp) as lastTime, count() as count by ComputerName, UserName, ParentBaseFileName, TargetFileName, FileName
| fields firstTime, lastTime, ComputerName, UserName, ParentBaseFileName, TargetFileName, FileName, count
```

### Certutil Decoding Unusual Files
---
```sql
event_platform=Win event_simpleName=ProcessRollup2 FileName=certutil.exe CommandLine=/.*-decode.*/
| search CommandLine=/.*\.(pdf|jpg|png)\s+.*\.(rar|zip|pdf|exe)/
| stats min(timestamp) as firstTime, max(timestamp) as lastTime, count() as count, values(CommandLine) as process, values(ParentBaseFileName) as parent_process by ComputerName, UserName
| extract CommandLine=/.*-decode\s+(?<input_file>\S+)\s+(?<output_file>\S+)/
| fields firstTime, lastTime, ComputerName, UserName, parent_process, process, input_file, output_file, count
```

### WinRAR Execution from Non-Standard Path
---
```sql
event_platform=Win event_simpleName=ProcessRollup2 (FileName=WinRAR.exe OR FileName=rar.exe OR FileName=images.png) CommandLine=/.*( x | e ).*/ CommandLine=/.*C:\\Users\\Public.*/
| search NOT (FilePath=/.*\\Program Files\\.*|.*\\Program Files \(x86\)\\.*/)
| stats min(timestamp) as firstTime, max(timestamp) as lastTime, count() as count, values(FilePath) as process_path, values(CommandLine) as process, values(ParentBaseFileName) as parent_process by ComputerName, UserName, FileName
| fields firstTime, lastTime, ComputerName, UserName, parent_process, FileName, process_path, process, count
```

### Registry Run Key Modification for Persistence
---
```sql
event_platform=Win event_simpleName=RegKeyWritten RegistryKeyPath=/.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run.*/ RegistryValue=/.*cmd(\.exe)? \/c start.*C:\\Users\\Public.*/
| stats min(timestamp) as firstTime, max(timestamp) as lastTime, count() as count, values(RegistryKeyPath) as registry_path, values(RegistryValueName) as registry_key_name, values(RegistryValue) as registry_value_data by ComputerName, UserName
| fields firstTime, lastTime, ComputerName, UserName, registry_path, registry_key_name, registry_value_data, count
```

### PXA Stealer C2 and Staging Domains
---
```sql
event_platform=Win event_simpleName=NetworkConnectIP4 (DomainName=paste.rs OR DomainName=0x0.st OR DomainName=lp2tpju9yrz2fklj.lone-none-1807.workers.dev)
| stats min(timestamp) as firstTime, max(timestamp) as lastTime, count() as count by SourceIpAddress, DestinationIpAddress, UserName, DomainName
| fields firstTime, lastTime, SourceIpAddress, DestinationIpAddress, UserName, DomainName, count
```