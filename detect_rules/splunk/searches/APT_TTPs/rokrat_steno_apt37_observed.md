### RoKRAT Steganographic Shellcode Threat Report
---

APT37, a North Korean state-sponsored threat actor, is actively deploying new variants of the RoKRAT malware, utilizing sophisticated steganography techniques to embed malicious shellcode within image files and employing multi-stage encrypted shellcode injection to evade detection. This fileless approach, often initiated via malicious LNK files, allows the malware to operate stealthily and exfiltrate data through legitimate cloud services, posing a significant challenge to traditional security solutions.

A significant new finding is the observed shift in RoKRAT's infection chain from primarily cloud-reliant payloads to self-contained LNK files, which now embed encrypted shellcode directly. This adaptation demonstrates the threat actor's continuous evolution to bypass security defenses and minimize reliance on external servers, making detection more challenging.

### Actionable Threat Data
---

Monitor for unusually large LNK files (e.g., ~54MB) that may contain embedded components like decoy documents, shellcode, PowerShell commands, and batch scripts, as these are used for initial compromise.

Detect PowerShell commands performing XOR operations on file contents, especially those involving single-byte keys (e.g., 0x33, 0xAA, 0x29), as this indicates shellcode decoding.

Look for process injection attempts into legitimate Windows processes like mspaint.exe or notepad.exe from unusual directories (e.g., C:\Windows\SysWOW64), as RoKRAT uses these for fileless execution.

Identify outbound network connections to legitimate cloud storage services (e.g., api.pcloud.com, cloud-api.yandex.net, api.dropboxapi.com) that exhibit suspicious behavior or originate from processes not typically associated with cloud synchronization.

Monitor for DLL side-loading attempts where legitimate executables (e.g., ShellRunas.exe, AccessEnum.exe, Hhc.exe) load malicious DLLs (e.g., credui.dll, mpr.dll, hha.dll) that then download and process image files containing hidden payloads.

### Large LNK File
---
```sql
-- Name of detection: Large LNK File
-- Author: RW
-- Date: 2025-08-05
-- MITRE TTPs: T1204.001, T1566.001
-- Malware Family: RoKRAT

`comment("This detection rule identifies the creation of unusually large LNK files, a technique observed in RoKRAT malware campaigns where payloads are embedded directly into the shortcut file.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*.lnk" OR Filesystem.file_name="*.lnk") AND Filesystem.file_size > 10485760 by Filesystem.dest, Filesystem.user, Filesystem.file_name, Filesystem.file_path, Filesystem.file_size
| `drop_dm_object_name("Filesystem")`
| `convert ctime(firstTime) ctime(lastTime)`
| `eval file_size_mb = round(file_size/1024/1024, 2)`
| `comment("The file size threshold is set to 10MB, as legitimate LNK files are typically only a few kilobytes. This may need tuning based on environment, but is a strong indicator of embedded content. If legitimate large LNK files exist, consider adding them to an allowlist.")`
| table firstTime, lastTime, dest, user, file_name, file_path, file_size_mb
```

### PowerShell XOR Decoding
---
```sql
-- Name of detection: PowerShell XOR Payload Decoding
-- Author: RW
-- Date: 2025-08-05
-- MITRE TTPs: T1027, T1059.001
-- Malware Family: RoKRAT

`comment("This detection rule identifies PowerShell execution containing the '-bxor' operator used in conjunction with reading file content. This is a technique often used for decoding malicious payloads, as observed in RoKRAT malware campaigns to decode embedded shellcode from a file.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe") AND Processes.process="*-bxor*" AND Processes.process="*Get-Content*" by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process
| `drop_dm_object_name("Processes")`
| `convert ctime(firstTime) ctime(lastTime)`
| `comment("The combination of 'Get-Content' and '-bxor' in a PowerShell command is a strong indicator of file-based payload decoding. Legitimate use is uncommon.")`
| `comment("FP Tuning: If legitimate scripts perform this action, consider adding the specific command line or parent process to an allowlist.")`
| table firstTime, lastTime, dest, user, parent_process_name, process
```

### Process Injection
---
```sql
-- Name of detection: RoKRAT Process Injection into Common Utilities
-- Author: RW
-- Date: 2025-08-05
-- MITRE TTPs: T1055
-- Malware Family: RoKRAT

`comment("This detection rule identifies process injection into common Windows utilities like mspaint.exe and notepad.exe. This technique is used by RoKRAT malware for defense evasion and fileless execution.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `cim_process_injection_filter` AND (Processes.target_process_name IN ("mspaint.exe", "notepad.exe")) by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.target_process_name, Processes.target_process_path
| `drop_dm_object_name("Processes")`
| `convert ctime(firstTime) ctime(lastTime)`
| `comment("This logic relies on EDR data that identifies process injection events. The macro 'cim_process_injection_filter' and fields like 'target_process_name' may need to be customized for your specific data sources.")`
| `comment("FP Tuning: Legitimate software, such as accessibility tools or screen readers, may inject into processes. If false positives occur, investigate the source process (process_name) and consider adding it to an allowlist if the behavior is expected.")`
| table firstTime, lastTime, dest, user, process_name, process, target_process_name, target_process_path
```

### Cloud C2 Communication
---
```sql
-- Name of detection: Suspicious Cloud Storage C2 Communication
-- Author: RW
-- Date: 2025-08-05
-- MITRE TTPs: T1071.001, T1102
-- Malware Family: RoKRAT

`comment("This detection rule identifies network connections to known RoKRAT C2 domains associated with legitimate cloud services. It filters for connections originating from processes not typically associated with these services.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Network_Traffic where (Network_Traffic.dest_host IN ("api.pcloud.com", "cloud-api.yandex.net", "api.dropboxapi.com")) AND NOT (Network_Traffic.process_name IN ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "Dropbox.exe", "pCloud.exe")) by Network_Traffic.dest, Network_Traffic.user, Network_Traffic.process_name, Network_Traffic.dest_host
| `drop_dm_object_name("Network_Traffic")`
| `convert ctime(firstTime) ctime(lastTime)`
| `comment("The rule looks for connections to specific cloud API domains used by RoKRAT and excludes common web browsers and legitimate client applications to reduce noise.")`
| `comment("FP Tuning: Legitimate third-party applications may use these cloud APIs. If false positives occur, investigate the process_name and consider adding it to the allowlist if the behavior is expected and sanctioned.")`
| table firstTime, lastTime, dest, user, process_name, dest_host
```

### DLL Side-Loading
---
```sql
-- Name of detection: RoKRAT DLL Side-Loading
-- Author: RW
-- Date: 2025-08-05
-- MITRE TTPs: T1574.001
-- Malware Family: RoKRAT

`comment("This detection rule identifies specific instances of DLL side-loading used by RoKRAT malware, where legitimate executables are abused to load malicious DLLs.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Image_Loads where (Image_Loads.process_name IN ("ShellRunas.exe", "AccessEnum.exe", "Hhc.exe")) AND (Image_Loads.image_name IN ("credui.dll", "mpr.dll", "hha.dll")) by Image_Loads.dest, Image_Loads.user, Image_Loads.process_name, Image_Loads.image_name
| `drop_dm_object_name("Image_Loads")`
| `convert ctime(firstTime) ctime(lastTime)`
| `comment("This logic looks for known vulnerable executables loading specific DLLs known to be used by RoKRAT.")`
| `comment("FP Tuning: While this combination is highly suspicious, it's possible for legitimate software to use these names. If false positives occur, investigate the file paths and hashes of the involved files to confirm legitimacy.")`
| table firstTime, lastTime, dest, user, process_name, image_name
```

### RoKRAT Hashes
---
```sql
-- Name of detection: RoKRAT Malware Hashes
-- Author: RW
-- Date: 2025-08-05
-- Malware Family: RoKRAT

`comment("This detection rule identifies known malicious file hashes associated with the RoKRAT malware family.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("a2ee8d2aa9f79551eb5dd8f9610ad557", "ae7e18a62abb7f93b657276dcae985b9", "d5fe744b9623a0cc7f0ef6464c5530da", "f6d72abf9ca654a20bbaf23ea1c10a55", "fd9099005f133f95a5b699ab30a2f79b", "5ed95cde6c29432a4f7dc48602f82734", "16a8aaaf2e3125668e6bfb1705a065f9", "64d729d0290e2c8ceaa6e38fa68e80e9", "443a00feeb3beaea02b2fbcd4302a3c9", "e13c3a38ca58fb0fa9da753e857dd3d5", "e4813c34fe2327de1a94c51e630213d1") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process, Processes.process_hash
| `drop_dm_object_name("Processes")`
| `convert ctime(firstTime) ctime(lastTime)`
| `comment("This search leverages a list of known malicious MD5 hashes. Detections are high-fidelity and indicate a confirmed compromise.")`
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process, process_hash
```