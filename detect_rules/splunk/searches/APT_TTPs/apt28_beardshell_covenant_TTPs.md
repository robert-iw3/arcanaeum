### APT28 Cyber Attacks on Government Agencies Using BEARDSHELL and COVENANT
---

APT28, a Russian state-sponsored threat actor, has been observed targeting Ukrainian government agencies with new malware families, BEARDSHELL and COVENANT. The attacks leverage social engineering via Signal messages to deliver malicious documents, ultimately leading to the deployment of backdoors and data exfiltration.

A significant new finding is APT28's use of Signal for initial access and delivery of malicious documents, exploiting the platform's widespread use in official communications to enhance the credibility of their social engineering tactics. This is noteworthy as it highlights the group's adaptability in leveraging legitimate communication channels to bypass traditional security controls.

### Actionable Threat Data
---

Initial Access & Execution (T1566.001, T1204.002):

Malicious Word documents ("`Акт.doc`") delivered via Signal messages containing `macros` that drop `ctec.dll` and `windows.png` (shellcode).

Monitor for `.doc` files delivered via messaging applications, especially those containing macros.

Look for the creation of `ctec.dll` in `%APPDATA%\microsoft\protect\` and windows.png in `%LOCALAPPDATA%`.

Persistence (T1546.008):

COM hijacking by creating registry keys under `HKCU\Software\Classes\CLSID\{2227A280–3AEA-1069-A2DE-08002B30309D}\InProcServer32` and `HKEY_CURRENT_USER\Software\Classes\CLSID\{2DEA658F-54C1–4227-AF9B-260AB5FC3543}\InProcServer32` to load malicious DLLs (`ctec.dll`, `PlaySndSrv.dll`) when `explorer.exe` or the `SystemSoundsService` scheduled task starts.

Detect modifications to `HKCU\Software\Classes\CLSID\` for `InProcServer32` entries, particularly those pointing to unusual DLL paths.

Monitor for the creation or modification of the `Microsoft\Windows\Multimedia\SystemSoundsService` scheduled task.

Defense Evasion & Command and Control (T1027, T1071.001):

Use of legitimate services like `Icedrive (api.icedrive[.]net)` and `Koofr (app.koofr[.]net)` for C2 communication and data exfiltration. `BEARDSHELL` uses `chacha20-poly1305` for decryption of PowerShell scripts.

Monitor network connections to `api.icedrive[.]net` and `app.koofr[.]net`.

Look for PowerShell script execution that involves `chacha20-poly1305` decryption.

Discovery (T1119):

`SLIMAGENT` malware captures screenshots and saves them locally in `%TEMP%\Desktop_%d-%m-%%Y_%H-%M-%S.svc`.

Monitor for the creation of `.svc` files in the `%TEMP%` directory, especially with names following the `Desktop_` pattern.

Malware Dropped: `ksmqsyck.dx4.exe` (COVENANT framework component), `PlaySndSrv.dll`, `sample-03.wav` (shellcode), `BeardShell.dll` (BEARDSHELL backdoor).

Monitor for the creation and execution of these specific file names and their associated hashes.

### APT28 Malicious Document Dropping BEARDSHELL/COVENANT Loaders
---
```sql
`comment(
APT28 Malicious Document Dropping BEARDSHELL/COVENANT Loaders

Detects a Microsoft Word process creating files in locations known to be used by an APT28 campaign. This activity is associated with the execution of a malicious macro from a document, which drops a loader DLL (`ctec.dll`) and a file containing shellcode (`windows.png`).

tags:
   - attack.initial_access
   - attack.execution
   - attack.t1566.001
   - attack.t1204.002
   - threat_actor.apt28
   - malware.beardshell
   - malware.covenant

falsepositives:
   - The filename `windows.png` is generic. However, the likelihood of a legitimate user saving a file with this specific name from Word into the `AppData\Local` directory is low. This detection is best scoped to user workstations.

level: high

This search requires data from file creation events (e.g., Sysmon Event Code 11) mapped to the Endpoint.Filesystem data model.
)`

| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where \
  # Parent process is Microsoft Word.
  Filesystem.parent_process_name="*\\winword.exe" AND \
  # Specific malicious files dropped by the macro.
  (Filesystem.file_path="*\\AppData\\Roaming\\Microsoft\\Protect\\ctec.dll" OR Filesystem.file_path="*\\AppData\\Local\\windows.png") \
  by Filesystem.dest, Filesystem.user, Filesystem.parent_process_name, Filesystem.file_path, _time span=1h \
| `drop` count \
| `rename` Filesystem.dest as dest, Filesystem.user as user, Filesystem.parent_process_name as parent_process, Filesystem.file_path as file_path \
| `convert` ctime(_time) as timestamp
```

### APT28 COM Hijacking - Detects Persistence via Registry Modification
---
```sql
`comment(

APT28 COM Hijacking for Persistence

Detects COM hijacking techniques used by APT28 for persistence. The threat actor modifies specific CLSID InProcServer32 registry keys to point to their malicious DLLs, which are then loaded by legitimate processes like explorer.exe or the SystemSoundsService scheduled task.

tags:
   - attack.persistence
   - attack.t1546.015
   - threat_actor.apt28
   - malware.beardshell
   - malware.covenant

falsepositives:
   - This detection is highly specific to the APT28 campaign and is unlikely to generate false positives.

level: high

This search requires data from registry modification events (e.g., Sysmon Event Code 13) mapped to the Endpoint.Registry data model.
)`

`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where \
  # Match one of the specific CLSID InProcServer32 paths targeted by APT28.
  (Registry.registry_path="*\\Software\\Classes\\CLSID\\{2227A280-3AEA-1069-A2DE-08002B30309D}\\InProcServer32*" OR Registry.registry_path="*\\Software\\Classes\\CLSID\\{2DEA658F-54C1-4227-AF9B-260AB5FC3543}\\InProcServer32*") AND \
  # Match the value being set to one of the malicious DLLs.
  (Registry.registry_value_data="*\\ctec.dll" OR Registry.registry_value_data="*\\PlaySndSrv.dll") \
  by Registry.dest, Registry.user, Registry.process_name, Registry.registry_path, Registry.registry_value_data \
| `drop_dm_object_name("Registry")` \
| `rename` dest as host, process_name as process, registry_path as target_object, registry_value_data as details \
| `convert` ctime(firstTime) ctime(lastTime)
```

### APT28 C2 Communication via Icedrive and Koofr Cloud Services
---
```sql
`tstats` summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (Network_Traffic.dest_host="*api.icedrive.net" OR Network_Traffic.dest_host="*app.koofr.net") by Network_Traffic.src, Network_Traffic.dest, Network_Traffic.dest_host, Network_Traffic.user, Network_Traffic.process_name
| `drop_dm_object_name("Network_Traffic")`
| `rename` src as source_ip, dest as destination_ip, dest_host as destination_hostname, process_name as process
# Convert epoch times to human-readable format
| `convert` ctime(firstTime) ctime(lastTime)
```

### SLIMAGENT Malware Screenshot Artifacts Creation
---
```sql
`comment(
SLIMAGENT Screenshot Artifacts

Detects the creation of screenshot files by the SLIMAGENT malware, used by APT28. The malware saves screenshots in the %TEMP% directory with a specific naming convention "Desktop_DD-MM-YYYY_HH-MM-SS.svc".

tags:
   - attack.collection
   - attack.t1113
   - threat_actor.apt28
   - malware.slimagent

falsepositives:

   - The file naming pattern is quite specific. It is possible, but unlikely, that a legitimate application would create '.svc' files with a 'Desktop_' prefix in the user's temporary directory.

level: medium

This search requires file creation event data (e.g., Sysmon Event Code 11) mapped to the Endpoint.Filesystem data model.
)`

`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path = "*\\AppData\\Local\\Temp\\Desktop_*.svc" by Filesystem.dest, Filesystem.user, Filesystem.process_name, Filesystem.file_path
| `drop_dm_object_name("Filesystem")`
| `rename` dest as host, process_name as process, file_path as target_filename
# Convert epoch times to human-readable format
| `convert` ctime(firstTime) ctime(lastTime)
```

### Detect BEARDSHELL and COVENANT Malware via File Hashes
---
```sql
`comment(
BEARDSHELL and COVENANT Hashes

The provided hashes are direct indicators of the BEARDSHELL and COVENANT malware families used by APT28. Detecting these hashes on endpoints is a high-fidelity way to identify compromise.

tags:
   - attack.t1027
   - threat_actor.apt28
   - malware.beardshell
   - malware.covenant

falsepositives:
   - Unlikely, as this detection is based on specific file hashes associated with known malware.

level: high

This search requires file creation or process execution data with file hashes (e.g., Sysmon, EDR logs) mapped to the Endpoint data model.
)`

`tstats` summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash_md5 IN ("915179579ab7dc358c41ea99e4fcab52", "2cae8dc37baf5216a3e7342aac755894", "b52c71318815836126f1257a180a74e7", "5171e84d59fd2bbef9235dfa6459ad8a", "99f2fd309b88b8ec3a9c9c50dddb08b5", "bd76f54d26bf00686da42f3664e3f2ae", "b859f38bfa8bba05d7c0eb4207b95037", "b6e3894c17fb05db754a61ac9a0e5925", "d802290cb9e5c3fed1ba1a8daf827882", "8e0143a6fd791c859d79445768af44d1", "5d938b4316421a2caf7e2e0121b36459", "889b83d375a0fb00670af5276816080e") OR Filesystem.file_hash_sha256 IN ("c49d4acad68955692c32d5fa924eb5bb3f95a192d2c70ff6b0b2ce63c6afe985", "be588c14f7ed3252e36c7db623c09cde8e01fa850c5431d9d621ac942695804d", "0a0fefb509a85c069539003c03c4f9c292d415fb27d18aef750446b63533b432", "84e9eb9615f16316adac6c261fe427905bf1a3d36161e2e4f7658cd177a2c460", "296b294a5fed830c2ff1fac9cb361a2d665b70f2f37188b593b5d1401cd6ca28", "225b7abe861375141f6cfebde4981f615cb2aa4d913faf85172666fa4b4b320b", "d1deeaf0f1807720b11d0f235e3c134a1384054e4c3700eabab26b3a39d2c19a", "20987f7163c8fe466930ece075cd051273530dfcbe8893600fd21fcfb58b5b08", "88e28107fbf171fdbcf4abbc0c731295549923e82ce19d5b6f6fefa3c9f497c9", "39c1f38d0bdc70e50588964ccf3e63dabb871dca83392305a0c64144c7860155", "2eabe990f91bfc480c09db02a4de43116b40da2d6eaad00a034adf4214dac4d1", "9faeb1c8a4b9827f025a63c086d87c409a369825428634b2b01314460a332c6c")) by Filesystem.dest, Filesystem.user, Filesystem.process_name, Filesystem.file_name, Filesystem.file_path, Filesystem.file_hash_md5, Filesystem.file_hash_sha256
| `drop_dm_object_name("Filesystem")`
| `rename` dest as host, process_name as process, file_name as file_name, file_path as file_path, file_hash_md5 as md5, file_hash_sha256 as sha256
# Convert epoch times to human-readable format
| `convert` ctime(firstTime) ctime(lastTime)
```
