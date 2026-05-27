### ClickFix Attack Vector Report
---

The ClickFix attack vector is a growing social engineering technique where threat actors trick users into manually executing malicious commands, often under the guise of fixing computer issues. This method bypasses traditional security controls by leveraging user interaction, leading to the deployment of various malware families such as NetSupport RAT, Latrodectus, and Lumma Stealer.


Recent intelligence indicates a significant surge in ClickFix attacks, with a 517% increase in the past six months, making it the second most common attack vector after phishing. Notably, Lumma Stealer has shown a rapid resurgence after a major law enforcement takedown in May 2025, adapting its distribution channels to more discreet methods like GitHub abuse and fake CAPTCHA sites, and employing in-memory execution to evade detection. Latrodectus has also expanded its reach, utilizing TikTok videos as a new vector for ClickFix campaigns.

### Actionable Threat Data
---

Suspicious Command Execution (Win+R/Win+X): Monitor for `cmd.exe` or `powershell.exe` being launched via `explorer.exe` (Win+X Quick Access Menu) or directly through the Run dialog (Win+R), especially when followed by suspicious child processes like `curl.exe`, `mshta.exe`, `certutil.exe`, or `rundll32.exe`. This is a strong indicator of a ClickFix attempt. (T1059.001, T1059.003)

Registry Key Monitoring for RunMRU: Regularly inspect the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` registry key for obfuscated commands, keywords related to payload download/execution from unknown domains, or calls to administrative interfaces. (T1112)

DLL Side-Loading and Process Injection: Look for legitimate executables (e.g., `jp2launcher.exe`, `filezilla.exe`, `nvidia.exe`) loading unusual or malicious DLLs (e.g., `msvcp140.dll`, `libcef.dll`, `libsqlite3-0.dll`) from unexpected locations, followed by process injection or execution of shellcode. (T1574.002, T1055)

PowerShell Script Execution with Obfuscation: Detect PowerShell commands that are heavily obfuscated (e.g., Base64 encoded, junk JSON variables, Russian comments) and attempt to download or execute additional scripts or binaries from remote sources. (T1059.001, T1027)

Typosquatting and Malvertising Domains: Block connections to domains that are typosquatted versions of legitimate services (e.g., `iplogger[.]co` for `iplogger[.]org`) or those associated with malvertising campaigns and ClearFake infrastructure (e.g., `oktacheck.it[.]com`, `docusign.sa[.]com`). (T1566.002, T1583.001)

### Suspicious Command Execution
---
```sql
`comment("This detection rule identifies suspicious command execution patterns associated with the ClickFix attack vector, where a command interpreter (cmd.exe or powershell.exe) spawns a process commonly used for downloading or executing malicious code.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("cmd.exe", "powershell.exe") AND Processes.process_name IN ("curl.exe", "mshta.exe", "certutil.exe", "rundll32.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name("Processes")`

`comment("Convert timestamps to a human-readable format.")`
| convert ctime(firstTime) ctime(lastTime)

`comment("Rename fields for clarity and align with common schemas.")`
| rename dest as host, user as user, parent_process_name as parent_process, process_name as process_name, process as process_command_line

`comment("Potential False Positives: Legitimate administrative scripts or software installers may occasionally use these command sequences. If false positives occur, consider tuning the rule by excluding known safe scripts based on command-line arguments or by filtering for specific parent processes of cmd.exe/powershell.exe, such as explorer.exe.")`
| table firstTime, lastTime, host, user, parent_process, process_name, process_command_line
```

### RunMRU Registry Key Monitoring
---
```sql
`comment("This rule is sourced from the Splunk Common Information Model (CIM). It requires the Endpoint data model to be populated, typically by a technology add-on that maps endpoint and registry data to the CIM.")`

`comment("The following detection rule identifies suspicious commands written to the RunMRU registry key. This activity is a key indicator of the ClickFix attack vector, where a user is tricked into pasting and executing a malicious command in the Run dialog (Win+R).")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\*" AND (Registry.registry_value_data IN ("*powershell*", "*cmd*", "*mshta*", "*rundll32*", "*certutil*", "*curl*", "*bitsadmin*", "*wget*", "*iex(*", "*invoke-expression*", "*downloadstring*")) by Registry.dest, Registry.user, Registry.registry_path, Registry.registry_value_name, Registry.registry_value_data
| `drop_dm_object_name("Registry")`

`comment("Convert timestamps to a human-readable format for easier analysis.")`
| convert ctime(firstTime), ctime(lastTime)

`comment("Rename fields for better readability and alignment with common security schemas.")`
| rename dest as host, user as user, registry_path as registry_path, registry_value_name as registry_value_name, registry_value_data as registry_command

`comment("Potential False Positives: System administrators or power users may legitimately use the Run dialog for executing these types of commands. If false positives occur, consider excluding known administrative accounts or specific, benign command-line patterns.")`
| table firstTime, lastTime, host, user, registry_path, registry_value_name, registry_command
```

### DLL Side-Loading & Process Injection
---
```sql
`comment("This rule detects potential DLL side-loading as seen in ClickFix campaigns. It identifies legitimate processes loading DLLs with names associated with malware from suspicious, user-writable locations. This behavior is indicative of TTPs T1574.002 and T1055.")`
`comment("Date: 2025-07-23")`
`comment("References: https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/")`

| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.ImageLoads where (ImageLoads.process_name IN ("jp2launcher.exe", "filezilla.exe", "nvidia.exe")) AND (ImageLoads.file_name IN ("msvcp140.dll", "libcef.dll", "libsqlite3-0.dll")) AND (ImageLoads.file_path IN ("*\\AppData\\*", "*\\ProgramData\\*", "*\\Temp\\*")) by ImageLoads.dest, ImageLoads.user, ImageLoads.process_name, ImageLoads.file_name, ImageLoads.file_path
| `drop_dm_object_name("ImageLoads")`

`comment("Convert timestamps to a human-readable format.")`
| convert ctime(firstTime), ctime(lastTime)

`comment("Rename fields for clarity and consistency.")`
| rename dest as host, user as user, process_name as parent_process_name, file_name as loaded_dll_name, file_path as loaded_dll_path

`comment("Potential False Positives: While specific, some applications might legitimately load DLLs from user-profile directories. If false positives occur, investigate the specific file path and application behavior. Consider adding more specific path exclusions if a legitimate pattern is identified.")`
| table firstTime, lastTime, host, user, parent_process_name, loaded_dll_name, loaded_dll_path
```

### Obfuscated PowerShell Execution
---
```sql
`comment("This rule detects potentially obfuscated PowerShell execution, a technique commonly used in ClickFix campaigns to download and run malicious payloads while evading basic signature-based detections. It looks for command-line arguments and functions associated with encoding, in-memory execution, and remote file downloads.")`

| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("powershell.exe", "pwsh.exe")) AND (Processes.process IN ("* -e *", "* -en *", "* -enc *", "* -encodedcommand *", "*FromBase64String*", "*iex(*", "*Invoke-Expression*", "*DownloadString*") OR match(Processes.process, "(?i)[\u0400-\u04FF]+")) by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process
| `drop_dm_object_name("Processes")`

`comment("Convert timestamps to a human-readable format.")`
| convert ctime(firstTime), ctime(lastTime)

`comment("Rename fields for clarity and consistency.")`
| rename dest as host, user as user, parent_process_name as parent_process, process as process_command_line

`comment("Potential False Positives: Legitimate administrative or deployment scripts may use encoded commands to handle complex characters or logic. Review the decoded command line and parent process to determine legitimacy. Exclude known safe scripts or parent processes if necessary.")`
| table firstTime, lastTime, host, user, parent_process, process_command_line
```

### Typosquatting & Malvertising Domains
---
```sql
`comment("This rule detects network traffic to domains associated with ClickFix malvertising and typosquatting campaigns, as identified in recent threat intelligence. It leverages the Network Resolution (DNS) data model to find lookups for known malicious domains.")`
`comment("Date: 2025-07-23")`
`comment("References: https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/")`

| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where (DNS.query IN ("iplogger.co", "oktacheck.it.com", "docusign.sa.com", "stuffgull.top", "sumeriavgv.digital", "pub-164d8d82c41c4e1b871bc21802a18154.r2.dev", "pub-626890a630d8418ea6c2ef0fa17f02ef.r2.dev", "pub-a5a2932dc7f143499b865f8580102688.r2.dev", "pub-7efc089d5da740a994d1472af48fc689.r2.dev", "agroeconb.live", "animatcxju.live", "webbs.live", "diab.live", "mhbr.live", "decr.live", "lexip.live", "rimz.live", "byjs.live", "btco.live", "izan.live", "k.veuwb.live", "r.netluc.live", "heyues.live", "k.mailam.live", "doccsign.it.com", "dosign.it.com", "loyalcompany.net", "leocompany.org", "mhousecreative.com", "mh-sns.com", "lasix20.com")) by DNS.src, DNS.user, DNS.query
| `drop_dm_object_name("DNS")`

`comment("Convert timestamps to a human-readable format.")`
| convert ctime(firstTime), ctime(lastTime)

`comment("Rename fields for clarity.")`
| rename src as src_ip, user as user, query as domain_queried

`comment("Potential False Positives: This rule is based on specific IOCs and is expected to have a low false positive rate. However, a domain could be sinkholed or repurposed, leading to benign traffic. Investigate the source system for signs of compromise if an alert fires.")`
| table firstTime, lastTime, src_ip, user, domain_queried
```

### Malware Hashes
---
```sql
`comment("This rule detects the execution of processes matching known malicious SHA256 hashes associated with ClickFix campaigns, including Lumma Stealer, Latrodectus, and NetSupport RAT payloads.")`
`comment("Date: 2025-07-23")`
`comment("References: https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/")`

| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.hash IN ("2bc23b53bb76e59d84b0175e8cba68695a21ed74be9327f0b6ba37edc2daaeef", "06efe89da25a627493ef383f1be58c95c3c89a20ebb4af4696d82e729c75d1a7", "5809c889e7507d357e64ea15c7d7b22005dbf246aefdd3329d4a5c58d482e7e1", "52e6e819720fede0d12dcc5430ff15f70b5656cbd3d5d251abfc2dcd22783293", "57e75c98b22d1453da5b2642c8daf6c363c60552e77a52ad154c200187d20b9a", "33a0cf0a0105d8b65cf62f31ec0a6dcd48e781d1fece35b963c6267ab2875559", "5C762FF1F604E92ECD9FD1DC5D1CB24B3AF4B4E0D25DE462C78F7AC0F897FC2D", "9DCA5241822A0E954484D6C303475F94978B6EF0A016CBAE1FBA29D0AED86288", "CBAF513E7FD4322B14ADCC34B34D793D79076AD310925981548E8D3CFF886527", "506ab08d0a71610793ae2a5c4c26b1eb35fd9e3c8749cd63877b03c205feb48a", "3ACC40334EF86FD0422FB386CA4FB8836C4FA0E722A5FCFA0086B9182127C1D7")) by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.hash
| `drop_dm_object_name("Processes")`

`comment("Convert timestamps to a human-readable format.")`
| convert ctime(firstTime), ctime(lastTime)

`comment("Rename fields for clarity.")`
| rename dest as host, user as user, process_name as process_name, process as process_command_line, hash as file_hash

`comment("Potential False Positives: This rule has a very low probability of false positives as it is based on specific, known-malicious file hashes. An alert indicates a high-confidence threat.")`
| table firstTime, lastTime, host, user, process_name, process_command_line, file_hash
```

### Malicious IP Address
---
```sql
`comment("This rule detects network connections to a known malicious IP address (80.77.23.48) associated with NetSupport RAT C2 infrastructure used in ClickFix campaigns.")`
`comment("Date: 2025-07-23")`
`comment("References: https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/")`

| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (All_Traffic.dest_ip="80.77.23.48") by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.user, All_Traffic.dest_port
| `drop_dm_object_name("All_Traffic")`

`comment("Convert timestamps to a human-readable format.")`
| convert ctime(firstTime), ctime(lastTime)

`comment("Rename fields for clarity.")`
| rename src_ip as source_ip, dest_ip as destination_ip, user as user, dest_port as destination_port

`comment("Potential False Positives: This rule is based on a specific IOC and is expected to have a low false positive rate. However, if the IP address is reallocated to a benign service in the future, false positives could occur. Investigate the source system for other signs of compromise if an alert fires.")`
| table firstTime, lastTime, source_ip, destination_ip, user, destination_port, count
```
