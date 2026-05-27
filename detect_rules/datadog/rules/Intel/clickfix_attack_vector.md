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
(source:endpoint parent_process.name:(cmd.exe OR powershell.exe) process.name:(curl.exe OR mshta.exe OR certutil.exe OR rundll32.exe))
| select host, user, parent_process.name AS parent_process, process.name AS process_name, process.cmdline AS process_command_line, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, parent_process, process_name, process_command_line
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, parent_process, process_name, process_command_line
```

### RunMRU Registry Key Monitoring
---
```sql
source:endpoint registry.path:*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\* registry.value:/(powershell|cmd|mshta|rundll32|certutil|curl|bitsadmin|wget|iex\(|invoke-expression|downloadstring)/
| select host, user, registry.path AS registry_path, registry.value_name AS registry_value_name, registry.value AS registry_command, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, registry_path, registry_value_name, registry_command
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, registry_path, registry_value_name, registry_command
```

### DLL Side-Loading & Process Injection
---
```sql
(source:endpoint process.name:(jp2launcher.exe OR filezilla.exe OR nvidia.exe) image_load.name:(msvcp140.dll OR libcef.dll OR libsqlite3-0.dll) image_load.path:(*\\AppData\\* OR *\\ProgramData\\* OR *\\Temp\\*))
| select host, user, process.name AS parent_process_name, image_load.name AS loaded_dll_name, image_load.path AS loaded_dll_path, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, parent_process_name, loaded_dll_name, loaded_dll_path
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, parent_process_name, loaded_dll_name, loaded_dll_path
```

### Obfuscated PowerShell Execution
---
```sql
(source:endpoint process.name:(powershell.exe OR pwsh.exe) process.cmdline:("-e " OR "-en " OR "-enc " OR "-encodedcommand " OR FromBase64String OR "iex(" OR Invoke-Expression OR DownloadString OR /[\u0400-\u04FF]+/))
| select host, user, parent_process.name AS parent_process, process.cmdline AS process_command_line, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, parent_process, process_command_line
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, parent_process, process_command_line
```

### Typosquatting & Malvertising Domains
---
```sql
source:network_resolution dns.query:(iplogger.co OR oktacheck.it.com OR docusign.sa.com OR stuffgull.top OR sumeriavgv.digital OR pub-164d8d82c41c4e1b871bc21802a18154.r2.dev OR pub-626890a630d8418ea6c2ef0fa17f02ef.r2.dev OR pub-a5a2932dc7f143499b865f8580102688.r2.dev OR pub-7efc089d5da740a994d1472af48fc689.r2.dev OR agroeconb.live OR animatcxju.live OR webbs.live OR diab.live OR mhbr.live OR decr.live OR lexip.live OR rimz.live OR byjs.live OR btco.live OR izan.live OR k.veuwb.live OR r.netluc.live OR heyues.live OR k.mailam.live OR doccsign.it.com OR dosign.it.com OR loyalcompany.net OR leocompany.org OR mhousecreative.com OR mh-sns.com OR lasix20.com)
| select ip.src AS src_ip, user, dns.query AS domain_queried, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by src_ip, user, domain_queried
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, src_ip, user, domain_queried
```

### Malware Hashes
---
```sql
(source:endpoint process.hash:(2bc23b53bb76e59d84b0175e8cba68695a21ed74be9327f0b6ba37edc2daaeef OR 06efe89da25a627493ef383f1be58c95c3c89a20ebb4af4696d82e729c75d1a7 OR 5809c889e7507d357e64ea15c7d7b22005dbf246aefdd3329d4a5c58d482e7e1 OR 52e6e819720fede0d12dcc5430ff15f70b5656cbd3d5d251abfc2dcd22783293 OR 57e75c98b22d1453da5b2642c8daf6c363c60552e77a52ad154c200187d20b9a OR 33a0cf0a0105d8b65cf62f31ec0a6dcd48e781d1fece35b963c6267ab2875559 OR 5C762FF1F604E92ECD9FD1DC5D1CB24B3AF4B4E0D25DE462C78F7AC0F897FC2D OR 9DCA5241822A0E954484D6C303475F94978B6EF0A016CBAE1FBA29D0AED86288 OR CBAF513E7FD4322B14ADCC34B34D793D79076AD310925981548E8D3CFF886527 OR 506ab08d0a71610793ae2a5c4c26b1eb35fd9e3c8749cd63877b03c205feb48a OR 3ACC40334EF86FD0422FM386CA4FB8836C4FA0E722A5FCFA0086B9182127C1D7))
| select host, user, process.name AS process_name, process.cmdline AS process_command_line, process.hash AS file_hash, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, process_name, process_command_line, file_hash
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, process_name, process_command_line, file_hash
```

### Malicious IP Address
---
```sql
source:network_traffic ip.dst:80.77.23.48
| select ip.src AS source_ip, ip.dst AS destination_ip, user, port.dst AS destination_port, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by source_ip, destination_ip, user, destination_port
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, source_ip, destination_ip, user, destination_port, count
```