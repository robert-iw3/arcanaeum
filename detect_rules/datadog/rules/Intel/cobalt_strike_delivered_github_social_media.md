### Cobalt Strike Beacon Delivered via GitHub and Social Media
---

This report details a cyberattack campaign active from late 2024 to April 2025, which utilized spear-phishing emails with malicious LNK attachments to deliver Cobalt Strike Beacon. The attackers employed sophisticated evasion techniques, including DLL hijacking and dynamic API resolution, and leveraged legitimate online platforms like GitHub, Quora, and Microsoft Learn Challenge to host C2 information.

A significant new finding is the adversary's continued use of legitimate social media and content-sharing platforms (GitHub, Quora, Microsoft Learn Challenge, Mail.ru) to host encrypted Cobalt Strike C2 information, even after a two-month hiatus in attacks. This tactic, aligned with MITRE ATT&CK T1585.001 (Compromise Accounts), is noteworthy as it abuses trusted services to bypass traditional network defenses and complicates C2 infrastructure detection.

### Actionable Threat Data
---

Initial Access - Spearphishing with LNK Attachments:

The campaign begins with spear-phishing emails containing RAR archives with malicious `.lnk` files. These .lnk files execute commands to copy and rename malicious executables and DLLs, ultimately leading to the execution of a legitimate crash reporting utility (`BsSndRpt.exe` renamed to `nau.exe`) that sideloads a malicious DLL.

Defense Evasion - DLL Hijacking and Sideloading:

The attackers exploit DLL hijacking (T1574.001) by placing a malicious DLL named `BugSplatRc64.dll` in a location where the legitimate `nau.exe` (renamed `BsSndRpt.exe`) expects to find its legitimate DLL. This malicious DLL then intercepts API calls, specifically `MessageBoxW`, to execute its payload.

Defense Evasion - Dynamic API Resolution and Obfuscation:

The malicious `BugSplatRc64.dll` employs dynamic API resolution (T1027.007) with a custom hashing algorithm (similar to CRC) and XOR encryption to obfuscate API functions. API functions are reloaded after each call, making static analysis difficult.

Command and Control - Legitimate Platform Abuse:

The malicious DLL retrieves the next stage payload URL from legitimate online platforms such as GitHub, Microsoft Learn Challenge, Quora, and Russian social media sites. The C2 information is embedded as a base64-encoded, XOR-encrypted string within public profiles or posts on these platforms.

Execution - Reflective DLL Injection of Cobalt Strike:

The downloaded and decrypted shellcode acts as a reflective loader (T1620), injecting the Cobalt Strike Beacon directly into process memory. This technique avoids writing the Beacon to disk, further hindering detection.

### Cobalt Strike LNK Spear-Phishing Command
---
```sql
source:endpoint process.name:cmd.exe process.cmdline:("xcopy /h /y" AND " ren " AND BugSplatRc64.dll AND nau.exe AND Требования)
| select host, user, parent_process.name AS parent_process, process.name AS process_name, process.cmdline AS process, process.id AS process_id, process.guid AS process_guid, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, parent_process, process_name, process, process_id, process_guid
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, parent_process, process_name, process, process_id, process_guid
```

### Cobalt Strike DLL Sideloading via BugSplat
---
```sql
source:endpoint image_load.name:BugSplatRc64.dll process.name:nau.exe image_load.signature:Unsigned image_load.path:*\\Users\\Public\\*
| select host, user, process.name AS process_name, process.path AS process_path, image_load.name AS Image_Name, image_load.path AS Image_Path, image_load.signature, process.guid AS process_guid, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, process_name, process_path, Image_Name, Image_Path, signature, process_guid
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, process_name, process_path, Image_Name, Image_Path, signature, process_guid
```

### Cobalt Strike Loader Spawns Child Process
---
```sql
source:endpoint process.name:nau.exe parent_process.name:nau.exe process.cmdline:*qstt*
| select host, user, parent_process.name AS parent_process_name, process.name AS process_name, process.cmdline AS process, process.id AS process_id, parent_process.id AS parent_process_id, process.guid AS process_guid, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, parent_process_name, process_name, process, process_id, parent_process_id, process_guid
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, parent_process_name, process_name, process, process_id, parent_process_id, process_guid
```

### Cobalt Strike C2 via Social Media
---
```sql
source:endpoint_web process.name:nau.exe http.url:(*github.com/* OR *raw.githubusercontent.com/* OR *quora.com/profile/* OR *techcommunity.microsoft.com/t5/user/viewprofilepage/* OR *techcommunity.microsoft.com/users/* OR *learn.microsoft.com/en-us/collections/* OR *my.mail.ru/mail/*/photo/*)
| select host, user, process.name AS process_name, http.url, http.method, process.guid AS process_guid, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, process_name, http.url, http.method, process_guid
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, process_name, http.url, http.method, process_guid
```

### Cobalt Strike Beacon Injection via Reflective Loading
---
```sql
source:endpoint_web process.name:nau.exe http.url:*moeodincovo.com*
| select host, user, process.name AS process_name, http.url, http.method, process.guid AS process_guid, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, process_name, http.url, http.method, process_guid
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, process_name, http.url, http.method, process_guid
```

### Cobalt Strike C2 Domain Communication (moeodincovo.com)
---
```sql
source:endpoint_web http.url:*moeodincovo.com*
| select host, user, process.name AS process_name, http.url, http.method, process.guid AS process_guid, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, process_name, http.url, http.method, process_guid
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, process_name, http.url, http.method, process_guid
```

### Malicious LNK File Hash
---
```sql
source:endpoint file.hash:(30D11958BFD72FB63751E8F8113A9B04 OR 92481228C18C336233D242DA5F73E2D5)
| select host, user, file.name AS file_name, file.path AS file_path, file.hash AS file_hash, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, file_name, file_path, file_hash
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, file_name, file_path, file_hash
```

### Malicious DLL Hash
---
```sql
source:endpoint file.hash:(2FF63CACF26ADC536CD177017EA7A369 OR 08FB7BD0BB1785B67166590AD7F99FD2 OR 02876AF791D3593F2729B1FE4F058200 OR F9E20EB3113901D780D2A973FF539ACE OR B2E24E061D0B5BE96BA76233938322E7 OR 15E590E8E6E9E92A18462EF5DFB94298 OR 66B6E4D3B6D1C30741F2167F908AB60D OR ADD6B9A83453DB9E8D4E82F5EE46D16C OR A02C80AD2BF4BFFBED9A77E9B02410FF OR 672222D636F5DC51F5D52A6BD800F660 OR 2662D1AE8CF86B0D64E73280DF8C19B3 OR 4948E80172A4245256F8627527D7FA96)
| select host, user, file.name AS file_name, file.path AS file_path, file.hash AS file_hash, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, file_name, file_path, file_hash
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, file_name, file_path, file_hash
```