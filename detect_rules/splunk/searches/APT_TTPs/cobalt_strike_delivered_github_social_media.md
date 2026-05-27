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
search: |-
  | tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name = "cmd.exe") AND (Processes.process="*xcopy /h /y*") AND (Processes.process="* ren *") AND (Processes.process="*BugSplatRc64.dll*") AND (Processes.process="*nau.exe*") AND (Processes.process="*Требования*") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.process_guid
  | `drop_dm_object_name(Processes)`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `cobalt_strike_lnk_spear_phishing_command_filter`
```

### Cobalt Strike DLL Sideloading via BugSplat
---
```sql
search: |-
  | tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.ImageLoads where (ImageLoads.Image_Name = "BugSplatRc64.dll") AND (ImageLoads.process_name = "nau.exe") AND (ImageLoads.signature = "Unsigned") AND (ImageLoads.Image_Path="*\\Users\\Public\\*") by ImageLoads.dest ImageLoads.user ImageLoads.process_name ImageLoads.process_path ImageLoads.Image_Name ImageLoads.Image_Path ImageLoads.signature ImageLoads.process_guid
  | `drop_dm_object_name(ImageLoads)`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `cobalt_strike_dll_sideloading_via_bugsplat_filter`
```

### Cobalt Strike Loader Spawns Child Process
---
```sql
search: |-
  | tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name = "nau.exe") AND (Processes.parent_process_name = "nau.exe") AND (Processes.process = "*qstt*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid
  | `drop_dm_object_name(Processes)`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `cobalt_strike_loader_spawns_child_process_filter`
```

### Cobalt Strike C2 via Social Media
---
```sql
search: |-
  | tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Web where (Web.process_name = "nau.exe") AND (Web.url IN ("*github.com/*", "*raw.githubusercontent.com/*", "*quora.com/profile/*", "*techcommunity.microsoft.com/t5/user/viewprofilepage/*", "*techcommunity.microsoft.com/users/*", "*learn.microsoft.com/en-us/collections/*", "*my.mail.ru/mail/*/photo/*")) by Web.dest Web.user Web.process_name Web.url Web.http_method Web.process_guid
  | `drop_dm_object_name(Web)`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `cobalt_strike_c2_via_social_media_filter`
```

### Cobalt Strike Beacon Injection via Reflective Loading
---
```sql
search: |-
  | tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Web where (Web.process_name = "nau.exe") AND (Web.url = "*moeodincovo.com*") by Web.dest Web.user Web.process_name Web.url Web.http_method Web.process_guid
  | `drop_dm_object_name(Web)`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `cobalt_strike_beacon_injection_via_reflective_loading_filter`
```

### Cobalt Strike C2 Domain Communication (moeodincovo.com)
---
```sql
search: |-
  | tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Web
  where (Web.url = "*moeodincovo.com*")  -- Look for traffic to the known malicious C2 domain
  by Web.dest Web.user Web.process_name Web.url Web.http_method Web.process_guid
  | `drop_dm_object_name(Web)`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `cobalt_strike_c2_domain_moeodincovo_filter`
```

### Malicious LNK File Hash
---
```sql
search: |-
  | tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash IN ("30D11958BFD72FB63751E8F8113A9B04", "92481228C18C336233D242DA5F73E2D5")) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash
  | `drop_dm_object_name(Filesystem)`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `malicious_lnk_file_hash_filter`
```

### Malicious DLL Hash
---
```sql
search: |-
  | tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash IN ("2FF63CACF26ADC536CD177017EA7A369", "08FB7BD0BB1785B67166590AD7F99FD2", "02876AF791D3593F2729B1FE4F058200", "F9E20EB3113901D780D2A973FF539ACE", "B2E24E061D0B5BE96BA76233938322E7", "15E590E8E6E9E92A18462EF5DFB94298", "66B6E4D3B6D1C30741F2167F908AB60D", "ADD6B9A83453DB9E8D4E82F5EE46D16C", "A02C80AD2BF4BFFBED9A77E9B02410FF", "672222D636F5DC51F5D52A6BD800F660", "2662D1AE8CF86B0D64E73280DF8C19B3", "4948E80172A4245256F8627527D7FA96")) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash
  | `drop_dm_object_name(Filesystem)`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `malicious_dll_hash_filter`
```