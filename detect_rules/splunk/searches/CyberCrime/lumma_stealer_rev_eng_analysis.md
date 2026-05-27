### Lumma Stealer Infection Analysis
---

This report details the reverse engineering of a Lumma Stealer infection, highlighting its multi-stage loading process, obfuscation techniques, and information-stealing capabilities. Lumma Stealer, a prevalent information stealer offered as Malware-as-a-Service (MaaS), employs sophisticated methods like process injection and API hashing to evade detection and exfiltrate sensitive user data.

Recent intelligence indicates that Lumma Stealer has re-emerged and evolved following a significant law enforcement takedown in May 2025, leveraging new delivery methods such as GitHub abuse and fake CAPTCHA sites, and employing stealthier evasion tactics including AMSI bypasses and rapidly rotating domains. This resurgence and adaptation underscore the persistent threat posed by Lumma Stealer despite disruption efforts.

### Actionable Threat Data
---

Lumma Stealer utilizes a .NET/C# loader that performs checks for valid DOS and PE headers before decrypting and executing the next stage.

The malware employs process injection (T1055) by creating a suspended process (T1055.012) using `CreateProcessW` with the `CREATE_SUSPENDED` flag, allocating memory with `VirtualAllocEx` (T1055.001), writing the malicious payload with `WriteProcessMemory` (T1055.001), and resuming the thread with `ResumeThread` (T1055.001).

Lumma Stealer resolves API addresses dynamically at runtime by parsing the Process Environment Block (PEB) (T1574.008) and iterating through loaded DLLs to find functions like `LoadLibraryA` and `GetProcAddress` (T1027.004).

The unpacked Lumma payload uses control flow flattening (T1027.003) and "`Heaven's Gate`" (T1027.006) to switch between 32-bit and 64-bit execution modes, complicating analysis and detection.

The malware performs anti-analysis checks, including verifying if it's running in a packed form and checking the system's default UI language (specifically for Russian language settings) (T1036.003).

Lumma Stealer establishes C2 communication (T1071.001) by decrypting C2 domains using `ChaCha20` (T1027) and sending `POST` requests with specific user-agent and URI patterns via `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`, and `WinHttpSendRequest`.

Initial access methods observed include `.ZIP`, `.LNK`, and `.COMMAND` files, with recent campaigns also leveraging fake CAPTCHA sites, malvertising, and GitHub infrastructure for distribution.

### Process Injection via CreateRemoteThread

use "Lumma Stealer Process Hollowing" in the enterprise security content.

### Dynamic API Resolution
---
```sql
[comment]: <> (description: This detection identifies processes loading networking-related DLLs, such as `winhttp.dll` or `ws2_32.dll`, that are not typically associated with network activity. This behavior is a common precursor to malicious activities like C2 communication, often seen in malware like Lumma Stealer, which dynamically resolves APIs to evade static detection. The malware first loads the necessary library and then uses functions like `GetProcAddress` to find the memory address of the functions it needs to execute its objectives.)

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.ImageLoads where (lower(ImageLoads.image_path) IN ("*\\winhttp.dll", "*\\ws2_32.dll")) by ImageLoads.dest ImageLoads.user ImageLoads.process_name ImageLoads.process_path ImageLoads.image_path
| `drop_dm_object_name(ImageLoads)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
# Filter out common legitimate processes that load these networking DLLs.
| where NOT (process_name IN ("chrome.exe", "firefox.exe", "msedge.exe", "svchost.exe", "powershell.exe", "iexplore.exe", "MicrosoftEdgeUpdate.exe", "Teams.exe", "OneDrive.exe", "outlook.exe", "msedgewebview2.exe", "opera.exe", "brave.exe", "vivaldi.exe", "safari.exe") OR process_path LIKE "C:\\Program Files\\%" OR process_path LIKE "C:\\Program Files (x86)\\%" OR process_path LIKE "C:\\Windows\\System32\\%" OR process_path LIKE "C:\\Windows\\SysWOW64\\%")
# This search may generate false positives. Tune the 'where' clause by adding legitimate processes or paths specific to your environment.
| `suspicious_dll_load_for_dynamic_api_resolution_filter`
```

### Anti-Analysis Checks
---
```sql
[comment]: <> (description: Detects processes performing a system language check by calling 'GetUserDefaultUILanguage'. This technique is used by malware like Lumma Stealer to evade analysis or execution in certain regions. Lumma specifically checks if the system language is Russian ('ru-RU') before proceeding with its main payload. This detection focuses on unusual processes making this check, filtering out common legitimate software.)

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Changes where (Changes.call_trace="*GetUserDefaultUILanguage*") by Changes.dest Changes.user Changes.process_name Changes.process_path
| `drop_dm_object_name(Changes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
# Note: This detection requires a log source that can capture API calls, such as Sysmon Event ID 10, mapped to the Endpoint.Changes data model.
# Filter out common legitimate processes that perform language checks for localization.
| where NOT (process_name IN ("chrome.exe", "firefox.exe", "msedge.exe", "svchost.exe", "powershell.exe", "explorer.exe", "officec2rclient.exe", "teams.exe", "onedrive.exe", "outlook.exe", "msedgewebview2.exe") OR process_path LIKE "C:\\Program Files\\%" OR process_path LIKE "C:\\Program Files (x86)\\%" OR process_path LIKE "C:\\Windows\\System32\\%" OR process_path LIKE "C:\\Windows\\SysWOW64\\%" OR process_path LIKE "C:\\Windows\\WinSxS\\%")
# This search may generate false positives from legitimate applications not included in the filter.
# Consider tuning the 'where' clause by adding legitimate processes or paths specific to your environment.
| `lumma_stealer_anti_analysis_system_language_check_filter`
```

### C2 Communication via WinHTTP
---
```sql
[comment]: <> (description: Detects potential Lumma Stealer C2 communication by identifying specific HTTP POST request patterns. Lumma Stealer is known to use WinHTTP to send POST requests to its C2 servers with a characteristic User-Agent, URI, and content type.)

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.http_method="POST" AND All_Traffic.url="*/api*" AND All_Traffic.url="*act=life*" AND All_Traffic.http_user_agent="Mozilla/5.0 (Windows NT 10; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119" AND All_Traffic.http_content_type="application/x-www-form-urlencoded") by All_Traffic.dest All_Traffic.src All_Traffic.user All_Traffic.url All_Traffic.http_user_agent All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
# This detection leverages a combination of highly specific indicators seen in Lumma Stealer C2 traffic.
# While specific, threat actors may change these indicators. Consider creating broader rules based on subsets of these indicators for threat hunting.
| `lumma_stealer_c2_communication_via_winhttp_filter`
```

### Suspicious TLD Connections
---
```sql
[comment]: <> (description: Detects network connections from non-browser processes to Top-Level Domains (TLDs) such as .help, .top, .shop, .biz, .pro, .xyz, or the domain steamcommunity.com. This pattern is a known indicator of Lumma Stealer C2 activity.)

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (All_Traffic.dest LIKE "%.help" OR All_Traffic.dest LIKE "%.top" OR All_Traffic.dest LIKE "%.shop" OR All_Traffic.dest LIKE "%.biz" OR All_Traffic.dest LIKE "%.pro" OR All_Traffic.dest LIKE "%.xyz" OR All_Traffic.dest="*steamcommunity.com*") by All_Traffic.dest All_Traffic.src All_Traffic.user All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
# Filter out connections from common web browsers to reduce false positives.
| where NOT (process_name IN ("chrome.exe", "firefox.exe", "msedge.exe", "msedgewebview2.exe", "microsoftedge.exe", "iexplore.exe", "safari.exe", "brave.exe", "opera.exe", "vivaldi.exe"))
# This detection may flag legitimate non-browser applications (e.g., game launchers, updaters) that connect to these domains.
# Consider adding legitimate processes to the filter list to tune for your environment.
| `lumma_stealer_suspicious_tld_connections_filter`
```

### Heaven's Gate Technique
---
```sql
[comment]: <> (description: Detects the use of the Heavens Gate technique, where a 32-bit process running under the WoW64 subsystem makes a far jump to execute 64-bit code. This is identified by analyzing the call stack for transitions involving `wow64cpu.dll`, which handles the switch from 32-bit to 64-bit mode. This technique is used by malware like Lumma Stealer to evade security products and call native 64-bit APIs directly. The detection filters for processes not located in standard system or application directories to reduce noise from legitimate 32-bit applications.)

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Changes where (Changes.call_trace="*wow64cpu.dll*") by Changes.dest Changes.user Changes.process_name Changes.process_path Changes.call_trace
| `drop_dm_object_name(Changes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
# This detection requires a data source that provides detailed call stack information, such as Sysmon Event ID 10, mapped to the Endpoint.Changes data model.
# The presence of 'wow64cpu.dll' in a call stack indicates a 32-bit process is transitioning to 64-bit mode to execute a syscall.
# Filter out processes running from standard, trusted locations to focus on anomalous behavior.
| where NOT (process_path LIKE "C:\\Windows\\%" OR process_path LIKE "C:\\Program Files\\%" OR process_path LIKE "C:\\Program Files (x86)\\%")
# Further filter common legitimate applications that run as 32-bit processes on 64-bit systems.
| where NOT process_name IN ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "svchost.exe", "powershell.exe", "cmd.exe", "explorer.exe", "teams.exe", "outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe", "onedrive.exe", "msedgewebview2.exe")
# This detection may generate false positives from legitimate 32-bit applications installed in non-standard directories (e.g., %APPDATA%).
# Tuning may be required by adding legitimate processes or paths to the filter list.
| `heavens_gate_evasion_technique_filter`
```