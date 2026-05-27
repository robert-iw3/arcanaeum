### Mythic C2 with EarlyBird Injection and Defender Evasion
---

This report details the use of Mythic C2, a versatile command and control framework, in conjunction with the EarlyBird injection technique to evade detection by endpoint security solutions like Windows Defender. The core of the evasion relies on sophisticated redirector infrastructure and process injection that occurs before typical security hooks are in place.

Recent intelligence highlights the increasing use of AI and machine learning by malware authors to dynamically adapt evasion techniques, making traditional static signature-based defenses less effective against methods like EarlyBird injection. Additionally, threat actors like Transparent Tribe are actively abusing legitimate red teaming tools such as Mythic C2 for malicious purposes, demonstrating a shift towards leveraging readily available, powerful frameworks.

### Actionable Threat Data
---

Suspended Process Creation and APC Queueing (T1055.001, T1055.004):

Monitor for `CreateProcessW` calls with the `CREATE_SUSPENDED` flag followed by `VirtualAllocEx`, `WriteProcessMemory`, and `QueueUserAPC` targeting processes like `WerFault.exe`. This sequence is indicative of EarlyBird injection.

Unusual Network Connections from System Processes (T1071.001):

Look for `WerFault.exe` initiating outbound network connections, especially to newly registered or uncategorized domains, or domains not typically associated with Microsoft error reporting.

HTTP/HTTPS Traffic to Suspicious Subdomains/Paths (T1071.001):

Detect HTTP/HTTPS requests to subdomains or URL paths that mimic legitimate web content (e.g., `/assets/fonts/*.ttf`) but are used for C2 communication or payload delivery. Pay attention to `User-Agent` strings and other HTTP headers that might be rotated or appear generic.

Process Memory Modifications with Execute Permissions (T1055):

Monitor for `VirtualAllocEx` calls that allocate memory with `PAGE_EXECUTE_READWRITE` permissions in processes, particularly when followed by `WriteProcessMemory` and `QueueUserAPC`.

WinHTTP API Misuse with Security Flag Bypasses (T1102):

Identify applications using `WinHttpOpen` and `WinHttpSetOption` with security flags like `SECURITY_FLAG_IGNORE_CERT_CN_INVALID`, `SECURITY_FLAG_IGNORE_CERT_DATE_INVALID`, or `SECURITY_FLAG_IGNORE_UNKNOWN_CA`, as this can indicate an attempt to bypass certificate validation for malicious communication.

### EarlyBird Injection via Suspended WerFault.exe
---
```sql
(`your_process_creation_index`)
`comment("CIM-compliant search for process creation events. Adjust sourcetype/index as needed.")`
(sourcetype=win*eventlog:security EventCode=4688) OR (sourcetype=xmlwineventlog EventCode=1) OR (sourcetype=crowdstrike:raw:json Event_SimpleName=ProcessRollup2)

`comment("Key detection logic: WerFault.exe created in a suspended state.")`
`comment("The field for creation flags (e.g., CreationFlags, ProcessFlags) and its value (e.g., *0x4*, *CREATE_SUSPENDED*) are highly dependent on the EDR or logging source. Adjust the field name and value as needed for your environment.")`
| where (process_name="WerFault.exe" OR process_path="*\\WerFault.exe") AND (match(CreationFlags, "0x4") OR match(ProcessFlags, "0x4"))

`comment("Grouping results and providing context for investigation.")`
| stats count min(_time) as firstTime max(_time) as lastTime by dest, user, parent_process_name, process_name, process_path, process_command_line, CreationFlags, ProcessFlags
| convert ctime(firstTime) ctime(lastTime)
| rename dest as host
```

### WerFault.exe Network Connections
---
```sql
(`your_network_traffic_index`)
`comment("CIM-compliant search for network traffic events. Adjust sourcetype/index as needed.")`
(sourcetype=stream* OR sourcetype=pan:traffic OR sourcetype=suricata OR (sourcetype=crowdstrike:raw:json Event_SimpleName=NetworkConnectIP4))

`comment("Filter for network connections initiated by WerFault.exe.")`
| where (process_name="WerFault.exe" OR process_path="*\\WerFault.exe")

`comment("List of legitimate Microsoft domains for error reporting. This list should be reviewed and customized for your environment.")`
| where NOT (like(dest_host, "%.microsoft.com") OR like(dest_host, "%.windows.com") OR like(dest_host, "%.msftconnecttest.com") OR like(dest_host, "%.windowsupdate.com"))

`comment("Optional: Further filter for connections to newly registered or uncategorized domains if you have that data enriched in a lookup.")`
`comment("| lookup your_nrd_lookup domain as dest_host OUTPUT is_nrd")`
`comment("| lookup your_proxy_lookup dest as dest_host OUTPUT category")`
`comment("| where is_nrd=true OR category=\"uncategorized\"")`

`comment("Grouping results and providing context for investigation.")`
| stats count min(_time) as firstTime max(_time) as lastTime values(dest_host) as destinations by dest, user, parent_process_name, process_name, process_path, process_command_line
| convert ctime(firstTime) ctime(lastTime)
| rename dest as host
```

### Mimicked Web Content for C2
---
```sql
(`your_web_proxy_index`)
`comment("CIM-compliant search for web proxy or network traffic logs. Requires URL and process context.")`
(sourcetype=zscaler:nss:web OR sourcetype=stream:http OR sourcetype=pan:traffic OR sourcetype=crowdstrike:raw:json Event_SimpleName=NetworkConnectIP4)

`comment("Filter for URLs mimicking font file paths, a common C2 masquerading technique.")`
| where match(url, "(?i)\/assets\/fonts\/[^\/]+\.ttf$")

`comment("Exclude common web browsers to reduce noise. Legitimate font downloads are expected from browsers.")`
`comment("This requires process context in logs. If not available, this detection will be much noisier.")`
| where NOT (process_name IN ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "browser.exe", "opera.exe", "safari.exe"))

`comment("Grouping results and providing context for investigation.")`
| stats count min(_time) as firstTime max(_time) as lastTime values(url) as urls values(http_user_agent) as user_agents by dest, user, parent_process_name, process_name, process_path
| convert ctime(firstTime) ctime(lastTime)
| rename dest as host
```

### Remote Process Executable Memory Allocation
---
```sql
(`your_edr_index`)
`comment("This detection requires an EDR or other advanced logging source that can report on memory allocation in remote processes, specifically capturing memory protection flags. Field names (e.g., actor_process_name, target_process_name, allocation_flags) must be adapted to your specific data source.")`
(sourcetype=crowdstrike:raw:json Event_SimpleName=ProcessRollup2) OR (sourcetype=carbonblack:json)

`comment("Filter for events indicating memory allocation with RWX permissions (PAGE_EXECUTE_READWRITE = 0x40).")`
| where match(allocation_flags, "0x40")

`comment("Ensure the memory allocation is happening in a different process. This check might be implicit in some EDR events.")`
| where actor_process_name != target_process_name

`comment("FP Tuning: Exclude common legitimate processes that may perform this behavior. This list should be customized for your environment.")`
| where NOT (actor_process_name IN ("csrss.exe", "lsass.exe", "svchost.exe", "YourEDRAgent.exe") OR target_process_name IN ("msedge.exe", "chrome.exe", "firefox.exe"))

`comment("Grouping results for analysis and providing context.")`
| stats count min(_time) as firstTime max(_time) as lastTime by dest, user, actor_process_name, actor_process_path, actor_process_command_line, target_process_name, target_process_path
| convert ctime(firstTime) ctime(lastTime)
| rename dest as host
```

### WinHTTP Certificate Bypass Detected
---
```sql
(`your_edr_index`)
`comment("This detection requires an EDR or other advanced logging source that can report on API calls and their specific parameters. The field names and event types must be adapted to your specific data source.")`
(sourcetype=crowdstrike:raw:json) OR (sourcetype=sysmon) OR (sourcetype=carbonblack:json)

`comment("Filter for events indicating the use of security flags that bypass certificate validation. The field 'api_parameters' is a placeholder and should be replaced with the field from your data source that contains API call details.")`
| where match(api_parameters, "(?i)SECURITY_FLAG_IGNORE_CERT_CN_INVALID|SECURITY_FLAG_IGNORE_CERT_DATE_INVALID|SECURITY_FLAG_IGNORE_UNKNOWN_CA|SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE") OR match(api_parameters, "(?i)0x1000|0x2000|0x100|0x200")

`comment("FP Tuning: Exclude known legitimate processes. This list should be customized for your environment.")`
| where NOT process_name IN ("YourInternalUpdater.exe", "YourDevTool.exe")

`comment("Grouping results for analysis and providing context.")`
| stats count min(_time) as firstTime max(_time) as lastTime values(api_parameters) as evidence by dest, user, parent_process_name, process_name, process_path, process_command_line
| convert ctime(firstTime) ctime(lastTime)
| rename dest as host
```
