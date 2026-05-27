### SLOW#TEMPEST Malware Obfuscation Techniques
---

The SLOW#TEMPEST campaign utilizes advanced obfuscation techniques, including control flow graph (CFG) obfuscation with dynamic jumps and obfuscated function calls, to evade analysis and detection. Understanding these evolving tactics is crucial for developing robust detection rules and strengthening defenses against sophisticated threats.


The article highlights the use of dynamic jumps and obfuscated function calls, which are significant as they make static analysis tools ineffective and complicate dynamic analysis by obscuring the true execution flow and function purposes. The anti-sandbox check requiring at least 6GB of RAM is a noteworthy new finding, indicating a specific evasion technique targeting analysis environments.

### Actionable Threat Data
---

Monitor for the distribution of malware as ISO files, a common technique used by SLOW#TEMPEST to bundle multiple files and potentially evade initial detection.

Look for instances of legitimate signed binaries, such as `DingTalk.exe`, being used for DLL sideloading to execute malicious DLLs like `zlibwapi.dll` (loader DLL) and `ipc_core.dll` (payload DLL).

Implement detection rules for the use of `GlobalMemoryStatusEx` API calls, specifically looking for checks related to system memory (e.g., requiring at least 6 GB of RAM) as an anti-sandbox technique.

Analyze and detect dynamic jump instructions (e.g., `JMP RAX`) and obfuscated function calls (`Call RAX`) where target addresses are computed at runtime, as these are key obfuscation methods employed by SLOW#TEMPEST.

Focus on behavioral analysis that can identify the execution of payloads that are separated from their loader DLLs, as the malicious code only executes when both are present.

### SLOW#TEMPEST ISO Hash
---
```sql
# Name: SLOW#TEMPEST ISO Hash
# Date: 2025-07-23
# References:
#   - https://unit42.paloaltonetworks.com/slow-tempest-malware-obfuscation/
# Description:
#   This detection rule identifies the presence of the SLOW#TEMPEST ISO file based on its SHA256 hash.
#   This ISO file is the initial delivery mechanism for the malware campaign.

(index=* OR sourcetype=*)
`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.sha256="a05882750f7caac48a5b5ddf4a1392aa704e6e584699fe915c6766306dae72cc" by Filesystem.dest Filesystem.file_name Filesystem.sha256
`drop_dm_object_name("Filesystem")`

# The following search can be used if you have file hash information in other data models or sourcetypes.
# | append [
#   `tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.file_hash="a05882750f7caac48a5b5ddf4a1392aa704e6e584699fe915c6766306dae72cc" by All_Traffic.dest All_Traffic.file_name All_Traffic.file_hash
#   `drop_dm_object_name("All_Traffic")`
#   `rename file_hash as sha256`
# ]
```

### SLOW#TEMPEST Loader DLL Hash
---
```sql
`comment("name: SLOW#TEMPEST Loader DLL IOC")`
`comment("date: 2025-07-23")`
`comment("description: This rule detects a specific DLL hash (3d3837eb69c3b072fdfc915468cbc8a83bb0db7babd5f7863bdf81213045023c) associated with the SLOW#TEMPEST campaign. This file is the loader DLL responsible for executing the malware's payload.")`
`comment("references: https://unit42.paloaltonetworks.com/slow-tempest-malware-obfuscation/")`

`comment("This query uses the Endpoint data model to find the malicious hash in both executed processes and files on disk.")`
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint where (nodename=Endpoint.Processes Processes.hash="3d3837eb69c3b072fdfc915468cbc8a83bb0db7babd5f7863bdf81213045023c") OR (nodename=Endpoint.Filesystem Filesystem.file_hash="3d3837eb69c3b072fdfc915468cbc8a83bb0db7babd5f7863bdf81213045023c") by dest, user, Processes.process_name, Processes.process_path, Filesystem.file_name, Filesystem.file_path, Processes.hash, Filesystem.file_hash
| `drop_dm_object_name("Processes")`
| `drop_dm_object_name("Filesystem")`
| `ctime(firstTime)`
| `ctime(lastTime)`

`comment("Combine fields from Processes and Filesystem data models for a unified view.")`
| fillnull value="" process_path, file_path, process_name, file_name, hash, file_hash
| eval process = if(process_name!="", process_name, file_name)
| eval path = if(process_path!="", process_path, file_path)
| eval sha256 = if(hash!="", hash, file_hash)

`comment("Analyst Note: This is a high-fidelity alert for a known malicious file. Any host with this file should be considered compromised and investigated immediately. The 'process' field indicates the name of the malicious file itself, while 'user' and 'dest' (host) show where it was observed.")`
| table firstTime, lastTime, dest, user, process, path, sha256, count
```

### SLOW#TEMPEST Payload DLL Hash
---
```sql
`comment("name: SLOW#TEMPEST Payload DLL IOC")`
`comment("date: 2025-07-23")`
`comment("description: This rule detects a specific DLL hash (3583cc881cb077f97422b9729075c9465f0f8f94647b746ee7fa049c4970a978) associated with the SLOW#TEMPEST campaign. This file is a DLL that contains the encrypted payload.")`
`comment("references: https://unit42.paloaltonetworks.com/slow-tempest-malware-obfuscation/")`

`comment("This query uses the Endpoint data model to find the malicious hash in both executed processes and files on disk.")`
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint where (nodename=Endpoint.Processes Processes.hash="3583cc881cb077f97422b9729075c9465f0f8f94647b746ee7fa049c4970a978") OR (nodename=Endpoint.Filesystem Filesystem.file_hash="3583cc881cb077f97422b9729075c9465f0f8f94647b746ee7fa049c4970a978") by dest, user, Processes.process_name, Processes.process_path, Filesystem.file_name, Filesystem.file_path, Processes.hash, Filesystem.file_hash
| `drop_dm_object_name("Processes")`
| `drop_dm_object_name("Filesystem")`
| `ctime(firstTime)`
| `ctime(lastTime)`

`comment("Combine fields from Processes and Filesystem data models for a unified view.")`
| fillnull value="" process_path, file_path, process_name, file_name, hash, file_hash
| eval process = if(process_name!="", process_name, file_name)
| eval path = if(process_path!="", process_path, file_path)
| eval sha256 = if(hash!="", hash, file_hash)

`comment("Analyst Note: This is a high-fidelity alert for a known malicious file. Any host with this file should be considered compromised and investigated immediately. The 'process' field indicates the name of the malicious file itself, while 'user' and 'dest' (host) show where it was observed.")`
| table firstTime, lastTime, dest, user, process, path, sha256, count
```

### ISO File Distribution
---
```sql
`comment("This detection rule identifies the creation of ISO (.iso) files on endpoints. The SLOW#TEMPEST campaign is known to use ISO files to distribute its malware payload, often bundled with legitimate applications and malicious DLLs. This detection focuses on ISO files created by processes that commonly download files from the internet, which is a primary vector for this threat.")`
`tstats` summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.action=created) AND (Filesystem.file_name="*.iso") by Filesystem.dest Filesystem.process_name Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name("Filesystem")`
| `rename` dest as host, process_name as process, file_path as path, file_name as file
| `ctime(firstTime)`
| `ctime(lastTime)`
`comment("Focus on ISO files created by browsers or email clients to reduce noise from legitimate administrative tools.")`
| search process IN ("chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe", "brave.exe", "outlook.exe", "thunderbird.exe")
`comment("FP Tuning: Legitimate software is often downloaded as an ISO. An investigation should correlate this activity with other events, such as the mounting of the ISO and subsequent execution of files from the mounted volume. The process list may need to be tuned for your environment.")`
| table firstTime, lastTime, host, process, path, file, count
```

### DLL Sideloading Detection
---
```sql
`comment("name: SLOW#TEMPEST DLL Sideloading via DingTalk")`
`comment("date: 2025-07-23")`
`comment("description: This detection identifies when the legitimate application DingTalk.exe loads a DLL from a non-standard file path. This behavior is associated with the SLOW#TEMPEST campaign, which uses this DLL sideloading technique to execute its malicious payload.")`
`comment("references: https://unit42.paloaltonetworks.com/slow-tempest-malware-obfuscation/")`

`comment("This detection rule identifies potential DLL sideloading activity associated with the SLOW#TEMPEST campaign.")`
tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.ImageLoads where (ImageLoads.action=loaded ImageLoads.file_name="*.dll" ImageLoads.process_name="DingTalk.exe") by ImageLoads.dest ImageLoads.process_name ImageLoads.file_path ImageLoads.file_name ImageLoads.file_hash
| `drop_dm_object_name("ImageLoads")`
| `rename` dest as host, process_name as process, file_path as loaded_dll_path, file_name as loaded_dll, file_hash as hash
`comment("Filter out common, legitimate DLL locations to focus on non-standard paths. These paths may need tuning for your environment.")`
| where NOT (like(loaded_dll_path, "C:\\Program Files\\%") OR like(loaded_dll_path, "C:\\Program Files (x86)\\%") OR like(loaded_dll_path, "C:\\Windows\\System32\\%") OR like(loaded_dll_path, "C:\\Windows\\SysWOW64\\%"))
| `ctime(firstTime)`
| `ctime(lastTime)`
`comment("FP Tuning: Legitimate plugins or updates for DingTalk could be loaded from other directories like AppData. Investigate the loaded DLL's reputation and origin. The list of excluded paths may need to be expanded based on legitimate application behavior in your environment.")`
| table firstTime, lastTime, host, process, loaded_dll_path, loaded_dll, hash, count
```

### Anti-Sandbox Memory Check
---
```sql
`comment("name: SLOW#TEMPEST Anti-Sandbox Memory Check")`
`comment("date: 2025-07-23")`
`comment("description: This detection rule identifies processes that call the 'GlobalMemoryStatusEx' Windows API. This behavior is a known sandbox evasion technique used by malware, including SLOW#TEMPEST, to check the system's physical memory size before executing a malicious payload. The rule is tuned to focus on unsigned processes or those running from non-standard locations.")`
`comment("references: https://unit42.paloaltonetworks.com/slow-tempest-malware-obfuscation/")`
`comment("mitre_ttp: T1497.001")`

`comment("This rule requires a data source that logs Windows API calls, such as an EDR. The index, sourcetype, and field names (e.g., api_call, process_path, signer) are placeholders and must be configured for your environment.")`
search index=endpoint sourcetype=edr:api_calls api_call="GlobalMemoryStatusEx"
| stats count min(_time) as firstTime max(_time) as lastTime by host, process_name, process_path, process_guid, user, signer
| `ctime(firstTime)`
| `ctime(lastTime)`

`comment("FP Tuning: Filter out signed processes or those in standard directories to focus on suspicious activity. Legitimate applications may perform this check, but are typically signed and run from Program Files or Windows directories.")`
| where isnull(signer) OR NOT (like(process_path, "C:\\Program Files\\%") OR like(process_path, "C:\\Program Files (x86)\\%") OR like(process_path, "C:\\Windows\\%"))

`comment("FP Tuning: Highlight processes that are not widespread in the environment, as malware may have a smaller footprint than legitimate software.")`
| eventstats dc(host) as host_prevalence by process_name
| where host_prevalence < 5

`comment("Analyst Note: Investigate the identified process. A positive hit on this rule is a strong indicator of sandbox evasion. Check the process's origin, subsequent network activity, and file modifications.")`
| table firstTime, lastTime, host, user, process_name, process_path, signer, host_prevalence, count
```

### Obfuscated Control Flow
---
```sql
`comment("name: SLOW#TEMPEST Obfuscated Control Flow Detection")`
`comment("date: 2025-07-23")`
`comment("description: This rule detects the execution of DLLs that exhibit signs of advanced code obfuscation, such as dynamic jumps (e.g., JMP RAX) or indirect function calls (e.g., CALL RAX). This technique is used by malware like SLOW#TEMPEST to hinder static and dynamic analysis.")`
`comment("references: https://unit42.paloaltonetworks.com/slow-tempest-malware-obfuscation/")`
`comment("mitre_ttp: T1027")`

`comment("PREREQUISITE: This detection requires an advanced EDR, sandbox, or memory analysis tool that can identify and alert on specific code obfuscation patterns at runtime or through analysis. The sourcetype, signature, and threat_name fields are placeholders and must be configured for your environment's data source.")`
search (index=endpoint sourcetype=edr_advanced_threats) (signature IN ("DynamicJumpInstruction", "IndirectCallInstruction", "ObfuscatedCodeExecution") OR threat_name="*Obfuscated Control Flow*")
`comment("The threat intelligence specifies this technique was observed in DLLs.")`
| where match(file_name, "(?i)\.dll$")

`comment("Aggregate alerts to summarize the activity for investigation.")`
| stats count min(_time) as firstTime max(_time) as lastTime by host, process_name, process_path, file_name, file_path, file_hash, signature, threat_name, user
| `ctime(firstTime)`
| `ctime(lastTime)`

`comment("Analyst Note: An alert from this rule is a strong indicator of malicious code attempting to evade analysis. Investigate the process that loaded the DLL. Examine the DLL's reputation, its origin on disk, and any subsequent suspicious activity from the parent process.")`
| table firstTime, lastTime, host, user, process_name, process_path, file_name, file_path, file_hash, signature, threat_name, count
```

###