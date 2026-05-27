### APT41's Evolving Toolset: DodgeBox and MoonWalk
---

APT41, a China-based threat actor, has updated its arsenal with a new loader, DodgeBox, and a backdoor, MoonWalk, both designed with advanced evasion techniques. DodgeBox, an evolution of StealthVector, employs sophisticated methods like DLL sideloading, call stack spoofing, and environmental keying to deliver MoonWalk, which further utilizes Google Drive for command-and-control (C2) communication and Windows Fibers for evasion.

A significant new finding is the use of Google Drive for command-and-control (C2) communication by the MoonWalk backdoor, which is noteworthy as it allows the malware to blend in with legitimate network traffic, making detection more challenging. Additionally, MoonWalk's use of Windows Fibers for evasion is a less commonly observed technique, indicating APT41's continuous efforts to innovate and bypass security solutions.

### Actionable Threat Data
---

DLL Sideloading Detection: Monitor for `taskhost.exe` or `SandboxieWUAU.exe` loading `sbiedll.dll` from unexpected or non-standard paths, as this is a primary execution method for DodgeBox.

Anomalous Process Behavior: Look for processes attempting to disable Control Flow Guard (CFG) by patching `ntdll!LdrpHandleInvalidUserCallTarget` or modifying `msvcrt!_guard_check_icall_fptr`, which are techniques used by DodgeBox for defense evasion.

DLL Hollowing and PEB Manipulation: Detect reflective loading of DLLs into memory, especially when accompanied by modifications to the Process Environment Block (PEB) to conceal newly loaded DLLs, a technique employed by DodgeBox and MoonWalk.

API Call Stack Spoofing: Implement advanced behavioral analytics to identify API calls (e.g., `NtAllocateVirtualMemory`) where the call stack appears to originate from legitimate Windows modules (KernelBase, ntdll) but lacks a clear originating malicious module, indicating call stack spoofing.

Google Drive C2 Activity: Monitor network traffic for suspicious connections to Google Drive, particularly from processes not typically associated with cloud storage synchronization, as MoonWalk uses Google Drive for C2.

Windows Fibers Abuse: Investigate processes exhibiting unusual usage of Windows Fibers, a technique employed by MoonWalk to evade AV/EDR solutions.

### APT41 DodgeBox/MoonWalk DLL Sideloading
---
```sql
`tstats` summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Image_Loads where (Image_Loads.process_name="taskhost.exe" OR ImageLoads.process_name="taskhostw.exe" OR Image_Loads.process_name="SandboxieWUAU.exe") AND Image_Loads.file_name="sbiedll.dll" by Image_Loads.dest Image_Loads.user Image_Loads.process_name Image_Loads.file_path Image_Loads.file_name
| `drop_dm_object_name("Image_Loads")`
// Filter out standard system directories to focus on suspicious load paths.
| where NOT (file_path LIKE "C:\\Windows\\System32\\%" OR file_path LIKE "C:\\Windows\\SysWOW64\\%")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `apt41_dodgebox_dll_sideloading_filter`
```

### APT41 DodgeBox CFG Bypass Attempt
---
```sql
`tstats` summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Events where (Events.action="memory_protection_changed" OR Events.action="virtual_protect") AND (Events.module_path="*\\ntdll.dll" OR Events.module_path="*\\msvcrt.dll") AND (Events.memory_protection="PAGE_EXECUTE_READWRITE" OR Events.memory_protection="0x40") by Events.dest Events.user Events.process_name Events.process_path Events.module_path Events.memory_protection
| `drop_dm_object_name("Events")`
-- comment: Focus on processes making system DLLs writable and executable, a key step in patching.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- comment: The following macro is a placeholder for environment-specific tuning. It should be used to filter out legitimate processes known to perform this action.
| `apt41_dodgebox_cfg_bypass_attempt_filter`
```

### APT41 DodgeBox DLL Hollowing Staging
---
```sql
`tstats` summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action="created" AND Filesystem.file_path="C:\\Windows\\Microsoft.NET\\assembly\\GAC_MSIL\\System.Data.Trace\\v4.0_4.0.0.0__\\*" AND Filesystem.file_name="*.dll" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name("Filesystem")`
-- comment: The file path is a specific indicator for the staging phase of DodgeBox's DLL hollowing technique.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- comment: The following macro is a placeholder for environment-specific tuning. It should be used to filter out legitimate processes known to perform this action.
| `apt41_dodgebox_dll_hollowing_staging_filter`
```

### Google Drive C2 Activity
---
```sql
tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.http_user_agent="curl/7.54.0" AND Web.url_domain="www.googleapis.com" AND ((Web.http_method="PATCH" AND Web.url_path="/upload/drive/v3/files/*") OR (Web.http_method="GET" AND Web.url_path="/drive/v3/files")) by Web.src, Web.dest, Web.user, Web.http_method, Web.url, Web.http_user_agent
`security_content_ctime(firstTime)`
`security_content_ctime(lastTime)`
`comment("This search uses the Web datamodel to find network traffic matching the C2 pattern of the APT41 MoonWalk backdoor.")`
`comment("The rule filters for the specific User-Agent string 'curl/7.54.0' hardcoded in the malware.")`
`comment("It further narrows the search to PATCH and GET requests to specific Google Drive API endpoints used for C2 communication.")`
```

### Google Drive C2 by Non-Standard Process
---
```sql
`tstats` summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Events where (Events.event_type="network_connection" OR Events.event_type="network_flow") AND (Events.dest_host IN ("drive.google.com", "www.googleapis.com")) by Events.dest Events.user Events.process_name Events.process_path Events.dest_host
| `drop_dm_object_name("Events")`
-- comment: Filter out common web browsers and the official Google Drive sync client to reduce noise.
| where NOT (process_name IN ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe", "brave.exe", "GoogleDrive.exe", "GoogleDriveFS.exe", "googledrivesync.exe"))
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- comment: The following macro is a placeholder for environment-specific tuning. It should be used to filter out other legitimate processes known to connect to Google services.
| `google_drive_c2_by_non_standard_process_filter`
```

### Windows Fibers Abuse for Evasion
---
```sql
-- comment: This detection assumes an EDR or agent is logging Fiber-related API calls (e.g., CreateFiber, ConvertThreadToFiber) and mapping them to a specific action or event type in the Endpoint data model. The action names used here are examples and may need to be adjusted for your specific data source.
`tstats` summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Events where (Events.action="fiber_created" OR Events.action="thread_converted_to_fiber") by Events.dest Events.user Events.process_name Events.process_path
| `drop_dm_object_name("Events")`
-- comment: Filter out common applications known to use Fibers to reduce noise. This list should be customized for your environment.
| where NOT (process_name IN (
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe", "brave.exe",
    "sqlservr.exe",
    "javaw.exe"
))
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- comment: The following macro is a placeholder for environment-specific tuning. It should be used to filter out other legitimate processes known to use Fibers.
| `windows_fibers_abuse_for_evasion_filter`
```

### APT41 DodgeBox, MoonWalk and StealthVector Hashes
---
```sql
`tstats` summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("0d068b6d0523f069d1ada59c12891c4a", "b3067f382d70705d4c8f6977a7d7bee4", "d72f202c1d684c9a19f075290a60920f", "294cc02db5a122e3a1bc4f07997956da", "393065ef9754e3f39b24b2d1051eab61", "bcac2cbda36019776d7861f12d9b59c4", "f062183da590aba5e911d2392bc29181", "4141c4b827ff67c180096ff5f2cc1474", "bc85062de0f70afd44bb072b0b71a8cc", "72070b165d1f11bd4d009a81bf28a3e5", "f0953ed4a679b987a2da955788737602") by Processes.dest, Processes.user, Processes.process_name, Processes.process_path, Processes.process_hash
| `drop_dm_object_name("Processes")`
-- comment: Normalize field names to combine with file-based events.
| rename process_hash as file_hash, process_name as file_name, process_path as file_path
| append [
    `tstats` summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("0d068b6d0523f069d1ada59c12891c4a", "b3067f382d70705d4c8f6977a7d7bee4", "d72f202c1d684c9a19f075290a60920f", "294cc02db5a122e3a1bc4f07997956da", "393065ef9754e3f39b24b2d1051eab61", "bcac2cbda36019776d7861f12d9b59c4", "f062183da590aba5e911d2392bc29181", "4141c4b827ff67c180096ff5f2cc1474", "bc85062de0f70afd44bb072b0b71a8cc", "72070b165d1f11bd4d009a81bf28a3e5", "f0953ed4a679b987a2da955788737602") by Filesystem.dest, Filesystem.user, Filesystem.file_name, Filesystem.file_path, Filesystem.file_hash
    | `drop_dm_object_name("Filesystem")`
]
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `apt41_dodgebox_moonwalk_and_stealthvector_hashes_filter`
```

### MoonWalk Mutex Creation
---
```sql
tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where Changes.object="Global\\ctXjvsAxpzyqElmk" by Changes.dest, Changes.user, Changes.process_name, Changes.parent_process_name, Changes.object
`security_content_ctime(firstTime)`
`security_content_ctime(lastTime)`
`comment("This search leverages the Change datamodel to find the creation of a mutex used by the MoonWalk backdoor.")`
`comment("The rule filters for a specific mutex name identified as an IOC for this threat.")`
```

### MoonWalk File System Artifacts
---
```sql
tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="C:\\Windows\\Microsoft.NET\\assembly\\GAC_MSIL\\System.Data.Trace" OR (Filesystem.file_path LIKE "C:\\ProgramData\\%" AND length(Filesystem.file_name)=32)) by Filesystem.dest, Filesystem.user, Filesystem.process_name, Filesystem.file_name, Filesystem.file_path
`security_content_ctime(firstTime)`
`security_content_ctime(lastTime)`
`comment("This search uses the Endpoint.Filesystem datamodel to find file creation events matching MoonWalk artifacts.")`
`comment("The rule filters for two distinct patterns: a hardcoded DLL path and a configuration file pattern in C:\\ProgramData.")`
`comment("The configuration file is identified by its location and a 32-character filename, consistent with an MD5 hash.")`
```