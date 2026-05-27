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
processName IN ("taskhost.exe", "taskhostw.exe", "SandboxieWUAU.exe")
AND dllName = "sbiedll.dll"
AND dllPath NOT LIKE "C:\\Windows\\System32\\*"
AND dllPath NOT LIKE "C:\\Windows\\SysWOW64\\*"
| SELECT
    AgentName AS host_name,
    user AS user_name,
    processName AS process_name,
    dllPath AS file_path,
    dllName AS file_name,
    COUNT(*) AS count,
    MIN(eventTime) AS firstTime,
    MAX(eventTime) AS lastTime
| GROUP BY
    host_name, user_name, process_name, file_path, file_name
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### APT41 DodgeBox CFG Bypass Attempt
---
```sql
eventType IN ("memory_protection_changed", "virtual_protect")
AND dllPath IN ("*\\ntdll.dll", "*\\msvcrt.dll")
AND memoryProtection IN ("PAGE_EXECUTE_READWRITE", "0x40")
| SELECT
    AgentName AS host_name,
    user AS user_name,
    processName AS process_name,
    processPath AS process_path,
    dllPath AS module_path,
    memoryProtection AS memory_protection,
    COUNT(*) AS count,
    MIN(eventTime) AS firstTime,
    MAX(eventTime) AS lastTime
| GROUP BY
    host_name, user_name, process_name, process_path, module_path, memory_protection
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### APT41 DodgeBox DLL Hollowing Staging
---
```sql
eventType = "file_creation"
AND filePath LIKE "C:\\Windows\\Microsoft.NET\\assembly\\GAC_MSIL\\System.Data.Trace\\v4.0_4.0.0.0__\\*"
AND fileName LIKE "*.dll"
| SELECT
    AgentName AS host_name,
    user AS user_name,
    processName AS process_name,
    processPath AS process_path,
    filePath AS file_path,
    fileName AS file_name,
    COUNT(*) AS count,
    MIN(eventTime) AS firstTime,
    MAX(eventTime) AS lastTime
| GROUP BY
    host_name, user_name, process_name, process_path, file_path, file_name
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### Google Drive C2 Activity
---
```sql
networkUserAgent = "curl/7.54.0"
AND networkDomain = "www.googleapis.com"
AND (
  (networkHttpMethod = "PATCH" AND networkUrlPath LIKE "/upload/drive/v3/files/*")
  OR (networkHttpMethod = "GET" AND networkUrlPath = "/drive/v3/files")
)
| SELECT
    srcIp AS source_ip,
    dstIp AS destination_ip,
    user AS user_name,
    networkHttpMethod AS http_method,
    networkUrl AS url,
    networkUserAgent AS http_user_agent,
    COUNT(*) AS count,
    MIN(eventTime) AS firstTime,
    MAX(eventTime) AS lastTime
| GROUP BY
    source_ip, destination_ip, user_name, http_method, url, http_user_agent
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### Google Drive C2 by Non-Standard Process
---
```sql
eventType IN ("network_connection", "network_flow") AND dstDomain IN ("drive.google.com", "www.googleapis.com") AND processName NOT IN ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe", "brave.exe", "GoogleDrive.exe", "GoogleDriveFS.exe", "googledrivesync.exe")
| SELECT dstIp, user, processName, processPath, dstDomain, COUNT(*) AS count, MIN(eventTime) AS firstTime, MAX(eventTime) AS lastTime
| GROUP BY dstIp, user, processName, processPath, dstDomain
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### Windows Fibers Abuse for Evasion
---
```sql
eventType IN ("fiber_created", "thread_converted_to_fiber") AND processName NOT IN ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe", "brave.exe", "sqlservr.exe", "javaw.exe")
| SELECT AgentName, user, processName, processPath, COUNT(*) AS count, MIN(eventTime) AS firstTime, MAX(eventTime) AS lastTime
| GROUP BY AgentName, user, processName, processPath
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### APT41 DodgeBox, MoonWalk and StealthVector Hashes
---
```sql
(fileHash IN (
    "0d068b6d0523f069d1ada59c12891c4a", "b3067f382d70705d4c8f6977a7d7bee4",
    "d72f202c1d684c9a19f075290a60920f", "294cc02db5a122e3a1bc4f07997956da",
    "393065ef9754e3f39b24b2d1051eab61", "bcac2cbda36019776d7861f12d9b59c4",
    "f062183da590aba5e911d2392bc29181", "4141c4b827ff67c180096ff5f2cc1474",
    "bc85062de0f70afd44bb072b0b71a8cc", "72070b165d1f11bd4d009a81bf28a3e5",
    "f0953ed4a679b987a2da955788737602"
) AND (eventType = "process_creation" OR eventType = "file_creation"))
| SELECT AgentName, user, fileName, filePath, fileHash, COUNT(*) AS count, MIN(eventTime) AS firstTime, MAX(eventTime) AS lastTime
| GROUP BY AgentName, user, fileName, filePath, fileHash
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### MoonWalk Mutex Creation
---
```sql
mutexName = "Global\\ctXjvsAxpzyqElmk" AND eventType = "mutex_creation"
| SELECT AgentName, user, processName, parentProcessName, mutexName, COUNT(*) AS count, MIN(eventTime) AS firstTime, MAX(eventTime) AS lastTime
| GROUP BY AgentName, user, processName, parentProcessName, mutexName
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### MoonWalk File System Artifacts
---
```sql
eventType = "file_creation" AND (filePath = "C:\\Windows\\Microsoft.NET\\assembly\\GAC_MSIL\\System.Data.Trace" OR (filePath LIKE "C:\\ProgramData\\*" AND LENGTH(fileName) = 32))
| SELECT AgentName, user, processName, fileName, filePath, COUNT(*) AS count, MIN(eventTime) AS firstTime, MAX(eventTime) AS lastTime
| GROUP BY AgentName, user, processName, fileName, filePath
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```