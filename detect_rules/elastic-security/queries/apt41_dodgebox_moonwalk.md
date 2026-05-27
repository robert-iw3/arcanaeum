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
FROM *
| WHERE (process.name IN ("taskhost.exe", "taskhostw.exe", "SandboxieWUAU.exe"))
  AND file.name == "sbiedll.dll"
  AND NOT (file.path LIKE "C:\\Windows\\System32\\*"
           OR file.path LIKE "C:\\Windows\\SysWOW64\\*")
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.name, file.path, file.name
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### APT41 DodgeBox CFG Bypass Attempt
---
```sql
FROM *
| WHERE (event.action IN ("memory_protection_changed", "virtual_protect"))
  AND (file.path LIKE "*\\ntdll.dll" OR file.path LIKE "*\\msvcrt.dll")
  AND (memory.protection IN ("PAGE_EXECUTE_READWRITE", "0x40"))
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.name, process.executable, file.path, memory.protection
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### APT41 DodgeBox DLL Hollowing Staging
---
```sql
FROM *
| WHERE event.action == "created"
  AND file.path LIKE "C:\\Windows\\Microsoft.NET\\assembly\\GAC_MSIL\\System.Data.Trace\\v4.0_4.0.0.0__\\*"
  AND file.name LIKE "*.dll"
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.name, process.executable, file.path, file.name
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### Google Drive C2 Activity
---
```sql
FROM *
| WHERE http.request.user_agent == "curl/7.54.0"
  AND url.domain == "www.googleapis.com"
  AND (
    (http.request.method == "PATCH" AND url.path LIKE "/upload/drive/v3/files/*")
    OR (http.request.method == "GET" AND url.path == "/drive/v3/files")
  )
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY source.ip, destination.ip, user.name, http.request.method, url.full, http.request.user_agent
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### Google Drive C2 by Non-Standard Process
---
```sql
FROM *
| WHERE event.type IN ("connection", "protocol")
  AND destination.domain IN ("drive.google.com", "www.googleapis.com")
  AND NOT process.name IN ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe", "brave.exe", "GoogleDrive.exe", "GoogleDriveFS.exe", "googledrivesync.exe")
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY destination.ip, user.name, process.name, process.executable, destination.domain
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### Windows Fibers Abuse for Evasion
---
```sql
FROM *
| WHERE event.action IN ("fiber_created", "thread_converted_to_fiber")
  AND NOT process.name IN ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe", "brave.exe", "sqlservr.exe", "javaw.exe")
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.name, process.executable
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### APT41 DodgeBox, MoonWalk and StealthVector Hashes
---
```sql
FROM endpoint
| WHERE (event.category == "process" OR event.category == "file")
  AND file.hash.md5 IN (
    "0d068b6d0523f069d1ada59c12891c4a", "b3067f382d70705d4c8f6977a7d7bee4",
    "d72f202c1d684c9a19f075290a60920f", "294cc02db5a122e3a1bc4f07997956da",
    "393065ef9754e3f39b24b2d1051eab61", "bcac2cbda36019776d7861f12d9b59c4",
    "f062183da590aba5e911d2392bc29181", "4141c4b827ff67c180096ff5f2cc1474",
    "bc85062de0f70afd44bb072b0b71a8cc", "72070b165d1f11bd4d009a81bf28a3e5",
    "f0953ed4a679b987a2da955788737602"
  )
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, file.name, file.path, file.hash.md5
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### MoonWalk Mutex Creation
---
```sql
FROM *
| WHERE event.category == "configuration"
  AND mutex.name == "Global\\ctXjvsAxpzyqElmk"
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.name, process.parent.name, mutex.name
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### MoonWalk File System Artifacts
---
```sql
FROM *
| WHERE event.category == "file"
  AND (file.path == "C:\\Windows\\Microsoft.NET\\assembly\\GAC_MSIL\\System.Data.Trace"
       OR (file.path LIKE "C:\\ProgramData\\*" AND LENGTH(file.name) == 32))
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.name, file.name, file.path
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```