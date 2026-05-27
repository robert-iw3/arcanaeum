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
from // <your_process_creation_index>
| where (
    (event.module == "wineventlog" and event.code == "4688")
    OR (event.module == "xmlwineventlog" and event.code == "1")
    OR (event.module == "crowdstrike" and event.action == "ProcessRollup2")
)
  and (
    process.name == "WerFault.exe"
    OR process.executable like "%\\WerFault.exe"
  )
  and (
    process.creation_flags like "%0x4%"
    OR process.flags like "%0x4%"
  )
| stats
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  BY
    host.name,
    user.name,
    process.parent.name,
    process.name,
    process.executable,
    process.command_line,
    process.creation_flags,
    process.flags
| eval
    firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"),
    lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
| rename host.name AS host
| keep
    host,
    user.name,
    process.parent.name,
    process.name,
    process.executable,
    process.command_line,
    process.creation_flags,
    process.flags,
    count,
    firstTime,
    lastTime
```

### WerFault.exe Network Connections
---
```sql
from // <your_network_traffic_index>
| where (
    process.name == "WerFault.exe"
    OR process.executable like "%\\WerFault.exe"
  )
  and not (
    destination.domain like "%.microsoft.com"
    OR destination.domain like "%.windows.com"
    OR destination.domain like "%.msftconnecttest.com"
    OR destination.domain like "%.windowsupdate.com"
  )
/* Optional: Uncomment and adjust if you have lookups for newly registered domains or proxy categories
| enrich your_nrd_lookup ON destination.domain WITH is_nrd
| enrich your_proxy_lookup ON destination.domain WITH category
| where is_nrd == true OR category == "uncategorized"
*/
| stats
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp),
    destinations = COLLECT(destination.domain)
  BY
    host.name,
    user.name,
    process.parent.name,
    process.name,
    process.executable,
    process.command_line
| eval
    firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"),
    lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
| rename host.name AS host
| keep
    host,
    user.name,
    process.parent.name,
    process.name,
    process.executable,
    process.command_line,
    destinations,
    count,
    firstTime,
    lastTime
```

### Mimicked Web Content for C2
---
```sql
from // <your_web_proxy_index>
| where url MATCHES "(?i)/assets/fonts/[^/]+\\.ttf$"
  and process.name not IN ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "browser.exe", "opera.exe", "safari.exe")
| stats
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp),
    urls = COLLECT(url),
    user_agents = COLLECT(http.user_agent)
  BY
    host.name,
    user.name,
    process.parent.name,
    process.name,
    process.executable
| eval
    firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"),
    lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
| rename host.name AS host
| keep
    host,
    user.name,
    process.parent.name,
    process.name,
    process.executable,
    urls,
    user_agents,
    count,
    firstTime,
    lastTime
```

### Remote Process Executable Memory Allocation
---
```sql
from // <your_edr_index>
| where process.memory.allocation.flags like "%0x40%"
  and process.actor.name != process.target.name
  and process.actor.name not IN ("csrss.exe", "lsass.exe", "svchost.exe", "YourEDRAgent.exe")
  and process.target.name not IN ("msedge.exe", "chrome.exe", "firefox.exe")
| stats
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  BY
    host.name,
    user.name,
    process.actor.name,
    process.actor.executable,
    process.actor.command_line,
    process.target.name,
    process.target.executable
| eval
    firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"),
    lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
| rename host.name AS host
| keep
    host,
    user.name,
    process.actor.name,
    process.actor.executable,
    process.actor.command_line,
    process.target.name,
    process.target.executable,
    count,
    firstTime,
    lastTime
```

### WinHTTP Certificate Bypass Detected
---
```sql
from // <your_edr_index>
| where (
    process.api.parameters MATCHES "(?i)SECURITY_FLAG_IGNORE_CERT_CN_INVALID|SECURITY_FLAG_IGNORE_CERT_DATE_INVALID|SECURITY_FLAG_IGNORE_UNKNOWN_CA|SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE"
    OR process.api.parameters MATCHES "(?i)0x1000|0x2000|0x100|0x200"
  )
  and process.name not IN ("YourInternalUpdater.exe", "YourDevTool.exe")
| stats
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp),
    evidence = COLLECT(process.api.parameters)
  BY
    host.name,
    user.name,
    process.parent.name,
    process.name,
    process.executable,
    process.command_line
| eval
    firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"),
    lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
| rename host.name AS host
| keep
    host,
    user.name,
    process.parent.name,
    process.name,
    process.executable,
    process.command_line,
    evidence,
    count,
    firstTime,
    lastTime
```
