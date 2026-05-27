### Lazarus Group Weaponizing Open Source to Target Developers
---

The North Korea-backed Lazarus Group is actively weaponizing open-source software packages, particularly within the npm and PyPI ecosystems, to target developers and infiltrate software supply chains. Their primary objective is not financial gain through cryptomining, but rather espionage and long-term infiltration to exfiltrate sensitive data like credentials, API tokens, and SSH keys, ultimately gaining access to source code repositories, cloud infrastructure, and internal networks.

Recent intelligence indicates a significant evolution in Lazarus Group's tactics, moving beyond direct financial attacks to a more stealthy, multi-stage approach that leverages the trusted nature of open-source ecosystems for initial access and persistent compromise. This includes the use of sophisticated obfuscation techniques, anti-analysis checks, and modular malware delivery, making detection more challenging and enabling longer dwell times within compromised environments.

### Actionable Threat Data
---

Software Supply Chain Compromise (T1588.006, T1588.007, T1588.002):

Lazarus Group is actively publishing malicious packages to public repositories like npm and PyPI, often using typosquatting, brand-jacking, or combo-squatting to impersonate legitimate libraries (e.g., winston-compose, nodemailer-helper, servula, velocky, pycryptoconf, pycryptoenv). Monitor for newly introduced or infrequently downloaded packages, especially those with names similar to popular libraries.

Initial Access via Spearphishing (T1566.001, T1566.002):

The group uses fake job offers or collaboration requests on platforms like LinkedIn and GitHub to entice developers into downloading malicious content. Be vigilant for suspicious communications, especially those prompting downloads of executables or repositories.

Multi-Stage Payload Delivery (T1059.007, T1105):

Initial droppers contact C2 servers (e.g., 0927.vercel.app/api/ipcheck, log-server-lovat.vercel.app/api/ipcheck/703) to fetch heavily obfuscated loaders. These loaders then deploy multiple specialized payloads. Monitor network connections initiated by newly installed packages to unusual or suspicious domains, especially those using eval() on server responses.

Host Profiling and Evasion (T1497.001, T1497.003):

The malware performs checks for virtualized or sandboxed environments (e.g., wmic computersystem get model, manufacturer on Windows, system_profiler SPHardwareDataType on macOS, /proc/cpuinfo on Linux) to evade analysis. Look for processes executing system information commands followed by unusual network activity or process termination.

Data Exfiltration (T1041, T1048.003, T1020):

Payloads include clipboard stealers, credential stealers (e.g., "BeaverTail" targeting browser and crypto wallet data), broad file stealers (searching for keywords like .env, secret, wallet, mnemonic and extensions like .pdf, .docx, .csv), and Windows-specific keyloggers and screenshotters. Monitor for suspicious file access patterns, large outbound data transfers, and processes accessing sensitive directories or clipboard content.

Command and Control (T1071.001, T1071.004):

Lazarus Group utilizes legitimate services like GitHub, Slack, or Dropbox for C2 communication to blend in with normal network traffic. While difficult to detect solely based on domain, look for unusual activity patterns (e.g., high volume of data, unusual timing) to these services from developer machines or build environments.

### Lazarus Malicious Open-Source Package Installation
---
```sql
AgentName IS NOT EMPTY
AND (
  ProcessName IN ("npm.exe", "pip.exe", "pip3.exe", "npm", "pip", "pip3")
  AND ProcessCmd CONTAINS "install"
  AND ProcessCmd IN ("*winston-compose*", "*nodemailer-helper*", "*servula*", "*velocky*", "*vite-postcss-helper*", "*pycryptoconf*", "*pycryptoenv*")
)
| SELECT AgentName, User, ProcessName, ProcessCmd, COUNT(*) AS count, MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime
| GROUP BY AgentName, User, ProcessName, ProcessCmd
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### Lazarus C2 Connection via Vercel
---
```sql
SrcIp IS NOT EMPTY
AND (
  DstDomain IN ("0927.vercel.app", "log-server-lovat.vercel.app")
  OR Url CONTAINS "*0927.vercel.app/api/ipcheck*"
  OR Url CONTAINS "*log-server-lovat.vercel.app/api/ipcheck/703*"
)
| SELECT SrcIp, DstDomain, Url, User, COUNT(*) AS count, MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime
| GROUP BY SrcIp, DstDomain, Url, User
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### Lazarus Group Host Profiling for Evasion
---
```sql
AgentName IS NOT EMPTY
AND (
  ProcessName IN ("wmic.exe", "system_profiler")
  AND ProcessCmd IN ("*computersystem*get*model*", "*computersystem*get*manufacturer*", "*SPHardwareDataType*")
  AND ParentProcessName IN ("node.exe", "python.exe", "python3.exe", "pwsh.exe", "powershell.exe", "node", "python", "python3")
)
| SELECT AgentName, User, ParentProcessName, ProcessName, ProcessCmd, COUNT(*) AS count, MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime
| GROUP BY AgentName, User, ParentProcessName, ProcessName, ProcessCmd
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### Lazarus Group Clipboard Stealer Activity
---
```sql
AgentName IS NOT EMPTY
AND (
  (
    ProcessName IN ("powershell.exe", "pwsh.exe")
    AND ProcessCmd CONTAINS "Get-Clipboard"
  )
  OR ProcessName = "pbpaste"
)
AND ParentProcessName IN ("node.exe", "python.exe", "python3.exe", "pwsh.exe", "powershell.exe", "node", "python", "python3")
| SELECT AgentName, User, ParentProcessName, ProcessName, ProcessCmd, COUNT(*) AS count, MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime
| GROUP BY AgentName, User, ParentProcessName, ProcessName, ProcessCmd
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### Lazarus Group BeaverTail Credential Stealer Activity
---
```sql
AgentName IS NOT EMPTY
AND (
  ProcessName IN ("node.exe", "node", "python.exe", "python", "python3.exe", "python3", "pwsh.exe", "powershell.exe")
  AND (
    FileFullName IN ("Login Data", "Web Data", "Cookies")
    OR FilePath CONTAINS "acmacodkjbdgmoleebolmdjonilkdbch"
    OR FilePath CONTAINS "bfnaelmomeimhlpmgjnjophhpkkoljpa"
    OR FilePath CONTAINS "ibnejdfjmmkpcnlpebklmnkoeoihofec"
    OR FilePath CONTAINS "hifafgmccdpekplomjjkcfgodnhcellj"
    OR FilePath CONTAINS "nkbihfbeogaeaoehlefnkodbefgpgknn"
  )
  AND (
    FilePath CONTAINS "Chrome\\User Data"
    OR FilePath CONTAINS "Brave-Browser\\User Data"
    OR FilePath CONTAINS "/Application Support/Google/Chrome"
    OR FilePath CONTAINS "/.config/google-chrome"
  )
)
| SELECT AgentName, User, ProcessName, GROUP_CONCAT(FilePath) AS file_paths, COUNT(*) AS count, MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime
| GROUP BY AgentName, User, ProcessName
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### Lazarus Group Broad File Stealer Activity
---
```sql
(
  AgentName IS NOT EMPTY
  AND (
    ProcessName IN ("node.exe", "node", "python.exe", "python", "python3.exe", "python3", "pwsh.exe", "powershell.exe")
    AND (
      FileFullName LIKE "%.env%"
      OR FileFullName LIKE "%secret%"
      OR FileFullName LIKE "%wallet%"
      OR FileFullName LIKE "%mnemonic%"
      OR FileFullName LIKE "%keypair%"
      OR FileFullName LIKE "%credential%"
      OR FileFullName LIKE "%recovery%"
      OR FileFullName LIKE "%.pdf"
      OR FileFullName LIKE "%.docx"
      OR FileFullName LIKE "%.csv"
      OR FileFullName LIKE "%.json"
      OR FileFullName LIKE "%.txt"
    )
  )
)
| SELECT AgentName, User, ProcessName, COUNT_DISTINCT(FilePath) AS file_count, EventTime
| GROUP BY AgentName, User, ProcessName, TIME_BUCKET(EventTime, 10m) AS time_bucket
| UNION (
  SrcIp IS NOT EMPTY
  AND ProcessName IN ("node.exe", "node", "python.exe", "python", "python3.exe", "python3", "pwsh.exe", "powershell.exe")
  | SELECT AgentName, User, ProcessName, SUM(BytesOut) AS bytes_out, EventTime
  | GROUP BY AgentName, User, ProcessName, TIME_BUCKET(EventTime, 10m) AS time_bucket
)
| SELECT AgentName, User, ProcessName, MIN(time_bucket) AS firstTime, MAX(time_bucket) AS lastTime,
  MAX(file_count) AS distinct_sensitive_files_accessed, MAX(bytes_out) AS total_bytes_out
| GROUP BY AgentName, User, ProcessName
| WHERE distinct_sensitive_files_accessed > 20 AND total_bytes_out > 500000
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
```

### Lazarus Group Keylogger and Screenshotter Activity
---
```sql
(
  SrcIp IS NOT EMPTY
  AND DstIp = "144.172.94.226" AND DstPort = 5974
  | SELECT AgentName, User, ProcessName, DstIp, DstPort, COUNT(*) AS count, MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime
  | GROUP BY AgentName, User, ProcessName, DstIp, DstPort
  | SET detection_type = "IOC - C2 Communication"
)
| UNION (
  (
    AgentName IS NOT EMPTY
    AND ProcessName IN ("node.exe", "node", "powershell.exe", "pwsh.exe", "python.exe", "python")
    AND (
      FileFullName LIKE "%.png" OR FileFullName LIKE "%.jpeg" OR FileFullName LIKE "%.jpg" OR FileFullName LIKE "%.bmp"
    )
    AND (
      FilePath LIKE "%/windows cache/%" OR FilePath LIKE "%\\Temp\\%" OR FilePath LIKE "%\\tmp\\%" OR FilePath LIKE "%/tmp/%" OR FilePath LIKE "%/var/tmp/%"
    )
    | SELECT AgentName, User, ProcessName, COUNT(*) AS count, EventTime
    | SET event_type = "screenshot_created"
  )
  | UNION (
    SrcIp IS NOT EMPTY
    AND ProcessName IN ("node.exe", "node", "powershell.exe", "pwsh.exe", "python.exe", "python")
    AND NetworkDirection = "outbound" AND NetworkOutcome = "success"
    AND DstIp NOT LIKE "10.%"
    AND DstIp NOT LIKE "172.16.%"
    AND DstIp NOT LIKE "172.17.%"
    AND DstIp NOT LIKE "172.18.%"
    AND DstIp NOT LIKE "172.19.%"
    AND DstIp NOT LIKE "172.20.%"
    AND DstIp NOT LIKE "172.21.%"
    AND DstIp NOT LIKE "172.22.%"
    AND DstIp NOT LIKE "172.23.%"
    AND DstIp NOT LIKE "172.24.%"
    AND DstIp NOT LIKE "172.25.%"
    AND DstIp NOT LIKE "172.26.%"
    AND DstIp NOT LIKE "172.27.%"
    AND DstIp NOT LIKE "172.28.%"
    AND DstIp NOT LIKE "172.29.%"
    AND DstIp NOT LIKE "172.30.%"
    AND DstIp NOT LIKE "172.31.%"
    AND DstIp NOT LIKE "192.168.%"
    AND DstIp NOT LIKE "127.%"
    | SELECT AgentName, User, ProcessName, COUNT(*) AS count, EventTime
    | SET event_type = "network_outbound"
  )
  | GROUP BY AgentName, User, ProcessName, TIME_BUCKET(EventTime, 5m) AS time_bucket
  | SELECT AgentName, User, ProcessName, MIN(time_bucket) AS firstTime, MAX(time_bucket) AS lastTime, GROUP_CONCAT(event_type) AS event_types
  | WHERE event_types LIKE "%,%"
  | SET detection_type = "TTP - Screenshot and Exfil"
)
| SELECT AgentName, User, ProcessName, DstIp, DstPort, firstTime, lastTime, detection_type, event_types, count
| FORMAT firstTime = "yyyy-MM-dd'T'HH:mm:ss", lastTime = "yyyy-MM-dd'T'HH:mm:ss"
| SET User = COALESCE(User, ""), event_types = COALESCE(event_types, "")
```