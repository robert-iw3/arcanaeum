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
FROM * // replace with your index or data-stream
| WHERE (
  process.name IN ("npm.exe", "pip.exe", "pip3.exe", "npm", "pip", "pip3")
  AND process.command_line LIKE "*install*"
  AND process.command_line IN ("*winston-compose*", "*nodemailer-helper*", "*servula*", "*velocky*", "*vite-postcss-helper*", "*pycryptoconf*", "*pycryptoenv*")
)
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.name, process.command_line
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### Lazarus C2 Connection via Vercel
---
```sql
FROM *
| WHERE (
  destination.domain IN ("0927.vercel.app", "log-server-lovat.vercel.app")
  OR url.full LIKE "*0927.vercel.app/api/ipcheck*"
  OR url.full LIKE "*log-server-lovat.vercel.app/api/ipcheck/703*"
)
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY source.ip, destination.domain, url.full, user.name
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### Lazarus Group Host Profiling for Evasion
---
```sql
FROM *
| WHERE (
  process.name IN ("wmic.exe", "system_profiler")
  AND process.command_line IN ("*computersystem*get*model*", "*computersystem*get*manufacturer*", "*SPHardwareDataType*")
  AND process.parent.name IN ("node.exe", "python.exe", "python3.exe", "pwsh.exe", "powershell.exe", "node", "python", "python3")
)
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.name, process.command_line
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### Lazarus Group Clipboard Stealer Activity
---
```sql
FROM *
| WHERE (
  (
    process.name IN ("powershell.exe", "pwsh.exe")
    AND process.command_line LIKE "*Get-Clipboard*"
  )
  OR process.name = "pbpaste"
)
AND process.parent.name IN ("node.exe", "python.exe", "python3.exe", "pwsh.exe", "powershell.exe", "node", "python", "python3")
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.name, process.command_line
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### Lazarus Group BeaverTail Credential Stealer Activity
---
```sql
FROM *
| WHERE (
  process.name IN ("node.exe", "node", "python.exe", "python", "python3.exe", "python3", "pwsh.exe", "powershell.exe")
  AND (
    file.name IN ("Login Data", "Web Data", "Cookies")
    OR file.path LIKE "%acmacodkjbdgmoleebolmdjonilkdbch%"
    OR file.path LIKE "%bfnaelmomeimhlpmgjnjophhpkkoljpa%"
    OR file.path LIKE "%ibnejdfjmmkpcnlpebklmnkoeoihofec%"
    OR file.path LIKE "%hifafgmccdpekplomjjkcfgodnhcellj%"
    OR file.path LIKE "%nkbihfbeogaeaoehlefnkodbefgpgknn%"
  )
  AND (
    file.path LIKE "%Chrome\\User Data%"
    OR file.path LIKE "%Brave-Browser\\User Data%"
    OR file.path LIKE "%/Application Support/Google/Chrome%"
    OR file.path LIKE "%/.config/google-chrome%"
  )
)
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), file_paths = GROUP_CONCAT(file.path)
  BY host.name, user.name, process.name
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### Lazarus Group Broad File Stealer Activity
---
```sql
FROM *
| WHERE (
  process.name IN ("node.exe", "node", "python.exe", "python", "python3.exe", "python3", "pwsh.exe", "powershell.exe")
  AND (
    file.name LIKE "%.env%"
    OR file.name LIKE "%secret%"
    OR file.name LIKE "%wallet%"
    OR file.name LIKE "%mnemonic%"
    OR file.name LIKE "%keypair%"
    OR file.name LIKE "%credential%"
    OR file.name LIKE "%recovery%"
    OR file.name LIKE "%.pdf"
    OR file.name LIKE "%.docx"
    OR file.name LIKE "%.csv"
    OR file.name LIKE "%.json"
    OR file.name LIKE "%.txt"
  )
)
| STATS file_count = COUNT_DISTINCT(file.path) BY @timestamp, host.name, user.name, process.name
| EVAL time_bucket = DATE_TRUNC(10 minutes, @timestamp)
| STATS distinct_sensitive_files_accessed = SUM(file_count) BY time_bucket, host.name, user.name, process.name
| APPEND (
  FROM network
  | WHERE process.name IN ("node.exe", "node", "python.exe", "python", "python3.exe", "python3", "pwsh.exe", "powershell.exe")
  | STATS bytes_out = SUM(network.bytes_out) BY @timestamp, host.name, user.name, process.name
  | EVAL time_bucket = DATE_TRUNC(10 minutes, @timestamp)
  | STATS total_bytes_out = SUM(bytes_out) BY time_bucket, host.name, user.name, process.name
)
| STATS firstTime = MIN(time_bucket), lastTime = MAX(time_bucket), distinct_sensitive_files_accessed = MAX(distinct_sensitive_files_accessed), total_bytes_out = MAX(total_bytes_out)
  BY host.name, user.name, process.name
| WHERE distinct_sensitive_files_accessed > 20 AND total_bytes_out > 500000
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### Lazarus Group Keylogger and Screenshotter Activity
---
```sql
FROM *
| WHERE (
  destination.ip = "144.172.94.226" AND destination.port = 5974
)
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.name, destination.ip, destination.port
| EVAL detection_type = "IOC - C2 Communication", firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
| APPEND (
  FROM endpoint
  | WHERE (
    process.name IN ("node.exe", "node", "powershell.exe", "pwsh.exe", "python.exe", "python")
    AND (
      file.name LIKE "%.png" OR file.name LIKE "%.jpeg" OR file.name LIKE "%.jpg" OR file.name LIKE "%.bmp"
    )
    AND (
      file.path LIKE "%/windows cache/%" OR file.path LIKE "%\\Temp\\%" OR file.path LIKE "%\\tmp\\%" OR file.path LIKE "%/tmp/%" OR file.path LIKE "%/var/tmp/%"
    )
  )
  | EVAL event_type = "screenshot_created"
  | STATS count = COUNT(*) BY @timestamp, host.name, user.name, process.name
  | APPEND (
    FROM network
    | WHERE (
      process.name IN ("node.exe", "node", "powershell.exe", "pwsh.exe", "python.exe", "python")
      AND network.direction = "outbound" AND network.outcome = "success"
      AND NOT destination.ip LIKE "10.%"
      AND NOT destination.ip LIKE "172.16.%"
      AND NOT destination.ip LIKE "172.17.%"
      AND NOT destination.ip LIKE "172.18.%"
      AND NOT destination.ip LIKE "172.19.%"
      AND NOT destination.ip LIKE "172.20.%"
      AND NOT destination.ip LIKE "172.21.%"
      AND NOT destination.ip LIKE "172.22.%"
      AND NOT destination.ip LIKE "172.23.%"
      AND NOT destination.ip LIKE "172.24.%"
      AND NOT destination.ip LIKE "172.25.%"
      AND NOT destination.ip LIKE "172.26.%"
      AND NOT destination.ip LIKE "172.27.%"
      AND NOT destination.ip LIKE "172.28.%"
      AND NOT destination.ip LIKE "172.29.%"
      AND NOT destination.ip LIKE "172.30.%"
      AND NOT destination.ip LIKE "172.31.%"
      AND NOT destination.ip LIKE "192.168.%"
      AND NOT destination.ip LIKE "127.%"
    )
    | EVAL event_type = "network_outbound"
    | STATS count = COUNT(*) BY @timestamp, host.name, user.name, process.name
  )
  | EVAL time_bucket = DATE_TRUNC(5 minutes, @timestamp)
  | STATS firstTime = MIN(time_bucket), lastTime = MAX(time_bucket), event_types = GROUP_CONCAT(event_type) BY host.name, user.name, process.name
  | WHERE event_types LIKE "%,%"
  | EVAL detection_type = "TTP - Screenshot and Exfil", firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
)
| KEEP host.name, user.name, process.name, destination.ip, destination.port, firstTime, lastTime, detection_type, event_types, count
| EVAL user.name = COALESCE(user.name, ""), event_types = COALESCE(event_types, "")
```