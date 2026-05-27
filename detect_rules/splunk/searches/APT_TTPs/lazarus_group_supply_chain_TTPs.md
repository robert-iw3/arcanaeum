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

NOTE: The following splunk queries depend on the CIM add-on configured with standard data models present.

### Lazarus Malicious Open-Source Package Installation
---
```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (
    -- Look for common package manager process names. This list may need to be customized for your environment.
    Processes.process_name IN ("npm.exe", "pip.exe", "pip3.exe", "npm", "pip", "pip3")
    AND
    -- Filter for installation commands.
    Processes.process = "*install*"
    AND
    -- Identify known malicious packages used by Lazarus. This list should be updated as new intel becomes available.
    (Processes.process IN ("*winston-compose*", "*nodemailer-helper*", "*servula*", "*velocky*", "*vite-postcss-helper*", "*pycryptoconf*", "*pycryptoenv*"))
)
by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- comment: False positives are unlikely but possible if a legitimate package is created with one of these names. The primary tuning mechanism is to update the list of malicious packages.
| `lazarus_malicious_open_source_package_installation_filter`
```

### Lazarus C2 Connection via Vercel
---
```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (
    -- Filter for known Lazarus C2 domains hosted on Vercel
    Network_Traffic.dest IN ("0927.vercel.app", "log-server-lovat.vercel.app")
    OR
    -- Also check the URL field for the full path for more specific matching
    Network_Traffic.url IN ("*0927.vercel.app/api/ipcheck*", "*log-server-lovat.vercel.app/api/ipcheck/703*")
) by Network_Traffic.src, Network_Traffic.dest, Network_Traffic.url, Network_Traffic.user
| `drop_dm_object_name("Network_Traffic")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- comment: These are specific IOCs, so false positives should be rare. However, Vercel is a legitimate service. If these IOCs become stale, they should be removed or updated to prevent potential future collisions.
| `lazarus_c2_connection_via_vercel_filter`
```

### Lazarus Group Host Profiling for Evasion
---
```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (
    -- Search for specific system information discovery commands used to identify virtualized environments.
    (Processes.process_name IN ("wmic.exe", "system_profiler") AND Processes.process IN ("*computersystem*get*model*", "*computersystem*get*manufacturer*", "*SPHardwareDataType*"))
)
-- Filter for suspicious parent processes like scripting engines, as seen in the Lazarus payloads.
AND Processes.parent_process_name IN ("node.exe", "python.exe", "python3.exe", "pwsh.exe", "powershell.exe", "node", "python", "python3")
by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- comment: This detection identifies discovery commands spawned by scripting engines. False positives may occur from legitimate system administration or inventory scripts that use Python, PowerShell, or Node.js. Review the full script content and purpose to validate. The Linux variant of this TTP involves reading /proc/cpuinfo, which would require file-level monitoring to detect.
| `lazarus_group_host_profiling_for_evasion_filter`
```

### Lazarus Group Clipboard Stealer Activity
---
```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (
    -- Detects clipboard access commands on Windows and macOS
    (Processes.process_name IN ("powershell.exe", "pwsh.exe") AND Processes.process="*Get-Clipboard*")
    OR
    (Processes.process_name="pbpaste")
)
-- The parent process is often a scripting engine, as seen in the Lazarus Node.js payload
AND Processes.parent_process_name IN ("node.exe", "python.exe", "python3.exe", "pwsh.exe", "powershell.exe", "node", "python", "python3")
by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- comment: Legitimate administrative or automation scripts may perform this action. Investigate the parent process and the script's purpose. Correlate these findings with outbound network traffic from the parent process (`parent_process_name`) on the same host (`dest`) to confirm data exfiltration.
| `lazarus_group_clipboard_stealer_activity_filter`
```

### Lazarus Group BeaverTail Credential Stealer Activity
---
```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_paths from datamodel=Endpoint.Filesystem where
    -- Filter for suspicious processes, such as scripting engines, that are not legitimate browsers.
    (Filesystem.process_name IN ("node.exe", "node", "python.exe", "python", "python3.exe", "python3", "pwsh.exe", "powershell.exe"))
    AND
    -- Filter for access to sensitive browser credential files or specific crypto wallet extension folders.
    (
        Filesystem.file_name IN ("Login Data", "Web Data", "Cookies")
        OR Filesystem.file_path LIKE "%acmacodkjbdgmoleebolmdjonilkdbch%" -- MetaMask
        OR Filesystem.file_path LIKE "%bfnaelmomeimhlpmgjnjophhpkkoljpa%" -- Phantom
        OR Filesystem.file_path LIKE "%ibnejdfjmmkpcnlpebklmnkoeoihofec%" -- Coinbase Wallet
        OR Filesystem.file_path LIKE "%hifafgmccdpekplomjjkcfgodnhcellj%" -- Ronin Wallet
        OR Filesystem.file_path LIKE "%nkbihfbeogaeaoehlefnkodbefgpgknn%" -- MetaMask (alt)
    )
    -- Ensure the path is related to a common browser's user data directory to add context.
    AND (Filesystem.file_path LIKE "%Chrome\\User Data%" OR Filesystem.file_path LIKE "%Brave-Browser\\User Data%" OR Filesystem.file_path LIKE "%/Application Support/Google/Chrome%" OR Filesystem.file_path LIKE "%/.config/google-chrome%")
by Filesystem.dest, Filesystem.user, Filesystem.process_name
| `drop_dm_object_name("Filesystem")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- comment: This detection identifies non-browser processes accessing credential stores. False positives may occur from legitimate system administration, backup, or developer tools that interact with browser data. Investigate the process, its parent, and any associated scripts or network connections to determine legitimacy.
| `lazarus_group_beavertail_credential_stealer_activity_filter`
```

### Lazarus Group Broad File Stealer Activity
---
```sql
| tstats `security_content_summariesonly` count from datamodel=Endpoint.Filesystem where
    -- Focus on scripting engines and common utilities that are unlikely to perform these actions legitimately at scale.
    Filesystem.process_name IN ("node.exe", "node", "python.exe", "python", "python3.exe", "python3", "pwsh.exe", "powershell.exe")
    AND (
        -- Keywords
        Filesystem.file_name LIKE "%.env%" OR Filesystem.file_name LIKE "%secret%" OR Filesystem.file_name LIKE "%wallet%" OR Filesystem.file_name LIKE "%mnemonic%" OR Filesystem.file_name LIKE "%keypair%" OR Filesystem.file_name LIKE "%credential%" OR Filesystem.file_name LIKE "%recovery%"
        OR
        -- Common document extensions
        Filesystem.file_name LIKE "%.pdf" OR Filesystem.file_name LIKE "%.docx" OR Filesystem.file_name LIKE "%.csv" OR Filesystem.file_name LIKE "%.json" OR Filesystem.file_name LIKE "%.txt"
    )
    by _time, Filesystem.dest, Filesystem.user, Filesystem.process_name, Filesystem.file_path
| `drop_dm_object_name("Filesystem")`
| bin _time span=10m
| stats dc(file_path) as file_count by _time, dest, user, process_name
| append [
    | tstats `security_content_summariesonly` sum(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic where All_Traffic.process_name IN ("node.exe", "node", "python.exe", "python", "python3.exe", "python3", "pwsh.exe", "powershell.exe") by _time, All_Traffic.dest, All_Traffic.user, All_Traffic.process_name
    | `drop_dm_object_name("All_Traffic")`
    | bin _time span=10m
    | stats sum(bytes_out) as bytes_out by _time, dest, user, process_name
]
| stats min(_time) as firstTime, max(_time) as lastTime, values(file_count) as distinct_sensitive_files_accessed, values(bytes_out) as total_bytes_out by dest, user, process_name
| where distinct_sensitive_files_accessed > 20 AND total_bytes_out > 500000
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- comment: This detection correlates mass file access of sensitive documents with significant data exfiltration by the same process. Thresholds for 'distinct_sensitive_files_accessed' (default: >20) and 'total_bytes_out' (default: >500KB) may need tuning for your environment. Legitimate backup, archival, or developer tools could trigger this; investigate the process and its command line to confirm malicious activity.
| `lazarus_group_broad_file_stealer_activity_filter`
```

### Lazarus Group Keylogger and Screenshotter Activity
---
```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where
    -- High-fidelity IOC
    (All_Traffic.dest_ip="144.172.94.226" AND All_Traffic.dest_port="5974")
    by All_Traffic.dest, All_Traffic.user, All_Traffic.process_name, All_Traffic.dest_ip, All_Traffic.dest_port
| `drop_dm_object_name("All_Traffic")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval detection_type="IOC - C2 Communication"
| append [
    | tstats `security_content_summariesonly` count from datamodel=Endpoint.Filesystem where
        -- Look for scripting engines creating image files
        (Filesystem.process_name IN ("node.exe", "node", "powershell.exe", "pwsh.exe", "python.exe", "python"))
        AND (Filesystem.file_name LIKE "%.png" OR Filesystem.file_name LIKE "%.jpeg" OR Filesystem.file_name LIKE "%.jpg" OR Filesystem.file_name LIKE "%.bmp")
        -- Focus on temp directories or the specific path from the report
        AND (Filesystem.file_path LIKE "%/windows cache/%" OR Filesystem.file_path LIKE "%\\Temp\\%" OR Filesystem.file_path LIKE "%\\tmp\\%" OR Filesystem.file_path LIKE "%/tmp/%" OR Filesystem.file_path LIKE "%/var/tmp/%")
        by _time, Filesystem.dest, Filesystem.user, Filesystem.process_name
    | `drop_dm_object_name("Filesystem")`
    | eval event_type="screenshot_created"
    | append [
        | tstats `security_content_summariesonly` count from datamodel=Network_Traffic where
            -- Look for the same scripting engines making outbound connections
            (All_Traffic.process_name IN ("node.exe", "node", "powershell.exe", "pwsh.exe", "python.exe", "python"))
            AND All_Traffic.action=allowed AND All_Traffic.direction=outbound
            -- Exclude private/local traffic
            AND `cidrmatch("10.0.0.0/8", All_Traffic.dest_ip)`=false AND `cidrmatch("172.16.0.0/12", All_Traffic.dest_ip)`=false AND `cidrmatch("192.168.0.0/16", All_Traffic.dest_ip)`=false AND `cidrmatch("127.0.0.0/8", All_Traffic.dest_ip)`=false
            by _time, All_Traffic.dest, All_Traffic.user, All_Traffic.process_name
        | `drop_dm_object_name("All_Traffic")`
        | eval event_type="network_outbound"
    ]
    -- Correlate events within a 5-minute window
    | bin _time span=5m
    | stats min(_time) as firstTime, max(_time) as lastTime, values(event_type) as event_types by dest, user, process_name
    -- Find processes that did both actions
    | where mvcount(event_types) > 1
    | `security_content_ctime(firstTime)`
    | `security_content_ctime(lastTime)`
    | eval detection_type="TTP - Screenshot and Exfil"
]
| fillnull value=""
-- comment: This rule has two parts. The IOC-based part is high-fidelity. The TTP-based part detects suspicious behavior; false positives could occur if legitimate automation scripts (e.g., for UI testing) create screenshots and also have network capabilities. Investigate the process, its parent, and the destination of the network traffic to confirm maliciousness.
| `lazarus_group_keylogger_and_screenshotter_activity_filter`
```