### Katz Stealer Threat Intelligence Report
---

Katz Stealer is a potent Malware-as-a-Service (MaaS) infostealer that emerged in early 2025, designed to exfiltrate a wide range of sensitive information including credentials, cryptocurrency keys, and browser data. It employs sophisticated evasion techniques such as steganography, UAC bypass, and process hollowing to maintain stealth and persistence on compromised systems.


Recent intelligence indicates Katz Stealer's continued use of steganography within image files for payload delivery, with new observations of this technique being used in conjunction with Excel spreadsheets and HTA files for initial access. Additionally, the malware's ability to bypass Application-Bound Encryption (ABE) in Chromium-based browsers by extracting and saving decryption keys as plaintext files in the %APPDATA% folder is a significant evolution, allowing for more effective credential theft.

### Actionable Threat Data
---

Initial access often involves highly obfuscated JavaScript within .gz archive files, delivered via phishing emails or trojanized downloads, which then executes a PowerShell script.

The malware leverages PowerShell commands, often with the `-WindowStyle Hidden` flag, to download subsequent payloads, which can be hidden within seemingly harmless image files using steganography.

The PowerShell script downloads a seemingly harmless image file (.jpg, .jpeg, or .png) that contains a base64-encoded payload embedded between specific markers (e.g., `<<INICIO>>` and `<<FIM>>` or `<<base64_start>>` and `<<base64_end>>`).

Katz Stealer leverages `cmstp.exe` to bypass User Account Control (UAC) and gain elevated privileges, often by dropping a dummy INF file and invoking `cmstp.exe` for execution.

Persistence is established by creating a scheduled task that triggers upon system restart.

The main Katz Stealer module is executed via process hollowing within `MSBuild.exe`, allowing it to operate with SYSTEM-level access and evade detection.

Katz Stealer injects a specialized DLL into headless browser processes to access sensitive data, and for Chromium-based browsers, it decrypts and saves master encryption keys as plaintext files (e.g., `decrypted_chrome_key.txt`) in the `%APPDATA%` folder.

The malware targets a wide array of cryptocurrency wallets (desktop and browser extensions), searching for wallet files, private keys, and seed phrases using known file paths, folder names, and extension IDs.

Command and Control (C2) communication typically involves hardcoded IP addresses and HTTP/HTTPS for data exfiltration, with stolen data sent in chunks via HTTP POST requests.

### Obfuscated JS Execution
---
```sql
`comment("This detection rule identifies the execution of potentially obfuscated JavaScript files. This technique is used by malware droppers, such as the initial stage of Katz Stealer, to execute malicious code on a victim's machine.")`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
  where (Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe") AND Processes.process="*.js*"
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`

`comment("Calculate metrics to assess command line complexity, which can be a strong indicator of obfuscation. A high ratio of special characters is suspicious.")`
| eval cmd_len = len(process)
| eval special_chars = len(replace(process, "[a-zA-Z0-9\\s.:\\\\]", ""))
| eval special_char_ratio = special_chars / cmd_len

`comment("Identify execution from suspicious parent processes. Malware droppers are often launched from email clients, office applications, or archive utilities.")`
| eval is_suspicious_parent = if(match(parent_process_name, /(?i)(outlook|winword|excel|powerpnt|pwsh|powershell|explorer|winrar|7z|rundll32)\.exe$/), 1, 0)

`comment("The core detection logic combines multiple indicators: long command lines, high ratio of special characters, suspicious parentage, and specific obfuscation patterns. Thresholds for length and ratio may need tuning to reduce potential false positives from legitimate, complex scripts.")`
| where (cmd_len > 1024 AND special_char_ratio > 0.20) OR (is_suspicious_parent=1 AND special_char_ratio > 0.30) OR match(process, /(?i)(\[][^\]\[]*\[\]|\[\]\s*\+)/)

`comment("Format the results for triage and investigation.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process, cmd_len, special_char_ratio
| `obfuscated_javascript_execution_filter`
```

### PowerShell Steganography Download
---
```sql
`comment("This search detects PowerShell commands that download an image file and then attempt to read its content or decode strings from it. This is a steganography technique used by malware like Katz Stealer to hide malicious payloads.")`
`comment("Requires process execution logs (e.g., Sysmon Event ID 1, EDR data) mapped to the Endpoint data model.")`
from datamodel=Endpoint.Processes
| where (process_name="powershell.exe" OR process_name="pwsh.exe")
| where (
    `comment("Looks for a web download command.")`
    (process="*Invoke-WebRequest*" OR process="*System.Net.WebClient*" OR process="*iwr*" OR process="*DownloadFile*") AND
    `comment("Looks for a reference to an image file in the command.")`
    (process="*.jpg*" OR process="*.jpeg*" OR process="*.png*" OR process="*.gif*" OR process="*.bmp*") AND
    `comment("Looks for a command to read file content or decode a string.")`
    (process="*Get-Content*" OR process="*gc*" OR process="*ReadAllText*" OR process="*FromBase64String*" OR process="*select-string*")
)
`comment("FP Note: Legitimate administrative scripts could potentially perform these actions, though the combination is rare. If false positives occur, consider filtering by parent process or excluding known safe scripts/users.")`
| stats count min(_time) as firstTime max(_time) as lastTime values(process) as process by dest, user, parent_process
| rename dest as host
| convert ctime(firstTime), ctime(lastTime)
| fields firstTime, lastTime, host, user, parent_process, process, count
```

### Hidden PowerShell Download
---
```sql
`comment("This rule detects PowerShell executing with a hidden window to download a remote image file, a technique used by malware like Katz Stealer for stealthy payload delivery.")`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
  where Processes.process_name="powershell.exe"
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.process_guid
| `drop_dm_object_name(Processes)`

`comment("Filter for commands that combine a hidden window flag, a download method, and a URL pointing to an image file. This combination is a strong indicator of malicious activity, though legitimate automation scripts could trigger it. Review the parent process and full command line for context.")`
| where match(process, /(?i)(-w|-win|-windowstyle)\s+(1|h|hid|hidden)/)
  AND (match(process, /(?i)(iwr|invoke-webrequest|start-bitstransfer|\.downloadfile\(|\.downloadstring\(|new-object\s+system\.net\.webclient)/))
  AND match(process, /(?i)https?:\/\/[^\s"]+\.(jpg|jpeg|png|gif|bmp)("|')?/)

`comment("Format the results for triage and investigation.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process, process_id, process_guid
| `hidden_powershell_image_file_download_filter`
```

Method 2:

---
```sql
(index=*) (sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1) OR (sourcetype=crowdstrike:falcon:event:detailed event_simpleName=ProcessRollup2)
-- key: normalize common field names for process execution events
| eval process_name = coalesce(process_name, ProcessName), process_command_line = coalesce(CommandLine, process_command_line), parent_process_name = coalesce(ParentImage, parent_process_name), host = coalesce(Computer, host), user = coalesce(User, user)
-- key: filter for powershell.exe launched with a hidden window from a script host
| where (process_name = "powershell.exe" AND (lower(process_command_line) LIKE "%-windowstyle hidden%" OR lower(process_command_line) LIKE "%-w hidden%")) AND parent_process_name IN ("wscript.exe", "cscript.exe")
-- comment: While this is a strong indicator of malicious activity, some administrative scripts may use this combination. If false positives occur, consider excluding known-good script paths or specific parent command lines.
-- key: aggregate results to create a single alert per host and command
| stats count min(_time) as firstTime max(_time) as lastTime by host, user, parent_process_name, process_command_line
-- key: convert epoch time to a human-readable format
| convert ctime(firstTime) ctime(lastTime)
-- key: rename fields for better readability in alerts
| rename host as source_host, process_command_line as command_line
```

### UAC Bypass via cmstp.exe
---
```sql
`comment("This rule detects the execution of cmstp.exe with specific command-line arguments commonly used to bypass User Account Control (UAC). Malware, such as Katz Stealer, leverages this technique to execute code with elevated privileges without prompting the user.")`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
  where Processes.process_name="cmstp.exe"
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.process_guid
| `drop_dm_object_name(Processes)`

`comment("Filter for the /au (auto-install) switch, which is a key indicator of this UAC bypass. Legitimate use is rare and typically limited to system administration scripts. The parent process should be reviewed for context, as droppers often use script hosts or Office applications to initiate this bypass.")`
| where match(process, /(?i)\s\/au\s/)

`comment("Highlight executions from suspicious parent processes to aid in triage.")`
| eval is_suspicious_parent = if(match(parent_process_name, /(?i)(powershell|pwsh|cmd|wscript|cscript|winword|excel|outlook|rundll32)\.exe$/), "True", "False")

`comment("Format the results for triage and investigation.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process_name, is_suspicious_parent, process_name, process, process_id, process_guid
| `uac_bypass_via_cmstp_exe_filter`
```

Method 2:

---
```sql
(index=*) (sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1) OR (sourcetype=crowdstrike:falcon:event:detailed event_simpleName=ProcessRollup2)
-- key: normalize common field names for process execution events
| eval process_name = coalesce(process_name, ProcessName), process_command_line = coalesce(CommandLine, process_command_line), parent_process_name = coalesce(ParentImage, parent_process_name), host = coalesce(Computer, host), user = coalesce(User, user)
-- key: filter for cmstp.exe execution with command-line arguments indicative of UAC bypass
| where (process_name = "cmstp.exe" AND (process_command_line LIKE "% /au %" OR process_command_line LIKE "% /s %") AND process_command_line LIKE "%.inf%")
-- comment: Legitimate use of cmstp.exe with these flags is uncommon on standard workstations. To reduce potential false positives, consider filtering for INF files in non-standard locations (e.g., AppData, Temp) or for suspicious parent processes (e.g., wscript.exe, powershell.exe).
-- key: aggregate results to create a single alert per host and command
| stats count min(_time) as firstTime max(_time) as lastTime values(parent_process_name) as parent_processes by host, user, process_command_line
-- key: convert epoch time to a human-readable format
| convert ctime(firstTime) ctime(lastTime)
-- key: rename fields for better readability in alerts
| rename host as source_host, process_command_line as command_line
```

### Process Hollowing MSBuild.exe
---
```sql
`comment("This rule detects MSBuild.exe making network connections, a highly anomalous behavior. MSBuild is a software build tool and should not typically initiate network traffic on its own. This activity is a strong indicator of process injection or hollowing, where malware like Katz Stealer uses the process to run malicious code.")`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Network_Traffic
  where All_Network.process_name="MSBuild.exe"
  by All_Network.dest All_Network.user All_Network.process_name All_Network.process_path All_Network.process_guid All_Network.dest_ip All_Network.dest_port
| `drop_dm_object_name(All_Network)`

`comment("Legitimate MSBuild processes may connect to known package repositories (e.g., nuget.org). This logic could be extended to filter out such known-good destinations if false positives occur in specific build environments.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, process_name, process_path, process_guid, dest_ip, dest_port
| `process_hollowing_via_msbuild_filter`
```

### Scheduled Task Persistence
---
```sql
`comment("This rule detects the creation of a scheduled task using schtasks.exe with suspicious parameters, a common persistence technique used by malware like Katz Stealer.")`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
  where Processes.process_name="schtasks.exe" AND match(Processes.process, /(?i)\/create/)
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.process_guid
| `drop_dm_object_name(Processes)`

`comment("Identify suspicious characteristics of the scheduled task command line.")`
| eval suspicious_location = if(match(process, /(?i)\/tr\s+.*(appdata|temp|public|programdata|users\\.*\\downloads).*(.exe|.dll|.ps1|.vbs|.js|.bat|.com)/), 1, 0)
| eval suspicious_trigger = if(match(process, /(?i)\s\/sc\s+(onlogon|onstart|onidle|minute)/), 1, 0)
| eval high_privileges = if(match(process, /(?i)(\s\/ru\s+\"system\"|\s\/rl\s+highest)/), 1, 0)
| eval lolbas_execution = if(match(process, /(?i)\/tr\s+.*(powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript)/), 1, 0)

`comment("The core detection logic triggers if a task executes from a suspicious location, or if it combines a suspicious trigger with high privileges or the execution of a LOLBAS. These patterns are highly indicative of malicious persistence. Legitimate admin scripts may trigger this; review the parent process and full command for context.")`
| where suspicious_location=1 OR (suspicious_trigger=1 AND (high_privileges=1 OR lolbas_execution=1))

`comment("Format the results for triage and investigation.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process, suspicious_location, suspicious_trigger, high_privileges, lolbas_execution
| `suspicious_scheduled_task_creation_filter`
```

Method 2:

---
```sql
(index=*) (sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1) OR (sourcetype=crowdstrike:falcon:event:detailed event_simpleName=ProcessRollup2)
-- key: normalize common field names for process execution events
| eval process_name = coalesce(process_name, ProcessName), process_command_line = coalesce(CommandLine, process_command_line), parent_process_name = coalesce(ParentImage, parent_process_name), host = coalesce(Computer, host), user = coalesce(User, user)
-- key: filter for schtasks.exe creating a task that runs on startup/logon and executes MSBuild.exe
| where process_name = "schtasks.exe" AND process_command_line LIKE "%/create%" AND (process_command_line LIKE "%/sc onstart%" OR process_command_line LIKE "%/sc onlogon%") AND process_command_line LIKE "%MSBuild.exe%"
-- comment: This behavior can be legitimate on developer workstations or build servers. Consider excluding these systems or known-good parent processes to reduce false positives.
-- key: aggregate results to create a single alert per host and command
| stats count min(_time) as firstTime max(_time) as lastTime values(parent_process_name) as parent_processes by host, user, process_command_line
-- key: convert epoch time to a human-readable format
| convert ctime(firstTime) ctime(lastTime)
-- key: rename fields for better readability in alerts
| rename host as source_host, process_command_line as command_line
```

### Browser Credential Dump Files
---
```sql
`comment("This rule detects the creation of specific plaintext files in the AppData directory, which are known artifacts of the Katz Stealer malware dumping decrypted browser credentials.")`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem
  where Filesystem.action="created" AND (Filesystem.file_name="decrypted_chrome_key.txt" OR Filesystem.file_name="decrypted_brave_key.txt" OR Filesystem.file_name="decrypted_edge_key.txt")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`

`comment("Filter for files created within the AppData directory, a common location for malware to store temporary or stolen data. The file names are highly specific to Katz Stealer.")`
| where match(file_path, /(?i)AppData\\Roaming/)

`comment("The creating process should be investigated to confirm malicious activity. While these file names are specific, a security researcher or tool could potentially create similarly named files.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, process_name, file_path, file_name
| `katz_stealer_browser_credential_dump_file_creation_filter`
```

Method 2:

---
```sql
(index=*) (sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=11) OR (sourcetype=crowdstrike:falcon:event:detailed event_simpleName=FileWritten)
-- key: normalize common field names for file creation events
| eval file_name = coalesce(TargetFilename, FileName), file_path = coalesce(TargetFilename, Path), process_name = coalesce(Image, ProcessName), host = coalesce(Computer, host), user = coalesce(User, user)
-- key: search for specific file names in the AppData directory
| where (file_name LIKE "decrypted_%_key.txt" AND file_path LIKE "%\\AppData\\Roaming\\%")
-- comment: The file names are highly specific to Katz Stealer's behavior. However, it's worth investigating the creating process to rule out any custom administrative scripts that might use similar naming conventions.
-- key: aggregate results to create a single alert per host and file
| stats count min(_time) as firstTime max(_time) as lastTime values(process_name) as creating_process by host, user, file_name, file_path
-- key: convert epoch time to a human-readable format
| convert ctime(firstTime) ctime(lastTime)
-- key: rename fields for better readability in alerts
| rename host as source_host
```

### Katz Stealer C2 Communication
---
```sql
`comment("This search detects network traffic associated with Katz Stealer C2 communication, identified by its unique User-Agent string 'katz-ontop'.")`
`comment("Requires web proxy logs or network traffic data mapped to the Splunk Web data model.")`
from datamodel=Web.Web
`comment("The 'katz-ontop' User-Agent is a specific indicator for this malware as noted in threat intelligence.")`
| where http_user_agent = "*katz-ontop*"
`comment("FP Note: This User-Agent is highly specific, making false positives unlikely. However, malware can be reconfigured. Consider supplementing this detection with rules that look for connections to known Katz Stealer C2 IPs.")`
| stats count min(_time) as firstTime max(_time) as lastTime values(url) as url by src, dest, user, http_user_agent
| rename src as source, dest as destination
| convert ctime(firstTime), ctime(lastTime)
| fields firstTime, lastTime, source, destination, user, http_user_agent, url, count
```

### Suspicious C2 Connections
---
```sql
--
-- Name: Katz Stealer C2 Communication
--
-- Date: 2025-07-23
--
-- References:
-- - https://www.sentinelone.com/blog/katz-stealer-powerful-maas-on-the-prowl-for-credentials-and-crypto-assets/
--
-- Description:
-- This search identifies network traffic to known Command and Control (C2) infrastructure
-- associated with the Katz Stealer malware family. It uses a list of hardcoded IP addresses
-- and domains from the provided threat intelligence.
--
-- False Positive Sensitivity: Medium
--
-- Tags:
-- - Tactic: Command and Control
-- - Technique: T1071
-- - Malware: Katz Stealer
--
-- Recommended Scoping:
-- Update the initial search line with the appropriate index and sourcetypes for your environment's
-- network traffic data (e.g., firewall, proxy, DNS, or EDR logs).
--
(index=*) (sourcetype=pan:traffic OR sourcetype=stream:http OR sourcetype=zeek:conn OR sourcetype=cisco:asa)
-- key: search for network traffic to known Katz Stealer C2 indicators
| where (
    dest_host IN (
        "katz-panel.com",
        "katz-stealer.com",
        "katzstealer.com",
        "pub-ce02802067934e0eb072f69bf6427bf6.r2.dev",
        "twist2katz.com",
        "Zxczxczxczxc.twist2katz.com"
    )
    OR
    dest_ip IN (
        "172.67.146.103",
        "185.107.74.40",
        "195.182.25.71",
        "31.177.109.39",
        "80.64.18.219"
    )
)
-- comment: IP addresses can be re-assigned over time. If this rule generates false positives,
-- consider verifying the current status of the indicators or integrating a threat intelligence feed.
-- key: aggregate results to create a single alert per source-destination pair
| stats count min(_time) as firstTime max(_time) as lastTime by src_ip, dest_ip, dest_host, user
-- key: convert epoch time to a human-readable format
| convert ctime(firstTime) ctime(lastTime)
-- key: rename fields for better readability in alerts
| rename src_ip as source, dest_ip as destination_ip, dest_host as destination_domain
```
