### Stealer-Traffer Ecosystem Threat Report
---

The stealer-traffer ecosystem is a sophisticated cybercrime model where "traffers" distribute stealer malware, often enhanced with FUD (Fully Undetectable) loaders and crypters, to compromise systems and steal sensitive data. This stolen information, including credentials and cryptocurrency, is then sold on underground markets, with profits shared among stealer operators, traffic team administrators, and traffers.

Recent developments in the stealer-traffer ecosystem include the evolution of StealC to version 2, which now incorporates server-side decryption, dynamic C2 targeting, and enhanced evasion techniques, making it a more potent and stealthy threat. Additionally, there's a growing trend of stealer loaders, such as those used by the Dungeon Team, embedding cryptocurrency miners, turning compromised systems into revenue-generating bots for the attackers.

### Actionable Threat Data
---

Monitor for the execution of FUD loaders and crypters, which often employ techniques like code obfuscation, anti-analysis checks (e.g., debugger detection, environment fingerprinting), and dynamic payload loading to evade traditional antivirus and EDR solutions. (T1027.002, T1027, T1497)

Implement network traffic analysis to detect unusual C2 communication patterns, such as the JSON-based protocol and RC4 encryption used by StealC V2, or the exfiltration of large volumes of sensitive data (e.g., browser credentials, cryptocurrency wallet data, system information) to suspicious external IP addresses or domains. (T1041, T1071.001)

Look for evidence of SEO poisoning and malvertising, where attackers manipulate search engine results or use malicious advertisements on platforms like YouTube, Instagram, and TikTok to redirect users to phishing pages or sites hosting stealer malware. (T1566.002, T1566.001)

Detect the presence of cryptocurrency miners by monitoring for unusual spikes in CPU or GPU utilization, unexpected network connections to mining pools, or the creation of new scheduled tasks or services designed to maintain persistence for mining operations. (T1496)

Be vigilant for the distribution of stealer malware via seemingly legitimate channels, such as malicious attachments in spoofed emails (e.g., Rhadamanthys using typosquatted domains and fake invoices), or through compromised legitimate websites (e.g., government agencies, universities) that are exploited to host malicious links or redirects. (T1566.001, T1189)

### FUD Loader Execution
---
```sql
-- Description: Detects a process performing multiple checks for virtualization environments, analysis tools, or system configurations (like language settings). This behavior is common in FUD (Fully Undetectable) loaders and other malware attempting to evade automated analysis or target specific regions.
-- Author: RW
-- Date: 2025-08-18

-- MITRE TTPs:
-- - T1497: Virtualization/Sandbox Evasion
-- - T1027: Obfuscated Files or Information
-- - T1027.002: Software Packing

-- False Positive Sensitivity: Medium
-- - This detection may trigger on legitimate system administration scripts or diagnostic tools.
-- - The `process_name` exclusion list should be tuned based on baseline activity in your environment.

search = | tstats `summariesonly` count from datamodel=Endpoint.Registry where (Registry.registry_path IN ("*\\SOFTWARE\\Oracle\\VirtualBox*", "*\\SOFTWARE\\VMware, Inc.\\VMware Tools*", "*\\SYSTEM\\CurrentControlSet\\Services\\VBox*", "*\\SYSTEM\\CurrentControlSet\\Services\\VMware*", "*\\HARDWARE\\DEVICEMAP\\Scsi*", "*\\HARDWARE\\Description\\System*", "*\\Keyboard Layout\\Preload*", "*\\Control Panel\\International*")) by _time, Registry.dest, Registry.process_name, Registry.process_id, Registry.registry_path | `drop_dm_object_name("Registry")` | rename registry_path as action \
| append [| tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process IN ("*wmic computersystem get model*", "*wmic computersystem get manufacturer*", "*wmic bios get serialnumber*", "*wmic cpu get numberofcores*", "systeminfo", "tasklist")) by _time, Processes.dest, Processes.process_name, Processes.process_id, Processes.process | `drop_dm_object_name("Processes")` | rename process as action] \
`comment("Filter out known legitimate processes. This list may need tuning for your specific environment to reduce false positives.")` \
| where NOT (process_name IN ("vboxservice.exe", "vmtoolsd.exe", "msinfo32.exe", "TiWorker.exe", "svchost.exe", "powershell.exe", "WmiPrvSE.exe")) \
`comment("Aggregate checks by process over a 5-minute window.")` \
| bin _time span=5m \
| stats dc(action) as distinct_action_count, values(action) as actions by _time, dest, process_name, process_id \
`comment("Trigger an alert if a single process performs 2 or more distinct checks, indicating a high likelihood of evasion.")` \
| where distinct_action_count >= 2 \
`comment("Provide final fields for investigation.")` \
| rename dest as endpoint, process_name as suspicious_process, process_id as suspicious_process_id, actions as observed_actions, distinct_action_count as observed_action_count \
| fields _time, endpoint, suspicious_process, suspicious_process_id, observed_actions, observed_action_count
```

### Unusual C2 Communication
---
```sql
-- Description: Detects processes with a high ratio of outbound to inbound network traffic over common web ports (80, 443). This behavior can indicate data exfiltration over a C2 channel, a technique used by info-stealers like StealC V2.
-- Author: RW
-- Date: 2025-08-18

-- MITRE TTPs:
-- - T1041: Exfiltration Over C2 Channel
-- - T1071.001: Application Layer Protocol: Web Protocols

-- False Positive Sensitivity: Medium
-- - This detection may trigger on legitimate applications that upload large files (e.g., cloud backup, software updates, large file sharing).
-- - The `process_name` exclusion list is critical for tuning and should be adapted to your environment's baseline activity.

search = | tstats `summariesonly` sum(All_Traffic.bytes_out) as total_bytes_out, sum(All_Traffic.bytes_in) as total_bytes_in from datamodel=Endpoint.Network_Traffic where All_Traffic.direction=outbound AND All_Traffic.dest_port IN (80, 443) AND nodename=All_Traffic by _time, All_Traffic.src, All_Traffic.process_name, All_Traffic.dest \
| `drop_dm_object_name("All_Traffic")` \
`comment("Set the time window for aggregation to 10 minutes.")` \
| bin _time span=10m \
`comment("Aggregate traffic stats per process, source, and destination.")` \
| stats sum(total_bytes_out) as total_bytes_out, sum(total_bytes_in) as total_bytes_in by _time, src, process_name, dest \
`comment("Filter out connections to private IP space.")` \
| where NOT (cidrmatch("10.0.0.0/8", dest) OR cidrmatch("172.16.0.0/12", dest) OR cidrmatch("192.168.0.0/16", dest) OR cidrmatch("127.0.0.0/8", dest)) \
`comment("FP Filtering: Exclude common processes known for high upload volumes. This list should be tuned for your environment.")` \
| where NOT (process_name IN ("msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "teams.exe", "onedrive.exe", "outlook.exe", "svchost.exe", "backgroundtaskhost.exe", "wudfhost.exe", "compatelrunner.exe", "officeclicktorun.exe")) \
`comment("Filter for connections with a significant amount of outbound data (e.g., > 10KB).")` \
| where total_bytes_out > 10000 \
`comment("Calculate the exfiltration ratio. Handle cases where inbound bytes is zero to avoid division errors.")` \
| eval exfil_ratio = if(total_bytes_in > 0, round(total_bytes_out / total_bytes_in, 2), total_bytes_out) \
`comment("Trigger alert if the outbound traffic is at least 10x greater than inbound traffic.")` \
| where exfil_ratio > 10 \
`comment("Provide final fields for investigation.")` \
| rename src as endpoint, dest as destination_ip, process_name as suspicious_process \
| fields _time, endpoint, suspicious_process, destination_ip, total_bytes_out, total_bytes_in, exfil_ratio
```

### SEO Poisoning/Malvertising
---
```sql
-- Description: Detects when a user navigates from a common search engine or social media platform to a URL that appears to be a direct download link for a potentially malicious file type (e.g., .exe, .zip, .iso). This pattern is indicative of SEO poisoning or malvertising campaigns used to distribute malware.
-- Author: RW
-- Date: 2025-08-18

-- MITRE TTPs:
-- - T1566.001: Spearphishing Attachment
-- - T1566.002: Spearphishing Link

-- False Positive Sensitivity: Medium
-- - This detection may trigger on legitimate downloads initiated from a search.
-- - The `dest_domain` exclusion list is a critical tuning point and should be customized for your environment to allowlist legitimate software distribution sites.

search = `comment("Search the Web datamodel for events with a referrer URL.")` \
search `datamodel("Web", "Web")` http_referrer!="" \
`comment("Extract the domain from the referrer URL.")` \
| rex field=http_referrer "https?:\/\/(?<referrer_domain>[^\/]+)" \
`comment("Filter for referrers from common search engines and social media sites.")` \
| where match(referrer_domain, "(google|bing|yahoo|duckduckgo|yandex)\..*|.*(youtube|tiktok|instagram|facebook|twitter|linkedin)\.com|t\.co") \
`comment("Filter for destination URLs that contain a suspicious file extension.")` \
| where match(url, "\.(exe|dll|msi|bat|cmd|ps1|vbs|iso|img|zip|rar|7z)(\?.*)?$") \
`comment("Extract the domain from the destination URL for further filtering.")` \
| rex field=url "https?:\/\/(?<dest_domain>[^\/]+)" \
`comment("FP Filtering: Exclude known safe download sources and ensure referrer is different from destination.")` \
| where NOT match(dest_domain, ".*(windowsupdate\.microsoft|download\.microsoft|dl\.google|adobe|ninite)\.com") AND referrer_domain != dest_domain \
`comment("Summarize the results to reduce noise and provide a clear alert.")` \
| stats count, min(_time) as firstTime, max(_time) as lastTime by dest, user, process_name, url, http_referrer \
| `ctime(firstTime)` \
| `ctime(lastTime)` \
| rename dest as endpoint, user as actor, process_name as process, url as destination_url, http_referrer as referrer_url \
| fields firstTime, lastTime, endpoint, actor, process, destination_url, referrer_url, count
```

### Cryptocurrency Miner Presence
---
```sql
-- Description: Detects cryptocurrency miner activity by looking for suspicious process command-line arguments or network connections to known mining pool domains and ports. This behavior is indicative of resource hijacking (T1496), often deployed by stealer loaders.
-- Author: RW
-- Date: 2025-08-18

-- MITRE TTPs:
-- - T1496: Resource Hijacking

-- False Positive Sensitivity: Medium
-- - This rule may generate false positives from legitimate system administration tools or software that uses similar keywords or ports.
-- - The filter for `svchost.exe` is a starting point; other legitimate processes may need to be allowlisted based on your environment's baseline.

search = | tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process IN ("*--donate-level*", "*-o stratum+tcp://*", "*-xmr*", "*--proxy*", "*-pool*", "*pool.minexmr.com*", "*moneroocean.stream*", "*--threads*", "*--cpu-affinity*", "*--randomx*", "*xmrig*") by _time, Processes.dest, Processes.process_name, Processes.process_id, Processes.process_path, Processes.process \
| `drop_dm_object_name("Processes")` \
| rename process as indicator \
| eval evidence_type="ProcessCommandLineIndicator" \
| append [ \
    | tstats `summariesonly` values(All_Traffic.dest_host) as dest_host, values(All_Traffic.dest_port) as dest_port from datamodel=Endpoint.Network_Traffic where (All_Traffic.dest_host IN ("*stratum*", "*monero*", "*xmrpool*", "*nanopool*", "*ethermine*", "*minergate*", "*nicehash*") OR All_Traffic.dest_port IN (3333, 4444, 5555, 6666, 7777, 8888, 9999, 14444, 20580)) AND NOT All_Traffic.dest_port IN (80, 443) by _time, All_Traffic.dest, All_Traffic.process_name, All_Traffic.process_id, All_Traffic.process_path \
    | `drop_dm_object_name("All_Traffic")` \
    | eval indicator = dest_host + ":" + dest_port \
    | eval evidence_type = case(match(dest_host, "(stratum|monero|xmrpool|nanopool|ethermine|minergate|nicehash)"), "NetworkUrlIndicator", isnotnull(dest_port), "NetworkPortIndicator") \
] \
`comment("Filter out events that are not associated with a process ID.")` \
| where isnotnull(process_id) AND process_id != 0 \
`comment("FP Filtering: Miners often masquerade as system processes but rarely run from the correct system directory. This may need tuning.")` \
| where NOT (process_name="svchost.exe" AND match(process_path, "system32")) \
`comment("Summarize findings to create a single alert per process over a 10-minute window.")` \
| bin _time span=10m \
| stats min(_time) as start_time, max(_time) as end_time, values(evidence_type) as evidence_types, values(indicator) as indicators by dest, process_name, process_id \
| `ctime(start_time)` \
| `ctime(end_time)` \
| rename dest as endpoint \
| fields start_time, end_time, endpoint, process_name, process_id, evidence_types, indicators
```

### Malware via Legitimate Channels
---
```sql
-- Description: Detects the execution of a potentially malicious file (e.g., .iso, .zip, .exe) shortly after it was created by a browser or email client. This pattern is common in attacks leveraging phishing attachments (T1566.001) or drive-by compromises from legitimate but compromised websites (T1189).
-- Author: RW
-- Date: 2025-08-18

-- MITRE TTPs:
-- - T1566.001: Spearphishing Attachment
-- - T1189: Drive-by Compromise

-- False Positive Sensitivity: Medium
-- - This detection may trigger on legitimate software installers or updaters downloaded by users.
-- - Consider adding trusted software publishers or specific legitimate file names to an exclusion list to tune for your environment.

search = | tstats `summariesonly` earliest(_time) as file_create_time from datamodel=Endpoint.Filesystem where Filesystem.action=created AND Filesystem.process_name IN ("msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "opera.exe", "brave.exe", "outlook.exe", "thunderbird.exe") AND (Filesystem.file_path LIKE "%\\Downloads\\%" OR Filesystem.file_path LIKE "%\\AppData\\Local\\Temp\\%" OR Filesystem.file_path LIKE "%\\Outlook\\Content.Outlook\\%") AND Filesystem.file_name IN ("*.iso", "*.img", "*.cab", "*.zip", "*.rar", "*.lnk", "*.js", "*.vbs", "*.hta", "*.exe", "*.scr", "*.msi") AND Filesystem.file_hash != "0" AND Filesystem.file_hash != "" by Filesystem.dest, Filesystem.file_hash, Filesystem.file_name, Filesystem.file_path, Filesystem.process_name \
| `drop_dm_object_name("Filesystem")` \
| rename process_name as delivery_app \
`comment("Join with process execution events for the same file hash on the same host.")` \
| join type=inner dest, file_hash [ \
    | tstats `summariesonly` earliest(_time) as process_exec_time, values(Processes.process) as process_command_line from datamodel=Endpoint.Processes where Processes.file_hash != "0" AND Processes.file_hash != "" by Processes.dest, Processes.file_hash, Processes.process_name \
    | `drop_dm_object_name("Processes")` \
    `comment("FP Tuning: Exclude processes signed by highly trusted publishers. This requires signer info in your data model and may need to be customized.")` \
    `comment("| where NOT (file_signer IN (\"Microsoft Corporation\", \"Google LLC\", \"Mozilla Corporation\") AND file_is_signed=true)")` \
] \
`comment("Key correlation: Ensure the process was created shortly after the file was written (within 5 minutes).")` \
| where process_exec_time > file_create_time AND (process_exec_time - file_create_time) < 300 \
`comment("Summarize to create a single alert per malicious file.")` \
| stats min(file_create_time) as first_seen, max(process_exec_time) as last_seen, values(delivery_app) as delivery_apps, values(file_name) as file_names, values(file_path) as file_paths, values(process_name) as executed_processes, values(process_command_line) as process_command_lines by dest, file_hash \
| `ctime(first_seen)` \
| `ctime(last_seen)` \
| rename dest as endpoint \
| fields first_seen, last_seen, endpoint, file_hash, delivery_apps, file_names, file_paths, executed_processes, process_command_lines
```