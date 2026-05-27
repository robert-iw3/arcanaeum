### Chinese Cyber Operations Targeting Critical Infrastructure
---

Chinese state-sponsored cyber operations are actively targeting critical infrastructure globally, including in the U.S., Europe, and Asia-Pacific, with the intent to pre-position for potential wartime disruption and intellectual property theft. These operations leverage sophisticated tactics, techniques, and procedures (TTPs) to maintain stealthy, long-term access within targeted systems.

Recent intelligence indicates a significant escalation in the volume and sophistication of Chinese cyberattacks, with Taiwan experiencing a doubling of daily attacks in 2024, and new reports of Salt Typhoon targeting U.S. telecommunications networks for espionage and potential disruption. This highlights an increased focus on strategic pre-positioning and intelligence gathering in critical sectors, extending beyond traditional espionage to include capabilities for future kinetic conflict.

### Actionable Threat Data
---

Monitor for the use of Living-off-the-Land (LotL) techniques, particularly the execution of native Windows commands and PowerShell scripts for reconnaissance, credential dumping, and data exfiltration, as observed with Volt Typhoon.

Detect attempts to exploit known vulnerabilities in internet-facing systems, especially edge devices like routers, firewalls, and VPNs, which are frequently targeted for initial access and used as proxy infrastructure by Chinese APTs like Volt Typhoon.

Look for spear-phishing campaigns, often with political or current event themes, delivering malware such as PlugX, as this is a common initial access vector for groups like Mustang Panda and APT41.

Identify the presence of webshells (e.g., China Chopper, ANTSWORD, BLUEBEAM) on compromised systems, which are used by APT41 and others for persistent access,
command execution, and data exfiltration.

Analyze network traffic for unusual SSL communication on TCP 443 and proxied HTTP traffic over non-standard ports, as seen with RedEcho, which may indicate command and control (C2) activity.

### LotL Techniques by Volt Typhoon
---
```sql
`comment(
-- Volt Typhoon-style Living-off-the-Land (LotL) Activity

-- Description:
--   This detection identifies a sequence of command-line activities consistent with techniques used by state-sponsored actors like Volt Typhoon.
--   The rule looks for the execution of multiple native Windows reconnaissance or credential dumping commands from a single host and user,
--   which is a common pattern for actors performing hands-on-keyboard operations after gaining initial access.

)`

((sourcetype=WinEventLog:Security EventCode=4688) OR (sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1))

`comment("Normalize field names for consistency across different data sources.")`
| eval process_name = lower(coalesce(ProcessName, NewProcessName)), parent_process_name = lower(coalesce(ParentProcessName, ParentProcessName)), command_line = coalesce(CommandLine, ProcessCommandLine)

`comment("Filter for common reconnaissance and credential dumping commands often used in LotL attacks.")`
| search (
    (process_name IN ("cmd.exe", "powershell.exe") AND (command_line="*whoami*" OR command_line="*hostname*" OR command_line="*systeminfo*" OR command_line="*ipconfig /all*" OR command_line="*net user*" OR command_line="*net group*" OR command_line="*net localgroup*" OR command_line="*net view*" OR command_line="*nltest*" OR command_line="*query user*" OR command_line="*qwinsta*" OR command_line="*nbtstat*" OR command_line="*arp -a*" OR command_line="*tasklist /v*")) OR
    (process_name="ntdsutil.exe") OR
    (process_name="vssadmin.exe" AND command_line="*create shadow*") OR
    (process_name="reg.exe" AND (command_line="*save HKLM\\SAM*" OR command_line="*save HKLM\\SYSTEM*"))
)

`comment("Categorize the observed command line activity based on MITRE ATT&CK techniques.")`
| eval technique = case(
    mvcount(match(command_line, "(?i)whoami|hostname|systeminfo|ipconfig|net user|net group|net localgroup|net view|nltest|query user|qwinsta|nbtstat|arp|tasklist")) > 0, "Reconnaissance",
    mvcount(match(command_line, "(?i)ntdsutil|vssadmin create shadow|reg save HKLM\\SAM|reg save HKLM\\SYSTEM")) > 0, "Credential Dumping",
    1=1, "Other LotL Activity"
)

`comment("Aggregate commands by host and user to identify suspicious sequences of activity within a 30-minute window.")`
| transaction dest, user maxspan=30m
| where eventcount > 1

`comment("Filter for higher-confidence events. For example, multiple distinct techniques used, or execution from a suspicious parent process. This section can be tuned to reduce false positives.")`
| where (mvcount(eval(mvdedup(technique))) > 1) OR (parent_process_name IN ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat*.exe")) OR (technique LIKE "%Credential Dumping%")

`comment("FP Tuning: The list of suspicious parent processes (w3wp.exe, etc.) may need to be expanded or tailored to your environment. Some administrative scripts may legitimately run multiple reconnaissance commands; consider adding known good scripts or users to an exclusion list.")`
| eval start_time=strftime(_time, "%Y-%m-%d %H:%M:%S"), end_time=strftime(_time+duration, "%Y-%m-%d %H:%M:%S")
| table start_time, end_time, dest, user, parent_process_name, command_line, technique
```

### Exploitation of Edge Devices
---
```sql
`comment(
-- Potential Exploitation of Internet-Facing Edge Device

-- Description:
--   This detection identifies patterns consistent with exploitation attempts against public-facing edge devices (e.g., firewalls, routers, VPNs).
--   It searches network and threat logs for common indicators of exploitation, such as path traversal, command injection, or specific threat signatures.
--   This behavior is a known TTP (T1190) used by actors like Volt Typhoon for initial access.

-- MITRE ATT&CK: T1190
)`

`comment("Define the data sources. This should include logs from firewalls, IDS/IPS, and web proxies.")`
(sourcetype=pan:threat OR sourcetype=opsec:threat OR sourcetype=suricata OR sourcetype=cisco:asa OR sourcetype=fortinet:fortigate:utm OR sourcetype=stream:http)

`comment("Normalize common field names for consistency across different log sources.")`
| rename coalesce(dest_ip, dest) as dest_ip, coalesce(src_ip, src) as src_ip, coalesce(url, http_uri) as url, coalesce(signature, threat_name, msg) as signature

`comment("Filter for common web exploit patterns or high-confidence threat signatures.")`
| where (
    match(url, "(?i)(\.\.\/|\%2e\%2e|etc\/passwd|cmd\.exe|powershell\.exe|wget|curl|bin\/sh)") OR
    match(signature, "(?i)(Command Injection|Path Traversal|Remote Code Execution|RCE)")
)

`comment("FP Tuning: To focus on edge devices, use an asset inventory lookup. This is critical for reducing noise. The lookup should contain fields like 'ip' and 'category'.")`
`comment("Example: | lookup asset_inventory.csv ip as dest_ip OUTPUT category as target_category | where target_category IN (\"firewall\", \"router\", \"vpn\")")`

`comment("FP Tuning: Exclude known vulnerability scanners to reduce false positives. Create a lookup file 'known_scanners.csv' with a field 'ip'.")`
`comment("Example: | lookup known_scanners.csv ip as src_ip OUTPUT is_scanner | where isnull(is_scanner)")`

`comment("Aggregate events by source and destination to identify targeted attempts and reduce alert volume.")`
| stats count, values(url) as sample_urls, values(signature) as triggered_signatures by src_ip, dest_ip
| where count > 5

`comment("Format the output for alerting and investigation.")`
| rename src_ip as Attacker_IP, dest_ip as Target_IP, count as Attempt_Count, sample_urls as Sample_URLs, triggered_signatures as Signatures
| fields Attacker_IP, Target_IP, Attempt_Count, Sample_URLs, Signatures
```

### Spear-Phishing Campaigns
---
```sql
`comment(
-- Suspicious Script Execution by Microsoft Office Application

-- Description:
--   This rule detects when a Microsoft Office application (e.g., Word, Excel, Outlook) spawns a command shell or script interpreter (e.g., PowerShell, cmd.exe).
--   This behavior is a strong indicator of a malicious document or spearphishing attachment being opened, which then attempts to execute code on the endpoint.
--   This technique (T1566.001) is commonly used by threat actors like Mustang Panda and APT41 to gain initial access.

-- MITRE ATT&CK: T1566.001
)`

((sourcetype=WinEventLog:Security EventCode=4688) OR (sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1))

`comment("Normalize field names for consistency across different data sources.")`
| eval parent_process_name = lower(coalesce(ParentProcessName, ParentProcessName)), process_name = lower(coalesce(NewProcessName, ProcessName)), command_line = coalesce(CommandLine, ProcessCommandLine)

`comment("Identify instances where an MS Office application is the parent process.")`
| where match(parent_process_name, "(?i)(winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe|msaccess\.exe)$")

`comment("Look for the creation of suspicious child processes used for script execution.")`
| where match(process_name, "(?i)(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe|rundll32\.exe)$")

`comment("FP Tuning: Legitimate add-ins or complex macros may sometimes cause this behavior. Exclude known safe parent-child process relationships or command lines if they trigger false positives in your environment.")`
`comment("Example: | where NOT (parent_process_name=\"excel.exe\" AND match(command_line, \"safe_script.ps1\"))")`

`comment("Aggregate and format the results for alerting.")`
| stats count by _time, dest, user, parent_process_name, process_name, command_line
| rename dest as Endpoint, user as User, parent_process_name as Parent_Process, process_name as Child_Process, command_line as Command_Line, count as Event_Count
```

### Webshells on Compromised Systems
---
```sql
`comment(
-- Web Server Spawning Suspicious Child Process

-- Description:
--   This rule detects when a common web server process (e.g., w3wp.exe, httpd.exe) spawns a command shell or other suspicious utility.
--   This is a strong indicator of a webshell (e.g., China Chopper, ANTSWORD) being used for command execution on a compromised server.
--   This technique (T1505.003) is used by threat actors like APT41.

-- MITRE ATT&CK: T1505.003
)`

((sourcetype=WinEventLog:Security EventCode=4688) OR (sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1))

`comment("Normalize field names for consistency across different data sources.")`
| eval parent_process_name = lower(coalesce(ParentProcessName, ParentProcessName)), process_name = lower(coalesce(NewProcessName, ProcessName)), command_line = coalesce(CommandLine, ProcessCommandLine)

`comment("Filter for common web server processes as the parent.")`
| where match(parent_process_name, "(?i)(w3wp\.exe|httpd\.exe|nginx\.exe|tomcat\d*\.exe|php-cgi\.exe)$")

`comment("Filter for suspicious child processes commonly used for command execution or reconnaissance.")`
| where match(process_name, "(?i)(cmd\.exe|powershell\.exe|pwsh\.exe|whoami\.exe|ipconfig\.exe|net\.exe|net1\.exe|systeminfo\.exe|quser\.exe|qwinsta\.exe|nbtstat\.exe|nltest\.exe|certutil\.exe|bitsadmin\.exe|sh\.exe|bash\.exe)$")

`comment("FP Tuning: Some legitimate application monitoring or administrative tools might trigger this behavior. If specific command lines are known to be safe, they can be excluded here.")`
`comment("Example: | where NOT (parent_process_name=\"w3wp.exe\" AND match(command_line, \"run_safe_diag.bat\"))")`

`comment("Aggregate and format the results for alerting.")`
| stats count by _time, dest, user, parent_process_name, process_name, command_line
| rename dest as Endpoint, user as User, parent_process_name as Parent_Process, process_name as Child_Process, command_line as Command_Line, count as Event_Count
```

### Unusual SSL/Proxied HTTP Traffic
---
```sql
`comment(
-- Unusual SSL or HTTP C2 Communication

-- Description:
--   This rule detects network traffic patterns that may indicate Command and Control (C2) activity, similar to techniques used by groups like RedEcho.
--   It specifically looks for two conditions:
--   1. SSL/TLS connections to external hosts using self-signed certificates on port 443.
--   2. HTTP traffic communicating over non-standard ports.
--   These patterns can be indicative of an actor attempting to hide C2 traffic.

-- MITRE ATT&CK: T1071.001, T1090
)`

`comment("Define the data sources. This should include Zeek (Bro) SSL/HTTP logs and/or firewall traffic logs.")`
(sourcetype=zeek:ssl OR sourcetype=zeek:http OR sourcetype=pan:traffic OR sourcetype=suricata)

`comment("Normalize common field names for consistency across different log sources.")`
| eval src_ip=coalesce(id.orig_h, src_ip, source_ip, src_ip), dest_ip=coalesce(id.resp_h, dest_ip, destination_ip, dest_ip), dest_port=coalesce(id.resp_p, dest_port, destination_port, dest_port), app=coalesce(app, service, http.http_method)

`comment("Identify the specific suspicious behavior.")`
| eval reason = case(
    sourcetype="zeek:ssl" AND isnotnull(issuer) AND isnotnull(subject) AND issuer==subject AND dest_port=443, "Self-Signed SSL on Port 443",
    (sourcetype="zeek:http" OR app="http" OR isnotnull(http.http_method)) AND dest_port NOT IN (80, 8080, 8000, 8888), "HTTP on Non-Standard Port"
  )
| where isnotnull(reason)

`comment("FP Tuning: Filter out traffic to internal, private IP space to focus on external C2 communication.")`
| where NOT (cidrmatch("10.0.0.0/8", dest_ip) OR cidrmatch("172.16.0.0/12", dest_ip) OR cidrmatch("192.168.0.0/16", dest_ip))

`comment("FP Tuning: For self-signed certs, exclude known legitimate internal CAs or services if they are fingerprinted incorrectly. Example: | where NOT (sourcetype=\"zeek:ssl\" AND match(subject, \"CN=myinternalapp.local\"))")`

`comment("Aggregate events to reduce alert volume and summarize activity.")`
| stats count, dc(reason) as distinct_reasons, values(reason) as reasons by src_ip, dest_ip, dest_port
| rename src_ip as Source_IP, dest_ip as Destination_IP, dest_port as Destination_Port, count as Event_Count, reasons as Detections

`comment("Format the output for alerting and investigation.")`
| fields Source_IP, Destination_IP, Destination_Port, Event_Count, Detections
```
