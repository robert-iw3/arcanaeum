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
-- Volt Typhoon-style Living-off-the-Land (LotL) Activity

-- Description:
--   This detection identifies a sequence of command-line activities consistent with techniques used by state-sponsored actors like Volt Typhoon.
--   The rule looks for the execution of multiple native Windows reconnaissance or credential dumping commands from a single host and user,
--   which is a common pattern for actors performing hands-on-keyboard operations after gaining initial access.

(process.name:cmd.exe OR process.name:powershell.exe (whoami OR hostname OR systeminfo OR "ipconfig /all" OR "net user" OR "net group" OR "net localgroup" OR "net view" OR nltest OR "query user" OR qwinsta OR nbtstat OR "arp -a" OR "tasklist /v") OR process.name:ntdsutil.exe OR (process.name:vssadmin.exe "create shadow") OR (process.name:reg.exe ("save HKLM\\SAM" OR "save HKLM\\SYSTEM")))
| select process.name AS process_name, process.parent.name AS parent_process_name, process.cmdline AS command_line, host, user
| eval technique = case(
    contains(process.cmdline, "whoami|hostname|systeminfo|ipconfig|net user|net group|net localgroup|net view|nltest|query user|qwinsta|nbtstat|arp|tasklist") => "Reconnaissance",
    contains(process.cmdline, "ntdsutil|vssadmin create shadow|reg save HKLM\\SAM|reg save HKLM\\SYSTEM") => "Credential Dumping",
    true => "Other LotL Activity"
)
| aggregate count, distinct_count(technique) AS technique_count, first(timestamp) AS start_time, last(timestamp) AS end_time by host, user, parent_process_name, command_line, technique window 30m
| where count > 1 AND (technique_count > 1 OR parent_process_name:(w3wp.exe OR httpd.exe OR nginx.exe OR tomcat*.exe) OR technique:Credential\ Dumping)
| select strftime(start_time, "%Y-%m-%d %H:%M:%S") AS start_time, strftime(end_time, "%Y-%m-%d %H:%M:%S") AS end_time, host AS dest, user, parent_process_name, command_line, technique
```

### Exploitation of Edge Devices
---
```sql
-- Potential Exploitation of Internet-Facing Edge Device

-- Description:
--   This detection identifies patterns consistent with exploitation attempts against public-facing edge devices (e.g., firewalls, routers, VPNs).
--   It searches network and threat logs for common indicators of exploitation, such as path traversal, command injection, or specific threat signatures.
--   This behavior is a known TTP (T1190) used by actors like Volt Typhoon for initial access.

-- MITRE ATT&CK: T1190

(source:pan* OR source:opsec* OR source:suricata OR source:cisco_asa OR source:fortinet* OR source:stream_http)
| select ip.dst AS dest_ip, ip.src AS src_ip, http.url AS url, threat.name AS signature
| where url:/(\.\.\/|\%2e\%2e|etc\/passwd|cmd\.exe|powershell\.exe|wget|curl|bin\/sh)/ OR signature:/(Command Injection|Path Traversal|Remote Code Execution|RCE)/
| aggregate count, collect(url) AS sample_urls, collect(signature) AS triggered_signatures by src_ip, dest_ip
| where count > 5
| select src_ip AS Attacker_IP, dest_ip AS Target_IP, count AS Attempt_Count, sample_urls AS Sample_URLs, triggered_signatures AS Signatures
```

### Spear-Phishing Campaigns
---
```sql
-- Suspicious Script Execution by Microsoft Office Application

-- Description:
--   This rule detects when a Microsoft Office application (e.g., Word, Excel, Outlook) spawns a command shell or script interpreter (e.g., PowerShell, cmd.exe).
--   This behavior is a strong indicator of a malicious document or spearphishing attachment being opened, which then attempts to execute code on the endpoint.
--   This technique (T1566.001) is commonly used by threat actors like Mustang Panda and APT41 to gain initial access.

-- MITRE ATT&CK: T1566.001

(source:windows_event_log EventCode:4688 OR source:sysmon EventCode:1)
| select lower(coalesce(ProcessName, NewProcessName)) AS process_name, lower(coalesce(ParentProcessName)) AS parent_process_name, coalesce(CommandLine, ProcessCommandLine) AS command_line, host, user
| where parent_process_name:/(winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe|msaccess\.exe)$/ AND process_name:/(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe|rundll32\.exe)$/
| aggregate count by timestamp, host, user, parent_process_name, process_name, command_line
| select timestamp AS _time, host AS Endpoint, user AS User, parent_process_name AS Parent_Process, process_name AS Child_Process, command_line AS Command_Line, count AS Event_Count
```

### Webshells on Compromised Systems
---
```sql
-- Web Server Spawning Suspicious Child Process

-- Description:
--   This rule detects when a common web server process (e.g., w3wp.exe, httpd.exe) spawns a command shell or other suspicious utility.
--   This is a strong indicator of a webshell (e.g., China Chopper, ANTSWORD) being used for command execution on a compromised server.
--   This technique (T1505.003) is used by threat actors like APT41.

-- MITRE ATT&CK: T1505.003

(source:windows_event_log EventCode:4688 OR source:sysmon EventCode:1)
| select lower(coalesce(ProcessName, NewProcessName)) AS process_name, lower(coalesce(ParentProcessName)) AS parent_process_name, coalesce(CommandLine, ProcessCommandLine) AS command_line, host, user
| where parent_process_name:/(w3wp\.exe|httpd\.exe|nginx\.exe|tomcat\d*\.exe|php-cgi\.exe)$/ AND process_name:/(cmd\.exe|powershell\.exe|pwsh\.exe|whoami\.exe|ipconfig\.exe|net\.exe|net1\.exe|systeminfo\.exe|quser\.exe|qwinsta\.exe|nbtstat\.exe|nltest\.exe|certutil\.exe|bitsadmin\.exe|sh\.exe|bash\.exe)$/
| aggregate count by timestamp, host, user, parent_process_name, process_name, command_line
| select timestamp AS _time, host AS Endpoint, user AS User, parent_process_name AS Parent_Process, process_name AS Child_Process, command_line AS Command_Line, count AS Event_Count
```

### Unusual SSL/Proxied HTTP Traffic
---
```sql
-- Unusual SSL or HTTP C2 Communication

-- Description:
--   This rule detects network traffic patterns that may indicate Command and Control (C2) activity, similar to techniques used by groups like RedEcho.
--   It specifically looks for two conditions:
--   1. SSL/TLS connections to external hosts using self-signed certificates on port 443.
--   2. HTTP traffic communicating over non-standard ports.
--   These patterns can be indicative of an actor attempting to hide C2 traffic.

-- MITRE ATT&CK: T1071.001, T1090

(source:zeek_ssl OR source:zeek_http OR source:pan_traffic OR source:suricata)
| select coalesce(id.orig_h, src_ip, source_ip) AS src_ip, coalesce(id.resp_h, dest_ip, destination_ip) AS dest_ip, coalesce(id.resp_p, dest_port, destination_port) AS dest_port, coalesce(app, service, http.http_method) AS app
| eval reason = case(
    source:zeek_ssl AND ssl.issuer IS NOT NULL AND ssl.subject IS NOT NULL AND ssl.issuer = ssl.subject AND dest_port:443 => "Self-Signed SSL on Port 443",
    (source:zeek_http OR app:http OR http.http_method IS NOT NULL) AND dest_port NOT IN (80, 8080, 8000, 8888) => "HTTP on Non-Standard Port"
)
| where reason IS NOT NULL AND NOT (dest_ip:10.0.0.0/8 OR dest_ip:172.16.0.0/12 OR dest_ip:192.168.0.0/16)
| aggregate count, distinct_count(reason) AS distinct_reasons, collect(reason) AS reasons by src_ip, dest_ip, dest_port
| select src_ip AS Source_IP, dest_ip AS Destination_IP, dest_port AS Destination_Port, count AS Event_Count, reasons AS Detections
```
