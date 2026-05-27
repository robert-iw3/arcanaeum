### Russian Military Cyber Actors Target US and Global Critical Infrastructure
---

Russian GRU Unit 29155, also known as Cadet Blizzard, Ember Bear, UNC2589, and UAC-0056, has been conducting cyber operations globally since at least 2020, focusing on espionage, sabotage, and reputational harm, with a significant increase in activity against Ukraine and its allies since early 2022. The group primarily targets critical infrastructure and government entities, utilizing publicly available tools and destructive malware like WhisperGate.

Recent intelligence indicates that Unit 29155 (Cadet Blizzard/Ember Bear) continues to operate actively, with a re-emergence of increased operations in early 2023 after a period of reduced activity in mid-2022, specifically targeting entities in Ukraine and Europe with website defacements and hack-and-leak operations. This highlights a sustained and evolving threat, demonstrating the group's adaptability and continued focus on disruptive activities and information operations.

### Actionable Threat Data

Monitor for the execution of powershell.exe with the encoded command UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAwAA== (decoded: Start-Sleep -s 10), which has been observed in WhisperGate stage 2 execution.

Detect attempts to modify Windows Defender exclusions, specifically the command powershell Set-MpPreference -ExclusionPath 'C:\', as seen in the Nmddfrqqrbyjeygggda.vbs script used by WhisperGate.

Look for the creation and execution of AdvancedRun.exe in the %TEMP% directory, particularly when used to stop WinDefend or remove the Windows Defender directory.

Identify HTTP GET requests to Discord CDN URLs (e.g., cdn.discordapp[.]com/attachments/) for downloading executable payloads like Tbopbh.jpg, which is a reversed PE file.

Monitor for the use of InstallUtil.exe from the %TEMP% directory, as it has been observed in the final stages of WhisperGate deployment leading to file corruption.

Detect the use of smbclient via ProxyChains to access internal network shares, and subsequent use of PSQL and MySQL clients to access internal databases.

Look for the execution of Impacket scripts such as secretsdump.py and psexec.py for credential dumping and lateral movement, respectively.

Monitor for su-bruteforce activity, indicating brute-force attempts against selected users via the su command.

Detect the use of LinPEAS for privilege escalation enumeration on Linux systems.

Identify the presence and execution of the GO Simple Tunnel (GOST) tool (MD5: 896e0f54fc67d72d94b40d7885f10c51) for tunneling traffic.

Monitor for password spraying attempts against Microsoft Outlook Web Access (OWA) infrastructure.

Detect DNS tunneling activity using tools like dnscat/2 and Iodine, specifically looking for unusual DNS queries to domains like dns.test658324901domain.me.

Look for the use of web shells (exp_door v1.0.2, b374k, WSO 4.0.5, P.A.S. web shells) and modifications to .php scripts for server-side manipulation.

Monitor for exfiltration of LSASS memory dumps, SAM files, and SECURITY/SYSTEM event logs.

Detect the use of Rclone to exfiltrate data to cloud storage services like mega[.]nz.

Identify network scanning activity using tools such as Acunetix, Amass, Droopescan, JoomScan, MASSCAN, Netcat, Nmap, Shodan, VirusTotal, and WPScan.

Monitor for exploitation attempts against known vulnerabilities, including CVE-2021-33044, CVE-2021-33045 (Dahua Security), CVE-2022-26134, CVE-2022-26138 (Atlassian Confluence), and CVE-2022-3236 (Sophos Firewall).

Look for connections to the historical Unit 29155 infrastructure IP addresses listed in Appendix B of the provided intel.

Detect the use of ngrok[.]com and 3proxy[.]ru for jump host tooling.

### GRU Unit 29155 Combined Analysis Search
---
```sql
-- title: GRU Unit 29155 (Ember Bear/Cadet Blizzard) Activity
-- description: >-
--   Detects a wide range of Tactics, Techniques, and Procedures (TTPs) associated with the Russian GRU Unit 29155,
--   also known as Ember Bear and Cadet Blizzard. This rule covers process execution, network communications,
--   and specific tool usage as detailed in CISA advisory AA24-249A.
-- author: RW
-- date: 2025-08-21
-- reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-249a
-- tags: G1003, EMBER_BEAR, CADET_BLIZZARD, UNC2589, UAC-0056, WHISPERGATE, RUSSIA, TA0002, TA0005, TA0006, TA0007, TA0008, TA0010, TA0011, T1059.001, T1562.001, T1003, T1550.002, T1567.002, T1572, T1090.003, T1071.004, T1071.001, T1105

FROM logs-endpoint.events.*,logs-network.* -- <-- replace with EDR/Network data-streams or index
| WHERE
  /* Process Execution TTPs */
  (event.category == "process" AND event.action == "start" AND
    /* WhisperGate stage2.exe PowerShell command */
    (process.name IN ("powershell.exe", "pwsh.exe") AND process.command_line LIKE "* -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAwAA==*") OR
    /* PowerShell command to exclude C: drive from Windows Defender */
    (process.name IN ("powershell.exe", "pwsh.exe") AND process.command_line LIKE "*Set-MpPreference*ExclusionPath*C:\\*") OR
    /* AdvancedRun.exe used to disable Windows Defender */
    (process.name == "AdvancedRun.exe" AND (process.command_line LIKE "*stop WinDefend*" OR process.command_line LIKE "*rmdir *C:\\ProgramData\\Microsoft\\Windows Defender*")) OR
    /* InstallUtil.exe run from a temp directory */
    (process.name == "InstallUtil.exe" AND (process.executable LIKE "*\\AppData\\Local\\Temp\\*" OR process.executable LIKE "*\\Windows\\Temp\\*")) OR
    /* Impacket's secretsdump.py or psexec.py */
    (process.command_line LIKE "*secretsdump.py*" OR process.command_line LIKE "*psexec.py*") OR
    /* Rclone usage for data exfiltration to MEGA */
    (process.name ILIKE "rclone*" AND process.command_line LIKE "*mega*.nz*") OR
    /* GOST tunneling tool execution pattern (renamed to java) */
    (process.name == "java.exe" AND (process.command_line LIKE "*-L*socks5://*" OR process.command_line LIKE "*-L*rtcp://*")) OR
    /* ProxyChains usage */
    (process.command_line LIKE "*proxychains*") OR
    /* su-bruteforce tool */
    (process.command_line LIKE "*su-bruteforce*") OR
    /* LinPEAS privilege escalation script */
    (process.command_line LIKE "*linpeas.sh*" OR process.command_line LIKE "*linpeas.py*")
  ) OR
  /* File Creation TTPs */
  (event.category == "file" AND event.action == "creation" AND
    /* GOST tunneling tool file hash */
    file.hash.md5 == "896e0f54fc67d72d94b40d7885f10c51"
  ) OR
  /* Network Connection TTPs */
  (event.category == "network" AND
    /* Connections to known Unit 29155 C2 IPs */
    (destination.ip IN ("5.226.139.66", "45.141.87.11", "46.101.242.222", "62.173.140.223", "79.124.8.66", "90.131.156.107", "112.51.253.153", "112.132.218.45", "154.21.20.82", "179.43.133.202", "179.43.142.42", "179.43.162.55", "179.43.175.38", "179.43.175.108", "179.43.176.60", "179.43.187.47", "179.43.189.218", "185.245.84.227", "185.245.85.251", "194.26.29.84", "194.26.29.95", "194.26.29.98", "194.26.29.251")) OR
    /* Connections to known jump host and C2 domains */
    (destination.domain IN ("interlinks.top", "3proxy.ru", "nssm.cc")) OR
    /* Connections to Discord CDN for payload download */
    (destination.domain LIKE "*cdn.discordapp.com" AND url.full LIKE "*/attachments/*") OR
    /* Connections to Ngrok */
    (destination.domain LIKE "*ngrok.com")
  ) OR
  /* DNS Lookup TTPs */
  (event.category == "dns" AND
    /* Iodine DNS tunneling */
    dns.question.name == "dns.test658324901domain.me"
  )
| EVAL TTP_Category = CASE(
  process.command_line LIKE "* -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAwAA==*", "WhisperGate PowerShell",
  process.command_line LIKE "*Set-MpPreference*ExclusionPath*", "PowerShell Defender Exclusion",
  process.name == "AdvancedRun.exe", "AdvancedRun Defender Disabling",
  process.name == "InstallUtil.exe" AND (process.executable LIKE "*\\Temp\\*", "InstallUtil from Temp Path",
  process.command_line LIKE "*secretsdump.py*" OR process.command_line LIKE "*psexec.py*", "Impacket Execution",
  process.name ILIKE "rclone*" AND process.command_line LIKE "*mega*.nz*", "Rclone Exfil to MEGA",
  process.name == "java.exe" AND process.command_line LIKE "*-L*socks5://*", "GOST Tunneling",
  process.command_line LIKE "*proxychains*", "ProxyChains Usage",
  process.command_line LIKE "*su-bruteforce*", "su-bruteforce Usage",
  process.command_line LIKE "*linpeas.*", "LinPEAS Execution",
  file.hash.md5 == "896e0f54fc67d72d94b40d7885f10c51", "GOST Tool File Hash",
  destination.ip IS NOT NULL OR destination.domain IS NOT NULL, "C2 Network Connection",
  dns.question.name IS NOT NULL, "Iodine DNS Tunneling",
  true, null
)
| KEEP @timestamp AS _time, host.name AS host, user.name AS user, TTP_Category, process.name AS Process_Name, process.command_line AS CommandLine, process.executable AS Image, file.hash.md5 AS md5, destination.ip AS dest, url.full AS url, dns.question.name AS QueryName
| SORT _time DESC
| LIMIT 1000
```