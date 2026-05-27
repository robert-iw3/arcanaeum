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

name: GRU Unit 29155 Ember Bear Activity
type: signal_correlation
cases:
  - name: WhisperGate PowerShell
    status: high
    query: "@process.name:(powershell.exe OR pwsh.exe) AND @process.cmdline:* -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAwAA==*"
  - name: PowerShell Defender Exclusion
    status: high
    query: "@process.name:(powershell.exe OR pwsh.exe) AND @process.cmdline:*Set-MpPreference*ExclusionPath*C:\\*"
  - name: AdvancedRun Defender Disabling
    status: medium
    query: "@process.name:AdvancedRun.exe AND (@process.cmdline:*stop WinDefend* OR @process.cmdline:*rmdir *C:\\ProgramData\\Microsoft\\Windows Defender*)"
  - name: InstallUtil from Temp Path
    status: medium
    query: "@process.name:InstallUtil.exe AND (@process.executable:*\\AppData\\Local\\Temp\\* OR @process.executable:*\\Windows\\Temp\\*)"
  - name: Impacket Execution
    status: high
    query: "@process.cmdline:(*secretsdump.py* OR *psexec.py*)"
  - name: Rclone Exfil to MEGA
    status: high
    query: "@process.name:rclone* AND @process.cmdline:*mega*.nz*"
  - name: GOST Tunneling
    status: medium
    query: "@process.name:java.exe AND (@process.cmdline:*-L*socks5://* OR @process.cmdline:*-L*rtcp://*)"
  - name: ProxyChains Usage
    status: medium
    query: "@process.cmdline:*proxychains*"
  - name: su-bruteforce Usage
    status: high
    query: "@process.cmdline:*su-bruteforce*"
  - name: LinPEAS Execution
    status: medium
    query: "@process.cmdline:(*linpeas.sh* OR *linpeas.py*)"
  - name: GOST Tool File Hash
    status: high
    query: "@file.md5:896e0f54fc67d72d94b40d7885f10c51"
  - name: C2 Network Connection
    status: high
    query: "@network.destination.ip:(5.226.139.66 OR 45.141.87.11 OR 46.101.242.222 OR 62.173.140.223 OR 79.124.8.66 OR 90.131.156.107 OR 112.51.253.153 OR 112.132.218.45 OR 154.21.20.82 OR 179.43.133.202 OR 179.43.142.42 OR 179.43.162.55 OR 179.43.175.38 OR 179.43.175.108 OR 179.43.176.60 OR 179.43.187.47 OR 179.43.189.218 OR 185.245.84.227 OR 185.245.85.251 OR 194.26.29.84 OR 194.26.29.95 OR 194.26.29.98 OR 194.26.29.251) OR @network.destination.domain:(interlinks.top OR 3proxy.ru OR nssm.cc OR *cdn.discordapp.com AND @url:*/attachments/* OR *ngrok.com)"
  - name: Iodine DNS Tunneling
    status: high
    query: "@dns.query:dns.test658324901domain.me"
signal_correlation:
  rule_id: gru_29155_correlation
  group_by_fields:
    - @host
    - @usr
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: "GRU Unit 29155 Activity: {distinct_count} TTP(s) on host {@host} by user {@usr}: {case_names}"
severity: high
```