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

-- This is a broad query covering multiple data sources and TTPs.
-- For performance, it's recommended to restrict the index and sourcetype to what's relevant in your environment.
-- e.g., `(index=main sourcetype=...) OR (index=wineventlog sourcetype=...)`
-- This query uses field names common in Sysmon and other security logs. If you use the Splunk CIM, you should align these fields (e.g., Process_Name -> Processes.process_name, CommandLine -> Processes.process, dest -> Network_Traffic.dest).
-- False Positives: Legitimate use of tools such as Rclone, ProxyChains, and Ngrok may trigger this rule. Connections to Discord's CDN are common and should be correlated with other suspicious activity.

(index=*)
(
    -- Process Execution TTPs (e.g., Sysmon EventCode 1 or Windows 4688)
    (
        (sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1) OR
        (sourcetype="WinEventLog:Security" EventCode=4688)
    )
    AND
    (
        -- WhisperGate stage2.exe PowerShell command
        (Process_Name IN ("powershell.exe", "pwsh.exe") AND CommandLine="* -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAwAA==*") OR

        -- PowerShell command to exclude C: drive from Windows Defender
        (Process_Name IN ("powershell.exe", "pwsh.exe") AND CommandLine="*Set-MpPreference*ExclusionPath*C:\\*") OR

        -- AdvancedRun.exe used to disable Windows Defender
        (Process_Name="AdvancedRun.exe" AND (CommandLine="*stop WinDefend*" OR CommandLine="*rmdir *C:\\ProgramData\\Microsoft\\Windows Defender*")) OR

        -- InstallUtil.exe run from a temp directory
        (Process_Name="InstallUtil.exe" AND (Image="*\\AppData\\Local\\Temp\\*" OR Image="*\\Windows\\Temp\\*")) OR

        -- Impacket's secretsdump.py or psexec.py
        (CommandLine IN ("*secretsdump.py*", "*psexec.py*")) OR

        -- Rclone usage for data exfiltration to MEGA. Can be noisy.
        (Process_Name IN ("rclone.exe", "rclone") AND CommandLine="*mega*.nz*") OR

        -- GOST tunneling tool execution pattern (renamed to java)
        (Process_Name IN ("java.exe", "java") AND (CommandLine="*-L*socks5://*" OR CommandLine="*-L*rtcp://*")) OR

        -- ProxyChains usage. Can be legitimate.
        (CommandLine="*proxychains*") OR

        -- su-bruteforce tool
        (CommandLine="*su-bruteforce*") OR

        -- LinPEAS privilege escalation script
        (CommandLine IN ("*linpeas.sh*", "*linpeas.py*"))
    )
)
OR
(
    -- File Creation TTPs (e.g., Sysmon EventCode 11)
    (sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=11)
    AND
    (
        -- GOST tunneling tool file hash
        md5="896e0f54fc67d72d94b40d7885f10c51"
    )
)
OR
(
    -- Network Connection TTPs (e.g., Sysmon EventCode 3, proxy, firewall logs)
    -- Note: Field names like dest, url may vary by sourcetype.
    (
        -- Connections to known Unit 29155 C2 IPs
        dest IN ("5.226.139.66", "45.141.87.11", "46.101.242.222", "62.173.140.223", "79.124.8.66", "90.131.156.107", "112.51.253.153", "112.132.218.45", "154.21.20.82", "179.43.133.202", "179.43.142.42", "179.43.162.55", "179.43.175.38", "179.43.175.108", "179.43.176.60", "179.43.187.47", "179.43.189.218", "185.245.84.227", "185.245.85.251", "194.26.29.84", "194.26.29.95", "194.26.29.98", "194.26.29.251")
    )
    OR
    (
        -- Connections to known jump host and C2 domains
        dest IN ("interlinks.top", "3proxy.ru", "nssm.cc")
    )
    OR
    (
        -- Connections to Discord CDN for payload download. Can be noisy.
        (dest="*cdn.discordapp.com" AND url="*/attachments/*")
    )
    OR
    (
        -- Connections to Ngrok, a legitimate but often abused service.
        dest="*ngrok.com"
    )
)
OR
(
    -- DNS Lookup TTPs (e.g., Sysmon EventCode 22, DNS logs)
    -- Note: Field name for query may vary by sourcetype.
    (
        -- Iodine DNS tunneling
        QueryName="dns.test658324901domain.me"
    )
)

-- Grouping and presenting the results
| eval TTP_Category=case(
    like(CommandLine, "%-enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAwAA==%"), "WhisperGate PowerShell",
    like(CommandLine, "%Set-MpPreference%ExclusionPath%"), "PowerShell Defender Exclusion",
    Process_Name="AdvancedRun.exe", "AdvancedRun Defender Disabling",
    Process_Name="InstallUtil.exe" AND (like(Image, "%\\AppData\\Local\\Temp\\%") OR like(Image, "%\\Windows\\Temp\\%")), "InstallUtil from Temp Path",
    like(CommandLine, "%secretsdump.py%") OR like(CommandLine, "%psexec.py%"), "Impacket Execution",
    Process_Name IN ("rclone.exe", "rclone") AND like(CommandLine, "%mega%.nz%"), "Rclone Exfil to MEGA",
    Process_Name IN ("java.exe", "java") AND (like(CommandLine, "%-L%socks5://%") OR like(CommandLine, "%-L%rtcp://%")), "GOST Tunneling",
    like(CommandLine, "%proxychains%"), "ProxyChains Usage",
    like(CommandLine, "%su-bruteforce%"), "su-bruteforce Usage",
    like(CommandLine, "%linpeas.%"), "LinPEAS Execution",
    isnotnull(md5), "GOST Tool File Hash",
    isnotnull(dest), "C2 Network Connection",
    isnotnull(QueryName), "Iodine DNS Tunneling"
    )
| table _time, host, user, TTP_Category, Process_Name, CommandLine, Image, md5, dest, url, QueryName
```