### Active Exploitation of SonicWall VPNs by Akira Ransomware
---

A likely zero-day vulnerability in SonicWall VPNs is being actively exploited to bypass MFA and deploy Akira ransomware. Threat actors are rapidly moving from initial breach to domain controller compromise and ransomware deployment within hours.

Recent intelligence indicates that the Akira ransomware group is actively exploiting a suspected zero-day vulnerability in SonicWall SSL VPNs, even on fully patched devices with MFA enabled, allowing for rapid network compromise and ransomware deployment. This is a significant evolution as it bypasses traditional security controls like MFA, highlighting a critical and immediate threat to organizations utilizing these VPNs.

### Actionable Threat Data
---

Initial Access & Persistence:

Monitor for suspicious logins to SonicWall SSL VPNs, especially those originating from Virtual Private Server (VPS) hosting providers, as these are often used by ransomware groups.

Detect the deployment of Cloudflared tunnels (`cloudflared.exe`) and OpenSSH (`sshd.exe`, `OpenSSHa.msi`) for persistence, particularly when staged in `C:\ProgramData`.

Look for the installation and use of Remote Monitoring and Management (RMM) tools like AnyDesk or ScreenConnect, which attackers use for persistence and control.

Identify the creation of new user accounts, especially those with administrative privileges, and monitor for RDP brute-force attempts.

Defense Evasion & Credential Theft:

Detect the execution of `Set-MpPreference` to disable Microsoft Defender and `netsh.exe` commands to disable the firewall.

Monitor for attempts to dump and decrypt credentials from Veeam Backup databases or to back up the `NTDS.dit` Active Directory database using `wbadmin.exe`.

Look for credential harvesting from web browsers, such as copying Login Data from Edge browser profiles.

Discovery & Lateral Movement:

Identify the execution of enumeration tools like `Advanced_IP_Scanner.exe`, `netscan.exe`, `nltest.exe` (e.g., /trusted_domains, /dclist, /domain_trusts), `Get-ADComputer`, `net group "Domain admins" /dom`, and `quser`.

Detect lateral movement using WMI and PowerShell Remoting.

Impact:

Monitor for the deletion of Volume Shadow Copies using `vssadmin.exe delete shadows /all /quiet`.

Detect the execution of ransomware executables, such as `w.exe` or `win.exe`, and the use of tools like WinRAR for data staging and FileZilla for exfiltration.

### SonicWall VPN Exploitation
---
```sql
`tstats` `security_content_summariesonly` values(Processes.process) as process, values(Processes.process_name) as process_name, values(Processes.file_hash) as file_hash
from datamodel=Endpoint.Processes
where (Processes.process_name IN ("vssadmin.exe", "wbadmin.exe", "WinRAR.exe", "w.exe", "win.exe", "nltest.exe", "net.exe", "net1.exe"))
by _time, Processes.dest, Processes.user span=30m
| `drop_dm_object_name(Processes)`

-- Key detection logic: Identify specific TTPs by creating flags for each suspicious activity.
| eval ntds_backup = if(match(process, /(?i)wbadmin.*start backup.*include:.*\\NTDS\\.dit/), 1, 0)
| eval shadow_delete = if(match(process, /(?i)vssadmin.*delete shadows.*\/all.*\/quiet/), 1, 0)
| eval winrar_staging = if(process_name="WinRAR.exe" AND match(process, /(?i)\s+a\s+-ep1\s+-scul\s+-r0\s+-iext\s+-imon1\s+/), 1, 0)
| eval akira_ransomware = if((process_name="w.exe" OR process_name="win.exe") AND file_hash="d080f553c9b1276317441894ec6861573fa64fb1fae46165a55302e782b1614d", 1, 0)
| eval discovery = if(match(process, /(?i)nltest.*(\/dclist|\/domain_trusts)/) OR match(process, /(?i)net\s+group.*Domain Admins.*\/dom/), 1, 0)
| eval user_creation = if(match(process, /(?i)net\s+user\s+.*\/add\s+\/dom/), 1, 0)

-- Aggregate TTPs per host/user to identify a pattern of behavior.
| stats sum(ntds_backup) as ntds_backup_flag,
        sum(shadow_delete) as shadow_delete_flag,
        sum(winrar_staging) as winrar_staging_flag,
        sum(akira_ransomware) as akira_ransomware_flag,
        sum(discovery) as discovery_flag,
        sum(user_creation) as user_creation_flag,
        values(process) as commands
        by dest, user

-- Alerting condition: Trigger on high-confidence indicators or a combination of lower-confidence discovery and persistence activities.
| where (ntds_backup_flag > 0 OR shadow_delete_flag > 0 OR winrar_staging_flag > 0 OR akira_ransomware_flag > 0) OR (discovery_flag > 0 AND user_creation_flag > 0)

-- Format output for analysts.
| rename dest as host
| eval threat_phase=case(
    akira_ransomware_flag > 0, "Impact (Akira Ransomware)",
    shadow_delete_flag > 0, "Impact (Shadow Copy Deletion)",
    ntds_backup_flag > 0, "Credential Access (NTDS.dit Backup)",
    winrar_staging_flag > 0, "Collection (Suspicious WinRAR Staging)",
    discovery_flag > 0 AND user_creation_flag > 0, "Persistence & Discovery",
    1=1, "Suspicious Activity Pattern"
)
| table host, user, threat_phase, commands
```

### Cloudflared and OpenSSH for Persistence
---
```sql
`tstats` `security_content_summariesonly` values(Processes.process) as process, count, min(_time) as first_seen, max(_time) as last_seen
from datamodel=Endpoint.Processes
where
  -- Filter for the specific IOCs related to Cloudflared and OpenSSH.
  (
    (Processes.process_name = "cloudflared.exe" AND Processes.process_path = "C:\\ProgramData\\") OR
    (Processes.process_name = "msiexec.exe" AND Processes.process LIKE "%C:\\ProgramData\\OpenSSHa.msi%") OR
    (Processes.process_name = "sshd.exe" AND Processes.process_path = "C:\\Program Files\\OpenSSH\\")
  )
-- Group by host and other relevant fields to identify unique events.
by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name
| `drop_dm_object_name(Processes)`
-- Format the output for analysts.
| `security_content_ctime(first_seen)`
| `security_content_ctime(last_seen)`
| rename dest as host
| eval threat_object=case(
    process_name="cloudflared.exe", "C:\\ProgramData\\cloudflared.exe",
    process_name="msiexec.exe", "C:\\ProgramData\\OpenSSHa.msi",
    process_name="sshd.exe", "C:\\Program Files\\OpenSSH\\sshd.exe"
  )
| table first_seen, last_seen, host, user, parent_process, process_name, process, threat_object
```

### RMM Tool Installation
---
```sql
`tstats` `security_content_summariesonly` count min(_time) as first_seen max(_time) as last_seen from datamodel=Endpoint.Processes
where
  -- Look for known RMM tool process names.
  (Processes.process_name IN ("AnyDesk.exe", "ScreenConnect.ClientService.exe", "ScreenConnect.Client.exe"))
  -- Optional: Filter for suspicious paths if legitimate use is common.
  -- AND (Processes.process_path IN ("C:\\ProgramData\\*", "C:\\Windows\\Temp\\*", "C:\\Users\\*\\AppData\\Local\\Temp\\*"))
by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process_path, Processes.process
| `drop_dm_object_name(Processes)`
-- Format the output for analysts.
| `security_content_ctime(first_seen)`
| `security_content_ctime(last_seen)`
| rename dest as host
| table first_seen, last_seen, host, user, parent_process, process_name, process_path, process, count
```

### Credential Theft from Veeam/NTDS.dit
---
```sql
`tstats` `security_content_summariesonly` count min(_time) as first_seen max(_time) as last_seen from datamodel=Endpoint.Processes
where
  -- Detect NTDS.dit backup via wbadmin
  (Processes.process_name="wbadmin.exe" AND Processes.process="*start backup*" AND Processes.process="*include:*NTDS.dit*") OR
  -- Detect Veeam credential dumping via a known PowerShell script
  (Processes.process_name IN ("powershell.exe", "pwsh.exe") AND Processes.process="*Veeam_Dump_Postgresql.ps1*")
by Processes.dest, Processes.user, Processes.parent_process, Processes.process
| `drop_dm_object_name(Processes)`
-- Categorize the detected threat for easier analysis.
| eval threat_type = if(match(process, "(?i)wbadmin.*NTDS\\.dit"), "NTDS.dit Backup via Wbadmin", "Veeam Credential Dump via PowerShell")
-- Format the output for analysts.
| `security_content_ctime(first_seen)`
| `security_content_ctime(last_seen)`
| rename dest as host
| table first_seen, last_seen, host, user, parent_process, process, threat_type, count
```

### Web Browser Credential Harvesting
---
```sql
`tstats` `security_content_summariesonly` count min(_time) as first_seen max(_time) as last_seen from datamodel=Endpoint.Processes
where
  -- Focus on command-line utilities often used for this activity
  (Processes.process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "xcopy.exe"))
  -- Look for keywords indicating a copy operation
  AND (Processes.process LIKE "%copy%" OR Processes.process LIKE "%Copy-Item%")
  -- Identify sensitive browser files in the command string
  AND (
    Processes.process LIKE "%Login Data%" OR
    Processes.process LIKE "%Web Data%" OR
    Processes.process LIKE "%Cookies%" OR
    Processes.process LIKE "%logins.json%" OR
    Processes.process LIKE "%key4.db%"
  )
  -- Ensure the source path is a typical browser profile location to increase fidelity
  AND (
    Processes.process LIKE "%\\AppData\\Local\\Google\\Chrome\\User Data%" OR
    Processes.process LIKE "%\\AppData\\Local\\Microsoft\\Edge\\User Data%" OR
    Processes.process LIKE "%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles%"
  )
by Processes.dest, Processes.user, Processes.parent_process, Processes.process
| `drop_dm_object_name(Processes)`
-- Format the output for analysts
| `security_content_ctime(first_seen)`
| `security_content_ctime(last_seen)`
| rename dest as host
| table first_seen, last_seen, host, user, parent_process, process, count
```

### Defense Evasion via Set-MpPreference/netsh
---
```sql
`tstats` `security_content_summariesonly` count min(_time) as first_seen max(_time) as last_seen from datamodel=Endpoint.Processes
where
  -- Detect PowerShell commands used to tamper with Microsoft Defender settings
  (
    (Processes.process_name IN ("powershell.exe", "pwsh.exe") AND Processes.process LIKE "%Set-MpPreference%" AND (Processes.process LIKE "%-DisableRealtimeMonitoring %true%" OR Processes.process LIKE "%-DisableBehaviorMonitoring %true%" OR Processes.process LIKE "%-DisableIntrusionPreventionSystem %true%" OR Processes.process LIKE "%-ExclusionPath%"))
  )
  OR
  -- Detect netsh commands used to disable the firewall or add permissive rules
  (
    (Processes.process_name="netsh.exe") AND (Processes.process LIKE "%advfirewall set % state off%" OR (Processes.process LIKE "%advfirewall firewall add rule%" AND Processes.process LIKE "%action=allow%"))
  )
  OR
  -- Detects use of SystemSettingsAdminFlows to disable Defender notifications, as seen in the reference
  (
    (Processes.process_name="SystemSettingsAdminFlows.exe") AND (Processes.process LIKE "%Defender DisableEnhancedNotifications 1%")
  )
by Processes.dest, Processes.user, Processes.parent_process, Processes.process
| `drop_dm_object_name(Processes)`
-- Categorize the detected technique for easier analysis
| eval evasion_technique = case(
    like(process, "%Set-MpPreference%"), "Microsoft Defender Tampering via PowerShell",
    like(process, "%netsh%"), "Windows Firewall Tampering via Netsh",
    like(process, "%SystemSettingsAdminFlows.exe%"), "Microsoft Defender Tampering via AdminFlows",
    1=1, "Unknown Defense Evasion"
  )
-- Format the output for analysts
| `security_content_ctime(first_seen)`
| `security_content_ctime(last_seen)`
| rename dest as host
| table first_seen, last_seen, host, user, parent_process, process, evasion_technique, count
```

### Enumeration Tools Usage
---
```sql
`tstats` `security_content_summariesonly` count min(_time) as first_seen max(_time) as last_seen from datamodel=Endpoint.Processes
where
  -- Detect third-party scanning tools
  (Processes.process_name IN ("Advanced_IP_Scanner.exe", "netscan.exe"))
  OR
  -- Detect nltest with common enumeration arguments
  (Processes.process_name="nltest.exe" AND (Processes.process LIKE "%/dclist:%" OR Processes.process LIKE "%/trusted_domains%" OR Processes.process LIKE "%/domain_trusts%"))
  OR
  -- Detect 'net group' for domain admin enumeration
  (Processes.process_name IN ("net.exe", "net1.exe") AND Processes.process LIKE "%group \"Domain Admins\"%" AND Processes.process LIKE "%/dom%")
  OR
  -- Detect quser for session enumeration
  (Processes.process_name="quser.exe")
  OR
  -- Detect PowerShell Active Directory computer enumeration
  (Processes.process_name IN ("powershell.exe", "pwsh.exe") AND Processes.process LIKE "%Get-ADComputer%")
by Processes.dest, Processes.user, Processes.parent_process, Processes.process
| `drop_dm_object_name(Processes)`
-- Categorize the tool for easier triage
| eval tool_used = case(
    like(process, "%Advanced_IP_Scanner%"), "Advanced IP Scanner",
    like(process, "%netscan.exe%"), "Netscan",
    like(process, "%nltest.exe%"), "nltest.exe",
    like(process, "%Get-ADComputer%"), "PowerShell (Get-ADComputer)",
    like(process, "%net%group%"), "net.exe (Group Enum)",
    like(process, "%quser.exe%"), "quser.exe",
    1=1, "Unknown Enumeration Tool"
  )
-- Format the output for analysts
| `security_content_ctime(first_seen)`
| `security_content_ctime(last_seen)`
| rename dest as host
| table first_seen, last_seen, host, user, parent_process, process, tool_used, count
```

### Volume Shadow Copy Deletion
---
```sql
`tstats` `security_content_summariesonly` count min(_time) as first_seen max(_time) as last_seen from datamodel=Endpoint.Processes
where
  -- Filter for vssadmin.exe process
  Processes.process_name="vssadmin.exe"
  -- Look for the specific command line arguments for deleting all shadows quietly
  AND Processes.process LIKE "%delete shadows%"
  AND Processes.process LIKE "%/all%"
  AND Processes.process LIKE "%/quiet%"
by Processes.dest, Processes.user, Processes.parent_process, Processes.process
| `drop_dm_object_name(Processes)`
-- Format the output for analysts
| `security_content_ctime(first_seen)`
| `security_content_ctime(last_seen)`
| rename dest as host
| table first_seen, last_seen, host, user, parent_process, process, count
```

### Akira Ransomware Executables
---
```sql
`tstats` `security_content_summariesonly` count min(_time) as first_seen max(_time) as last_seen from datamodel=Endpoint.Processes
where
  -- Detect by the specific SHA256 hash or by known filenames
  (Processes.file_hash="d080f553c9b1276317441894ec6861573fa64fb1fae46165a55302e782b1614d" OR Processes.process_name IN ("w.exe", "win.exe"))
by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process, Processes.file_hash
| `drop_dm_object_name(Processes)`
-- Format the output for analysts
| `security_content_ctime(first_seen)`
| `security_content_ctime(last_seen)`
| rename dest as host
| table first_seen, last_seen, host, user, parent_process, process_name, process, file_hash, count
```

### WinRAR and FileZilla for Data Staging/Exfil
---
```sql
`tstats` `security_content_summariesonly` count min(_time) as first_seen max(_time) as last_seen from datamodel=Endpoint.Processes
where
  -- Detect WinRAR running from a suspicious, non-standard path
  (Processes.process_name = "winrar.exe" AND Processes.process_path = "C:\\ProgramData\\")
  OR
  -- Detect the specific WinRAR command line used for staging
  (Processes.process_name = "WinRAR.exe" AND Processes.process LIKE "% a -ep1 -scul -r0 -iext -imon1 %")
  OR
  -- Detect the FileZilla SFTP client, a known exfiltration tool
  (Processes.process_name = "fzsftp.exe" AND Processes.process_path = "C:\\Program Files\\FileZilla FTP Client\\")
by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process_path, Processes.process
| `drop_dm_object_name(Processes)`
-- Format the output for analysts
| `security_content_ctime(first_seen)`
| `security_content_ctime(last_seen)`
| rename dest as host
| table first_seen, last_seen, host, user, parent_process, process_name, process_path, process, count
```

### Attacker IP Addresses
---
```sql
`tstats` `security_content_summariesonly` count min(_time) as first_seen max(_time) as last_seen from datamodel=Network_Traffic
where
  -- Check if either source or destination IP matches the known attacker infrastructure
  (All_Traffic.src_ip IN ("42.252.99.59", "45.86.208.240", "77.247.126.239", "104.238.205.105", "104.238.220.216", "181.215.182.64", "193.163.194.7", "193.239.236.149", "194.33.45.155")
  OR All_Traffic.dest_ip IN ("42.252.99.59", "45.86.208.240", "77.247.126.239", "104.238.205.105", "104.238.220.216", "181.215.182.64", "193.163.194.7", "193.239.236.149", "194.33.45.155"))
-- Group by connection details to see unique traffic flows
by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.user, All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
-- Identify which IP is the attacker's and the direction of the traffic for easier analysis
| eval attacker_ip = if(src_ip IN ("42.252.99.59", "45.86.208.240", "77.247.126.239", "104.238.205.105", "104.238.220.216", "181.215.182.64", "193.163.194.7", "193.239.236.149", "194.33.45.155"), src_ip, dest_ip)
| eval traffic_direction = if(src_ip IN ("42.252.99.59", "45.86.208.240", "77.247.126.239", "104.238.205.105", "104.238.220.216", "181.215.182.64", "193.163.194.7", "193.239.236.149", "194.33.45.155"), "inbound", "outbound")
-- Format the output for analysts
| `security_content_ctime(first_seen)`
| `security_content_ctime(last_seen)`
| table first_seen, last_seen, src_ip, dest_ip, dest_port, user, action, attacker_ip, traffic_direction, count
```

### New User Account Creation and Privilege Escalation
---
```sql
`tstats` `security_content_summariesonly` count min(_time) as first_seen max(_time) as last_seen from datamodel=Endpoint.Processes
where
  -- Detect user creation or group modification via net.exe/net1.exe
  (
    (Processes.process_name IN ("net.exe", "net1.exe")) AND
    (
      (Processes.process LIKE "% user % /add%") OR
      (Processes.process LIKE "% localgroup %Administrators% /add%") OR
      (Processes.process LIKE "% localgroup %\"Remote Desktop Users\"% /add%") OR
      (Processes.process LIKE "% group %\"Domain Admins\"% /add%")
    )
  )
  OR
  -- Detect hiding a user account from the logon screen via registry modification
  (
    (Processes.process_name = "reg.exe") AND
    (Processes.process LIKE "%add%HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList%")
  )
by Processes.dest, Processes.user, Processes.parent_process, Processes.process
| `drop_dm_object_name(Processes)`
-- Categorize the type of account manipulation for easier analysis
| eval technique = case(
    like(process, "% user % /add%"), "New User Creation",
    like(process, "% localgroup %Administrators% /add%"), "Added to Local Administrators",
    like(process, "% group %\"Domain Admins\"% /add%"), "Added to Domain Admins",
    like(process, "% localgroup %\"Remote Desktop Users\"% /add%"), "Added to Remote Desktop Users",
    like(process, "%SpecialAccounts\\UserList%"), "User Account Hidden from Logon",
    1=1, "Unknown Account Manipulation"
  )
-- Format the output for analysts
| `security_content_ctime(first_seen)`
| `security_content_ctime(last_seen)`
| rename dest as host
| table first_seen, last_seen, host, user, parent_process, process, technique, count
```

### Lateral Movement via WMI or PowerShell Remoting
---
```sql
`tstats` `security_content_summariesonly` count min(_time) as first_seen max(_time) as last_seen from datamodel=Endpoint.Processes
where
  -- Look for processes spawned by WMI or WinRM providers, which indicates remote execution
  Processes.parent_process_name IN ("wmiprvse.exe", "wsmprovhost.exe")
  -- Filter for common command shells, scripting engines, or specific malicious scripts used for lateral movement
  AND (
    Processes.process_name IN ("powershell.exe", "pwsh.exe", "cmd.exe") OR
    Processes.process LIKE "%Veeam_Dump_Postgresql.ps1%"
  )
  -- NOTE: Legitimate admin tools (SCCM, etc.) use these parents. Baseline and filter known good activity.
  -- For example: NOT (Processes.user="*SCCM_ACCOUNT*")
by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
-- Categorize the remote execution method for easier analysis
| eval technique = case(
    parent_process_name == "wmiprvse.exe", "Lateral Movement via WMI",
    parent_process_name == "wsmprovhost.exe", "Lateral Movement via PowerShell Remoting",
    1=1, "Unknown Remote Execution"
  )
-- Format the output for analysts
| `security_content_ctime(first_seen)`
| `security_content_ctime(last_seen)`
| rename dest as host, parent_process_name as parent_process
| table first_seen, last_seen, host, user, parent_process, process_name, process, technique, count
```