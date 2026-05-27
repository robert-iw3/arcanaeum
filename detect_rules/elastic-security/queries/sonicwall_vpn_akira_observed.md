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
FROM *
| WHERE process.name IN ("vssadmin.exe", "wbadmin.exe", "WinRAR.exe", "w.exe", "win.exe", "nltest.exe", "net.exe", "net1.exe")
| EVAL ntds_backup = IF(process.command_line RLIKE "(?i).*wbadmin.*start backup.*include:.*\\\\NTDS\\\\.dit.*", 1, 0),
       shadow_delete = IF(process.command_line RLIKE "(?i).*vssadmin.*delete shadows.*\/all.*\/quiet.*", 1, 0),
       winrar_staging = IF(process.name == "WinRAR.exe" AND process.command_line RLIKE "(?i).*\\s+a\\s+-ep1\\s+-scul\\s+-r0\\s+-iext\\s+-imon1\\s+.*", 1, 0),
       akira_ransomware = IF((process.name IN ("w.exe", "win.exe") AND file.hash.sha256 == "d080f553c9b1276317441894ec6861573fa64fb1fae46165a55302e782b1614d"), 1, 0),
       discovery = IF(process.command_line RLIKE "(?i).*nltest.*(\/dclist|\/domain_trusts).*|.*net\\s+group.*Domain Admins.*\/dom.*", 1, 0),
       user_creation = IF(process.command_line RLIKE "(?i).*net\\s+user\\s+.*\/add\\s+\/dom.*", 1, 0)
| STATS ntds_backup_flag = SUM(ntds_backup),
        shadow_delete_flag = SUM(shadow_delete),
        winrar_staging_flag = SUM(winrar_staging),
        akira_ransomware_flag = SUM(akira_ransomware),
        discovery_flag = SUM(discovery),
        user_creation_flag = SUM(user_creation),
        commands = ARRAY_AGG(process.command_line)
  BY host.name, user.name
| WHERE ntds_backup_flag > 0 OR shadow_delete_flag > 0 OR winrar_staging_flag > 0 OR akira_ransomware_flag > 0 OR (discovery_flag > 0 AND user_creation_flag > 0)
| EVAL threat_phase = CASE(
        akira_ransomware_flag > 0, "Impact (Akira Ransomware)",
        shadow_delete_flag > 0, "Impact (Shadow Copy Deletion)",
        ntds_backup_flag > 0, "Credential Access (NTDS.dit Backup)",
        winrar_staging_flag > 0, "Collection (Suspicious WinRAR Staging)",
        discovery_flag > 0 AND user_creation_flag > 0, "Persistence & Discovery",
        TRUE, "Suspicious Activity Pattern")
| KEEP host.name AS host, user.name AS user, threat_phase, commands
```

### Cloudflared and OpenSSH for Persistence
---
```sql
FROM *
| WHERE (
    (process.name == "cloudflared.exe" AND process.executable == "C:\\ProgramData\\cloudflared.exe") OR
    (process.name == "msiexec.exe" AND process.command_line ILIKE "*C:\\ProgramData\\OpenSSHa.msi*") OR
    (process.name == "sshd.exe" AND process.executable == "C:\\Program Files\\OpenSSH\\sshd.exe")
  )
| STATS count = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        process = ARRAY_AGG(process.command_line)
  BY host.name, user.name, process.parent.name, process.name
| EVAL first_seen = TO_STRING(first_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       last_seen = TO_STRING(last_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       threat_object = CASE(
         process.name == "cloudflared.exe", "C:\\ProgramData\\cloudflared.exe",
         process.name == "msiexec.exe", "C:\\ProgramData\\OpenSSHa.msi",
         process.name == "sshd.exe", "C:\\Program Files\\OpenSSH\\sshd.exe"
       )
| KEEP first_seen, last_seen, host.name AS host, user.name AS user, process.parent.name AS parent_process, process.name AS process_name, process, threat_object
```

### RMM Tool Installation
---
```sql
FROM *
| WHERE process.name IN ("AnyDesk.exe", "ScreenConnect.ClientService.exe", "ScreenConnect.Client.exe")
| STATS count = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.name, process.executable, process.command_line
| EVAL first_seen = TO_STRING(first_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       last_seen = TO_STRING(last_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| KEEP first_seen, last_seen, host.name AS host, user.name AS user, process.parent.name AS parent_process, process.name AS process_name, process.executable AS process_path, process.command_line AS process, count
```

### Credential Theft from Veeam/NTDS.dit
---
```sql
FROM *
| WHERE (
    (process.name == "wbadmin.exe" AND process.command_line ILIKE "*start backup*include:*NTDS.dit*") OR
    (process.name IN ("powershell.exe", "pwsh.exe") AND process.command_line ILIKE "*Veeam_Dump_Postgresql.ps1*")
  )
| STATS count = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.command_line
| EVAL first_seen = TO_STRING(first_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       last_seen = TO_STRING(last_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       threat_type = CASE(
         process.command_line ILIKE "*wbadmin*NTDS.dit*", "NTDS.dit Backup via Wbadmin",
         TRUE, "Veeam Credential Dump via PowerShell"
       )
| KEEP first_seen, last_seen, host.name AS host, user.name AS user, process.parent.name AS parent_process, process.command_line AS process, threat_type, count
```

### Web Browser Credential Harvesting
---
```sql
FROM *
| WHERE process.name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "xcopy.exe")
  AND process.command_line ILIKE "*copy* OR *Copy-Item*"
  AND process.command_line ILIKE "*Login Data* OR *Web Data* OR *Cookies* OR *logins.json* OR *key4.db*"
  AND process.command_line ILIKE "*\\AppData\\Local\\Google\\Chrome\\User Data* OR *\\AppData\\Local\\Microsoft\\Edge\\User Data* OR *\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles*"
| STATS count = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.command_line
| EVAL first_seen = TO_STRING(first_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       last_seen = TO_STRING(last_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| KEEP first_seen, last_seen, host.name AS host, user.name AS user, process.parent.name AS parent_process, process.command_line AS process, count
```

### Defense Evasion via Set-MpPreference/netsh
---
```sql
FROM *
| WHERE (
    (process.name IN ("powershell.exe", "pwsh.exe") AND process.command_line ILIKE "*Set-MpPreference* AND (*-DisableRealtimeMonitoring *true* OR *-DisableBehaviorMonitoring *true* OR *-DisableIntrusionPreventionSystem *true* OR *-ExclusionPath*)") OR
    (process.name == "netsh.exe" AND process.command_line ILIKE "*advfirewall set *state off* OR (*advfirewall firewall add rule* AND *action=allow*)") OR
    (process.name == "SystemSettingsAdminFlows.exe" AND process.command_line ILIKE "*Defender DisableEnhancedNotifications 1*")
  )
| STATS count = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.command_line
| EVAL first_seen = TO_STRING(first_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       last_seen = TO_STRING(last_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       evasion_technique = CASE(
         process.command_line ILIKE "*Set-MpPreference*", "Microsoft Defender Tampering via PowerShell",
         process.command_line ILIKE "*netsh*", "Windows Firewall Tampering via Netsh",
         process.command_line ILIKE "*SystemSettingsAdminFlows.exe*", "Microsoft Defender Tampering via AdminFlows",
         TRUE, "Unknown Defense Evasion"
       )
| KEEP first_seen, last_seen, host.name AS host, user.name AS user, process.parent.name AS parent_process, process.command_line AS process, evasion_technique, count
```

### Enumeration Tools Usage
---
```sql
FROM *
| WHERE (
    (process.name IN ("Advanced_IP_Scanner.exe", "netscan.exe")) OR
    (process.name == "nltest.exe" AND process.command_line ILIKE "* /dclist:* OR * /trusted_domains* OR * /domain_trusts*") OR
    (process.name IN ("net.exe", "net1.exe") AND process.command_line ILIKE "*group *Domain Admins* */dom*") OR
    (process.name == "quser.exe") OR
    (process.name IN ("powershell.exe", "pwsh.exe") AND process.command_line ILIKE "*Get-ADComputer*")
  )
| STATS count = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.command_line
| EVAL first_seen = TO_STRING(first_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       last_seen = TO_STRING(last_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       tool_used = CASE(
         process.command_line ILIKE "*Advanced_IP_Scanner*", "Advanced IP Scanner",
         process.command_line ILIKE "*netscan.exe*", "Netscan",
         process.command_line ILIKE "*nltest.exe*", "nltest.exe",
         process.command_line ILIKE "*Get-ADComputer*", "PowerShell (Get-ADComputer)",
         process.command_line ILIKE "*net*group*Domain Admins*", "net.exe (Group Enum)",
         process.command_line ILIKE "*quser.exe*", "quser.exe",
         TRUE, "Unknown Enumeration Tool"
       )
| KEEP first_seen, last_seen, host.name AS host, user.name AS user, process.parent.name AS parent_process, process.command_line AS process, tool_used, count
```

### Volume Shadow Copy Deletion
---
```sql
FROM *
| WHERE process.name == "vssadmin.exe"
  AND process.command_line ILIKE "*delete shadows* AND */all* AND */quiet*"
| STATS count = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.command_line
| EVAL first_seen = TO_STRING(first_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       last_seen = TO_STRING(last_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| KEEP first_seen, last_seen, host.name AS host, user.name AS user, process.parent.name AS parent_process, process.command_line AS process, count
```

### Akira Ransomware Executables
---
```sql
FROM *
| WHERE file.hash.sha256 == "d080f553c9b1276317441894ec6861573fa64fb1fae46165a55302e782b1614d"
  OR process.name IN ("w.exe", "win.exe")
| STATS count = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.name, process.command_line, file.hash.sha256
| EVAL first_seen = TO_STRING(first_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       last_seen = TO_STRING(last_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| KEEP first_seen, last_seen, host.name AS host, user.name AS user, process.parent.name AS parent_process, process.name AS process_name, process.command_line AS process, file.hash.sha256 AS file_hash, count
```

### WinRAR and FileZilla for Data Staging/Exfil
---
```sql
FROM *
| WHERE (
    (process.name == "winrar.exe" AND process.executable == "C:\\ProgramData\\winrar.exe") OR
    (process.name == "WinRAR.exe" AND process.command_line ILIKE "* a -ep1 -scul -r0 -iext -imon1 *") OR
    (process.name == "fzsftp.exe" AND process.executable == "C:\\Program Files\\FileZilla FTP Client\\fzsftp.exe")
  )
| STATS count = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.name, process.executable, process.command_line
| EVAL first_seen = TO_STRING(first_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
       last_seen = TO_STRING(last_seen, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
| KEEP first_seen, last_seen, host.name AS host, user.name AS user, process.parent.name AS parent_process, process.name AS process_name, process.executable AS process_path, process.command_line AS process, count
```

### Attacker IP Addresses
---
```sql
from *
where
  (source.ip in ("42.252.99.59", "45.86.208.240", "77.247.126.239", "104.238.205.105", "104.238.220.216", "181.215.182.64", "193.163.194.7", "193.239.236.149", "194.33.45.155") OR
   destination.ip in ("42.252.99.59", "45.86.208.240", "77.247.126.239", "104.238.205.105", "104.238.220.216", "181.215.182.64", "193.163.194.7", "193.239.236.149", "194.33.45.155"))
| stats count = count(),
        first_seen = min(@timestamp),
        last_seen = max(@timestamp)
    by source.ip, destination.ip, destination.port, user.name, network.direction
| eval attacker_ip = if(source.ip in ("42.252.99.59", "45.86.208.240", "77.247.126.239", "104.238.205.105", "104.238.220.216", "181.215.182.64", "193.163.194.7", "193.239.236.149", "194.33.45.155"), source.ip, destination.ip),
       traffic_direction = if(source.ip in ("42.252.99.59", "45.86.208.240", "77.247.126.239", "104.238.205.105", "104.238.220.216", "181.215.182.64", "193.163.194.7", "193.239.236.149", "194.33.45.155"), "inbound", "outbound")
| project first_seen, last_seen, source.ip, destination.ip, destination.port, user.name, network.direction, attacker_ip, traffic_direction, count
```

### New User Account Creation and Privilege Escalation
---
```sql
from *
where
  (
    (process.name in ("net.exe", "net1.exe") AND
     (process.command_line : "* user * /add*" OR
      process.command_line : "* localgroup *Administrators* /add*" OR
      process.command_line : "* localgroup *\"Remote Desktop Users\"* /add*" OR
      process.command_line : "* group *\"Domain Admins\"* /add*"))
  ) OR
  (
    (process.name = "reg.exe") AND
    (process.command_line : "*add*HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList*")
  )
| stats count = count(),
        first_seen = min(@timestamp),
        last_seen = max(@timestamp)
    by host.name, user.name, process.parent.name, process.command_line
| eval technique = case(
    process.command_line : "* user * /add*", "New User Creation",
    process.command_line : "* localgroup *Administrators* /add*", "Added to Local Administrators",
    process.command_line : "* group *\"Domain Admins\"* /add*", "Added to Domain Admins",
    process.command_line : "* localgroup *\"Remote Desktop Users\"* /add*", "Added to Remote Desktop Users",
    process.command_line : "*SpecialAccounts\\UserList*", "User Account Hidden from Logon",
    true, "Unknown Account Manipulation"
  )
| project first_seen, last_seen, host.name, user.name, process.parent.name, process.command_line, technique, count
```

### Lateral Movement via WMI or PowerShell Remoting
---
```sql
from *
where
  (process.parent.name in ("wmiprvse.exe", "wsmprovhost.exe")) AND
  (
    process.name in ("powershell.exe", "pwsh.exe", "cmd.exe") OR
    process.command_line : "*Veeam_Dump_Postgresql.ps1*"
  )
  // NOTE: Legitimate admin tools (SCCM, etc.) use these parents. Baseline and filter known good activity.
  // For example: AND NOT (user.name = "*SCCM_ACCOUNT*")
| stats count = count(),
        first_seen = min(@timestamp),
        last_seen = max(@timestamp)
    by host.name, user.name, process.parent.name, process.name, process.command_line
| eval technique = case(
    process.parent.name == "wmiprvse.exe", "Lateral Movement via WMI",
    process.parent.name == "wsmprovhost.exe", "Lateral Movement via PowerShell Remoting",
    true, "Unknown Remote Execution"
  )
| project first_seen, last_seen, host.name, user.name, process.parent.name, process.name, process.command_line, technique, count
```