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
event_platform=Win event_simpleName=ProcessRollup2 (FileName IN ("vssadmin.exe", "wbadmin.exe", "WinRAR.exe", "w.exe", "win.exe", "nltest.exe", "net.exe", "net1.exe"))
| eval ntds_backup=if(CommandLine=/.*wbadmin.*start backup.*include:.*\\NTDS\\.dit.*/i, 1, 0), shadow_delete=if(CommandLine=/.*vssadmin.*delete shadows.*\/all.*\/quiet.*/i, 1, 0), winrar_staging=if(FileName="WinRAR.exe" AND CommandLine=/.*\s+a\s+-ep1\s+-scul\s+-r0\s+-iext\s+-imon1\s+.*/i, 1, 0), akira_ransomware=if((FileName="w.exe" OR FileName="win.exe") AND SHA256HashData="d080f553c9b1276317441894ec6861573fa64fb1fae46165a55302e782b1614d", 1, 0), discovery=if(CommandLine=/.*nltest.*(\/dclist|\/domain_trusts).*/i OR CommandLine=/.*net\s+group.*Domain Admins.*\/dom.*/i, 1, 0), user_creation=if(CommandLine=/.*net\s+user\s+.*\/add\s+\/dom.*/i, 1, 0)
| stats sum(ntds_backup) as ntds_backup_flag, sum(shadow_delete) as shadow_delete_flag, sum(winrar_staging) as winrar_staging_flag, sum(akira_ransomware) as akira_ransomware_flag, sum(discovery) as discovery_flag, sum(user_creation) as user_creation_flag, values(CommandLine) as commands by ComputerName, UserName
| where (ntds_backup_flag > 0 OR shadow_delete_flag > 0 OR winrar_staging_flag > 0 OR akira_ransomware_flag > 0) OR (discovery_flag > 0 AND user_creation_flag > 0)
| eval threat_phase=case(akira_ransomware_flag > 0, "Impact (Akira Ransomware)", shadow_delete_flag > 0, "Impact (Shadow Copy Deletion)", ntds_backup_flag > 0, "Credential Access (NTDS.dit Backup)", winrar_staging_flag > 0, "Collection (Suspicious WinRAR Staging)", discovery_flag > 0 AND user_creation_flag > 0, "Persistence & Discovery", true, "Suspicious Activity Pattern")
| fields ComputerName as host, UserName as user, threat_phase, commands
```

### Cloudflared and OpenSSH for Persistence
---
```sql
event_platform=Win event_simpleName=ProcessRollup2
((FileName="cloudflared.exe" AND FilePath="C:\\ProgramData\\") OR
 (FileName="msiexec.exe" AND CommandLine=/.*C:\\ProgramData\\OpenSSHa\.msi.*/) OR
 (FileName="sshd.exe" AND FilePath="C:\\Program Files\\OpenSSH\\"))
| stats min(timestamp) as first_seen, max(timestamp) as last_seen, count() as count, values(CommandLine) as process
  by ComputerName, UserName, ParentBaseFileName, FileName
| eval threat_object=case(FileName="cloudflared.exe", "C:\\ProgramData\\cloudflared.exe",
                         FileName="msiexec.exe", "C:\\ProgramData\\OpenSSHa.msi",
                         FileName="sshd.exe", "C:\\Program Files\\OpenSSH\\sshd.exe")
| fields first_seen, last_seen, ComputerName as host, UserName as user, ParentBaseFileName as parent_process, FileName as process_name, process, threat_object
```

### RMM Tool Installation
---
```sql
event_platform=Win event_simpleName=ProcessRollup2 FileName IN ("AnyDesk.exe", "ScreenConnect.ClientService.exe", "ScreenConnect.Client.exe")
| stats min(timestamp) as first_seen, max(timestamp) as last_seen, count() as count by ComputerName, UserName, ParentBaseFileName, FileName, FilePath, CommandLine
| fields first_seen, last_seen, ComputerName as host, UserName as user, ParentBaseFileName as parent_process, FileName as process_name, FilePath as process_path, CommandLine as process, count
```

### Credential Theft from Veeam/NTDS.dit
---
```sql
event_platform=Win event_simpleName=ProcessRollup2
((FileName="wbadmin.exe" AND CommandLine=/.*start backup.*include:.*NTDS\.dit.*/i) OR
 (FileName IN ("powershell.exe", "pwsh.exe") AND CommandLine=/.*Veeam_Dump_Postgresql\.ps1.*/i))
| stats min(timestamp) as first_seen, max(timestamp) as last_seen, count() as count
  by ComputerName, UserName, ParentBaseFileName, CommandLine
| eval threat_type=if(CommandLine=/.*wbadmin.*NTDS\.dit.*/i, "NTDS.dit Backup via Wbadmin", "Veeam Credential Dump via PowerShell")
| fields first_seen, last_seen, ComputerName as host, UserName as user, ParentBaseFileName as parent_process, CommandLine as process, threat_type, count
```

### Web Browser Credential Harvesting
---
```sql
event_platform=Win event_simpleName=ProcessRollup2 FileName IN ("cmd.exe", "powershell.exe", "pwsh.exe", "xcopy.exe")
CommandLine=/.*(copy|Copy-Item).*(Login Data|Web Data|Cookies|logins\.json|key4\.db).*(AppData\\Local\\Google\\Chrome\\User Data|AppData\\Local\\Microsoft\\Edge\\User Data|AppData\\Roaming\\Mozilla\\Firefox\\Profiles).*/i
| stats min(timestamp) as first_seen, max(timestamp) as last_seen, count() as count by ComputerName, UserName, ParentBaseFileName, CommandLine
| fields first_seen, last_seen, ComputerName as host, UserName as user, ParentBaseFileName as parent_process, CommandLine as process, count
```

### Defense Evasion via Set-MpPreference/netsh
---
```sql
event_platform=Win event_simpleName=ProcessRollup2
((FileName IN ("powershell.exe", "pwsh.exe") AND CommandLine=/.*Set-MpPreference.*(-DisableRealtimeMonitoring\s+true|-DisableBehaviorMonitoring\s+true|-DisableIntrusionPreventionSystem\s+true|-ExclusionPath).*/i) OR
 (FileName="netsh.exe" AND CommandLine=/.*(advfirewall set.*state off|advfirewall firewall add rule.*action=allow).*/i) OR
 (FileName="SystemSettingsAdminFlows.exe" AND CommandLine=/.*Defender DisableEnhancedNotifications 1.*/i))
| stats min(timestamp) as first_seen, max(timestamp) as last_seen, count() as count
  by ComputerName, UserName, ParentBaseFileName, CommandLine
| eval evasion_technique=case(CommandLine=/.*Set-MpPreference.*/i, "Microsoft Defender Tampering via PowerShell",
                             CommandLine=/.*netsh.*/i, "Windows Firewall Tampering via Netsh",
                             CommandLine=/.*SystemSettingsAdminFlows\.exe.*/i, "Microsoft Defender Tampering via AdminFlows",
                             true, "Unknown Defense Evasion")
| fields first_seen, last_seen, ComputerName as host, UserName as user, ParentBaseFileName as parent_process, CommandLine as process, evasion_technique, count
```

### Enumeration Tools Usage
---
```sql
event_platform=Win event_simpleName=ProcessRollup2
((FileName IN ("Advanced_IP_Scanner.exe", "netscan.exe")) OR
 (FileName="nltest.exe" AND CommandLine=/.*(\/dclist:|\/trusted_domains|\/domain_trusts).*/i) OR
 (FileName IN ("net.exe", "net1.exe") AND CommandLine=/.*group\s+"Domain Admins".*\/dom.*/i) OR
 (FileName="quser.exe") OR
 (FileName IN ("powershell.exe", "pwsh.exe") AND CommandLine=/.*Get-ADComputer.*/i))
| stats min(timestamp) as first_seen, max(timestamp) as last_seen, count() as count
  by ComputerName, UserName, ParentBaseFileName, CommandLine
| eval tool_used=case(CommandLine=/.*Advanced_IP_Scanner.*/i, "Advanced IP Scanner",
                     CommandLine=/.*netscan\.exe.*/i, "Netscan",
                     CommandLine=/.*nltest\.exe.*/i, "nltest.exe",
                     CommandLine=/.*Get-ADComputer.*/i, "PowerShell (Get-ADComputer)",
                     CommandLine=/.*net.*group.*Domain Admins.*/i, "net.exe (Group Enum)",
                     CommandLine=/.*quser\.exe.*/i, "quser.exe",
                     true, "Unknown Enumeration Tool")
| fields first_seen, last_seen, ComputerName as host, UserName as user, ParentBaseFileName as parent_process, CommandLine as process, tool_used, count
```

### Volume Shadow Copy Deletion
---
```sql
event_platform=Win event_simpleName=ProcessRollup2 FileName="vssadmin.exe" CommandLine=/.*delete shadows.*\/all.*\/quiet.*/i
| stats min(timestamp) as first_seen, max(timestamp) as last_seen, count() as count
  by ComputerName, UserName, ParentBaseFileName, CommandLine
| fields first_seen, last_seen, ComputerName as host, UserName as user, ParentBaseFileName as parent_process, CommandLine as process, count
```

### Akira Ransomware Executables
---
```sql
event_platform=Win event_simpleName=ProcessRollup2
(SHA256HashData="d080f553c9b1276317441894ec6861573fa64fb1fae46165a55302e782b1614d" OR FileName IN ("w.exe", "win.exe"))
| stats min(timestamp) as first_seen, max(timestamp) as last_seen, count() as count
  by ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, SHA256HashData
| fields first_seen, last_seen, ComputerName as host, UserName as user, ParentBaseFileName as parent_process, FileName as process_name, CommandLine as process, SHA256HashData as file_hash, count
```

### WinRAR and FileZilla for Data Staging/Exfil
---
```sql
event_platform=Win event_simpleName=ProcessRollup2
((FileName="winrar.exe" AND FilePath="C:\\ProgramData\\") OR
 (FileName="WinRAR.exe" AND CommandLine=/.*\s+a\s+-ep1\s+-scul\s+-r0\s+-iext\s+-imon1\s+.*/i) OR
 (FileName="fzsftp.exe" AND FilePath="C:\\Program Files\\FileZilla FTP Client\\"))
| stats min(timestamp) as first_seen, max(timestamp) as last_seen, count() as count
  by ComputerName, UserName, ParentBaseFileName, FileName, FilePath, CommandLine
| fields first_seen, last_seen, ComputerName as host, UserName as user, ParentBaseFileName as parent_process, FileName as process_name, FilePath as process_path, CommandLine as process, count
```

### Attacker IP Addresses
---
```sql
event_simpleName=NetworkConnect
| filter (DstIP in ("42.252.99.59", "45.86.208.240", "77.247.126.239", "104.238.205.105", "104.238.220.216", "181.215.182.64", "193.163.194.7", "193.239.236.149", "194.33.45.155") OR
            SrcIP in ("42.252.99.59", "45.86.208.240", "77.247.126.239", "104.238.205.105", "104.238.220.216", "181.215.182.64", "193.163.194.7", "193.239.236.149", "194.33.45.155"))
| groupBy([SrcIP, DstIP, DstPort, UserName, NetworkDirection],
        function=[count(), min(Timestamp), max(Timestamp)])
| eval attacker_ip = if(SrcIP in ("42.252.99.59", "45.86.208.240", "77.247.126.239", "104.238.205.105", "104.238.220.216", "181.215.182.64", "193.163.194.7", "193.239.236.149", "194.33.45.155"), SrcIP, DstIP)
| eval traffic_direction = if(SrcIP in ("42.252.99.59", "45.86.208.240", "77.247.126.239", "104.238.205.105", "104.238.220.216", "181.215.182.64", "193.163.194.7", "193.239.236.149", "194.33.45.155"), "inbound", "outbound")
| project Timestamp as first_seen, max(Timestamp) as last_seen, SrcIP, DstIP, DstPort, UserName, NetworkDirection, attacker_ip, traffic_direction, _count
```

### New User Account Creation and Privilege Escalation
---
```sql
event_simpleName=ProcessRollup2
| filter (
  (FileName in ("net.exe", "net1.exe") AND
   (CommandLine contains " user " and CommandLine contains " /add" OR
    CommandLine contains " localgroup " and CommandLine contains "Administrators" and CommandLine contains " /add" OR
    CommandLine contains " localgroup " and CommandLine contains "\"Remote Desktop Users\"" and CommandLine contains " /add" OR
    CommandLine contains " group " and CommandLine contains "\"Domain Admins\"" and CommandLine contains " /add"))
  OR
  (FileName = "reg.exe" AND
   CommandLine contains "add" and CommandLine contains "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList")
)
| groupBy([ComputerName, UserName, ParentBaseFileName, CommandLine],
        function=[count(), min(Timestamp), max(Timestamp)])
| eval technique = case(
    CommandLine contains " user " and CommandLine contains " /add", "New User Creation",
    CommandLine contains " localgroup " and CommandLine contains "Administrators" and CommandLine contains " /add", "Added to Local Administrators",
    CommandLine contains " group " and CommandLine contains "\"Domain Admins\"" and CommandLine contains " /add", "Added to Domain Admins",
    CommandLine contains " localgroup " and CommandLine contains "\"Remote Desktop Users\"" and CommandLine contains " /add", "Added to Remote Desktop Users",
    CommandLine contains "SpecialAccounts\\UserList", "User Account Hidden from Logon",
    "Unknown Account Manipulation"
  )
| project min(Timestamp) as first_seen, max(Timestamp) as last_seen, ComputerName as host, UserName as user, ParentBaseFileName as parent_process, CommandLine as process, technique, _count as count
```

### Lateral Movement via WMI or PowerShell Remoting
---
```sql
event_simpleName=ProcessRollup2
| filter (
  (ParentBaseFileName in ("wmiprvse.exe", "wsmprovhost.exe")) AND
  (
    FileName in ("powershell.exe", "pwsh.exe", "cmd.exe") OR
    CommandLine contains "Veeam_Dump_Postgresql.ps1"
  )
  // NOTE: Legitimate admin tools (SCCM, etc.) use these parents. Baseline and filter known good activity.
  // For example: AND NOT (UserName contains "*SCCM_ACCOUNT*")
)
| groupBy([ComputerName, UserName, ParentBaseFileName, FileName, CommandLine],
        function=[count(), min(Timestamp), max(Timestamp)])
| eval technique = case(
    ParentBaseFileName == "wmiprvse.exe", "Lateral Movement via WMI",
    ParentBaseFileName == "wsmprovhost.exe", "Lateral Movement via PowerShell Remoting",
    "Unknown Remote Execution"
  )
| project min(Timestamp) as first_seen, max(Timestamp) as last_seen, ComputerName as host, UserName as user, ParentBaseFileName as parent_process, FileName as process_name, CommandLine as process, technique, _count as count
```