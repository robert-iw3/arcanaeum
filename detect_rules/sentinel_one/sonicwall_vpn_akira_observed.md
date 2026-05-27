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
Process where
  (
    InitiatingProcessName IN ('vssadmin.exe', 'wbadmin.exe', 'WinRAR.exe', 'w.exe', 'win.exe', 'nltest.exe', 'net.exe', 'net1.exe')
  )
Group By
    EndpointName, InitiatingUser
Select
    SUM(CASE WHEN CommandLine Like '%wbadmin%start backup%include:%NTDS.dit%' THEN 1 ELSE 0 END) AS ntds_backup_flag,
    SUM(CASE WHEN CommandLine Like '%vssadmin%delete shadows% /all% /quiet%' THEN 1 ELSE 0 END) AS shadow_delete_flag,
    SUM(CASE WHEN InitiatingProcessName = 'WinRAR.exe' AND CommandLine Like '% a -ep1 -scul -r0 -iext -imon1 %' THEN 1 ELSE 0 END) AS winrar_staging_flag,
    SUM(CASE WHEN InitiatingProcessName In ('w.exe', 'win.exe') AND InitiatingProcessHashSHA256 = 'd080f553c9b1276317441894ec6861573fa64fb1fae46165a55302e782b1614d' THEN 1 ELSE 0 END) AS akira_ransomware_flag,
    SUM(CASE WHEN CommandLine Like '%nltest%dclist%' OR CommandLine Like '%nltest%domain_trusts%' OR CommandLine Like '%net group%Domain Admins% /dom%' THEN 1 ELSE 0 END) AS discovery_flag,
    SUM(CASE WHEN CommandLine Like '%net user% /add%' THEN 1 ELSE 0 END) AS user_creation_flag,
    COLLECT(CommandLine) AS commands,
    EndpointName As host, InitiatingUser As user
Where
  (ntds_backup_flag > 0 OR shadow_delete_flag > 0 OR winrar_staging_flag > 0 OR akira_ransomware_flag > 0 OR (discovery_flag > 0 AND user_creation_flag > 0))
Select
    host, user, ntds_backup_flag, shadow_delete_flag, winrar_staging_flag, akira_ransomware_flag, discovery_flag, user_creation_flag, commands,
    CASE
        WHEN akira_ransomware_flag > 0 THEN 'Impact (Akira Ransomware)'
        WHEN shadow_delete_flag > 0 THEN 'Impact (Shadow Copy Deletion)'
        WHEN ntds_backup_flag > 0 THEN 'Credential Access (NTDS.dit Backup)'
        WHEN winrar_staging_flag > 0 THEN 'Collection (Suspicious WinRAR Staging)'
        WHEN discovery_flag > 0 AND user_creation_flag > 0 THEN 'Persistence & Discovery'
        ELSE 'Suspicious Activity Pattern'
    END AS threat_phase
```

### Cloudflared and OpenSSH for Persistence
---
```sql
Process where
  (
    (InitiatingProcessName = 'cloudflared.exe' AND InitiatingProcessPath = 'C:\\ProgramData\\cloudflared.exe') OR
    (InitiatingProcessName = 'msiexec.exe' AND CommandLine Like '%C:\\ProgramData\\OpenSSHa.msi%') OR
    (InitiatingProcessName = 'sshd.exe' AND InitiatingProcessPath = 'C:\\Program Files\\OpenSSH\\sshd.exe')
  )
Group By
    EndpointName, InitiatingUser, ParentProcessName, InitiatingProcessName
Select
    MIN(Time) As first_seen, MAX(Time) As last_seen, COUNT(*) As count,
    COLLECT(CommandLine) As process_cmdlines, -- Renamed for clarity as it collects multiple command lines
    CASE
        WHEN InitiatingProcessName = 'cloudflared.exe' THEN 'C:\\ProgramData\\cloudflared.exe'
        WHEN InitiatingProcessName = 'msiexec.exe' THEN 'C:\\ProgramData\\OpenSSHa.msi'
        WHEN InitiatingProcessName = 'sshd.exe' THEN 'C:\\Program Files\\OpenSSH\\sshd.exe'
        ELSE 'Unknown Threat Object'
    END AS threat_object,
    EndpointName As host, InitiatingUser As user, ParentProcessName As parent_process, InitiatingProcessName as process_name
```

### RMM Tool Installation
---
```sql
Process where
  (InitiatingProcessName In ('AnyDesk.exe', 'ScreenConnect.ClientService.exe', 'ScreenConnect.Client.exe'))
Group By
    EndpointName, InitiatingUser, ParentProcessName, InitiatingProcessName, InitiatingProcessPath, CommandLine
Select
    MIN(Time) As first_seen, MAX(Time) As last_seen, COUNT(*) As count,
    EndpointName As host, InitiatingUser As user, ParentProcessName As parent_process,
    InitiatingProcessName As process_name, InitiatingProcessPath As process_path, CommandLine As process
```

### Credential Theft from Veeam/NTDS.dit
---
```sql
Process where
  (
    (InitiatingProcessName = 'wbadmin.exe' AND CommandLine Like '%start backup%include:%NTDS.dit%') OR
    (InitiatingProcessName In ('powershell.exe', 'pwsh.exe') AND CommandLine Like '%Veeam_Dump_Postgresql.ps1%')
  )
Group By
    EndpointName, InitiatingUser, ParentProcessName, CommandLine
Select
    MIN(Time) As first_seen, MAX(Time) As last_seen, COUNT(*) As count,
    EndpointName As host, InitiatingUser As user, ParentProcessName As parent_process,
    CommandLine As process,
    CASE
        WHEN CommandLine Like '%wbadmin%NTDS.dit%' THEN 'NTDS.dit Backup via Wbadmin'
        WHEN CommandLine Like '%Veeam_Dump_Postgresql.ps1%' THEN 'Veeam Credential Dump via PowerShell'
        ELSE 'Unknown Credential Access'
    END AS threat_type
```

### Web Browser Credential Harvesting
---
```sql
Process where
  (
    InitiatingProcessName IN ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'xcopy.exe')
    AND (CommandLine Like '%copy%' OR CommandLine Like '%Copy-Item%')
    AND (CommandLine Like '%Login Data%' OR CommandLine Like '%Web Data%' OR CommandLine Like '%Cookies%' OR CommandLine Like '%logins.json%' OR CommandLine Like '%key4.db%')
    AND (CommandLine Like '%\\AppData\\Local\\Google\\Chrome\\User Data%' OR CommandLine Like '%\\AppData\\Local\\Microsoft\\Edge\\User Data%' OR CommandLine Like '%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles%')
  )
Group By
    EndpointName, InitiatingUser, ParentProcessName, CommandLine
Select
    MIN(Time) As first_seen, MAX(Time) As last_seen, COUNT(*) As count,
    EndpointName As host, InitiatingUser As user, ParentProcessName As parent_process,
    CommandLine As process
```

### Defense Evasion via Set-MpPreference/netsh
---
```sql
Process where
  (
    (InitiatingProcessName In ('powershell.exe', 'pwsh.exe') AND CommandLine Like '%Set-MpPreference%' AND (CommandLine Like '%-DisableRealtimeMonitoring %true%' OR CommandLine Like '%-DisableBehaviorMonitoring %true%' OR CommandLine Like '%-DisableIntrusionPreventionSystem %true%' OR CommandLine Like '%-ExclusionPath%')) OR
    (InitiatingProcessName = 'netsh.exe' AND (CommandLine Like '%advfirewall set %state off%' OR (CommandLine Like '%advfirewall firewall add rule%' AND CommandLine Like '%action=allow%'))) OR
    (InitiatingProcessName = 'SystemSettingsAdminFlows.exe' AND CommandLine Like '%Defender DisableEnhancedNotifications 1%')
  )
Group By
    EndpointName, InitiatingUser, ParentProcessName, CommandLine
Select
    MIN(Time) As first_seen, MAX(Time) As last_seen, COUNT(*) As count,
    EndpointName As host, InitiatingUser As user, ParentProcessName As parent_process,
    CommandLine As process,
    CASE
        WHEN CommandLine Like '%Set-MpPreference%' THEN 'Microsoft Defender Tampering via PowerShell'
        WHEN CommandLine Like '%netsh%' THEN 'Windows Firewall Tampering via Netsh'
        WHEN CommandLine Like '%SystemSettingsAdminFlows.exe%' THEN 'Microsoft Defender Tampering via AdminFlows'
        ELSE 'Unknown Defense Evasion'
    END AS evasion_technique
```

### Enumeration Tools Usage
---
```sql
Process where
  (
    (InitiatingProcessName In ('Advanced_IP_Scanner.exe', 'netscan.exe')) OR
    (InitiatingProcessName = 'nltest.exe' AND CommandLine Like '%/dclist:% OR CommandLine Like '%/trusted_domains%' OR CommandLine Like '%/domain_trusts%') OR
    (InitiatingProcessName In ('net.exe', 'net1.exe') AND CommandLine Like '%group %Domain Admins% %/dom%') OR
    (InitiatingProcessName = 'quser.exe') OR
    (InitiatingProcessName In ('powershell.exe', 'pwsh.exe') AND CommandLine Like '%Get-ADComputer%')
  )
Group By
    EndpointName, InitiatingUser, ParentProcessName, CommandLine
Select
    MIN(Time) As first_seen, MAX(Time) As last_seen, COUNT(*) As count,
    EndpointName As host, InitiatingUser As user, ParentProcessName As parent_process,
    CommandLine As process,
    CASE
        WHEN CommandLine Like '%Advanced_IP_Scanner%' THEN 'Advanced IP Scanner'
        WHEN CommandLine Like '%netscan.exe%' THEN 'Netscan'
        WHEN CommandLine Like '%nltest.exe%' THEN 'nltest.exe'
        WHEN CommandLine Like '%Get-ADComputer%' THEN 'PowerShell (Get-ADComputer)'
        WHEN CommandLine Like '%net%group%Domain Admins%' THEN 'net.exe (Group Enum)'
        WHEN CommandLine Like '%quser.exe%' THEN 'quser.exe'
        ELSE 'Unknown Enumeration Tool'
    END AS tool_used
```

### Volume Shadow Copy Deletion
---
```sql
Process where
  (InitiatingProcessName = 'vssadmin.exe'
     AND CommandLine Like '%delete shadows%'
     AND CommandLine Like '%/all%'
     AND CommandLine Like '%/quiet%')
Group By
    EndpointName, InitiatingUser, ParentProcessName, CommandLine
Select
    MIN(Time) As first_seen, MAX(Time) As last_seen, COUNT(*) As count,
    EndpointName As host, InitiatingUser As user, ParentProcessName As parent_process,
    CommandLine As process
```

### Akira Ransomware Executables
---
```sql
Process where
  (InitiatingProcessHashSHA256 = "d080f553c9b1276317441894ec6861573fa64fb1fae46165a55302e782b1614d"
     OR InitiatingProcessName IN ('w.exe', 'win.exe'))
Group By
    EndpointName, InitiatingUser, ParentProcessName, InitiatingProcessName, CommandLine, InitiatingProcessHashSHA256
Select
    MIN(Time) As first_seen, MAX(Time) As last_seen, COUNT(*) As count,
    EndpointName As host, InitiatingUser As user, ParentProcessName As parent_process,
    InitiatingProcessName As process_name, CommandLine As process, InitiatingProcessHashSHA256 As file_hash
```

### WinRAR and FileZilla for Data Staging/Exfil
---
```sql
Process where
  (
    (InitiatingProcessName = "winrar.exe" AND InitiatingProcessPath = "C:\\ProgramData\\winrar.exe") OR
    (InitiatingProcessName = "WinRAR.exe" AND CommandLine Like "% a -ep1 -scul -r0 -iext -imon1 %") OR
    (InitiatingProcessName = "fzsftp.exe" AND InitiatingProcessPath = "C:\\Program Files\\FileZilla FTP Client\\fzsftp.exe")
  )
Group By
    EndpointName, InitiatingUser, ParentProcessName, InitiatingProcessName, InitiatingProcessPath, CommandLine
Select
    MIN(Time) As first_seen, MAX(Time) As last_seen, COUNT(*) As count,
    EndpointName As host, InitiatingUser As user, ParentProcessName As parent_process,
    InitiatingProcessName As process_name, InitiatingProcessPath As process_path, CommandLine As process
```

### Attacker IP Addresses
---
```sql
Process where
    (Network.RemoteIP In ('42.252.99.59', '45.86.208.240', '77.247.126.239', '104.238.205.105', '104.238.220.216', '181.215.182.64', '193.163.194.7', '193.239.236.149', '194.33.45.155'))
or
    (Network.LocalIP In ('42.252.99.59', '45.86.208.240', '77.247.126.239', '104.238.205.105', '104.238.220.216', '181.215.182.64', '193.163.194.7', '193.239.236.149', '194.33.45.155'))
Group By
    Network.LocalIP, Network.RemoteIP, Network.RemotePort, InitiatingUser, Type
Select
    MIN(Time) As first_seen, MAX(Time) As last_seen,
    Network.LocalIP, Network.RemoteIP, Network.RemotePort, InitiatingUser, Type,
    CASE
        WHEN Network.LocalIP In ('42.252.99.59', '45.86.208.240', '77.247.126.239', '104.238.205.105', '104.238.220.216', '181.215.182.64', '193.163.194.7', '193.239.236.149', '194.33.45.155') THEN Network.LocalIP
        ELSE Network.RemoteIP
    END AS attacker_ip,
    CASE
        WHEN Network.LocalIP In ('42.252.99.59', '45.86.208.240', '77.247.126.239', '104.238.205.105', '104.238.220.216', '181.215.182.64', '193.163.194.7', '193.239.236.149', '194.33.45.155') THEN 'inbound'
        ELSE 'outbound'
    END AS traffic_direction,
    COUNT(*) AS count
```

### New User Account Creation and Privilege Escalation
---
```sql
Process where
  (
    (InitiatingProcessName In ('net.exe', 'net1.exe')) AND
    (
      (CommandLine Like '% user % /add%') OR
      (CommandLine Like '% localgroup %Administrators% /add%') OR
      (CommandLine Like '% localgroup %\"Remote Desktop Users\"% /add%') OR
      (CommandLine Like '% group %\"Domain Admins\"% /add%')
    )
  )
  OR
  (
    (InitiatingProcessName = 'reg.exe') AND
    (CommandLine Like '%add%HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList%')
  )
Group By
    EndpointName, InitiatingUser, ParentProcessName, CommandLine
Select
    MIN(Time) As first_seen, MAX(Time) As last_seen,
    EndpointName As host, InitiatingUser As user, ParentProcessName As parent_process, CommandLine As process,
    CASE
        WHEN CommandLine Like '% user % /add%' THEN 'New User Creation'
        WHEN CommandLine Like '% localgroup %Administrators% /add%' THEN 'Added to Local Administrators'
        WHEN CommandLine Like '% group %\"Domain Admins\"% /add%' THEN 'Added to Domain Admins'
        WHEN CommandLine Like '% localgroup %\"Remote Desktop Users\"% /add%' THEN 'Added to Remote Desktop Users'
        WHEN CommandLine Like '%SpecialAccounts\\UserList%' THEN 'User Account Hidden from Logon'
        ELSE 'Unknown Account Manipulation'
    END AS technique,
    COUNT(*) AS count
```

### Lateral Movement via WMI or PowerShell Remoting
---
```sql
Process where
  (ParentProcessName In ('wmiprvse.exe', 'wsmprovhost.exe'))
  AND
  (
    (InitiatingProcessName In ('powershell.exe', 'pwsh.exe', 'cmd.exe')) OR
    (CommandLine Like '%Veeam_Dump_Postgresql.ps1%')
  )
  -- IMPORTANT: Baseline and filter known good activity. Example:
  -- AND NOT (InitiatingUser Like '*SCCM_ACCOUNT*')
Group By
    EndpointName, InitiatingUser, ParentProcessName, InitiatingProcessName, CommandLine
Select
    MIN(Time) As first_seen,
    MAX(Time) As last_seen,
    EndpointName As host,
    InitiatingUser As user,
    ParentProcessName As parent_process,
    InitiatingProcessName As process_name,
    CommandLine As process,
    CASE
        WHEN ParentProcessName = 'wmiprvse.exe' THEN 'Lateral Movement via WMI'
        WHEN ParentProcessName = 'wsmprovhost.exe' THEN 'Lateral Movement via PowerShell Remoting'
        ELSE 'Unknown Remote Execution'
    END AS technique,
    COUNT(*) AS count
```