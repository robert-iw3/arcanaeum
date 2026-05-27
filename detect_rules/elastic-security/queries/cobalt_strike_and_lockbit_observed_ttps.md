### LockBit Ransomware Activity Report
---

This report details a LockBit ransomware intrusion initiated by a Cobalt Strike beacon disguised as a legitimate utility, followed by extensive lateral movement, credential access, and data exfiltration using various tools like Rclone, SystemBC, and GhostSOCKS. The attack culminated in the widespread deployment of LockBit ransomware across the victim's environment, highlighting the group's persistent and adaptive tactics.

Recent intelligence indicates LockBit's continued evolution, with the announcement of LockBit 4.0 for release in early 2025, featuring enhanced stealth and adaptability, including new evasion techniques and modified PowerShell scripts for payload deployment. This signifies the group's efforts to rebound and refine its operations despite law enforcement disruptions.

### Actionable Threat Data
---

Monitor for the execution of `setup_wm.exe` or similarly named executables impersonating legitimate Windows utilities, especially if originating from unusual download locations or exhibiting outbound Cobalt Strike C2 communications.

Detect the use of `Rclone` for data exfiltration, particularly when observed communicating with cloud storage services like `Mega.io` or attempting FTP transfers to suspicious external IPs.

Implement detections for the creation of scheduled tasks or registry run keys (`HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\App`) that establish persistence for tools like `SystemBC` or `GhostSOCKS`, especially when associated with `svcmc.dll`, `svcmcc.dll`, or `svchosts.exe`.

Look for process injection into legitimate processes such as `WUAUCLT.exe` or `svchost.exe`, particularly when followed by access to LSASS memory (`0x1010` or `0x1fffff` access rights) or the loading of reconnaissance modules like `Seatbelt` and `SharpView`.

Identify attempts to disable Windows Defender via Group Policy modifications or PowerShell commands (`Set-MpPreference -DisableRealtimeMonitoring $true`) executed remotely via `WMIC` or `PsExec`, as this is a common precursor to ransomware deployment.

Monitor for the execution of `check.exe` or similar binaries that perform host discovery, especially when followed by remote PowerShell sessions for Active Directory reconnaissance or attempts to access `NTDS.dit`.

Detect the use of `PsExec` and `BITSAdmin` for remote ransomware deployment, looking for service creation events (`Event ID 7045`) associated with `PSEXESVC.exe` and `wmiprvse.exe` spawning `bitsadmin` commands to transfer and execute ransomware binaries.

Create alerts for network connections to known Cobalt Strike C2 domains and IPs (e.g., `compdatasystems[.]com`, `user.compdatasystems[.]com`, `retailadvertisingservices[.]com`, `31.172.83.162`, `159.100.14.254`) and `SystemBC/GhostSOCKS` C2 infrastructure (e.g., `185.236.232.20:445`, `91.142.74.28:30001`, `195.2.70.38:30001`, `38.180.61.247:30001`).

### Cobalt Strike Beacon Hash
---
```sql
FROM * // replace with your index or data-stream for faster search
| WHERE file.hash.sha256 = "d8b2d883d3b376833fa8e2093e82d0a118ba13b01a2054f8447f57d9fec67030"
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.name, process.executable, file.hash.sha256
| KEEP firstTime, lastTime, host.name, user.name, process.parent.name, process.name, process.executable, file.hash.sha256, count
| RENAME host.name AS dest, user.name AS user, process.parent.name AS parent_process_name, process.name AS process_name, process.executable AS process, file.hash.sha256 AS hash
```

### Cobalt Strike C2 Domain Detection
---
```sql
FROM *
| WHERE dns.question.name LIKE "*.compdatasystems.com" OR dns.question.name LIKE "*.retailadvertisingservices.com"
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY source.ip, destination.ip, dns.question.name
| KEEP firstTime, lastTime, source.ip, destination.ip, dns.question.name, count
| RENAME source.ip AS src, destination.ip AS dest, dns.question.name AS query
```

### Cobalt Strike C2 / GhostSOCKS / SystemBC IP Address Detection
---
```sql
FROM *
| WHERE destination.ip IN ("31.172.83.162", "159.100.14.254", "185.236.232.20", "91.142.74.28", "195.2.70.38", "38.180.61.247", "93.115.26.127", "46.21.250.52")
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY source.ip, destination.ip, destination.port, user.name, process.name
| KEEP firstTime, lastTime, source.ip, destination.ip, destination.port, user.name, process.name, count
| RENAME source.ip AS src_ip, destination.ip AS dest_ip, destination.port AS dest_port, user.name AS user, process.name AS process_name
```

### Rclone for Exfiltration
---
```sql
FROM *
| WHERE process.name = "rclone.exe" AND (process.command_line LIKE "* copy *" OR process.command_line LIKE "* sync *")
  AND (process.command_line LIKE "* mega:%*" OR process.command_line LIKE "* ftp%:%*" OR process.command_line LIKE "* sftp:%*" OR process.command_line LIKE "* dropbox:%*" OR process.command_line LIKE "* onedrive:%*" OR process.command_line LIKE "* gdrive:%*")
  AND (process.command_line LIKE "*--no-console*" OR process.command_line LIKE "*--auto-confirm*" OR process.command_line LIKE "*-q*")
| STATS count = COUNT(*), process = ARRAY_AGG(process.command_line), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.parent.name
| KEEP firstTime, lastTime, host.name, user.name, process.parent.name, process, count
| RENAME host.name AS dest, user.name AS user, process.parent.name AS parent_process_name
```

### Process Injection into WUAUCLT.exe
---
```sql
FROM *
| WHERE event.action = "access" AND process.name = "wuauclt.exe" AND process.target.name = "lsass.exe" AND process.target.access_mask RLIKE "(0x1010|0x1410|0x1fffff)"
| STATS count = COUNT(*), process = ARRAY_AGG(process.command_line), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.target.access_mask
| KEEP firstTime, lastTime, host.name, user.name, process.parent.name, process, process.target.access_mask, count
| RENAME host.name AS dest, user.name AS user, process.parent.name AS parent_process_name, process.target.access_mask AS signature
```

### Disabling Windows Defender
---
```sql
FROM *
| WHERE
  (
    process.name = "powershell.exe" AND
    process.command_line LIKE "*Set-MpPreference*" AND
    process.command_line LIKE "*DisableRealtimeMonitoring*" AND
    (process.command_line LIKE "*$true*" OR process.command_line LIKE "*1*")
  )
  OR
  (
    registry.path LIKE "*\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring" AND
    (registry.data.strings = "0x00000001" OR registry.data.strings = "1")
  )
| STATS
    count = COUNT(*),
    process = ARRAY_AGG(process.command_line),
    parent_process = ARRAY_AGG(COALESCE(process.parent.name, process.name)),
    registry_path = ARRAY_AGG(registry.path),
    registry_value = ARRAY_AGG(registry.data.strings),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  BY @timestamp, host.name, user.name, process.name
| EVAL
    dest = host.name,
    user = user.name,
    activity_type = CASE(
      process IS NOT NULL, "PowerShell Command",
      TRUE, "Registry Modification"
    ),
    details = CASE(
      process IS NOT NULL, process,
      TRUE, CONCAT(registry_path, " set to ", registry_value)
    )
| KEEP firstTime, lastTime, dest, user, parent_process, activity_type, details
```

### PsExec and BITSAdmin for Ransomware
---
```sql
FROM *
| WHERE
  (
    process.parent.name = "PSEXESVC.exe"
  )
  OR
  (
    process.parent.name = "wmiprvse.exe" AND
    process.name = "bitsadmin.exe" AND
    process.command_line LIKE "* /transfer *"
  )
| STATS
    count = COUNT(*),
    process = ARRAY_AGG(process.command_line),
    process_name = ARRAY_AGG(process.name),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  BY host.name, user.name, process.parent.name
| EVAL
    threat_pattern = CASE(
      process.parent.name = "PSEXESVC.exe", "PsExec Remote Execution",
      process.parent.name = "wmiprvse.exe", "WMI/BITSAdmin Payload Download"
    )
| KEEP firstTime, lastTime, host.name, user.name, process.parent.name, process_name, process, threat_pattern, count
| RENAME host.name AS dest, user.name AS user, process.parent.name AS parent_process_name
```

### Scheduled Task for Persistence
---
```sql
FROM *
| WHERE process.name = "schtasks.exe" AND process.command_line LIKE "*/create*"
  AND (
    process.command_line LIKE "*/ru SYSTEM*"
    OR
    (process.command_line LIKE "*/tr*" AND (
      process.command_line LIKE "*%PUBLIC%*" OR
      process.command_line LIKE "*C:\\Users\\Public\\*" OR
      process.command_line LIKE "*C:\\ProgramData\\*" OR
      process.command_line LIKE "*%TEMP%*"
    ))
    OR
    (process.command_line LIKE "*/tr*" AND (
      process.command_line LIKE "*rundll32*" OR
      process.command_line LIKE "*powershell*" OR
      process.command_line LIKE "*mshta*" OR
      process.command_line LIKE "*regsvr32*"
    ))
  )
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.command_line
| KEEP firstTime, lastTime, host.name, user.name, process.parent.name, process.command_line, count
| RENAME host.name AS dest, user.name AS user, process.parent.name AS parent_process_name, process.command_line AS process
```

### Registry Run Key for Persistence
---
```sql
FROM *
| WHERE registry.path LIKE "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*"
  AND (
    registry.data.strings LIKE "*%PUBLIC%*" OR
    registry.data.strings LIKE "*\\Users\\Public\\*" OR
    registry.data.strings LIKE "*%APPDATA%*" OR
    registry.data.strings LIKE "*\\AppData\\Roaming\\*" OR
    registry.data.strings LIKE "*%TEMP%*" OR
    registry.data.strings LIKE "*\\AppData\\Local\\Temp\\*" OR
    registry.data.strings LIKE "*\\Windows\\Temp\\*" OR
    registry.data.strings LIKE "*C:\\ProgramData\\*"
  )
  AND registry.data.strings RLIKE ".*\\.(exe|dll|bat|vbs|ps1|scr)(\\s|$|\").*"
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, process.name, registry.path, registry.key, registry.data.strings
| KEEP firstTime, lastTime, host.name, user.name, process.name, registry.path, registry.key, registry.data.strings, count
| RENAME host.name AS dest, user.name AS user, process.name AS process_name, registry.path AS registry_path, registry.key AS registry_value_name, registry.data.strings AS registry_value_data
```

### Remote Service Creation for Lateral Movement
---
```sql
FROM *
| WHERE event.action = "installed"
  AND (
    service.executable LIKE "*\\Users\\Public\\*" OR
    service.executable LIKE "*C:\\ProgramData\\*" OR
    service.executable LIKE "*\\AppData\\*" OR
    service.executable LIKE "*\\Windows\\Temp\\*"
    OR
    (
      service.executable LIKE "*cmd.exe*" OR service.executable LIKE "*powershell.exe*"
    ) AND (
      service.executable LIKE "* -encodedcommand *" OR
      service.executable LIKE "* -w hidden *" OR
      service.executable LIKE "* /c *"
    )
    OR
    (
      service.executable LIKE "*rundll32.exe*" AND (
        service.executable LIKE "*\\Users\\Public\\*" OR
        service.executable LIKE "*C:\\ProgramData\\*" OR
        service.executable LIKE "*\\AppData\\*" OR
        service.executable LIKE "*\\Windows\\Temp\\*"
      )
    )
    OR
    (
      LENGTH(service.name) < 10 AND service.name RLIKE "^[a-zA-Z0-9]+$"
    )
  )
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.name, user.name, service.name, service.executable, service.start_type
| KEEP firstTime, lastTime, host.name, user.name, service.name, service.executable, service.start_type, count
| RENAME host.name AS dest, user.name AS user, service.name AS service_name, service.executable AS service_path, service.start_type AS service_start_type
```

### Active Directory Reconnaissance
---
```sql
FROM *
| WHERE
  (
    process.name = "nltest.exe" AND (
      process.command_line LIKE "*/dclist:*" OR
      process.command_line LIKE "*/domain_trusts*"
    )
    OR
    (
      process.name IN ("net.exe", "net1.exe") AND
      process.command_line LIKE "* group *" AND (
        process.command_line LIKE "*\"Domain Admins\"*" OR
        process.command_line LIKE "*\"Enterprise Admins\"*" OR
        process.command_line LIKE "*\"Schema Admins\"*"
      )
    )
    OR
    (
      process.name = "powershell.exe" AND (
        process.command_line LIKE "*Get-ADComputer*" OR
        process.command_line LIKE "*Get-ADUser*" OR
        process.command_line LIKE "*Get-ADGroup*" OR
        process.command_line LIKE "*Get-ADDomain*" OR
        process.command_line LIKE "*Import-Module ActiveDirectory*"
      )
    )
  )
| STATS
    count = COUNT(*),
    process = ARRAY_AGG(process.command_line),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  BY host.name, user.name, process.parent.name
| KEEP firstTime, lastTime, host.name, user.name, process.parent.name, process, count
| RENAME host.name AS dest, user.name AS user, process.parent.name AS parent_process_name
```

### Credential Dumping from Veeam
---
```sql
FROM *
| WHERE
  (
    process.name = "powershell.exe" AND process.command_line LIKE "*Veeam-Get-Creds.ps1*"
  )
  OR
  (
    event.code = "4104" AND
    script.content LIKE "*Veeam\\Veeam Backup and Replication*" AND
    script.content LIKE "*[dbo].[Credentials]*" AND
    script.content LIKE "*SELECT*password*"
  )
| STATS
    count = COUNT(*),
    details = ARRAY_AGG(COALESCE(process.command_line, script.content)),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  BY @timestamp, host.name, user.name, process.parent.name
| EVAL
    dest = host.name,
    user = user.name
| STATS
    values_details = ARRAY_AGG(details),
    count = SUM(count)
  BY firstTime, lastTime, dest, user, process.parent.name
| KEEP firstTime, lastTime, dest, user, process.parent.name, values_details
| RENAME process.parent.name AS parent_process_name, values_details AS details
```

### Accessing Shared Account Passwords
---
```sql
FROM *
| WHERE process.command_line LIKE "*passwords.txt*"
  OR process.command_line LIKE "*password.txt*"
  OR process.command_line LIKE "*creds.txt*"
  OR process.command_line LIKE "*credentials.txt*"
  OR process.command_line LIKE "*passwords.docx*"
  OR process.command_line LIKE "*credentials.docx*"
  OR process.command_line LIKE "*passwords.xlsx*"
  OR process.command_line LIKE "*credentials.xlsx*"
  OR process.command_line LIKE "*secrets.txt*"
  OR process.command_line LIKE "*account*password*"
  OR process.command_line LIKE "*shared*password*"
  OR process.command_line LIKE "*shared_account_passwords.docx*"
| STATS
    count = COUNT(*),
    process = ARRAY_AGG(process.command_line),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  BY host.name, user.name, process.parent.name
| KEEP firstTime, lastTime, host.name, user.name, process.parent.name, process, count
| RENAME host.name AS dest, user.name AS user, process.parent.name AS parent_process_name
```

### NTDS.dit Access Attempt
---
```sql
FROM *
| WHERE
  (
    process.name = "ntdsutil.exe" AND
    process.command_line LIKE "* ifm *" AND
    (process.command_line LIKE "* create *" OR process.command_line LIKE "* cr *")
  )
  OR
  (
    process.name IN ("copy.exe", "xcopy.exe", "robocopy.exe") AND
    process.command_line LIKE "*\\NTDS\\ntds.dit"
  )
| STATS
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  BY host.name, user.name, process.parent.name, process.command_line
| KEEP firstTime, lastTime, host.name, user.name, process.parent.name, process.command_line, count
| RENAME host.name AS dest, user.name AS user, process.parent.name AS parent_process_name, process.command_line AS process
```