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
EventType = "Process Creation" AND FileSha256 = "d8b2d883d3b376833fa8e2093e82d0a118ba13b01a2054f8447f57d9fec67030"
| GROUP BY AgentName, User, ParentProcessName, ProcessName, ProcessImagePath, FileSha256
  AGGREGATE count = COUNT(*), firstTime = MIN(timestamp), lastTime = MAX(timestamp)
| SELECT firstTime, lastTime, AgentName AS dest, User AS user, ParentProcessName AS parent_process_name, ProcessName AS process_name, ProcessImagePath AS process, FileSha256 AS hash, count
```

### Cobalt Strike C2 Domain Detection
---
```sql
EventType = "DNS" AND (DnsRequest LIKE "*.compdatasystems.com" OR DnsRequest LIKE "*.retailadvertisingservices.com")
| GROUP BY SrcIP, DstIP, DnsRequest
  AGGREGATE count = COUNT(*), firstTime = MIN(timestamp), lastTime = MAX(timestamp)
| SELECT firstTime, lastTime, SrcIP AS src, DstIP AS dest, DnsRequest AS query, count
```

### Cobalt Strike C2 / GhostSOCKS / SystemBC IP Address Detection
---
```sql
EventType = "Network" AND DstIP IN ("31.172.83.162", "159.100.14.254", "185.236.232.20", "91.142.74.28", "195.2.70.38", "38.180.61.247", "93.115.26.127", "46.21.250.52")
| GROUP BY SrcIP, DstIP, DstPort, User, ProcessName
  AGGREGATE count = COUNT(*), firstTime = MIN(timestamp), lastTime = MAX(timestamp)
| SELECT firstTime, lastTime, SrcIP AS src_ip, DstIP AS dest_ip, DstPort AS dest_port, User AS user, ProcessName AS process_name, count
```

### Rclone for Exfiltration
---
```sql
EventType = "Process Creation" AND ProcessName = "rclone.exe" AND (ProcessCmd LIKE "* copy *" OR ProcessCmd LIKE "* sync *")
  AND (ProcessCmd LIKE "* mega:%*" OR ProcessCmd LIKE "* ftp%:%*" OR ProcessCmd LIKE "* sftp:%*" OR ProcessCmd LIKE "* dropbox:%*" OR ProcessCmd LIKE "* onedrive:%*" OR ProcessCmd LIKE "* gdrive:%*")
  AND (ProcessCmd LIKE "*--no-console*" OR ProcessCmd LIKE "*--auto-confirm*" OR ProcessCmd LIKE "*-q*")
| GROUP BY AgentName, User, ParentProcessName
  AGGREGATE count = COUNT(*), process = COLLECT(ProcessCmd), firstTime = MIN(timestamp), lastTime = MAX(timestamp)
| SELECT firstTime, lastTime, AgentName AS dest, User AS user, ParentProcessName AS parent_process_name, process, count
```

### Process Injection into WUAUCLT.exe
---
```sql
EventType = "Process Access" AND ProcessName = "wuauclt.exe" AND ProcessName = "lsass.exe" AND access.mask MATCHES "(0x1010|0x1410|0x1fffff)"
| GROUP BY AgentName, User, ParentProcessName, access.mask
  AGGREGATE count = COUNT(*), process = COLLECT(ProcessCmd), firstTime = MIN(timestamp), lastTime = MAX(timestamp)
| SELECT firstTime, lastTime, AgentName AS dest, User AS user, ParentProcessName AS parent_process_name, process, access.mask AS signature, count
```

### Disabling Windows Defender
---
```sql
EventType IN ("Process Creation", "Registry Modification")
  AND (
    (
      ProcessName = "powershell.exe" AND
      ProcessCmd LIKE "*Set-MpPreference*" AND
      ProcessCmd LIKE "*DisableRealtimeMonitoring*" AND
      (ProcessCmd LIKE "*$true*" OR ProcessCmd LIKE "*1*")
    )
    OR
    (
      RegistryPath LIKE "*\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring" AND
      (RegistryValueData = "0x00000001" OR RegistryValueData = "1")
    )
  )
| GROUP BY timestamp, AgentName, User, ProcessName
  AGGREGATE
    count = COUNT(*),
    process = COLLECT(ProcessCmd),
    parent_process = COLLECT(COALESCE(ParentProcessName, ProcessName)),
    registry_path = COLLECT(RegistryPath),
    registry_value = COLLECT(RegistryValueData),
    firstTime = MIN(timestamp),
    lastTime = MAX(timestamp)
| SELECT
    firstTime,
    lastTime,
    AgentName AS dest,
    User AS user,
    parent_process,
    CASE
      WHEN process IS NOT NULL THEN "PowerShell Command"
      ELSE "Registry Modification"
    END AS activity_type,
    CASE
      WHEN process IS NOT NULL THEN process
      ELSE registry_path + " set to " + registry_value
    END AS details,
    count
```

### PsExec and BITSAdmin for Ransomware
---
```sql
EventType = "Process Creation" AND
  (
    ParentProcessName = "PSEXESVC.exe"
    OR
    (
      ParentProcessName = "wmiprvse.exe" AND
      ProcessName = "bitsadmin.exe" AND
      ProcessCmd LIKE "* /transfer *"
    )
  )
| GROUP BY AgentName, User, ParentProcessName
  AGGREGATE
    count = COUNT(*),
    process = COLLECT(ProcessCmd),
    process_name = COLLECT(ProcessName),
    firstTime = MIN(timestamp),
    lastTime = MAX(timestamp)
| SELECT
    firstTime,
    lastTime,
    AgentName AS dest,
    User AS user,
    ParentProcessName AS parent_process_name,
    process_name,
    process,
    CASE
      WHEN ParentProcessName = "PSEXESVC.exe" THEN "PsExec Remote Execution"
      WHEN ParentProcessName = "wmiprvse.exe" THEN "WMI/BITSAdmin Payload Download"
    END AS threat_pattern,
    count
```

### Scheduled Task for Persistence
---
```sql
EventType = "Process Creation" AND ProcessName = "schtasks.exe" AND ProcessCmd LIKE "*/create*"
  AND (
    ProcessCmd LIKE "*/ru SYSTEM*"
    OR
    (ProcessCmd LIKE "*/tr*" AND (
      ProcessCmd LIKE "*%PUBLIC%*" OR
      ProcessCmd LIKE "*C:\\Users\\Public\\*" OR
      ProcessCmd LIKE "*C:\\ProgramData\\*" OR
      ProcessCmd LIKE "*%TEMP%*"
    ))
    OR
    (ProcessCmd LIKE "*/tr*" AND (
      ProcessCmd LIKE "*rundll32*" OR
      ProcessCmd LIKE "*powershell*" OR
      ProcessCmd LIKE "*mshta*" OR
      ProcessCmd LIKE "*regsvr32*"
    ))
  )
| GROUP BY AgentName, User, ParentProcessName, ProcessCmd
  AGGREGATE count = COUNT(*), firstTime = MIN(timestamp), lastTime = MAX(timestamp)
| SELECT firstTime, lastTime, AgentName AS dest, User AS user, ParentProcessName AS parent_process_name, ProcessCmd AS process, count
```

### Registry Run Key for Persistence
---
```sql
EventType = "Registry Modification" AND
  RegistryPath LIKE "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*"
  AND (
    RegistryValueData LIKE "*%PUBLIC%*" OR
    RegistryValueData LIKE "*\\Users\\Public\\*" OR
    RegistryValueData LIKE "*%APPDATA%*" OR
    RegistryValueData LIKE "*\\AppData\\Roaming\\*" OR
    RegistryValueData LIKE "*%TEMP%*" OR
    RegistryValueData LIKE "*\\AppData\\Local\\Temp\\*" OR
    RegistryValueData LIKE "*\\Windows\\Temp\\*" OR
    RegistryValueData LIKE "*C:\\ProgramData\\*"
  )
  AND RegistryValueData MATCHES ".*\\.(exe|dll|bat|vbs|ps1|scr)(\\s|$|\").*"
| GROUP BY AgentName, User, ProcessName, RegistryPath, RegistryValueName, RegistryValueData
  AGGREGATE count = COUNT(*), firstTime = MIN(timestamp), lastTime = MAX(timestamp)
| SELECT
    firstTime,
    lastTime,
    AgentName AS dest,
    User AS user,
    ProcessName AS process_name,
    RegistryPath AS registry_path,
    RegistryValueName AS registry_value_name,
    RegistryValueData AS registry_value_data,
    count
```

### Remote Service Creation for Lateral Movement
---
```sql
EventType = "Service Creation" AND EventAction = "installed"
  AND (
    ServicePath LIKE "*\\Users\\Public\\*" OR
    ServicePath LIKE "*C:\\ProgramData\\*" OR
    ServicePath LIKE "*\\AppData\\*" OR
    ServicePath LIKE "*\\Windows\\Temp\\*"
    OR
    (
      ServicePath LIKE "*cmd.exe*" OR ServicePath LIKE "*powershell.exe*"
    ) AND (
      ServicePath LIKE "* -encodedcommand *" OR
      ServicePath LIKE "* -w hidden *" OR
      ServicePath LIKE "* /c *"
    )
    OR
    (
      ServicePath LIKE "*rundll32.exe*" AND (
        ServicePath LIKE "*\\Users\\Public\\*" OR
        ServicePath LIKE "*C:\\ProgramData\\*" OR
        ServicePath LIKE "*\\AppData\\*" OR
        ServicePath LIKE "*\\Windows\\Temp\\*"
      )
    )
    OR
    (
      LENGTH(ServiceName) < 10 AND ServiceName MATCHES "^[a-zA-Z0-9]+$"
    )
  )
| GROUP BY AgentName, User, ServiceName, ServicePath, ServiceStartType
  AGGREGATE count = COUNT(*), firstTime = MIN(timestamp), lastTime = MAX(timestamp)
| SELECT
    firstTime,
    lastTime,
    AgentName AS dest,
    User AS user,
    ServiceName AS service_name,
    ServicePath AS service_path,
    ServiceStartType AS service_start_type,
    count
```

### Active Directory Reconnaissance
---
```sql
EventType = "Process Creation" AND
  (
    (
      ProcessName = "nltest.exe" AND (
        ProcessCmd LIKE "*/dclist:*" OR
        ProcessCmd LIKE "*/domain_trusts*"
      )
    )
    OR
    (
      ProcessName IN ("net.exe", "net1.exe") AND
      ProcessCmd LIKE "* group *" AND (
        ProcessCmd LIKE "*\"Domain Admins\"*" OR
        ProcessCmd LIKE "*\"Enterprise Admins\"*" OR
        ProcessCmd LIKE "*\"Schema Admins\"*"
      )
    )
    OR
    (
      ProcessName = "powershell.exe" AND (
        ProcessCmd LIKE "*Get-ADComputer*" OR
        ProcessCmd LIKE "*Get-ADUser*" OR
        ProcessCmd LIKE "*Get-ADGroup*" OR
        ProcessCmd LIKE "*Get-ADDomain*" OR
        ProcessCmd LIKE "*Import-Module ActiveDirectory*"
      )
    )
  )
| GROUP BY AgentName, User, ParentProcessName
  AGGREGATE
    count = COUNT(*),
    process = COLLECT(ProcessCmd),
    firstTime = MIN(timestamp),
    lastTime = MAX(timestamp)
| SELECT
    firstTime,
    lastTime,
    AgentName AS dest,
    User AS user,
    ParentProcessName AS parent_process_name,
    process,
    count
```

### Credential Dumping from Veeam
---
```sql
EventType IN ("Process Creation", "Script Execution")
  AND (
    (
      ProcessName = "powershell.exe" AND
      ProcessCmd LIKE "*Veeam-Get-Creds.ps1*"
    )
    OR
    (
      EventId = "4104" AND
      ScriptContent LIKE "*Veeam\\Veeam Backup and Replication*" AND
      ScriptContent LIKE "*[dbo].[Credentials]*" AND
      ScriptContent LIKE "*SELECT*password*"
    )
  )
| GROUP BY timestamp, AgentName, User, ParentProcessName
  AGGREGATE
    count = COUNT(*),
    details = COLLECT(COALESCE(ProcessCmd, ScriptContent)),
    firstTime = MIN(timestamp),
    lastTime = MAX(timestamp)
| GROUP BY firstTime, lastTime, AgentName, User, ParentProcessName
  AGGREGATE
    values_details = COLLECT(details),
    count = SUM(count)
| SELECT
    firstTime,
    lastTime,
    AgentName AS dest,
    User AS user,
    ParentProcessName AS parent_process_name,
    values_details AS details,
    count
```

### Accessing Shared Account Passwords
---
```sql
EventType = "Process Creation" AND (
  ProcessCmd LIKE "*passwords.txt*" OR
  ProcessCmd LIKE "*password.txt*" OR
  ProcessCmd LIKE "*creds.txt*" OR
  ProcessCmd LIKE "*credentials.txt*" OR
  ProcessCmd LIKE "*passwords.docx*" OR
  ProcessCmd LIKE "*credentials.docx*" OR
  ProcessCmd LIKE "*passwords.xlsx*" OR
  ProcessCmd LIKE "*credentials.xlsx*" OR
  ProcessCmd LIKE "*secrets.txt*" OR
  ProcessCmd LIKE "*account*password*" OR
  ProcessCmd LIKE "*shared*password*" OR
  ProcessCmd LIKE "*shared_account_passwords.docx*"
)
| GROUP BY AgentName, User, ParentProcessName
  AGGREGATE
    count = COUNT(*),
    process = COLLECT(ProcessCmd),
    firstTime = MIN(timestamp),
    lastTime = MAX(timestamp)
| SELECT
    firstTime,
    lastTime,
    AgentName AS dest,
    User AS user,
    ParentProcessName AS parent_process_name,
    process,
    count
```

### NTDS.dit Access Attempt
---
```sql
EventType = "Process Creation" AND
  (
    (
      ProcessName = "ntdsutil.exe" AND
      ProcessCmd LIKE "* ifm *" AND
      (ProcessCmd LIKE "* create *" OR ProcessCmd LIKE "* cr *")
    )
    OR
    (
      ProcessName IN ("copy.exe", "xcopy.exe", "robocopy.exe") AND
      ProcessCmd LIKE "*\\NTDS\\ntds.dit"
    )
  )
| GROUP BY AgentName, User, ParentProcessName, ProcessCmd
  AGGREGATE
    count = COUNT(*),
    firstTime = MIN(timestamp),
    lastTime = MAX(timestamp)
| SELECT
    firstTime,
    lastTime,
    AgentName AS dest,
    User AS user,
    ParentProcessName AS parent_process_name,
    ProcessCmd AS process,
    count
```