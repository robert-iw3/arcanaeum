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
source:endpoint process.hash:d8b2d883d3b376833fa8e2093e82d0a118ba13b01a2054f8447f57d9fec67030
| select host, user, parent_process.name AS parent_process_name, process.name AS process_name, process.cmdline AS process, process.hash, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, parent_process_name, process_name, process, hash
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, parent_process_name, process_name, process, hash
```

### Cobalt Strike C2 Domain Detection
---
```sql
source:network_resolution dns.query:(*compdatasystems.com OR *retailadvertisingservices.com)
| select ip.src AS src, ip.dst AS dest, dns.query AS query, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by src, dest, query
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, src, dest, query
```

### Cobalt Strike C2 / GhostSOCKS / SystemBC IP Address Detection
---
```sql
source:network_traffic ip.dst:(31.172.83.162 OR 159.100.14.254 OR 185.236.232.20 OR 91.142.74.28 OR 195.2.70.38 OR 38.180.61.247 OR 93.115.26.127 OR 46.21.250.52)
| select ip.src AS src_ip, ip.dst AS dest_ip, port.dst AS dest_port, user, process.name AS process_name, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by src_ip, dest_ip, dest_port, user, process_name
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, src_ip, dest_ip, dest_port, user, process_name
```

### Rclone for Exfiltration
---
```sql
source:endpoint process.name:rclone.exe process.cmdline:(" copy " OR " sync ") process.cmdline:(mega: OR ftp: OR sftp: OR dropbox: OR onedrive: OR gdrive:) process.cmdline:("--no-console" OR "--auto-confirm" OR "-q")
| select host, user, parent_process.name AS parent_process_name, process.cmdline AS process, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate collect(process) AS process by host, user, parent_process_name
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, parent_process_name, process
```

### Process Injection into WUAUCLT.exe
---
```sql
source:endpoint process.name:wuauclt.exe process.target:lsass.exe signature:/(0x1010|0x1410|0x1fffff)/
| select host, user, parent_process.name AS parent_process_name, process.cmdline AS process, signature, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate collect(process) AS process by host, user, parent_process_name, signature
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, parent_process_name, process, signature
```

### Disabling Windows Defender
---
```sql
source:endpoint (process.name:powershell.exe process.cmdline:(Set-MpPreference AND DisableRealtimeMonitoring AND ($true OR 1)) OR registry.path:*\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring registry.value:(0x00000001 OR 1))
| select coalesce(process.host, registry.host) AS dest, coalesce(process.user, registry.user) AS user, coalesce(parent_process.name, registry.process_name) AS parent_process, case(process.cmdline IS NOT NULL => "PowerShell Command", true => "Registry Modification") AS activity_type, coalesce(process.cmdline, registry.path + " set to " + registry.value) AS details, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate collect(details) AS details by firstTime, lastTime, dest, user, parent_process, activity_type
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, dest, user, parent_process, activity_type, details
```

### PsExec and BITSAdmin for Ransomware
---
```sql
source:endpoint (parent_process.name:PSEXESVC.exe OR (parent_process.name:wmiprvse.exe process.name:bitsadmin.exe process.cmdline:" /transfer "))
| select host, user, parent_process.name AS parent_process_name, process.name AS process_name, process.cmdline AS process, case(parent_process.name = "PSEXESVC.exe" => "PsExec Remote Execution", parent_process.name = "wmiprvse.exe" => "WMI/BITSAdmin Payload Download") AS threat_pattern, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate collect(process) AS process, collect(process_name) AS process_name by host, user, parent_process_name, threat_pattern
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, parent_process_name, process_name, process, threat_pattern
```

### Scheduled Task for Persistence
---
```sql
source:endpoint process.name:schtasks.exe process.cmdline:("/create" AND ("/ru SYSTEM" OR process.cmdline:(*%PUBLIC%* OR *C:\\Users\\Public\\* OR *C:\\ProgramData\\* OR *%TEMP%*) OR process.cmdline:("*rundll32*" OR "*powershell*" OR "*mshta*" OR "*regsvr32*")))
| select host, user, parent_process.name AS parent_process_name, process.cmdline AS process, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, parent_process_name, process
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, parent_process_name, process
```

### Registry Run Key for Persistence
---
```sql
source:endpoint registry.path:*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run* registry.value:(*%PUBLIC%* OR *\\Users\\Public\\* OR *%APPDATA%* OR *\\AppData\\Roaming\\* OR *%TEMP%* OR *\\AppData\\Local\\Temp\\* OR *\\Windows\\Temp\\* OR *C:\\ProgramData\\*) registry.value:(*.exe* OR *.dll* OR *.bat* OR *.vbs* OR *.ps1* OR *.scr*)
| select host, user, registry.process_name AS process_name, registry.path AS registry_path, registry.value_name AS registry_value_name, registry.value AS registry_value_data, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, process_name, registry_path, registry_value_name, registry_value_data
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, process_name, registry_path, registry_value_name, registry_value_data
```

### Remote Service Creation for Lateral Movement
---
```sql
source:endpoint service.action:installed (service.path:(*\\Users\\Public\\* OR *C:\\ProgramData\\* OR *\\AppData\\* OR *\\Windows\\Temp\\*) OR (service.path:(*cmd.exe* OR *powershell.exe*) AND service.path:("* -encodedcommand *" OR "* -w hidden *" OR "* /c *")) OR (service.path:*rundll32.exe* AND service.path:(*\\Users\\Public\\* OR *C:\\ProgramData\\* OR *\\AppData\\* OR *\\Windows\\Temp\\*)) OR (len(service.name) < 10 AND service.name:/^[a-zA-Z0-9]+$/))
| select host, user, service.name AS service_name, service.path AS service_path, service.start_type AS service_start_type, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, service_name, service_path, service_start_type
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, service_name, service_path, service_start_type
```

### Active Directory Reconnaissance
---
```sql
source:endpoint ((process.name:nltest.exe process.cmdline:("/dclist:" OR "/domain_trusts")) OR (process.name:(net.exe OR net1.exe) process.cmdline:(" group " AND ("\"Domain Admins\"" OR "\"Enterprise Admins\"" OR "\"Schema Admins\""))) OR (process.name:powershell.exe process.cmdline:(Get-ADComputer OR Get-ADUser OR Get-ADGroup OR Get-ADDomain OR "Import-Module ActiveDirectory")))
| select host, user, parent_process.name AS parent_process_name, process.cmdline AS process, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate collect(process) AS process by host, user, parent_process_name
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, parent_process_name, process
```

### Credential Dumping from Veeam
---
```sql
source:endpoint (process.name:powershell.exe process.cmdline:*Veeam-Get-Creds.ps1* OR script.block:(*Veeam\\Veeam\ Backup\ and\ Replication* AND *[dbo].[Credentials]* AND *SELECT*password*))
| select coalesce(process.host, script.host) AS dest, coalesce(process.user, script.user) AS user, parent_process.name AS parent_process_name, coalesce(process.cmdline, script.block) AS details, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate collect(details) AS details by firstTime, lastTime, dest, user, parent_process_name
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, dest, user, parent_process_name, details
```

### Accessing Shared Account Passwords
---
```sql
source:endpoint process.cmdline:(*passwords.txt* OR *password.txt* OR *creds.txt* OR *credentials.txt* OR *passwords.docx* OR *credentials.docx* OR *passwords.xlsx* OR *credentials.xlsx* OR *secrets.txt* OR *account*password* OR *shared*password* OR *shared_account_passwords.docx*)
| select host, user, parent_process.name AS parent_process_name, process.cmdline AS process, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate collect(process) AS process by host, user, parent_process_name
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, parent_process_name, process
```

### NTDS.dit Access Attempt
---
```sql
source:endpoint ((process.name:ntdsutil.exe process.cmdline:(" ifm " AND (" create " OR " cr "))) OR (process.name:(copy.exe OR xcopy.exe OR robocopy.exe) process.cmdline:*\\NTDS\\ntds.dit))
| select host, user, parent_process.name AS parent_process_name, process.cmdline AS process, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, parent_process_name, process
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host, user, parent_process_name, process
```