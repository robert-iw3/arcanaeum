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
| tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
-- search for the specific SHA256 hash of the Cobalt Strike beacon
where Processes.hash="d8b2d883d3b376833fa8e2093e82d0a118ba13b01a2054f8447f57d9fec67030"
-- group by fields that provide context for the execution event
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.hash
-- rename fields for better readability
| rename Processes.* as *
-- convert timestamps to human-readable format
| convert ctime(firstTime) ctime(lastTime)
```

### Cobalt Strike C2 Domain Detection
---
```sql
| tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution
-- search for DNS queries ending with the known malicious domains. The wildcard at the beginning covers subdomains.
where (DNS.query="*compdatasystems.com" OR DNS.query="*retailadvertisingservices.com")
-- group by fields that provide context for the DNS query
by DNS.src DNS.dest DNS.query
-- rename fields for better readability
| rename DNS.* as *
-- convert timestamps to human-readable format
| convert ctime(firstTime) ctime(lastTime)
```

### Cobalt Strike C2 / GhostSOCKS / SystemBC IP Address Detection
---
```sql
| tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic
-- search for connections to known malicious destination IPs
where All_Traffic.dest_ip IN ("31.172.83.162", "159.100.14.254", "185.236.232.20", "91.142.74.28", "195.2.70.38", "38.180.61.247", "93.115.26.127", "46.21.250.52")
-- group by fields that provide context for the network connection
by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.user All_Traffic.process_name
-- rename fields for better readability
| rename All_Traffic.* as *
-- convert timestamps to human-readable format
| convert ctime(firstTime) ctime(lastTime)
```

### Rclone for Exfiltration
---
```sql
| tstats `summariesonly` values(Processes.process) as process, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = "rclone.exe" AND (Processes.process="* copy *" OR Processes.process="* sync *") by Processes.dest, Processes.user, Processes.parent_process_name
| `drop_dm_object_name("Processes")`
-- Filter for command line arguments indicating exfiltration to cloud or FTP services.
| where (like(process, "% mega:%") OR like(process, "% ftp%:%") OR like(process, "% sftp:%") OR like(process, "% dropbox:%") OR like(process, "% onedrive:%") OR like(process, "% gdrive:%"))
-- Further refine by looking for flags that suggest non-interactive, automated execution.
  AND (like(process, "%--no-console%") OR like(process, "%--auto-confirm%") OR like(process, "%-q%"))
-- Convert timestamps to human-readable format.
| convert ctime(firstTime) ctime(lastTime)
-- False Positive Note: Legitimate backup scripts or administrative tasks may use Rclone. If this generates noise, consider filtering by user, parent_process_name, or specific command-line arguments associated with legitimate scripts.
| table firstTime, lastTime, dest, user, parent_process_name, process
```

### Process Injection into WUAUCLT.exe
---
```sql
| tstats `summariesonly` values(Processes.process) as process, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where `process_access` AND Processes.process_name="wuauclt.exe" AND Processes.dest="lsass.exe" by Processes.dest, Processes.user, Processes.parent_process_name, Processes.signature
| `drop_dm_object_name("Processes")`
-- Filter for specific access rights that allow reading memory, which is necessary for credential dumping.
-- The intel specifically mentions 0x1010 and 0x1fffff. 0x1410 is also common.
| where match(signature, /(?i)(0x1010|0x1410|0x1fffff)/)
-- Convert timestamps to a readable format.
| convert ctime(firstTime) ctime(lastTime)
-- False Positive Note: It is extremely rare for wuauclt.exe to legitimately access lsass.exe memory. However, some EDR or security monitoring tools may exhibit this behavior. Investigate the parent process of wuauclt.exe and any associated module loads to determine legitimacy.
| table firstTime, lastTime, dest, user, parent_process_name, process, signature
```

### Disabling Windows Defender
---
```sql
-- Search across both Processes and Registry data models for indicators of tampering.
| tstats `summariesonly` values(Processes.process) as process, values(Processes.parent_process_name) as parent_process, values(Registry.registry_path) as registry_path, values(Registry.registry_value_data) as registry_value, min(_time) as firstTime, max(_time) as lastTime
FROM datamodel=Endpoint
WHERE
  -- Condition 1: PowerShell command to disable real-time monitoring.
  (
    Processes.process_name = "powershell.exe" AND
    Processes.process = "*Set-MpPreference*" AND
    Processes.process = "*DisableRealtimeMonitoring*" AND
    (Processes.process = "*$true*" OR Processes.process = "*1*")
  )
  OR
  -- Condition 2: Registry key modification to disable real-time monitoring.
  (
    Registry.registry_path = "*\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring" AND
    (Registry.registry_value_data = "0x00000001" OR Registry.registry_value_data = "1")
  )
-- Group by common fields to correlate activity.
by _time, Processes.dest, Processes.user, Registry.dest, Registry.user, Registry.process_name
| `drop_dm_object_name("Processes")`
| `drop_dm_object_name("Registry")`
-- Coalesce fields from both data models for a unified view.
| eval dest = coalesce(Processes_dest, Registry_dest),
       user = coalesce(Processes_user, Registry_user),
       parent_process = coalesce(parent_process, process_name),
       activity_type = if(isnotnull(process), "PowerShell Command", "Registry Modification"),
       details = if(isnotnull(process), process, registry_path + " set to " + registry_value)
-- Convert timestamps to human-readable format.
| convert ctime(firstTime) ctime(lastTime)
-- False Positive Note: Legitimate administrative scripts or system management tools (like SCCM, Intune) might perform these actions. Investigate the parent process and user context to determine legitimacy.
| table firstTime, lastTime, dest, user, parent_process, activity_type, details
```

### PsExec and BITSAdmin for Ransomware
---
```sql
| tstats `summariesonly` values(Processes.process) as process, values(Processes.process_name) as process_name, min(_time) as firstTime, max(_time) as lastTime
  FROM datamodel=Endpoint.Processes
  WHERE
    -- Pattern 1: PsExec service executing a command, often for payload staging or execution.
    (Processes.parent_process_name = "PSEXESVC.exe")
    OR
    -- Pattern 2: WMI provider host spawning BITSAdmin to download a payload.
    (Processes.parent_process_name = "wmiprvse.exe" AND Processes.process_name = "bitsadmin.exe" AND Processes.process = "* /transfer *")
  by Processes.dest, Processes.user, Processes.parent_process_name
| `drop_dm_object_name("Processes")`
-- Add a field to identify which pattern was matched for easier analysis.
| eval threat_pattern = case(
    parent_process_name == "PSEXESVC.exe", "PsExec Remote Execution",
    parent_process_name == "wmiprvse.exe", "WMI/BITSAdmin Payload Download"
  )
-- Convert timestamps to human-readable format.
| convert ctime(firstTime) ctime(lastTime)
-- False Positive Note: PsExec is a legitimate administrative tool. Its use should be correlated with other suspicious activity. WMI spawning BITSAdmin is highly suspicious but could be used by some management software. Investigate the downloaded file and subsequent activity on the host.
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process, threat_pattern
```

### Scheduled Task for Persistence
---
```sql
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  FROM datamodel=Endpoint.Processes
  WHERE
    -- Look for the creation of a scheduled task via schtasks.exe
    (Processes.process_name="schtasks.exe" AND Processes.process="*/create*")
    AND
    (
      -- Pattern 1: Task is set to run with SYSTEM privileges, as seen in the reference report.
      Processes.process="*/ru SYSTEM*"
      OR
      -- Pattern 2: The task's action (/tr) involves executing a file from a world-writable or temporary location.
      (Processes.process="*/tr*" AND (Processes.process="*%PUBLIC%*" OR Processes.process="*C:\\Users\\Public\\*" OR Processes.process="*C:\\ProgramData\\*" OR Processes.process="*%TEMP%*"))
      OR
      -- Pattern 3: The task's action involves a LOLBIN or script interpreter.
      (Processes.process="*/tr*" AND (Processes.process="*rundll32*" OR Processes.process="*powershell*" OR Processes.process="*mshta*" OR Processes.process="*regsvr32*"))
    )
  by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process
| `drop_dm_object_name("Processes")`
-- Convert timestamps to human-readable format.
| convert ctime(firstTime) ctime(lastTime)
-- False Positive Note: Legitimate software installers and system management tools may create scheduled tasks that run as SYSTEM or execute from C:\ProgramData. Review the parent process and the command being executed by the task (/tr) to determine legitimacy. Consider filtering for known legitimate parent processes or task names if false positives occur.
| table firstTime, lastTime, dest, user, parent_process_name, process
```

### Registry Run Key for Persistence
---
```sql
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  FROM datamodel=Endpoint.Registry
  WHERE
    -- Filter for common registry run keys for persistence. This covers HKLM, HKCU, Run, RunOnce, etc.
    (Registry.registry_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*")
    AND
    -- Look for values pointing to executables in suspicious locations, as seen in the reference.
    (
      (Registry.registry_value_data="*%PUBLIC%*" OR Registry.registry_value_data="*\\Users\\Public\\*") OR
      (Registry.registry_value_data="*%APPDATA%*" OR Registry.registry_value_data="*\\AppData\\Roaming\\*") OR
      (Registry.registry_value_data="*%TEMP%*" OR Registry.registry_value_data="*\\AppData\\Local\\Temp\\*" OR Registry.registry_value_data="*\\Windows\\Temp\\*") OR
      (Registry.registry_value_data="*C:\\ProgramData\\*")
    )
    AND
    -- Ensure the value is pointing to a potentially executable file type.
    (Registry.registry_value_data IN ("*.exe*", "*.dll*", "*.bat*", "*.vbs*", "*.ps1*", "*.scr*"))
  by Registry.dest, Registry.user, Registry.process_name, Registry.registry_path, Registry.registry_value_name, Registry.registry_value_data
| `drop_dm_object_name("Registry")`
-- Convert timestamps to human-readable format.
| convert ctime(firstTime) ctime(lastTime)
-- False Positive Note: Legitimate software installers may create run keys for auto-updaters or helper processes. However, they typically install to Program Files. A run key pointing to a user's AppData, Public, or Temp directories is suspicious and warrants investigation.
| table firstTime, lastTime, dest, user, process_name, registry_path, registry_value_name, registry_value_data
```

### Remote Service Creation for Lateral Movement
---
```sql
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  FROM datamodel=Endpoint.Services
  WHERE
    -- Filter for new service installation events.
    Services.action="installed"
    AND
    (
      -- Pattern 1: Service executable is in a suspicious, world-writable, or temp location.
      (Services.service_path IN ("*\\Users\\Public\\*", "*C:\\ProgramData\\*", "*\\AppData\\*", "*\\Windows\\Temp\\*"))
      OR
      -- Pattern 2: Service command line uses a script interpreter with suspicious arguments, like Cobalt Strike's psexec_psh.
      (Services.service_path IN ("*cmd.exe*", "*powershell.exe*") AND Services.service_path IN ("* -encodedcommand *", "* -w hidden *", "* /c *"))
      OR
      -- Pattern 3: Service command line uses rundll32 to execute a DLL from a suspicious path, as seen in the intel.
      (Services.service_path="*rundll32.exe*" AND Services.service_path IN ("*\\Users\\Public\\*", "*C:\\ProgramData\\*", "*\\AppData\\*", "*\\Windows\\Temp\\*"))
      OR
      -- Pattern 4: Service name appears to be randomly generated (short, alphanumeric), a common tactic for tools like PsExec or Cobalt Strike.
      (len(Services.service_name) < 10 AND match(Services.service_name, "^[a-zA-Z0-9]+$"))
    )
  by Services.dest, Services.user, Services.service_name, Services.service_path, Services.service_start_type
| `drop_dm_object_name("Services")`
-- Convert timestamps to human-readable format.
| convert ctime(firstTime) ctime(lastTime)
-- False Positive Note: Legitimate administrative tools like PsExec or some software installers may create services that trigger this rule. To reduce noise, consider creating an allowlist for known legitimate service names, service paths, or administrative users who are authorized to perform such actions.
| table firstTime, lastTime, dest, user, service_name, service_path, service_start_type
```

### Active Directory Reconnaissance
---
```sql
| tstats `summariesonly` values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime
  FROM datamodel=Endpoint.Processes
  WHERE
    (
      -- Pattern 1: nltest used for domain controller or trust discovery.
      (Processes.process_name = "nltest.exe" AND (Processes.process IN ("*/dclist:*", "*/domain_trusts*")))
      OR
      -- Pattern 2: 'net group' used to enumerate members of high-privilege domain groups.
      (Processes.process_name IN ("net.exe", "net1.exe") AND Processes.process LIKE "% group %" AND (Processes.process LIKE "%\"Domain Admins\"%" OR Processes.process LIKE "%\"Enterprise Admins\"%" OR Processes.process LIKE "%\"Schema Admins\"%"))
      OR
      -- Pattern 3: PowerShell used with the Active Directory module for reconnaissance.
      (Processes.process_name = "powershell.exe" AND (Processes.process LIKE "%Get-ADComputer%" OR Processes.process LIKE "%Get-ADUser%" OR Processes.process LIKE "%Get-ADGroup%" OR Processes.process LIKE "%Get-ADDomain%" OR Processes.process LIKE "%Import-Module ActiveDirectory%"))
    )
  by Processes.dest, Processes.user, Processes.parent_process_name
| `drop_dm_object_name("Processes")`
-- Convert timestamps to human-readable format.
| convert ctime(firstTime) ctime(lastTime)
-- False Positive Note: These commands are frequently used by system administrators and helpdesk personnel for legitimate purposes. To reduce noise, correlate these events with other suspicious activity, or filter out known administrative users, scripts, or parent processes (e.g., from monitoring or management tools).
| table firstTime, lastTime, dest, user, parent_process_name, process
```

### Credential Dumping from Veeam
---
```sql
| tstats `summariesonly` values(Processes.process) as process, values(Scriptloads.script_block) as script_block, min(_time) as firstTime, max(_time) as lastTime
  FROM datamodel=Endpoint
  WHERE
    -- Pattern 1: Detects the execution of the specific PowerShell script by name via process monitoring.
    (Processes.process_name="powershell.exe" AND Processes.process="*Veeam-Get-Creds.ps1*")
    OR
    -- Pattern 2: Detects script blocks containing keywords from the Veeam credential dumping script via PowerShell logging (EventCode 4104).
    -- This is more resilient if the script is renamed or obfuscated.
    (
      Scriptloads.script_block="*Veeam\\Veeam Backup and Replication*" AND
      Scriptloads.script_block="*[dbo].[Credentials]*" AND
      Scriptloads.script_block="*SELECT*password*"
    )
  by _time, Processes.dest, Processes.user, Processes.parent_process_name, Scriptloads.dest, Scriptloads.user
| `drop_dm_object_name("Processes")`
| `drop_dm_object_name("Scriptloads")`
-- Coalesce fields from both process and script load data models for a unified view.
| eval dest = coalesce(Processes_dest, Scriptloads_dest),
       user = coalesce(Processes_user, Scriptloads_user),
       details = coalesce(process, script_block)
-- Convert timestamps to human-readable format.
| convert ctime(firstTime) ctime(lastTime)
-- Group again to present unique alerts with combined details.
| stats values(details) as details by firstTime, lastTime, dest, user, parent_process_name
-- False Positive Note: While this script is publicly available for password recovery, its execution in a production environment is highly unusual and should be investigated. Legitimate use by a backup administrator is possible but rare. Correlate with other suspicious activity.
| table firstTime, lastTime, dest, user, parent_process_name, details
```

### Accessing Shared Account Passwords
---
```sql
| tstats `summariesonly` values(Processes.process) as process, min(_time) as firstTime, max(_time) as lastTime
  FROM datamodel=Endpoint.Processes
  WHERE
    -- Look for command lines that reference files with names suggesting they contain credentials.
    Processes.process IN (
      "*passwords.txt*",
      "*password.txt*",
      "*creds.txt*",
      "*credentials.txt*",
      "*passwords.docx*",
      "*credentials.docx*",
      "*passwords.xlsx*",
      "*credentials.xlsx*",
      "*secrets.txt*",
      "*account*password*",
      "*shared*password*",
      "*shared_account_passwords.docx*"
    )
  by Processes.dest, Processes.user, Processes.parent_process_name
| `drop_dm_object_name("Processes")`
-- Convert timestamps to human-readable format.
| convert ctime(firstTime) ctime(lastTime)
-- False Positive Note: This detection may trigger on legitimate access to documents containing the word "password" for non-sensitive reasons. Tune the keywords and file extensions based on your environment. Investigate the user and the context of the file access.
| table firstTime, lastTime, dest, user, parent_process_name, process
```

### NTDS.dit Access Attempt
---
```sql
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  FROM datamodel=Endpoint.Processes
  WHERE
    -- Pattern 1: Detects the use of ntdsutil to create an "Install From Media" backup, a common method to exfiltrate NTDS.dit.
    (Processes.process_name="ntdsutil.exe" AND Processes.process LIKE "% ifm %" AND (Processes.process LIKE "% create %" OR Processes.process LIKE "% cr %"))
    OR
    -- Pattern 2: Detects direct copy attempts of the NTDS.dit file, often from a volume shadow copy.
    (Processes.process_name IN ("copy.exe", "xcopy.exe", "robocopy.exe") AND Processes.process LIKE "%\\NTDS\\ntds.dit")
  by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process
| `drop_dm_object_name("Processes")`
-- Convert timestamps to human-readable format.
| convert ctime(firstTime) ctime(lastTime)
-- False Positive Note: Legitimate backup processes for Domain Controllers may use ntdsutil or copy the NTDS.dit file from a volume shadow copy. Investigate the parent process and user context. Activity not originating from a known backup solution or administrator should be considered suspicious.
| table firstTime, lastTime, dest, user, parent_process_name, process
```