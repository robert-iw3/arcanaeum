### Zero Trust - Total Bust: Analysis of ZTNA Vulnerabilities
---

This report summarizes critical vulnerabilities identified in leading Zero Trust Network Access (ZTNA) solutions from Check Point, Zscaler, and Netskope, highlighting how these flaws can lead to authentication bypasses, privilege escalation, and data exposure. The findings underscore that despite the "never trust, always verify" principle, ZTNA implementations can still harbor significant security weaknesses.

A significant new finding is the continued exploitation of the Netskope "OrgKey" vulnerability (CVE-2024-7401 / NSKPSA-2024-001) by bug bounty hunters, even after Netskope released a fix and advisory in August 2024. This indicates that many organizations have not yet enabled Secure Enrollment, leaving them vulnerable to authentication bypass and user impersonation.

### Actionable Threat Data
---

Monitor for unusual authentication attempts or access from new/unfamiliar devices or locations within ZTNA logs, as these could indicate authentication bypass or token replay attacks.

Implement auditing for DPAPI activity (Event ID 16385 in Microsoft-Windows-Crypto-DPAPI/Debug and Event ID 4693 in Security Log) to detect unauthorized decryption of sensitive data, such as ZTNA configuration files or authentication tokens.

Configure System Access Control Lists (SACLs) on critical registry keys, particularly those related to ZTNA client configurations and authentication tokens (e.g., HKLM\SOFTWARE\Netskope\SecureToken\AuthenticationToken and HKEY_LOCAL_MACHINE\SOFTWARE\Zscaler Inc.\Zscaler\EXTRA), to log and alert on unauthorized read or modification attempts.

Look for suspicious child processes of ZTNA clients (e.g., ZSATray.exe or stAgentUI.exe) or evidence of process injection into these clients, which could indicate attempts at local privilege escalation or configuration theft.

Regularly review ZTNA client logs for indications of posture check bypasses, such as discrepancies in reported device health or compliance status, or attempts to spoof hardware IDs.

### ZTNA Auth Bypass
---
ZTNA Authentication from New Device or Location

author: RW

Detects successful ZTNA authentications from a device or country not seen for a user in the last 14 days.
This could indicate an authentication bypass, such as the Netskope "OrgKey" vulnerability (CVE-2024-7401),
or other account compromise scenarios where an attacker enrolls a new device or logs in from an unusual location.

creationDate 2025-08-11

tags

- attack.initial_access

- attack.t1566

- attack.t1078

splunk:
```sql
`comment("Specify the data source for your ZTNA authentication logs. E.g., (index=netskope OR index=zscaler)")`
`comment("Ensure your data is CIM-compliant or adjust field names (user, dest_device_id, src_ip, action, app) as needed.")`
(index=ztna) action=success app IN ("Netskope Private Access", "Zscaler Private Access", "Zscaler Internet Access")
| iplocation src_ip
`comment("The main search looks for successful authentications in the last hour.")`
| where _time >= relative_time(now(), "-1h")
`comment("A left join compares recent activity against a baseline of known devices and countries for each user over the last 14 days.")`
| join type=left user [
    search (index=ztna) action=success app IN ("Netskope Private Access", "Zscaler Private Access", "Zscaler Internet Access") earliest=-14d@d latest=-1h@h
    | iplocation src_ip
    | stats values(dest_device_id) as known_devices, values(Country) as known_countries by user
]
`comment("Identify if the device or country is new for the user by checking if it exists in the baseline.")`
| eval is_new_device = if(isnull(known_devices) OR isnull(mvfind(known_devices, dest_device_id)), "true", "false")
| eval is_new_country = if(isnotnull(Country) AND (isnull(known_countries) OR isnull(mvfind(known_countries, Country))), "true", "false")
`comment("Filter for events where either the device or the country is new.")`
| where is_new_device="true" OR is_new_country="true"
`comment("Potential False Positives: A user might legitimately use a new device or travel for work. To reduce FPs, consider excluding specific user groups (e.g., frequent travelers, IT admins) or increasing the lookback period (e.g., to -30d@d) to build a more robust baseline.")`
| stats
    min(_time) as start_time,
    max(_time) as end_time,
    values(src_ip) as src_ips,
    values(eval(if(is_new_device="true", dest_device_id, null))) as new_devices,
    values(eval(if(is_new_country="true", Country, null))) as new_countries,
    values(known_devices) as known_devices_baseline,
    values(known_countries) as known_countries_baseline
    by user
| `comment("Final fields for the alert.")`
| rename user as User, src_ips as SourceIPs, new_devices as NewDevices, new_countries as NewCountries, known_devices_baseline as KnownDevices, known_countries_baseline as KnownCountries
| fields start_time, end_time, User, NewDevices, NewCountries, SourceIPs, KnownDevices, KnownCountries
```

crowdstrike fql:
```sql
event_type="ZTNA_Authentication"
| action="success" app IN ("Netskope Private Access", "Zscaler Private Access", "Zscaler Internet Access")
| timestamp >= NOW() - 1h
| geoip(src_ip, "country")
| join type=left user_name (
    event_type="ZTNA_Authentication" action="success" app IN ("Netskope Private Access", "Zscaler Private Access", "Zscaler Internet Access")
    | timestamp >= NOW() - 14d AND timestamp < NOW() - 1h
    | geoip(src_ip, "country")
    | group by user_name
    | aggregate known_devices=VALUES(dest_device_id), known_countries=VALUES(geoip_country)
)
| is_new_device=IF(dest_device_id NOT IN known_devices OR known_devices IS NULL, "true", "false")
| is_new_country=IF(geoip_country IS NOT NULL AND (geoip_country NOT IN known_countries OR known_countries IS NULL), "true", "false")
| is_new_device="true" OR is_new_country="true"
| group by user_name
| aggregate start_time=MIN(timestamp), end_time=MAX(timestamp), SourceIPs=VALUES(src_ip),
           NewDevices=VALUES(IF(is_new_device="true", dest_device_id, NULL)),
           NewCountries=VALUES(IF(is_new_country="true", geoip_country, NULL)),
           KnownDevices=VALUES(known_devices), KnownCountries=VALUES(known_countries)
| rename user_name as User
```

datadog:
```sql
source:ztna action:success app:("Netskope Private Access" OR "Zscaler Private Access" OR "Zscaler Internet Access")
@timestamp:>=now-1h
| eval geo_country = geoip(src_ip, "country")
| join type=left user (
    source:ztna action:success app:("Netskope Private Access" OR "Zscaler Private Access" OR "Zscaler Internet Access")
    @timestamp:[now-14d TO now-1h]
    | eval geo_country = geoip(src_ip, "country")
    | stats values(dest_device_id) as known_devices, values(geo_country) as known_countries by user
)
| eval is_new_device = if(dest_device_id !in known_devices OR known_devices IS NULL, "true", "false"),
       is_new_country = if(geo_country IS NOT NULL AND (geo_country !in known_countries OR known_countries IS NULL), "true", "false")
| where is_new_device = "true" OR is_new_country = "true"
| stats min(@timestamp) as start_time, max(@timestamp) as end_time,
        values(src_ip) as SourceIPs,
        values(if(is_new_device="true", dest_device_id, NULL)) as NewDevices,
        values(if(is_new_country="true", geo_country, NULL)) as NewCountries,
        values(known_devices) as KnownDevices, values(known_countries) as KnownCountries
        by user
| rename user as User
```

elastic:
```sql
FROM logs-ztna*
| WHERE event.outcome == "success"
  AND network.application IN ("Netskope Private Access", "Zscaler Private Access", "Zscaler Internet Access")
  AND @timestamp >= NOW() - 1 HOUR
| EVAL geo_country = GEOIP(source.ip, "country")
| JOIN type=LEFT user.name [
    FROM logs-ztna*
    | WHERE event.outcome == "success"
      AND network.application IN ("Netskope Private Access", "Zscaler Private Access", "Zscaler Internet Access")
      AND @timestamp >= NOW() - 14 DAYS AND @timestamp < NOW() - 1 HOUR
    | EVAL geo_country = GEOIP(source.ip, "country")
    | STATS known_devices = MV_DEDUP(device.id), known_countries = MV_DEDUP(geo_country) BY user.name
]
| EVAL is_new_device = CASE(device.id NOT IN known_devices OR known_devices IS NULL, "true", "false"),
      is_new_country = CASE(geo_country IS NOT NULL AND (geo_country NOT IN known_countries OR known_countries IS NULL), "true", "false")
| WHERE is_new_device == "true" OR is_new_country == "true"
| STATS start_time = MIN(@timestamp),
        end_time = MAX(@timestamp),
        SourceIPs = MV_DEDUP(source.ip),
        NewDevices = MV_DEDUP(CASE(is_new_device == "true", device.id, NULL)),
        NewCountries = MV_DEDUP(CASE(is_new_country == "true", geo_country, NULL)),
        KnownDevices = MV_DEDUP(known_devices),
        KnownCountries = MV_DEDUP(known_countries)
  BY user.name
| RENAME user.name AS User
```

sentinel one:
```sql
event.type = "ZTNA_Authentication"
AND event.outcome = "success"
AND application IN ("Netskope Private Access", "Zscaler Private Access", "Zscaler Internet Access")
AND event.timestamp >= NOW() - 1h
| EVAL geo_country = GEOIP(network.source.ip, "country")
| JOIN type=LEFT user.name (
    event.type = "ZTNA_Authentication"
    AND event.outcome = "success"
    AND application IN ("Netskope Private Access", "Zscaler Private Access", "Zscaler Internet Access")
    AND event.timestamp >= NOW() - 14d AND event.timestamp < NOW() - 1h
    | EVAL geo_country = GEOIP(network.source.ip, "country")
    | GROUP BY user.name
    | SELECT VALUES(device.id) AS known_devices, VALUES(geo_country) AS known_countries
)
| EVAL is_new_device = IF(device.id NOT IN known_devices OR known_devices IS NULL, "true", "false"),
      is_new_country = IF(geo_country IS NOT NULL AND (geo_country NOT IN known_countries OR known_countries IS NULL), "true", "false")
| WHERE is_new_device = "true" OR is_new_country = "true"
| GROUP BY user.name
| SELECT MIN(event.timestamp) AS start_time,
         MAX(event.timestamp) AS end_time,
         VALUES(network.source.ip) AS SourceIPs,
         VALUES(IF(is_new_device = "true", device.id, NULL)) AS NewDevices,
         VALUES(IF(is_new_country = "true", geo_country, NULL)) AS NewCountries,
         VALUES(known_devices) AS KnownDevices,
         VALUES(known_countries) AS KnownCountries,
         user.name AS User
```

### ZTNA Config Theft
---
ZTNA Configuration or Token Theft via Unauthorized Process Access

author: RW

description:

Detects when a non-standard process accesses sensitive ZTNA configuration files or registry keys.
This could indicate an attacker attempting to steal credentials, tokens, or configuration data for
replay attacks, as described in the "Zero Trust - Total Bust" research. This detection requires that
System Access Control Lists (SACLs) are enabled for the specified objects to generate Security Event ID 4663.

creationDate 2025-08-11

tags

- attack.credential_access

- attack.t1552.001

- attack.t1552.002

splunk:
```sql
`comment("This detection requires the 'Microsoft-Windows-Crypto-DPAPI/Debug' log to be enabled via Group Policy or other means to log EventCode 16385.")`
`comment("Specify the index for your Windows event logs.")`
(index=wineventlog)
`comment("Search for DPAPI unprotect events or master key backup events.")`
(source="WinEventLog:Microsoft-Windows-Crypto-DPAPI/Debug" EventCode=16385) OR (source="WinEventLog:Security" EventCode=4693)
| `comment("Normalize fields across the two different event types for easier processing.")`
| eval EventType = case(EventCode=16385, "DPAPI Unprotect", EventCode=4693, "DPAPI Master Key Backup"),
       ProcessInfo = coalesce(ProcessName, "PID: ".CallerProcessID),
       Description = coalesce(DataDescription, "DPAPI Master Key Backup"),
       User = coalesce(SubjectUserName, SecurityUserID)
| `comment("Extract the process file name from the full path if available.")`
| eval ProcessFileName = if(isnotnull(ProcessName), replace(ProcessName, "^.*\\\\", ""), null)
| `comment("Define keywords to identify ZTNA-related data being decrypted. Customize this list for your environment.")`
| eval ztna_keywords = "zscaler,netskope,client configuration"
| eval ztna_keywords_list = split(ztna_keywords, ",")
| `comment("Define the list of legitimate processes expected to access ZTNA artifacts. Customize this list.")`
| eval ztna_processes = "ZSATray.exe,stAgentUI.exe,Netskope Client.exe,Zscaler.exe,svchost.exe"
| eval ztna_processes_list = split(ztna_processes, ",")
| `comment("Filter for high-fidelity master key backups or decryption of ZTNA-related data.")`
| where EventCode=4693 OR (EventCode=16385 AND (mvfilter(match(lower(Description), "(?i)".ztna_keywords_list))))
| `comment("Filter out known-good processes for master key backup events. For DPAPI unprotect events (16385), the process name is not in the event, so the PID in 'ProcessInfo' must be investigated manually.")`
| where EventCode=16385 OR (EventCode=4693 AND NOT (mvfilter(match(ProcessFileName, "(?i)".ztna_processes_list))))
`comment("Potential False Positives: Legitimate backup software or administrative scripts might trigger this alert. Add any known-good processes to the 'ztna_processes' list to reduce noise.")`
| stats
    min(_time) as start_time,
    max(_time) as end_time,
    values(EventType) as EventTypes,
    values(Description) as Descriptions,
    values(ProcessInfo) as Processes
    by host, User
| convert ctime(start_time), ctime(end_time)
| rename host as dvc
| fields start_time, end_time, dvc, User, EventTypes, Descriptions, Processes
```

crowdstrike fql:
```sql
event_type IN ("DPAPIUnprotect", "DPAPIMasterKeyBackup")
| (
    (event_type="DPAPIUnprotect" AND event_code="16385")
    OR (event_type="DPAPIMasterKeyBackup" AND event_code="4693")
)
| EventType=CASE(event_code="16385", "DPAPI Unprotect", event_code="4693", "DPAPI Master Key Backup")
| ProcessInfo=COALESCE(process_name, "PID: " + caller_process_id)
| Description=COALESCE(data_description, "DPAPI Master Key Backup")
| User=COALESCE(subject_user_name, security_user_id)
| ProcessFileName=IF(process_name IS NOT NULL, REGEX_REPLACE(process_name, "^.*\\\\", ""), NULL)
| ztna_keywords_list=SPLIT("zscaler,netskope,client configuration", ",")
| ztna_processes_list=SPLIT("ZSATray.exe,stAgentUI.exe,Netskope Client.exe,Zscaler.exe,svchost.exe", ",")
| (
    event_code="4693"
    OR (event_code="16385" AND ANY(LOWER(Description) LIKE "%" + ztna_keywords_list + "%"))
)
| event_code="16385" OR (event_code="4693" AND NOT ANY(ProcessFileName LIKE "%" + ztna_processes_list + "%"))
| group by hostname, User
| aggregate start_time=MIN(timestamp), end_time=MAX(timestamp),
           EventTypes=VALUES(EventType), Descriptions=VALUES(Description), Processes=VALUES(ProcessInfo)
| format_time(start_time), format_time(end_time)
| rename hostname as dvc
```

datadog:
```sql
source:(wineventlog_dpapi OR wineventlog_security)
(event_code:16385 OR event_code:4693)
| eval EventType = case(event_code == 16385, "DPAPI Unprotect", event_code == 4693, "DPAPI Master Key Backup"),
       ProcessInfo = coalesce(ProcessName, concat("PID: ", CallerProcessID)),
       Description = coalesce(DataDescription, "DPAPI Master Key Backup"),
       User = coalesce(SubjectUserName, SecurityUserID),
       ProcessFileName = if(ProcessName != null, replace(ProcessName, "^.*\\\\", ""), null),
       ztna_keywords_list = split("zscaler,netskope,client configuration", ","),
       ztna_processes_list = split("ZSATray.exe,stAgentUI.exe,Netskope Client.exe,Zscaler.exe,svchost.exe", ",")
| where event_code = 4693 OR (
    event_code = 16385 AND any(lower(Description) LIKE concat("%", ztna_keywords_list, "%"))
)
| where event_code = 16385 OR (
    event_code = 4693 AND NOT any(ProcessFileName LIKE concat("%", ztna_processes_list, "%"))
)
| stats min(@timestamp) as start_time, max(@timestamp) as end_time,
        values(EventType) as EventTypes, values(Description) as Descriptions, values(ProcessInfo) as Processes
        by host, User
| eval start_time = strftime(start_time, "%Y-%m-%d %H:%M:%S"), end_time = strftime(end_time, "%Y-%m-%d %H:%M:%S")
| rename host as dvc
```

elastic:
```sql
FROM logs-windows*
| WHERE (event.code == "16385" AND event.provider == "Microsoft-Windows-Crypto-DPAPI/Debug")
  OR (event.code == "4693" AND event.provider == "Microsoft-Windows-Security-Auditing")
| EVAL EventType = CASE(event.code == "16385", "DPAPI Unprotect", event.code == "4693", "DPAPI Master Key Backup"),
      ProcessInfo = COALESCE(process.name, CONCAT("PID: ", process.pid)),
      Description = COALESCE(event.description, "DPAPI Master Key Backup"),
      User = COALESCE(user.name, user.id),
      ProcessFileName = CASE(process.name IS NOT NULL, REGEXP_REPLACE(process.name, "^.*\\\\", ""), NULL),
      ztna_keywords_list = SPLIT("zscaler,netskope,client configuration", ","),
      ztna_processes_list = SPLIT("ZSATray.exe,stAgentUI.exe,Netskope Client.exe,Zscaler.exe,svchost.exe", ",")
| WHERE event.code == "4693"
  OR (event.code == "16385" AND ANY(LOWER(Description) LIKE ("%" + ztna_keywords_list + "%")))
| WHERE event.code == "16385"
  OR (event.code == "4693" AND NOT ANY(ProcessFileName LIKE ("%" + ztna_processes_list + "%")))
| STATS start_time = MIN(@timestamp),
        end_time = MAX(@timestamp),
        EventTypes = MV_DEDUP(EventType),
        Descriptions = MV_DEDUP(Description),
        Processes = MV_DEDUP(ProcessInfo)
  BY host.hostname, User
| EVAL start_time = TO_STRING(start_time, "yyyy-MM-dd HH:mm:ss"),
      end_time = TO_STRING(end_time, "yyyy-MM-dd HH:mm:ss")
| RENAME host.hostname AS dvc
```

sentinel one:
```sql
event.type IN ("DPAPIUnprotect", "DPAPIMasterKeyBackup")
AND (
  (event.code = "16385" AND event.source = "Microsoft-Windows-Crypto-DPAPI/Debug")
  OR (event.code = "4693" AND event.source = "Security")
)
| EVAL EventType = CASE(event.code = "16385", "DPAPI Unprotect", event.code = "4693", "DPAPI Master Key Backup"),
      ProcessInfo = COALESCE(process.name, CONCAT("PID: ", process.pid)),
      Description = COALESCE(event.description, "DPAPI Master Key Backup"),
      User = COALESCE(user.name, user.id),
      ProcessFileName = IF(process.name IS NOT NULL, REGEX_REPLACE(process.name, "^.*\\\\", ""), NULL),
      ztna_keywords_list = SPLIT("zscaler,netskope,client configuration", ","),
      ztna_processes_list = SPLIT("ZSATray.exe,stAgentUI.exe,Netskope Client.exe,Zscaler.exe,svchost.exe", ",")
| WHERE event.code = "4693"
  OR (event.code = "16385" AND ANY(LOWER(Description) LIKE "%" + ztna_keywords_list + "%"))
| WHERE event.code = "16385"
  OR (event.code = "4693" AND NOT ANY(ProcessFileName LIKE "%" + ztna_processes_list + "%"))
| GROUP BY agent.hostname, User
| SELECT MIN(event.timestamp) AS start_time,
         MAX(event.timestamp) AS end_time,
         VALUES(EventType) AS EventTypes,
         VALUES(Description) AS Descriptions,
         VALUES(ProcessInfo) AS Processes,
         agent.hostname AS dvc
| EVAL start_time = FORMAT_TIME(start_time, "YYYY-MM-DD HH:mm:ss"),
      end_time = FORMAT_TIME(end_time, "YYYY-MM-DD HH:mm:ss")
```

### ZTNA Client Process Injection
---
Suspicious Child Process of ZTNA Client

author: RW

description:

Detects when a Zero Trust Network Access (ZTNA) client process spawns a suspicious child process,
such as a command-line interpreter or a common reconnaissance tool. This activity could indicate
that an attacker has compromised the ZTNA client, potentially through process injection, to
perform local privilege escalation or configuration theft.

creationDate 2025-08-11

tags

- attack.privilege_escalation

- attack.execution

- attack.t1059.001

- attack.t1059.003

splunk:
```sql
`comment("This search requires process creation event logs, typically from Sysmon (EventCode=1) or other EDR sources, mapped to the CIM.")`
`comment("Ensure your data is CIM-compliant or adjust field names (ParentProcessName, ProcessName, CommandLine, ParentCommandLine) as needed.")`
(index=main sourcetype=sysmon) EventCode=1
`comment("Define the list of ZTNA parent processes to monitor. Customize for your environment.")`
| where ParentProcessName IN (
    "ZSATray.exe",
    "stAgentUI.exe",
    "Netskope Client.exe",
    "Zscaler.exe",
    "ZSATunnel.exe"
)
`comment("Define a list of suspicious child processes often used for reconnaissance or execution.")`
| where ProcessName IN (
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "whoami.exe",
    "net.exe",
    "net1.exe",
    "systeminfo.exe",
    "quser.exe",
    "qwinsta.exe",
    "reg.exe",
    "sc.exe",
    "tasklist.exe"
)
`comment("Potential False Positives: Some ZTNA clients may have legitimate diagnostic functions that spawn command shells. These should be baselined and excluded if they generate noise. For example: | where NOT (like(ParentCommandLine, \"%diagnostics%\") AND ProcessName=\"cmd.exe\")")`
| stats
    min(_time) as start_time,
    max(_time) as end_time,
    values(CommandLine) as child_process_command_line,
    values(ParentCommandLine) as parent_process_command_line
    by host, user, ParentProcessName, ProcessName
| `comment("Convert timestamps to a readable format.")`
| convert ctime(start_time), ctime(end_time)
| `comment("Rename fields for clarity in the final alert.")`
| rename
    host as dvc,
    user as User,
    ParentProcessName as ParentProcess,
    ProcessName as ChildProcess,
    child_process_command_line as ChildProcessCommandLine,
    parent_process_command_line as ParentProcessCommandLine
| fields start_time, end_time, dvc, User, ParentProcess, ParentProcessCommandLine, ChildProcess, ChildProcessCommandLine
```

crowdstrike fql:
```sql
event_type="ProcessCreation" event_code="1"
| parent_process_name IN ("ZSATray.exe", "stAgentUI.exe", "Netskope Client.exe", "Zscaler.exe", "ZSATunnel.exe")
| process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "whoami.exe", "net.exe", "net1.exe", "systeminfo.exe", "quser.exe", "qwinsta.exe", "reg.exe", "sc.exe", "tasklist.exe")
| group by hostname, user_name, parent_process_name, process_name
| aggregate start_time=MIN(timestamp), end_time=MAX(timestamp),
           ChildProcessCommandLine=VALUES(cmd_line), ParentProcessCommandLine=VALUES(parent_cmd_line)
| format_time(start_time), format_time(end_time)
| rename hostname as dvc, user_name as User, parent_process_name as ParentProcess, process_name as ChildProcess
```

datadog:
```sql
source:sysmon event_code:1
parent_process_name:("ZSATray.exe" OR "stAgentUI.exe" OR "Netskope Client.exe" OR "Zscaler.exe" OR "ZSATunnel.exe")
process_name:("cmd.exe" OR "powershell.exe" OR "pwsh.exe" OR "wscript.exe" OR "cscript.exe" OR "rundll32.exe" OR "whoami.exe" OR "net.exe" OR "net1.exe" OR "systeminfo.exe" OR "quser.exe" OR "qwinsta.exe" OR "reg.exe" OR "sc.exe" OR "tasklist.exe")
| stats min(@timestamp) as start_time, max(@timestamp) as end_time,
        values(process_command_line) as ChildProcessCommandLine,
        values(parent_process_command_line) as ParentProcessCommandLine
        by host, user, parent_process_name, process_name
| eval start_time = strftime(start_time, "%Y-%m-%d %H:%M:%S"), end_time = strftime(end_time, "%Y-%m-%d %H:%M:%S")
| rename host as dvc, user as User, parent_process_name as ParentProcess, process_name as ChildProcess
```

elastic:
```sql
FROM logs-windows.sysmon*
| WHERE event.code == "1"
  AND process.parent.name IN ("ZSATray.exe", "stAgentUI.exe", "Netskope Client.exe", "Zscaler.exe", "ZSATunnel.exe")
  AND process.name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "whoami.exe", "net.exe", "net1.exe", "systeminfo.exe", "quser.exe", "qwinsta.exe", "reg.exe", "sc.exe", "tasklist.exe")
| STATS start_time = MIN(@timestamp),
        end_time = MAX(@timestamp),
        ChildProcessCommandLine = MV_DEDUP(process.command_line),
        ParentProcessCommandLine = MV_DEDUP(process.parent.command_line)
  BY host.hostname, user.name, process.parent.name, process.name
| EVAL start_time = TO_STRING(start_time, "yyyy-MM-dd HH:mm:ss"),
      end_time = TO_STRING(end_time, "yyyy-MM-dd HH:mm:ss")
| RENAME host.hostname AS dvc,
         user.name AS User,
         process.parent.name AS ParentProcess,
         process.name AS ChildProcess
```

sentinel one:
```sql
event.type = "ProcessCreation" AND event.code = "1"
AND process.parent.name IN ("ZSATray.exe", "stAgentUI.exe", "Netskope Client.exe", "Zscaler.exe", "ZSATunnel.exe")
AND process.name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "whoami.exe", "net.exe", "net1.exe", "systeminfo.exe", "quser.exe", "qwinsta.exe", "reg.exe", "sc.exe", "tasklist.exe")
| GROUP BY agent.hostname, user.name, process.parent.name, process.name
| SELECT MIN(event.timestamp) AS start_time,
         MAX(event.timestamp) AS end_time,
         VALUES(process.command_line) AS ChildProcessCommandLine,
         VALUES(process.parent.command_line) AS ParentProcessCommandLine,
         agent.hostname AS dvc,
         user.name AS User,
         process.parent.name AS ParentProcess,
         process.name AS ChildProcess
| EVAL start_time = FORMAT_TIME(start_time, "YYYY-MM-DD HH:mm:ss"),
      end_time = FORMAT_TIME(end_time, "YYYY-MM-DD HH:mm:ss")
```

### ZTNA Posture Check Bypass
---
ZTNA Posture Check Status Change from Non-Compliant to Compliant

author: RW

description:

Detects when a device's ZTNA posture check status rapidly changes from non-compliant to compliant.
This could indicate a posture check bypass, potentially through client-side manipulation like API
hooking or hardware ID spoofing, allowing a non-compliant device to gain access.

creationDate 2025-08-11

tags

- attack.defense_evasion

- attack.t1562.001

splunk:
```sql
`comment("Specify the data source for your ZTNA posture check logs. E.g., (index=zscaler OR index=netskope)")`
`comment("Ensure your data is CIM-compliant or adjust field names (dvc, user, compliance_status, reason) as needed.")`
(index=ztna) compliance_status IN ("Compliant", "Non-Compliant")
| `comment("Sort events by device and time to process them chronologically for each device.")`
| sort 0 dvc, _time
| `comment("Use streamstats to get the status and time of the previous event for each device.")`
| streamstats window=1 current=f last(compliance_status) as prev_status last(_time) as prev_time last(reason) as prev_reason by dvc
| `comment("Look for the specific transition from Non-Compliant to Compliant.")`
| where prev_status="Non-Compliant" AND compliance_status="Compliant"
| `comment("Calculate the time difference in seconds.")`
| eval time_delta = _time - prev_time
| `comment("Alert only if the change happened within the 5-minute (300 seconds) rapid change threshold.")`
| where time_delta < 300
| `comment("Potential False Positives: Very fast, automated remediation actions could trigger this alert. Consider increasing the threshold (e.g., to 600 for 10 minutes) or excluding specific remediation reasons if available.")`
| `comment("Format timestamps to be human-readable.")`
| convert ctime(prev_time) as StartTime, ctime(_time) as EndTime
| `comment("Rename fields for the final alert output.")`
| rename
    dvc as DeviceName,
    user as UserPrincipalName,
    time_delta as TimeDelta,
    prev_status as PreviousStatus,
    prev_reason as PreviousReasonForNonCompliance,
    compliance_status as CurrentStatus
| `comment("Select the fields for the final table.")`
| table StartTime, EndTime, DeviceName, UserPrincipalName, TimeDelta, PreviousStatus, PreviousReasonForNonCompliance, CurrentStatus
```

crowdstrike fql:
```sql
event_type="ZTNA_PostureCheck"
| compliance_status IN ("Compliant", "Non-Compliant")
| sort hostname, timestamp
| streamstats window=1 current=false prev_status=LAST(compliance_status), prev_time=LAST(timestamp), prev_reason=LAST(reason) by hostname
| prev_status="Non-Compliant" AND compliance_status="Compliant"
| time_delta=timestamp - prev_time
| time_delta < 300
| format_time(prev_time, "StartTime"), format_time(timestamp, "EndTime")
| rename hostname as DeviceName, user_name as UserPrincipalName, time_delta as TimeDelta, prev_status as PreviousStatus, prev_reason as PreviousReasonForNonCompliance, compliance_status as CurrentStatus
| project StartTime, EndTime, DeviceName, UserPrincipalName, TimeDelta, PreviousStatus, PreviousReasonForNonCompliance, CurrentStatus
```

datadog:
```sql
source:ztna compliance_status:("Compliant" OR "Non-Compliant")
| sort host, @timestamp
| streamstats window=1 current=false last(compliance_status) as prev_status, last(@timestamp) as prev_time, last(reason) as prev_reason by host
| where prev_status = "Non-Compliant" AND compliance_status = "Compliant"
| eval time_delta = @timestamp - prev_time
| where time_delta < 300
| eval StartTime = strftime(prev_time, "%Y-%m-%d %H:%M:%S"), EndTime = strftime(@timestamp, "%Y-%m-%d %H:%M:%S")
| rename host as DeviceName, user as UserPrincipalName, time_delta as TimeDelta, prev_status as PreviousStatus, prev_reason as PreviousReasonForNonCompliance, compliance_status as CurrentStatus
| select StartTime, EndTime, DeviceName, UserPrincipalName, TimeDelta, PreviousStatus, PreviousReasonForNonCompliance, CurrentStatus
```

elastic:
```sql
FROM logs-ztna*
| WHERE device.compliance_status IN ("Compliant", "Non-Compliant")
| SORT host.hostname, @timestamp
| EVAL prev_status = LAG(device.compliance_status, 1) OVER (PARTITION BY host.hostname),
      prev_time = LAG(@timestamp, 1) OVER (PARTITION BY host.hostname),
      prev_reason = LAG(event.reason, 1) OVER (PARTITION BY host.hostname)
| WHERE prev_status == "Non-Compliant" AND device.compliance_status == "Compliant"
| EVAL time_delta = (@timestamp - prev_time) / 1000
| WHERE time_delta < 300
| EVAL StartTime = TO_STRING(prev_time, "yyyy-MM-dd HH:mm:ss"),
      EndTime = TO_STRING(@timestamp, "yyyy-MM-dd HH:mm:ss")
| RENAME host.hostname AS DeviceName,
         user.name AS UserPrincipalName,
         time_delta AS TimeDelta,
         prev_status AS PreviousStatus,
         prev_reason AS PreviousReasonForNonCompliance,
         device.compliance_status AS CurrentStatus
| KEEP StartTime, EndTime, DeviceName, UserPrincipalName, TimeDelta, PreviousStatus, PreviousReasonForNonCompliance, CurrentStatus
```

sentinel one:
```sql
event.type = "ZTNA_PostureCheck"
AND device.compliance_status IN ("Compliant", "Non-Compliant")
| SORT agent.hostname, event.timestamp
| EVAL prev_status = LAG(device.compliance_status, 1) OVER (PARTITION BY agent.hostname),
      prev_time = LAG(event.timestamp, 1) OVER (PARTITION BY agent.hostname),
      prev_reason = LAG(event.reason, 1) OVER (PARTITION BY agent.hostname)
| WHERE prev_status = "Non-Compliant" AND device.compliance_status = "Compliant"
| EVAL time_delta = (event.timestamp - prev_time) / 1000
| WHERE time_delta < 300
| EVAL StartTime = FORMAT_TIME(prev_time, "YYYY-MM-DD HH:mm:ss"),
      EndTime = FORMAT_TIME(event.timestamp, "YYYY-MM-DD HH:mm:ss")
| SELECT StartTime, EndTime,
         agent.hostname AS DeviceName,
         user.name AS UserPrincipalName,
         time_delta AS TimeDelta,
         prev_status AS PreviousStatus,
         prev_reason AS PreviousReasonForNonCompliance,
         device.compliance_status AS CurrentStatus
```

### ZTNA Registry Key Access
---
ZTNA Configuration or Token Theft via Unauthorized Process Access

author: RW

description:

Detects when a non-standard process accesses sensitive ZTNA configuration files or registry keys.
This could indicate an attacker attempting to steal credentials, tokens, or configuration data for
replay attacks, as described in the "Zero Trust - Total Bust" research. This detection requires that
System Access Control Lists (SACLs) are enabled for the specified objects to generate Security Event ID 4663.

creationDate 2025-08-11

tags

- attack.credential_access

- attack.t1552.002

splunk:
```sql
`comment("This detection requires Windows Security Event ID 4663, which is generated when SACLs are configured on the target registry keys.")`
(index=wineventlog sourcetype=WinEventLog:Security) EventCode=4663 ObjectType=Key
`comment("Filter for access to sensitive ZTNA registry keys. Customize these paths for your environment.")`
| where (
    ObjectName LIKE "%\\REGISTRY\\MACHINE\\SOFTWARE\\Netskope\\SecureToken%" OR
    ObjectName LIKE "%\\REGISTRY\\MACHINE\\SOFTWARE\\Zscaler Inc.\\Zscaler\\EXTRA%"
)
`comment("Extract the process file name from the full path.")`
| eval process_name=mvindex(split(ProcessName,"\\"),-1)
`comment("Filter out known legitimate processes. Add any other legitimate software (e.g., backup, security scanners) to this list to reduce false positives.")`
| where NOT process_name IN (
    "ZSATray.exe",
    "stAgentUI.exe",
    "Netskope Client.exe",
    "Zscaler.exe",
    "svchost.exe"
)
`comment("Group events to create a single alert per host, user, and process.")`
| stats
    min(_time) as start_time,
    max(_time) as end_time,
    values(ObjectName) as accessed_keys,
    values(AccessMask) as access_masks,
    count by host, user, Sid, process_name
| `comment("Convert timestamps to a readable format.")`
| convert ctime(start_time), ctime(end_time)
| `comment("Rename fields for clarity in the final alert.")`
| rename
    host as dvc,
    user as User,
    Sid as UserSid,
    process_name as ProcessName,
    accessed_keys as AccessedRegistryKeys,
    access_masks as AccessMasks
| fields start_time, end_time, dvc, User, UserSid, ProcessName, AccessedRegistryKeys, AccessMasks, count
```

crowdstrike fql:
```sql
event_type="RegistryAccess" event_code="4663" object_type="Key"
| object_name LIKE "%\\REGISTRY\\MACHINE\\SOFTWARE\\Netskope\\SecureToken%" OR object_name LIKE "%\\REGISTRY\\MACHINE\\SOFTWARE\\Zscaler Inc.\\Zscaler\\EXTRA%"
| process_name=REGEX_REPLACE(process_name, "^.*\\\\", "")
| NOT process_name IN ("ZSATray.exe", "stAgentUI.exe", "Netskope Client.exe", "Zscaler.exe", "svchost.exe")
| group by hostname, user_name, user_sid, process_name
| aggregate start_time=MIN(timestamp), end_time=MAX(timestamp), AccessedRegistryKeys=VALUES(object_name), AccessMasks=VALUES(access_mask), count=COUNT()
| format_time(start_time), format_time(end_time)
| rename hostname as dvc, user_name as User, user_sid as UserSid, process_name as ProcessName
```

datadog:
```sql
source:wineventlog_security event_code:4663 object_type:Key
(object_name:*\\REGISTRY\\MACHINE\\SOFTWARE\\Netskope\\SecureToken* OR object_name:*\\REGISTRY\\MACHINE\\SOFTWARE\\Zscaler Inc.\\Zscaler\\EXTRA*)
| eval process_name = mvindex(split(ProcessName, "\\"), -1)
| where NOT process_name IN ("ZSATray.exe", "stAgentUI.exe", "Netskope Client.exe", "Zscaler.exe", "svchost.exe")
| stats min(@timestamp) as start_time, max(@timestamp) as end_time,
        values(object_name) as AccessedRegistryKeys, values(access_mask) as AccessMasks, count
        by host, user, user_sid, process_name
| eval start_time = strftime(start_time, "%Y-%m-%d %H:%M:%S"), end_time = strftime(end_time, "%Y-%m-%d %H:%M:%S")
| rename host as dvc, user as User, user_sid as UserSid, process_name as ProcessName
```

elastic:
```sql
FROM logs-windows.security*
| WHERE event.code == "4663" AND registry.hive == "HKEY_LOCAL_MACHINE"
  AND (registry.path LIKE "*\\SOFTWARE\\Netskope\\SecureToken*" OR registry.path LIKE "*\\SOFTWARE\\Zscaler Inc.\\Zscaler\\EXTRA*")
| EVAL process_name = REGEXP_REPLACE(process.name, "^.*\\\\", "")
| WHERE NOT process_name IN ("ZSATray.exe", "stAgentUI.exe", "Netskope Client.exe", "Zscaler.exe", "svchost.exe")
| STATS start_time = MIN(@timestamp),
        end_time = MAX(@timestamp),
        AccessedRegistryKeys = MV_DEDUP(registry.path),
        AccessMasks = MV_DEDUP(registry.access),
        count = COUNT()
  BY host.hostname, user.name, user.id, process_name
| EVAL start_time = TO_STRING(start_time, "yyyy-MM-dd HH:mm:ss"),
      end_time = TO_STRING(end_time, "yyyy-MM-dd HH:mm:ss")
| RENAME host.hostname AS dvc,
         user.name AS User,
         user.id AS UserSid,
         process_name AS ProcessName
```

sentinel one:
```sql
event.type = "RegistryAccess" AND event.code = "4663" AND registry.hive = "HKEY_LOCAL_MACHINE"
AND (registry.path LIKE "%\\SOFTWARE\\Netskope\\SecureToken%" OR registry.path LIKE "%\\SOFTWARE\\Zscaler Inc.\\Zscaler\\EXTRA%")
| EVAL process_name = REGEX_REPLACE(process.name, "^.*\\\\", "")
| WHERE NOT process_name IN ("ZSATray.exe", "stAgentUI.exe", "Netskope Client.exe", "Zscaler.exe", "svchost.exe")
| GROUP BY agent.hostname, user.name, user.id, process_name
| SELECT MIN(event.timestamp) AS start_time,
         MAX(event.timestamp) AS end_time,
         VALUES(registry.path) AS AccessedRegistryKeys,
         VALUES(registry.access) AS AccessMasks,
         COUNT() AS count,
         agent.hostname AS dvc,
         user.name AS User,
         user.id AS UserSid,
         process_name AS ProcessName
| EVAL start_time = FORMAT_TIME(start_time, "YYYY-MM-DD HH:mm:ss"),
      end_time = FORMAT_TIME(end_time, "YYYY-MM-DD HH:mm:ss")
```