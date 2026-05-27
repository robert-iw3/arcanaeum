### Confluence Exploit Leads to LockBit Ransomware
---

This report details a LockBit ransomware intrusion initiated by exploiting CVE-2023-22527 in an exposed Windows Confluence server, leading to rapid network compromise and data encryption within approximately two hours. The threat actor leveraged common tools and techniques, including Metasploit, Mimikatz, AnyDesk, and PDQ Deploy, for execution, persistence, credential access, lateral movement, and widespread ransomware deployment.

The report highlights the rapid Time to Ransom (TTR) of just two hours, demonstrating the increased speed and efficiency of LockBit affiliates in compromising and encrypting environments. Additionally, the use of PDQ Deploy for automated ransomware distribution across the network is a noteworthy evolution in their deployment tactics, indicating a shift towards leveraging legitimate enterprise tools for broader impact.

### Actionable Threat Data
---

Monitor for `mshta.exe` spawning `powershell.exe` with encoded commands, especially if the powershell.exe command line contains `System.IO.Compression.GzipStream` or `System.Convert::FromBase64String`.

Detect the creation of new local user accounts and their immediate addition to the "`Administrators`" group, particularly when followed by `RDP` logins from these new accounts.

Look for `mimikatz.exe` process creation and subsequent access to `lsass.exe` (Sysmon Event ID 10 with `GrantedAccess` of `0x1010`).

Identify the execution of `rclone.exe` with command-line arguments indicating exfiltration to cloud storage services like `mega.nz` (e.g., `--config=rclone.conf copy c:\fs mega:FTP`).

Monitor for the installation and use of legitimate software deployment tools like PDQ Deploy (`PDQDeployService.exe`, `PDQDeployRunner-*.exe`) in conjunction with suspicious batch files (.bat) or executable files (.exe) being copied over `SMB` shares and executed remotely.

### Confluence RCE via OGNL
---
```sql
-- description: >
--   Detects the Confluence server process (e.g., tomcat.exe) spawning suspicious child processes
--   like command shells, network discovery tools, or downloaders. This behavior is a strong indicator
--   of remote code execution, as seen in the exploitation of vulnerabilities like CVE-2023-22527.
-- false_positives: >
--   Legitimate Confluence plugins or administrative scripts might spawn some of these processes, though it is uncommon.
--   Tuning may be required to exclude known administrative activity. Review the full command line of the
--   spawned process for additional context.
-- data_source:
--   - Endpoint

(index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1)
| `tstats` summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("tomcat*.exe", "Confluence.exe") AND Processes.process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "sh.exe", "bash.exe", "net.exe", "net1.exe", "whoami.exe", "query.exe", "tasklist.exe", "ipconfig.exe", "hostname.exe", "mshta.exe", "curl.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
-- comment: Convert epoch timestamps to human-readable format.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- comment: Rename fields for clarity and consistency.
| rename parent_process_name as parent_process, process_name as child_process, process as child_process_commandline, dest as host
-- comment: Table of results for investigation.
| table firstTime, lastTime, host, user, parent_process, child_process, child_process_commandline
```

### Encoded PowerShell via MSHTA
---
```sql
-- description: >
--   Detects encoded or compressed PowerShell commands executed via mshta.exe. This technique is frequently used by adversaries
--   for stealthy payload delivery and execution, often as a second stage after initial access, bypassing traditional defenses.
--   The parent-child relationship of `mshta.exe` -> `powershell.exe` combined with command-line indicators of encoding
--   or compression is a strong indicator of malicious activity.
-- false_positives: >
--   Legitimate, complex administrative scripts might use these .NET classes for data manipulation. However,
--   being spawned from `mshta.exe` significantly reduces the likelihood of it being benign. Review the HTA
--   source if available.
-- data_source:
--   - Endpoint

| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="mshta.exe" AND Processes.process_name IN ("powershell.exe", "pwsh.exe") AND (Processes.process="*FromBase64String*" OR Processes.process="*System.IO.Compression.GzipStream*" OR Processes.process="*System.IO.Compression.DeflateStream*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
-- comment: Convert epoch timestamps to human-readable format.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- comment: Rename fields for clarity and consistency.
| rename parent_process_name as parent_process, process_name as child_process, process as child_process_commandline, dest as host
-- comment: Table of results for investigation.
| table firstTime, lastTime, host, user, parent_process, child_process, child_process_commandline
```

### Suspicious Local Account Creation
---
```sql
-- description: >
--   Detects a sequence of events where a new local user account is created, immediately added to the local Administrators group,
--   and then used to log in via RDP, all within a short time frame. This pattern is a strong indicator of a threat actor
--   establishing persistence and escalating privileges on a compromised host.
-- false_positives: >
--   This activity may be legitimate during rapid, manual server setup or via specific automated provisioning tools.
--   However, such behavior is typically rare in established environments. Investigate the context of the user creation
--   and the source of the RDP connection.
-- data_source:
--   - Security

(index=* sourcetype=WinEventLog:Security)
-- comment: Pre-filter for the three key events: User Creation (4720), Add to Admin Group (4732), and RDP Logon (4624).
(EventCode=4720 OR (EventCode=4732 AND Group_Name="Administrators") OR (EventCode=4624 AND Logon_Type=10))
-- comment: Correlate events by the user's SID and the host, within a 15-minute window.
| transaction maxspan=15m dest Target_User_SID
-- comment: Ensure the transaction contains all three distinct events required for the pattern.
| where eventcount>=3 AND mvfind(EventCode, "4720") AND mvfind(EventCode, "4732") AND mvfind(EventCode, "4624")
-- comment: Convert epoch timestamps to human-readable format.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- comment: Extract the username, which can sometimes be multi-valued in a transaction.
| eval user_name=mvindex(mvfilter(match(Target_User_Name, ".+")),0)
-- comment: Rename fields for clarity and consistency.
| rename dest as host, Target_User_SID as user_sid, duration as transaction_duration_sec
-- comment: Table of results for investigation.
| table firstTime, lastTime, transaction_duration_sec, host, user_name, user_sid
```

### Mimikatz LSASS Access
---
```sql
-- description: >
--   Detects a process named mimikatz.exe accessing the LSASS process with specific access rights (0x1010)
--   that allow for querying information and reading process memory. This is a hallmark of credential dumping
--   attempts using Mimikatz, as observed in Sysmon Event ID 10.
-- false_positives: >
--   This detection is highly specific to the process name "mimikatz.exe". False positives are unlikely.
--   However, attackers can easily rename the binary. For broader detection, consider removing the
--   `process_name="mimikatz.exe"` filter to alert on any process accessing LSASS with these rights,
--   but this will require tuning to exclude legitimate security tools.
-- data_source:
--   - Endpoint

| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="mimikatz.exe" AND Processes.target_process_name="lsass.exe" AND Processes.process_granted_access="0x1010") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process_guid Processes.target_process_name Processes.process_granted_access
| `drop_dm_object_name(Processes)`
-- comment: Convert epoch timestamps to human-readable format.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- comment: Rename fields for clarity and consistency.
| rename dest as host, process_name as source_process_name, process_path as source_process_path, process_guid as source_process_guid, target_process_name as target_process, process_granted_access as granted_access
-- comment: Table of results for investigation.
| table firstTime, lastTime, host, user, source_process_name, source_process_path, source_process_guid, target_process, granted_access
```

### Rclone Exfiltration to Cloud
---
```sql
-- description: >
--   Detects the use of rclone.exe to exfiltrate data to common cloud storage providers.
--   This rule looks for the execution of rclone with commands like 'copy' or 'sync'
--   and command-line arguments that specify a remote destination associated with
--   cloud services like Mega, Dropbox, Google Drive, etc.
-- false_positives: >
--   Legitimate use of rclone by system administrators or developers for backups or data migration.
--   Tuning may be required to exclude known-good activity based on user, host, or specific
--   command-line arguments.
-- data_source:
--   - Endpoint

| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="rclone.exe" AND (Processes.process="* copy *" OR Processes.process="* sync *" OR Processes.process="* move *") AND (Processes.process="*mega:*" OR Processes.process="*dropbox:*" OR Processes.process="*gdrive:*" OR Processes.process="*onedrive:*" OR Processes.process="*pcloud:*" OR Processes.process="*box:*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
-- comment: Convert epoch timestamps to human-readable format.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- comment: Rename fields for clarity and consistency.
| rename parent_process_name as parent_process, process_name as child_process, process as child_process_commandline, dest as host
-- comment: Table of results for investigation.
| table firstTime, lastTime, host, user, parent_process, child_process, child_process_commandline
```

### PDQ Deploy for Ransomware
---
```sql
-- description: >
--   Detects the PDQ Deploy runner process (`PDQDeployRunner-*.exe`) executing a command shell (`cmd.exe`)
--   to launch a script file (`.bat` or `.ps1`). This pattern is indicative of a remote command or script
--   being executed via PDQ Deploy. While this can be used for legitimate administrative purposes, threat actors,
--   such as those deploying LockBit ransomware, have leveraged this exact technique to distribute malware
--   across a network.
-- false_positives: >
--   Legitimate software deployments or administrative tasks performed via PDQ Deploy may use command steps
--   to execute batch or PowerShell scripts. Tuning may be required to exclude known scripts, hosts, or
--   administrative users.
-- data_source:
--   - Endpoint

| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="PDQDeployRunner-*.exe" AND Processes.process_name="cmd.exe" AND (Processes.process="*.bat*" OR Processes.process="*.ps1*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
-- comment: Convert epoch timestamps to human-readable format.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- comment: Rename fields for clarity and consistency.
| rename parent_process_name as parent_process, process_name as child_process, process as child_process_commandline, dest as host
-- comment: Table of results for investigation.
| table firstTime, lastTime, host, user, parent_process, child_process, child_process_commandline
```