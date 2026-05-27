### Dropping Elephant APT Group Targets Turkish Defense Industry
---

The cyber-espionage group Dropping Elephant (also known as Patchwork or Quilted Tiger) has launched a new campaign targeting Turkish defense contractors, specifically a manufacturer of precision-guided missile systems. This campaign utilizes a five-stage execution chain, leveraging malicious LNK files, LOLBAS (Living Off the Land Binaries and Scripts) like PowerShell, and DLL side-loading with legitimate applications such as VLC Media Player and Microsoft Task Scheduler for defense evasion and persistence.


Dropping Elephant has evolved its capabilities by diversifying from x64 DLL to x86 PE architecture, reducing library dependencies, and enhancing its C2 protocol with raw code parsing and strtok() for command processing. The group is also employing sophisticated operational security measures, including impersonating legitimate websites for C2 infrastructure and manipulating compilation timestamps for anti-forensics.

### Actionable Threat Data
---


    Initial Access & Execution:

        Monitor for LNK files delivered via spear-phishing, especially those disguised as conference invitations or other enticing lures.

        Look for PowerShell execution with obfuscated commands, particularly those attempting to download files from external sources or manipulate scheduled tasks.

        MITRE ATT&CK:

            T1566.001 (Spear-phishing Attachment), T1059.001 (PowerShell), T1105 (Ingress Tool Transfer)

    Defense Evasion & Persistence:

        Detect the creation of scheduled tasks that abuse legitimate applications like vlc.exe or schtasks.exe to load malicious DLLs (e.g., libvlc.dll).

        Monitor for the creation of new files in unusual directories (e.g., C:\Windows\Tasks\) with manipulated file extensions that are later corrected.

        MITRE ATT&CK:

            T1574.002 (DLL Side-Loading), T1053.005 (Scheduled Task), T1036.005 (Match Legitimate Name or Location), T1027 (Obfuscated Files or Information)

    Command and Control & Data Exfiltration:

        Identify network connections to suspicious domains impersonating legitimate websites (e.g., expouav[.]org, roseserve[.]org).

        Monitor for the creation of mutex ghjghkj which is used to prevent multiple instances of the malware from running.

        Look for unusual outbound HTTP POST requests to C2 servers with structured parameters and specific user-agents (e.g., Mozilla/5.0).

        MITRE ATT&CK:

            T1071.001 (Web Protocols), T1573.001 (Symmetric Cryptography), T1041 (Exfiltration Over C2 Channel), T1583.001 (Acquire Infrastructure)

    Reconnaissance & Impact:

        Detect attempts to gather system information (computer name, username, firmware) and perform environment checks (processor features, system time queries) for sandboxing evasion.

        Monitor for screen capture activities and the creation of JPG files for exfiltration.

        MITRE ATT&CK:

            T1082 (System Information Discovery), T1124 (System Time Discovery), T1497 (Virtualization/Sandbox Evasion), T1113 (Screen Capture)


### Malicious LNK File
---
```sql
# Name: Dropping Elephant Malicious LNK File
# Date: 2025-07-24
# References:
#  - https://arcticwolf.com/resources/blog/dropping-elephant-apt-group-targets-turkish-defense-industry/
# MITRE ATT&CK: T1566.001
# Description: Detects a malicious LNK file by its SHA256 hash. This file was used by the Dropping Elephant APT group for initial access in a campaign targeting the Turkish defense industry.
# False Positives: This is a hash-based detection and is considered high-fidelity with a very low likelihood of false positives.

# Search for the specific file hash in endpoint data models.
# The `Endpoint.Filesystem` data model can be replaced with raw data sources from EDR tools (e.g., `index=crowdstrike`, `sourcetype=carbonblack:file`).
(`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash="341f27419becc456b52d6fbe2d223e8598065ac596fa8dec23cc722726a28f62" by Filesystem.dest, Filesystem.file_name, Filesystem.file_path, Filesystem.file_hash)
| `drop_dm_object_name("Filesystem")`

# Format the timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

# Provide useful fields for investigation.
| table firstTime, lastTime, dest, file_name, file_path, file_hash, count
```

### Malicious PDF Lure
---
```sql
# Name: Dropping Elephant Malicious PDF Lure
# Date: 2025-07-24
# References:
#  - https://arcticwolf.com/resources/blog/dropping-elephant-apt-group-targets-turkish-defense-industry/
# MITRE ATT&CK: T1204.002
# Description: Detects a malicious PDF file used as a lure by the Dropping Elephant APT group. The detection is based on the file's SHA256 hash.
# False Positives: This is a hash-based detection and is considered high-fidelity with a very low likelihood of false positives.

# Search for the specific file hash in endpoint data models.
# The `Endpoint.Filesystem` data model can be replaced with raw data sources from EDR tools (e.g., `index=crowdstrike`, `sourcetype=carbonblack:file`).
(`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash="588021b5553838fae5498de40172d045b5168c8e608b8929a7309fd08abfaa93" by Filesystem.dest, Filesystem.file_name, Filesystem.file_path, Filesystem.file_hash)
| `drop_dm_object_name("Filesystem")`

# Format the timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

# Provide useful fields for investigation.
| table firstTime, lastTime, dest, file_name, file_path, file_hash, count
```

### Malicious DLL (libvlc.dll)
---
```sql
# Name: Dropping Elephant Malicious DLL
# Date: 2025-07-24
# References:
#  - https://arcticwolf.com/resources/blog/dropping-elephant-apt-group-targets-turkish-defense-industry/
# MITRE ATT&CK: T1574.002
# Description: Detects a malicious DLL file (libvlc.dll) used for shellcode execution by the Dropping Elephant APT group as part of a DLL side-loading technique. The detection is based on the file's SHA256 hash.
# False Positives: This is a hash-based detection and is considered high-fidelity with a very low likelihood of false positives.

# Search for the specific file hash in endpoint data models.
# The `Endpoint.Filesystem` data model can be replaced with raw data sources from EDR tools (e.g., `index=crowdstrike`, `sourcetype=carbonblack:file`).
(`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash="2cd2a4f1fc7e4b621b29d41e42789c1365e5689b4e3e8686b80f80268e2c0d8d" by Filesystem.dest, Filesystem.file_name, Filesystem.file_path, Filesystem.file_hash)
| `drop_dm_object_name("Filesystem")`

# Format the timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

# Provide useful fields for investigation.
| table firstTime, lastTime, dest, file_name, file_path, file_hash, count
```

### Encrypted Shellcode (vlc.log)
---
```sql
# Name: Dropping Elephant Encrypted Shellcode File
# Date: 2025-07-24
# References:
#  - https://arcticwolf.com/resources/blog/dropping-elephant-apt-group-targets-turkish-defense-industry/
# MITRE ATT&CK: T1027
# Description: Detects a specific file (vlc.log) containing encrypted shellcode used by the Dropping Elephant APT group. The detection is based on the file's SHA256 hash.
# False Positives: This is a hash-based detection and is considered high-fidelity with a very low likelihood of false positives.

# Search for the specific file hash in endpoint data models.
(`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash="89ec9f19958a442e9e3dd5c96562c61229132f3acb539a6b919c15830f403553" by Filesystem.dest, Filesystem.file_name, Filesystem.file_path, Filesystem.file_hash)
| `drop_dm_object_name("Filesystem")`

# Format the timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

# Provide useful fields for investigation.
| table firstTime, lastTime, dest, file_name, file_path, file_hash, count
```

### Decrypted Shellcode Payload
---
```sql
# Name: Dropping Elephant Decrypted Shellcode Payload
# Date: 2025-07-24
# References:
#  - https://arcticwolf.com/resources/blog/dropping-elephant-apt-group-targets-turkish-defense-industry/
# MITRE ATT&CK: T1055
# Description: Detects the final payload (decrypted shellcode) used by the Dropping Elephant APT group. The detection is based on the file's SHA256 hash. While the payload is injected into memory, this rule detects the file if it is written to disk.
# False Positives: This is a hash-based detection and is considered high-fidelity with a very low likelihood of false positives.

# Search for the specific file hash in endpoint data models.
(`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash="8b6acc087e403b913254dd7d99f09136dc54fa45cf3029a8566151120d34d1c2" by Filesystem.dest, Filesystem.file_name, Filesystem.file_path, Filesystem.file_hash)
| `drop_dm_object_name("Filesystem")`

# Format the timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

# Provide useful fields for investigation.
| table firstTime, lastTime, dest, file_name, file_path, file_hash, count
```

### Malicious Delivery Domain
---
```sql
# Name: Dropping Elephant Delivery Domain
# Date: 2025-07-24
# References:
#  - https://arcticwolf.com/resources/blog/dropping-elephant-apt-group-targets-turkish-defense-industry/
# MITRE ATT&CK: T1105, T1583.001
# Description: Detects network traffic to expouav.org, a domain used by the Dropping Elephant APT group to host and deliver malicious files.
# False Positives: This is a domain-based detection. False positives are unlikely unless the domain is sinkholed or repurposed.

# Search for network traffic to the malicious domain.
# This can be replaced with raw data sources like proxy, DNS, or firewall logs.
(`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest_domain="expouav.org" by All_Traffic.src, All_Traffic.dest, All_Traffic.user, All_Traffic.dest_domain)
| `drop_dm_object_name("All_Traffic")`

# Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

# Provide useful fields for investigation.
| table firstTime, lastTime, src, dest, user, dest_domain, count
```

### Malicious C2 Server
---
```sql
# Name: Dropping Elephant C2 Domain
# Date: 2025-07-24
# References:
#  - https://arcticwolf.com/resources/blog/dropping-elephant-apt-group-targets-turkish-defense-industry/
# MITRE ATT&CK: T1071.001, T1583.001
# Description: Detects network traffic to roseserve.org, a command and control (C2) domain used by the Dropping Elephant APT group. This domain was observed impersonating a legitimate Turkish project website.
# False Positives: This is a domain-based detection. False positives are unlikely unless the domain is sinkholed or repurposed.

# Search for network traffic to the malicious C2 domain.
# This can be replaced with raw data sources like proxy, DNS, or firewall logs.
(`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest_domain="roseserve.org" by All_Traffic.src, All_Traffic.dest, All_Traffic.user, All_Traffic.dest_domain)
| `drop_dm_object_name("All_Traffic")`

# Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

# Provide useful fields for investigation.
| table firstTime, lastTime, src, dest, user, dest_domain, count
```

### DLL Side-Loading VLC
---
```sql
# Name: VLC DLL Side-Loading
# Date: 2025-07-24
# References:
#  - https://arcticwolf.com/resources/blog/dropping-elephant-apt-group-targets-turkish-defense-industry/
# MITRE ATT&CK: T1574.002
# Description: Detects the legitimate VLC media player process (vlc.exe) loading a DLL from an unusual file path. This technique was used by the Dropping Elephant APT group, which dropped a malicious version of libvlc.dll into C:\Windows\Tasks\ to be side-loaded by vlc.exe.
# False Positives: This detection may trigger on portable versions of VLC running from non-standard directories. Consider filtering by specific DLL names or paths if false positives occur.

# Search for module load events from the Endpoint data model.
# This can be replaced with raw data sources like Sysmon (EventCode=7) or EDR logs.
`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.ImageLoads where (ImageLoads.process_name="vlc.exe" AND ImageLoads.file_path IN ("C:\\Windows\\Tasks\\*", "C:\\Tasks\\*")) by ImageLoads.dest, ImageLoads.user, ImageLoads.process_name, ImageLoads.file_name, ImageLoads.file_path, ImageLoads.file_hash
| `drop_dm_object_name("ImageLoads")`

# Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

# Provide useful fields for investigation.
| table firstTime, lastTime, dest, user, process_name, file_name, file_path, file_hash, count
```

### Scheduled Task Persistence
---
```sql
# Name: Dropping Elephant Scheduled Task Persistence
# Date: 2025-07-24
# References:
#  - https://arcticwolf.com/resources/blog/dropping-elephant-apt-group-targets-turkish-defense-industry/
# MITRE ATT&CK: T1053.005
# Description: Detects the creation of a scheduled task, typically via a script, that is configured to execute vlc.exe from a suspicious directory such as C:\Windows\Tasks\. This specific persistence technique was used by the Dropping Elephant APT group.
# False Positives: Legitimate administrative scripts or software installers might schedule tasks involving VLC from unusual paths, especially in portable app scenarios. Review the parent process and full command line for context.

# Search for process creation events from the Endpoint data model.
`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="schtasks.exe" AND Processes.parent_process_name IN ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")) AND (Processes.process IN ("*/create*", "*/change*") AND Processes.process="*/tr*") AND (Processes.process IN ("*C:\\Windows\\Tasks\\vlc*", "*C:\\Tasks\\vlc*")) by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process, Processes.process_id, Processes.parent_process_id
| `drop_dm_object_name("Processes")`

# Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

# Provide useful fields for investigation.
| table firstTime, lastTime, dest, user, parent_process, process_name, process, process_id, parent_process_id, count
```

### Obfuscated PowerShell Execution
---
```sql
# Name: Obfuscated PowerShell Execution
# Date: 2025-07-24
# References:
#  - https://arcticwolf.com/resources/blog/dropping-elephant-apt-group-targets-turkish-defense-industry/
# MITRE ATT&CK: T1059.001, T1562.001
# Description: Detects obfuscated or stealthy PowerShell execution, characterized by parameters that bypass execution policies or suppress progress indicators, combined with commands for downloading files or creating persistence. This pattern was used by the Dropping Elephant APT group.
# False Positives: Legitimate automation or administration scripts may use these command combinations. Tuning may be required to exclude known good scripts or parent processes.

# Search for PowerShell process creation events.
`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="powershell.exe")
# Look for common evasion techniques like suppressing progress or bypassing execution policy.
AND ((Processes.process="*SilentlyContinue*") OR (Processes.process IN ("*-ep*bypass*", "*-ExecutionPolicy*Bypass*")))
# Correlate with suspicious actions like downloading files or creating scheduled tasks.
AND ((Processes.process IN ("*wget*", "*iwr*", "*Invoke-WebRequest*", "*DownloadFile*", "*DownloadString*")) OR (Processes.process IN ("*schtasks*", "*/Create*", "*New-ScheduledTask*")))
by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process, Processes.process_id, Processes.parent_process_id
| `drop_dm_object_name("Processes")`

# Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

# Provide useful fields for investigation.
| table firstTime, lastTime, dest, user, parent_process, process_name, process, process_id, parent_process_id, count
```

### System Information Discovery
---
```sql
# Name: System Information Discovery Command Cluster
# Date: 2025-07-24
# References:
#  - https://arcticwolf.com/resources/blog/dropping-elephant-apt-group-targets-turkish-defense-industry/
# MITRE ATT&CK: T1082, T1124, T1497
# Description: Detects a cluster of multiple, distinct system information discovery commands executed on a single host by the same user and parent process within a short time frame. This pattern of activity is common during the reconnaissance phase of an attack, where adversaries gather information about the compromised system and its environment. The Dropping Elephant APT group was observed performing similar reconnaissance activities.
# False Positives: Legitimate administrative scripts, diagnostic tools, or some software installers may execute several of these commands in quick succession. Tuning may be required by excluding known legitimate parent processes or scripts.

# Search for process creation events from the Endpoint data model.
`tstats` prestats=true min(_time) as firstTime, max(_time) as lastTime, values(Processes.process) as process, values(Processes.process_name) as process_name from datamodel=Endpoint.Processes
# Filter for a list of common system, network, and user discovery commands.
where Processes.process_name IN ("arp.exe", "gpresult.exe", "hostname.exe", "ipconfig.exe", "nbtstat.exe", "net.exe", "net1.exe", "nltest.exe", "quser.exe", "qwinsta.exe", "query.exe", "route.exe", "systeminfo.exe", "tasklist.exe", "whoami.exe")
by _time, Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`

# Group events into 5-minute windows.
| bin _time span=5m

# Correlate commands executed by the same host, user, and parent process within the time window.
| stats dc(process_name) as distinct_command_count, values(process) as commands_executed, min(firstTime) as firstTime, max(lastTime) as lastTime by _time, dest, user, parent_process

# A threshold of 3 distinct commands is used to identify suspicious activity. This can be tuned to adjust sensitivity.
| where distinct_command_count > 3

# Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

# Provide useful fields for investigation.
| table firstTime, lastTime, dest, user, parent_process, distinct_command_count, commands_executed
```

### Screen Capture for Data Exfil
---
```sql
# Name: Suspicious Process Creating Image File
# Date: 2025-07-24
# References:
#  - https://arcticwolf.com/resources/blog/dropping-elephant-apt-group-targets-turkish-defense-industry/
# MITRE ATT&CK: T1113, T1041
# Description: Detects a process, not typically associated with image creation, writing an image file (e.g., JPG, PNG) to disk. This behavior can be indicative of malware or spyware capturing screenshots of the user's desktop for data exfiltration, a technique observed in use by groups like Dropping Elephant.
# False Positives: Legitimate applications, especially portable apps, custom tools, or software updaters, may create image files. Tuning the process name allowlist is critical to reducing false positives in a specific environment.

# Search for file creation events from the Endpoint data model.
`tstats` count min(_time) as firstTime max(_time) as lastTime, values(Filesystem.file_path) as file_path, values(Filesystem.process_path) as process_path from datamodel=Endpoint.Filesystem
# Filter for common image file extensions that could be used for screenshots.
where Filesystem.file_name IN ("*.jpg", "*.jpeg", "*.png", "*.bmp")
# Group by host and the process that created the file.
by Filesystem.dest, Filesystem.process_name, Filesystem.user
| `drop_dm_object_name("Filesystem")`
| `rename process_name as process`

# Filter out common legitimate processes known to create image files.
# This allowlist is a critical tuning point and should be customized for your environment.
| where 'process' NOT IN ("SnippingTool.exe", "snip.exe", "ScreenClippingHost.exe", "mspaint.exe", "Photos.exe", "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe", "WhatsApp.exe", "Telegram.exe", "slack.exe", "teams.exe", "WINWORD.EXE", "POWERPNT.EXE", "EXCEL.EXE", "OUTLOOK.EXE", "OneDrive.exe", "greenshot.exe", "lightshot.exe", "Snipaste.exe", "ShareX.exe", "vmware-remotemks.exe", "mstsc.exe", "photoshop.exe")

# Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

# Provide useful fields for investigation.
| table firstTime, lastTime, dest, user, process, process_path, file_path, count
```

### Mutex Creation (ghjghkj)
---
```sql
# Name: Dropping Elephant Mutex Creation
# Date: 2025-07-24
# References:
#  - https://arcticwolf.com/resources/blog/dropping-elephant-apt-group-targets-turkish-defense-industry/
# MITRE ATT&CK: T1082
# Description: Detects the creation of the mutex "ghjghkj", a specific host artifact associated with the Dropping Elephant APT group's malware. This mutex is used to ensure only one instance of the malware runs on a compromised system. The full object path for this artifact is `Sessions\1\BaseNamedObjects\ghjghkj`.
# False Positives: Extremely low. The mutex name is a unique, random-looking string.

# This detection requires an EDR or logging agent that records mutex creation events.
# The query below is a template. You must replace `index=* sourcetype=*` with the appropriate data source for your environment.
# It also assumes a field `mutex_name` exists. If your data source uses a different field name (e.g., MutexName, object_name), update the query accordingly.
index=* sourcetype=* mutex_name="ghjghkj"

# Group events by host and process.
| stats count min(_time) as firstTime max(_time) as lastTime by dest, user, process_name, mutex_name

# Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

# Provide useful fields for investigation.
| table firstTime, lastTime, dest, user, process_name, mutex_name, count
```

