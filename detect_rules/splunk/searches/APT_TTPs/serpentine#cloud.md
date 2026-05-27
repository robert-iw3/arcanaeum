### SERPENTINE#CLOUD Threat Report
---

The SERPENTINE#CLOUD campaign is a sophisticated, multi-stage attack leveraging Cloudflare Tunnels and Python-based malware to achieve stealthy, in-memory code execution and persistence. The threat actors utilize phishing emails with malicious .lnk files to initiate the infection chain, ultimately deploying Donut-packed payloads and various Remote Access Trojans (RATs).


Recent intelligence indicates a significant increase in the abuse of Cloudflare Tunnels by various threat actors for stealthy payload delivery and C2, highlighting a growing trend beyond the SERPENTINE#CLOUD campaign. This widespread adoption of Cloudflare Tunnels by malicious actors makes detection more challenging as it blends malicious traffic with legitimate services, necessitating a shift from traditional static blocklists to behavioral detection.

### Actionable Threat Data
---

Monitor for the creation of `.lnk` files, especially those disguised as documents (e.g., PDFs) and delivered via email or suspicious downloads, as these are frequently used for initial access in this campaign and others.

Detect outbound network connections to `trycloudflare[.]com` subdomains, particularly those initiated by unusual processes or in conjunction with WebDAV activity, as this indicates potential abuse of Cloudflare Tunnels for payload delivery.

Look for the execution of robocopy or `cscript.exe` downloading files from remote WebDAV shares, especially those hosted on Cloudflare Tunnel domains, as this is a key stage in the SERPENTINE#CLOUD infection chain.

Identify the creation or modification of files within Windows startup folders (`%APPDATA%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`) with suspicious extensions (e.g., `.vbs`, `.bat`) or content, as this is a common persistence mechanism for this threat actor.

Detect python.exe executing from unusual or temporary directories (e.g., `C:\Users\username\contacts\Extracted`) and initiating process injection (e.g., into notepad.exe) or making outbound network connections to known C2 infrastructure, indicating the final stages of the attack.

### LNK File Initial Access
---
```sql
#
# SERPENTINE#CLOUD LNK Initial Access with Robocopy and WebDAV
#
# Date: 2025-07-23
#
# Description:
# Detects a command-line execution pattern consistent with the SERPENTINE#CLOUD campaign's initial access method.
# This involves a malicious LNK file launching cmd.exe, which then uses robocopy.exe to download a file from a
# remote WebDAV share and executes it using cscript.exe or wscript.exe.
#
# References:
# - https://www.securonix.com/blog/analyzing_serpentinecloud-threat-actors-abuse-cloudflare-tunnels-threat-research/
#
# False Positive Sensitivity: Medium
# This TTP uses legitimate Windows binaries. False positives may occur in environments where administrators
# use scripts that leverage robocopy and WebDAV for software distribution.
# Consider filtering by parent process (e.g., explorer.exe) or excluding known administrative servers/scripts.
#
# MITRE ATT&CK:
# - T1566.001: Phishing: Spearphishing Attachment
# - T1204.002: User Execution: Malicious File
# - T1059.003: Command and Scripting Interpreter: Windows Command Shell
# - T1059.005: Command and Scripting Interpreter: Visual Basic
# - T1218: System Binary Proxy Execution
#
from datamodel=Endpoint.Processes
| eval timestamp=_time
# Focus on cmd.exe as the process launched by the malicious LNK file.
| where process_name="cmd.exe"
# Detect the combination of robocopy for download and a script host for execution in the same command.
| where like(process, "%robocopy%") AND (like(process, "%cscript.exe%") OR like(process, "%wscript.exe%"))
# Identify the use of WebDAV paths for remote payload retrieval. The @SSL syntax is a strong indicator.
| where (like(process, "%\\\\%@SSL\\DavWWWRoot\\%") OR like(process, "%\\\\%\\DavWWWRoot\\%"))
| stats count min(timestamp) as firstTime max(timestamp) as lastTime values(process) as process by dest, user, parent_process_name, process_name
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
# Placeholder for tuning, e.g., filtering known admin servers or scripts.
# Example: | search NOT (user IN (known_admin_users) AND dest IN (known_servers))
| where parent_process_name != "sccm.exe"
```

### Cloudflare Tunnel Abuse
---
```sql
#
# Cloudflare Tunnel Abuse via WebDAV
#
# Date: 2025-07-23
#
# Description:
# Detects processes accessing WebDAV shares hosted on `trycloudflare.com` subdomains.
# This technique is used by the SERPENTINE#CLOUD campaign and other threat actors to deliver
# malicious payloads stealthily, bypassing some network defenses by leveraging the
# legitimate Cloudflare Tunnel service.
#
# References:
# - https://www.securonix.com/blog/analyzing_serpentinecloud-threat-actors-abuse-cloudflare-tunnels-threat-research/
#
# False Positive Sensitivity: Medium
# This rule detects the use of a legitimate service (`trycloudflare.com`) combined with WebDAV access from the command line.
# False positives may occur in environments where developers or administrators use Cloudflare Tunnels for testing or remote file access.
# Tuning by user, host, or parent process may be required to filter out legitimate administrative or development activity.
#
# MITRE ATT&CK:
# - T1071.001: Application Layer Protocol: Web Protocols
# - T1572: Protocol Tunneling
#
from datamodel=Endpoint.Processes
| eval timestamp=_time
# Filter for command-lines containing the trycloudflare.com domain, a known abused service.
| where like(process, "%.trycloudflare.com%")
# Further filter for command-lines that indicate WebDAV usage, a TTP for payload delivery in this campaign.
# The @SSL syntax is a strong indicator of this specific TTP.
| where (like(process, "%\\\\%@SSL\\DavWWWRoot\\%") OR like(process, "%\\\\%\\DavWWWRoot\\%"))
# Aggregate results to create a single alert per host/user combination.
| stats count min(timestamp) as firstTime max(timestamp) as lastTime values(process) as process by dest, user, parent_process_name, process_name
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
# Tuning placeholder: Exclude known developer systems or administrative scripts that legitimately use this combination.
# Example: | search NOT (user IN (known_dev_users) AND dest IN (known_dev_systems))
```

### Robocopy/Cscript WebDAV Download
---
```sql
#
# SERPENTINE#CLOUD LNK Initial Access with Robocopy and WebDAV
#
# Date: 2025-07-23
#
# Description:
# Detects a command-line execution pattern consistent with the SERPENTINE#CLOUD campaign's initial access method.
# This involves a malicious LNK file launching cmd.exe, which then uses robocopy.exe to download a file from a
# remote WebDAV share and executes it using cscript.exe or wscript.exe.
#
# References:
# - https://www.securonix.com/blog/analyzing_serpentinecloud-threat-actors-abuse-cloudflare-tunnels-threat-research/
#
# False Positive Sensitivity: Medium
# This TTP uses legitimate Windows binaries. False positives may occur in environments where administrators
# use scripts that leverage robocopy and WebDAV for software distribution.
# Consider filtering by parent process (e.g., explorer.exe) or excluding known administrative servers/scripts.
#
# MITRE ATT&CK:
# - T1105: Ingress Tool Transfer
# - T1059.003: Command and Scripting Interpreter: Windows Command Shell
# - T1059.005: Command and Scripting Interpreter: Visual Basic
# - T1218: System Binary Proxy Execution
#
from datamodel=Endpoint.Processes
| eval timestamp=_time
# Focus on cmd.exe as the process launched by the malicious LNK file.
| where process_name="cmd.exe"
# Detect the combination of robocopy for download and a script host for execution in the same command.
| where like(process, "%robocopy%") AND (like(process, "%cscript.exe%") OR like(process, "%wscript.exe%"))
# Identify the use of WebDAV paths for remote payload retrieval. The @SSL syntax is a strong indicator.
| where (like(process, "%\\\\%@SSL\\DavWWWRoot\\%") OR like(process, "%\\\\%\\DavWWWRoot\\%"))
| stats count min(timestamp) as firstTime max(timestamp) as lastTime values(process) as process by dest, user, parent_process_name, process_name
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
# Placeholder for tuning, e.g., filtering known admin servers or scripts.
# Example: | search NOT (user IN (known_admin_users) AND dest IN (known_servers))
| where parent_process_name != "sccm.exe"
```

### Startup Folder Persistence
---
```sql
#
# Suspicious File Creation in Windows Startup Folder
#
# Date: 2025-07-23
#
# Description:
# Detects the creation of suspicious file types (e.g., .vbs, .bat, .js, .ps1, .lnk) in the Windows Startup folder.
# Threat actors, such as those behind the SERPENTINE#CLOUD campaign, use this technique to establish persistence
# by ensuring their malicious scripts or programs are executed every time a user logs on.
#
# References:
# - https://www.securonix.com/blog/analyzing_serpentinecloud-threat-actors-abuse-cloudflare-tunnels-threat-research/
#
# False Positive Sensitivity: Medium
# Legitimate applications (e.g., collaboration tools, updaters) may create shortcuts (.lnk files) or scripts in the Startup folder.
# Tuning may be required to exclude known good applications or administrative scripts.
# Consider filtering by the process name that created the file or specific, known-good file names.
#
# MITRE ATT&CK:
# - T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
#
from datamodel=Endpoint.Filesystem
| eval timestamp=_time
# Filter for file creation events in the user-specific or system-wide Startup folders.
| where (match(file_path, /(?i)AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup/i) OR match(file_path, /(?i)ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp/i))
# Look for suspicious file types commonly used for persistence. The SERPENTINE#CLOUD campaign used .vbs and .bat files.
| where match(file_name, /(?i)\.(bat|vbs|js|ps1|lnk|exe|scr)$/i)
# Aggregate the results to provide a summary of the activity.
| stats count min(timestamp) as firstTime max(timestamp) as lastTime values(file_name) as file_name values(file_path) as file_path by dest, user, process_name
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
# Tuning placeholder: Exclude known legitimate processes that create startup items.
# Example: | search NOT (process_name IN ("msiexec.exe", "Teams.exe", "OneDrive.exe") OR file_name IN ("known_good_file.lnk"))
```

### Python Process Injection/C2
---
```sql
#
# Python Execution from Unusual Location with Network Activity
#
# Date: 2025-07-23
#
# Description:
# Detects python.exe executing from a non-standard, user-writable directory while making an outbound network connection.
# This behavior is highly suspicious and is a key TTP in the final stages of the SERPENTINE#CLOUD campaign,
# where Python is used to load shellcode, perform process injection, and establish C2 communications.
#
# References:
# - https://www.securonix.com/blog/analyzing_serpentinecloud-threat-actors-abuse-cloudflare-tunnels-threat-research/
#
# False Positive Sensitivity: Medium
# Legitimate portable Python applications or developer scripts running from user directories could trigger this alert.
# Tuning is recommended to exclude known developer hosts or specific, approved script paths.
#
# MITRE ATT&CK:
# - T1059.006: Command and Scripting Interpreter: Python
# - T1055: Process Injection
# - T1071.001: Application Layer Protocol: Web Protocols
#
from datamodel=Endpoint.Network
| eval timestamp=_time
# Filter for network connections made by the Python interpreter.
| where process_name="python.exe"
# Focus on execution from unusual, user-writable directories. SERPENTINE#CLOUD specifically used the 'Contacts' folder.
| where (like(process_path, "%\\Users\\%\\Contacts\\%") OR like(process_path, "%\\Users\\%\\Downloads\\%") OR like(process_path, "%\\Users\\Public\\%") OR like(process_path, "%\\Temp\\%") OR like(process_path, "C:\\Users\\Default\\%"))
# Exclude common legitimate installation paths to reduce false positives.
| where NOT (like(process_path, "C:\\Program Files\\%") OR like(process_path, "C:\\Python%") OR like(process_path, "%\\AppData\\Local\\Programs\\Python\\%"))
# Aggregate results for alert clarity.
| stats count min(timestamp) as firstTime max(timestamp) as lastTime values(process_path) as process_path values(dest) as dest values(dest_port) as dest_port by dest, user, parent_process_name
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
# Tuning placeholder: Exclude known developer machines or approved script paths.
# Example: | search NOT (dest="dev-machine-01" OR process_path="C:\\Users\\developer\\approved_scripts\\python.exe")
```