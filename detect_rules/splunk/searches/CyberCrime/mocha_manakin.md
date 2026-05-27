### Mocha Manakin and NodeInitRAT Threat Report
---

Mocha Manakin is an activity cluster that leverages "paste and run" social engineering to deliver NodeInitRAT, a custom NodeJS-based backdoor. This threat is assessed to likely lead to ransomware, with overlaps observed with Interlock ransomware activity.


Recent intelligence confirms that the "paste and run" technique, also known as "ClickFix," continues to be a prevalent initial access vector, with Interlock ransomware actors specifically observed using it as recently as June 2025. This highlights the ongoing effectiveness of this social engineering tactic and its adoption by various threat groups, including those associated with ransomware.

### Actionable Threat Data
---

Monitor for PowerShell commands utilizing `Invoke-Expression` (iex) and `Invoke-RestMethod` (irm) to download content from remote IP addresses, especially those involving `trycloudflare[.]com` domains.

Detect instances where `node.exe` spawns `cmd.exe` to add or modify Windows Registry run keys, particularly those named "`ChromeUpdater`" or similar, to establish persistence.

Look for the creation of `.zip` files in temporary directories (e.g., `C:\Users\<user>\AppData\Local\Temp\downloaded.zip`) followed by the execution of `node.exe` from within these extracted contents.

Identify HTTP `POST` requests to adversary-controlled servers, often through Cloudflare tunnels, with `URL` paths ending in `/init1234`.

Hunt for the execution of reconnaissance commands such as `nltest`, `net.exe`, `setspn.exe`, `arp.exe -a`, `tasklist.exe /svc`, and `Get-Service` via `node.exe` or `PowerShell`.

### PowerShell Download Cradle
---
```sql
--## Title: PowerShell Download and Execution Cradle via IP Address
--##
--## Date: 2025-07-24
--##
--## MITRE ATT&CK:
--##   - T1059.001: Command and Scripting Interpreter: PowerShell
--##   - T1105: Ingress Tool Transfer
--##
--## References:
--##   - https://redcanary.com/blog/threat-intelligence/mocha-manakin-nodejs-backdoor/
--##
--## Description:
--## This rule detects PowerShell command lines that use a combination of a download command (Invoke-RestMethod/irm/iwr)
--## and an execution command (Invoke-Expression/iex) to download and run content from a remote IP address. This
--## "download cradle" is a common technique used by adversaries, including Mocha Manakin, for initial access and
--## payload delivery.
--##
--## False Positives:
--## Legitimate administration scripts or software management tools like Chocolatey may use this pattern.
--## Tuning may be required to exclude known-good source IPs or scripts.
--##
--## Data Source:
--## Requires process execution logs with command-line details, such as those from Sysmon (Event ID 1) or EDR platforms,
--## mapped to the Splunk Common Information Model (CIM) Endpoint.Processes data model.
--##
--## Splunk Query
--##
(index=* sourcetype=*)
| `tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=powershell.exe OR Processes.process_name=pwsh.exe) AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*") AND (Processes.process="*irm*" OR Processes.process="*Invoke-RestMethod*" OR Processes.process="*iwr*") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`

--# Key logic: Detects PowerShell using a combination of download and execution commands.
| where (match(process, /(?i)iex|invoke-expression/)) AND (match(process, /(?i)irm|iwr|invoke-restmethod/))

--# Extract the IP address from the command line.
| rex field=process "(?<remote_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| where isnotnull(remote_ip)

--# FP Reduction: Filter out common private, loopback, and other non-public IP ranges.
| where NOT match(remote_ip, "(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)")

--# Formatting and output.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process, process_name, process, remote_ip
```

### Node.exe Registry Persistence
---
```sql
--## Title: Node.exe Spawning Cmd to Add Registry Run Key
--##
--## Date: 2025-07-24
--##
--## MITRE ATT&CK:
--##   - T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
--##
--## References:
--##   - https://redcanary.com/blog/threat-intelligence/mocha-manakin-nodejs-backdoor/
--##
--## Description:
--## Detects instances where the Node.js runtime (node.exe) spawns the Windows Command Processor (cmd.exe)
--## to add or modify a registry run key. This behavior is indicative of the NodeInitRAT, used by the
--## Mocha Manakin threat actor, establishing persistence on a compromised system.
--##
--## False Positives:
--## While uncommon, some legitimate software installers or management tools built with Node.js might
--## perform this action. Tuning may be required to exclude legitimate parent processes or scripts if
--## false positives occur.
--##
--## Data Source:
--## Requires process execution logs with command-line details, such as those from Sysmon (Event ID 1) or EDR platforms,
--## mapped to the Splunk Common Information Model (CIM) Endpoint.Processes data model.
--##
--## Splunk Query
--##
`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="node.exe" AND Processes.process_name="cmd.exe" AND Processes.process LIKE "%reg%add%" AND (Processes.process LIKE "%CurrentVersion\\Run%" OR Processes.process LIKE "%CurrentVersion\\RunOnce%")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`

--# Key logic: Identifies cmd.exe spawned by node.exe to add a registry run key for persistence.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process_name, parent_process, process_name, process
```

### NodeInitRAT Temp File Creation
---
```sql
--## Title: Node.js Execution from Temp Following ZIP File Creation
--##
--## Date: 2025-07-24
--##
--## MITRE ATT&CK:
--##   - T1027: Obfuscated Files or Information
--##   - T1105: Ingress Tool Transfer
--##
--## References:
--##   - https://redcanary.com/blog/threat-intelligence/mocha-manakin-nodejs-backdoor/
--##
--## Description:
--## Detects a sequence of events where a ZIP archive is created in a temporary user directory,
--## followed shortly by the execution of node.exe from that same directory. This pattern is
--## characteristic of the Mocha Manakin threat actor, who drops the NodeInitRAT payload in a
--## ZIP file before execution to establish a foothold.
--##
--## False Positives:
--## Legitimate software installers, updaters, or development tools that are built with or use
--## Node.js may exhibit this behavior. If false positives occur, consider tuning by excluding
--## known legitimate ZIP file names or parent processes of node.exe.
--##
--## Data Source:
--## Requires file creation and process execution logs, such as those from Sysmon (Event IDs 11 and 1)
--## or other EDR platforms, mapped to the Splunk Common Information Model (CIM) Filesystem and
--## Processes data models.
--##
--## Splunk Query
--##
`cim` ((Filesystem.action=created AND Filesystem.file_name=*.zip AND (Filesystem.file_path="*\\AppData\\Local\\Temp\\*" OR Filesystem.file_path="*\\Windows\\Temp\\*")) OR (Processes.process_name="node.exe" AND (Processes.process_path="*\\AppData\\Local\\Temp\\*" OR Processes.process_path="*\\Windows\\Temp\\*")))
| `drop_dm_object_name(Filesystem)`
| `drop_dm_object_name(Processes)`

--# Create a field to distinguish between file creation and process execution events.
| eval event_type=if(isnotnull(file_name), "zip_creation", "node_execution")

--# Group the two events into a single transaction if they occur on the same host within 5 minutes.
--# The transaction must start with the zip creation.
| transaction dest startswith=(event_type="zip_creation") endswith=(event_type="node_execution") maxspan=5m

--# Filter for completed transactions containing both the zip creation and node execution events.
| where eventcount>=2

--# Collect details from the transaction for reporting.
| stats earliest(_time) as firstTime, latest(_time) as lastTime, values(file_path) as zip_file_path, values(process_path) as node_process_path, values(process) as node_process_commandline by dest, user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, zip_file_path, node_process_path, node_process_commandline
```

### NodeInitRAT C2 Communication
---
```sql
--## Title: NodeInitRAT C2 Communication via Cloudflare Tunnel
--##
--## Date: 2025-07-24
--##
--## MITRE ATT&CK:
--##   - T1071.001: Application Layer Protocol: Web Protocols
--##
--## References:
--##   - https://redcanary.com/blog/threat-intelligence/mocha-manakin-nodejs-backdoor/
--##
--## Description:
--## Detects HTTP POST requests to URIs ending in "/init1234" directed towards "trycloudflare.com" domains.
--## This specific network pattern is a known indicator of command-and-control (C2) communications
--## for the NodeInitRAT backdoor, used by the Mocha Manakin threat actor.
--##
--## False Positives:
--## While legitimate applications may use Cloudflare tunnels, the combination of an HTTP POST to a URI
--## path ending in "/init1234" is highly specific to NodeInitRAT. False positives are unlikely.
--##
--## Data Source:
--## Requires network traffic logs (e.g., proxy, firewall, EDR) mapped to the Splunk Common
--## Information Model (CIM) Web data model.
--##
--## Splunk Query
--##
`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.http_method="POST" AND Web.url="*/init1234" AND Web.url="*trycloudflare.com*" by Web.src Web.dest Web.user Web.url Web.http_user_agent
| `drop_dm_object_name("Web")`

--# Key logic: Filters for POST requests to the specific "/init1234" URI path used by NodeInitRAT
--# over the trycloudflare.com domain, which acts as C2 infrastructure.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, src, dest, user, url, http_user_agent, count
```

### NodeInitRAT Reconnaissance Commands
---
```sql
--## Title: Node.js Spawning System Reconnaissance Commands
--##
--## Date: 2025-07-24
--##
--## MITRE ATT&CK:
--##   - T1016: System Network Configuration Discovery
--##   - T1049: System Network Connections Discovery
--##   - T1057: Process Discovery
--##   - T1087: Account Discovery
--##
--## References:
--##   - https://redcanary.com/blog/threat-intelligence/mocha-manakin-nodejs-backdoor/
--##
--## Description:
--## Detects the Node.js runtime (node.exe) spawning common system reconnaissance commands. This behavior is
--## highly anomalous and is a known TTP of the NodeInitRAT backdoor, used by the Mocha Manakin threat actor,
--## to gather information about the compromised host and domain.
--##
--## False Positives:
--## False positives are unlikely, as legitimate Node.js applications or development tools should not typically
--## spawn these specific system utilities. However, some administrative or automation tools built with Node.js
--## might exhibit this behavior.
--##
--## Data Source:
--## Requires process execution logs with command-line details, such as those from Sysmon (Event ID 1) or EDR platforms,
--## mapped to the Splunk Common Information Model (CIM) Endpoint.Processes data model.
--##
--## Splunk Query
--##
`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="node.exe" AND (Processes.process_name IN ("nltest.exe", "net.exe", "setspn.exe", "arp.exe", "tasklist.exe") OR (Processes.process_name IN ("powershell.exe", "pwsh.exe") AND Processes.process="*Get-Service*")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name("Processes")`

--# Key logic: Filters for common reconnaissance tools being executed by the Node.js parent process (node.exe).
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process_name, parent_process, process_name, process, count
```

