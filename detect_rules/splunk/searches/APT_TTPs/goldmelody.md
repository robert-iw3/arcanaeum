### GoldMelody's Exploitation of Leaked Machine Keys
---

GoldMelody, an Initial Access Broker (IAB) also known as TGR-CRI-0045, UNC961, and Prophet Spider, has been actively exploiting leaked ASP.NET Machine Keys to gain unauthorized access to organizations. This actor leverages ASP.NET View State deserialization to execute malicious payloads directly in server memory, minimizing on-disk presence and making detection challenging.


Recent activity by GoldMelody (TGR-CRI-0045) shows a significant increase in exploitation between late January and March 2025, with a focus on deploying post-exploitation tools and custom utilities for persistence and privilege escalation. This includes the use of a custom C# binary named updf for local privilege escalation via the GodPotato exploit and the use of TXPortMap for internal network reconnaissance.

### Actionable Threat Data
---

Monitor for `cmd.exe` invocations originating from w3wp.exe (IIS worker process) with stdout and stderr output redirection, especially when combined with the staging directory `C:\Windows\Temp\111t`.

Look for `HTTP POST` requests to IIS servers containing unusually large or Base64-encoded `__VIEWSTATE` parameters, as this could indicate malicious View State deserialization attempts.

Alert on the creation or modification of files named `updf.exe` or `txp.exe/txpm.exe` in the `C:\Windows\Temp\111t` directory, or any other suspicious executables with one, two, or three-character filenames followed by a rename operation.

Investigate ASP.NET event logs for Event ID 1316, which indicates View State deserialization failures, particularly if the View State contains binaries or encrypted data when encryption is expected to be disabled.

Monitor for network connections from IIS servers to suspicious external IP addresses, such as `195.123.240[.]233`, which has been observed serving post-exploitation tooling.

### Suspicious w3wp.exe Child Process
---
```sql
// This query uses the Endpoint data model to find process creation events.
`tstats` summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where
    -- name: Suspicious IIS Worker Process Child Process
    -- id: 83d18d44-bf44-4d6e-9243-082efa69c816
    -- date: 2025-07-23
    -- description: Detects the IIS worker process (w3wp.exe) spawning a command shell (cmd.exe) with specific arguments associated with the GoldMelody threat actor.
    -- references:
    --   - https://unit42.paloaltonetworks.com/initial-access-broker-exploits-leaked-machine-keys/
    -- mitre_technique: T1059.003
    -- mitre_tactic: TA0002
    -- false_positives: Legitimate administrative scripts that spawn from w3wp.exe and use this specific command structure are possible but highly unlikely. The combination of the parent process, child process, output redirection, and the specific temporary directory is a strong indicator of malicious activity.
    -- data_source:
    --   - Sysmon: EventCode=1
    --   - EDR: Process Creation
    --   - Splunk Add-on for Microsoft Windows
    -- Filter for the IIS worker process (w3wp.exe) spawning a command shell.
    (Processes.parent_process_name="w3wp.exe" AND Processes.process_name="cmd.exe") AND
    -- Look for specific command-line arguments used by the GoldMelody actor.
    -- The combination of output redirection and the specific temp directory is a strong indicator.
    -- This could be tuned by removing the directory path, but that would increase the potential for false positives.
    (Processes.process="*2>&1*" AND Processes.process="*C:\\Windows\\Temp\\111t*")
    -- Group events to create a single alert per unique incident.
    by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `rename` Processes.* as *
| `ctime` lastTime
| `ctime` firstTime
```

### Malicious View State Deserialization
---
```sql
-- name: Malicious View State Deserialization
-- id: c599a9bb-78d9-4ea2-98a0-9aad07f01b9d
-- date: 2025-07-23
-- description: Detects HTTP POST requests with an unusually large `__VIEWSTATE` parameter, which may indicate an ASP.NET View State deserialization attack. Threat actors like GoldMelody use tools like ysoserial.net to embed malicious payloads within the `__VIEWSTATE` parameter to achieve remote code execution.
-- references:
--   - https://unit42.paloaltonetworks.com/initial-access-broker-exploits-leaked-machine-keys/
-- mitre_technique: T1190, T1071.001
-- mitre_tactic: TA0001, TA0011
-- false_positives: Legitimate web applications may use large `__VIEWSTATE` parameters. The length threshold may need to be tuned based on a baseline of normal traffic for your specific applications.
-- data_source:
--   - IIS Logs
--   - Web Proxy Logs
--   - Zeek
--   - EDR Web Telemetry

-- This search requires web logs that include the HTTP method and full POST body (form_data).
-- Adjust the index and sourcetype to match your environment's web data source.
`search` (index=* sourcetype=iis) OR (index=* sourcetype=stream:http) http_method=POST form_data="*__VIEWSTATE=*"
-- Extract the __VIEWSTATE parameter value.
| rex field=form_data "(?i)__VIEWSTATE=(?<viewstate_value>[^&]+)"
-- Calculate the length of the __VIEWSTATE parameter.
| eval viewstate_len=len(viewstate_value)
-- Filter for unusually large __VIEWSTATE values, which may indicate an embedded payload.
-- The threshold of 50000 bytes is a starting point and may need to be tuned for your environment.
| where viewstate_len > 50000
-- Group results to create a single alert per incident.
| stats count min(_time) as firstTime max(_time) as lastTime values(viewstate_len) as viewstate_lengths by src, dest, url, user, http_user_agent
| `ctime` firstTime
| `ctime` lastTime
```

### Suspicious Executable in Temp Dir
---
```sql
-- name: Suspicious Executable in Temp Directory
-- id: 60b98e7b-1757-46c3-9888-3cb4b22889d2
-- date: 2025-07-23
-- description: Detects the creation or renaming of executables in the C:\Windows\Temp\111t\ directory, a tactic used by the GoldMelody threat actor for post-exploitation activities like privilege escalation and reconnaissance.
-- references:
--   - https://unit42.paloaltonetworks.com/initial-access-broker-exploits-leaked-machine-keys/
-- mitre_technique: T1036.005, T1134.001, T1046
-- mitre_tactic: TA0005, TA0004, TA0007
-- false_positives: The use of this specific directory and filenames by legitimate applications is highly unlikely. However, if custom administrative scripts use this path, it could lead to false positives.
-- data_source:
--   - Sysmon: EventCode=1, EventCode=11
--   - EDR: Process Creation, File Creation
--   - Splunk Add-on for Microsoft Windows

-- This query uses the Endpoint data model to find file creation and process execution events.
`tstats` summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint where
    -- This clause detects the creation of specific tools used by GoldMelody in their staging directory.
    ( (nodename=Endpoint.Filesystem Filesystem.file_path="*\\Windows\\Temp\\111t\\*" AND Filesystem.file_name IN ("updf.exe", "txp.exe", "txpm.exe")) OR
    -- This clause detects the renaming of files to executables in the staging directory, a defense evasion technique used by the actor.
    (nodename=Endpoint.Processes Processes.process_name="cmd.exe" AND Processes.process="* move *\\Windows\\Temp\\111t\\* *\\Windows\\Temp\\111t\\*.exe*") )
-- Group events to create a single alert per unique incident.
by nodename, Endpoint.dest, Endpoint.user, Endpoint.parent_process, Endpoint.process_name, Endpoint.process, Endpoint.file_path, Endpoint.file_name
| `rename` Endpoint.* as *
| `ctime` firstTime
| `ctime` lastTime
```

### ASP.NET View State Deserialization Failure
---
```sql
-- name: ASP.NET View State Deserialization Failure
-- id: 3ef0f9c2-fca0-47a4-b5d5-9a40791127fd
-- date: 2025-07-23
-- description: Detects ASP.NET event 1316, which indicates a View State deserialization failure. This event, especially when the message contains keywords related to object serialization gadgets or binary data, can be an indicator of an attempted View State deserialization attack, a technique used by actors like GoldMelody.
-- references:
--   - https://unit42.paloaltonetworks.com/initial-access-broker-exploits-leaked-machine-keys/
-- mitre_technique: T1190
-- mitre_tactic: TA0001
-- false_positives: Legitimate application errors can also trigger Event ID 1316. This rule attempts to reduce false positives by searching for keywords associated with known exploitation tools and techniques. The keywords in the `where` clause may need to be tuned for specific environments to avoid legitimate error messages.
-- data_source:
--   - Windows Event Log (Application)

-- Search for Windows Application event logs.
`search` (sourcetype=WinEventLog:Application OR sourcetype=xmlwineventlog)
-- Filter for ASP.NET View State validation failure events (Event ID 1316).
EventCode=1316 Source_Name="ASP.NET*"
-- Further filter for messages indicating a potentially malicious payload.
-- This looks for keywords associated with deserialization gadgets or embedded assemblies.
-- These keywords may need to be tuned based on legitimate application errors.
| where match(Message, "(?i)Xaml|Assembly|ysoserial|ExploitClass|Base64")
-- Group similar events to reduce alert volume.
| stats count min(_time) as firstTime max(_time) as lastTime values(Message) as Messages by host, user, Source_Name
| `ctime` firstTime
| `ctime` lastTime
```

### Connection to GoldMelody C2
---
```sql
-- name: Connection to GoldMelody C2
-- id: b58d2f87-af3d-458d-95af-5c327bd3acc6
-- date: 2025-07-23
-- description: Detects network connections to an IP address (195.123.240.233) known to be used by the GoldMelody threat actor for serving post-exploitation tooling.
-- references:
--   - https://unit42.paloaltonetworks.com/initial-access-broker-exploits-leaked-machine-keys/
-- mitre_technique: T1105
-- mitre_tactic: TA0011
-- false_positives: This IP address could be reallocated in the future and used for benign purposes. If this IP is part of a shared hosting environment, legitimate traffic could also be observed.
-- data_source:
--   - Firewall Logs
--   - Netflow
--   - Zeek
--   - EDR Network Telemetry

-- This query uses the Network_Traffic data model to find outbound connections.
`tstats` summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where
    -- Filter for connections to the known malicious IP address.
    Network_Traffic.dest_ip="195.123.240.233"
    -- Group events to create a single alert per unique connection.
    by Network_Traffic.src, Network_Traffic.dest, Network_Traffic.dest_ip, Network_Traffic.user, Network_Traffic.dest_port
| `rename` Network_Traffic.* as *
| `ctime` firstTime
| `ctime` lastTime
```

### GoldMelody Reflective .NET Assembly
---
```sql
-- name: GoldMelody Reflective .NET Assembly
-- id: cc8e3ccb-2ee4-4062-bbc6-501eedca89b3
-- date: 2025-07-23
-- description: Detects known reflective .NET assemblies used by the GoldMelody threat actor for in-memory execution.
-- references:
--   - https://unit42.paloaltonetworks.com/initial-access-broker-exploits-leaked-machine-keys/
-- mitre_technique: T1587.001
-- mitre_tactic: TA0043
-- false_positives: The likelihood of a false positive is low, as this detection is based on specific file hashes.
-- data_source:
--   - EDR
--   - Sysmon
--   - Antivirus Logs

-- This query uses the Endpoint data model to find files by their hash.
`tstats` summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.All_Endpoint where
    -- Filter for events where the file hash matches one of the known malicious hashes.
    All_Endpoint.hash IN ("106506ebc7156be116fe5d2a4d662917ddbbfb286007b6ee7a2b01c9536b1ee4", "87bd7e24af5f10fe1e01cfa640ce26e9160b0e0e13488d7ee655e83118d16697", "55656f7b2817087183ceedeb4d9b78d3abee02409666bffbe180d6ea87ee20fb", "18a90b3702776b23f87738b26002e013301f60d9801d83985a57664b133cadd1", "d5d0772cb90d54ac3e3093c1ea9fcd7b878663f7ddd1f96efea0725ce47d46d5", "b3c085672ac34f1b738879096af5fcd748953116e319367e6e371034366eaeca")
    -- Group events to create a single alert per host and hash.
    by All_Endpoint.dest, All_Endpoint.user, All_Endpoint.file_name, All_Endpoint.hash
| `rename` All_Endpoint.* as *
| `ctime` firstTime
| `ctime` lastTime
```

### GoldMelody Post-Exploitation Tooling
---
```sql
-- name: GoldMelody Post-Exploitation Tooling
-- id: 01dc2c0b-8e9d-46d8-b910-d47ef1dadb0f
-- date: 2025-07-23
-- description: Detects post-exploitation tools such as TxPortMap and updf, which are used by the GoldMelody threat actor.
-- references:
--   - https://unit42.paloaltonetworks.com/initial-access-broker-exploits-leaked-machine-keys/
-- mitre_technique: T1587.001, T1105
-- mitre_tactic: TA0043, TA0011
-- false_positives: The likelihood of a false positive is low, as this detection is based on specific file hashes.
-- data_source:
--   - EDR
--   - Sysmon
--   - Antivirus Logs

-- This query uses the Endpoint data model to find files by their hash.
`tstats` summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.All_Endpoint where
    -- Filter for events where the file hash matches one of the known malicious hashes.
    All_Endpoint.hash IN ("d4bfaf3fd3d3b670f585114b4619aaf9b10173c5b1e92d42be0611b6a9b1eff2", "c1f66cadc1941b566e2edad0d1f288c93bf060eef383c79638306638b6cefdf8", "52a72f899991506d2b1df958dd8736f7baa26592d664b771c3c3dbaef8d3114a", "d3767be11d9b211e74645bf434c9a5974b421cb96ec40d856f4b232a5ef9e56d", "f368ec59fb970cc23f955f127016594e2c72de168c776ae8a3f9c21681860e9c")
    -- Group events to create a single alert per host and hash.
    by All_Endpoint.dest, All_Endpoint.user, All_Endpoint.file_name, All_Endpoint.hash
| `rename` All_Endpoint.* as *
| `ctime` firstTime
| `ctime` lastTime
```

### GoldMelody Exploitation IP
---
```sql
-- name: GoldMelody Exploitation IP
-- id: ae203611-3cbc-4324-8e02-8e5a02ccca30
-- date: 2025-07-23
-- description: Detects inbound network connections from IP addresses known to be used by the GoldMelody threat actor to deliver malicious __VIEWSTATE payloads.
-- references:
--   - https://unit42.paloaltonetworks.com/initial-access-broker-exploits-leaked-machine-keys/
-- mitre_technique: T1190
-- mitre_tactic: TA0001
-- false_positives: These IP addresses could be reallocated in the future and used for benign purposes. If any of these IPs are part of a shared hosting environment or a NAT pool, legitimate traffic could also be observed.
-- data_source:
--   - Firewall Logs
--   - Netflow
--   - Zeek
--   - EDR Network Telemetry

-- This query uses the Network_Traffic data model to find inbound connections from known malicious IPs.
`tstats` summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where
    -- Filter for connections where the source IP matches one of the known malicious IPs.
    Network_Traffic.src_ip IN ("67.43.234.96", "213.252.232.237", "98.159.108.69", "190.211.254.95", "109.176.229.89", "169.150.198.91", "194.5.82.11", "138.199.21.243", "194.114.136.95")
    -- Group events to create a single alert per unique connection.
    by Network_Traffic.src, Network_Traffic.dest, Network_Traffic.src_ip, Network_Traffic.user, Network_Traffic.dest_port
| `rename` Network_Traffic.* as *
| `ctime` firstTime
| `ctime` lastTime
```