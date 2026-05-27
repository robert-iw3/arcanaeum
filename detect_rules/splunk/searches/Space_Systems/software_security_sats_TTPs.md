### Space Odyssey: An Experimental Software Security Analysis of Satellites
---

This report analyzes the security of satellite firmware, identifying critical vulnerabilities across three real-world satellites and highlighting the prevalence of outdated security assumptions and practices in the space industry. The key takeaway is that modern in-orbit satellites are susceptible to various software security vulnerabilities and often lack proper access protection mechanisms, enabling attackers to gain full control.

Recent research indicates a shift in the attacker model, with ground stations becoming more affordable and accessible to private individuals, creating a novel attack surface for adversaries to communicate with satellites and exploit software vulnerabilities. Additionally, the increasing use of Commercial Off-The-Shelf (COTS) components and open-source designs in satellites, particularly in the "New Space Era," means attackers can now gain detailed knowledge of target satellite systems, including their firmware, challenging the outdated assumption of "security by obscurity".

### Actionable Threat Data
---

Unsecured Telecommand Access: Satellites often lack proper authentication and encryption for telecommand (TC) traffic, allowing external attackers with custom ground stations to issue arbitrary commands and potentially seize control.

Memory Corruption Vulnerabilities: Buffer overflows and other memory corruption issues in satellite firmware, particularly in handling TCs, can lead to arbitrary code execution and full system compromise.

Insecure Software Updates: The ability to upload malicious firmware images to satellites without sufficient verification or authentication allows attackers to gain persistent control.

Trusted Size Field Vulnerabilities: Insufficient validation of size fields in communication protocols can lead to buffer overflows and allow semi-privileged operators or attackers to alter TCs.

Vulnerable Libraries: The use of outdated or insecure third-party libraries (e.g., uffs and libCSP) in satellite firmware introduces known vulnerabilities, such as buffer overflows and cryptographic weaknesses, that can be exploited.

### Unsecured TC Access
---
```sql
-- name: Unauthorized External Communication with Satellite Control Systems
-- author: RW
-- date: 2025-08-18
-- description: Detects network traffic from external, non-authorized IP addresses to known satellite control systems. This activity could represent an attempt by an external attacker to send unsecured telecommands (TCs) to a satellite.
-- references: https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_s25_paper.pdf
-- data_source: network_traffic
-- false_positive_sensitivity: medium

`comment("Define the search for network traffic. Adjust the index and sourcetype for your environment.")`
(index=pan OR index=opnsense OR index=firewall OR sourcetype=aws:vpcflow) action=allowed
`comment("Exclude private source IPs to focus on external traffic.")`
| where NOT (cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("172.16.0.0/12", src_ip) OR cidrmatch("192.168.0.0/16", src_ip))
`comment("Filter results where the source IP is NOT authorized AND the destination IS a satellite control system.")`
| search
    [| makeresults
    `comment("Placeholder list of authorized Ground Station (GS) IPs and administrative networks. This list is critical for reducing false positives and must be populated.")`
    | eval authorized_ips="203.0.113.10,198.51.100.55,192.0.2.0/24"
    `comment("Placeholder list of satellite control system IPs or hostnames that receive telecommands (TCs).")`
    | eval satellite_systems="198.18.0.1,sat-control.corp.net"
    | makemv delim="," authorized_ips
    | makemv delim="," satellite_systems
    | mvexpand authorized_ips
    | mvexpand satellite_systems
    | fields - _time
    `comment("This format command constructs the subsearch to filter the main query.")`
    | format "NOT (src_ip IN (\"$authorized_ips$\")) AND (dest_ip IN (\"$satellite_systems$\") OR dest_host IN (\"$satellite_systems$\"))"
    ]
`comment("Summarize the suspicious traffic for alerting.")`
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime, values(dest_port) as dest_ports by src_ip, dest_ip, dest_host
| `ctime(firstTime)`
| `ctime(lastTime)`
| rename src_ip as "Source IP", dest_ip as "Destination IP", dest_host as "Destination Host", dest_ports as "Destination Ports", count as "Event Count", firstTime as "First Seen", lastTime as "Last Seen"
`comment("FP Mitigation: The accuracy of this rule heavily depends on the completeness of the 'authorized_ips' and 'satellite_systems' lists. Regularly review and update these lists with any new legitimate ground stations, partner networks, or administrative access points.")`
```

### Memory Corruption in Firmware
---
```sql
-- name: Potential Memory Corruption Exploit via Large Data Transfer to Satellite Control Systems
-- author: RW
-- date: 2025-08-18
-- description: Detects unusually large data transfers from a single external source to a known satellite control system. This could indicate an attempt to exploit a memory corruption vulnerability (e.g., buffer overflow) in the satellite's firmware by sending a malformed telecommand (TC) with an oversized payload.
-- references: https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_s25_paper.pdf
-- data_source: network_traffic
-- false_positive_sensitivity: medium

`comment("Define the search for network traffic. Adjust the index and sourcetype for your environment.")`
(index=pan OR index=opnsense OR index=firewall OR sourcetype=aws:vpcflow)
`comment("Use a subsearch to filter for traffic from non-authorized sources to satellite control systems.")`
| search
    [| makeresults
    `comment("Placeholder list of authorized Ground Station (GS) IPs. Note: This method does not handle CIDR ranges well. For CIDR support, consider using the 'where' command with cidrmatch() or a lookup file.")`
    | eval authorized_ips="203.0.113.10,198.51.100.55,192.0.2.0/24"
    `comment("Placeholder list of satellite control system IPs or hostnames that receive telecommands (TCs).")`
    | eval satellite_systems="198.18.0.1,sat-control.corp.net"
    | format "NOT (src_ip IN ($authorized_ips$)) AND (dest_ip IN ($satellite_systems$) OR dest_host IN ($satellite_systems$))"
    ]
`comment("Exclude private source IPs to focus on external traffic.")`
| where NOT (cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("172.16.0.0/12", src_ip) OR cidrmatch("192.168.0.0/16", src_ip))
`comment("Summarize traffic from each source to each destination. The 'bytes' field may need to be changed to 'bytes_out' or 'bytes_in' depending on the log source.")`
| stats sum(bytes) as TotalBytes, earliest(_time) as firstTime, latest(_time) as lastTime, values(dest_port) as dest_ports by src_ip, dest_ip, dest_host
`comment("Define the threshold for an unusually large data transfer (in bytes). This is a critical tuning parameter.")`
| where TotalBytes > 1000000
| `ctime(firstTime)`
| `ctime(lastTime)`
| rename src_ip as "Source IP", dest_ip as "Destination IP", dest_host as "Destination Host", dest_ports as "Destination Ports", TotalBytes as "Total Bytes Transferred", firstTime as "First Seen", lastTime as "Last Seen"
`comment("FP Mitigation: The 'TotalBytes' threshold is a heuristic. Legitimate activities like large file transfers or software updates could trigger this. It's crucial to establish a baseline of normal traffic volumes to these specific systems and adjust the threshold accordingly. Also, ensure the 'authorized_ips' and 'satellite_systems' lists are comprehensive and accurate.")`
```

### Insecure Firmware Updates
---
```sql
-- name: Insecure Firmware Update on Satellite Control System
-- author: RW
-- date: 2025-08-18
-- description: Detects the creation of a potential firmware file on a satellite control system by a process that recently received a network connection from an unauthorized external IP address. This could indicate an attempt to upload a malicious firmware image without proper verification.
-- references: https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_s25_paper.pdf
-- data_source: sysmon
-- false_positive_sensitivity: medium

`comment("This rule requires Sysmon Event Logs (EventCodes 3 and 11). Adjust the index and sourcetype as needed.")`
(index=sysmon OR sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational) (EventCode=3 OR EventCode=11)
`comment("Filter for events on designated satellite control systems.")`
| search
    [| makeresults
    `comment("Placeholder list of satellite control system hostnames. This list must be populated.")`
    | eval host="sat-control-win.corp.net,sat-control-lnx.corp.net"
    | makemv delim="," host
    | mvexpand host
    | format]
`comment("Correlate network connections and file creation events by the same process instance.")`
| stats
    values(EventCode) as event_codes,
    values(TargetFilename) as file_path,
    values(SourceIp) as remote_ip,
    values(Image) as process_name,
    values(user) as user by host, ProcessGuid
`comment("Ensure the process both received a network connection (EC3) and created a file (EC11).")`
| where mvfind(event_codes, "3") IS NOT NULL AND mvfind(event_codes, "11") IS NOT NULL
`comment("Filter for files created in common firmware directories with typical firmware extensions.")`
| mvexpand file_path
| where
    (
        like(file_path, "%\\firmware\\updates\\%") OR like(file_path, "%/opt/satellite/firmware/%") OR like(file_path, "%/var/firmware/%")
    )
    AND
    (
        match(file_path, "(?i)\.bin$") OR match(file_path, "(?i)\.img$") OR match(file_path, "(?i)\.hex$") OR match(file_path, "(?i)\.fw$") OR match(file_path, "(?i)\.swu$")
    )
`comment("Filter for connections from external IPs that are not on the authorized list.")`
| mvexpand remote_ip
| where NOT (cidrmatch("10.0.0.0/8", remote_ip) OR cidrmatch("172.16.0.0/12", remote_ip) OR cidrmatch("192.168.0.0/16", remote_ip))
| search NOT
    [| makeresults
    `comment("Placeholder list of authorized external IPs (e.g., ground stations, admin networks). This list must be populated.")`
    | eval authorized_ips="203.0.113.10,198.51.100.55,192.0.2.0/24"
    | makemv delim="," authorized_ips
    | mvexpand authorized_ips
    | rename authorized_ips as remote_ip
    | format]
`comment("Aggregate results for alerting.")`
| stats
    values(process_name) as process_name,
    values(user) as user,
    values(remote_ip) as unauthorized_source_ips by host, file_path
| rename host as "Satellite Control System", file_path as "Firmware File", process_name as "Process Name", user as "User", unauthorized_source_ips as "Unauthorized Source IPs"
`comment("FP Mitigation: This detection relies heavily on the accuracy of the satellite control system, authorized IP, and firmware path lists. Legitimate remote administration or automated update processes from IPs not on the allowlist could cause false positives. Establish a baseline of normal update procedures and add any legitimate source IPs or processes to an exclusion list.")`
```

### Trusted Size Field Exploitation
---
```sql
-- name: Satellite Control Application Crash Following Network Connection
-- author: RW
-- date: 2025-08-18
-- description: Detects a crash in a satellite control application that occurs shortly after it received an inbound network connection. This pattern can indicate a successful or attempted exploitation of a memory corruption or trusted size field vulnerability, where a malformed telecommand (TC) causes the application to terminate. This aligns with the "Trusted Size Field" and "Inconsistent Size Field" vulnerabilities, which can lead to buffer overflows.
-- references: https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_s25_paper.pdf
-- data_source: windows_event_log, sysmon
-- false_positive_sensitivity: medium

`comment("This rule requires Windows Application Event Logs (EventCode 1000) and Sysmon Event Logs (EventCode 3).")`
`comment("Start by finding crash events for specified satellite control applications.")`
(index=wineventlog sourcetype=wineventlog:application EventCode=1000)
| search [| makeresults
    `comment("This list must be populated with the process names of your satellite control applications.")`
    | eval process_name="tc_handler.exe,sat_control_app.exe,obsw_main.exe,FlyingLaptop.exe"
    | makemv delim="," process_name
    | format "(\"Faulting application name:\" IN ($process_name$))"
]
`comment("Extract the Process ID from the event message. The PID is needed to correlate with network events.")`
| rex field=Message "Faulting process id: 0x(?<ProcessId_hex>.*)"
| eval ProcessId=tonumber(ProcessId_hex, 16)
| rename "Faulting application name:" as process_name, host
`comment("For each crash, search backwards in time (5 mins) for a network connection event (Sysmon EC3) involving the same process instance.")`
| map maxsearches=1000 search="
    search (index=sysmon sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational) EventCode=3 host=$host$ ProcessId=$ProcessId$ earliest=-5m@m latest=@m
    | head 1
    | eval crash_time=$_time$, process_name=\"$process_name$\", host=\"$host$\", ProcessId=\"$ProcessId$\"
"
`comment("Aggregate the results to create a single alert for each incident.")`
| stats values(process_name) as CrashedApplication, values(SourceIp) as SourceIP, values(SourcePort) as SourcePort, values(DestinationPort) as DestinationPort by crash_time, host, ProcessId
| rename host as SatelliteControlSystem, ProcessId as CrashedProcessID, crash_time as CrashTime
| convert ctime(CrashTime)
`comment("FP Mitigation: This detection may trigger on legitimate but unstable applications that crash frequently. If a specific application is known to be unstable, consider excluding it or increasing the time window for correlation to reduce noise. The primary value is in flagging unexpected crashes in critical, supposedly stable, control software immediately following data reception, which is a strong indicator of an attack attempt.")`
```

### Vulnerable Satellite Libraries
---
```sql
-- name: Potentially Vulnerable Satellite Libraries Found on Control Systems
-- author: RW
-- date: 2025-08-18
-- description: Hunts for files on satellite control systems that may be vulnerable third-party libraries (e.g., uffs, libcsp). The presence of these libraries could expose the system to known vulnerabilities like buffer overflows or cryptographic weaknesses. This query is intended for hunting and asset inventory purposes.
-- references: https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_s25_paper.pdf
-- data_source: sysmon
-- false_positive_sensitivity: medium

`comment("This rule requires file creation events, such as Sysmon EventCode 11. Adjust the index and sourcetype as needed.")`
(index=sysmon OR sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational) EventCode=11
`comment("Filter for events on designated satellite control systems.")`
| search
    [| makeresults
    `comment("This list must be populated with the hostnames of your satellite control systems.")`
    | eval host="sat-control-win.corp.net,sat-control-lnx.corp.net"
    | makemv delim="," host
    | mvexpand host
    | format]
`comment("Filter for filenames containing vulnerable library names and having common library extensions. The search is case-insensitive.")`
| where (
    (match(TargetFilename, "(?i)uffs") OR match(TargetFilename, "(?i)libcsp"))
    AND
    (match(TargetFilename, "(?i)\.dll$") OR match(TargetFilename, "(?i)\.so$") OR match(TargetFilename, "(?i)\.a$"))
)
`comment("Summarize the findings to show the latest instance of each library found, along with its hash.")`
| stats latest(_time) as lastSeen, values(user) as User, values(Hashes) as Hashes by host, TargetFilename
| `ctime(lastSeen)`
| rename host as SatelliteControlSystem, TargetFilename as LibraryPathAndName, Hashes as LibraryHashes
`comment("FP Mitigation: This is a hunting query and may identify files with similar names that are not the actual vulnerable libraries. The primary value is in asset identification. Once a potentially vulnerable library is found, the file hash (e.g., SHA1, MD5) should be used to confirm its identity and version against known vulnerable versions.")`
```