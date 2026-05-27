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

-- Data Source: Network logs from firewalls or VPC flow logs.
-- Query Strategy: Filter for traffic to satellite control systems from non-authorized, non-private IPs, aggregate by source and destination, and exclude allowlisted IPs.
-- False Positive Tuning: Use comprehensive authorized IP lists.

logs(
  source:(pan OR opnsense OR firewall OR vpcflow)
  network.action:allowed
  (network.dest_ip:(@satellite_systems) OR network.dest_host:(@satellite_systems))
  -network.src_ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)
  -network.src_ip:(@authorized_ips)
)
| group by network.src_ip, network.dest_ip, network.dest_host
| select
    min(@timestamp) as FirstSeen,
    max(@timestamp) as LastSeen,
    network.src_ip as SourceIP,
    network.dest_ip as DestinationIP,
    network.dest_host as DestinationHost,
    values(network.dest_port) as DestinationPorts,
    count as EventCount
| display FirstSeen, LastSeen, SourceIP, DestinationIP, DestinationHost, DestinationPorts, EventCount
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

-- Data Source: Network logs from firewalls or VPC flow logs.
-- Query Strategy: Filter for large data transfers to satellite control systems from non-authorized, non-private IPs, aggregate by source and destination, and exclude allowlisted IPs.
-- False Positive Tuning: Adjust byte threshold based on baseline traffic.

logs(
  source:(pan OR opnsense OR firewall OR vpcflow)
  (network.dest_ip:(@satellite_systems) OR network.dest_host:(@satellite_systems))
  -network.src_ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)
  -network.src_ip:(@authorized_ips)
)
| group by network.src_ip, network.dest_ip, network.dest_host
| select
    min(@timestamp) as FirstSeen,
    max(@timestamp) as LastSeen,
    network.src_ip as SourceIP,
    network.dest_ip as DestinationIP,
    network.dest_host as DestinationHost,
    values(network.dest_port) as DestinationPorts,
    sum(network.bytes) as TotalBytesTransferred
| where TotalBytesTransferred > 1000000
| display FirstSeen, LastSeen, SourceIP, DestinationIP, DestinationHost, DestinationPorts, TotalBytesTransferred
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

-- Data Source: Sysmon logs (Event Codes 3 and 11) for network connections and file creation.
-- Query Strategy: Correlate network connections (Event Code 3) and firmware file creation (Event Code 11) by process GUID, filter for unauthorized external IPs, and aggregate by host and file path.
-- False Positive Tuning: Exclude legitimate update processes and IPs.

logs(
  source:sysmon
  event.code:(3 OR 11)
  @host:(@satellite_control_systems)
)
| group by @host, process.guid
| select
    values(event.code) as EventCodes,
    values(file.path) as FilePath,
    values(network.src_ip) as RemoteIP,
    values(process.name) as ProcessName,
    values(@user) as User
| where EventCodes IN (3, 11)
| where (
  FilePath LIKE "%\\firmware\\updates\\%" OR
  FilePath LIKE "%/opt/satellite/firmware/%" OR
  FilePath LIKE "%/var/firmware/%"
) AND (
  FilePath MATCHES "(?i)\.bin$" OR
  FilePath MATCHES "(?i)\.img$" OR
  FilePath MATCHES "(?i)\.hex$" OR
  FilePath MATCHES "(?i)\.fw$" OR
  FilePath MATCHES "(?i)\.swu$"
)
| where NOT RemoteIP IN (10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16 OR @authorized_ips)
| group by @host, FilePath
| select
    values(ProcessName) as ProcessName,
    values(User) as User,
    values(RemoteIP) as UnauthorizedSourceIPs,
    @host as SatelliteControlSystem,
    FilePath as FirmwareFile
| display SatelliteControlSystem, FirmwareFile, ProcessName, User, UnauthorizedSourceIPs
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

-- Data Source: Windows Application Event Logs (Event Code 1000) and Sysmon logs (Event Code 3).
-- Query Strategy: Correlate application crashes with prior network connections by process ID, filter for critical satellite control applications, and aggregate by host and process.
-- False Positive Tuning: Exclude unstable applications and adjust time window.

logs(
  source:wineventlog
  event.source:application
  event.code:1000
  faulting.application.name:(tc_handler.exe OR sat_control_app.exe OR obsw_main.exe OR FlyingLaptop.exe)
)
| eval ProcessId = tonumber(regex_extract(faulting.message, "Faulting process id: 0x([0-9a-f]+)", 1), 16)
| join process.id=ProcessId (
  logs(
    source:sysmon
    event.code:3
    @host = outer.@host
    @timestamp:[outer.@timestamp-5m TO outer.@timestamp]
  )
  | select network.src_ip as SourceIP, network.src_port as SourcePort, network.dest_port as DestinationPort
  | limit 1
)
| group by @timestamp, @host, ProcessId
| select
    @timestamp as CrashTime,
    @host as SatelliteControlSystem,
    ProcessId as CrashedProcessID,
    values(faulting.application.name) as CrashedApplication,
    values(SourceIP) as SourceIP,
    values(SourcePort) as SourcePort,
    values(DestinationPort) as DestinationPort
| display CrashTime, SatelliteControlSystem, CrashedProcessID, CrashedApplication, SourceIP, SourcePort, DestinationPort
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

-- Data Source: Sysmon logs (Event Code 11) for file creation events.
-- Query Strategy: Filter for files matching vulnerable library names and extensions on satellite control systems, aggregate by host and file path, and include file hashes for verification.
-- False Positive Tuning: Verify library versions using hashes.

logs(
  source:sysmon
  event.code:11
  @host:(@satellite_control_systems)
  (
    file.path:(*uffs* OR *libcsp*) AND
    file.path:(*.dll OR *.so OR *.a)
  )
)
| group by @host, file.path
| select
    max(@timestamp) as LastSeen,
    values(@user) as User,
    values(file.hash) as LibraryHashes,
    @host as SatelliteControlSystem,
    file.path as LibraryPathAndName
| display LastSeen, SatelliteControlSystem, LibraryPathAndName, User, LibraryHashes
```