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

-- Data Source: Network logs (logs-network-*).
-- Query Strategy: Filter for traffic to satellite control systems from non-authorized, non-private IPs, aggregate by source and destination, and exclude allowlisted IPs.
-- False Positive Tuning: Use comprehensive authorized IP lists.

FROM logs-network-*
| WHERE event.action == "allowed"
  AND (destination.ip IN ("198.18.0.1") OR destination.domain IN ("sat-control.corp.net"))
  AND NOT source.ip IN ("203.0.113.10", "198.51.100.55", "192.0.2.0/24")
  AND NOT (
    source.ip LIKE "10.%.%.%" OR
    source.ip LIKE "172.16.%.%" OR
    source.ip LIKE "172.17.%.%" OR
    source.ip LIKE "172.18.%.%" OR
    source.ip LIKE "172.19.%.%" OR
    source.ip LIKE "172.20.%.%" OR
    source.ip LIKE "172.21.%.%" OR
    source.ip LIKE "172.22.%.%" OR
    source.ip LIKE "172.23.%.%" OR
    source.ip LIKE "172.24.%.%" OR
    source.ip LIKE "172.25.%.%" OR
    source.ip LIKE "172.26.%.%" OR
    source.ip LIKE "172.27.%.%" OR
    source.ip LIKE "172.28.%.%" OR
    source.ip LIKE "172.29.%.%" OR
    source.ip LIKE "172.30.%.%" OR
    source.ip LIKE "172.31.%.%" OR
    source.ip LIKE "192.168.%.%"
  )
| STATS
    EventCount = COUNT(*),
    FirstSeen = MIN(@timestamp),
    LastSeen = MAX(@timestamp),
    DestinationPorts = MV_CONCAT(DISTINCT destination.port)
  BY source.ip, destination.ip, destination.domain
| KEEP FirstSeen, LastSeen, source.ip, destination.ip, destination.domain, DestinationPorts, EventCount
| RENAME source.ip AS SourceIP, destination.ip AS DestinationIP, destination.domain AS DestinationHost
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

-- Data Source: Network logs (logs-network-*).
-- Query Strategy: Filter for large data transfers to satellite control systems from non-authorized, non-private IPs, aggregate by source and destination, and exclude allowlisted IPs.
-- False Positive Tuning: Adjust byte threshold based on baseline.

FROM logs-network-*
| WHERE (destination.ip IN ("198.18.0.1") OR destination.domain IN ("sat-control.corp.net"))
  AND NOT source.ip IN ("203.0.113.10", "198.51.100.55", "192.0.2.0/24")
  AND NOT (
    source.ip LIKE "10.%.%.%" OR
    source.ip LIKE "172.16.%.%" OR
    source.ip LIKE "172.17.%.%" OR
    source.ip LIKE "172.18.%.%" OR
    source.ip LIKE "172.19.%.%" OR
    source.ip LIKE "172.20.%.%" OR
    source.ip LIKE "172.21.%.%" OR
    source.ip LIKE "172.22.%.%" OR
    source.ip LIKE "172.23.%.%" OR
    source.ip LIKE "172.24.%.%" OR
    source.ip LIKE "172.25.%.%" OR
    source.ip LIKE "172.26.%.%" OR
    source.ip LIKE "172.27.%.%" OR
    source.ip LIKE "172.28.%.%" OR
    source.ip LIKE "172.29.%.%" OR
    source.ip LIKE "172.30.%.%" OR
    source.ip LIKE "172.31.%.%" OR
    source.ip LIKE "192.168.%.%"
  )
| STATS
    TotalBytesTransferred = SUM(network.bytes),
    FirstSeen = MIN(@timestamp),
    LastSeen = MAX(@timestamp),
    DestinationPorts = MV_CONCAT(DISTINCT destination.port)
  BY source.ip, destination.ip, destination.domain
| WHERE TotalBytesTransferred > 1000000
| KEEP FirstSeen, LastSeen, source.ip, destination.ip, destination.domain, DestinationPorts, TotalBytesTransferred
| RENAME source.ip AS SourceIP, destination.ip AS DestinationIP, destination.domain AS DestinationHost
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

-- Data Source: Sysmon logs (logs-endpoint.events-*, Event Codes 3, 11).
-- Query Strategy: Correlate network connections (Event Code 3) and firmware file creation (Event Code 11) by process PID, filter for unauthorized external IPs, and aggregate by host and file path.
-- False Positive Tuning: Exclude legitimate update processes.

FROM logs-endpoint.events-*
| WHERE event.code IN ("3", "11")
  AND host.hostname IN ("sat-control-win.corp.net", "sat-control-lnx.corp.net")
| STATS
    EventCodes = MV_CONCAT(DISTINCT event.code),
    FilePath = MV_CONCAT(DISTINCT file.path),
    RemoteIP = MV_CONCAT(DISTINCT source.ip),
    ProcessName = MV_CONCAT(DISTINCT process.name),
    User = MV_CONCAT(DISTINCT user.name)
  BY host.hostname, process.pid
| WHERE EventCodes LIKE "*3*" AND EventCodes LIKE "*11*"
| WHERE (
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
| WHERE NOT (
    RemoteIP IN ("203.0.113.10", "198.51.100.55", "192.0.2.0/24") OR
    RemoteIP LIKE "10.%.%.%" OR
    RemoteIP LIKE "172.16.%.%" OR
    RemoteIP LIKE "172.17.%.%" OR
    RemoteIP LIKE "172.18.%.%" OR
    RemoteIP LIKE "172.19.%.%" OR
    RemoteIP LIKE "172.20.%.%" OR
    RemoteIP LIKE "172.21.%.%" OR
    RemoteIP LIKE "172.22.%.%" OR
    RemoteIP LIKE "172.23.%.%" OR
    RemoteIP LIKE "172.24.%.%" OR
    RemoteIP LIKE "172.25.%.%" OR
    RemoteIP LIKE "172.26.%.%" OR
    RemoteIP LIKE "172.27.%.%" OR
    RemoteIP LIKE "172.28.%.%" OR
    RemoteIP LIKE "172.29.%.%" OR
    RemoteIP LIKE "172.30.%.%" OR
    RemoteIP LIKE "172.31.%.%" OR
    RemoteIP LIKE "192.168.%.%"
  )
| STATS
    ProcessName = MV_CONCAT(DISTINCT ProcessName),
    User = MV_CONCAT(DISTINCT User),
    UnauthorizedSourceIPs = MV_CONCAT(DISTINCT RemoteIP)
  BY host.hostname, FilePath
| RENAME host.hostname AS SatelliteControlSystem, FilePath AS FirmwareFile
| KEEP SatelliteControlSystem, FirmwareFile, ProcessName, User, UnauthorizedSourceIPs
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

-- Data Source: Windows Application Event Logs (logs-windows-*, Event Code 1000) and Sysmon logs (logs-endpoint.events-*, Event Code 3).
-- Query Strategy: Correlate crashes with prior network connections by process PID within a 5-minute window, filter for critical applications, and aggregate by host and process.
-- False Positive Tuning: Exclude unstable applications.

FROM logs-windows-*
| WHERE event.code == "1000"
  AND winlog.event_data.TargetImage IN ("tc_handler.exe", "sat_control_app.exe", "obsw_main.exe", "FlyingLaptop.exe")
| EVAL ProcessId = TO_INT(REGEXP_SUBSTR(winlog.event_data.Message, "Faulting process id: 0x([0-9a-f]+)", 1), 16)
| JOIN (
  FROM logs-endpoint.events-*
  | WHERE event.code == "3"
    AND @timestamp >= NOW() - 5 minutes
    AND @timestamp <= NOW()
  | KEEP @timestamp, host.hostname, process.pid, source.ip, source.port, destination.port
) ON host.hostname = host.hostname AND ProcessId = process.pid
| STATS
    CrashedApplication = MV_CONCAT(DISTINCT winlog.event_data.TargetImage),
    SourceIP = MV_CONCAT(DISTINCT source.ip),
    SourcePort = MV_CONCAT(DISTINCT source.port),
    DestinationPort = MV_CONCAT(DISTINCT destination.port)
  BY @timestamp, host.hostname, ProcessId
| RENAME @timestamp AS CrashTime, host.hostname AS SatelliteControlSystem, ProcessId AS CrashedProcessID
| KEEP CrashTime, SatelliteControlSystem, CrashedProcessID, CrashedApplication, SourceIP, SourcePort, DestinationPort
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

-- Data Source: Sysmon logs (logs-endpoint.events-*, Event Code 11).
-- Query Strategy: Filter for files matching vulnerable library names and extensions, aggregate by host and file path, and include hashes for verification.
-- False Positive Tuning: Verify library versions using hashes.

FROM logs-endpoint.events-*
| WHERE event.code == "11"
  AND host.hostname IN ("sat-control-win.corp.net", "sat-control-lnx.corp.net")
  AND (
    LOWER(file.path) LIKE "%uffs%" OR
    LOWER(file.path) LIKE "%libcsp%"
  ) AND (
    file.path MATCHES "(?i)\.dll$" OR
    file.path MATCHES "(?i)\.so$" OR
    file.path MATCHES "(?i)\.a$"
  )
| STATS
    LastSeen = MAX(@timestamp),
    User = MV_CONCAT(DISTINCT user.name),
    LibraryHashes = MV_CONCAT(DISTINCT file.hash.sha1)
  BY host.hostname, file.path
| RENAME host.hostname AS SatelliteControlSystem, file.path AS LibraryPathAndName
| KEEP LastSeen, SatelliteControlSystem, LibraryPathAndName, User, LibraryHashes
```