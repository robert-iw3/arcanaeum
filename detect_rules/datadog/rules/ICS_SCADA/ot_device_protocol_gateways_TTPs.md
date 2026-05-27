### Detecting OT Devices Across Protocol Gateways
---

This report summarizes the challenges and methods for detecting Operational Technology (OT) devices across various industrial protocols, highlighting the increasing convergence of IT and OT networks. It emphasizes the need for robust discovery and monitoring to secure these critical environments against evolving threats.

Recent intelligence indicates a significant increase in internet-exposed OT devices and a rise in sophisticated attacks targeting the IT/OT convergence points, including the exploitation of vulnerabilities in common OT protocols like Modbus and DNP3, and the use of new malware specifically designed for OT environments. Notably, a critical Erlang/OTP SSH vulnerability (CVE-2025-32433) is being actively exploited, disproportionately affecting OT networks and demonstrating how IT-centric vulnerabilities can bridge into operational threats.

### Actionable Threat Data
---

Monitor for unusual Modbus TCP/IP (port 502) or DNP3 (port 20000) traffic patterns, especially connections originating from or destined for external networks, as these protocols often lack strong authentication and encryption, making them vulnerable to unauthorized access and data tampering.

Implement network segmentation to isolate OT networks from IT networks and the internet, and monitor for any unauthorized communication attempts across these boundaries (e.g., IT assets attempting to connect directly to PLCs or other OT devices).

Detect attempts to enumerate or "banner sniff" OT devices using protocols like Modbus and DNP3, as this reconnaissance activity often precedes targeted attacks. Look for repeated connection attempts to common OT ports from unusual sources.

Monitor for the exploitation of known vulnerabilities in industrial control systems and their associated protocols, such as the Erlang/OTP SSH vulnerability (CVE-2025-32433) which has been observed to affect OT networks. Look for SSH connections on non-standard ports (e.g., TCP 2222) or unexpected command execution.

Establish baselines for normal communication patterns and device identities within your OT environment and alert on deviations, such as new or unrecognized devices appearing on the network, changes in device configurations, or unexpected protocol usage.

### Search
---
```sql
-- Name: External Communication to OT Protocols (Modbus/DNP3)
-- Description: Detects network traffic to or from external IP addresses on ports commonly used for OT protocols like Modbus (502) and DNP3 (20000). This could indicate misconfigured devices, unauthorized remote access, or reconnaissance against industrial control systems.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK:
-- - T1071.004: Application Layer Protocol: File Transfer Protocols
-- - T1090: Proxy
-- - T1572: Protocol Tunneling
-- False Positive Sensitivity: Medium
-- - Legitimate remote administration, cloud-based SCADA monitoring services, or connections from business partners may use these protocols over the internet.
-- References:
-- - https://www.veridify.com/dnp3-security-risks/
-- - https://www.veridify.com/modbus-security-issues-and-how-to-mitigate-cyber-risks/

-- Data Source: Network logs from firewalls, IDS/IPS, or OT monitoring platforms.
-- Query Strategy: Filter for traffic on OT ports crossing internal/external boundaries, exclude allowlisted IPs, and aggregate by source/destination.
-- False Positive Tuning: Use tags for authorized external IPs.

logs(
  source:network
  @host:(plc* OR rtu* OR ot*)
  network.dest_port:(502 OR 20000)
)
| eval
    is_src_private = case(
      network.src_ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16), 1,
      0
    ),
    is_dest_private = case(
      network.dest_ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16), 1,
      0
    )
| where is_src_private != is_dest_private
| exclude network.src_ip:(@ot_ip_allowlist) OR network.dest_ip:(@ot_ip_allowlist)
| eval protocol = case(
    network.dest_port = 502, "Modbus",
    network.dest_port = 20000, "DNP3",
    true, "Other"
  )
| group by network.src_ip, network.dest_ip, network.dest_port
| select
    min(@timestamp) as FirstTime,
    max(@timestamp) as LastTime,
    network.src_ip as SrcIp,
    network.dest_ip as DestIp,
    network.dest_port as DestPort,
    protocol as Protocol,
    count as ConnectionCount
| display FirstTime, LastTime, SrcIp, DestIp, DestPort, Protocol, ConnectionCount
```
---
```sql
-- Name: Unauthorized IT to OT Network Communication
-- Description: Detects network traffic originating from the IT network and connecting to devices on the OT network over common industrial protocol ports. This can indicate a breach of network segmentation policies, unauthorized access attempts, or lateral movement from IT to OT environments.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK:
-- - T1090: Proxy
-- - T1572: Protocol Tunneling
-- False Positive Sensitivity: Medium
-- References:
-- - https://www.cisa.gov/uscert/ics/publications/recommended-practice-improving-industrial-control-system-cybersecurity-network

-- Data Source: Network logs from firewalls or OT monitoring platforms.
-- Query Strategy: Filter for IT-to-OT traffic on OT ports, exclude authorized connections, and aggregate by source/destination.
-- False Positive Tuning: Use tags for IT/OT subnets and authorized connections.

logs(
  source:network
  network.src_ip:(@it_subnets)
  network.dest_ip:(@ot_subnets)
  network.dest_port:(@ot_ports)
)
| eval connection_key = network.src_ip + ":" + network.dest_ip + ":" + network.dest_port
| exclude connection_key:(@authorized_it_ot_connections)
| eval protocol = case(
    network.dest_port = 502, "Modbus",
    network.dest_port = 20000, "DNP3",
    network.dest_port = 44818, "EtherNet/IP (TCP)",
    network.dest_port = 2222, "EtherNet/IP (UDP)",
    true, "Other"
  )
| group by network.src_ip, network.dest_ip, network.dest_port
| select
    min(@timestamp) as FirstTime,
    max(@timestamp) as LastTime,
    network.src_ip as SourceIT_IP,
    network.dest_ip as DestinationOT_IP,
    network.dest_port as DestinationPort,
    protocol as Protocol,
    count as ConnectionCount
| display FirstTime, LastTime, SourceIT_IP, DestinationOT_IP, DestinationPort, Protocol, ConnectionCount
```
---
```sql
-- Name: OT Protocol Scanning (Banner Sniffing)
-- Description: Detects potential reconnaissance activity where a single source IP address attempts to connect to multiple distinct devices on common Operational Technology (OT) ports. This behavior is indicative of an adversary performing "banner sniffing" or enumeration to gather information about OT assets, which often precedes a targeted attack. This rule identifies scanning from both internal and external sources.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK:
-- - T1595: Active Scanning
-- - T1590: Gather Victim Network Information
-- False Positive Sensitivity: Medium
-- - Legitimate systems such as vulnerability scanners, network management tools, or data historians may exhibit this behavior.

-- Data Source: Network logs from firewalls or OT monitoring platforms.
-- Query Strategy: Identify sources scanning multiple OT devices, exclude authorized scanners, and aggregate by source IP.
-- False Positive Tuning: Use tags for scanner allowlist and threshold tuning.

logs(
  source:network
  @host:(plc* OR rtu* OR ot*)
  network.dest_port:(@ot_ports)
  -network.src_ip:(@scanner_ip_allowlist)
)
| group by network.src_ip, network.dest_ip, network.dest_port, @timestamp
| group by network.src_ip
| select
    min(@timestamp) as StartTime,
    max(@timestamp) as EndTime,
    count_distinct(network.dest_ip) as DistinctOTDevicesScanned,
    values(network.dest_ip) as ScannedOT_IPs,
    values(network.dest_port) as ScannedPorts,
    count as TotalConnections,
    case(
      network.src_ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16), "Internal",
      true, "External"
    ) as ScannerLocation
| where DistinctOTDevicesScanned > 3
| rename network.src_ip as ScannerIP
| display StartTime, EndTime, ScannerIP, ScannerLocation, DistinctOTDevicesScanned, TotalConnections, ScannedOT_IPs, ScannedPorts
```
---
```sql
-- Name: Erlang/OTP SSH Vulnerability Exploitation (CVE-2025-32433)
-- Description: Detects potential exploitation of a fictional Erlang/OTP SSH vulnerability (CVE-2025-32433). The rule identifies two key patterns associated with this threat: 1) Erlang-related processes accepting inbound connections on non-standard SSH ports (e.g., 2222), which is a primary indicator of the exploit attempt, especially in OT networks. 2) Erlang-related processes spawning command shells, indicating successful post-exploitation and remote code execution.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK:
-- - T1190: Exploit Public-Facing Application
-- - T1021: Remote Services
-- - T1059: Command and Scripting Interpreter
-- False Positive Sensitivity: Medium
-- - Some legitimate applications built on Erlang/OTP may use SSH on non-standard ports for administrative purposes.
-- - Spawning a shell from an Erlang process is highly suspicious but could occur in bespoke management scripts.
-- References:
-- - https://unit42.paloaltonetworks.com/erlang-otp-cve-2025-32433/
-- - https://gbhackers.com/erlang-otp-ssh-rce-vulnerability-actively-exploited/

-- Data Source: Endpoint logs for process and port activity.
-- Query Strategy: Identify Erlang processes on non-standard SSH ports or spawning shells, focus on OT networks, and aggregate by host.
-- False Positive Tuning: Exclude legitimate Erlang-based applications.

-- Tactic 1: Non-Standard SSH Port Connections
logs(
  source:endpoint
  @host:(plc* OR rtu* OR ot*)
  network.dest_port:(@non_standard_ssh_ports)
  process.name:(@erlang_processes)
)
| group by @host, process.name, network.dest_port, network.src_ip, @timestamp
| select
    @timestamp as Time,
    "Non-Standard SSH Port Connection to Erlang Process" as Activity,
    @host as Host,
    process.name as ProcessName,
    "N/A" as ParentProcessName,
    "N/A" as CommandLine,
    network.dest_port as LocalPort,
    network.src_ip as RemoteIp

-- Tactic 2: Shell Spawning by Erlang Process
| union(
  logs(
    source:endpoint
    @host:(plc* OR rtu* OR ot*)
    process.name:(@shell_processes)
    process.parent.name:(@erlang_processes)
  )
  | group by @host, process.name, process.parent.name, @timestamp
  | select
      @timestamp as Time,
      "Shell Spawned by Erlang Process" as Activity,
      @host as Host,
      process.name as ProcessName,
      process.parent.name as ParentProcessName,
      process.command_line as CommandLine,
      "N/A" as LocalPort,
      "N/A" as RemoteIp
)

| display Time, Activity, Host, ProcessName, ParentProcessName, CommandLine, LocalPort, RemoteIp
```
---
```sql
-- Name: OT Network Baseline Deviations
-- Description: Detects new devices or new communication patterns within the Operational Technology (OT) network by comparing recent activity against a historical baseline. This can indicate newly connected (and potentially unauthorized) devices, or existing devices being used in an anomalous way, which could be a precursor to or part of a malicious attack.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK:
-- - T1592: Gather Victim Host Information
-- - T1595: Active Scanning
-- - T1083: File and Directory Discovery
-- False Positive Sensitivity: Medium
-- - This rule will trigger when new devices are legitimately added to the OT network or when device configurations are intentionally changed. These events should be reviewed and acknowledged.

-- Data Source: Network logs from OT monitoring platforms or firewalls.
-- Query Strategy: Identify new devices or new port usage in the OT network, exclude baseline activity, and aggregate by device.
-- False Positive Tuning: Use tags for OT subnets and pre-populated asset lists.

-- Tactic 1: New OT Devices
logs(
  source:network
  @host:(plc* OR rtu* OR ot*)
  network.dest_ip:(@ot_subnets)
  @timestamp:[NOW-1d TO NOW]
)
| group by network.dest, network.dest_ip
| select
    min(@timestamp) as StartTime,
    max(@timestamp) as EndTime,
    values(network.dest_port) as Port,
    values(network.src_ip) as ConnectedRemoteIPs,
    "New OT Device Detected" as DeviationType,
    network.dest as DeviceName,
    network.dest_ip as OT_DeviceIP,
    "New device appeared on the OT network. Ports used: " + mvjoin(network.dest_port, ", ") as Details
| exclude network.dest_ip IN (
  logs(
    source:network
    network.dest_ip:(@ot_subnets)
    @timestamp:[NOW-14d TO NOW-1d]
  )
  | group by network.dest_ip
  | select network.dest_ip
)

-- Tactic 2: New Communication Patterns
| union(
  logs(
    source:network
    network.dest_ip:(@ot_subnets)
    @host:(plc* OR rtu* OR ot*)
    @timestamp:[NOW-1d TO NOW]
  )
  | group by network.dest, network.dest_ip, network.dest_port
  | select
      min(@timestamp) as StartTime,
      max(@timestamp) as EndTime,
      values(network.src_ip) as ConnectedRemoteIPs,
      network.dest_port as Port,
      "New OT Communication Pattern Detected" as DeviationType,
      network.dest as DeviceName,
      network.dest_ip as OT_DeviceIP,
      "Existing device communicated on a new port: " + network.dest_port + ". Connected from/to remote IPs: " + mvjoin(network.src_ip, ", ") as Details
  | exclude (network.dest_ip + ":" + network.dest_port) IN (
    logs(
      source:network
      network.dest_ip:(@ot_subnets)
      @timestamp:[NOW-14d TO NOW-1d]
    )
    | group by network.dest_ip, network.dest_port
    | select network.dest_ip + ":" + network.dest_port as device_port_key
  )
  | where network.dest_ip IN (
    logs(
      source:network
      network.dest_ip:(@ot_subnets)
      @timestamp:[NOW-14d TO NOW-1d]
    )
    | group by network.dest_ip
    | select network.dest_ip
  )
)

| display StartTime, EndTime, DeviationType, DeviceName, OT_DeviceIP, Details, ConnectedRemoteIPs, Port
```