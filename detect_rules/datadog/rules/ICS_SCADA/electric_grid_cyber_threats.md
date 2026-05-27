### Electric Grid Cybersecurity Threat Report
---

This report summarizes the evolving cyber threats to the electric grid, highlighting the increasing sophistication of attacks and the critical need for robust cybersecurity measures. The focus is on understanding the vulnerabilities within Industrial Control Systems (ICS) and Operational Technology (OT) environments that underpin grid operations.

Recent intelligence indicates a significant increase in cyberattacks targeting utilities, with a 70% spike in 2024 compared to the previous year, and the number of susceptible points in the grid increasing by approximately 60 per day. This surge, coupled with the growing reliance on interconnected IoT devices and advanced communication networks in smart grids, expands the attack surface and introduces new vulnerabilities like false data injection attacks and malicious command injections.

### Actionable Threat Data
---

Monitor for anomalous voltage fluctuations and grid oscillations, which can be indicators of physical manipulation or cyber-physical attacks on the grid.

Implement robust network segmentation to isolate critical control systems from business and external networks, limiting lateral movement of attackers within the ICS environment.

Prioritize patching and vulnerability management for internet-connected devices, especially those in distributed energy resources like solar inverters and panels, as they are increasingly targeted due to often weak default security configurations.

Enhance detection capabilities for sophisticated ICS-specific malware (e.g., Industroyer, BlackEnergy, Triton) and techniques like unauthorized command messages to control systems devices.

Strengthen authentication mechanisms and access controls for all ICS/OT systems, including multi-factor authentication and strict role-based access, to prevent initial access and privilege escalation.

### Search
---
```sql
-- Name: Anomalous Grid Fluctuations in ICS/OT Environments
-- Description: This detection identifies anomalous voltage or frequency fluctuations in an Industrial Control System (ICS) or Operational Technology (OT) environment. Such anomalies can be early indicators of a cyber-physical attack aiming to destabilize the power grid, as described in the Spain outage event. The query establishes a baseline for normal voltage and frequency for each sensor and then flags significant deviations or oscillations.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK for ICS:
-- Tactic: Impair Process Control (TA0103)
-- Technique: Disturbing the State (T0816)
-- False Positive Sensitivity: Medium
-- References:
-- - https://www.cisa.gov/news-events/ics-advisories/icsa-17-204-01
-- Comments:
-- This rule requires telemetry data from OT/ICS devices, such as Programmable Logic Controllers (PLCs), Remote Terminal Units (RTUs), or other sensors.
-- The data should be in a key-value format or be parsed to extract fields for device_id, metric_name, and metric_value.
-- False positives can occur from non-malicious grid events, equipment maintenance, or sensor malfunction.

-- Data Source: OT telemetry logs from PLCs, RTUs, or sensors.
-- Query Strategy: Aggregate metrics for voltage and frequency, compare against a 24-hour baseline, and flag deviations based on thresholds.
-- False Positive Tuning: Exclude maintenance windows and noisy devices using tags or filters.

logs(
  source:ot_telemetry
  metric.name:(Voltage_V OR Frequency_Hz)
  @host:(plc* OR rtu* OR grid*)
)
| bin @timestamp span=5m
| group by @timestamp, device.id, metric.name
| select
    min(metric.value) as recent_min,
    max(metric.value) as recent_max,
    stdev(metric.value) as recent_stdev,
    count as event_count
| join inner(device.id, metric.name) with (
  logs(
    source:ot_telemetry
    metric.name:(Voltage_V OR Frequency_Hz)
    @host:(plc* OR rtu* OR grid*)
    -@timestamp:[NOW-24h TO NOW-5m]
  )
  | group by device.id, metric.name
  | select
      avg(metric.value) as baseline_avg,
      stdev(metric.value) as baseline_stdev
  | where baseline_stdev > 0
)
| eval
    voltage_spike_threshold = baseline_avg * 1.05,
    voltage_dip_threshold = baseline_avg * 0.95,
    is_spike = case(metric.name = "Voltage_V" AND recent_max > voltage_spike_threshold, 1, 0),
    is_dip = case(metric.name = "Voltage_V" AND recent_min < voltage_dip_threshold, 1, 0),
    is_oscillation = case(
      (metric.name = "Voltage_V" AND recent_stdev > 2.5 AND recent_stdev > (baseline_stdev * 2)) OR
      (metric.name = "Frequency_Hz" AND recent_stdev > 0.5 AND recent_stdev > (baseline_stdev * 2)),
      1, 0
    ),
    anomaly_type = case(
      is_oscillation = 1, "High Oscillation",
      is_spike = 1, "Anomalous Spike",
      is_dip = 1, "Anomalous Dip"
    )
| where is_spike = 1 OR is_dip = 1 OR is_oscillation = 1
| select
    @timestamp as Time,
    device.id as DeviceId,
    metric.name as MetricName,
    anomaly_type as AnomalyType,
    recent_min as RecentMin,
    recent_max as RecentMax,
    recent_stdev as RecentStdev,
    baseline_avg as BaselineAvg,
    baseline_stdev as BaselineStdev,
    event_count as EventCount
| exclude @timestamp:(maintenance_window OR noisy_device_tag)
```
---
```sql
-- Name: ICS-Specific Malware Activity
-- Description: Detects indicators of ICS-specific malware (like Industroyer, BlackEnergy, Triton) by identifying unauthorized program downloads to OT assets or the use of high-risk ICS/OT commands from non-standard sources. Such activity can be a precursor to or part of an attempt to impair process control.
-- Author: RW
-- Date: 2025-08-17

-- MITRE ATT&CK for ICS Information:
-- Tactic: Impair Process Control (TA0103)
-- Technique: Program Download (T0843), Unauthorized Command Message (T0861)

-- False Positive Sensitivity: Medium

-- Data Source: Network logs from firewalls, IDS/IPS, or OT monitoring platforms.
-- Query Strategy: Search for suspicious file downloads and high-risk commands to OT assets, exclude authorized engineering workstations, and aggregate by source/destination IPs.
-- False Positive Tuning: Use tags for OT assets and engineering workstations.

-- Pattern 1: Suspicious File Downloads
logs(
  source:network
  @host:(plc* OR rtu* OR grid*)
  network.file.name:(*.exe OR *.dll OR *.bin OR *.s7p OR *.msf OR *.out OR *.ps1 OR *.bat)
  -network.src_ip:(@eng_workstations)
)
| group by @timestamp, network.src_ip, network.dest_ip, network.file.name, network.protocol
| select
    @timestamp as Time,
    network.src_ip as SourceIp,
    network.dest_ip as DestIp,
    network.file.name as FilePath,
    network.protocol as Protocol,
    "Suspicious File Download to OT" as Activity,
    "Program Download (T0843)" as MitreTechnique,
    "" as Command

-- Pattern 2: Unauthorized High-Risk ICS Commands
| union(
  logs(
    source:ot_protocol
    @host:(plc* OR rtu* OR grid*)
    -network.src_ip:(@eng_workstations)
    command:(Write Single Coil OR Write Multiple Coils OR Write Single Register OR Write Multiple Registers OR PLC Stop OR S7 Download)
  )
  | group by @timestamp, network.src_ip, network.dest_ip, network.protocol, command
  | select
      @timestamp as Time,
      network.src_ip as SourceIp,
      network.dest_ip as DestIp,
      "" as FilePath,
      network.protocol as Protocol,
      "Unauthorized High-Risk ICS Command" as Activity,
      "Unauthorized Command Message (T0861)" as MitreTechnique,
      command as Command
)

-- Combine and Summarize
| group by SourceIp, DestIp
| select
    min(Time) as StartTime,
    max(Time) as EndTime,
    values(Activity) as Activities,
    values(MitreTechnique) as MitreTechniques,
    values(Protocol) as Protocols,
    values(Command) as Commands,
    values(FilePath) as FilePaths,
    "Impair Process Control" as MitreTactic
| display StartTime, EndTime, SourceIp, DestIp, Activities, MitreTechniques, Protocols, Commands, FilePaths
```
---
```sql
-- Name: Weak Authentication or Access to ICS/OT Systems

-- Description: Detects attempts to bypass or exploit weak authentication and access controls in ICS/OT systems. This includes brute-force login attempts against OT assets and connections to sensitive OT remote services from unauthorized sources.

-- Author: RW
-- Date: 2025-08-17

-- MITRE ATT&CK for ICS Information:
-- Tactic: Initial Access (TA0108)
-- Technique: Brute Force (T0806), Exploitation of Remote Services (T0866)

-- False Positive Sensitivity: Medium

-- Data Source: Authentication logs (e.g., Windows Event Logs, OT device logs) and network flow logs.
-- Query Strategy: Identify high failed login counts and connections to sensitive OT ports from unauthorized sources, aggregate by source/destination.
-- False Positive Tuning: Exclude known engineering workstations and tune brute-force thresholds.

-- Pattern 1: Brute Force Attempts
logs(
  source:(wineventlog OR ot_auth)
  event.outcome:failure
  @host:(plc* OR rtu* OR grid*)
)
| group by @timestamp span=10m, network.src_ip, network.dest_ip, @user
| select
    @timestamp as Time,
    network.src_ip as SourceIp,
    network.dest_ip as DestIp,
    @user as User,
    count as EventCount,
    "Potential Brute Force Against OT Asset" as Activity,
    "Brute Force (T0806)" as MitreTechnique,
    "N/A" as DestPort
| where EventCount > 15

-- Pattern 2: Unauthorized Remote Service Connections
| union(
  logs(
    source:(netfw OR zeek)
    @host:(plc* OR rtu* OR grid*)
    -network.src_ip:(@eng_workstations)
    network.dest_port:(@ics_remote_ports)
  )
  | group by @timestamp span=1h, network.src_ip, network.dest_ip, network.dest_port
  | select
      @timestamp as Time,
      network.src_ip as SourceIp,
      network.dest_ip as DestIp,
      "N/A" as User,
      values(network.dest_port) as DestPort,
      "Unauthorized Connection to OT Remote Service" as Activity,
      "Exploitation of Remote Services (T0866)" as MitreTechnique
)

-- Combine and Summarize
| group by SourceIp, DestIp
| select
    min(Time) as StartTime,
    max(Time) as EndTime,
    values(Activity) as Activities,
    values(MitreTechnique) as MitreTechniques,
    values(User) as Users,
    values(DestPort) as DestinationPorts,
    "Initial Access" as MitreTactic
| rename SourceIp as SourceIP, DestIp as DestinationDevice
| display StartTime, EndTime, SourceIP, DestinationDevice, Activities, MitreTechniques, Users, DestinationPorts
```
---
```sql
-- Name: Exploitation of Internet-Connected DER Vulnerabilities

-- Description: Detects potential exploitation attempts against internet-connected Industrial Control System (ICS) devices, particularly Distributed Energy Resources (DER) like solar inverters and panels. The rule identifies three patterns of malicious activity from external sources: port scanning, web-based exploit attempts (e.g., command injection, path traversal), and brute-force login attempts. These devices are often targeted due to weak default security configurations.

-- Author: RW
-- Date: 2025-08-17

-- MITRE ATT&CK for ICS Information:
-- Tactic: Initial Access (TA0108)
-- Technique: Exploitation of Vulnerability (T0882), Remote Services (T0868)

-- False Positive Sensitivity: Medium

-- Data Source: Network and web logs from firewalls, IDS/IPS, or web proxies.
-- Query Strategy: Identify port scans, exploit attempts, and brute-force attempts targeting DER assets, exclude benign scanners, and aggregate by source/destination.
-- False Positive Tuning: Use tags for DER assets and known benign scanners.

-- Pattern 1: Port Scanning
logs(
  source:network
  @host:(der* OR solar* OR grid*)
  -network.src_ip:(@private_ips OR @known_scanners)
)
| group by @timestamp, network.src_ip, network.dest_ip
| select
    count_distinct(network.dest_port) as PortCount,
    values(network.dest_port) as ScannedPorts,
    @timestamp as Time,
    network.src_ip as SourceIP,
    network.dest_ip as DestinationAssetIP,
    "Port Scanning of DER Asset" as Activity,
    "Remote Services (T0868)" as Technique,
    mvjoin(ScannedPorts, ", ") as Details
| where PortCount > 5

-- Pattern 2: Web-based Exploit Attempts
| union(
  logs(
    source:web
    @host:(der* OR solar* OR grid*)
    -network.src_ip:(@private_ips)
    (http.url:(@vuln_paths) OR http.user_agent:(@known_scanner_ua))
  )
  | group by @timestamp, network.src_ip, network.dest_ip
  | select
      @timestamp as Time,
      network.src_ip as SourceIP,
      network.dest_ip as DestinationAssetIP,
      "Web Exploit Attempt Against DER Asset" as Activity,
      "Exploitation of Vulnerability (T0882)" as Technique,
      "URLs: " + mvjoin(http.url, "; ") + " | UserAgents: " + mvjoin(http.user_agent, "; ") as Details
)

-- Pattern 3: Brute-Force Attempts
| union(
  logs(
    source:network
    @host:(der* OR solar* OR grid*)
    -network.src_ip:(@private_ips)
    network.action:denied
  )
  | group by @timestamp, network.src_ip, network.dest_ip, network.dest_port
  | select
      @timestamp as Time,
      network.src_ip as SourceIP,
      network.dest_ip as DestinationAssetIP,
      count as EventCount,
      "Brute-Force Attempt Against DER Asset" as Activity,
      "Remote Services (T0868)" as Technique,
      "Failed to connect " + count + " times to port " + network.dest_port as Details
  | where EventCount > 10
)

-- Combine and Summarize
| group by SourceIP, DestinationAssetIP
| select
    min(Time) as StartTime,
    max(Time) as EndTime,
    values(Activity) as Activities,
    values(Technique) as Techniques,
    values(Details) as ActivityDetails,
    "Initial Access" as Tactic
| display StartTime, EndTime, SourceIP, DestinationAssetIP, Activities, Techniques, ActivityDetails
```
---
```sql
-- Name: Lateral Movement in Segmented ICS Environments

-- Description: This rule detects potential lateral movement activities within or between segmented network zones, specifically focusing on traffic patterns that violate typical ICS/OT network segmentation policies. It identifies two primary suspicious patterns: 1) Direct communication between IT and OT zones that bypasses designated DMZ/jump hosts. 2) Use of common administrative protocols (e.g., RDP, SMB, SSH) for peer-to-peer communication between assets within the OT zone, which is often anomalous.

-- Author: RW
-- Date: 2025-08-17

-- MITRE ATT&CK for ICS Information:
-- Tactic: Lateral Movement (TA0109)
-- Technique: Standard Application Layer Protocol (T0864), Valid Accounts (T0865)

-- False Positive Sensitivity: Medium

-- Comments:
-- This detection relies heavily on the correct definition of your network segments (IT, OT) and authorized hosts. Inaccurate definitions will lead to false positives or negatives.
-- The rule assumes that most OT assets should not communicate with each other using administrative protocols and that IT-OT traffic is routed through specific, authorized systems.

-- Data Source: Network flow logs from firewalls or Zeek.
-- Query Strategy: Identify prohibited IT-OT traffic and anomalous intra-OT administrative protocol use, exclude authorized jump hosts, and aggregate by source/destination.
-- False Positive Tuning: Use tags for network segments and jump hosts.

-- Pattern 1: Prohibited IT-OT Cross-Segment Traffic
logs(
  source:network
  (
    (network.src_ip:(@it_networks) AND network.dest_ip:(@ot_networks)) OR
    (network.src_ip:(@ot_networks) AND network.dest_ip:(@it_networks))
  )
  -network.src_ip:(@authorized_jump_hosts)
)
| group by @timestamp, network.src_ip, network.dest_ip, network.dest_port
| select
    @timestamp as Time,
    network.src_ip as SrcIp,
    network.dest_ip as DestIp,
    values(network.dest_port) as DestPorts,
    count as ConnectionCount,
    "Prohibited Cross-Segment Communication" as ViolationType,
    "T0864" as MitreTechniques

-- Pattern 2: Anomalous Intra-OT Peer Communication
| union(
  logs(
    source:network
    network.src_ip:(@ot_networks)
    network.dest_ip:(@ot_networks)
    network.dest_port:(@lateral_movement_ports)
    -(network.src_ip:(@authorized_jump_hosts) OR network.dest_ip:(@authorized_jump_hosts))
  )
  | group by @timestamp, network.src_ip, network.dest_ip, network.dest_port
  | select
      @timestamp as Time,
      network.src_ip as SrcIp,
      network.dest_ip as DestIp,
      values(network.dest_port) as DestPorts,
      count as ConnectionCount,
      "Anomalous Intra-OT Peer Communication" as ViolationType,
      "T0864, T0865" as MitreTechniques
)

-- Combine and Summarize
| group by SrcIp, DestIp, ViolationType
| select
    min(Time) as StartTime,
    max(Time) as EndTime,
    values(DestPorts) as DestPorts,
    sum(ConnectionCount) as ConnectionCount,
    values(MitreTechniques) as MitreTechniques,
    "Lateral Movement (TA0109)" as MitreTactic,
    "Potential lateral movement detected from " + SrcIp + " to " + DestIp + ". Policy Violated: " + ViolationType as Summary
| display StartTime, EndTime, SrcIp, DestIp, DestPorts, ConnectionCount, MitreTechniques, MitreTactic, Summary
```