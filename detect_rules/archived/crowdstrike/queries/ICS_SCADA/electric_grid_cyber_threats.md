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

-- Rule: Uses ProcessRollup2 and FileWrite to detect commands or file changes on grid control systems (e.g., PLCs, RTUs) that could manipulate voltage/frequency. Assumes sensor data is not directly available; focuses on control system activity. Optimizes with OT asset filtering and regex for command/file patterns.
event_platform=Win (
    (event_simpleName=ProcessRollup2 CommandLine IN ("Voltage_Set", "Frequency_Set", "Setpoint_Override", "Control_Adjust")
    | eval anomaly_type="Command-Induced Fluctuation" activity="Command: " + CommandLine)
| append [
        event_simpleName=FileWrite TargetFileName IN ("*control_config.ini", "voltage_config", "frequency_config")
        | eval anomaly_type="Config File Modification" activity="File Modified: " + TargetFileName
    ]
) +ComputerName:/(PLC|RTU|GRID)/i
| stats min(@timestamp) as StartTime max(@timestamp) as EndTime count values(anomaly_type) as anomaly_types values(activity) as activities by ComputerName LocalUserName
| rename ComputerName as device_id LocalUserName as user
| table StartTime EndTime device_id user anomaly_types activities count
-- Potential False Positives: Legitimate maintenance or configuration changes. Correlate with maintenance schedules. Tune command/file patterns and filter for grid-specific assets (e.g., +ComputerName:/(PLC|RTU)/i). Integrate with OT monitoring tools (e.g., Dragos) for direct sensor telemetry.
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

-- Comments:
-- This rule requires logs from network security devices (Firewalls, IDS/IPS, Zeek) and/or specialized OT security monitoring platforms (e.g., Dragos, Nozomi, Claroty).
-- False positives can occur if the lists of known engineering workstations or OT assets are incomplete.

-- Rule: Uses NetworkReceiveFile for file downloads and ProcessRollup2 for high-risk commands. Filters for OT assets and excludes engineering workstations. Optimizes with file extension regex and command list.
event_platform=Win (
    (event_simpleName=NetworkReceiveFile TargetFileName:/.(exe|dll|bin|s7p|msf|out|ps1|bat)$/i !LocalAddressIP4 IN ("eng_workstation_ip1", "eng_workstation_ip2")
    | eval activity="Suspicious File Download to OT" mitre_technique="Program Download (T0843)" command="" file_path=TargetFileName)
| append [
        event_simpleName=ProcessRollup2 CommandLine IN ("Write Single Coil", "Write Multiple Coils", "Write Single Register", "Write Multiple Registers", "PLC Stop", "S7 Download") !LocalAddressIP4 IN ("eng_workstation_ip1", "eng_workstation_ip2")
        | eval activity="Unauthorized High-Risk ICS Command" mitre_technique="Unauthorized Command Message (T0861)" file_path="" command=CommandLine
    ]
) +ComputerName:/(PLC|RTU|GRID)/i
| stats min(@timestamp) as start_time max(@timestamp) as end_time values(mitre_technique) as mitre_techniques values(activity) as activities values(command) as commands values(file_path) as file_paths by LocalAddressIP4 RemoteAddressIP4
| rename LocalAddressIP4 as src_ip RemoteAddressIP4 as dest_ip
| eval mitre_tactic="Impair Process Control"
| table start_time end_time src_ip dest_ip mitre_tactic mitre_techniques activities protocols commands file_paths
-- Potential False Positives: Legitimate file transfers or commands from unlisted engineering systems. Maintain dynamic allowlists for workstations. Filter for grid assets (e.g., +ComputerName:/(PLC|RTU)/i).
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

-- Comments:
-- This rule requires authentication logs from OT devices and network flow logs with visibility into the OT network.
-- False positives can occur from misconfigured applications, network scanners, or incomplete lists of authorized workstations.

-- Rule: Uses UserLoginFailed for brute-force attempts and NetworkConnectTCPv4 for unauthorized remote service connections. Filters for OT assets and excludes engineering workstations. Optimizes with time aggregation and port filtering.
(
    (event_simpleName=UserLoginFailed
    | stats count by @timestamp
    span=10m SourceAddressIP4 ComputerName LocalUserName
    | where count > 15
    | eval activity="Potential Brute Force Against OT Asset" mitre_technique="Brute Force (T0806)" dest_port="N/A")
| append [
        event_simpleName=NetworkConnectTCPv4 dest_port IN (3389, 22, 44818) !SourceAddressIP4 IN ("eng_workstation_ip1", "eng_workstation_ip2") +ComputerName:/(PLC|RTU|GRID)/i
        | stats values(dest_port) as dest_port by @timestamp span=1h SourceAddressIP4 ComputerName
        | eval activity="Unauthorized Connection to OT Remote Service" mitre_technique="Exploitation of Remote Services (T0866)" LocalUserName="N/A"
    ]
)
| stats min(@timestamp) as start_time max(@timestamp) as end_time values(activity) as activities values(mitre_technique) as mitre_techniques values(LocalUserName) as users values(dest_port) as destination_ports by SourceAddressIP4 ComputerName
| rename SourceAddressIP4 as SourceIP ComputerName as DestinationDevice
| eval mitre_tactic="Initial Access"
| table start_time end_time SourceIP DestinationDevice mitre_tactic mitre_techniques activities users destination_ports
-- Potential False Positives: Misconfigured apps or unlisted admin systems. Tune brute-force threshold (e.g., count > 15) and maintain allowlists. Filter for grid assets (e.g., +ComputerName:/(PLC|RTU)/i).
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

-- Comments:
-- This rule requires accurate asset and network information to be effective. It relies on the CIM for Network_Traffic and Web datamodels.
-- False positives can be generated by legitimate administrative activity from unexpected IP addresses or by benign internet scanners.

-- Rule: Uses NetworkConnectTCPv4 for port scans and brute-force attempts, and WebRequest for exploit attempts. Filters for DER IPs and excludes benign scanners. Optimizes with thresholds and time aggregation.
(
    (event_simpleName=NetworkConnectTCPv4 !SourceAddressIP4:/^(10.|192.168.|172.(1[6-9]|2[0-9]|3[0-1]).)/ !SourceAddressIP4 IN ("known_scanner_ip1", "known_scanner_ip2") ComputerName:/(DER|SOLAR|INVERTER)/i
    | stats dc(dest_port) as port_count values(dest_port) as scanned_ports by @timestamp span=1h SourceAddressIP4 ComputerName
    | where port_count > 5
    | eval activity="Port Scanning of DER Asset" technique="Remote Services (T0868)" details=mvjoin(scanned_ports, ", "))
| append [
        event_simpleName=WebRequest !SourceAddressIP4:/^(10.|192.168.|172.(1[6-9]|2[0-9]|3[0-1]).)/ (URL IN ("/login", "/admin", "*/config", "cmd=", "path=") OR HttpUserAgent IN ("Shodan", "Censys")) ComputerName:/(DER|SOLAR|INVERTER)/i
        | stats values(URL) as urls values(HttpUserAgent) as user_agents by @timestamp span=1h SourceAddressIP4 ComputerName
        | eval activity="Web Exploit Attempt Against DER Asset" technique="Exploitation of Vulnerability (T0882)" details="URLs: " + mvjoin(urls, "; ") + "
        | UserAgents: " + mvjoin(user_agents, "; ")
    ]
| append [
        event_simpleName=NetworkConnectTCPv4 !SourceAddressIP4:/^(10.|192.168.|172.(1[6-9]|2[0-9]|3[0-1]).)/ ConnectionStatus="denied" ComputerName:/(DER|SOLAR|INVERTER)/i
        | stats count by @timestamp span=1h SourceAddressIP4 ComputerName dest_port
        | where count > 10
        | eval activity="Brute-Force Attempt Against DER Asset" technique="Remote Services (T0868)" details="Failed to connect " + count + " times to port " + dest_port
    ]
)
| stats min(@timestamp) as start_time max(@timestamp) as end_time values(activity) as Activities values(technique) as Techniques values(details) as ActivityDetails by SourceAddressIP4 ComputerName
| rename SourceAddressIP4 as SourceIP ComputerName as DestinationAssetIP
| eval tactic="Initial Access"
| table start_time end_time SourceIP DestinationAssetIP tactic Techniques Activities ActivityDetails
-- Potential False Positives: Legitimate admin access or benign scans. Maintain benign scanner list and tune thresholds (e.g., port_count > 5, count > 10). Filter for DER assets (e.g., +ComputerName:/(DER|SOLAR)/i).
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

-- Rule: Uses NetworkConnectTCPv4 and NetworkAcceptTCPv4 to detect prohibited IT-OT or intra-OT traffic on admin ports. Filters for OT assets and excludes jump hosts. Optimizes with time aggregation and port filtering.
(
    (event_simpleName IN ("NetworkConnectTCPv4", "NetworkAcceptTCPv4") (
        (SourceAddressIP4:/^10.0./ AND RemoteAddressIP4:/^192.168.1./) OR
        (SourceAddressIP4:/^192.168.1./ AND RemoteAddressIP4:/^10.0./)
    ) !SourceAddressIP4 IN ("jump_host_ip1", "jump_host_ip2") +ComputerName:/(PLC|RTU|GRID)/i
    | eval violation_type="Prohibited Cross-Segment Communication" mitre_techniques="T0864")
| append [
        event_simpleName IN ("NetworkConnectTCPv4", "NetworkAcceptTCPv4") SourceAddressIP4:/^192.168.1./ RemoteAddressIP4:/^192.168.1./ dest_port IN (3389, 445, 22) !SourceAddressIP4 IN ("jump_host_ip1", "jump_host_ip2") !RemoteAddressIP4 IN ("jump_host_ip1", "jump_host_ip2") +ComputerName:/(PLC|RTU|GRID)/i | eval violation_type="Anomalous Intra-OT Peer Communication" mitre_techniques="T0864, T0865"
    ]
)
| stats min(@timestamp) as start_time max(@timestamp) as end_time values(dest_port) as dest_ports sum(count) as connection_count values(mitre_techniques) as mitre_techniques by SourceAddressIP4 RemoteAddressIP4 violation_type
| rename SourceAddressIP4 as src_ip RemoteAddressIP4 as dest_ip
| eval mitre_tactic="Lateral Movement (TA0109)" summary="Potential lateral movement detected from " + src_ip + " to " + dest_ip + ". Policy Violated: " + violation_type
| table start_time end_time src_ip dest_ip mitre_tactic mitre_techniques dest_ports connection_count summary
-- Potential False Positives: Misconfigured or unlisted jump hosts. Maintain accurate network range and jump host allowlists. Filter for grid assets (e.g., +ComputerName:/(PLC|RTU)/i).
```