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
-- Description: Detects network traffic to or from external IP addresses on ports commonly used for OT protocols like Modbus (502) and DNP3 (20000), indicating potential misconfigured devices, unauthorized access, or reconnaissance.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK: T1071.004, T1090, T1572
-- False Positive Sensitivity: Medium
-- Tags: ICS, OT, Modbus, DNP3, External Access, Reconnaissance
-- Rule: Assumes network traffic logs with ECS fields, requiring an allowlist for authorized external IPs.
-- References: https://www.veridify.com/dnp3-security-risks/, https://www.veridify.com/modbus-security-issues-and-how-to-mitigate-cyber-risks/

FROM *
| WHERE (destination.port IN (502, 20000) OR source.port IN (502, 20000))
| EVAL is_src_private = CASE(
    CIDR_MATCH("10.0.0.0/8", source.ip) OR CIDR_MATCH("172.16.0.0/12", source.ip) OR CIDR_MATCH("192.168.0.0/16", source.ip), 1,
    true, 0
  ),
  is_dest_private = CASE(
    CIDR_MATCH("10.0.0.0/8", destination.ip) OR CIDR_MATCH("172.16.0.0/12", destination.ip) OR CIDR_MATCH("192.168.0.0/16", destination.ip), 1,
    true, 0
  )
| WHERE is_src_private != is_dest_private
| WHERE NOT (source.ip IN ("1.2.3.4", "8.8.8.8") OR destination.ip IN ("1.2.3.4", "8.8.8.8"))
| EVAL protocol = CASE(
    destination.port == 502 OR source.port == 502, "Modbus",
    destination.port == 20000 OR source.port == 20000, "DNP3",
    true, "Other"
  )
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), count = COUNT() BY source.ip, destination.ip, destination.port
| EVAL firstTime = TO_STRING(firstTime), lastTime = TO_STRING(lastTime)
| RENAME source.ip AS src_ip, destination.ip AS dest_ip, destination.port AS dest_port
| KEEP firstTime, lastTime, src_ip, dest_ip, dest_port, protocol, count
-- Potential False Positives:
-- Legitimate remote administration or cloud-based SCADA services may trigger alerts.
-- Example: Update allowlist with IPs like "203.0.113.10" or use a lookup table.
-- | WHERE NOT (src_ip IN (SELECT ip FROM ot_ip_allowlist))
```
---
```sql
-- Name: Unauthorized IT to OT Network Communication
-- Description: Detects network traffic from IT to OT network segments over common OT protocol ports, indicating potential breaches of segmentation or lateral movement.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK: T1090, T1572
-- False Positive Sensitivity: Medium
-- Tags: ICS, OT, Modbus, DNP3, EtherNet/IP, Network Segmentation
-- Rule: Assumes network traffic logs with ECS fields, requiring definitions for IT/OT subnets and authorized connections.
-- References: https://www.cisa.gov/uscert/ics/publications/recommended-practice-improving-industrial-control-system-cybersecurity-network

FROM *
| WHERE destination.port IN (502, 20000, 44818, 2222)
| EVAL is_it_subnet = CASE(
    CIDR_MATCH("10.0.0.0/8", source.ip) OR CIDR_MATCH("172.16.0.0/12", source.ip) OR CIDR_MATCH("192.168.0.0/16", source.ip), 1,
    true, 0
  ),
  is_ot_subnet = CASE(
    CIDR_MATCH("100.64.0.0/10", destination.ip), 1,
    true, 0
  )
| WHERE is_it_subnet == 1 AND is_ot_subnet == 1
| EVAL connection_key = CONCAT(source.ip, ":", destination.ip, ":", TO_STRING(destination.port))
| WHERE NOT connection_key IN ("10.1.1.100:100.64.10.50:502", "10.1.2.200:100.64.20.75:44818")
| EVAL protocol = CASE(
    destination.port == 502, "Modbus",
    destination.port == 20000, "DNP3",
    destination.port == 44818, "EtherNet/IP (TCP)",
    destination.port == 2222, "EtherNet/IP (UDP)",
    true, "Other"
  )
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), count = COUNT() BY source.ip, destination.ip, destination.port
| EVAL firstTime = TO_STRING(firstTime), lastTime = TO_STRING(lastTime)
| RENAME source.ip AS SourceIT_IP, destination.ip AS DestinationOT_IP, destination.port AS DestinationPort, count AS ConnectionCount
| KEEP firstTime, lastTime, SourceIT_IP, DestinationOT_IP, DestinationPort, protocol, ConnectionCount
-- Potential False Positives:
-- Legitimate systems like data historians may trigger alerts.
-- Example: Update authorized connections with tuples like "10.1.1.101:100.64.10.51:502".
-- | WHERE NOT (connection_key IN (SELECT connection FROM authorized_it_ot_connections))
```
---
```sql
-- Name: OT Protocol Scanning (Banner Sniffing)
-- Description: Detects potential reconnaissance activity where a single source IP attempts connections to multiple OT devices on common OT ports, indicative of banner sniffing or enumeration.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK: T1595, T1590
-- False Positive Sensitivity: Medium
-- Tags: ICS, OT, Modbus, DNP3, EtherNet/IP, Reconnaissance
-- Rule: Assumes network traffic logs with ECS fields, requiring an allowlist for authorized scanners.

FROM *
| WHERE destination.port IN (502, 20000, 44818, 2222)
| WHERE NOT source.ip IN ("192.168.1.100", "10.10.0.50")
| STATS StartTime = MIN(@timestamp), EndTime = MAX(@timestamp), DistinctOTDevicesScanned = COUNT_DISTINCT(destination.ip), ScannedOT_IPs = VALUES(destination.ip), ScannedPorts = VALUES(destination.port), TotalConnections = COUNT() BY source.ip
| WHERE DistinctOTDevicesScanned > 3
| EVAL ScannerLocation = CASE(
    CIDR_MATCH("10.0.0.0/8", source.ip) OR CIDR_MATCH("172.16.0.0/12", source.ip) OR CIDR_MATCH("192.168.0.0/16", source.ip), "Internal",
    true, "External"
  )
| EVAL StartTime = TO_STRING(StartTime), EndTime = TO_STRING(EndTime)
| RENAME source.ip AS ScannerIP
| KEEP StartTime, EndTime, ScannerIP, ScannerLocation, DistinctOTDevicesScanned, TotalConnections, ScannedOT_IPs, ScannedPorts
-- Potential False Positives:
-- Legitimate scanners or management tools may trigger alerts.
-- Example: Update allowlist with IPs like "192.168.1.101" or use a lookup table.
-- | WHERE NOT (ScannerIP IN (SELECT ip FROM scanner_ip_allowlist))
```
---
```sql
-- Name: Erlang/OTP SSH Vulnerability Exploitation (CVE-2025-32433)
-- Description: Detects potential exploitation of CVE-2025-32433 by identifying Erlang-related processes accepting connections on non-standard SSH ports (e.g., 2222) or spawning command shells, indicating RCE in OT networks.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK: T1190, T1021, T1059
-- False Positive Sensitivity: Medium
-- Tags: ICS, OT, CVE-2025-32433, Erlang, SSH, RCE
-- Rule: Assumes network and process event logs with ECS fields, focusing on OT network ranges.
-- References: https://unit42.paloaltonetworks.com/erlang-otp-cve-2025-32433/, https://gbhackers.com/erlang-otp-ssh-rce-vulnerability-actively-exploited/

FROM *
| WHERE (
    -- Tactic 1: Erlang process accepting connections on non-standard SSH ports
    (event.category == "network" AND destination.port IN (2222) AND process.name IN ("beam.smp", "beam", "erl", "erlexec") AND
      (CIDR_MATCH("10.100.0.0/16", host.ip) OR CIDR_MATCH("192.168.50.0/24", host.ip)))
    OR
    -- Tactic 2: Erlang process spawning a command shell
    (event.category == "process" AND process.name IN ("bash", "sh", "zsh", "csh", "ksh", "cmd.exe", "powershell.exe") AND
      process.parent.name IN ("beam.smp", "beam", "erl", "erlexec") AND
      (CIDR_MATCH("10.100.0.0/16", host.ip) OR CIDR_MATCH("192.168.50.0/24", host.ip)))
  )
| EVAL activity = CASE(
    event.category == "network", "Non-Standard SSH Port Connection to Erlang Process",
    event.category == "process", "Shell Spawned by Erlang Process"
  ),
  local_port = COALESCE(destination.port, "N/A"),
  remote_ip = COALESCE(source.ip, "N/A"),
  parent_process_name = COALESCE(process.parent.name, "N/A"),
  command_line = COALESCE(process.command_line, "N/A")
| RENAME host.ip AS host, process.name AS process_name
| KEEP @timestamp, activity, host, process_name, parent_process_name, command_line, local_port, remote_ip
| EVAL _time = TO_STRING(@timestamp)
-- Potential False Positives:
-- Legitimate Erlang applications may use non-standard SSH ports or spawn shells.
-- Example: | WHERE NOT (command_line LIKE "%known_safe_script%")
```
---
```sql
-- Name: OT Network Baseline Deviations
-- Description: Detects new devices or new communication patterns in the OT network by comparing recent activity against a historical baseline, indicating potential unauthorized devices or anomalous behavior.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK: T1592, T1595, T1083
-- False Positive Sensitivity: Medium
-- Tags: ICS, OT, Network Baseline, Anomaly Detection
-- Rule: Assumes network traffic logs with ECS fields, requiring a baseline comparison.
-- Note: Subsearches are replaced with pre-populated lookup tables for performance in production.

-- Define lookup tables for baseline (populated daily via scheduled job)
-- lookup ot_baseline_devices: { dest_ip: string }
-- lookup ot_baseline_device_ports: { device_port_key: string }

FROM *
| WHERE @timestamp >= NOW() - 1 DAY AND (
    CIDR_MATCH("10.100.0.0/16", destination.ip) OR CIDR_MATCH("192.168.50.0/24", destination.ip)
  )
| EVAL device_port_key = CONCAT(destination.ip, ":", TO_STRING(destination.port))
| STATS StartTime = MIN(@timestamp), EndTime = MAX(@timestamp), Port = VALUES(destination.port), ConnectedRemoteIPs = VALUES(source.ip) BY host.name, destination.ip
| EVAL DeviationType = CASE(
    NOT destination.ip IN (SELECT dest_ip FROM ot_baseline_devices), "New OT Device Detected",
    NOT device_port_key IN (SELECT device_port_key FROM ot_baseline_device_ports) AND
      destination.ip IN (SELECT dest_ip FROM ot_baseline_devices), "New OT Communication Pattern Detected",
    true, "Unknown"
  )
| WHERE DeviationType IN ("New OT Device Detected", "New OT Communication Pattern Detected")
| EVAL Details = CASE(
    DeviationType == "New OT Device Detected", CONCAT("New device appeared on the OT network. Ports used: ", MVJOIN(Port, ", ")),
    DeviationType == "New OT Communication Pattern Detected", CONCAT("Existing device communicated on a new port: ", MVJOIN(Port, ", "), ". Connected from/to remote IPs: ", MVJOIN(ConnectedRemoteIPs, ", "))
  )
| RENAME host.name AS DeviceName, destination.ip AS OT_DeviceIP
| EVAL StartTime = TO_STRING(StartTime), EndTime = TO_STRING(EndTime)
| KEEP StartTime, EndTime, DeviationType, DeviceName, OT_DeviceIP, Details, ConnectedRemoteIPs, Port
-- Potential False Positives:
-- Legitimate new devices or configuration changes may trigger alerts.
-- Example: Update ot_baseline_devices and ot_baseline_device_ports lookups regularly.
```