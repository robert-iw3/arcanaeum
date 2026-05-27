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
-- ES|QL Notes:
-- ES|QL does not support dynamic subqueries for joins directly, so the historical baseline is handled via an ENRICH policy. Assume the following setup:
-- 1. Run the baseline query:
FROM ot_telemetry_index | WHERE metric_name IN ("Voltage_V", "Frequency_Hz") AND @timestamp
 >= now() - 24h AND @timestamp
 < now() - 5m | STATS baseline_avg = AVG(metric_value), baseline_stdev = STDDEV(metric_value) BY device_id, metric_name | WHERE baseline_stdev > 0 | EVAL enrich_key = CONCAT(device_id, "|", metric_name)
-- 2. Index the results into a temporary index (e.g., baseline_index) using Elasticsearch APIs.
-- 3. Create and execute an enrich policy: match_field="enrich_key", enrich_fields=["baseline_avg", "baseline_stdev"] on baseline_index.
-- 4. Use the policy in the main query. For optimization, run this query over a short recent time range (e.g., last 30m) to focus on near-real-time detection, as baselines are pre-computed.
-- The query uses DATE_TRUNC for binning and conditional EVAL for anomaly flags to ensure efficiency.

FROM ot_telemetry_index -- <-- adjust to your index or data-stream
| WHERE metric_name IN ("Voltage_V", "Frequency_Hz")
| EVAL time_bin = DATE_TRUNC(5 minutes, @timestamp)
| STATS recent_min = MIN(metric_value), recent_max = MAX(metric_value), recent_stdev = STDDEV(metric_value), count = COUNT(*) BY time_bin, device_id, metric_name
| EVAL enrich_key = CONCAT(device_id, "|", metric_name)
| ENRICH baseline_policy ON enrich_key WITH baseline_avg, baseline_stdev
| EVAL voltage_spike_threshold = baseline_avg * 1.05
| EVAL voltage_dip_threshold = baseline_avg * 0.95
| EVAL is_spike = CASE(metric_name == "Voltage_V" AND recent_max > voltage_spike_threshold, 1, 0)
| EVAL is_dip = CASE(metric_name == "Voltage_V" AND recent_min < voltage_dip_threshold, 1, 0)
| EVAL is_oscillation = CASE((metric_name == "Voltage_V" AND recent_stdev > 2.5 AND recent_stdev > (baseline_stdev * 2)) OR (metric_name == "Frequency_Hz" AND recent_stdev > 0.5 AND recent_stdev > (baseline_stdev * 2)), 1, 0)
| WHERE is_spike == 1 OR is_dip == 1 OR is_oscillation == 1
| EVAL anomaly_type = CASE(is_oscillation == 1, "High Oscillation", is_spike == 1, "Anomalous Spike", is_dip == 1, "Anomalous Dip")
| KEEP time_bin, device_id, metric_name, anomaly_type, recent_min, recent_max, recent_stdev, baseline_avg, baseline_stdev, count
| SORT time_bin DESC
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
-- ES|QL Notes:
-- Assume ENRICH policies are created for templates: ot_asset_policy (match on asset_ip=dest_ip, enrich with is_ot), eng_workstation_policy (match on workstation_ip=src_ip, enrich with is_eng).
-- The two patterns are combined in one query by sourcing from multiple indices and using conditional EVAL/WHERE for filtering. This optimizes by reducing separate executions.
-- Assume network_traffic_index and ot_protocol_logs_index correspond to the data sources. Fields like file_name, protocol, command are assumed present where relevant; nulls are handled implicitly in conditions.
-- Use REGEXP for case-insensitive matching; VALUES() for collecting multi-values in STATS.

FROM network_traffic_index, ot_protocol_logs_index -- <-- use net/ot protocol logs index or data-stream (e.g. zeek/suricata/pcap)
| ENRICH ot_asset_policy ON dest_ip WITH is_ot
| ENRICH eng_workstation_policy ON src_ip WITH is_eng
| WHERE is_ot == true AND (is_eng != true OR is_eng IS NULL)
| EVAL is_download = CASE(REGEXP(file_name, "(?i)\\.(exe|dll|bin|s7p|msf|out|ps1|bat)$"), true, false)
| EVAL is_command = CASE(command IN ("Write Single Coil", "Write Multiple Coils", "Write Single Register", "Write Multiple Registers", "PLC Stop", "S7 Download"), true, false)
| WHERE is_download OR is_command
| EVAL activity = CASE(is_download, "Suspicious File Download to OT", is_command, "Unauthorized High-Risk ICS Command")
| EVAL mitre_technique = CASE(is_download, "Program Download (T0843)", is_command, "Unauthorized Command Message (T0861)")
| EVAL command = CASE(is_download, "", is_command, command)
| EVAL file_path = CASE(is_download, file_name, is_command, "")
| STATS start_time = MIN(@timestamp), end_time = MAX(@timestamp), mitre_techniques = VALUES(mitre_technique), activities = VALUES(activity), protocols = VALUES(protocol), commands = VALUES(command), file_paths = VALUES(file_path) BY src_ip, dest_ip
| EVAL start_time = DATE_FORMAT("YYYY-MM-dd'T'HH:mm:ss'Z'", start_time)
| EVAL end_time = DATE_FORMAT("YYYY-MM-dd'T'HH:mm:ss'Z'", end_time)
| EVAL mitre_tactic = "Impair Process Control"
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
-- False Positive Sensitivity: Medium-- Comments:
-- This rule requires authentication logs from OT devices and network flow logs with visibility into the OT network.
-- False positives can occur from misconfigured applications, network scanners, or incomplete lists of authorized workstations.
-- ES|QL Notes:
-- Assume ENRICH policies: ot_asset_policy (on asset_ip=dest/dest_ip, with asset_name), eng_workstation_policy (on workstation_ip=src, with is_eng_workstation), ics_remote_ports_policy (on port=dest_port, with protocol_name).
-- Brute force threshold is hardcoded as 15; adjust as needed.
-- Patterns are combined using multiple indices and conditional logic for optimization.
-- Use DATE_TRUNC for bucketing.

FROM ot_auth_failure_logs_index, network_traffic_logs_index
| ENRICH ot_asset_policy ON dest WITH asset_name
| WHERE asset_name IS NOT NULL
| EVAL is_brute = CASE(@index == "ot_auth_failure_logs_index", true, false) -- Assume @index metadata to distinguish sources if needed
| EVAL is_remote = CASE(@index == "network_traffic_logs_index", true, false)
| WHERE is_brute OR is_remote
| EVAL time_bin = CASE(is_brute, DATE_TRUNC(10 minutes, @timestamp), is_remote, DATE_TRUNC(1 hour, @timestamp))
| ENRICH eng_workstation_policy ON src WITH is_eng_workstation
| ENRICH ics_remote_ports_policy ON dest_port WITH protocol_name
| WHERE (is_remote IMPLIES (is_eng_workstation IS NULL AND protocol_name IS NOT NULL)) -- Apply filters conditionally
| STATS count = COUNT(*) BY time_bin, src, dest, user, dest_port, is_brute, is_remote
| WHERE (is_brute AND count > 15) OR is_remote
| EVAL activity = CASE(is_brute, "Potential Brute Force Against OT Asset", is_remote, "Unauthorized Connection to OT Remote Service")
| EVAL mitre_technique = CASE(is_brute, "Brute Force (T0806)", is_remote, "Exploitation of Remote Services (T0866)")
| EVAL user = CASE(is_brute, user, is_remote, "N/A")
| EVAL dest_port = CASE(is_brute, "N/A", is_remote, dest_port)
| STATS start_time = MIN(time_bin), end_time = MAX(time_bin), activities = VALUES(activity), mitre_techniques = VALUES(mitre_technique), users = VALUES(user), destination_ports = VALUES(dest_port) BY src, dest
| EVAL start_time = DATE_FORMAT("YYYY-MM-dd'T'HH:mm:ss'Z'", start_time)
| EVAL end_time = DATE_FORMAT("YYYY-MM-dd'T'HH:mm:ss'Z'", end_time)
| EVAL mitre_tactic = "Initial Access"
| RENAME src AS SourceIP, dest AS DestinationDevice
| SORT start_time DESC
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
-- ES|QL Notes:
-- Assume ENRICH policies for templates: der_asset_policy (on asset_ip=dest_ip), known_benign_scanners_policy (on scanner_ip=src_ip, with is_known_scanner), known_vuln_paths_policy (on url, with is_vuln_path), known_scanner_ua_policy (on http_user_agent, with is_known_ua).
-- Hardcode thresholds: port_scan 5, login_failure 10.
-- Patterns are combined in one query using conditional EVAL for efficiency, assuming data from network_traffic and web_logs indices (corresponding to datamodels).
-- Use VALUES for multi-value aggregation.

FROM network_traffic_index, web_logs_index
| ENRICH der_asset_policy ON dest_ip WITH asset_ip -- Filter for corporate/known assets implicitly
| WHERE asset_ip IS NOT NULL AND IPV4_IS_IN_RANGE(src_ip, "10.0.0.0/8") == false AND IPV4_IS_IN_RANGE(src_ip, "172.16.0.0/12") == false AND IPV4_IS_IN_RANGE(src_ip, "192.168.0.0/16") == false -- Non-private src_ip
| ENRICH known_benign_scanners_policy ON src_ip WITH is_known_scanner
| WHERE is_known_scanner != true
| EVAL is_port_scan = CASE(@index == "network_traffic_index" AND action != "denied", true, false)
| EVAL is_web_exploit = CASE(@index == "web_logs_index", true, false)
| EVAL is_brute = CASE(@index == "network_traffic_index" AND action == "denied", true, false)
| WHERE is_port_scan OR is_web_exploit OR is_brute
| ENRICH known_vuln_paths_policy ON url WITH is_vuln_path
| ENRICH known_scanner_ua_policy ON http_user_agent WITH is_known_ua
| WHERE (is_web_exploit IMPLIES (is_vuln_path == true OR is_known_ua == true))
| STATS port_count = DISTINCT_COUNT(dest_port), scanned_ports = VALUES(dest_port), urls = VALUES(url), user_agents = VALUES(http_user_agent), count = COUNT(*) BY @timestamp, src_ip, dest_ip, dest_port, is_port_scan, is_web_exploit, is_brute
| WHERE (is_port_scan AND port_count > 5) OR (is_brute AND count > 10) OR is_web_exploit
| EVAL activity = CASE(is_port_scan, "Port Scanning of DER Asset", is_web_exploit, "Web Exploit Attempt Against DER Asset", is_brute, "Brute-Force Attempt Against DER Asset")
| EVAL technique = CASE(is_port_scan, "Remote Services (T0868)", is_web_exploit, "Exploitation of Vulnerability (T0882)", is_brute, "Remote Services (T0868)")
| EVAL details = CASE(is_port_scan, MV_JOIN(scanned_ports, ", "), is_web_exploit, CONCAT("URLs: ", MV_JOIN(urls, "; "), " | UserAgents: ", MV_JOIN(user_agents, "; ")), is_brute, CONCAT("Failed to connect ", TO_STRING(count), " times to port ", TO_STRING(dest_port)))
| STATS start_time = MIN(@timestamp), end_time = MAX(@timestamp), Activities = VALUES(activity), Techniques = VALUES(technique), ActivityDetails = VALUES(details) BY src_ip, dest_ip
| EVAL start_time = DATE_FORMAT("YYYY-MM-dd'T'HH:mm:ss'Z'", start_time)
| EVAL end_time = DATE_FORMAT("YYYY-MM-dd'T'HH:mm:ss'Z'", end_time)
| EVAL tactic = "Initial Access"
| RENAME dest_ip AS DestinationAssetIP, src_ip AS SourceIP
```
---
```sql
-- Name: Lateral Movement in Segmented ICS Environments
-- Description: This rule detects potential lateral movement activities within or between segmented network zones, specifically focusing on traffic patterns that violate typical ICS/OT network segmentation policies. It identifies two primary suspicious patterns:
-- 1) Direct communication between IT and OT zones that bypasses designated DMZ/jump hosts.
-- 2) Use of common administrative protocols (e.g., RDP, SMB, SSH) for peer-to-peer communication between assets within the OT zone, which is often anomalous.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK for ICS Information:
-- Tactic: Lateral Movement (TA0109)
-- Technique: Standard Application Layer Protocol (T0864), Valid Accounts (T0865)
-- False Positive Sensitivity: Medium
-- Comments:
-- This detection relies heavily on the correct definition of your network segments (IT, OT) and authorized hosts. Inaccurate definitions will lead to false positives or negatives.
-- The rule assumes that most OT assets should not communicate with each other using administrative protocols and that IT-OT traffic is routed through specific, authorized systems.
-- ES|QL Notes:
-- Assume ENRICH policies: it_networks_policy (match on cidr=src_ip/dest_ip, with is_it), ot_networks_policy (on cidr=src_ip/dest_ip, with is_ot), authorized_jump_hosts_policy (on host_ip=src_ip/dest_ip, with is_jump), lateral_movement_ports_policy (on port=dest_port, with is_lateral_port).
-- Patterns combined in one query with conditional logic.
-- Use IPV4_IS_IN_RANGE or similar for network ranges, but since template are CIDR, ENRICH assumes it adds flags like is_it, is_ot.

FROM network_traffic_index
| ENRICH authorized_jump_hosts_policy ON src_ip WITH is_jump_src
| ENRICH authorized_jump_hosts_policy ON dest_ip WITH is_jump_dest
| ENRICH it_networks_policy ON src_ip WITH is_it_src
| ENRICH it_networks_policy ON dest_ip WITH is_it_dest
| ENRICH ot_networks_policy ON src_ip WITH is_ot_src
| ENRICH ot_networks_policy ON dest_ip WITH is_ot_dest
| ENRICH lateral_movement_ports_policy ON dest_port WITH is_lateral_port
| EVAL is_cross_segment = CASE((is_it_src AND is_ot_dest) OR (is_ot_src AND is_it_dest) AND is_jump_src != true, true, false)
| EVAL is_intra_ot = CASE(is_ot_src AND is_ot_dest AND is_lateral_port == true AND is_jump_src != true AND is_jump_dest != true, true, false)
| WHERE is_cross_segment OR is_intra_ot
| EVAL violation_type = CASE(is_cross_segment, "Prohibited Cross-Segment Communication", is_intra_ot, "Anomalous Intra-OT Peer Communication")
| EVAL mitre_techniques = CASE(is_cross_segment, "T0864", is_intra_ot, "T0864, T0865")
| STATS start_time = MIN(@timestamp), end_time = MAX(@timestamp), dest_ports = VALUES(dest_port), connection_count = COUNT(*), mitre_techniques = VALUES(mitre_techniques) BY src_ip, dest_ip, violation_type
| EVAL start_time = DATE_FORMAT("YYYY-MM-dd'T'HH:mm:ss'Z'", start_time)
| EVAL end_time = DATE_FORMAT("YYYY-MM-dd'T'HH:mm:ss'Z'", end_time)
| EVAL mitre_tactic = "Lateral Movement (TA0109)"
| EVAL summary = CONCAT("Potential lateral movement detected from ", src_ip, " to ", dest_ip, ". Policy Violated: ", violation_type)
| SORT start_time DESC
```