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
-- Tuning Steps:
-- 1. Adjust the thresholds in the 'eval' statements below to match your environment's specific operational characteristics.
-- 2. Update the 'metric_name' values to match the metric names used in your data source.
-- 3. Consider adding known maintenance windows or noisy devices to the 'anomalous_grid_fluctuations_in_ics_ot_environments_filter' macro.

`ot_telemetry_index` metric_name IN ("Voltage_V", "Frequency_Hz")
| bin _time span=5m
`comment("Summarize recent sensor readings within a 5-minute window.")`
| stats
    min(metric_value) as recent_min,
    max(metric_value) as recent_max,
    stdev(metric_value) as recent_stdev,
    count
    by _time, device_id, metric_name
`comment("Join with a subsearch that calculates the historical baseline over the last 24 hours.")`
| join type=inner device_id, metric_name [
    search `ot_telemetry_index` metric_name IN ("Voltage_V", "Frequency_Hz") earliest=-24h latest=-5m
    | stats
        avg(metric_value) as baseline_avg,
        stdev(metric_value) as baseline_stdev
        by device_id, metric_name
    | where baseline_stdev > 0 `comment("Ensure baseline is not flat to avoid division by zero or meaningless stats.")`
]
`comment("Define anomaly conditions based on thresholds. These may require tuning.")`
| eval voltage_spike_threshold = baseline_avg * 1.05
| eval voltage_dip_threshold = baseline_avg * 0.95
| eval is_spike = if(metric_name="Voltage_V" AND recent_max > voltage_spike_threshold, 1, 0)
| eval is_dip = if(metric_name="Voltage_V" AND recent_min < voltage_dip_threshold, 1, 0)
| eval is_oscillation = if((metric_name="Voltage_V" AND recent_stdev > 2.5 AND recent_stdev > (baseline_stdev * 2)) OR (metric_name="Frequency_Hz" AND recent_stdev > 0.5 AND recent_stdev > (baseline_stdev * 2)), 1, 0)
`comment("Filter for events that meet any anomaly condition.")`
| where is_spike=1 OR is_dip=1 OR is_oscillation=1
`comment("Create a human-readable anomaly type field for easier analysis.")`
| eval anomaly_type = case(
    is_oscillation=1, "High Oscillation",
    is_spike=1, "Anomalous Spike",
    is_dip=1, "Anomalous Dip"
)
`comment("Format the final output for analysts.")`
| table _time, device_id, metric_name, anomaly_type, recent_min, recent_max, recent_stdev, baseline_avg, baseline_stdev, count
| `anomalous_grid_fluctuations_in_ics_ot_environments_filter`
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
-- For this rule to be effective, the following macros and/or lookups must be configured:
-- - `ot_network_traffic`: Should include indexes and sourcetypes for network and OT protocol logs.
-- - `ot_asset_lookup`: A lookup defining OT network ranges or asset IPs.
-- - `eng_workstation_lookup`: A lookup defining trusted engineering workstations.

`comment("Define macros for maintainability. These should be configured in your Splunk environment.")`
`comment("Macro: is_in_ot_network(ip) -> | lookup ot_asset_lookup asset_ip as ip OUTPUT is_ot | where is_ot=\"true\"")`
`comment("Macro: is_eng_workstation(ip) -> | lookup eng_workstation_lookup workstation_ip as ip OUTPUT is_eng | where is_eng=\"true\"")`

`comment("Pattern 1: Detects suspicious file downloads to the OT network (T0843).")`
| tstats `summariesonly` count from datamodel=Network_Traffic where nodename=All_Traffic by _time, All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.file_name, All_Traffic.protocol
| `drop_dm_object_name("All_Traffic")`
| rename file_name as file_path
| `is_in_ot_network(dest_ip)`
| search NOT [`is_eng_workstation(src_ip)`]
| where match(file_path, "(?i)\.(exe|dll|bin|s7p|msf|out|ps1|bat)$")
| eval activity="Suspicious File Download to OT", mitre_technique="Program Download (T0843)", command=""

| append [
    `comment("Pattern 2: Detects high-risk commands sent from unauthorized systems (T0861).")`
    | search (`ot_protocol_logs`)
    | `is_in_ot_network(dest_ip)`
    | search NOT [`is_eng_workstation(src_ip)`]
    | search command IN ("Write Single Coil", "Write Multiple Coils", "Write Single Register", "Write Multiple Registers", "PLC Stop", "S7 Download")
    | eval activity="Unauthorized High-Risk ICS Command", mitre_technique="Unauthorized Command Message (T0861)", file_path=""
]

`comment("Combine results from both patterns for a unified alert.")`
| stats
    min(_time) as start_time,
    max(_time) as end_time,
    values(mitre_technique) as mitre_techniques,
    values(activity) as activities,
    values(protocol) as protocols,
    values(command) as commands,
    values(file_path) as file_paths
    by src_ip, dest_ip
| eval start_time = strftime(start_time, "%Y-%m-%dT%H:%M:%SZ")
| eval end_time = strftime(end_time, "%Y-%m-%dT%H:%M:%SZ")
| eval mitre_tactic="Impair Process Control"
| `ics_specific_malware_activity_filter`
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
-- Tuning Steps:
-- 1. Create and populate the lookups: 'ot_asset_lookup.csv', 'eng_workstation_lookup.csv', and 'ics_remote_ports_lookup.csv'.
-- 2. Configure the macros `ot_auth_failure_logs` and `network_traffic_logs` to point to your relevant data sources.
-- 3. Adjust the 'brute_force_threshold' value based on your environment's baseline authentication failures.

`comment("Define macros for data sources and thresholds. These should be configured in your Splunk environment.")`
`comment("Macro: ot_auth_failure_logs -> index=wineventlog sourcetype=wineventlog:security EventCode=4625 OR (index=ot sourcetype=ot_auth status=failure)")`
`comment("Macro: network_traffic_logs -> index=netfw OR index=zeek")`
`comment("Macro: brute_force_threshold -> 15")`

`comment("Pattern 1: Brute Force (T0806) - Looks for a high number of failed logins to an OT asset.")`
| search `ot_auth_failure_logs`
`comment("Identify destination as an OT asset using a lookup.")`
| lookup ot_asset_lookup.csv asset_ip as dest OUTPUTNEW asset_name
| where isnotnull(asset_name)
`comment("Count failed logins over a 10-minute window.")`
| bucket _time span=10m
| stats count by _time, src, dest, user
`comment("Apply brute force threshold. Tune this value for your environment.")`
| where count > `brute_force_threshold`
`comment("Format results for correlation.")`
| eval activity="Potential Brute Force Against OT Asset", mitre_technique="Brute Force (T0806)", dest_port="N/A"
| fields _time, src, dest, user, activity, mitre_technique, dest_port

| append [
    `comment("Pattern 2: Unauthorized Connection to Remote Services (T0866) - Looks for connections to sensitive OT ports from non-standard systems.")`
    | search `network_traffic_logs`
    `comment("Identify destination as an OT asset.")`
    | lookup ot_asset_lookup.csv asset_ip as dest OUTPUTNEW asset_name
    | where isnotnull(asset_name)
    `comment("Filter out traffic from known engineering workstations.")`
    | lookup eng_workstation_lookup.csv workstation_ip as src OUTPUTNEW is_eng_workstation
    | where isnull(is_eng_workstation)
    `comment("Filter for connections to sensitive ICS ports. The lookup should contain 'port' and 'protocol_name' fields.")`
    | lookup ics_remote_ports_lookup.csv port as dest_port OUTPUTNEW protocol_name
    | where isnotnull(protocol_name)
    `comment("Summarize connections over a 1-hour window.")`
    | bucket _time span=1h
    | stats values(dest_port) as dest_port by _time, src, dest
    `comment("Format results for correlation.")`
    | eval activity="Unauthorized Connection to OT Remote Service", mitre_technique="Exploitation of Remote Services (T0866)", user="N/A"
    | fields _time, src, dest, user, activity, mitre_technique, dest_port
]

`comment("Combine and summarize results from both patterns for alerting.")`
| stats
    min(_time) as start_time,
    max(_time) as end_time,
    values(activity) as activities,
    values(mitre_technique) as mitre_techniques,
    values(user) as users,
    values(dest_port) as destination_ports
    by src, dest
| eval start_time = strftime(start_time, "%Y-%m-%dT%H:%M:%SZ")
| eval end_time = strftime(end_time, "%Y-%m-%dT%H:%M:%SZ")
| eval mitre_tactic="Initial Access"
| rename src as SourceIP, dest as DestinationDevice
| `weak_authentication_or_access_to_ics_ot_systems_filter`
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
-- Tuning Steps:
-- 1. CRITICAL: Populate the 'der_asset_ips.csv' lookup with the public IP addresses of your DER and other internet-facing OT assets. The lookup should have a field named 'asset_ip'.
-- 2. Adjust the thresholds in the macros 'port_scan_threshold' and 'login_failure_threshold' based on your baseline network traffic.
-- 3. Populate the 'known_benign_scanners.csv' lookup with IPs of known benign scanners (e.g., Shodan, Censys) to reduce noise. The lookup should have a field named 'scanner_ip'.
-- 4. Customize the 'known_vulnerability_paths.csv' and 'known_scanner_user_agents.csv' lookups to include patterns relevant to your specific DER devices.

`comment("Define macros for thresholds and lists. These should be configured in your Splunk environment.")`
`comment("Macro: port_scan_threshold -> 5")`
`comment("Macro: login_failure_threshold -> 10")`

`comment("Pattern 1: External Port Scanning of DER Assets (T0868)")`
| tstats `summariesonly` dc(All_Traffic.dest_port) as port_count, values(All_Traffic.dest_port) as scanned_ports from datamodel=Network_Traffic where `cim_corporate_web_domain_search(All_Traffic.dest_ip)` AND NOT `is_private_ip(All_Traffic.src_ip)` AND NOT `is_known_scanner(All_Traffic.src_ip)` by _time, All_Traffic.src_ip, All_Traffic.dest_ip
| `drop_dm_object_name("All_Traffic")`
| where port_count > `port_scan_threshold`
| eval activity="Port Scanning of DER Asset", technique="Remote Services (T0868)", details=mvjoin(scanned_ports, ", ")
| fields _time, src_ip, dest_ip, activity, technique, details

| append [
    `comment("Pattern 2: Web-based Exploit Attempts against DER Assets (T0882)")`
    | tstats `summariesonly` values(Web.url) as urls, values(Web.http_user_agent) as user_agents from datamodel=Web where `cim_corporate_web_domain_search(Web.dest_ip)` AND NOT `is_private_ip(Web.src_ip)` AND (`contains_vuln_path(Web.url)` OR `is_known_scanner_ua(Web.http_user_agent)`) by _time, Web.src_ip, Web.dest_ip
    | `drop_dm_object_name("Web")`
    | eval activity="Web Exploit Attempt Against DER Asset", technique="Exploitation of Vulnerability (T0882)", details="URLs: " . mvjoin(urls, "; ") . " | UserAgents: " . mvjoin(user_agents, "; ")
    | fields _time, src_ip, dest_ip, activity, technique, details
]

| append [
    `comment("Pattern 3: External Brute-Force Attempts against DER Assets (T0868)")`
    | tstats `summariesonly` count from datamodel=Network_Traffic where `cim_corporate_web_domain_search(All_Traffic.dest_ip)` AND NOT `is_private_ip(All_Traffic.src_ip)` AND All_Traffic.action=denied by _time, All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port
    | `drop_dm_object_name("All_Traffic")`
    | where count > `login_failure_threshold`
    | eval activity="Brute-Force Attempt Against DER Asset", technique="Remote Services (T0868)", details="Failed to connect " . count . " times to port " . dest_port
    | fields _time, src_ip, dest_ip, activity, technique, details
]

`comment("Combine results from all patterns for a unified alert.")`
| rename dest_ip as DestinationAssetIP, src_ip as SourceIP
| stats
    earliest(_time) as start_time,
    latest(_time) as end_time,
    values(activity) as Activities,
    values(technique) as Techniques,
    values(details) as ActivityDetails
    by SourceIP, DestinationAssetIP
| eval start_time = strftime(start_time, "%Y-%m-%dT%H:%M:%SZ")
| eval end_time = strftime(end_time, "%Y-%m-%dT%H:%M:%SZ")
| eval tactic="Initial Access"
| `exploitation_of_internet_connected_der_vulnerabilities_filter`
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

-- Tuning Steps:
-- 1. CRITICAL: Create and populate the lookups 'it_network_ranges_lookup.csv', 'ot_network_ranges_lookup.csv', and 'authorized_jump_hosts_lookup.csv'.
-- 2. CRITICAL: Create and populate the lookup 'lateral_movement_ports_lookup.csv' with administrative ports used in your environment.
-- 3. Ensure the macros below are configured to use these lookups.
-- 4. This rule uses the Network_Traffic datamodel. Ensure your network data (firewall, Zeek, etc.) is CIM-compliant.

`comment("Define macros for network ranges, hosts, and ports. These must be configured by the user. Example macro definition: [| inputlookup my_lookup.csv | fields my_field]")`
`comment("Macro: get_it_networks -> [| inputlookup it_network_ranges_lookup.csv | fields cidr]")`
`comment("Macro: get_ot_networks -> [| inputlookup ot_network_ranges_lookup.csv | fields cidr]")`
`comment("Macro: get_authorized_jump_hosts -> [| inputlookup authorized_jump_hosts_lookup.csv | fields host_ip]")`
`comment("Macro: get_lateral_movement_ports -> [| inputlookup lateral_movement_ports_lookup.csv | fields port]")`

`comment("Pattern 1: Detects traffic that violates the defined IT <-> OT segmentation policy.")`
| tstats `summariesonly` count from datamodel=Network_Traffic where (nodename=All_Traffic) by _time, All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port
| `drop_dm_object_name("All_Traffic")`
| where src_ip NOT IN `get_authorized_jump_hosts`
| where (src_ip IN `get_it_networks` AND dest_ip IN `get_ot_networks`) OR (src_ip IN `get_ot_networks` AND dest_ip IN `get_it_networks`)
| eval violation_type="Prohibited Cross-Segment Communication", mitre_techniques="T0864"

| append [
    `comment("Pattern 2: Detects anomalous peer-to-peer communication within the OT zone using administrative protocols.")`
    | tstats `summariesonly` count from datamodel=Network_Traffic where (nodename=All_Traffic) by _time, All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port
    | `drop_dm_object_name("All_Traffic")`
    | where src_ip IN `get_ot_networks` AND dest_ip IN `get_ot_networks`
    | where dest_port IN `get_lateral_movement_ports`
    | where src_ip NOT IN `get_authorized_jump_hosts` AND dest_ip NOT IN `get_authorized_jump_hosts`
    | eval violation_type="Anomalous Intra-OT Peer Communication", mitre_techniques="T0864, T0865"
]

`comment("Combine results from both patterns for a unified alert.")`
| stats
    earliest(_time) as start_time,
    latest(_time) as end_time,
    values(dest_port) as dest_ports,
    sum(count) as connection_count,
    values(mitre_techniques) as mitre_techniques
    by src_ip, dest_ip, violation_type
| eval start_time = strftime(start_time, "%Y-%m-%dT%H:%M:%SZ")
| eval end_time = strftime(end_time, "%Y-%m-%dT%H:%M:%SZ")
| eval mitre_tactic="Lateral Movement (TA0109)"
| eval summary = "Potential lateral movement detected from ".src_ip." to ".dest_ip.". Policy Violated: ".violation_type
| `lateral_movement_in_segmented_ics_environments_filter`
```