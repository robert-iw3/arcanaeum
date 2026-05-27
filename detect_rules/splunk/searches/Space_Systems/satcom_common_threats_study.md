### Satellite Cyberattacks and Security
---

This report analyzes the cyberattack landscape for satellite systems, highlighting vulnerabilities across space, ground, user, and link segments, and detailing potential consequences such as service disruption, loss of control, extortion, and espionage. It emphasizes the critical need for robust cybersecurity measures and outlines current industry efforts and challenges in addressing these threats.

Recent intelligence indicates a growing trend of nation-state actors utilizing sophisticated cyber espionage techniques against the satellite industry, often leveraging supply chain vulnerabilities and direct satellite communication link attacks to maintain persistence and exfiltrate sensitive data. This evolution necessitates a shift towards proactive, multi-layered defense strategies beyond traditional perimeter security.

### Actionable Threat Data
---

Spear Phishing Campaigns Targeting Ground Station Personnel: Adversaries use OSINT to identify key personnel with privileged access to ground stations, followed by spear phishing via email and social media to gain initial access to workstations and subsequently satellite control systems.

Exploitation of Unencrypted Satellite Communication Links: Attackers can intercept and potentially modify data transmitted over unencrypted radiofrequency (RF) communication links between satellites and ground stations, leading to data confidentiality loss or service disruption.

Supply Chain Compromises in Satellite Hardware/Software: Vulnerabilities introduced through the complex supply chain, including counterfeit microelectronics, malicious hardware/software implants, or insecure development practices, provide persistent access points for adversaries.

Malicious Commands and Anomalous Telemetry: Unauthorized commands sent to satellites or unusual deviations in telemetry data can indicate a cyberattack aimed at disrupting services, seizing control, or causing physical damage to the satellite.

Exploitation of Cloud-Based Ground Station Services: The increasing adoption of cloud services for ground station operations expands the attack surface, making these platforms potential targets for adversaries to command attacks or access sensitive data.

### Spear Phishing Ground Crew
---
```sql
-- Name: Spear Phishing of Satellite Ground Crew
-- Author: RW
-- Date: 2025-08-19

-- Description: Detects when a high-value user, such as satellite ground crew, receives a phishing email and subsequently clicks on a URL contained within it. This behavior is a common TTP for gaining initial access to sensitive aerospace networks.

-- Tags: SATELLITE, AEROSPACE, INITIAL_ACCESS, PHISHING
-- Tactic: TA0001 (Initial Access)
-- Technique: T1566.002 (Spearphishing Link)

-- False Positives: This rule may trigger if a legitimate email is incorrectly classified as phishing. The accuracy is highly dependent on the upstream phishing detection tool and the proper configuration of the high-value user list.

-- Data Source Requirements:
-- - Email security logs (e.g., O365, Proofpoint) with phishing verdicts and extracted URLs.
-- - Web proxy or EDR network logs with user and URL click information.
-- - The CIM (Common Information Model) is recommended for normalization.

-- Macro/Lookup Requirements:
-- - `high_value_satellite_personnel`: A macro or lookup that contains the email addresses or user IDs of the high-value personnel to monitor.
--   Example lookup definition: | inputlookup high_value_satellite_personnel.csv
--   Example macro definition: `(user="user1@example.com" OR user="user2@example.com")`

(
    `comment("Get phishing emails sent to high-value users")`
    (index=* sourcetype=o365:management:activity OR sourcetype=proofpoint:tap)
    threat_verdict=phishing
    `high_value_satellite_personnel`
    | mvexpand urls
    | rename recipient AS user, urls AS url, subject AS email_subject, sender AS sender
    | eval event_type="email_received"
    | fields _time, user, url, email_subject, sender, event_type
)
| append [
    `comment("Get URL clicks from high-value users")`
    (index=* sourcetype=pan:traffic OR sourcetype=zscaler:nss:web)
    action=allowed
    `high_value_satellite_personnel`
    | eval event_type="url_clicked"
    | fields _time, user, url, event_type
]
`comment("Correlate email and click events by user and URL")`
| stats
    earliest(eval(if(event_type="email_received", _time, null()))) as email_time,
    latest(eval(if(event_type="url_clicked", _time, null()))) as click_time,
    values(eval(if(event_type="email_received", email_subject, null()))) as email_subject,
    values(eval(if(event_type="email_received", sender, null()))) as sender
    by user, url
`comment("Filter for events where a click happened within 1 hour after the email was received")`
| where isnotnull(email_time) AND isnotnull(click_time) AND (click_time > email_time) AND (click_time - email_time) <= 3600
`comment("Format the output for alerting")`
| eval time_to_click_seconds = click_time - email_time
| convert ctime(email_time)
| convert ctime(click_time)
| table user, sender, email_subject, url, email_time, click_time, time_to_click_seconds
| rename user as "User", sender as "Sender", email_subject as "Email Subject", url as "Clicked URL", email_time as "Email Time", click_time as "Click Time", time_to_click_seconds as "Time to Click (Seconds)"
```

### Unencrypted SatCom Exploitation
---
```sql
-- Name: Unencrypted Satellite Communication Traffic
-- Author: RW
-- Date: 2025-08-19

-- Description: Detects large volumes of potentially unencrypted network traffic between known ground station assets and satellite gateways. This could indicate an adversary exploiting unencrypted RF links for data interception or modification. This detection is highly dependent on environmental context and requires careful tuning of the associated reference lists and thresholds.

-- Tags: SATELLITE, AEROSPACE, COLLECTION, MITM
-- Tactic: TA0009 (Collection)
-- Technique: T1040 (Network Sniffing), T1557 (Man-in-the-Middle)

-- False Positives: Legitimate, high-volume unencrypted traffic used for specific telemetry or data transfer protocols. Normal operational traffic that uses non-standard ports but is still encrypted. The rule's effectiveness relies on accurate IP and port lists and a well-baselined data transfer threshold.

-- Data Source Requirements:
-- - CIM-compliant network traffic data (e.g., firewall, NetFlow).

-- Macro/Lookup Requirements:
-- - `ground_station_ips`: A macro or lookup containing the IP addresses of ground station assets.
--   Example macro: `(src_ip="192.168.1.10" OR src_ip="10.100.50.25")`
-- - `satellite_gateway_ips`: A macro or lookup containing the IP addresses of satellite gateways.
--   Example macro: `(dest_ip="203.0.113.100" OR dest_ip="198.51.100.200")`
-- - `known_encrypted_ports`: A macro or lookup containing destination ports known to carry encrypted traffic.
--   Example macro: `(dest_port="443" OR dest_port="22" OR dest_port="990")`

| tstats `summariesonly` sum(All_Traffic.bytes) as total_bytes from datamodel=Network_Traffic where
    # Filter for bidirectional traffic between ground stations and satellite gateways
    (
        (All_Traffic.src_ip IN `ground_station_ips` AND All_Traffic.dest_ip IN `satellite_gateway_ips`)
        OR
        (All_Traffic.src_ip IN `satellite_gateway_ips` AND All_Traffic.dest_ip IN `ground_station_ips`)
    )
    # Exclude traffic on ports commonly used for encrypted protocols
    AND NOT All_Traffic.dest_port IN `known_encrypted_ports`
    # Group data by source, destination, and a 1-hour time window
    by All_Traffic.src_ip, All_Traffic.dest_ip, _time span=1h
| rename "All_Traffic.*" as *
# Define the data transfer threshold (10 MB) and filter for traffic exceeding it
| where total_bytes > 10485760
# Convert bytes to a more readable format (MB)
| eval total_mb_transferred = round(total_bytes / 1024 / 1024, 2)
| convert ctime(_time)
# Format the final output table for alerting
| table _time, src_ip, dest_ip, total_mb_transferred
| rename src_ip as "Source IP", dest_ip as "Destination IP", total_mb_transferred as "Total MB Transferred"
```

### Supply Chain Compromise
---
```sql
-- Name: Suspicious Outbound Connection from Development Tool on Sensitive Host
-- Author: RW
-- Date: 2025-08-19

-- Description: Detects when a software development or build tool (like a compiler or build engine) on a sensitive system makes an outbound network connection to an unknown external IP address. This could indicate a compromised supply chain, where malicious code injected into a dependency or tool establishes a C2 channel. This is a potential indicator of the TTPs regarding supply chain compromises.

-- Tags: SATELLITE, AEROSPACE, SUPPLY_CHAIN, COMMAND_AND_CONTROL
-- Tactic: TA0011 (Command and Control), TA0003 (Persistence)
-- Technique: T1071 (Application Layer Protocol), T1554 (Compromise Client Software Binary)

-- False Positives: Legitimate developer activity, such as fetching dependencies from a new or uncategorized repository. Ad-hoc scripts or tools making legitimate network calls. Tuning the allowlists for sensitive hosts, processes, and known destinations is critical to reduce noise.

-- Data Source Requirements:
-- - EDR logs with process and network connection details, specifically Sysmon Event Code 3.
-- - Data must be ingested and parsed, with fields like `host`, `Image`, `CommandLine`, `DestinationIp`, and `DestinationHostname`.

-- Macro/Lookup Requirements:
-- - `sensitive_build_systems`: A macro or lookup containing the hostnames of sensitive systems like CI/CD servers, code repositories, etc.
--   Example macro: `(host="build-server-01" OR host="dev-lead-ws01.example.com")`
-- - `build_and_dev_processes`: A macro or lookup containing the names of development and build tools.
--   Example macro: `(Image="*\\MSBuild.exe" OR Image="*\\gcc.exe" OR Image="*\\make.exe")`
-- - `known_good_destinations`: A macro or lookup containing a regex of known-good domains to exclude.
--   Example macro: `NOT (match(DestinationHostname, "(?i)(github\.com|api\.nuget\.org|dev\.azure\.com)$"))`

`comment("Filter for Sysmon network connection events")`
(index=* sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational EventCode=3)
`comment("Filter for events on sensitive systems like build servers or key developer workstations")`
| search `sensitive_build_systems`
`comment("Filter for connections initiated by a development/build tool")`
| search `build_and_dev_processes`
`comment("Focus on external connections by excluding private and loopback IP ranges")`
| where NOT (
    cidrmatch("10.0.0.0/8", DestinationIp) OR
    cidrmatch("172.16.0.0/12", DestinationIp) OR
    cidrmatch("192.168.0.0/16", DestinationIp) OR
    cidrmatch("127.0.0.0/8", DestinationIp)
  )
`comment("Exclude connections to known good destinations to reduce false positives")`
| search `known_good_destinations`
`comment("Group related activity by host and process over a 1-hour window to reduce alert volume")`
| bucket _time span=1h
| stats
    count,
    values(DestinationIp) as target_ips,
    values(DestinationHostname) as target_hostnames,
    values(DestinationPort) as target_ports
    by _time, host, user, Image, CommandLine
`comment("Format the output for alerting")`
| rename
    host as principal_hostname,
    user as principal_user,
    Image as principal_process_path,
    CommandLine as principal_process_command_line
| table
    _time,
    principal_hostname,
    principal_user,
    principal_process_path,
    principal_process_command_line,
    target_ips,
    target_hostnames,
    target_ports,
    count
```

### Malicious Sat Commands
---
```sql
-- Name: Malicious Satellite Command Anomaly
-- Author: RW
-- Date: 2025-08-19

-- Description: Detects commands that were reportedly received and executed by a satellite but have no corresponding 'sent' record from the ground control station logs. This indicates a potential command injection attack, either from a compromised ground station asset or via a Man-in-the-Middle (MitM) attack on the command link itself. This detection relies on the defense-in-depth strategy of cross-validating commands sent from the ground with telemetry received from the satellite, as discussed in the reference.

-- Tags: SATELLITE, AEROSPACE, COMMAND_AND_CONTROL, IMPACT
-- Tactic: TA0011 (Command and Control), TA0040 (Impact)
-- Technique: T1071 (Application Layer Protocol), T1489 (Service Stop)

-- False Positives: Logging delays between the ground station and satellite telemetry ingestion. Dropped logs from the ground control station. Misconfigured or non-unique command identifiers across log sources.

-- Data Source Requirements:
-- - Ground Control Station (GCS) logs showing commands sent. Must have a unique command_id.
-- - Satellite telemetry logs showing commands received/executed. Must have the same unique command_id.

-- Macro/Lookup Requirements:
-- - `satellite_command_logs`: A macro to define the index and sourcetypes for both GCS and telemetry logs.
--   Example: `(index=satellite sourcetype=gcs_commands OR sourcetype=telemetry_receipts)`

`satellite_command_logs`
`comment("Identify the source of the command log: ground station 'sent' or satellite 'received'")`
| eval command_source = case(
    sourcetype="gcs_commands", "sent",
    sourcetype="telemetry_receipts", "received"
  )
`comment("Filter out events that are not relevant command logs")`
| where isnotnull(command_source) AND isnotnull(command_id)
`comment("Correlate events by the unique command ID over a 1-hour time window")`
| bucket _time span=1h
| stats
    count(eval(command_source="sent")) as sent_count,
    count(eval(command_source="received")) as received_count,
    values(satellite_id) as satellite_id,
    values(command_details) as command_details
    by _time, command_id
`comment("The core detection logic: a command was received, but no corresponding command was sent")`
| where received_count > 0 AND sent_count = 0
`comment("Format the output for alerting")`
| convert ctime(_time)
| rename
    _time as "Time",
    command_id as "Anomalous Command ID",
    satellite_id as "Target Satellite ID",
    received_count as "Telemetry Receipt Count",
    command_details as "Anomalous Command Details"
| table Time, "Anomalous Command ID", "Target Satellite ID", "Telemetry Receipt Count", "Anomalous Command Details"
```

### Cloud-Based Ground Station Exploitation
---
```sql
-- Name: Cloud-Based Ground Station Exploitation
-- Author: RW
-- Date: 2025-08-19

-- Description: Detects when a user account designated as high-value (e.g., satellite ground crew) performs sensitive cloud management actions from an IP address associated with known threat activity. This could indicate a compromised account is being used to manipulate cloud-based ground station services for malicious purposes, such as data exfiltration or command injection.

-- Tags: SATELLITE, AEROSPACE, CLOUD, AZURE, AWS, GCP
-- Tactic: TA0006 (Credential Access), TA0011 (Command and Control)
-- Technique: T1078.004 (Valid Accounts: Cloud Accounts)

-- False Positives: Threat intelligence misattributions. Legitimate administrative activity from a shared or dynamic IP that was previously associated with malicious activity. Use of legitimate VPN services whose exit nodes are on threat lists.

-- Data Source Requirements:
-- - CIM-compliant cloud infrastructure logs (e.g., AWS CloudTrail, Azure Activity Logs, GCP Audit Logs).

-- Macro/Lookup Requirements:
-- - `satellite_operations_crew`: A macro or lookup containing the user identities of the satellite operations team.
--   Example macro: `(All_Changes.user="alice" OR All_Changes.user="bob@example.com")`
-- - `sensitive_cloud_operations`: A macro or lookup containing sensitive cloud operations relevant to ground station control.
--   Example macro: `(All_Changes.operation="Microsoft.Orbital/contacts/write" OR All_Changes.operation="CreateContact" OR All_Changes.operation="*networksecuritygroups*")`
-- - `threat_intel_ip_lookup`: A lookup file or command that enriches IP addresses with threat intelligence.
--   Example: `| lookup my_ti_ip_lookup.csv ip as src_ip`

`comment("Search cloud infrastructure audit logs for changes.")`
| tstats `summariesonly` values(All_Changes.operation) as operations, values(All_Changes.object) as target_resources, count from datamodel=Cloud_Infrastructure where
    `comment("Filter for actions performed by high-value users.")`
    `satellite_operations_crew`
    AND
    `comment("Filter for sensitive operations relevant to ground station control or data access.")`
    `sensitive_cloud_operations`
    by All_Changes.user, All_Changes.src_ip, _time span=1h
| rename "All_Changes.*" as *
`comment("Look up the source IP against a threat intelligence feed.")`
| `threat_intel_ip_lookup`
`comment("Filter for events where the source IP has a known threat association.")`
| where isnotnull(threat_type)
`comment("Format the results for alerting.")`
| convert ctime(_time)
| rename user as "Principal_User", src_ip as "Suspicious_Source_IP", operations as "Attempted_Operations", target_resources as "Target_Resources", threat_type as "Threat_Type", threat_description as "Threat_Description", count as "Event_Count"
| table _time, Principal_User, Suspicious_Source_IP, Attempted_Operations, Target_Resources, Threat_Type, Threat_Description, Event_Count
```