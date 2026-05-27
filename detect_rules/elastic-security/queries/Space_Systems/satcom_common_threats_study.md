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

-- Data Source: Email security logs (logs-email-*) and web proxy logs (logs-web-*).
-- Query Strategy: Correlate phishing emails with URL clicks by user and URL within 1 hour, filter for high-value users, and aggregate by user and URL.
-- False Positive Tuning: Rely on upstream phishing verdict; exclude known benign URLs.

(
  FROM logs-email-*
  | WHERE event.dataset IN ("o365.management.activity", "proofpoint.tap")
    AND threat.verdict == "phishing"
    AND user.id IN ("user1@example.com", "user2@example.com")
  | DISSECT urls "%{url}"
  | RENAME message.recipient AS user, message.subject AS email_subject, message.sender AS sender
  | EVAL event_type = "email_received"
  | KEEP @timestamp, user, url, email_subject, sender, event_type
)
| UNION (
  FROM logs-web-*
  | WHERE event.dataset IN ("pan.traffic", "zscaler.nss.web")
    AND event.action == "allowed"
    AND user.id IN ("user1@example.com", "user2@example.com")
  | EVAL event_type = "url_clicked"
  | KEEP @timestamp, user.id AS user, http.url AS url, event_type
)
| STATS
    email_time = MIN_IF(@timestamp, event_type == "email_received"),
    click_time = MAX_IF(@timestamp, event_type == "url_clicked"),
    email_subject = MV_CONCAT(IF(event_type == "email_received", email_subject, NULL)),
    sender = MV_CONCAT(IF(event_type == "email_received", sender, NULL))
  BY user, url
| WHERE email_time IS NOT NULL AND click_time IS NOT NULL
  AND click_time > email_time
  AND (click_time - email_time) <= 3600000
| EVAL time_to_click_seconds = click_time - email_time
| KEEP user, sender, email_subject, url, email_time, click_time, time_to_click_seconds
| RENAME user AS User, sender AS Sender, email_subject AS "Email Subject", url AS "Clicked URL", email_time AS "Email Time", click_time AS "Click Time", time_to_click_seconds AS "Time to Click (Seconds)"
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

-- Data Source: Network traffic logs (logs-network-*).
-- Query Strategy: Filter for traffic between ground stations and gateways on non-encrypted ports, aggregate bytes by source/destination over 1 hour, and flag large transfers.
-- False Positive Tuning: Tune byte threshold and encrypted port list.

FROM logs-network-*
| WHERE (
    (source.ip IN ("192.168.1.10", "10.100.50.25") AND destination.ip IN ("203.0.113.100", "198.51.100.200")) OR
    (source.ip IN ("203.0.113.100", "198.51.100.200") AND destination.ip IN ("192.168.1.10", "10.100.50.25"))
  )
  AND NOT destination.port IN (443, 22, 990)
| STATS total_bytes = SUM(network.bytes) BY source.ip, destination.ip, BUCKET(@timestamp, 1 hour)
| WHERE total_bytes > 10485760
| EVAL total_mb_transferred = ROUND(total_bytes / 1024 / 1024, 2)
| KEEP BUCKET(@timestamp, 1 hour), source.ip, destination.ip, total_mb_transferred
| RENAME BUCKET(@timestamp, 1 hour) AS _time, source.ip AS "Source IP", destination.ip AS "Destination IP", total_mb_transferred AS "Total MB Transferred"
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

-- Data Source: Endpoint network events (logs-endpoint.events-*, Event Code 3).
-- Query Strategy: Filter for development tool processes on sensitive hosts making external connections, exclude known good destinations, and aggregate by host and process.
-- False Positive Tuning: Tune process and destination allowlists.

FROM logs-endpoint.events-*
| WHERE event.code == "3"
  AND host.hostname IN ("build-server-01", "dev-lead-ws01.example.com")
  AND process.executable LIKE ANY ("*\\MSBuild.exe", "*\\gcc.exe", "*\\make.exe")
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
    source.ip LIKE "192.168.%.%" OR
    source.ip LIKE "127.%.%.%"
  )
  AND NOT destination.hostname MATCHES "(?i)(github\.com|api\.nuget\.org|dev\.azure\.com)$"
| BUCKET @timestamp, 1 hour
| STATS
    count = COUNT(*),
    target_ips = MV_CONCAT(DISTINCT destination.ip),
    target_hostnames = MV_CONCAT(DISTINCT destination.hostname),
    target_ports = MV_CONCAT(DISTINCT destination.port)
  BY BUCKET(@timestamp, 1 hour), host.hostname, user.name, process.executable, process.command_line
| KEEP BUCKET(@timestamp, 1 hour), host.hostname, user.name, process.executable, process.command_line, target_ips, target_hostnames, target_ports, count
| RENAME BUCKET(@timestamp, 1 hour) AS _time, host.hostname AS principal_hostname, user.name AS principal_user, process.executable AS principal_process_path, process.command_line AS principal_process_command_line
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

-- Data Source: Satellite command logs (logs-satellite-*).
-- Query Strategy: Categorize sent/received commands, aggregate by command ID over 1 hour, and flag received commands without sent records.
-- False Positive Tuning: Tune for logging delays; ensure unique command IDs.

FROM logs-satellite-*
| WHERE event.dataset == "command_logs" AND @timestamp >= NOW() - 1 hour
  AND command_source IS NOT NULL AND command_id IS NOT NULL
| EVAL command_source = CASE(
    event.dataset == "gcs_commands", "sent",
    event.dataset == "telemetry_receipts", "received",
    command_source
  )
| BUCKET @timestamp, 1 hour
| STATS
    sent_count = COUNT_IF(command_source == "sent"),
    received_count = COUNT_IF(command_source == "received"),
    satellite_id = MV_CONCAT(DISTINCT telemetry.satellite_id),
    command_details = MV_CONCAT(DISTINCT telemetry.command_details)
  BY BUCKET(@timestamp, 1 hour), command_id
| WHERE received_count > 0 AND sent_count = 0
| KEEP BUCKET(@timestamp, 1 hour), command_id, satellite_id, received_count, command_details
| RENAME BUCKET(@timestamp, 1 hour) AS Time, command_id AS "Anomalous Command ID", satellite_id AS "Target Satellite ID", received_count AS "Telemetry Receipt Count", command_details AS "Anomalous Command Details"
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

-- Data Source: Cloud infrastructure logs (logs-cloud-*).
-- Query Strategy: Filter for sensitive operations by high-value users from threat IPs, aggregate by user and IP over 10 minutes.
-- False Positive Tuning: Maintain threat intel lookup and user list.

FROM logs-cloud-*
| WHERE @timestamp >= NOW() - 1 hour
  AND cloud.user.id IN ("alice", "bob@example.com")
  AND event.operation IN ("Microsoft.Orbital/contacts/write", "CreateContact", "*networksecuritygroups*")
| JOIN threat_intel_ip_lookup ON source.ip = threat_intel_ip_lookup.src_ip
| WHERE threat_intel_ip_lookup.threat_type IS NOT NULL
| STATS
    count = COUNT(*),
    operations = MV_CONCAT(DISTINCT event.operation),
    target_resources = MV_CONCAT(DISTINCT event.object)
  BY cloud.user.id, source.ip, BUCKET(@timestamp, 10 minutes)
| KEEP BUCKET(@timestamp, 1 hour), cloud.user.id, source.ip, operations, target_resources, threat_intel_ip_lookup.threat_type, threat_intel_ip_lookup.threat_description, count
| RENAME BUCKET(@timestamp, 1 hour) AS _time, cloud.user.id AS Principal_User, source.ip AS Suspicious_Source_IP, operations AS Attempted_Operations, target_resources AS Target_Resources, threat_intel_ip_lookup.threat_type AS Threat_Type, threat_intel_ip_lookup.threat_description AS Threat_Description, count AS Event_Count
| KEEP _time, Principal_User, Suspicious_Source_IP, Attempted_Operations, Target_Resources, Threat_Type, Threat_Description, Event_Count
```