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

-- Data Source: Email security logs (email) and web proxy logs (web).
-- Query Strategy: Union phishing emails and URL clicks, correlate by user and URL within 1 hour, and filter for high-value users.
-- False Positive Tuning: Exclude benign URLs or senders.

-- Phishing Emails
logs(
  source:(o365 OR proofpoint)
  threat.verdict:phishing
  @user:(user1@example.com OR user2@example.com)
)
| mvexpand urls
| eval event_type = "email_received"
| select
    @timestamp,
    message.recipient as user,
    urls as url,
    message.subject as email_subject,
    message.sender as sender,
    event_type

-- URL Clicks
| union(
  logs(
    source:(pan OR zscaler)
    event.action:allowed
    @user:(user1@example.com OR user2@example.com)
  )
  | eval event_type = "url_clicked"
  | select @timestamp, @user as user, http.url as url, event_type
)

-- Correlate and Filter
| group by user, url
| select
    min_if(@timestamp, event_type = "email_received") as email_time,
    max_if(@timestamp, event_type = "url_clicked") as click_time,
    values_if(email_subject, event_type = "email_received") as email_subject,
    values_if(sender, event_type = "email_received") as sender
| where email_time IS NOT NULL AND click_time IS NOT NULL AND click_time > email_time AND (click_time - email_time) <= 3600000
| eval time_to_click_seconds = click_time - email_time
| rename user as "User", sender as "Sender", email_subject as "Email Subject", url as "Clicked URL", email_time as "Email Time", click_time as "Click Time", time_to_click_seconds as "Time to Click (Seconds)"
| display "User", "Sender", "Email Subject", "Clicked URL", "Email Time", "Click Time", "Time to Click (Seconds)"
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

-- Data Source: Network traffic logs (network).
-- Query Strategy: Filter for traffic between ground stations and gateways on non-encrypted ports, aggregate bytes over 1 hour, and flag large transfers.
-- False Positive Tuning: Tune byte threshold and encrypted port tag.

logs(
  source:network
  (
    (network.src_ip:("192.168.1.10" OR "10.100.50.25") AND network.dest_ip:("203.0.113.100" OR "198.51.100.200")) OR
    (network.src_ip:("203.0.113.100" OR "198.51.100.200") AND network.dest_ip:("192.168.1.10" OR "10.100.50.25"))
  )
  -network.dest_port:(443 OR 22 OR 990)
)
| group by network.src_ip, network.dest_ip, span(@timestamp, 1h)
| select
    span(@timestamp, 1h) as _time,
    network.src_ip as "Source IP",
    network.dest_ip as "Destination IP",
    sum(network.bytes) as total_bytes
| where total_bytes > 10485760
| eval total_mb_transferred = round(total_bytes / 1024 / 1024, 2)
| display _time, "Source IP", "Destination IP", "Total MB Transferred"
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

-- Data Source: Endpoint logs (endpoint, Event Code 3).
-- Query Strategy: Filter for development tools on sensitive hosts connecting externally, exclude known good destinations, and group by host and process.
-- False Positive Tuning: Tune process and destination allowlists.

logs(
  source:endpoint
  event.code:3
  @host:(build-server-01 OR dev-lead-ws01.example.com)
  process.executable:(*\\MSBuild.exe OR *\\gcc.exe OR *\\make.exe)
  -network.src_ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16 OR 127.0.0.0/8)
  -network.dest_hostname:(github.com OR api.nuget.org OR dev.azure.com)
)
| group by span(@timestamp, 1h), @host, @user, process.executable, process.command_line
| select
    span(@timestamp, 1h) as _time,
    @host as principal_hostname,
    @user as principal_user,
    process.executable as principal_process_path,
    process.command_line as principal_process_command_line,
    values(network.dest_ip) as target_ips,
    values(network.dest_hostname) as target_hostnames,
    values(network.dest_port) as target_ports,
    count
| display _time, principal_hostname, principal_user, principal_process_path, principal_process_command_line, target_ips, target_hostnames, target_ports, count
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

-- Data Source: Satellite command logs (command_logs).
-- Query Strategy: Categorize sent/received, group by command ID over 1 hour, and flag anomalies.
-- False Positive Tuning: Account for logging delays with time windows.

logs(
  source:command_logs
  @timestamp:[NOW-1h TO NOW]
  @command_source IS NOT NULL
  @command_id IS NOT NULL
)
| eval command_source = case(
  event.dataset = "gcs_commands", "sent",
  event.dataset = "telemetry_receipts", "received",
  @command_source
)
| group by span(@timestamp, 1h), @command_id
| select
    count_if(command_source = "sent") as sent_count,
    count_if(command_source = "received") as received_count,
    values(@satellite_id) as satellite_id,
    values(@command_details) as command_details
| where received_count > 0 AND sent_count = 0
| rename span(@timestamp, 1h) as Time, @command_id as "Anomalous Command ID", satellite_id as "Target Satellite ID", received_count as "Telemetry Receipt Count", command_details as "Anomalous Command Details"
| display Time, "Anomalous Command ID", "Target Satellite ID", "Telemetry Receipt Count", "Anomalous Command Details"
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

-- Data Source: Cloud infrastructure logs (cloud_infrastructure).
-- Query Strategy: Filter for sensitive operations from high-value users from threat IPs, aggregate by user and IP over 10 minutes.
-- False Positive Tuning: Use threat intel integration and user tag.

logs(
  source:cloud_infrastructure
  @timestamp:[NOW-1h TO NOW]
  @user:(
    alice OR bob@example.com
  )
  @operation:(
    "Microsoft.Orbital/contacts/write" OR "CreateContact" OR "*networksecuritygroups*"
  )
)
| join source.ip with threat_intel_ip_lookup on threat_intel_ip_lookup.src_ip = source.ip
| where threat_intel_ip_lookup.threat_type IS NOT NULL
| group by @user, source.ip, span(@timestamp, 10m)
| select
    values(@operation) as operations,
    values(@object) as target_resources,
    count as Event_Count,
    @user as Principal_User,
    source.ip as Suspicious_Source_IP,
    threat_intel_ip_lookup.threat_type as Threat_Type,
    threat_intel_ip_lookup.threat_description as Threat_Description
| display _time, Principal_User, Suspicious_Source_IP, Attempted_Operations=operations, Target_Resources=target_resources, Threat_Type, Threat_Description, Event_Count
```