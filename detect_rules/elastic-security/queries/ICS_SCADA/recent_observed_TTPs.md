### SCADA System Compromise
---

Recent intelligence highlights a significant increase in sophisticated, AI-driven phishing attacks targeting Industrial Control Systems (ICS) operators, making initial access more challenging to detect and prevent. Additionally, newly disclosed vulnerabilities in widely used SCADA systems like ICONICS Suite and Mitsubishi Electric MC Works64 present new avenues for privilege escalation and system compromise once initial access is gained.

### Actionable Threat Data
---

Monitor for spear-phishing attempts targeting employees with access to OT/ICS environments, especially those with attachments or links to credential harvesting sites. (T1566.001, T1566.002)

Implement robust endpoint detection and response (EDR) solutions to identify and block custom-built or polymorphic RATs that may bypass traditional antivirus solutions. (T1059)

Monitor for unusual activity within SCADA/ICS networks, such as changes to operational parameters (e.g., voltage levels, pump pressure, valve states, sensor thresholds) or attempts to access or modify backup datasets. (T1531, T1565.001)

Regularly audit and patch SCADA/ICS software and hardware for known vulnerabilities, particularly those related to DLL hijacking, incorrect default permissions, and uncontrolled search path elements (e.g., CVE-2024-1182, CVE-2024-7587, CVE-2024-8299, CVE-2024-8300, CVE-2024-9852). (T1190, T1068)

Implement network segmentation between IT and OT networks to limit lateral movement in the event of a compromise, and monitor for any unauthorized communication between these environments. (TA0003)

### Phishing for Initial Access
---
```sql
-- Name: Phishing Attempt Targeting OT/ICS Personnel
-- Author: RW
-- Date: 2025-08-20

-- Description:
--   Detects potential spear-phishing attempts targeting OT/ICS personnel.
--   This rule identifies emails sent to individuals in OT/ICS roles that contain either suspicious attachments (by file type) or links (flagged as malicious or using suspicious TLDs).
--   This aligns with the threat intelligence indicating that phishing with malicious attachments is a primary initial access vector for compromising OT environments.

-- Tactic(s):
--   - Initial Access (TA0001)

-- Technique(s):
--   - Phishing: Spearphishing Attachment (T1566.001)
--   - Phishing: Spearphishing Link (T1566.002)

-- False Positive Sensitivity: Medium
--   - This rule's fidelity is highly dependent on the accuracy of the 'ot_personnel_lookup.csv' file. If the list is not maintained, the rule may miss threats or alert on non-OT staff.
--   - Legitimate emails may use archive file types. These should be reviewed for context.
--   - The list of suspicious TLDs may need tuning to match your organization's risk tolerance and typical business communications.

-- Data Source:
--   - Email Gateway Logs (e.g., Proofpoint, Mimecast, Defender for Office 365)
--   - Assumes ECS compliance (e.g., email.to.address, email.from.address, file.name, url.original).

-- Required Lookups:
--   - ot_personnel_lookup.csv: A lookup file containing the email addresses of OT/ICS personnel. It must have a header named 'recipient_email'.
--   Note: In Elastic, lookups can be simulated via enrich processors or scripted fields; for ES|QL, assume pre-enrichment or use EVAL with known lists for simplicity. Here, we simulate with an inline list—replace with actual enrichment.

-- Optimized for detection quality: Use exact matches where possible, regex for patterns, and aggregate to reduce noise.

FROM logs-email-*  -- Target email logs index; adjust as needed for optimization
| WHERE email.to.address IS NOT NULL
-- Simulate lookup filter: Replace with actual enriched field or inline list of OT emails for demo.
| EVAL is_ot_personnel = CASE(IN(email.to.address, ["ot_user1@company.com", "ot_user2@company.com"]), "true", TRUE, "false")  -- Replace with actual OT personnel emails
| WHERE is_ot_personnel == "true"
-- Evaluate threat indicators using regex for patterns
| EVAL threat_indicator = CASE(
    REGEXP(file.name, "(?i)\\.(iso|img|vhd|vhd|js|jse|vbs|vbe|wsf|hta|html|lnk)$"), "Suspicious Attachment Type",
    REGEXP(file.name, "(?i)\\.(zip|rar|7z|ace)$"), "Archive Attachment For Review",
    (url.category == "Malicious" OR url.verdict == "Malicious"), "Malicious URL Detected",
    REGEXP(url.original, "(?i)\\.(xyz|top|club|live|icu|gq|ru|click|link)$"), "URL with Suspicious TLD",
    TRUE, NULL
  )
| WHERE threat_indicator IS NOT NULL
-- Filter out known-good or internal senders
| WHERE NOT IN(SPLIT(email.from.address, "@")[1], ["mycompany.com", "trustedpartner.com"])  -- Extract domain from sender
| STATS count = COUNT(), threat_indicators = VALUES(threat_indicator), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), subjects = VALUES(email.subject), attachments = VALUES(file.name), urls = VALUES(url.original) BY email.from.address, email.to.address
| EVAL first_seen = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", first_seen), last_seen = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", last_seen)
| RENAME email.from.address AS sender, email.to.address AS recipient
| KEEP first_seen, last_seen, sender, recipient, threat_indicators, subjects, attachments, urls
| SORT first_seen DESC
| LIMIT 1000
```

### Custom RAT Detection
---
```sql
-- Name: Unsigned Process From Unusual Location With Network Connection
-- Author: RW
-- Date: 2025-08-20

-- Description:
--   Detects an unsigned process executing from a common user-writable or temporary directory
--   that also makes an outbound network connection. This behavior is highly indicative of
--   custom-built malware or Remote Access Trojans (RATs) as described in the provided threat intelligence,
--   which often bypass traditional AV and execute from non-standard locations.

-- Tactic(s):
--   - Execution (TA0002)
--   - Command and Control (TA0011)

-- Technique(s):
--   - Command and Scripting Interpreter (T1059)
--   - Ingress Tool Transfer (T1105)
--   - Application Layer Protocol (T1071)

-- False Positive Sensitivity: Medium
--   - Legitimate software installers, updaters, or portable applications may be unsigned and execute from user directories.
--   - The list of legitimate processes in the filter needs to be tuned for your environment to reduce noise.

-- Data Source:
--   - Endpoint Detection and Response (EDR) logs (e.g., Sysmon, CrowdStrike, Defender for Endpoint)
--   - Assumes ECS compliance and correlation of process and network events via a unique ID like process.entry_leader.entity_id.

-- Optimized: Join process and network on process.entity_id, use REGEXP for paths, IN for exclusions to leverage query optimization.

FROM logs-endpoint.events.process-*, logs-endpoint.events.network-*  -- Target process and network indices
| WHERE process.entry_leader.entity_id IS NOT NULL AND network.direction == "outbound"
-- Simulate join by aggregating on process.entity_id (assuming correlation via entity_id)
| STATS event_types = VALUES(event.category), process_path = VALUES(process.executable), process_name = VALUES(process.name), is_signed = VALUES(process.code_signature.signed), user = VALUES(user.name), dest_ips = VALUES(destination.ip) BY process.entity_id, host.name, @timestamp
| WHERE "process" IN event_types AND "network" IN event_types
| WHERE is_signed == false
| WHERE REGEXP(process_path, "(?i)(C:\\\\Users\\\\|C:\\\\ProgramData|C:\\\\PerfLogs|C:\\\\Windows\\\\Temp)")
| WHERE NOT IN(process_name, ["teams.exe", "ms-teams.exe", "OneDrive.exe", "chrome.exe", "msedge.exe", "gupdate.exe", "slack.exe", "Zoom.exe", "Code.exe", "Spotify.exe", "msrdc.exe"])
-- Filter out private IPs
| DISSECT dest_ips "*"  -- Handle multi-value if needed
| RENAME dest_ips AS dest_ip
| WHERE NOT (
    CIDR_MATCH(dest_ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fe80::/10", "::1/128")
  )
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), process_name = VALUES(process_name), process_path = VALUES(process_path), user = VALUES(user), public_destination_ips = VALUES(dest_ip) BY host.name, process.entity_id
| EVAL first_seen = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", first_seen), last_seen = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", last_seen)
| KEEP first_seen, last_seen, host.name, process.entity_id, process_name, process_path, user, public_destination_ips
| SORT first_seen DESC
| LIMIT 1000
```

### SCADA Parameter Tampering
---
```sql
-- Name: SCADA Parameter Tampering
-- Author: RW
-- Date: 2025-08-20

-- Description:
--   Detects two patterns of SCADA/ICS parameter manipulation indicative of an attack:
--   1. A high volume of distinct parameter changes made by a single user or from a single source system in a short time.
--   2. Any modification to a pre-defined list of critical parameters by an unauthorized user or system.
--   This aligns with intelligence where attackers made widespread changes to parameters like voltage levels, pump pressure, and valve states.
--   **IMPORTANT**: This rule requires logs from a SCADA/ICS/OT monitoring solution. The index, sourcetype, and field names are placeholders and must be adapted to your specific log source.

-- Tactic(s):
--   - Impact (TA0040)

-- Technique(s):
--   - Account Access Removal (T1531)

-- False Positive Sensitivity: Medium
--   - False positives can occur if a legitimate operator performs bulk configuration changes or if an authorized user is missing from the allowlist.
--   - Thorough tuning of the thresholds and allowlists is essential for your specific OT environment.

-- Data Source:
--   - SCADA/ICS/OT Logs

-- Required Lookups:
--   - Recommended: Use lookups for critical parameters and authorized users/systems for easier management.

-- Optimized: Use windowing via ROW_NUMBER or time bucketing if needed; here, aggregate over 1h windows implicitly via STATS.

FROM logs-ot.scada_change-*  -- Adjust index to your SCADA logs
| STATS distinct_parameter_count = COUNT_DISTINCT(parameter_name), all_parameters_changed = VALUES(parameter_name), devices_affected = VALUES(device) BY @timestamp, user.name, source.ip  -- Bin implicitly; for exact 1h, use DISSECT or EVAL on timestamp
| EVAL is_authorized = CASE(IN(user.name, ["operator_john", "scada_admin", "ics_maintenance_svc"]), "true", "false")
| EVAL critical_params_changed = FILTER(all_parameters_changed, REGEXP(all_parameters_changed, "(?i)EmergencyShutdown|SafetyBypassActive|CoreTempAlarmThreshold|VoltageLevel|PumpPressure"))
| EVAL detection_reason = CASE(
    critical_params_changed IS NOT NULL AND is_authorized == "false", "Unauthorized Critical Parameter Change",
    distinct_parameter_count > 15, "Bulk Parameter Change",
    TRUE, NULL
  )
| WHERE detection_reason IS NOT NULL
| RENAME user.name AS modifying_user, source.ip AS source_ip, @timestamp AS time
| EVAL time = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", time)
| KEEP time, modifying_user, source_ip, detection_reason, distinct_parameter_count, critical_params_changed, devices_affected, all_parameters_changed
| SORT time DESC
| LIMIT 1000
```

### Backup Dataset Manipulation
---
```sql
-- Name: SCADA/ICS Backup Dataset Manipulation
-- Author: RW
-- Date: 2025-08-20

-- Description:
--   Detects attempts to modify or create backup files on critical SCADA/ICS assets using non-standard or suspicious processes.
--   This activity could indicate an attacker attempting to poison backup datasets to disrupt recovery efforts, as described in the threat intelligence.
--   This rule requires endpoint file monitoring logs (e.g., Sysmon, CrowdStrike, Defender for Endpoint) mapped to ECS.

-- Tactic(s):
--   - Impact (TA0040)

-- Technique(s):
--   - Data Manipulation: Data from Local System (T1565.001)

-- False Positive Sensitivity: Medium
--   - Legitimate administrative scripts or third-party backup software not included in the allowlist may trigger this alert.
--   - Review and tune the process allowlist based on the software used in your OT environment.

-- Data Source:
--   - EDR / File System Monitoring Logs (ECS Compliant)

-- Required Lookups:
--   - critical_ot_assets.csv: Simulate with inline list or enrich.

-- FROM logs-endpoint.events.file-*
-- | WHERE host.name IN (lookup critical_ot_assets) -- Simulate
FROM logs-endpoint.events.file-*
| WHERE IN(event.action, ["creation", "modification"])  -- ECS uses 'creation', 'modification'
| WHERE (REGEXP(file.path, "(?i)(\\\\backup|\\\\archive)") OR REGEXP(file.name, "(?i)\\.(bak|bkf|zip|rar|7z|dmp|sql|apa|zap|mer)$"))
| WHERE NOT IN(process.name, ["wbengine.exe", "sqlservr.exe", "RSLinxNG.exe", "FTAManager.exe", "WinCCExplorer.exe"])
| STATS count = COUNT(), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), modified_backup_files = VALUES(file.path), command_lines = VALUES(process.command_line) BY host.name, user.name, process.name
| WHERE count > 0
| RENAME host.name AS asset_hostname, user.name AS modifying_user, process.name AS modifying_process
| EVAL first_seen = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", first_seen), last_seen = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", last_seen)
| KEEP first_seen, last_seen, asset_hostname, modifying_user, modifying_process, modified_backup_files, command_lines, count
| SORT first_seen DESC
| LIMIT 1000
```

### Exploitation of SCADA Vulnerabilities
---
```sql
-- Name: SCADA Application DLL Hijacking Attempt
-- Author: RW
-- Date: 2025-08-20

-- Description:
--   Detects when a known SCADA/ICS application process loads a DLL from an unusual or user-writable directory.
--   This is a strong indicator of a DLL Hijacking attack (T1574.001), often used for privilege escalation (T1068) or persistence on a critical OT asset.
--   This aligns with threat patterns involving exploitation of uncontrolled search paths in SCADA software.

-- Tactic(s):
--   - Privilege Escalation (TA0004)
--   - Persistence (TA0003)
--   - Defense Evasion (TA0005)

-- Technique(s):
--   - Exploitation for Privilege Escalation (T1068)
--   - Hijack Execution: DLL Hijacking (T1574.001)

-- False Positive Sensitivity: Medium
--   - Legitimate but poorly written plugins or helper applications might load DLLs from non-standard paths.
--   - It is critical to populate the process and path allowlists accurately to match your environment.

-- Data Source:
--   - EDR / Endpoint Logs (ECS Compliant)

-- Required Lookups:
--   - critical_ot_assets.csv: Simulate inline.

FROM logs-endpoint.events.library-*  -- For image loads
| WHERE host.name IN (["scada_host1", "scada_host2"])  -- Simulate critical assets
| WHERE IN(process.name, ["RSLinxNG.exe", "FTView.exe", "LogixDesigner.exe", "CCW.exe", "WinCCExplorer.exe", "s7epasrvx.exe", "view.exe"])
| WHERE NOT (REGEXP(file.path, "(?i)^C:\\\\Windows\\\\") OR REGEXP(file.path, "(?i)^C:\\\\Program Files\\\\") OR REGEXP(file.path, "(?i)^C:\\\\Program Files \\(x86\\)\\\\"))
| STATS count = COUNT(), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), loaded_dlls = VALUES(file.name), dll_paths = VALUES(file.path), dll_hashes = VALUES(file.hash.sha256), dll_is_signed = VALUES(file.code_signature.signed) BY host.name, user.name, process.name, process.executable
| RENAME host.name AS asset_hostname, user.name AS executing_user, process.name AS scada_process, process.executable AS scada_process_path
| EVAL first_seen = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", first_seen), last_seen = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", last_seen)
| KEEP first_seen, last_seen, asset_hostname, executing_user, scada_process, scada_process_path, loaded_dlls, dll_paths, dll_hashes, dll_is_signed, count
| SORT first_seen DESC
| LIMIT 1000
```

### IT/OT Network Segmentation Bypass
---
```sql
-- Name: IT/OT Network Segmentation Bypass
-- Author: RW
-- Date: 2025-08-20

-- Description:
--   Detects network traffic that crosses the defined boundary between IT and OT network segments and is not explicitly allowed.
--   This could indicate lateral movement from a compromised IT asset into the critical OT environment, or command-and-control/exfiltration from OT to IT.
--   This rule is highly dependent on the accurate definition of IT/OT subnets and an allowlist of authorized cross-segment communications.

-- Tactic(s):
--   - Lateral Movement (TA0008)
--   - Command and Control (TA0011)

-- Technique(s):
--   - Exploitation of Remote Services (T1210)

-- False Positive Sensitivity: Medium
--   - This rule will generate false positives if the IT/OT subnets are not correctly defined or if legitimate communication channels (e.g., from a data historian, jump box, or engineering workstation) are not added to the allowlist.
--   - It is critical to tune the subnet definitions and the allowlist for your environment.

-- Data Source:
--   - Network Traffic / Firewall Logs (ECS Compliant)

-- Required Lookups:
--   - Recommended: Use lookups for the IT/OT subnets and the allowlist for easier management.

FROM logs-endpoint.events.network-*
| WHERE source.ip IS NOT NULL AND destination.ip IS NOT NULL
| EVAL is_src_it = CASE(CIDR_MATCH(source.ip, "192.168.0.0/16", "10.0.0.0/8"), 1, 0)
| EVAL is_dest_it = CASE(CIDR_MATCH(destination.ip, "192.168.0.0/16", "10.0.0.0/8"), 1, 0)
| EVAL is_src_ot = CASE(CIDR_MATCH(source.ip, "172.16.0.0/12"), 1, 0)
| EVAL is_dest_ot = CASE(CIDR_MATCH(destination.ip, "172.16.0.0/12"), 1, 0)
| WHERE (is_src_it == 1 AND is_dest_ot == 1) OR (is_src_ot == 1 AND is_dest_it == 1)
| WHERE NOT (
    (source.ip == "192.168.1.50" AND destination.ip == "172.16.10.100" AND destination.port == 502) OR
    (source.ip == "172.16.20.5" AND destination.ip == "192.168.1.200" AND destination.port == 445) OR
    (source.ip == "192.168.5.25" AND destination.ip == "172.16.30.15" AND destination.port == 44818)
  )
| STATS count = COUNT(), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), user = VALUES(user.name), process_name = VALUES(process.name), total_bytes_out = SUM(network.bytes_out), total_bytes_in = SUM(network.bytes_in) BY source.ip, destination.ip, destination.port, is_src_it
| EVAL traffic_direction = CASE(is_src_it == 1, "IT_to_OT", "OT_to_IT")
| RENAME source.ip AS source_ip, destination.ip AS destination_ip, destination.port AS destination_port
| EVAL first_seen = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", first_seen), last_seen = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", last_seen)
| KEEP first_seen, last_seen, source_ip, destination_ip, destination_port, user, process_name, total_bytes_out, total_bytes_in, traffic_direction, count
| SORT first_seen DESC
| LIMIT 1000
```