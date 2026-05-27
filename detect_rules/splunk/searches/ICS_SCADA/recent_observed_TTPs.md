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

-- Description: >
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
--   - Assumes CIM compliance (e.g., `dest`, `src_user`, `file_name`, `url`).

-- Required Lookups:
--   - ot_personnel_lookup.csv: A lookup file containing the email addresses of OT/ICS personnel. It must have a header named 'recipient_email'.

(index=email OR sourcetype=cim_email)

-- Step 1: Enrich email events by identifying recipients who are part of OT/ICS teams.
-- Tuning: Ensure 'ot_personnel_lookup.csv' is populated with the email addresses of your OT/ICS staff.
| lookup ot_personnel_lookup.csv recipient_email AS dest OUTPUT is_ot_personnel

-- Step 2: Filter for emails sent specifically to the identified OT/ICS personnel.
| where is_ot_personnel="true"

-- Step 3: Identify emails containing suspicious indicators related to attachments or links.
| eval threat_indicator=case(
    -- T1566.001: Detects attachments with file types commonly used to deliver malware, such as disk images or scripts.
    match(file_name, "(?i)\.(iso|img|vhd|vhd|js|jse|vbs|vbe|wsf|hta|html|lnk)$"), "Suspicious Attachment Type",
    -- T1566.001: Flags archive files that could be used to conceal malicious payloads.
    match(file_name, "(?i)\.(zip|rar|7z|ace)$"), "Archive Attachment For Review",
    -- T1566.002: Identifies emails where the security gateway has already classified a URL as malicious.
    (url_category="Malicious" OR url_verdict="Malicious"), "Malicious URL Detected",
    -- T1566.002: Heuristic check for URLs using low-reputation or commonly abused TLDs.
    match(url, "(?i)\.(xyz|top|club|live|icu|gq|ru|click|link)$"), "URL with Suspicious TLD"
  )
| where isnotnull(threat_indicator)

-- Step 4: Filter out known-good or internal senders to reduce noise.
-- Tuning: Add your organization's domains and trusted partner domains to this list.
| where NOT (src_user_domain IN ("mycompany.com", "trustedpartner.com"))

-- Step 5: Aggregate the results to create a concise alert for investigation.
| stats count,
    values(threat_indicator) as threat_indicators,
    earliest(_time) as first_seen,
    latest(_time) as last_seen,
    values(subject) as subjects,
    values(file_name) as attachments,
    values(url) as urls by src_user, dest
| rename src_user as sender, dest as recipient
| convert ctime(first_seen) ctime(last_seen)
| fields - count
| `phishing_attempt_targeting_ot_ics_personnel_filter`
```

### Custom RAT Detection
---
```sql
-- Name: Unsigned Process From Unusual Location With Network Connection
-- Author: RW
-- Date: 2025-08-20

-- Description: >
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
--   - Assumes CIM compliance and correlation of process and network events via a unique ID like `process_guid`.

-- Step 1: Gather process start and network connection events using a unique process identifier.
(index=* (tag=process tag=start) OR (tag=network tag=communicate))
| stats values(tag) as event_types,
    values(process_path) as process_path,
    values(process_name) as process_name,
    values(is_signed) as is_signed,
    values(user) as user,
    values(dest) as dest_ips
    by process_guid, host, _time

-- Step 2: Filter for correlated events that include both a process start and a network connection.
| where "start" IN (event_types) AND "communicate" IN (event_types)

-- Step 3: Filter for processes that are unsigned.
| where is_signed="false"

-- Step 4: Filter for processes executing from suspicious, user-writable, or temporary locations.
-- Tuning: Add or remove paths based on your organization's policies and baseline activity.
| where match(process_path, "(?i)(C:\\Users\\|C:\\ProgramData|C:\\PerfLogs|C:\\Windows\\Temp)")

-- Step 5: Filter out known legitimate processes that may exhibit this behavior.
-- Tuning: This is the most critical part for reducing false positives. Add legitimate software common in your environment.
| where NOT (
    process_name IN (
        "teams.exe", "ms-teams.exe", "OneDrive.exe", "chrome.exe", "msedge.exe",
        "gupdate.exe", "slack.exe", "Zoom.exe", "Code.exe", "Spotify.exe", "msrdc.exe"
    )
)

-- Step 6: Filter out connections to only private/internal IP space.
| mvexpand dest_ips
| rename dest_ips as dest_ip
| where NOT (
    cidrmatch("10.0.0.0/8", dest_ip) OR
    cidrmatch("172.16.0.0/12", dest_ip) OR
    cidrmatch("192.168.0.0/16", dest_ip) OR
    cidrmatch("127.0.0.0/8", dest_ip) OR
    cidrmatch("169.254.0.0/16", dest_ip) OR
    cidrmatch("fe80::/10", dest_ip) OR
    cidrmatch("::1/128", dest_ip)
)

-- Step 7: Aggregate the final results for alerting.
| stats earliest(_time) as first_seen,
    latest(_time) as last_seen,
    values(process_name) as process_name,
    values(process_path) as process_path,
    values(user) as user,
    values(dest_ip) as public_destination_ips
    by host, process_guid
| convert ctime(first_seen), ctime(last_seen)
| `unsigned_process_from_unusual_location_with_network_connection_filter`
```

### SCADA Parameter Tampering
---
```sql
-- Name: SCADA Parameter Tampering
-- Author: RW
-- Date: 2025-08-20

-- Description: >
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

-- Step 1: Define base search for SCADA/ICS parameter change events.
-- IMPORTANT: Replace `index=ot sourcetype=scada_change` with your actual SCADA log source.
-- Field names like `user`, `src`, `parameter_name`, `device` are placeholders.

(index=ot sourcetype=scada_change)

-- Step 2: Aggregate parameter change events by user and source over a 1-hour window.
| bin _time span=1h
| stats
    dc(parameter_name) as distinct_parameter_count,
    values(parameter_name) as all_parameters_changed,
    values(device) as devices_affected
    by _time, user, src

-- Step 3: Define allowlists and critical parameters, then apply detection logic.
-- Tuning: For production, move these lists to lookup files for better management.
| eval is_authorized = if(user IN ("operator_john", "scada_admin", "ics_maintenance_svc"), "true", "false")
| eval critical_params_changed = mvfilter(match(all_parameters_changed, "(?i)EmergencyShutdown|SafetyBypassActive|CoreTempAlarmThreshold|VoltageLevel|PumpPressure"))
-- Tuning: Adjust the threshold for bulk changes based on your environment's baseline.
| eval detection_reason = case(
    isnotnull(critical_params_changed) AND is_authorized=="false", "Unauthorized Critical Parameter Change",
    distinct_parameter_count > 15, "Bulk Parameter Change"
  )

-- Step 4: Filter for events that match the detection criteria and format for alerting.
| where isnotnull(detection_reason)
| rename user as modifying_user, src as source_ip, _time as time
| convert ctime(time)
| table time, modifying_user, source_ip, detection_reason, distinct_parameter_count, critical_params_changed, devices_affected, all_parameters_changed
| `scada_parameter_tampering_filter`
```

### Backup Dataset Manipulation
---
```sql
-- Name: SCADA/ICS Backup Dataset Manipulation
-- Author: RW
-- Date: 2025-08-20

-- Description: >
--   Detects attempts to modify or create backup files on critical SCADA/ICS assets using non-standard or suspicious processes.
--   This activity could indicate an attacker attempting to poison backup datasets to disrupt recovery efforts, as described in the threat intelligence.
--   This rule requires endpoint file monitoring logs (e.g., Sysmon, CrowdStrike, Defender for Endpoint) mapped to the Splunk CIM.

-- Tactic(s):
--   - Impact (TA0040)

-- Technique(s):
--   - Data Manipulation: Data from Local System (T1565.001)

-- False Positive Sensitivity: Medium
--   - Legitimate administrative scripts or third-party backup software not included in the allowlist may trigger this alert.
--   - Review and tune the process allowlist based on the software used in your OT environment.

-- Data Source:
--   - EDR / File System Monitoring Logs (CIM Compliant)

-- Required Lookups:
--   - critical_ot_assets.csv: A lookup file containing the hostnames of critical SCADA/ICS assets. It must have a header named 'host'.

`cim_file_system_models`

-- Step 1: Filter for file creation or modification events on critical OT assets.
-- Tuning: Ensure the 'critical_ot_assets.csv' lookup is populated with your SCADA servers, HMIs, and Engineering Workstations.
| search [| inputlookup critical_ot_assets.csv | fields host]
| search (action="created" OR action="modified")

-- Step 2: Identify files that appear to be backups by path or extension.
-- Tuning: Add backup folder names and file extensions specific to your SCADA/ICS software.
| where (
    match(file_path, "(?i)(\\backup|\\archive)") OR
    match(file_name, "(?i)\.(bak|bkf|zip|rar|7z|dmp|sql|apa|zap|mer)$")
  )

-- Step 3: Filter out modifications made by known, legitimate backup processes.
-- Tuning: This is the most important step for reducing false positives. Add all authorized backup software processes from your environment.
| where NOT (
    process_name IN (
        "wbengine.exe",       # Windows Server Backup
        "sqlservr.exe",       # SQL Server
        "RSLinxNG.exe",       # Rockwell FactoryTalk (example)
        "FTAManager.exe",     # Rockwell FactoryTalk AssetCentre (example)
        "WinCCExplorer.exe"   # Siemens WinCC (example)
        # Add other legitimate backup/SCADA processes here
    )
)

-- Step 4: Group results and format for alerting.
| stats count,
    earliest(_time) as first_seen,
    latest(_time) as last_seen,
    values(file_path) as modified_backup_files,
    values(process_command_line) as command_lines
    by host, user, process_name
| where count > 0
| rename host as asset_hostname, user as modifying_user, process_name as modifying_process
| convert ctime(first_seen), ctime(last_seen)
| `scada_ics_backup_dataset_manipulation_filter`
```

### Exploitation of SCADA Vulnerabilities
---
```sql
-- Name: SCADA Application DLL Hijacking Attempt
-- Author: RW
-- Date: 2025-08-20

-- Description: >
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
--   - EDR / Endpoint Logs (CIM Compliant)

-- Required Lookups:
--   - critical_ot_assets.csv: A lookup file containing the hostnames of critical SCADA/ICS assets. It must have a header named 'host'.

`cim_endpoint_models`
| where (nodename = "Image_Loads")

-- Step 1: Filter for events on critical OT assets.
-- Tuning: Ensure the 'critical_ot_assets.csv' lookup is populated with your SCADA servers, HMIs, and Engineering Workstations.
| search [| inputlookup critical_ot_assets.csv | fields host]

-- Step 2: Filter for known SCADA/ICS application processes.
-- Tuning: This list is critical. Add the primary executables for the SCADA software used in your OT environment.
| where process_name IN (
    "RSLinxNG.exe",       # Rockwell
    "FTView.exe",         # Rockwell
    "LogixDesigner.exe",  # Rockwell
    "CCW.exe",            # Rockwell
    "WinCCExplorer.exe",  # Siemens
    "s7epasrvx.exe",      # Siemens
    "view.exe"            # Wonderware/AVEVA
    # Add other legitimate SCADA processes here
)

-- Step 3: Identify DLLs loaded from non-standard or suspicious locations.
-- This logic excludes legitimate Windows and Program Files directories, flagging anything else.
-- Tuning: If you have SCADA software installed in other standard locations (e.g., D:\SCADA\), add them to the exclusion list.
| where NOT (
    match(file_path, "(?i)^C:\\Windows\\") OR
    match(file_path, "(?i)^C:\\Program Files\\") OR
    match(file_path, "(?i)^C:\\Program Files (x86)\\")
)

-- Step 4: Group results and format for alerting.
| stats count,
    earliest(_time) as first_seen,
    latest(_time) as last_seen,
    values(file_name) as loaded_dlls,
    values(file_path) as dll_paths,
    values(file_hash) as dll_hashes,
    values(is_signed) as dll_is_signed
    by host, user, process_name, process_path
| rename host as asset_hostname, user as executing_user, process_name as scada_process, process_path as scada_process_path
| convert ctime(first_seen), ctime(last_seen)
| `scada_application_dll_hijacking_attempt_filter`
```

### IT/OT Network Segmentation Bypass
---
```sql
-- Name: IT/OT Network Segmentation Bypass
-- Author: RW
-- Date: 2025-08-20

-- Description: >
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
--   - Network Traffic / Firewall Logs (CIM Compliant)

-- Required Lookups:
--   - Recommended: Use lookups for the IT/OT subnets and the allowlist for easier management.

`cim_network_traffic_models`
| where isnotnull(src_ip) AND isnotnull(dest_ip)

-- Step 1: Define IT and OT network segments.
-- Tuning: Replace these CIDR ranges with the subnets for your IT and OT environments.
| eval is_src_it = if(cidrmatch("192.168.0.0/16", src_ip) OR cidrmatch("10.0.0.0/8", src_ip), 1, 0)
| eval is_dest_it = if(cidrmatch("192.168.0.0/16", dest_ip) OR cidrmatch("10.0.0.0/8", dest_ip), 1, 0)
| eval is_src_ot = if(cidrmatch("172.16.0.0/12", src_ip), 1, 0)
| eval is_dest_ot = if(cidrmatch("172.16.0.0/12", dest_ip), 1, 0)

-- Step 2: Filter for traffic that crosses the defined IT/OT boundary.
| where (is_src_it=1 AND is_dest_ot=1) OR (is_src_ot=1 AND is_dest_it=1)

-- Step 3: Filter out known, legitimate cross-segment communications.
-- Tuning: This is the most critical step for reducing false positives. Add all authorized connections.
| where NOT (
    # Example: IT Historian Server pulling data from an OT PLC via Modbus
    (src_ip="192.168.1.50" AND dest_ip="172.16.10.100" AND dest_port=502) OR
    # Example: OT Jump Box accessing a file server in the IT network via SMB
    (src_ip="172.16.20.5" AND dest_ip="192.168.1.200" AND dest_port=445) OR
    # Example: Engineering Workstation in IT pushing a configuration to an HMI in OT
    (src_ip="192.168.5.25" AND dest_ip="172.16.30.15" AND dest_port=44818)
)

-- Step 4: Aggregate unauthorized connections and format for alerting.
| stats count,
    earliest(_time) as first_seen,
    latest(_time) as last_seen,
    values(user) as user,
    values(process_name) as process_name,
    sum(bytes_out) as total_bytes_out,
    sum(bytes_in) as total_bytes_in
    by src_ip, dest_ip, dest_port, is_src_it

-- Step 5: Add context and rename fields for clarity.
| eval traffic_direction = if(is_src_it=1, "IT_to_OT", "OT_to_IT")
| rename src_ip as source_ip, dest_ip as destination_ip, dest_port as destination_port
| convert ctime(first_seen), ctime(last_seen)
| fields - is_src_it
| `it_ot_network_segmentation_bypass_filter`
```