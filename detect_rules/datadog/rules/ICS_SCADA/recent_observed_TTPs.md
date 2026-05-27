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

-- Required Lookups:
--   - ot_personnel_lookup.csv: Use Datadog attributes or tags for OT personnel filtering.

-- Log Search Query (use in Datadog Logs Explorer):
source:email @email.to.address:(ot_user1@company.com OR ot_user2@company.com)  -- Filter for OT personnel; replace with actual emails or use tags
((@file.name:"(?i)\\.(iso|img|vhd|vhd|js|jse|vbs|vbe|wsf|hta|html|lnk)$" OR @file.name:"(?i)\\.(zip|rar|7z|ace)$") OR (@url.category:Malicious OR @url.verdict:Malicious) OR @url.original:"(?i)\\.(xyz|top|club|live|icu|gq|ru|click|link)$")
-@email.from.domain:(mycompany.com OR trustedpartner.com)  -- Exclude known-good domains

-- In Logs Explorer:
-- - Group by: @email.from.address, @email.to.address
-- - Measure: count() as count, values(@threat_indicator) as threat_indicators, min(@timestamp) as first_seen, max(@timestamp) as last_seen, values(@email.subject) as subjects, values(@file.name) as attachments, values(@url.original) as urls
-- For threat_indicator, use a formula in UI or pre-compute via logs processing rules.
-- Optimize by using indexed facets like @email.to.address to reduce query time.
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

-- Log Search Query:
source:edr @process.code_signature.signed:false @process.executable:"(?i)(C:\\Users\\|C:\\ProgramData|C:\\PerfLogs|C:\\Windows\\Temp)" @network.direction:outbound -@process.name:(teams.exe OR ms-teams.exe OR OneDrive.exe OR chrome.exe OR msedge.exe OR gupdate.exe OR slack.exe OR Zoom.exe OR Code.exe OR Spotify.exe OR msrdc.exe) -@network.destination.ip:(10.* OR 172.16.* OR 192.168.* OR 127.* OR 169.254.* OR fe80::* OR ::1)

-- In Logs Explorer:
-- - Group by: @host.name, @process.entity_id
-- - Measure: min(@timestamp) as first_seen, max(@timestamp) as last_seen, values(@process.name) as process_name, values(@process.executable) as process_path, values(@usr.name) as user, values(@network.destination.ip) as public_destination_ips
-- Use IP range exclusions in query for optimization.
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

-- Log Search Query:
source:scada @parameter_name:* -@usr.name:(operator_john OR scada_admin OR ics_maintenance_svc) (@parameter_name:"(?i)EmergencyShutdown|SafetyBypassActive|CoreTempAlarmThreshold|VoltageLevel|PumpPressure" OR distinct_parameter_count:>15)  -- Use processing rules for distinct count if needed

-- In Logs Explorer:
-- - Group by: @timestamp (with 1h binning), @usr.name, @network.source.ip
-- - Measure: count_distinct(@parameter_name) as distinct_parameter_count, values(@parameter_name) as all_parameters_changed, values(@device) as devices_affected
-- Use formulas for detection_reason based on conditions.
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
--   This rule requires endpoint file monitoring logs (e.g., Sysmon, CrowdStrike, Defender for Endpoint).

-- Tactic(s):
--   - Impact (TA0040)

-- Technique(s):
--   - Data Manipulation: Data from Local System (T1565.001)

-- False Positive Sensitivity: Medium
--   - Legitimate administrative scripts or third-party backup software not included in the allowlist may trigger this alert.
--   - Review and tune the process allowlist based on the software used in your OT environment.

-- Data Source:
--   - EDR / File System Monitoring Logs

-- Log Search Query:
source:edr @event.action:(created OR modified) (@file.path:"(?i)(\\backup|\\archive)" OR @file.name:"(?i)\\.(bak|bkf|zip|rar|7z|dmp|sql|apa|zap|mer)$") -@process.name:(wbengine.exe OR sqlservr.exe OR RSLinxNG.exe OR FTAManager.exe OR WinCCExplorer.exe) @host.name:critical_ot_asset*  -- Filter for critical assets

-- In Logs Explorer:
-- - Group by: @host.name, @usr.name, @process.name
-- - Measure: count() as count, min(@timestamp) as first_seen, max(@timestamp) as last_seen, values(@file.path) as modified_backup_files, values(@process.cmdline) as command_lines
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
--   - EDR / Endpoint Logs

-- Log Search Query:
source:edr @process.name:(RSLinxNG.exe OR FTView.exe OR LogixDesigner.exe OR CCW.exe OR WinCCExplorer.exe OR s7epasrvx.exe OR view.exe) -@file.path:"(?i)^C:\\Windows\\" -@file.path:"(?i)^C:\\Program Files\\" -@file.path:"(?i)^C:\\Program Files (x86)\\" @host.name:critical_ot_asset*

-- In Logs Explorer:
-- - Group by: @host.name, @usr.name, @process.name, @process.executable
-- - Measure: count() as count, min(@timestamp) as first_seen, max(@timestamp) as last_seen, values(@file.name) as loaded_dlls, values(@file.path) as dll_paths, values(@file.hash) as dll_hashes, values(@file.code_signature.signed) as dll_is_signed
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
--   - Network Traffic / Firewall Logs

-- Log Search Query:
source:network ((@network.source.ip:(192.168.* OR 10.*) AND @network.destination.ip:172.16.*) OR (@network.source.ip:172.16.* AND @network.destination.ip:(192.168.* OR 10.*))) -((@network.source.ip:192.168.1.50 AND @network.destination.ip:172.16.10.100 AND @network.destination.port:502) OR (@network.source.ip:172.16.20.5 AND @network.destination.ip:192.168.1.200 AND @network.destination.port:445) OR (@network.source.ip:192.168.5.25 AND @network.destination.ip:172.16.30.15 AND @network.destination.port:44818))

-- In Logs Explorer:
-- - Group by: @network.source.ip, @network.destination.ip, @network.destination.port
-- - Measure: count() as count, min(@timestamp) as first_seen, max(@timestamp) as last_seen, values(@usr.name) as user, values(@process.name) as process_name, sum(@network.bytes_out) as total_bytes_out, sum(@network.bytes_in) as total_bytes_in
-- Use formulas for traffic_direction.
```