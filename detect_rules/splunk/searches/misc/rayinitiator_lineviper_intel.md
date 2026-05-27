### Malware Analysis Report: RayInitiator & LINE VIPER
---

RayInitiator is a sophisticated multi-stage bootkit designed for persistent compromise of Cisco ASA 5500-X series devices without secure boot, enabling the deployment of the LINE VIPER user-mode shellcode loader. LINE VIPER provides extensive capabilities for command execution, data exfiltration, and defense evasion, posing a significant threat to targeted organizations.

Recent intelligence highlights that the threat actor, identified as UAT4356 (aka Storm-1849) and linked to the ArcaneDoor campaign, is actively exploiting zero-day vulnerabilities (CVE-2025-20333, CVE-2025-20362, and CVE-2025-20363) in Cisco ASA devices to deploy RayInitiator and LINE VIPER. This represents a significant evolution in sophistication and operational security compared to previous campaigns, with a particular focus on anti-forensic techniques and encrypted command-and-control (C2) communications.

### Actionable Threat Data
---

Anomalous WebVPN Client Authentication Requests: Monitor Cisco ASA WebVPN client authentication sessions for unusual patterns, especially those containing partial PKCS7 certificates followed by shellcode, or XML elements with victim-specific tokens and Base64-encoded shellcode.

Syslog Suppression and Modification: Detect the suppression or significant volumetric decrease of specific Cisco ASA syslog IDs (302013, 302014, 609002, 710005), as LINE VIPER actively suppresses these messages to evade detection. Also, look for any modifications to syslog configurations or unexpected changes in logging behavior.

Unexpected Device Reboots or Crashes: Implement alerts for sudden or unexplained reboots of Cisco ASA devices, particularly if they occur after attempts to generate a core dump or execute diagnostic commands, as this is an anti-forensic measure employed by LINE VIPER.

Unauthorized CLI Command Execution and Harvesting: Monitor for the execution of unusual or unauthorized CLI commands, especially those granting level 15 privileges, and be alert for any indications of CLI command harvesting (Syslog IDs 111008, 111009).

AAA Bypass Activity: Look for instances of AAA bypass for actor-controlled devices, which LINE VIPER achieves by maintaining a table of device IDs that circumvent AAA checks.

Unusual Packet Capture Activity: Detect the initiation of packet captures that are not associated with legitimate administrative tasks, particularly if they target protocols like RADIUS, LDAP, or TACACS, as LINE VIPER can perform covert packet captures.

### Anomalous WebVPN Auth Requests
---
```sql
(sourcetype=cisco:asa OR sourcetype=cisco_asa)
-- This search looks for patterns in WebVPN authentication requests associated with LINE VIPER malware delivery, as described in NCSC-MAR-RAYINITIATOR-LINE-VIPER.
| eval detection_reason=if(
    (
        -- Detects WebVPN requests with a partial PKCS7 certificate or a client-cert-auth-signature element, known delivery methods for LINE VIPER shellcode. Potential for FPs exists; consider tuning by source IP or user agent if noise occurs.
        match(_raw, "(?i)<config-auth.*<client-cert\s+cert-format=\"pkcs7\">") OR
        match(_raw, "(?i)<config-auth.*<client-cert-auth-signature.*>")
    ),
    "Anomalous WebVPN Auth Request for LINE VIPER",
    null()
)
| where isnotnull(detection_reason)
-- Group alerts by device and source IP.
| stats earliest(_time) as firstTime latest(_time) as lastTime values(_raw) as raw_events count by dest, src, detection_reason
| rename dest as device, src as source_ip
```

### Syslog Suppression
---
```sql
-- This search detects potential syslog suppression on Cisco ASA devices, a technique used by LINE VIPER malware. It identifies devices that previously generated specific syslog messages related to C2 activity but have stopped in the last 24 hours, indicating possible tampering.
(sourcetype=cisco:asa OR sourcetype=cisco_asa) message_id IN (302013, 302014, 609002, 710005) earliest=-8d@d
-- Categorize events into a historical baseline (last 7 days, excluding today) and a current period (last 24 hours).
| eval period=if(_time >= relative_time(now(), "-24h"), "current_24h", "historical_7d")
-- Count the number of relevant events for each device in each period.
| stats earliest(_time) as firstTime, latest(_time) as lastTime, count by dest, period
-- Pivot the data to have one row per device, showing counts from both periods.
| stats values(period) as periods, values(count) as counts, min(firstTime) as firstTime, max(lastTime) as lastTime by dest
-- The core detection logic: find devices that had logs historically but have none in the current period. A threshold is used to ensure the historical activity was significant enough to be considered a baseline.
| where mvcount(periods) == 1 AND mvindex(periods, 0) == "historical_7d"
| eval historical_count=mvindex(counts, 0)
-- The historical_count_threshold can be tuned based on your environment's typical log volume. A higher value reduces false positives but may miss suppression on low-volume devices.
| where historical_count > 20
| rename dest as device
| fields device, firstTime, lastTime, historical_count
```

### Unexpected Device Reboots
---
```sql
(sourcetype=cisco:asa OR sourcetype=cisco_asa)
-- Detects high-severity syslog messages indicating a device reboot or a failover event, which could be an anti-forensic technique used by LINE VIPER.
message_id IN (
    199001, -- Message ID for 'Device reloaded'.
    199002, -- Message ID for 'Device reloaded' which includes a reason.
    104001  -- Message ID for a device in an HA pair switching to the ACTIVE state.
)
-- Aggregate results by the affected device, showing the time and the specific messages observed.
| stats earliest(_time) as firstTime, latest(_time) as lastTime, values(message) as reboot_messages, values(message_id) as message_ids, count by dest
| rename dest as device
-- These events can be legitimate during planned maintenance. To identify malicious activity, investigate the logs preceding the reboot for suspicious commands (e.g., 'crashinfo', 'copy system:/text', 'verify'). Correlating alerts with change management data can help reduce false positives.
| `cisco_asa_unexpected_reboot_filter`
```

### Unauthorized CLI Command Execution
---
```sql
(sourcetype=cisco:asa OR sourcetype=cisco_asa) message_id IN (111008, 111009)
-- Detects CLI command execution events. According to NCSC-MAR-RAYINITIATOR-LINE-VIPER, LINE VIPER hooks the functions that generate these logs to harvest commands.
| rex field=message "User '(?<user>[^']+)' executed (the '|cmd: )(?<command>[^\\n']+)'?"
-- Filter for specific commands associated with LINE VIPER's packet capture and anti-forensic capabilities. This reduces noise from benign administrative commands.
| where match(command, /(?i)(capture|copy system:\/text|verify)/)
-- Aggregate results to show which users executed suspicious commands on which devices.
| stats earliest(_time) as firstTime, latest(_time) as lastTime, values(command) as suspicious_commands, count by dest, user
| rename dest as device
-- FP Mitigation: Legitimate administrators may use the 'capture' command. Investigate the user and the context of the command. Consider adding a filter to exclude known administrative activity or users, e.g., '| where user NOT IN ('admin1', 'admin2')'.
| `line_viper_unauthorized_cli_execution_filter`
```

### AAA Bypass Activity
---
```sql
(sourcetype=cisco:asa OR sourcetype=cisco_asa)
-- Detects a WebVPN XML pattern used by LINE VIPER for AAA bypass, where specific device-id attributes are blank but the unique-id is populated. Ref: NCSC-MAR-RAYINITIATOR-LINE-VIPER.
| where match(_raw, "(?i)<device-id\s+computer-name=\"\"\s+device-type=\"\"\s+platform-version=\"\"\s+unique-id=\"[^\"]+\"")
-- Extract the unique device ID from the raw log for investigation.
| rex field=_raw "unique-id=\"(?<unique_id>[^\"]+)\""
-- Aggregate alerts to show which source IPs are attempting this bypass against which ASA devices.
| stats earliest(_time) as firstTime, latest(_time) as lastTime, values(unique_id) as unique_ids, count by dest, src
| rename dest as device, src as source_ip
-- FP Mitigation: A non-standard or misconfigured legitimate client could potentially generate similar logs. Investigate the source_ip and associated activity. Consider adding an allowlist for known benign source IPs if false positives occur.
| `line_viper_aaa_bypass_activity_filter`
```

### Covert Packet Capture
---
```sql
(sourcetype=cisco:asa OR sourcetype=cisco_asa) message_id IN (111008, 111009)
-- Detects CLI command execution events. According to NCSC-MAR-RAYINITIATOR-LINE-VIPER, LINE VIPER can initiate covert packet captures.
| rex field=message "User '(?<user>[^']+)' executed (the '|cmd: )(?<command>.+)'"
-- Filter for the 'capture' command being executed, specifically targeting sensitive authentication protocols mentioned in the threat intelligence.
| where like(lower(command), "%capture%") AND (like(lower(command), "%radius%") OR like(lower(command), "%ldap%") OR like(lower(command), "%tacacs%"))
-- Aggregate results to show which users executed these specific captures on which devices.
| stats earliest(_time) as firstTime, latest(_time) as lastTime, values(command) as capture_commands, count by dest, user
| rename dest as device
-- FP Mitigation: Legitimate administrators may perform packet captures on these protocols for troubleshooting. This activity should be correlated with change management tickets or known administrative tasks. Investigate the user and the context of the command. Consider creating an allowlist of authorized users if this generates noise.
| `line_viper_covert_packet_capture_filter`
```