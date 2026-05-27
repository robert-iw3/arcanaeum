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
-- Assuming Cisco ASA logs are ingested into Deep Visibility with fields like message (_raw equivalent), AgentName (device/dest), source_ip (src), and EventTime (timestamp). Standard S1QL handles filtering; use PowerQuery for aggregation and conditional logic.

-- S1QL Filter (Base Query):
message RegExp "(?i)<config-auth.*<client-cert\\s+cert-format=\"pkcs7\">" OR message RegExp "(?i)<config-auth.*<client-cert-auth-signature.*>"

-- PowerQuery for Detection and Aggregation:
| filter message RegExp "(?i)<config-auth.*<client-cert\\s+cert-format=\"pkcs7\">" OR message RegExp "(?i)<config-auth.*<client-cert-auth-signature.*>"
| let detection_reason = "Anomalous WebVPN Auth Request for LINE VIPER"
| group firstTime = min(EventTime), lastTime = max(EventTime), raw_events = array_concat(message), count = count() by AgentName, source_ip, detection_reason
| columns AgentName as device, source_ip, firstTime, lastTime, raw_events, count, detection_reason
| sort -count

-- Note: The let command adds the detection reason. Use the UI to filter non-null detection_reason if needed. Tune with source_ip exclusions for FPs.
```

### Syslog Suppression
---
```sql
-- This requires baseline comparison (historical vs. current). Use PowerQuery with time-based subqueries or unions for periods. Set query time range to last 8 days.

-- S1QL Filter (Base Query):
message_id = "302013" OR message_id = "302014" OR message_id = "609002" OR message_id = "710005"

-- PowerQuery for Period Comparison and Detection:
| filter EventTime > now - 8d AND (message_id = "302013" OR message_id = "302014" OR message_id = "609002" OR message_id = "710005")
| let period = if(EventTime >= now - 1d, "current_24h", "historical_7d")
| group firstTime = min(EventTime), lastTime = max(EventTime), historical_count = count_if(period = "historical_7d"), current_count = count_if(period = "current_24h") by AgentName
| filter historical_count > 20 AND current_count = 0
| columns AgentName as device, firstTime, lastTime, historical_count
| sort -historical_count

-- Note: The let and count_if approximate eval and conditional counting. For low-volume environments, adjust the >20 threshold. If count_if isn't supported, run separate queries for each period and join in PowerQuery.
```

### Unexpected Device Reboots
---
```sql
-- S1QL Filter (Base Query):
message_id = "199001" OR message_id = "199002" OR message_id = "104001"

-- PowerQuery for Aggregation:
| filter message_id = "199001" OR message_id = "199002" OR message_id = "104001"
| group firstTime = min(EventTime), lastTime = max(EventTime), reboot_messages = array_concat(message), message_ids = array_concat(message_id), count = count() by AgentName
| columns AgentName as device, firstTime, lastTime, reboot_messages, message_ids, count
| sort EventTime desc

-- Note: Correlate with preceding logs (e.g., via ProcessGroupId) for context. Exclude planned maintenance with | filter NOT (message Contains Anycase "planned").
```

### Unauthorized CLI Command Execution
---
```sql
-- Assuming user and command are parsed fields from message via a prior parse command in PowerQuery.

-- S1QL Filter (Base Query):
message_id = "111008" OR message_id = "111009" AND command RegExp "(?i)(capture|copy system:\\/text|verify)"

-- PowerQuery for Extraction and Aggregation:
| filter message_id = "111008" OR message_id = "111009"
| parse user, command from message with regex "User '(?<user>[^']+)' executed (the '|cmd: )(?<command>[^\\n']+)'?"
| filter command RegExp "(?i)(capture|copy system:\\/text|verify)"
| group firstTime = min(EventTime), lastTime = max(EventTime), suspicious_commands = array_concat(command), count = count() by AgentName, user
| columns AgentName as device, user, firstTime, lastTime, suspicious_commands, count
| sort -count

-- Note: The parse command uses regex for extraction. Exclude known admins with | filter user != "admin1" AND user != "admin2".
```

### AAA Bypass Activity
---
```sql
-- S1QL Filter (Base Query):
message RegExp "(?i)<device-id\\s+computer-name=\"\"\\s+device-type=\"\"\\s+platform-version=\"\"\\s+unique-id=\"[^\"]+\""

-- PowerQuery for Extraction and Aggregation:
| filter message RegExp "(?i)<device-id\\s+computer-name=\"\"\\s+device-type=\"\"\\s+platform-version=\"\"\\s+unique-id=\"[^\"]+\""
| parse unique_id from message with regex "unique-id=\"(?<unique_id>[^\"]+)\""
| group firstTime = min(EventTime), lastTime = max(EventTime), unique_ids = array_concat(unique_id), count = count() by AgentName, source_ip
| columns AgentName as device, source_ip, firstTime, lastTime, unique_ids, count
| sort -count

-- Note: Allowlist benign source_ip with | filter source_ip != "allowed_ip1".
```

### Covert Packet Capture
---
```sql
-- Assuming user and command parsed as above.

-- S1QL Filter (Base Query):
message_id = "111008" OR message_id = "111009" AND command Contains Anycase "capture" AND (command Contains Anycase "radius" OR command Contains Anycase "ldap" OR command Contains Anycase "tacacs")

-- PowerQuery for Extraction and Aggregation:
| filter message_id = "111008" OR message_id = "111009"
| parse user, command from message with regex "User '(?<user>[^']+)' executed (the '|cmd: )(?<command>.+)'"
| filter lower(command) Contains "capture" AND (lower(command) Contains "radius" OR lower(command) Contains "ldap" OR lower(command) Contains "tacacs")
| group firstTime = min(EventTime), lastTime = max(EventTime), capture_commands = array_concat(command), count = count() by AgentName, user
| columns AgentName as device, user, firstTime, lastTime, capture_commands, count
| sort -count

-- Note: Use lower() function if available for case-insensitive matching; otherwise, rely on Contains Anycase. Correlate with admin tickets externally.
```