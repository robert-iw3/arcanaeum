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
-- This search looks for patterns in WebVPN authentication requests associated with LINE VIPER malware delivery, as described in NCSC-MAR-RAYINITIATOR-LINE-VIPER.
FROM logs-cisco.asa-*
| WHERE (event.module == "cisco:asa" OR event.module == "cisco_asa")
  AND (REGEXP(message, "(?i)<config-auth.*<client-cert\\s+cert-format=\"pkcs7\">") OR REGEXP(message, "(?i)<config-auth.*<client-cert-auth-signature.*>"))
| EVAL detection_reason = "Anomalous WebVPN Auth Request for LINE VIPER"
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), raw_events = MV_CONCAT(message), count = COUNT(*) BY host.name, source.ip, detection_reason
| RENAME host.name AS device, source.ip AS source_ip
| KEEP device, source_ip, firstTime, lastTime, raw_events, count, detection_reason
```

### Syslog Suppression
---
```sql
-- This search detects potential syslog suppression on Cisco ASA devices, a technique used by LINE VIPER malware. It identifies devices that previously generated specific syslog messages related to C2 activity but have stopped in the last 24 hours, indicating possible tampering.
FROM logs-cisco.asa-*
| WHERE @timestamp >= NOW() - INTERVAL 8 DAYS
  AND cisco.asa.message_id IN ("302013", "302014", "609002", "710005")
  AND (event.module == "cisco:asa" OR event.module == "cisco_asa")
| EVAL period = CASE(@timestamp >= NOW() - INTERVAL 1 DAY, "current_24h", "historical_7d")
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp),
        historical_count = COUNT_IF(period == "historical_7d"),
        current_count = COUNT_IF(period == "current_24h")
  BY host.name
| WHERE historical_count > 20 AND current_count == 0
| RENAME host.name AS device
| KEEP device, firstTime, lastTime, historical_count
```

### Unexpected Device Reboots
---
```sql
-- Detects high-severity syslog messages indicating a device reboot or a failover event, which could be an anti-forensic technique used by LINE VIPER.
FROM logs-cisco.asa-*
| WHERE (event.module == "cisco:asa" OR event.module == "cisco_asa")
  AND cisco.asa.message_id IN ("199001", "199002", "104001")
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp),
        reboot_messages = MV_CONCAT(message), message_ids = MV_CONCAT(cisco.asa.message_id), count = COUNT(*)
  BY host.name
| RENAME host.name AS device
| KEEP device, firstTime, lastTime, reboot_messages, message_ids, count
```

### Unauthorized CLI Command Execution
---
```sql
FROM logs-cisco.asa-*
| WHERE (event.module == "cisco:asa" OR event.module == "cisco_asa")
  AND cisco.asa.message_id IN ("111008", "111009")
| EVAL command = GROK(message, "User '%{QUOTEDSTRING:user}' executed (the '|cmd: )%{GREEDYDATA:command}'?").command,
       user = GROK(message, "User '%{QUOTEDSTRING:user}' executed (the '|cmd: )%{GREEDYDATA:command}'?").user
| WHERE REGEXP(command, "(?i)(capture|copy system:\\/text|verify)")
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp),
        suspicious_commands = MV_CONCAT(command), count = COUNT(*)
  BY host.name, user
| RENAME host.name AS device
| KEEP device, user, firstTime, lastTime, suspicious_commands, count
```

### AAA Bypass Activity
---
```sql
FROM logs-cisco.asa-*
| WHERE (event.module == "cisco:asa" OR event.module == "cisco_asa")
  AND REGEXP(message, "(?i)<device-id\\s+computer-name=\"\"\\s+device-type=\"\"\\s+platform-version=\"\"\\s+unique-id=\"[^\"]+\"")
| EVAL unique_id = GROK(message, "unique-id=\"%{DATA:unique_id}\"").unique_id
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp),
        unique_ids = MV_CONCAT(unique_id), count = COUNT(*)
  BY host.name, source.ip
| RENAME host.name AS device, source.ip AS source_ip
| KEEP device, source_ip, firstTime, lastTime, unique_ids, count
```

### Covert Packet Capture
---
```sql
FROM logs-cisco.asa-*
| WHERE (event.module == "cisco:asa" OR event.module == "cisco_asa")
  AND cisco.asa.message_id IN ("111008", "111009")
| EVAL command = GROK(message, "User '%{QUOTEDSTRING:user}' executed (the '|cmd: )%{GREEDYDATA:command}'").command,
       user = GROK(message, "User '%{QUOTEDSTRING:user}' executed (the '|cmd: )%{GREEDYDATA:command}'").user
| WHERE LIKE(LOWER(command), "%capture%") AND (LIKE(LOWER(command), "%radius%") OR LIKE(LOWER(command), "%ldap%") OR LIKE(LOWER(command), "%tacacs%"))
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp),
        capture_commands = MV_CONCAT(command), count = COUNT(*)
  BY host.name, user
| RENAME host.name AS device
| KEEP device, user, firstTime, lastTime, capture_commands, count
```