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
source:(cisco:asa OR cisco_asa) AND ( /(?i)<config-auth.*<client-cert\s+cert-format=\"pkcs7\">/ OR /(?i)<config-auth.*<client-cert-auth-signature.*>/ )
```

### Syslog Suppression
---
```sql
-- This search detects potential syslog suppression on Cisco ASA devices, a technique used by LINE VIPER malware. It identifies devices that previously generated specific syslog messages related to C2 activity but have stopped in the last 24 hours, indicating possible tampering.
source:(cisco:asa OR cisco_asa) @cisco.asa.message_id:(302013 OR 302014 OR 609002 OR 710005)
```

### Unexpected Device Reboots
---
```sql
-- Detects high-severity syslog messages indicating a device reboot or a failover event, which could be an anti-forensic technique used by LINE VIPER.
source:(cisco:asa OR cisco_asa) @cisco.asa.message_id:(199001 OR 199002 OR 104001)
```

### Unauthorized CLI Command Execution
---
```sql
source:(cisco:asa OR cisco_asa) @cisco.asa.message_id:(111008 OR 111009) AND @message:/(?i)(capture|copy system:\/text|verify)/
```

### AAA Bypass Activity
---
```sql
source:(cisco:asa OR cisco_asa) AND /(?i)<device-id\s+computer-name=\"\"\s+device-type=\"\"\s+platform-version=\"\"\s+unique-id=\"[^\"]+\"/
```

### Covert Packet Capture
---
```sql
source:(cisco:asa OR cisco_asa) @cisco.asa.message_id:(111008 OR 111009) AND @message:/(?i)capture/ AND (@message:/(?i)radius/ OR @message:/(?i)ldap/ OR @message:/(?i)tacacs/)
```