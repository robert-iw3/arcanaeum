### ADCS Attack Analysis
---

This report analyzes the attack vectors and impacts, focusing on the exploitation of satellite Attitude Determination and Control System (ADCS) vulnerabilities. The primary attack involved leaking ground station radio configurations and sending malicious commands to abuse the on-board ADCS control algorithm, leading to satellite instability, loss of contact, and flight software crashes.

Recent intelligence highlights a growing trend of nation-state actors targeting satellite systems, including the use of malware to hijack satellites for data exfiltration and command-and-control operations, and the development of anti-satellite weapons. This expands beyond the Hack-A-Sat scenario by demonstrating real-world, sophisticated attacks with broader geopolitical implications and the potential for widespread disruption of critical infrastructure.

### Actionable Threat Data
---

Monitor for unusual or unauthorized access attempts to web servers hosting critical configuration data, specifically looking for exploitation of web vulnerabilities (e.g., "403 Denied" type errors) that could lead to data exfiltration of radio settings or other sensitive operational parameters.

Implement detection rules for anomalous commands sent to satellite ADCS, particularly those modifying control constants to unstable values or attempting to disable safety mechanisms like safe mode. Look for deviations from expected operational parameters in telemetry data.

Establish continuous monitoring of satellite telemetry for indicators of instability, such as rapid increases in wheel speed or angular velocity, which could signal an ongoing ADCS attack.

Analyze ground station communication logs for unexpected or excessive attempts to communicate with satellites using known or newly acquired radio configurations, especially from unusual source IPs or after a web server compromise.

Develop alerts for flight software crashes or unexpected reboots on satellite systems, as these can be a direct result of successful ADCS manipulation or other malicious commands.

### Web Vulnerability Exploitation
---
```sql
-- Name: Potential Web Vulnerability Exploitation Leading to Data Exfiltration
-- Author: RW
-- Date: 2025-08-18
-- Description: This rule detects a pattern where a source IP address first receives an HTTP 403 'Forbidden' error, followed by one or more successful HTTP 200 'OK' responses that involve a large data transfer from a sensitive-looking URL path. This pattern can indicate that an attacker first probed a directory or resource, was denied, and then successfully exploited a vulnerability (e.g., authorization bypass, path traversal) to access and exfiltrate data. This behavior was observed in the Hack-A-Sat competition where a web vulnerability was used to leak sensitive radio configuration data.
-- False Positive Sensitivity: Medium. False positives may occur if a legitimate user is denied access to a resource and then navigates to another page that legitimately serves large files (e.g., reports, software downloads).

-- Data Source: Web logs (logs-web-*).
-- Query Strategy: Identify 403 and 200 responses within a 10-minute window, filter for sensitive URLs, and aggregate by source IP.
-- False Positive Tuning: Tune byte threshold and sensitive path regex.

FROM logs-web-*
| WHERE http.response.status_code IN (200, 403)
| EVAL exfil_threshold_bytes = 100000
| EVAL sensitive_path_regex = "(?i)(config|setting|database|db|admin|backup|dump|export|secret|key|radio|cred|token)"
| EVAL event_type = CASE(
    http.response.status_code == 403, "forbidden_request",
    http.response.status_code == 200 AND http.response.bytes > exfil_threshold_bytes AND url.path MATCHES sensitive_path_regex, "suspicious_exfil_request",
    NULL
  )
| EVAL suspicious_details = IF(event_type == "suspicious_exfil_request", CONCAT("URL=", url.path, ", Bytes=", TO_STRING(http.response.bytes)), NULL)
| STATS
    event_types = MV_CONCAT(DISTINCT event_type),
    suspicious_requests = MV_CONCAT(DISTINCT suspicious_details),
    window_start = MIN(@timestamp),
    window_end = MAX(@timestamp)
  BY source.ip, BUCKET(@timestamp, 10 minutes)
| WHERE event_types LIKE "*forbidden_request*" AND event_types LIKE "*suspicious_exfil_request*"
| KEEP window_start, window_end, source.ip, suspicious_requests
| RENAME source.ip AS SourceIP, suspicious_requests AS SuspiciousExfiltrationRequests
```

### Anomalous ADCS Commands
---
```sql
-- Name: Anomalous Satellite ADCS Commands
-- Author: RW
-- Date: 2025-08-18
-- Description: Detects potentially malicious commands sent to a satellite's Attitude Determination and Control System (ADCS). The rule looks for two primary conditions observed during the Hack-A-Sat competition:
-- 1) Commands that set ADCS control constants (e.g., Kp, Kd, Ki) to extremely high, unstable values.
-- 2) Commands that disable the satellite's safe mode, preventing automated recovery from an unstable state.
-- Detecting these commands is critical for preventing loss of satellite control.
-- False Positive Sensitivity: Medium. False positives may occur if high control constant values are used for legitimate, albeit aggressive, maneuvers. System tests or specific operational modes might also trigger these alerts.

-- Data Source: Satellite command logs (logs-satellite-*).
-- Query Strategy: Extract control constants and safe mode status from log messages, filter for unstable values or disabled safe mode, and categorize anomalies.
-- False Positive Tuning: Adjust threshold for control constants.

FROM logs-satellite-*
| WHERE event.dataset == "satellite_commands" AND (message LIKE "*ADCS*" OR message LIKE "*safe mode*")
| EVAL unstable_threshold = 10000.0
| EVAL Kp = TO_DOUBLE(REGEXP_SUBSTR(message, "Kp\s+([\d\.]+)", 1))
| EVAL Kd = TO_DOUBLE(REGEXP_SUBSTR(message, "Kd\s+([\d\.]+)", 1))
| EVAL Ki = TO_DOUBLE(REGEXP_SUBSTR(message, "Ki\s+([\d\.]+)", 1))
| EVAL kPa = TO_DOUBLE(REGEXP_SUBSTR(message, "kPa\s+([\d\.]+)", 1))
| EVAL kIa = TO_DOUBLE(REGEXP_SUBSTR(message, "kIa\s+([\d\.]+)", 1))
| EVAL kDa = TO_DOUBLE(REGEXP_SUBSTR(message, "kDa\s+([\d\.]+)", 1))
| EVAL kpW = TO_DOUBLE(REGEXP_SUBSTR(message, "kpW\s+([\d\.]+)", 1))
| EVAL is_safe_mode_disabled = IF(message MATCHES "(?i)safe mode (off|disabled)", 1, 0)
| EVAL is_unstable_command = IF(
    (Kp IS NOT NULL AND Kp > unstable_threshold) OR
    (Kd IS NOT NULL AND Kd > unstable_threshold) OR
    (Ki IS NOT NULL AND Ki > unstable_threshold) OR
    (kPa IS NOT NULL AND kPa > unstable_threshold) OR
    (kIa IS NOT NULL AND kIa > unstable_threshold) OR
    (kDa IS NOT NULL AND kDa > unstable_threshold) OR
    (kpW IS NOT NULL AND kpW > unstable_threshold),
    1, 0
  )
| WHERE is_safe_mode_disabled == 1 OR is_unstable_command == 1
| EVAL AnomalyType = CASE(
    is_unstable_command == 1 AND is_safe_mode_disabled == 1, "Unstable ADCS Command and Safe Mode Disabled",
    is_unstable_command == 1, "Unstable ADCS Command",
    is_safe_mode_disabled == 1, "Safe Mode Disabled Command"
  )
| KEEP @timestamp, AnomalyType, host.id, source.ip, message
| RENAME @timestamp AS Time, host.id AS SatelliteID, source.ip AS CommandSource, message AS RawLogMessage
```

### Satellite Telemetry Instability
---
```sql
-- Name: Satellite Telemetry Instability
-- Author: RW
-- Date: 2025-08-18
-- Description: Detects anomalous rapid increases in satellite telemetry data, specifically reaction wheel speed and angular velocity. Such spikes can indicate a loss of stability, potentially caused by malicious commands targeting the Attitude Determination and Control System (ADCS), as seen in the Hack-A-Sat competition. This rule uses a moving average and standard deviation (Z-score) to identify sudden deviations from the established baseline for each satellite.
-- False Positive Sensitivity: Medium. False positives may occur if a satellite performs a legitimate but aggressive maneuver that causes a rapid change in wheel speed or angular velocity. System tests or specific operational modes might also trigger alerts.

-- Data Source: Telemetry logs (logs-satellite-*).
-- Query Strategy: Calculate moving averages and Z-scores for telemetry metrics, filter for outliers, and categorize anomalies.
-- False Positive Tuning: Adjust Z-score threshold and window size.

FROM logs-satellite-*
| WHERE event.dataset == "telemetry" AND host.id IS NOT NULL AND (telemetry.wheel_speed_rpm IS NOT NULL OR telemetry.angular_velocity_deg_s IS NOT NULL)
| EVAL WheelSpeed_RPM = TO_DOUBLE(telemetry.wheel_speed_rpm), AngularVelocity_deg_s = TO_DOUBLE(telemetry.angular_velocity_deg_s)
| SORT @timestamp ASC
| STATS
    avg_wheel_speed = AVG(WheelSpeed_RPM) OVER (PARTITION BY host.id ORDER BY @timestamp ROWS 20 PRECEDING),
    stdev_wheel_speed = STDEV(WheelSpeed_RPM) OVER (PARTITION BY host.id ORDER BY @timestamp ROWS 20 PRECEDING),
    avg_angular_velocity = AVG(AngularVelocity_deg_s) OVER (PARTITION BY host.id ORDER BY @timestamp ROWS 20 PRECEDING),
    stdev_angular_velocity = STDEV(AngularVelocity_deg_s) OVER (PARTITION BY host.id ORDER BY @timestamp ROWS 20 PRECEDING)
  BY @timestamp, host.id, WheelSpeed_RPM, AngularVelocity_deg_s
| EVAL wheel_speed_zscore = IF(stdev_wheel_speed > 0, ROUND(ABS(WheelSpeed_RPM - avg_wheel_speed) / stdev_wheel_speed, 2), 0)
| EVAL angular_velocity_zscore = IF(stdev_angular_velocity > 0, ROUND(ABS(AngularVelocity_deg_s - avg_angular_velocity) / stdev_angular_velocity, 2), 0)
| EVAL zscore_threshold = 3.5
| WHERE wheel_speed_zscore > zscore_threshold OR angular_velocity_zscore > zscore_threshold
| EVAL AnomalousMetric = CASE(
    wheel_speed_zscore > zscore_threshold AND angular_velocity_zscore > zscore_threshold, "WheelSpeed and AngularVelocity",
    wheel_speed_zscore > zscore_threshold, "WheelSpeed",
    TRUE, "AngularVelocity"
  )
| KEEP @timestamp, host.id, AnomalousMetric, WheelSpeed_RPM, wheel_speed_zscore, AngularVelocity_deg_s, angular_velocity_zscore
| RENAME @timestamp AS Time, host.id AS SatelliteID, WheelSpeed_RPM AS "Wheel Speed (RPM)", wheel_speed_zscore AS "Wheel Speed Z-Score", AngularVelocity_deg_s AS "Angular Velocity (deg/s)", angular_velocity_zscore AS "Angular Velocity Z-Score"
```

### Excessive Ground Station Comm
---
```sql
-- Name: Excessive Ground Station Communication Attempts
-- Author: RW
-- Date: 2025-08-18
-- Description: Detects a ground station communicating with an anomalously high number of distinct satellites or making an excessive number of total connection attempts in a short period. This behavior can indicate that an attacker has compromised a ground station and is attempting to discover or attack multiple satellites, as seen in the Hack-A-Sat competition where attackers looped through known radio settings to target multiple spacecraft.
-- False Positive Sensitivity: Medium. False positives may occur if a ground station, particularly one at a polar location, has a legitimate mission profile that involves communicating with many satellites in a short time frame.

-- Data Source: Ground station communication logs (logs-satellite-*).
-- Query Strategy: Aggregate by ground station and source IP, count distinct satellites and total attempts, and filter for excessive activity.
-- False Positive Tuning: Adjust thresholds for satellite count and attempts.

FROM logs-satellite-*
| WHERE event.dataset == "ground_comm" AND @timestamp >= NOW() - 1 hour
  AND host.id IS NOT NULL AND destination.id IS NOT NULL
| EVAL distinct_satellite_threshold = 5, total_attempts_threshold = 100
| STATS
    StartTime = MIN(@timestamp),
    EndTime = MAX(@timestamp),
    DistinctSatelliteCount = COUNT(DISTINCT destination.id),
    TotalAttempts = COUNT(*),
    TargetedSatellites = MV_CONCAT(DISTINCT destination.id),
    ConnectionSuccesses = COUNT_IF(event.outcome == "success"),
    ConnectionFailures = COUNT_IF(event.outcome != "success")
  BY host.id, source.ip, distinct_satellite_threshold, total_attempts_threshold
| WHERE DistinctSatelliteCount > distinct_satellite_threshold OR TotalAttempts > total_attempts_threshold
| EVAL Reason = CASE(
    DistinctSatelliteCount > distinct_satellite_threshold AND TotalAttempts > total_attempts_threshold,
      CONCAT("High number of total attempts (", TotalAttempts, ") and high distinct satellite count (", DistinctSatelliteCount, ")"),
    DistinctSatelliteCount > distinct_satellite_threshold,
      CONCAT("High distinct satellite count (", DistinctSatelliteCount, ")"),
    TRUE, CONCAT("High number of total attempts (", TotalAttempts, ")")
  )
| KEEP StartTime, EndTime, host.id, source.ip, Reason, DistinctSatelliteCount, TotalAttempts, ConnectionSuccesses, ConnectionFailures, TargetedSatellites
| RENAME host.id AS GroundStationID, source.ip AS SourceIP
```

### Flight Software Crashes
---
```sql
-- Name: Satellite Flight Software Crash or Unexpected Reboot
-- Author: RW
-- Date: 2025-08-18
-- Description: Detects events indicating that a satellite's flight software has crashed or the satellite has unexpectedly rebooted. These events can be the result of a successful attack, such as the ADCS manipulation seen in the Hack-A-Sat competition, where unstable parameters caused a floating-point error and crashed the flight software.
-- False Positive Sensitivity: Medium. False positives can occur due to non-malicious software bugs, hardware faults, or scheduled maintenance reboots.

-- Data Source: Flight software logs (logs-satellite-*).
-- Query Strategy: Search for crash or reboot keywords, categorize events, and output relevant fields.
-- False Positive Tuning: Exclude maintenance-related reboots.

FROM logs-satellite-*
| WHERE event.dataset == "fsw_logs"
  AND (
    message LIKE "*crash*" OR
    message LIKE "*fault*" OR
    message LIKE "*exception*" OR
    message LIKE "*segmentation fault*" OR
    message LIKE "*segfault*" OR
    message LIKE "*core dump*" OR
    message LIKE "*floating-point error*" OR
    message LIKE "*unhandled exception*" OR
    message LIKE "*exit application on error*" OR
    message LIKE "*msg limit err*" OR
    message LIKE "*reboot*" OR
    message LIKE "*restart*" OR
    message LIKE "*system startup*" OR
    message LIKE "*initializing system*"
  )
| EVAL EventType = CASE(
    message MATCHES "(?i)crash|fault|exception|segfault|core dump|floating-point error|unhandled|exit application on error|msg limit err", "Flight Software Crash",
    message MATCHES "(?i)reboot|restart|system startup|initializing", "Unexpected Reboot",
    TRUE, "Unknown Event"
  )
| KEEP @timestamp, host.id, process.name, EventType, message
| RENAME @timestamp AS Time, host.id AS SatelliteID, process.name AS ProcessName, message AS RawLogMessage
```