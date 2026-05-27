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

-- Data Source: Web logs (web).
-- Query Strategy: Filter for 403 and 200 responses, group by source IP within 10 minutes, and flag sensitive URLs with large data transfers.
-- False Positive Tuning: Adjust byte threshold and URL patterns.

logs(
  source:web
  http.status_code:(200 OR 403)
)
| eval exfil_threshold_bytes = 100000
| eval sensitive_path_regex = "(?i)(config|setting|database|db|admin|backup|dump|export|secret|key|radio|cred|token)"
| eval event_type = case(
  http.status_code = 403, "forbidden_request",
  http.status_code = 200 AND http.response.bytes > exfil_threshold_bytes AND http.url MATCHES sensitive_path_regex, "suspicious_exfil_request"
)
| eval suspicious_details = if(event_type = "suspicious_exfil_request", "URL=" + http.url + ", Bytes=" + http.response.bytes, null())
| group by network.src_ip, span(@timestamp, 10m)
| select
    min(@timestamp) as window_start,
    max(@timestamp) as window_end,
    values(event_type) as event_types,
    values(suspicious_details) as SuspiciousExfiltrationRequests,
    network.src_ip as SourceIP
| where event_types IN ("forbidden_request", "suspicious_exfil_request")
| display window_start, window_end, SourceIP, SuspiciousExfiltrationRequests
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

-- Data Source: Satellite command logs (satellite_commands).
-- Query Strategy: Parse command logs for control constants and safe mode status, filter for anomalies, and categorize events.
-- False Positive Tuning: Tune threshold for control constants.

logs(
  source:satellite_commands
  (ADCS OR "safe mode")
)
| eval unstable_threshold = 10000.0
| eval Kp = tonumber(regex_extract(message, "Kp\s+([\d\.]+)", 1))
| eval Kd = tonumber(regex_extract(message, "Kd\s+([\d\.]+)", 1))
| eval Ki = tonumber(regex_extract(message, "Ki\s+([\d\.]+)", 1))
| eval kPa = tonumber(regex_extract(message, "kPa\s+([\d\.]+)", 1))
| eval kIa = tonumber(regex_extract(message, "kIa\s+([\d\.]+)", 1))
| eval kDa = tonumber(regex_extract(message, "kDa\s+([\d\.]+)", 1))
| eval kpW = tonumber(regex_extract(message, "kpW\s+([\d\.]+)", 1))
| eval is_safe_mode_disabled = if(message MATCHES "(?i)safe mode (off|disabled)", 1, 0)
| eval is_unstable_command = if(
  (isnotnull(Kp) AND Kp > unstable_threshold) OR
  (isnotnull(Kd) AND Kd > unstable_threshold) OR
  (isnotnull(Ki) AND Ki > unstable_threshold) OR
  (isnotnull(kPa) AND kPa > unstable_threshold) OR
  (isnotnull(kIa) AND kIa > unstable_threshold) OR
  (isnotnull(kDa) AND kDa > unstable_threshold) OR
  (isnotnull(kpW) AND kpW > unstable_threshold),
  1, 0
)
| where is_safe_mode_disabled = 1 OR is_unstable_command = 1
| eval AnomalyType = case(
  is_unstable_command = 1 AND is_safe_mode_disabled = 1, "Unstable ADCS Command and Safe Mode Disabled",
  is_unstable_command = 1, "Unstable ADCS Command",
  is_safe_mode_disabled = 1, "Safe Mode Disabled Command"
)
| select @timestamp as Time, AnomalyType, @satellite_id as SatelliteID, @command_source as CommandSource, message as RawLogMessage
```

### Satellite Telemetry Instability
---
```sql
-- Name: Satellite Telemetry Instability
-- Author: RW
-- Date: 2025-08-18
-- Description: Detects anomalous rapid increases in satellite telemetry data, specifically reaction wheel speed and angular velocity. Such spikes can indicate a loss of stability, potentially caused by malicious commands targeting the Attitude Determination and Control System (ADCS), as seen in the Hack-A-Sat competition. This rule uses a moving average and standard deviation (Z-score) to identify sudden deviations from the established baseline for each satellite.
-- False Positive Sensitivity: Medium. False positives may occur if a satellite performs a legitimate but aggressive maneuver that causes a rapid change in wheel speed or angular velocity. System tests or specific operational modes might also trigger alerts.

-- Data Source: Telemetry logs (telemetry).
-- Query Strategy: Compute moving averages and Z-scores, filter for outliers, and categorize anomalies.
-- False Positive Tuning: Adjust Z-score threshold and window.

logs(
  source:telemetry
  @satellite_id IS NOT NULL
  (wheel_speed_rpm IS NOT NULL OR angular_velocity_deg_s IS NOT NULL)
)
| eval WheelSpeed_RPM = tonumber(wheel_speed_rpm), AngularVelocity_deg_s = tonumber(angular_velocity_deg_s)
| sort @timestamp asc
| streamstats window=20 current=false
  avg(WheelSpeed_RPM) as avg_wheel_speed,
  stdev(WheelSpeed_RPM) as stdev_wheel_speed,
  avg(AngularVelocity_deg_s) as avg_angular_velocity,
  stdev(AngularVelocity_deg_s) as stdev_angular_velocity
  by @satellite_id
| eval wheel_speed_zscore = if(stdev_wheel_speed > 0, round(abs(WheelSpeed_RPM - avg_wheel_speed) / stdev_wheel_speed, 2), 0)
| eval angular_velocity_zscore = if(stdev_angular_velocity > 0, round(abs(AngularVelocity_deg_s - avg_angular_velocity) / stdev_angular_velocity, 2), 0)
| eval zscore_threshold = 3.5
| where wheel_speed_zscore > zscore_threshold OR angular_velocity_zscore > zscore_threshold
| eval AnomalousMetric = case(
  wheel_speed_zscore > zscore_threshold AND angular_velocity_zscore > zscore_threshold, "WheelSpeed and AngularVelocity",
  wheel_speed_zscore > zscore_threshold, "WheelSpeed",
  true, "AngularVelocity"
)
| select
  @timestamp as Time,
  @satellite_id as SatelliteID,
  AnomalousMetric,
  WheelSpeed_RPM as "Wheel Speed (RPM)",
  wheel_speed_zscore as "Wheel Speed Z-Score",
  AngularVelocity_deg_s as "Angular Velocity (deg/s)",
  angular_velocity_zscore as "Angular Velocity Z-Score"
```

### Excessive Ground Station Comm
---
```sql
-- Name: Excessive Ground Station Communication Attempts
-- Author: RW
-- Date: 2025-08-18
-- Description: Detects a ground station communicating with an anomalously high number of distinct satellites or making an excessive number of total connection attempts in a short period. This behavior can indicate that an attacker has compromised a ground station and is attempting to discover or attack multiple satellites, as seen in the Hack-A-Sat competition where attackers looped through known radio settings to target multiple spacecraft.
-- False Positive Sensitivity: Medium. False positives may occur if a ground station, particularly one at a polar location, has a legitimate mission profile that involves communicating with many satellites in a short time frame.

-- Data Source: Ground station communication logs (ground_comm).
-- Query Strategy: Group by ground station and source IP, count satellites and attempts, and flag excessive activity.
-- False Positive Tuning: Tune thresholds for polar ground stations.

logs(
  source:ground_comm
  @timestamp:[NOW-1h TO NOW]
  @ground_station_id IS NOT NULL
  @satellite_id IS NOT NULL
)
| eval distinct_satellite_threshold = 5, total_attempts_threshold = 100
| group by @ground_station_id, network.src_ip
| select
    min(@timestamp) as StartTime,
    max(@timestamp) as EndTime,
    count_distinct(@satellite_id) as DistinctSatelliteCount,
    count as TotalAttempts,
    values(@satellite_id) as TargetedSatellites,
    count_if(event.outcome = "success") as ConnectionSuccesses,
    count_if(event.outcome != "success") as ConnectionFailures,
    @ground_station_id as GroundStationID,
    network.src_ip as SourceIP
| where DistinctSatelliteCount > distinct_satellite_threshold OR TotalAttempts > total_attempts_threshold
| eval Reason = case(
  DistinctSatelliteCount > distinct_satellite_threshold AND TotalAttempts > total_attempts_threshold,
    "High number of total attempts (" + TotalAttempts + ") and high distinct satellite count (" + DistinctSatelliteCount + ")",
  DistinctSatelliteCount > distinct_satellite_threshold,
    "High distinct satellite count (" + DistinctSatelliteCount + ")",
  true, "High number of total attempts (" + TotalAttempts + ")"
)
| display StartTime, EndTime, GroundStationID, SourceIP, Reason, DistinctSatelliteCount, TotalAttempts, ConnectionSuccesses, ConnectionFailures, TargetedSatellites
```

### Flight Software Crashes
---
```sql
-- Name: Satellite Flight Software Crash or Unexpected Reboot
-- Author: RW
-- Date: 2025-08-18
-- Description: Detects events indicating that a satellite's flight software has crashed or the satellite has unexpectedly rebooted. These events can be the result of a successful attack, such as the ADCS manipulation seen in the Hack-A-Sat competition, where unstable parameters caused a floating-point error and crashed the flight software.
-- False Positive Sensitivity: Medium. False positives can occur due to non-malicious software bugs, hardware faults, or scheduled maintenance reboots.

-- Data Source: Flight software logs (fsw_logs).
-- Query Strategy: Filter for crash or reboot keywords, categorize events, and format output.
-- False Positive Tuning: Exclude scheduled reboots.

logs(
  source:fsw_logs
  (
    crash OR fault OR exception OR "segmentation fault" OR segfault OR "core dump" OR
    "floating-point error" OR "unhandled exception" OR "exit application on error" OR
    "msg limit err" OR reboot OR restart OR "system startup" OR "initializing system"
  )
)
| eval EventType = case(
  message MATCHES "(?i)crash|fault|exception|segfault|core dump|floating-point error|unhandled|exit application on error|msg limit err", "Flight Software Crash",
  message MATCHES "(?i)reboot|restart|system startup|initializing", "Unexpected Reboot",
  true, "Unknown Event"
)
| select @timestamp as Time, @satellite_id as SatelliteID, process.name as ProcessName, EventType, message as RawLogMessage
```