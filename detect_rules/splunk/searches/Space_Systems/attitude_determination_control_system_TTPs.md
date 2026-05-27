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
-- Tuning:
-- - Adjust the 'exfil_threshold_bytes' value based on baseline traffic. A higher value will reduce noise but may miss smaller exfiltration events.
-- - Modify the 'sensitive_path_regex' pattern to include terms specific to your critical web applications and data stores.

-- Data source: This query is written for CIM-compliant web data. You may need to adjust field names (e.g., src, status, bytes_out, url) for your specific data source.
`web_proxy` (status=200 OR status=403)
| `comment("Set detection parameters. These should be tuned for your environment.")`
| eval exfil_threshold_bytes = 100000
| eval sensitive_path_regex = "(?i)(config|setting|database|db|admin|backup|dump|export|secret|key|radio|cred|token)"

| `comment("Group events by source IP within a 10-minute window.")`
| bin _time span=10m

| `comment("Identify forbidden requests and suspicious successful requests (large response from a sensitive path).")`
| eval event_type = case(
    status = 403, "forbidden_request",
    status = 200 AND bytes_out > exfil_threshold_bytes AND match(url, sensitive_path_regex), "suspicious_exfil_request"
    )
| eval suspicious_details = if(event_type="suspicious_exfil_request", "URL=" + url + ", Bytes=" + bytes_out, null())

| `comment("Summarize the activity for each source IP and time window.")`
| stats
    values(event_type) as event_types,
    values(suspicious_details) as suspicious_requests,
    earliest(_time) as window_start,
    latest(_time) as window_end
    by src, _time

| `comment("Filter for windows containing both a forbidden request and a suspicious exfiltration attempt.")`
| where mvfind(event_types, "forbidden_request") IS NOT NULL AND mvfind(event_types, "suspicious_exfil_request") IS NOT NULL

| `comment("Format the output for readability.")`
| convert ctime(window_start) ctime(window_end)
| table window_start, window_end, src, suspicious_requests
| rename src as SourceIP, suspicious_requests as SuspiciousExfiltrationRequests
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
-- Tuning:
-- - The `index` and `sourcetype` are placeholders. Adjust them to match your specific data schema for satellite telemetry or command logs.
-- - The 'unstable_threshold' value should be tuned based on documented safe operational parameters for the specific satellite's ADCS.
-- - Add or modify fields like 'SatelliteID' and 'CommandSource' to match your log schema for better context.

`comment("Define the data source for satellite command logs. Replace with your actual index and sourcetype.")`
(index=satellite_logs sourcetype=satellite_commands)
`comment("Prefilter for logs containing relevant keywords to improve performance.")`
("ADCS" OR "safe mode")

| `comment("Define the threshold for what is considered an unstable control constant value. Tune this based on the satellite's documented safe operational parameters.")`
| eval unstable_threshold = 10000.0

| `comment("Use rex to extract control constant values from the log message.")`
| rex field=_raw "Kp\s+(?<Kp>[\d\.]+)"
| rex field=_raw "Kd\s+(?<Kd>[\d\.]+)"
| rex field=_raw "Ki\s+(?<Ki>[\d\.]+)"
| rex field=_raw "kPa\s+(?<kPa>[\d\.]+)"
| rex field=_raw "kIa\s+(?<kIa>[\d\.]+)"
| rex field=_raw "kDa\s+(?<kDa>[\d\.]+)"
| rex field=_raw "kpW\s+(?<kpW>[\d\.]+)"

| `comment("Identify if the log indicates that safe mode was disabled.")`
| eval is_safe_mode_disabled = if(match(_raw, "(?i)safe mode (off|disabled)"), 1, 0)

| `comment("Identify if any extracted control constant exceeds the defined unstable threshold.")`
| eval is_unstable_command = if(
    (isnotnull(Kp) AND tonumber(Kp) > unstable_threshold) OR
    (isnotnull(Kd) AND tonumber(Kd) > unstable_threshold) OR
    (isnotnull(Ki) AND tonumber(Ki) > unstable_threshold) OR
    (isnotnull(kPa) AND tonumber(kPa) > unstable_threshold) OR
    (isnotnull(kIa) AND tonumber(kIa) > unstable_threshold) OR
    (isnotnull(kDa) AND tonumber(kDa) > unstable_threshold) OR
    (isnotnull(kpW) AND tonumber(kpW) > unstable_threshold),
    1, 0
    )

| `comment("Filter for events that match either of the malicious conditions.")`
| where is_safe_mode_disabled=1 OR is_unstable_command=1

| `comment("Categorize the detected anomaly for easier analysis.")`
| eval AnomalyType=case(
    is_unstable_command=1 AND is_safe_mode_disabled=1, "Unstable ADCS Command and Safe Mode Disabled",
    is_unstable_command=1, "Unstable ADCS Command",
    is_safe_mode_disabled=1, "Safe Mode Disabled Command"
    )

| `comment("Format the output fields for the alert. Add fields like SatelliteID and CommandSource if they exist in your data.")`
| table _time, AnomalyType, SatelliteID, CommandSource, _raw
| rename _raw as RawLogMessage
```

### Satellite Telemetry Instability
---
```sql
-- Name: Satellite Telemetry Instability
-- Author: RW
-- Date: 2025-08-18
-- Description: Detects anomalous rapid increases in satellite telemetry data, specifically reaction wheel speed and angular velocity. Such spikes can indicate a loss of stability, potentially caused by malicious commands targeting the Attitude Determination and Control System (ADCS), as seen in the Hack-A-Sat competition. This rule uses a moving average and standard deviation (Z-score) to identify sudden deviations from the established baseline for each satellite.
-- False Positive Sensitivity: Medium. False positives may occur if a satellite performs a legitimate but aggressive maneuver that causes a rapid change in wheel speed or angular velocity. System tests or specific operational modes might also trigger alerts.
-- Tuning:
-- - The `index` and `sourcetype` are placeholders. Adjust them to match your specific data schema for satellite telemetry.
-- - The fields 'WheelSpeed_RPM', 'AngularVelocity_deg_s', and 'SatelliteID' are placeholders. Adjust them to match your log schema.
-- - The 'window' size for streamstats should be adjusted based on the frequency and stability of your telemetry data. A larger window creates a more stable baseline but is slower to adapt to change.
-- - The 'zscore_threshold' controls the sensitivity of the anomaly detection. A higher value (e.g., 4.0 or 5.0) will make the detection less sensitive and reduce noise.

`comment("Define the data source for satellite telemetry data. Replace with your actual index and sourcetype.")`
(index=satellite sourcetype=telemetry)
`comment("Ensure telemetry fields are numeric and required fields exist.")`
| eval WheelSpeed_RPM=tonumber(WheelSpeed_RPM), AngularVelocity_deg_s=tonumber(AngularVelocity_deg_s)
| where isnotnull(SatelliteID) AND (isnotnull(WheelSpeed_RPM) OR isnotnull(AngularVelocity_deg_s))

| `comment("Sort events chronologically to prepare for streamstats.")`
| sort 0 _time

| `comment("Calculate a moving average and standard deviation over a 20-event window for each satellite.")`
| streamstats window=20 current=f avg(WheelSpeed_RPM) as avg_wheel_speed, stdev(WheelSpeed_RPM) as stdev_wheel_speed, avg(AngularVelocity_deg_s) as avg_angular_velocity, stdev(AngularVelocity_deg_s) as stdev_angular_velocity by SatelliteID

| `comment("Calculate the Z-score (number of standard deviations from the average) for each metric to identify outliers.")`
| eval wheel_speed_zscore = if(stdev_wheel_speed > 0, round(abs(WheelSpeed_RPM - avg_wheel_speed) / stdev_wheel_speed, 2), 0)
| eval angular_velocity_zscore = if(stdev_angular_velocity > 0, round(abs(AngularVelocity_deg_s - avg_angular_velocity) / stdev_angular_velocity, 2), 0)

| `comment("Set the anomaly detection threshold. A Z-score > 3.5 is often considered a significant outlier.")`
| eval zscore_threshold = 3.5

| `comment("Filter for events where either metric exceeds the Z-score threshold.")`
| where wheel_speed_zscore > zscore_threshold OR angular_velocity_zscore > zscore_threshold

| `comment("Categorize the anomaly for easier analysis.")`
| eval AnomalousMetric = case(
    wheel_speed_zscore > zscore_threshold AND angular_velocity_zscore > zscore_threshold, "WheelSpeed and AngularVelocity",
    wheel_speed_zscore > zscore_threshold, "WheelSpeed",
    "AngularVelocity"
    )

| `comment("Format the output fields for the alert.")`
| table _time, SatelliteID, AnomalousMetric, WheelSpeed_RPM, wheel_speed_zscore, AngularVelocity_deg_s, angular_velocity_zscore
| rename WheelSpeed_RPM as "Wheel Speed (RPM)", wheel_speed_zscore as "Wheel Speed Z-Score", AngularVelocity_deg_s as "Angular Velocity (deg/s)", angular_velocity_zscore as "Angular Velocity Z-Score"
```

### Excessive Ground Station Comm
---
```sql
-- Name: Excessive Ground Station Communication Attempts
-- Author: RW
-- Date: 2025-08-18
-- Description: Detects a ground station communicating with an anomalously high number of distinct satellites or making an excessive number of total connection attempts in a short period. This behavior can indicate that an attacker has compromised a ground station and is attempting to discover or attack multiple satellites, as seen in the Hack-A-Sat competition where attackers looped through known radio settings to target multiple spacecraft.
-- False Positive Sensitivity: Medium. False positives may occur if a ground station, particularly one at a polar location, has a legitimate mission profile that involves communicating with many satellites in a short time frame.
-- Tuning:
-- - The data source (e.g., index=satellite sourcetype=ground_comm) and its fields ('GroundStationID', 'SatelliteID', 'ConnectionStatus', 'SourceIP') are placeholders. Adjust them to match your specific data schema.
-- - The 'distinct_satellite_threshold' should be tuned based on the normal operating procedures for each ground station. A shared or polar ground station may have a higher baseline.
-- - The 'total_attempts_threshold' should be adjusted based on expected communication frequency.

`comment("Define the data source for ground station communication logs. Replace with your actual index and sourcetype.")`
(index=satellite sourcetype=ground_comm) earliest=-1h

| `comment("Ensure required fields are not empty.")`
| where isnotnull(GroundStationID) AND isnotnull(SatelliteID)

| `comment("Set detection thresholds. These should be tuned for your environment.")`
| eval distinct_satellite_threshold = 5
| eval total_attempts_threshold = 100

| `comment("Summarize communication activity per ground station and source IP.")`
| stats
    earliest(_time) as StartTime,
    latest(_time) as EndTime,
    dc(SatelliteID) as DistinctSatelliteCount,
    count as TotalAttempts,
    values(SatelliteID) as TargetedSatellites,
    count(eval(if(match(ConnectionStatus, "(?i)success"),_raw,null()))) as ConnectionSuccesses,
    count(eval(if(NOT match(ConnectionStatus, "(?i)success"),_raw,null()))) as ConnectionFailures
    by GroundStationID, SourceIP, distinct_satellite_threshold, total_attempts_threshold

| `comment("Apply thresholds to identify excessive activity.")`
| where DistinctSatelliteCount > distinct_satellite_threshold OR TotalAttempts > total_attempts_threshold

| `comment("Add a description of why the alert was triggered for the analyst.")`
| eval Reason = case(
    DistinctSatelliteCount > distinct_satellite_threshold AND TotalAttempts > total_attempts_threshold, "High number of total attempts (" + TotalAttempts + ") and high distinct satellite count (" + DistinctSatelliteCount + ")",
    DistinctSatelliteCount > distinct_satellite_threshold, "High distinct satellite count (" + DistinctSatelliteCount + ")",
    TotalAttempts > total_attempts_threshold, "High number of total attempts (" + TotalAttempts + ")"
    )

| `comment("Format the output fields for the alert.")`
| convert ctime(StartTime) ctime(EndTime)
| table StartTime, EndTime, GroundStationID, SourceIP, Reason, DistinctSatelliteCount, TotalAttempts, ConnectionSuccesses, ConnectionFailures, TargetedSatellites
```

### Flight Software Crashes
---
```sql
-- Name: Satellite Flight Software Crash or Unexpected Reboot
-- Author: RW
-- Date: 2025-08-18
-- Description: Detects events indicating that a satellite's flight software has crashed or the satellite has unexpectedly rebooted. These events can be the result of a successful attack, such as the ADCS manipulation seen in the Hack-A-Sat competition, where unstable parameters caused a floating-point error and crashed the flight software.
-- False Positive Sensitivity: Medium. False positives can occur due to non-malicious software bugs, hardware faults, or scheduled maintenance reboots.
-- Tuning:
-- - The data source (e.g., index=satellite sourcetype=fsw_logs) and fields ('SatelliteID', 'ProcessName') are placeholders. Adjust them to match your specific data schema for satellite system or application logs.
-- - The keyword lists in the search query should be refined based on the specific log messages generated by your satellite fleet.
-- - Consider creating an exclusion list for specific 'ProcessName' or 'SatelliteID' values during known maintenance windows to reduce noise.

`comment("Define the data source for satellite system logs. Replace with your actual index and sourcetype.")`
(index=satellite sourcetype=fsw_logs)

| `comment("Search for logs containing keywords that indicate a software crash or a system reboot.")`
| search (
    "crash" OR "fault" OR "exception" OR "segmentation fault" OR "segfault" OR "core dump" OR "floating-point error" OR "unhandled exception" OR "exit application on error" OR "msg limit err"
    OR "reboot" OR "restart" OR "system startup" OR "initializing system"
    )

| `comment("Categorize the event type for clarity in the alert.")`
| eval EventType = case(
    match(_raw, "(?i)crash|fault|exception|segfault|core dump|floating-point error|unhandled|exit application on error|msg limit err"), "Flight Software Crash",
    match(_raw, "(?i)reboot|restart|system startup|initializing"), "Unexpected Reboot",
    1=1, "Unknown Event"
    )

| `comment("Format the output fields for the alert. Add fields like SatelliteID and ProcessName if they exist in your data.")`
| table _time, SatelliteID, ProcessName, EventType, _raw
| rename _raw as RawLogMessage
```