### Space Threat Assessment and Actionable Detections
---

This report analyzes the evolving landscape of space threats, focusing on kinetic, non-kinetic, electronic, and cyber counterspace weapons. It highlights the increasing sophistication and proliferation of these capabilities by state and non-state actors, emphasizing the critical need for enhanced space situational awareness and robust defensive measures.

Recent intelligence indicates a significant surge in jamming attacks, particularly in geopolitical conflict zones, with a notable increase in reported jamming incidents affecting GNSS services. This trend underscores the growing use of reversible electronic warfare tactics to disrupt satellite communications and navigation, posing a persistent and evolving threat to both military and civilian space operations.

### Actionable Threat Data
---

Monitor for unusual or sustained electromagnetic interference (EMI) in satellite communication frequencies, particularly in areas of geopolitical conflict, which could indicate uplink or downlink jamming attempts.

Implement anomaly detection for unexpected changes in satellite telemetry data, such as sudden power fluctuations or unexpected reboots, which could be indicative of non-kinetic physical attacks (e.g., high-powered microwave weapons) or cyberattacks.

Establish baselines for normal satellite command and control (C2) traffic and alert on deviations, as cyberattacks targeting C2 systems can lead to data corruption or seizure of satellite control.

Analyze network traffic for indicators of compromise (IOCs) associated with known state-sponsored or hacktivist groups targeting the aerospace sector, as cyberattacks on ground infrastructure remain a significant threat vector.

Develop detection rules for unusual satellite maneuvers or proximity operations (RPOs) by unknown or adversarial satellites, which could precede co-orbital ASAT attacks or intelligence gathering.

### Satellite Communication Jamming
---
```sql
-- Name: Sustained Satellite Communication Jamming
-- Description: Detects sustained periods of high interference or low signal quality for satellite communications, potentially indicating jamming activity. This is based on the CSIS Space Threat Assessment report, which highlights the increased use of electronic warfare like jamming in geopolitical conflict zones. This rule requires a custom data source (e.g., from satellite RF monitoring systems) with fields for interference levels, signal-to-noise ratio (SNR), and location.
-- Author: RW
-- Date: 2025-08-19
-- Tactic: Denial of Service
-- Technique: T1070.006
-- False Positive Sensitivity: Medium. Natural atmospheric events, solar flares, or benign RF interference in high-traffic areas can cause false positives. Thresholds for interference, SNR, and event counts must be tuned based on environmental baselines.

-- Data Source: Satellite RF monitoring logs (logs-satellite-*).
-- Query Strategy: Filter for high interference/low SNR events, aggregate by region and satellite, and flag sustained intervals over 1 hour.
-- False Positive Tuning: Tune interference/SNR thresholds and region list.

FROM logs-satellite-*
| WHERE event.dataset == "rf_monitoring"
  AND (telemetry.interference_level > 70 OR telemetry.signal_to_noise_ratio < 10)
  AND telemetry.region IN ("Ukraine", "Eastern Europe", "Middle East", "South China Sea")
| BUCKET @timestamp, 5 minutes
| STATS count = COUNT(*) BY BUCKET(@timestamp, 5 minutes), telemetry.region, telemetry.satellite_id
| STATS
    num_sustained_intervals = COUNT_DISTINCT(BUCKET(@timestamp, 5 minutes)),
    total_interference_events = SUM(count),
    StartTime = MIN(@timestamp),
    EndTime = MAX(@timestamp),
    affected_satellites = MV_CONCAT(DISTINCT telemetry.satellite_id)
  BY telemetry.region
| WHERE num_sustained_intervals >= 4
| KEEP StartTime, EndTime, telemetry.region, total_interference_events, num_sustained_intervals, affected_satellites
| RENAME telemetry.region AS Suspected_Jamming_Region, total_interference_events AS Total_Interference_Events, num_sustained_intervals AS Sustained_5_Min_Intervals, affected_satellites AS Affected_Satellites
```

### Satellite Telemetry Anomalies
---
```sql
-- Name: Satellite Telemetry Anomalies
-- Description: Detects unexpected changes in satellite telemetry data, such as sudden power fluctuations or reboots. Such anomalies could indicate non-kinetic physical attacks (e.g., high-powered microwave weapons) or cyberattacks, as highlighted in the CSIS Space Threat Assessment. This rule requires a custom data source (e.g., from satellite operations) with fields for satellite ID, power levels, and system actions.
-- Author: RW
-- Date: 2025-08-19
-- Tactic: Impact
-- Technique: T1529, T1565.001
-- False Positive Sensitivity: Medium. Normal maintenance, safe mode entry due to benign environmental factors (e.g., solar flares), or temporary sensor errors can cause false positives. The power fluctuation threshold and reboot logic should be tuned based on the specific satellite's operational baseline.

-- Data Source: Satellite telemetry logs (logs-satellite-*).
-- Query Strategy: Aggregate metrics by satellite, detect reboots and power anomalies, and flag deviations.
-- False Positive Tuning: Tune power fluctuation threshold.

FROM logs-satellite-*
| WHERE event.dataset == "telemetry"
| STATS
    reboot_count = COUNT_IF(event.action == "REBOOT"),
    min_power = MIN(telemetry.power_level_w),
    max_power = MAX(telemetry.power_level_w),
    power_event_count = COUNT_IF(telemetry.power_level_w IS NOT NULL)
  BY telemetry.satellite_id
| EVAL is_power_anomaly = IF(max_power > (min_power * 1.5) AND power_event_count >= 2, "Yes", "No")
| EVAL is_reboot = IF(reboot_count > 0, "Yes", "No")
| WHERE is_power_anomaly == "Yes" OR is_reboot == "Yes"
| EVAL detection_methods = MV_CONCAT(
    IF(is_reboot == "Yes", "Unexpected Reboot", NULL),
    IF(is_power_anomaly == "Yes", "Power Fluctuation Anomaly", NULL)
  )
| KEEP telemetry.satellite_id, detection_methods, reboot_count, min_power, max_power, power_event_count
| RENAME telemetry.satellite_id AS Satellite_ID, detection_methods AS Detection_Methods, reboot_count AS Reboot_Count, min_power AS Min_Power_Observed_W, max_power AS Max_Power_Observed_W, power_event_count AS Power_Event_Count
```

### Satellite C2 Traffic Deviations
---
```sql
-- Name: Satellite C2 Traffic Deviations
-- Description: Detects deviations from normal satellite command and control (C2) traffic baselines. Such deviations, like anomalous command volumes, high failure rates, or commands from new sources, can indicate a cyberattack where an adversary attempts to corrupt data or seize control (T1070.006, T1070.007). This rule requires a custom log source (e.g., satellite_c2_log) and a lookup file of known C2 source IPs.
-- Author: RW
-- Date: 2025-08-19
-- Tactic: Defense Evasion
-- Technique: T1070.006, T1070.007
-- False Positive Sensitivity: Medium. Legitimate administrative activity from a new IP, network testing, or poorly tuned thresholds for volume and failure rates can cause false positives. The lookup file of known C2 source IPs must be actively maintained to reduce noise from new, legitimate sources.

-- Data Source: Satellite C2 logs (logs-satellite-*).
-- Query Strategy: Aggregate by satellite, detect anomalies in commands, failures, and new IPs using lookup for known sources.
-- False Positive Tuning: Tune thresholds and maintain known IP lookup.

FROM logs-satellite-*
| WHERE event.dataset == "c2_log" AND @timestamp >= NOW() - 1 hour
| JOIN known_satellite_c2_ips ON source.ip = known_satellite_c2_ips.known_ip
| STATS
    total_commands = COUNT(*),
    failed_commands = COUNT_IF(command_status == "failure"),
    new_source_ips = MV_CONCAT(IFNULL(known_satellite_c2_ips.known_ip, source.ip)),
    all_source_ips = MV_CONCAT(DISTINCT source.ip)
  BY telemetry.satellite_id
| EVAL volume_threshold = 100, failure_rate_threshold = 0.50, min_failed_commands_threshold = 5
| EVAL failure_rate = IF(total_commands > 0, failed_commands / total_commands, 0)
| EVAL is_new_source_anomaly = IF(LENGTH(new_source_ips) > 0, "Yes", "No")
| EVAL is_volume_anomaly = IF(total_commands > volume_threshold, "Yes", "No")
| EVAL is_failure_anomaly = IF(failure_rate >= failure_rate_threshold AND failed_commands >= min_failed_commands_threshold, "Yes", "No")
| WHERE is_new_source_anomaly == "Yes" OR is_volume_anomaly == "Yes" OR is_failure_anomaly == "Yes"
| EVAL detection_methods = MV_CONCAT(
    IF(is_new_source_anomaly == "Yes", "New C2 Source IP", NULL),
    IF(is_volume_anomaly == "Yes", "Anomalous C2 Command Volume", NULL),
    IF(is_failure_anomaly == "Yes", "High C2 Command Failure Rate", NULL)
  )
| EVAL new_source_ips = IF(is_new_source_anomaly == "No", "N/A", new_source_ips)
| EVAL failure_rate = CONCAT(TO_STRING(ROUND(failure_rate * 100, 2)), "%")
| KEEP telemetry.satellite_id, detection_methods, total_commands, failed_commands, failure_rate, new_source_ips, all_source_ips
| RENAME telemetry.satellite_id AS Satellite_ID, detection_methods AS Detection_Methods, total_commands AS Total_Commands, failed_commands AS Failed_Commands, failure_rate AS Failure_Rate, new_source_ips AS New_Source_IPs, all_source_ips AS All_Source_IPs
```

### Unusual Satellite Maneuvers
---
```sql
-- Name: Unusual Satellite Proximity Operations (RPO)
-- Description: Detects potential Rendezvous and Proximity Operations (RPO) by identifying when two or more satellites, at least one of which belongs to an adversarial owner, occupy the same discretized 3D space grid cell within a short time frame. This behavior can be a precursor to a co-orbital anti-satellite (ASAT) attack or intelligence gathering, as detailed in the CSIS Space Threat Assessment. This rule requires a custom data source (e.g., from satellite operations) with fields for satellite ID, owner, and positional data.
-- Author: RW
-- Date: 2025-08-19
-- Tactic: Impact
-- Technique: T1529
-- False Positive Sensitivity: Medium. Planned rendezvous missions, satellite servicing, large constellation station-keeping (e.g., Starlink), or grid cell boundaries causing unrelated satellites to be grouped are potential sources of false positives. The grid cell size and adversarial owner list are critical parameters for tuning.

-- Data Source: Satellite orbital data logs (logs-satellite-*).
-- Query Strategy: Calculate grid cells from positional data, filter for multi-satellite cells with adversarial owners, and aggregate by grid ID.
-- False Positive Tuning: Tune grid size and adversarial owner list.

FROM logs-satellite-*
| WHERE event.dataset == "orbital_data"
| EVAL grid_cell_size_km = 10
| EVAL grid_id = CONCAT(FLOOR(telemetry.pos_x_km / grid_cell_size_km), "_", FLOOR(telemetry.pos_y_km / grid_cell_size_km), "_", FLOOR(telemetry.pos_z_km / grid_cell_size_km))
| STATS
    satellite_count = COUNT_DISTINCT(telemetry.satellite_id),
    satellite_ids = MV_CONCAT(DISTINCT telemetry.satellite_id),
    satellite_owners = MV_CONCAT(DISTINCT telemetry.satellite_owner)
  BY grid_id, @timestamp
| WHERE satellite_count > 1
| EVAL adversarial_owners_present = MV_FILTER(satellite_owners, satellite_owners MATCHES "RUS|CHN|IRN|PRK")
| WHERE LENGTH(adversarial_owners_present) > 0
| WHERE NOT satellite_owners == "SPACEX"
| KEEP @timestamp, grid_id, satellite_count, satellite_ids, satellite_owners, adversarial_owners_present
| RENAME @timestamp AS Time_of_Proximity_Event, grid_id AS Grid_Cell_Identifier, satellite_count AS Distinct_Satellite_Count, satellite_ids AS Satellites_in_Cell, satellite_owners AS Owners_in_Cell, adversarial_owners_present AS Adversarial_Owners_Present
```