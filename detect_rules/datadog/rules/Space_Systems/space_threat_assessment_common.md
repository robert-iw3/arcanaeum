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

-- Data Source: Satellite RF monitoring logs (rf_monitoring).
-- Query Strategy: Filter for jamming indicators, group by 5-minute intervals, and aggregate sustained events over 1 hour.
-- False Positive Tuning: Tune thresholds and region filters.

logs(
  source:rf_monitoring
  (interference_level > 70 OR signal_to_noise_ratio < 10)
  @region:(Ukraine OR "Eastern Europe" OR "Middle East" OR "South China Sea")
)
| bin @timestamp span=5m
| group by @timestamp, @region, @satellite_id
| select
    @timestamp,
    @region,
    @satellite_id,
    count
| group by @region
| select
    min(@timestamp) as StartTime,
    max(@timestamp) as EndTime,
    count_distinct(@timestamp) as num_sustained_intervals,
    sum(count) as total_interference_events,
    values(@satellite_id) as affected_satellites
| where num_sustained_intervals >= 4
| rename @region as Suspected_Jamming_Region, total_interference_events as Total_Interference_Events, num_sustained_intervals as Sustained_5_Min_Intervals, affected_satellites as Affected_Satellites
| display StartTime, EndTime, Suspected_Jamming_Region, Total_Interference_Events, Sustained_5_Min_Intervals, Affected_Satellites
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

-- Data Source: Satellite telemetry logs (telemetry).
-- Query Strategy: Aggregate by satellite, detect anomalies in reboots and power levels.
-- False Positive Tuning: Tune power fluctuation multiplier.

logs(
  source:telemetry
)
| group by @satellite_id
| select
    count_if(event.action = "REBOOT") as reboot_count,
    min(power_level_w) as min_power,
    max(power_level_w) as max_power,
    count_if(power_level_w IS NOT NULL) as power_event_count
| eval is_power_anomaly = if(max_power > (min_power * 1.5) AND power_event_count >= 2, "Yes", "No")
| eval is_reboot = if(reboot_count > 0, "Yes", "No")
| where is_power_anomaly = "Yes" OR is_reboot = "Yes"
| eval detection_methods = mvappend(
    if(is_reboot = "Yes", "Unexpected Reboot", null()),
    if(is_power_anomaly = "Yes", "Power Fluctuation Anomaly", null())
  )
| rename @satellite_id as Satellite_ID, detection_methods as Detection_Methods, reboot_count as Reboot_Count, min_power as Min_Power_Observed_W, max_power as Max_Power_Observed_W, power_event_count as Power_Event_Count
| display Satellite_ID, Detection_Methods, Reboot_Count, Min_Power_Observed_W, Max_Power_Observed_W, Power_Event_Count
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

-- Data Source: Satellite C2 logs (c2_log).
-- Query Strategy: Aggregate by satellite, detect anomalies, and use tag for known IPs.
-- False Positive Tuning: Tune thresholds and update known IP tag.

logs(
  source:c2_log
  @timestamp:[NOW-1h TO NOW]
)
| join @source_ip with known_satellite_c2_ips on known_satellite_c2_ips.known_ip = @source_ip
| group by @satellite_id
| select
    count as total_commands,
    count_if(command_status = "failure") as failed_commands,
    values_if(@source_ip, isnull(known_satellite_c2_ips.known_ip)) as new_source_ips,
    values(@source_ip) as all_source_ips
| eval volume_threshold = 100, failure_rate_threshold = 0.50, min_failed_commands_threshold = 5
| eval failure_rate = if(total_commands > 0, failed_commands / total_commands, 0)
| eval is_new_source_anomaly = if(mvcount(new_source_ips) > 0, "Yes", "No")
| eval is_volume_anomaly = if(total_commands > volume_threshold, "Yes", "No")
| eval is_failure_anomaly = if(failure_rate >= failure_rate_threshold AND failed_commands >= min_failed_commands_threshold, "Yes", "No")
| where is_new_source_anomaly = "Yes" OR is_volume_anomaly = "Yes" OR is_failure_anomaly = "Yes"
| eval detection_methods = mvappend(
    if(is_new_source_anomaly = "Yes", "New C2 Source IP", null()),
    if(is_volume_anomaly = "Yes", "Anomalous C2 Command Volume", null()),
    if(is_failure_anomaly = "Yes", "High C2 Command Failure Rate", null())
  )
| eval new_source_ips = if(is_new_source_anomaly = "No", "N/A", new_source_ips)
| eval failure_rate = tostring(round(failure_rate * 100, 2)) + "%"
| rename @satellite_id as Satellite_ID, detection_methods as Detection_Methods, total_commands as Total_Commands, failed_commands as Failed_Commands, failure_rate as Failure_Rate, new_source_ips as New_Source_IPs, all_source_ips as All_Source_IPs
| display Satellite_ID, Detection_Methods, Total_Commands, Failed_Commands, Failure_Rate, New_Source_IPs, All_Source_IPs
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

-- Data Source: Satellite orbital data logs (orbital_data).
-- Query Strategy: Compute grid IDs, group by grid and time, filter for adversarial proximity.
-- False Positive Tuning: Tune grid size and exclude friendly constellations.

logs(
  source:orbital_data
)
| eval grid_cell_size_km = 10
| eval grid_id = floor(pos_x_km / grid_cell_size_km) + "_" + floor(pos_y_km / grid_cell_size_km) + "_" + floor(pos_z_km / grid_cell_size_km)
| group by grid_id, @timestamp
| select
    count_distinct(@satellite_id) as satellite_count,
    values(@satellite_id) as satellite_ids,
    values(@satellite_owner) as satellite_owners
| where satellite_count > 1
| eval adversarial_owners_present = mvfilter(satellite_owners MATCHES "RUS|CHN|IRN|PRK")
| where mvcount(adversarial_owners_present) > 0
| exclude satellite_owners = "SPACEX"
| rename @timestamp as Time_of_Proximity_Event, grid_id as Grid_Cell_Identifier, satellite_count as Distinct_Satellite_Count, satellite_ids as Satellites_in_Cell, satellite_owners as Owners_in_Cell, adversarial_owners_present as Adversarial_Owners_Present
| display Time_of_Proximity_Event, Grid_Cell_Identifier, Distinct_Satellite_Count, Satellites_in_Cell, Owners_in_Cell, Adversarial_Owners_Present
```