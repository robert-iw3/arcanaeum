### Hacking an On-Orbit Satellite
---

This report analyzes the CYSAT demonstration where researchers successfully exploited vulnerabilities in an orbiting European Space Agency (ESA) satellite, OPS-SAT, to gain control and manipulate its functions. The exercise highlights critical cybersecurity risks in space systems, particularly concerning software supply chain attacks, deserialization vulnerabilities, and the lack of robust segmentation and privilege management on spacecraft.

Recent intelligence emphasizes the increasing threat of nation-state attacks and the commercialization of hacking tools targeting the space sector, with a focus on supply chain compromises and the exploitation of ground station vulnerabilities. Additionally, the inherent lack of security features in Controller Area Network (CAN) bus systems, widely used in spacecraft, presents a significant and evolving attack surface for sophisticated adversaries.

### Actionable Threat Data
---

Software Supply Chain Compromise (T1195.002): Monitor for anomalous code uploads or modifications to satellite software, especially within hosted payloads or during software updates. This includes scrutinizing code for embedded vulnerabilities rather than just overt malicious payloads.

Exploitation of Deserialization Vulnerabilities (T1212): Implement logging and analysis of deserialization attempts, particularly for Java-based systems, to detect unusual object instantiation or unexpected method calls that could indicate an exploit.

Privilege Escalation (T1068) and Lateral Movement (T1572) via OS Vulnerabilities and Bus Segregation Issues: Look for processes running with excessive privileges (e.g., as root) and monitor for unusual communication or data transfer across internal spacecraft buses like CAN bus, which often lack inherent security.

Impact on Satellite Operations (T1498): Establish baselines for expected satellite behavior and data integrity. Alert on deviations in telemetry, command execution, or sensor data that could indicate manipulation of on-board values or mission disruption.

Unauthorized Access to Ground Systems (T1078): Focus on detecting unauthorized access attempts and activity within ground station infrastructure, as these often serve as initial access points for satellite compromises.

### Software Supply Chain Compromise
---
```sql
-- Name: Anomalous Code File Creation in Sensitive Directory
-- Author: RW
-- Date: 2025-08-18
-- Description: Detects the creation of executable, library, or script files in sensitive directories by unexpected processes. This could indicate a software supply chain compromise or unauthorized software deployment, similar to the technique described in the CYSAT demo where a vulnerable JAR file was placed on a satellite system.
-- Data Source: Endpoint data model (Filesystem node)
-- False Positives: Legitimate software updates, administrative scripts, or new software installations may trigger this alert. Tuning the path and process lists in the 'where' clause is crucial to reduce noise.
-- Tags: T1195.002, Supply Chain Compromise, Space, Satellite

-- Data Source: Endpoint file events (logs-endpoint.events-*).
-- Query Strategy: Filter for file creation events with specific extensions in sensitive directories, exclude known updater processes, and aggregate by host and file.
-- False Positive Tuning: Expand exclusion list for legitimate processes.

FROM logs-endpoint.events-*
| WHERE event.category == "file" AND event.action == "create"
  AND file.name MATCHES "(?i)\.jar$|\.dll$|\.so$|\.exe$|\.py$|\.sh$|\.bin$|\.ps1$"
  AND file.path LIKE ANY (
    "C:\\Program Files\\SatelliteControl\\%",
    "C:\\ProgramData\\HostedPayloads\\%",
    "/opt/payload_apps/%",
    "/srv/satellite_services/%",
    "/usr/lib/%",
    "/usr/local/lib/%",
    "C:\\Windows\\System32\\%"
  )
  AND NOT process.name IN (
    "msiexec.exe", "yum", "apt", "patch.exe", "dnf", "trustedinstaller.exe", "waagent.exe"
  )
| STATS
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  BY host.hostname, file.path, file.name, process.name, user.name
| KEEP firstTime, lastTime, host.hostname, user.name, process.name, file.path, file.name, count
| RENAME host.hostname AS endpoint, user.name AS user, process.name AS creating_process, file.path AS sensitive_directory, file.name AS file_created
```

### Deserialization Vulnerability Exploitation
---
```sql
-- Name: Potential Deserialization Exploit via Suspicious Child Process
-- Author: RW
-- Date: 2025-08-18
-- Description: Detects when a common Java application process spawns a command shell or other suspicious utility. This activity is a strong indicator of remote code execution, which can result from exploiting a deserialization vulnerability. The CYSAT demo involved exploiting a deserialization flaw in a Java application on a satellite to gain code execution.
-- Data Source: Endpoint data model (Processes node)
-- False Positives: Legitimate administrative scripts or application functions might spawn shells. It's important to baseline normal application behavior and add exclusions for known benign parent-child relationships or command lines.
-- Tags: T1190, T1059, Deserialization, RCE, Java, CYSAT

-- Data Source: Endpoint process events (logs-endpoint.events-*).
-- Query Strategy: Filter for Java parent processes spawning suspicious child processes, aggregate by host and process details.
-- False Positive Tuning: Exclude known benign parent-child relationships.

FROM logs-endpoint.events-*
| WHERE event.category == "process"
  AND process.parent.name IN (
    "java.exe", "javaw.exe", "tomcat*.exe", "JBossSvc.exe", "wrapper.exe", "prunsrv.exe"
  )
  AND process.name IN (
    "cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "zsh", "csh", "ksh",
    "wget.exe", "curl.exe", "certutil.exe", "bitsadmin.exe", "rundll32.exe"
  )
| STATS
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  BY host.hostname, user.name, process.parent.name, process.name, process.command_line
| KEEP firstTime, lastTime, host.hostname, user.name, process.parent.name, process.name, process.command_line, count
| RENAME host.hostname AS host, user.name AS user, process.parent.name AS parent_process, process.name AS child_process, process.command_line AS process_command_line
```

### Privilege Escalation via OS Vulnerabilities
---
```sql
-- Name: Suspicious SUID or SGID Bit Set via Chmod
-- Author: RW
-- Date: 2025-08-18
-- Description: Detects the use of the 'chmod' utility to set the SUID or SGID bit on a file. Setting the SUID/SGID bit on a file, especially a shell or a script, is a common privilege escalation technique used by attackers to maintain privileged access. The CYSAT demo highlighted privilege escalation as a key step after initial access.
-- Data Source: Endpoint data model (Processes node)
-- False Positives: Legitimate software installation scripts or system administrators may occasionally set SUID/SGID bits. It is important to review the context, such as the user, parent process, and the file being modified, to determine legitimacy. Exclusions for known administrative activity may be required.
-- Tags: T1548.001, Privilege Escalation, SUID, SGID, Linux, CYSAT

-- Data Source: Endpoint process events (logs-endpoint.events-*).
-- Query Strategy: Filter for chmod commands with SUID/SGID patterns, exclude package managers, and aggregate by host and command.
-- False Positive Tuning: Exclude legitimate admin scripts.

FROM logs-endpoint.events-*
| WHERE event.category == "process" AND process.name == "chmod"
  AND (process.command_line LIKE "%u+s%" OR process.command_line LIKE "%g+s%" OR process.command_line MATCHES ".*\s+[2-7]\d{3}\s+.*")
  AND NOT process.parent.name IN ("yum", "apt", "apt-get", "dpkg", "rpm", "ansible", "puppet", "chef-client")
| STATS
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp),
    cmdline = MV_CONCAT(DISTINCT process.command_line)
  BY host.hostname, user.name, process.parent.name
| KEEP firstTime, lastTime, host.hostname, user.name, process.parent.name, cmdline, count
| RENAME host.hostname AS host, user.name AS user, process.parent.name AS parent_process
```

### Lateral Movement via Bus Segregation Issues
---
```sql
-- Name: Lateral Movement via Anomalous CAN Bus Communication
-- Author: RW
-- Date: 2025-08-18
-- Description: Detects anomalous communication on a Controller Area Network (CAN) bus, where a component (e.g., a payload system) sends messages to another component it should not be communicating with (e.g., a core flight system). This technique was highlighted in the CYSAT demo, where attackers exploited a lack of bus segregation for lateral movement within a satellite's systems.
-- Data Source: This rule requires a custom data source for CAN bus or similar OT data. The search must be adapted for the specific index, sourcetype, and field names.
-- False Positives: This detection is highly dependent on the accuracy of the communication allowlist. Legitimate but unlisted communication paths, such as those used for diagnostics or after a system update, will trigger alerts. This allowlist requires careful and continuous tuning for the specific vehicle or system architecture. For production environments, managing this list in a lookup file is recommended.
-- Tags: Lateral Movement, Space, Satellite, CAN bus, OT

-- Data Source: Custom CAN bus logs (logs-ot-*).
-- Query Strategy: Filter for unallowed communication paths, aggregate by source and destination components.
-- False Positive Tuning: Maintain accurate allowlist for valid paths.

FROM logs-ot-*
| WHERE event.dataset == "can_bus" AND source.component IS NOT NULL AND destination.component IS NOT NULL
| EVAL CommunicationPath = CONCAT(source.component, ":", destination.component)
| WHERE NOT CommunicationPath IN (
    "FlightComputer:AttitudeControl",
    "PowerController:FlightComputer",
    "TelemetryUnit:GroundLink",
    "PayloadController:TelemetryUnit"
  )
| STATS
    count = COUNT(*)
  BY @timestamp, device.name, source.component, destination.component, CommunicationPath, can.arbitration_id, can.message_data
| KEEP @timestamp, device.name, source.component, destination.component, CommunicationPath, can.arbitration_id, can.message_data, count
| RENAME device.name AS SystemName, source.component AS AnomalousSource, destination.component AS AnomalousDestination
```

### Impact on Satellite Operations
---
```sql
-- Name: Anomalous Satellite Telemetry Reading
-- Author: RW
-- Date: 2025-08-18
-- Description: Detects significant deviations from historical baselines in critical satellite sensor telemetry. This could indicate manipulation of on-board values or mission disruption, as described in the CYSAT demo analysis where attackers modified imagery data.
-- Data Source: This rule requires a custom data source for satellite telemetry data. The index, sourcetype, and field names (e.g., satellite, sensor, value) must be customized for your environment.
-- False Positives: Legitimate operational events, such as attitude adjustments, safe-mode entry, or sensor calibration, can cause telemetry values to deviate from the baseline. Tuning the anomaly threshold and the list of critical sensors is essential. Correlating alerts with a command log can help validate legitimacy.
-- Tags: Impact, Space, Satellite, Telemetry, Anomaly Detection

-- Data Source: Telemetry logs (logs-telemetry-*).
-- Query Strategy: Use anomaly detection for critical sensors, filter for significant deviations, and output bounds and scores.
-- False Positive Tuning: Tune threshold and sensor list.

FROM logs-telemetry-*
| WHERE telemetry.sensor IN (
    "AttitudeControl_GyroX",
    "PowerSystem_BusVoltage",
    "Camera_Gimbal_Angle",
    "Propulsion_TankPressure",
    "Payload_Temperature"
  )
| EVAL anomaly_score = ANOMALY_SCORE(telemetry.value, 0.005) BY host.id, telemetry.sensor
| WHERE anomaly_score IS NOT NULL
| STATS
    anomalous_value = LAST(telemetry.value),
    lower_bound = LAST(telemetry.anomaly_lower_bound),
    upper_bound = LAST(telemetry.anomaly_upper_bound),
    current_period_avg = LAST(telemetry.anomaly_avg),
    current_period_stdev = LAST(telemetry.anomaly_stdev)
  BY @timestamp, host.id, telemetry.sensor, anomaly_score
| KEEP @timestamp, host.id, telemetry.sensor, anomalous_value, lower_bound, upper_bound, current_period_avg, current_period_stdev, anomaly_score
| RENAME host.id AS satellite, telemetry.sensor AS sensor
```

### Unauthorized Ground System Access
---
```sql
-- Name: First Time User Logon to Ground System from New Country
-- Author: RW
-- Date: 2025-08-18
-- Description: Detects when a user successfully authenticates to a critical ground system from a geographic location (country) for the first time in the last 30 days. This could indicate a compromised account (T1078) or unauthorized remote access, a common initial access vector for compromising space assets.
-- Data Source: Authentication data model
-- False Positives: Legitimate user travel or use of new VPN endpoints can cause false positives. The baseline period (30d) can be adjusted to reduce noise from infrequent travelers. Brand new users are filtered out, but the `first_seen` field should be checked by the analyst.
-- Tags: Initial Access, T1078, Valid Accounts, Space, Ground System

-- Data Source: Authentication logs (logs-authentication-*).
-- Query Strategy: Filter for successful logons to critical systems, exclude known country-user pairs from the past 30 days, and filter out new users.
-- False Positive Tuning: Adjust baseline period and exclude travel-related logons.

FROM logs-authentication-*
| WHERE event.category == "authentication" AND event.outcome == "success"
  AND @timestamp >= NOW() - 24 hours
  AND (destination.hostname IN ("gcs-portal.example.com", "mission-planner-1") OR event.dataset IN ("Ground Station VPN"))
| STATS
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp),
    src_ip = MV_CONCAT(DISTINCT source.ip),
    app = MV_CONCAT(DISTINCT event.dataset)
  BY user.name, source.geo.country_name, destination.hostname
| WHERE NOT (
  (user.name, source.geo.country_name) IN (
    FROM logs-authentication-*
    | WHERE event.category == "authentication" AND event.outcome == "success"
      AND @timestamp >= NOW() - 30 days AND @timestamp < NOW() - 24 hours
      AND (destination.hostname IN ("gcs-portal.example.com", "mission-planner-1") OR event.dataset IN ("Ground Station VPN"))
    | STATS count BY user.name, source.geo.country_name
    | KEEP user.name, source.geo.country_name
  )
)
| JOIN (
  FROM logs-authentication-*
  | WHERE @timestamp >= NOW() - 30 days
  | STATS first_seen = MIN(@timestamp) BY user.name
) ON user.name = user.name
| WHERE first_seen < NOW() - 24 hours
| KEEP firstTime, lastTime, user.name, source.geo.country_name, src_ip, destination.hostname, app, first_seen
| RENAME user.name AS user, source.geo.country_name AS new_country, destination.hostname AS destination_system
```