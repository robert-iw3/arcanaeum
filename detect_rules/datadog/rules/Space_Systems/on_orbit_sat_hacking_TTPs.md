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

-- Data Source: Endpoint logs (endpoint).
-- Query Strategy: Filter for file creation events, exclude trusted processes, and group by host and file details.
-- False Positive Tuning: Tune process exclusions.

logs(
  source:endpoint
  event.category:file
  event.action:create
  file.name:(*.jar OR *.dll OR *.so OR *.exe OR *.py OR *.sh OR *.bin OR *.ps1)
  file.path:(
    "C:\\Program Files\\SatelliteControl\\*" OR
    "C:\\ProgramData\\HostedPayloads\\*" OR
    "/opt/payload_apps/*" OR
    "/srv/satellite_services/*" OR
    "/usr/lib/*" OR
    "/usr/local/lib/*" OR
    "C:\\Windows\\System32\\*"
  )
  -process.name:(
    msiexec.exe OR yum OR apt OR patch.exe OR dnf OR trustedinstaller.exe OR waagent.exe
  )
)
| group by @host, file.path, file.name, process.name, @user
| select
    min(@timestamp) as firstTime,
    max(@timestamp) as lastTime,
    @host as endpoint,
    @user as user,
    process.name as creating_process,
    file.path as sensitive_directory,
    file.name as file_created,
    count
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

-- Data Source: Endpoint logs (endpoint).
-- Query Strategy: Filter for Java parent processes spawning suspicious children, group by host and process details.
-- False Positive Tuning: Add exclusions for legitimate scripts.

logs(
  source:endpoint
  event.category:process
  process.parent.name:(
    java.exe OR javaw.exe OR tomcat*.exe OR JBossSvc.exe OR wrapper.exe OR prunsrv.exe
  )
  process.name:(
    cmd.exe OR powershell.exe OR pwsh.exe OR sh OR bash OR zsh OR csh OR ksh OR
    wget.exe OR curl.exe OR certutil.exe OR bitsadmin.exe OR rundll32.exe
  )
)
| group by @host, @user, process.parent.name, process.name, process.command_line
| select
    min(@timestamp) as firstTime,
    max(@timestamp) as lastTime,
    @host as host,
    @user as user,
    process.parent.name as parent_process,
    process.name as child_process,
    process.command_line as process_command_line,
    count
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

-- Data Source: Endpoint logs (endpoint).
-- Query Strategy: Filter for chmod with SUID/SGID, exclude trusted parents, and group by host and command.
-- False Positive Tuning: Add exclusions for admin tools.

logs(
  source:endpoint
  event.category:process
  process.name:chmod
  (process.command_line:(*u+s* OR *g+s* OR "[2-7][0-7][0-7][0-7]"))
  -process.parent.name:(yum OR apt OR apt-get OR dpkg OR rpm OR ansible OR puppet OR chef-client)
)
| group by @host, @user, process.parent.name
| select
    min(@timestamp) as firstTime,
    max(@timestamp) as lastTime,
    @host as host,
    @user as user,
    process.parent.name as parent_process,
    values(process.command_line) as cmdline,
    count
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

-- Data Source: CAN bus logs (ot).
-- Query Strategy: Filter for unallowed communication paths, group by components and system.
-- False Positive Tuning: Update allowlist for diagnostics.

logs(
  source:ot
  @source_component IS NOT NULL
  @destination_component IS NOT NULL
)
| eval CommunicationPath = @source_component + ":" + @destination_component
| where NOT CommunicationPath IN (
  "FlightComputer:AttitudeControl",
  "PowerController:FlightComputer",
  "TelemetryUnit:GroundLink",
  "PayloadController:TelemetryUnit"
)
| group by @timestamp, @system_name, @source_component, @destination_component, CommunicationPath, @arbitration_id, @message_data
| select
    @timestamp,
    @system_name as SystemName,
    @source_component as AnomalousSource,
    @destination_component as AnomalousDestination,
    CommunicationPath,
    @arbitration_id as ArbitrationID,
    @message_data as MessageData,
    count
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

-- Data Source: Telemetry logs (telemetry_stream).
-- Query Strategy: Apply anomaly detection to sensor values, group by satellite and sensor.
-- False Positive Tuning: Adjust anomaly threshold.

logs(
  source:telemetry_stream
  @sensor:(
    AttitudeControl_GyroX OR PowerSystem_BusVoltage OR Camera_Gimbal_Angle OR
    Propulsion_TankPressure OR Payload_Temperature
  )
)
| anomaly_detection(@value, threshold=0.005) by @satellite_id, @sensor
| group by @timestamp, @satellite_id, @sensor, anomaly_score
| select
    @timestamp,
    @satellite_id as satellite,
    @sensor as sensor,
    last(@value) as anomalous_value,
    last(anomaly_lower_bound) as lower_bound,
    last(anomaly_upper_bound) as upper_bound,
    last(anomaly_avg) as current_period_avg,
    last(anomaly_stdev) as current_period_stdev,
    anomaly_score
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

-- Data Source: Authentication logs (authentication).
-- Query Strategy: Filter for successful logons, exclude known country-user pairs, and filter out new users.
-- False Positive Tuning: Tune baseline period.

logs(
  source:authentication
  event.category:authentication
  event.outcome:success
  @timestamp:[NOW-24h TO NOW]
  (@destination_system:(gcs-portal.example.com OR mission-planner-1) OR @app:"Ground Station VPN")
)
| group by @user, @src_country, @destination_system
| select
    min(@timestamp) as firstTime,
    max(@timestamp) as lastTime,
    values(network.src_ip) as src_ip,
    values(@app) as app,
    @user as user,
    @src_country as new_country,
    @destination_system as destination_system
| where NOT (
  (@user, @src_country) IN (
    logs(
      source:authentication
      event.category:authentication
      event.outcome:success
      @timestamp:[NOW-30d TO NOW-24h]
      (@destination_system:(gcs-portal.example.com OR mission-planner-1) OR @app:"Ground Station VPN")
    )
    | group by @user, @src_country
    | select @user, @src_country
  )
)
| join type=left @user (
  logs(
    source:authentication
    @timestamp:[NOW-30d TO NOW]
  )
  | group by @user
  | select min(@timestamp) as first_seen
)
| where first_seen < relative_time(now(), "-24h")
| display firstTime, lastTime, user, new_country, src_ip, destination_system, app, first_seen
```