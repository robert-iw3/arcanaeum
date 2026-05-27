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

| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where
    (Filesystem.action=create)
    -- Filter for common code or script file extensions. The CYSAT demo involved a JAR file.
    AND (Filesystem.file_name IN ("*.jar", "*.dll", "*.so", "*.exe", "*.py", "*.sh", "*.bin", "*.ps1"))
    -- Filter for sensitive directories. These paths are examples and MUST be customized for the target environment.
    AND (Filesystem.dest IN ("C:\\Program Files\\SatelliteControl\\*", "C:\\ProgramData\\HostedPayloads\\*", "/opt/payload_apps/*", "/srv/satellite_services/*", "/usr/lib/*", "/usr/local/lib/*", "C:\\Windows\\System32\\*"))
    -- Exclude known legitimate updater processes. This list should be expanded based on legitimate activity in your environment.
    AND NOT (Filesystem.process_name IN ("msiexec.exe", "yum", "apt", "patch.exe", "dnf", "trustedinstaller.exe", "waagent.exe"))
    by Filesystem.dest, Filesystem.file_name, Filesystem.process_name, Filesystem.user, Filesystem.host
| `drop_dm_object_name("Filesystem")`
-- Format output for readability
| `ctime(firstTime)`
| `ctime(lastTime)`
| rename dest as sensitive_directory, file_name as file_created, process_name as creating_process, host as endpoint
| table firstTime, lastTime, endpoint, user, creating_process, sensitive_directory, file_created, count
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

`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where
    -- Filter for common Java application server process names as the parent. This list may need tuning.
    (Processes.parent_process_name IN ("java.exe", "javaw.exe", "tomcat*.exe", "JBossSvc.exe", "wrapper.exe", "prunsrv.exe"))
    -- Filter for suspicious child processes that indicate command execution.
    AND (Processes.process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "zsh", "csh", "ksh", "wget.exe", "curl.exe", "certutil.exe", "bitsadmin.exe", "rundll32.exe"))
    -- Group by the relevant fields to create a unique event.
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
-- Rename fields for better readability in the alert.
| rename dest as host, process as process_command_line, process_name as child_process, parent_process_name as parent_process
| `ctime(firstTime)`
| `ctime(lastTime)`
-- Present the results in a clear format.
| table firstTime, lastTime, host, user, parent_process, child_process, process_command_line, count
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

`tstats` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.process_name="chmod" by Processes.dest, Processes.user, Processes.parent_process_name
| `drop_dm_object_name("Processes")`
-- Filter for chmod commands that add the SUID ('u+s') or SGID ('g+s') bit, using symbolic or octal modes.
| where (like(cmdline, "%u+s%") OR like(cmdline, "%g+s%") OR match(cmdline, ".*\s+[2-7]\d{3}\s+.*"))
-- Exclude common package managers and configuration management tools. This list may need tuning for your environment.
| where NOT (parent_process_name IN ("yum", "apt", "apt-get", "dpkg", "rpm", "ansible", "puppet", "chef-client"))
-- Rename fields for clarity
| rename dest as host, parent_process_name as parent_process
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, parent_process, cmdline
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

`comment("This search requires a custom data source for CAN bus or similar OT data. Replace 'index=ot sourcetype=can_bus' with the appropriate search for your environment.")`
index=ot sourcetype=can_bus SourceComponent=* DestinationComponent=*
| `comment("Create a standardized representation of the communication path.")`
| eval CommunicationPath = SourceComponent . ":" . DestinationComponent
| `comment("The core logic: alert on any communication path that is NOT in the allowlist. This list is critical and MUST be populated based on the specific system's design documentation.")`
| where NOT (CommunicationPath IN (
        "FlightComputer:AttitudeControl",
        "PowerController:FlightComputer",
        "TelemetryUnit:GroundLink",
        "PayloadController:TelemetryUnit"
        ))
| `comment("Rename fields for clarity and format the results for alerting.")`
| rename SourceComponent as AnomalousSource, DestinationComponent as AnomalousDestination, DeviceName as SystemName
| table _time, SystemName, AnomalousSource, AnomalousDestination, CommunicationPath, ArbitrationID, MessageData
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

`comment("This search requires a custom data source for satellite telemetry data. The index, sourcetype, and field names must be customized.")`
index=satellite_telemetry sourcetype=telemetry_stream
| `comment("Filter for critical sensors that are essential for mission operations. This list MUST be customized for the specific mission.")`
| search sensor IN (
    "AttitudeControl_GyroX",
    "PowerSystem_BusVoltage",
    "Camera_Gimbal_Angle",
    "Propulsion_TankPressure",
    "Payload_Temperature"
    )
| `comment("Use the anomalydetection command to identify values that deviate significantly from the learned baseline for each sensor on each satellite. The threshold can be tuned to adjust sensitivity; a lower value is more sensitive.")`
| anomalydetection action=filter threshold=0.005 "value" by "satellite, sensor"
| `comment("Rename fields for clarity in the alert.")`
| rename value as anomalous_value
| `comment("Format the results for easy analysis.")`
| table _time, satellite, sensor, anomalous_value, lower_bound, upper_bound, current_period_avg, current_period_stdev, anomaly_score
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

-- This macro must be defined to specify hosts/apps considered critical ground systems.
-- Example: `define critical_ground_systems (Authentication.dest IN ("gcs-portal.example.com", "mission-planner-1") OR Authentication.app IN ("Ground Station VPN"))`

`tstats` `summariesonly` min(_time) as firstTime, max(_time) as lastTime, values(Authentication.src) as src_ip, values(Authentication.app) as app
from datamodel=Authentication
-- Look for successful authentications to critical systems in the last 24 hours.
where `critical_ground_systems` AND Authentication.action="success" AND earliest=-24h
by Authentication.user, Authentication.src_country, Authentication.dest
| `drop_dm_object_name("Authentication")`

-- Subsearch finds all user/country combinations seen in the baseline period (last 30 days, excluding today).
-- The main search is then filtered to find user/country pairs that have NOT been seen in the baseline.
| where NOT [| tstats `summariesonly` count from datamodel=Authentication where `critical_ground_systems` AND Authentication.action="success" AND earliest=-30d@d latest=-24h@h by Authentication.user, Authentication.src_country | fields user, src_country | rename Authentication.user as user, Authentication.src_country as src_country | format]

-- To reduce noise from new accounts, filter out users whose first-ever activity was within the last 24 hours.
| join type=left user [| tstats `summariesonly` earliest(_time) as first_seen from datamodel=Authentication where earliest=-30d by Authentication.user | rename Authentication.user as user | fields user, first_seen]
| where first_seen < relative_time(now(), "-24h")

-- Format the results for alerting.
| `ctime(firstTime)`
| `ctime(lastTime)`
| `ctime(first_seen)`
| rename user as user, src_country as new_country, dest as destination_system
| table firstTime, lastTime, user, new_country, src_ip, destination_system, app, first_seen
```