### The Worst ICS/OT Cybersecurity Love Story
---

This report summarizes the evolving landscape of ICS/OT threats, highlighting the increasing convergence of state-sponsored adversaries and hacktivist groups, particularly those aligned with Russia. It emphasizes the growing threat of ransomware attacks against industrial organizations and the persistent vulnerabilities in remote access to OT environments.

The 2025 Dragos Year in Review report indicates a significant 87% increase in ransomware attacks against industrial organizations and a 60% rise in active ransomware groups impacting OT/ICS in 2024. Additionally, new intelligence reveals that state-sponsored APT44 (Sandworm) is leveraging hacktivist personas like Cyber Army of Russia Reborn (CARR), XakNet, and Solntsepek to manipulate critical infrastructure, blurring the lines between state-backed and hacktivist operations.

### Actionable Threat Data
---

Monitor for increased ransomware activity, specifically targeting industrial control systems and manufacturing entities, as these have seen a significant surge in attacks.

Implement robust security measures for remote access to OT/ICS environments, addressing insecure configurations, unpatched systems, and poor network architecture, as 65% of assessed sites had such vulnerabilities.

Detect and prevent the use of SSH for general-purpose encrypted communication to publicly routable addresses, as 45% of OT Watch customers had this vulnerability, which can be leveraged for C2 tunnels and proxies.

Focus on detecting initial access attempts by groups like KAMACITE (APT44), which often target IT networks to gain footholds in OT/ICS infrastructure, and look for credential harvesting activities.

Be aware of hacktivist groups like Cyber Army of Russia Reborn (CARR), KillNet, XakNet, and Solntsepek, especially their use of DDoS attacks, data leaks, and attempts to manipulate SCADA systems, as they may act as fronts for more advanced state-sponsored operations.

### Search
---
```sql
-- Name: Ransomware Activity in ICS/OT Environment
-- Author: RW
-- Date: 2025-08-17
-- Description: Detects common ransomware TTPs that are highly anomalous in an Industrial Control Systems (ICS) or Operational Technology (OT) environment. The query identifies shadow copy deletion, disabling of recovery features, and mass file renaming indicative of encryption. The detection is focused on behaviors that are particularly suspicious on critical assets like Engineering Workstations (EWS) or Human-Machine Interfaces (HMI).
-- False Positive Sensitivity: Medium
-- Tactic: Impact
-- Technique: T1490, T1486

-- This search requires endpoint data, such as from Sysmon or a similar EDR tool, mapped to the Endpoint data model.
-- TTP 1 & 2: Inhibit System Recovery (T1490)
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=vssadmin.exe AND Processes.process="*delete shadows*") OR (Processes.process_name=bcdedit.exe AND (Processes.process="*recoveryenabled no*" OR Processes.process="*bootstatuspolicy ignoreallfailures*")) by Processes.dest Processes.user Processes.process_name Processes.process
| `drop_dm_object_name("Processes")`
| rename Processes.dest as dest, Processes.user as user, Processes.process_name as process_name, Processes.process as process
| eval TTP=case(
    process_name="vssadmin.exe", "Shadow Copy Deletion",
    process_name="bcdedit.exe", "System Recovery Disabled"
  ), technique="T1490", tactic="Impact"
| fields firstTime, lastTime, dest, user, process_name, process, TTP, technique, tactic

-- Combine with mass file rename detection
| append [
    -- TTP 3: Data Encrypted for Impact (T1486)
    | tstats `summariesonly` count from datamodel=Endpoint.Filesystem where Filesystem.action=renamed by _time span=5m Filesystem.dest Filesystem.file_path Filesystem.process_name Filesystem.user
    | `drop_dm_object_name("Filesystem")`
    | rename Filesystem.dest as dest, Filesystem.process_name as process_name, Filesystem.file_path as renamed_file, Filesystem.user as user
    -- Extract the file extension from the renamed file path
    | rex field=renamed_file "\\.(?<new_ext>[^.\\\\]+)$"
    -- Summarize rename activity to find hosts where many files are renamed to a single new extension
    | stats count as renamed_file_count, dc(new_ext) as distinct_ext_count, values(new_ext) as new_extension by _time, dest, user, process_name
    -- FP Tuning: Adjust the threshold based on normal activity in your environment.
    | where renamed_file_count > 100 AND distinct_ext_count = 1
    | rename _time as firstTime
    | eval lastTime=firstTime
    | eval TTP="Mass File Renaming", technique="T1486", tactic="Impact", process="N/A (File System Activity)", new_extension=mvindex(new_extension, 0)
    | fields firstTime, lastTime, dest, user, process_name, process, TTP, technique, tactic, renamed_file_count, new_extension
]

-- FP Tuning: To focus this detection on critical ICS/OT assets, filter by device groups or naming conventions.
-- Example: | where match(dest, "(?i)HMI|EWS|HISTORIAN")
```
---
```sql
-- Name: Insecure Remote Access Pattern in ICS/OT Environment
-- Author: RW
-- Date: 2025-08-17
-- Description: Detects multiple patterns of insecure or highly anomalous remote access to or from critical Industrial Control Systems (ICS) or Operational Technology (OT) assets. This includes inbound RDP/VNC from the internet, outbound SSH to the internet, and the use of common remote administration software. Such activity is often forbidden by policy in OT environments and can be an indicator of misconfiguration or malicious activity. This detection is based on intelligence indicating that 65% of assessed OT sites have insecure remote conditions.
-- False Positive Sensitivity: Medium
-- Tactic: Initial Access, Command and Control
-- Technique: T1133, T1219

-- FP Tuning: Create the following macros. The query will not run without them.
-- `ot_asset_identifiers(field)`: A macro to identify critical OT assets. Example: `searchmatch("host=HMI* OR host=EWS*")`
-- `corporate_ip_ranges(field)`: A macro to exclude trusted IP ranges. Example: `cidrmatch("10.0.0.0/8", field) OR cidrmatch("192.168.0.0/16", field)`
-- `remote_admin_tools(field)`: A macro for a list of remote admin tools. Example: `IN("TeamViewer.exe", "AnyDesk.exe", "tv_w32.exe", "tv_x64.exe", "LogMeIn.exe", "ScreenConnect.exe", "splashtop.exe", "vncviewer.exe")`

-- Pattern 1: Detects inbound connections from the public internet on common remote access ports.
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where Network_Traffic.action=allowed Network_Traffic.direction=inbound Network_Traffic.dest_port IN (3389, 5800, 5900, 5901) AND NOT `corporate_ip_ranges("Network_Traffic.src")` by Network_Traffic.dest Network_Traffic.src Network_Traffic.dest_port
| `drop_dm_object_name("Network_Traffic")`
| rename dest as DeviceName, src as RemoteIP, dest_port as RemotePort
| eval Pattern="Inbound RDP/VNC from Internet", Tactic="Initial Access", Technique="T1133", ProcessName="N/A", ProcessCommandLine="N/A", UserName="N/A"
| fields firstTime, lastTime, DeviceName, Pattern, Tactic, Technique, RemoteIP, RemotePort, ProcessName, ProcessCommandLine, UserName

| append [
    -- Pattern 2: Detects outbound SSH connections from OT assets to the public internet.
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where Network_Traffic.action=allowed Network_Traffic.direction=outbound Network_Traffic.dest_port=22 AND NOT `corporate_ip_ranges("Network_Traffic.dest")` by Network_Traffic.src Network_Traffic.dest Network_Traffic.app
    | `drop_dm_object_name("Network_Traffic")`
    | rename src as DeviceName, dest as RemoteIP, app as ProcessName
    | eval Pattern="Outbound SSH to Internet", Tactic="Command and Control", Technique="T1133", RemotePort=22, ProcessCommandLine="N/A", UserName="N/A"
    | fields firstTime, lastTime, DeviceName, Pattern, Tactic, Technique, RemoteIP, RemotePort, ProcessName, ProcessCommandLine, UserName
]

| append [
    -- Pattern 3: Detects the execution of common remote administration software on OT assets.
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `remote_admin_tools("Processes.process_name")` by Processes.dest Processes.process_name Processes.process Processes.user
    | `drop_dm_object_name("Processes")`
    | rename dest as DeviceName, process_name as ProcessName, process as ProcessCommandLine, user as UserName
    | eval Pattern="Remote Administration Software Execution", Tactic="Command and Control", Technique="T1219", RemoteIP="N/A", RemotePort="N/A"
    | fields firstTime, lastTime, DeviceName, Pattern, Tactic, Technique, RemoteIP, RemotePort, ProcessName, ProcessCommandLine, UserName
]

-- Filter for activity on designated OT assets. This is the most important step to reduce noise.
| where `ot_asset_identifiers(DeviceName)`
| convert ctime(firstTime) ctime(lastTime)
```
---
```sql
-- Name: Outbound SSH Tunneling or High Data Transfer from ICS/OT Asset
-- Author: RW
-- Date: 2025-08-17
-- Description: Detects outbound SSH from critical ICS/OT assets to the public internet that exhibits signs of being used for C2 or proxying. The rule looks for either explicit command-line flags used for tunneling or high-volume data transfers over SSH. According to intelligence, 45% of assessed OT environments have SSH communicating to public addresses, which can be leveraged by adversaries for C2 tunnels and proxies.
-- False Positive Sensitivity: Medium
-- Tactic: Command and Control
-- Technique: T1090, T1572

-- FP Tuning: Create the following macros. The query will not run without them.
-- `ot_asset_identifiers(field)`: A macro to identify critical OT assets. Example: `searchmatch("host=HMI* OR host=EWS*")`
-- `corporate_ip_ranges(field)`: A macro to exclude trusted IP ranges. Example: `cidrmatch("10.0.0.0/8", field) OR cidrmatch("192.168.0.0/16", field)`

-- Pattern 1: Detects command-line arguments indicating SSH tunneling. This is a high-fidelity indicator of proxying.
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `ot_asset_identifiers(Processes.dest)` AND Processes.process_name IN ("ssh.exe", "plink.exe", "putty.exe") AND (Processes.process="*-D *" OR Processes.process="*-L *" OR Processes.process="*-R *") by Processes.dest Processes.user Processes.process_name Processes.process
| `drop_dm_object_name("Processes")`
| rename dest as dest_host, user as user_name, process_name as process_name, process as process_cmd
| eval pattern="SSH Tunneling Command Detected", total_bytes_transferred="N/A", remote_ip="N/A (check command line)"
| fields firstTime, lastTime, dest_host, user_name, pattern, process_name, process_cmd, remote_ip, total_bytes_transferred

-- Combine with high data transfer detection
| append [
    -- Pattern 2: Detects high-volume data transfers over SSH to a public IP address.
    | tstats `summariesonly` sum(All_Traffic.bytes_out) as bytes_out, sum(All_Traffic.bytes_in) as bytes_in from datamodel=Network_Traffic where `ot_asset_identifiers(All_Traffic.src)` AND All_Traffic.dest_port=22 AND NOT `corporate_ip_ranges(All_Traffic.dest)` by _time span=1h All_Traffic.src All_Traffic.dest All_Traffic.app
    | `drop_dm_object_name("All_Traffic")`
    | rename src as dest_host, dest as remote_ip, app as process_name
    | eval total_bytes = bytes_in + bytes_out
    -- FP Tuning: Adjust the data transfer threshold (in MB) to suit your environment's baseline for legitimate SSH activity.
    | eval data_transfer_threshold_mb = 10
    | where total_bytes > (data_transfer_threshold_mb * 1024 * 1024)
    | eval total_bytes_transferred = tostring(round(total_bytes/1024/1024, 2)) + " MB"
    | rename _time as firstTime
    | eval lastTime = firstTime
    | eval pattern="High Data Transfer over SSH to Public IP", process_cmd="N/A", user_name="N/A"
    | fields firstTime, lastTime, dest_host, user_name, pattern, process_name, process_cmd, remote_ip, total_bytes_transferred
]
| convert ctime(firstTime) ctime(lastTime)
```
---
```sql
-- Name: KAMACITE Initial Access and Credential Harvesting
-- Author: RW
-- Date: 2025-08-17
-- Description: Detects credential harvesting techniques commonly used by threat actors like KAMACITE (APT44) after gaining initial access to IT networks that bridge to OT/ICS environments. This rule identifies LSASS memory dumping and registry hive dumping, which are critical steps for adversaries to escalate privileges and move laterally. Detecting these activities is crucial to preventing deeper compromise of OT/ICS environments.
-- False Positive Sensitivity: Medium
-- Tactic: Credential Access
-- Technique: T1003.001, T1003.002

| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where
    (
        -- Pattern 1: LSASS memory dumping for credential access (T1003.001)
        (Processes.process_name=procdump.exe AND Processes.process="*-ma*" AND Processes.process="*lsass.exe*") OR
        (Processes.process_name=rundll32.exe AND Processes.process="*comsvcs.dll*MiniDump*")
    )
    OR
    (
        -- Pattern 2: Dumping registry hives for offline credential extraction (T1003.002)
        Processes.process_name=reg.exe AND Processes.process="*save*" AND (Processes.process="*hklm\\sam*" OR Processes.process="*hklm\\security*" OR Processes.process="*hklm\\system*")
    )
    by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name("Processes")`
-- Note: Direct memory access to LSASS by a suspicious process is another common technique.
-- Detecting it requires specific data sources like Sysmon EventID 10 (ProcessAccess) which is not covered by this general rule.

-- FP Tuning: This rule may generate alerts from legitimate administrative or security tool activity.
-- To reduce noise, filter for critical systems that bridge IT and OT, such as jump servers, EWS, or historian servers.
-- This can be done by creating a macro or lookup for those hostnames. e.g., | search `get_critical_systems(dest)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

-- Add contextual fields for triage and align with original detection logic.
| eval Pattern=case(
    (process_name="procdump.exe" OR process_name="rundll32.exe"), "LSASS Memory Dumping",
    process_name="reg.exe", "Registry Hive Dumping"
  )
| eval TechniqueId=case(
    Pattern=="LSASS Memory Dumping", "T1003.001",
    Pattern=="Registry Hive Dumping", "T1003.002"
  )
| rename dest as DeviceName, user as AccountName, parent_process_name as InitiatingProcessFileName, process_name as FileName, process as ProcessCommandLine
| table firstTime, lastTime, DeviceName, AccountName, Pattern, TechniqueId, InitiatingProcessFileName, FileName, ProcessCommandLine
```
---
```sql
-- Name: Hacktivist Activity on SCADA/OT Systems
-- Author: RW
-- Date: 2025-08-17
-- Description: This rule detects TTPs associated with hacktivist groups like CARR and KillNet targeting ICS/OT environments. It identifies potential DDoS symptoms, anomalous administrative tool usage on critical OT assets (HMIs, EWS), and large-scale data exfiltration. These activities can indicate attempts to manipulate SCADA systems or serve as a distraction for other malicious actions.
-- False Positive Sensitivity: Medium
-- Tactic: Impact, Execution, Exfiltration
-- Technique: T1498, T1059, T1048

-- FP Tuning: The following macros are CRITICAL for this detection to function properly and must be configured.
-- `ot_critical_assets(field)`: A macro to identify critical OT assets. Example: `searchmatch("host=HMI* OR host=EWS*")`
-- `corporate_ip_ranges(field)`: A macro to exclude trusted IP ranges. Example: `cidrmatch("10.0.0.0/8", field) OR cidrmatch("192.168.0.0/16", field)`
-- `anomalous_ot_processes(field)`: A macro for a list of anomalous tools. Example: `IN("powershell.exe", "cmd.exe", "cscript.exe", "wscript.exe", "nmap.exe", "netcat.exe", "nc.exe", "net.exe", "netsh.exe", "plink.exe", "putty.exe", "mstsc.exe")`

-- Pattern 1: Detects host-level symptoms of a DDoS or network flood attack.
| tstats `summariesonly` dc(All_Traffic.src) as distinct_remote_ips from datamodel=Network_Traffic where All_Traffic.direction=inbound AND NOT `corporate_ip_ranges(All_Traffic.src)` by _time span=5m All_Traffic.dest
| `drop_dm_object_name("All_Traffic")`
-- FP Tuning: Adjust the threshold for the number of distinct source IPs connecting to a single host.
| where distinct_remote_ips > 200
| rename dest as dest_host
| eval pattern="Potential DDoS Symptom (High Inbound Connections)", tactic="Impact", technique="T1498"
| eval details="Host " + dest_host + " received connections from " + distinct_remote_ips + " distinct external IPs in 5 minutes."
| fields _time, dest_host, pattern, tactic, technique, details

| append [
    -- Pattern 2: Detects execution of anomalous tools on critical OT assets.
    | tstats `summariesonly` count from datamodel=Endpoint.Processes where `ot_critical_assets(Processes.dest)` AND `anomalous_ot_processes(Processes.process_name)` by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process
    | `drop_dm_object_name("Processes")`
    -- FP Tuning: Add legitimate parent processes for your environment to this exclusion to reduce noise.
    | where parent_process!="monitoring_agent.exe"
    | rename dest as dest_host, user as user, parent_process as parent_process, process_name as process_name, process as process_cmd
    | eval pattern="Anomalous Process on Critical OT Asset", tactic="Execution", technique="T1059"
    | eval details="Process: " + process_name + ", CommandLine: " + process_cmd + ", Initiated by: " + parent_process
    | fields _time, dest_host, pattern, tactic, technique, details
]

| append [
    -- Pattern 3: Detects large data transfers from critical OT assets to external destinations.
    | tstats `summariesonly` sum(All_Traffic.bytes_out) as total_bytes_out from datamodel=Network_Traffic where `ot_critical_assets(All_Traffic.src)` AND All_Traffic.direction=outbound AND NOT `corporate_ip_ranges(All_Traffic.dest)` by _time span=1h All_Traffic.src All_Traffic.dest All_Traffic.app
    | `drop_dm_object_name("All_Traffic")`
    -- FP Tuning: Adjust the data transfer threshold (in MB) to suit your environment's baseline.
    | where total_bytes_out > (50 * 1024 * 1024)
    | rename src as dest_host, dest as remote_ip, app as process_name
    | eval pattern="Large Data Exfiltration from OT Asset", tactic="Exfiltration", technique="T1048"
    | eval details="Transferred " + tostring(round(total_bytes_out/1024/1024, 2)) + " MB from " + dest_host + " to " + remote_ip + " via process " + process_name
    | fields _time, dest_host, pattern, tactic, technique, details
]
```