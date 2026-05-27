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

-- ES|QL Notes:
-- Assume a unified endpoint_index or data-stream containing both process and filesystem events. Use conditional EVAL to distinguish patterns.
-- For filesystem rename, use REGEXP to extract extension. Adjust thresholds as needed.
-- For FP tuning on critical assets (e.g., HMI|EWS), use REGEXP on dest or implement via ENRICH policy (e.g., ot_critical_policy on dest with is_critical).
-- Optimize by running over short time ranges and using STATS for aggregation.

FROM * -- endpoint_index or data-stream
| WHERE
    (process_name IN ("vssadmin.exe", "bcdedit.exe") AND
     ((process_name == "vssadmin.exe" AND process LIKE "%delete shadows%") OR
      (process_name == "bcdedit.exe" AND (process LIKE "%recoveryenabled no%" OR process LIKE "%bootstatuspolicy ignoreallfailures%"))))
    OR (action == "renamed")
| EVAL is_process_ttp = CASE(process_name IN ("vssadmin.exe", "bcdedit.exe"), true, false)
| EVAL is_rename_ttp = CASE(action == "renamed", true, false)
| EVAL time_bin = CASE(is_rename_ttp, DATE_TRUNC(5 minutes, @timestamp), @timestamp)
| STATS count = COUNT(), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp) BY time_bin, dest, user, process_name, process, file_path, is_process_ttp, is_rename_ttp
| EVAL new_ext = CASE(is_rename_ttp, REGEXP_REPLACE(file_path, ".*\\.([^.\\\\]+)$", "$1"), NULL)
| STATS renamed_file_count = SUM(count) FILTER (WHERE is_rename_ttp), distinct_ext_count = DISTINCT_COUNT(new_ext) FILTER (WHERE is_rename_ttp), new_extension = VALUES(new_ext) FILTER (WHERE is_rename_ttp), firstTime = MIN(firstTime), lastTime = MAX(lastTime) BY dest, user, process_name, process, is_process_ttp, is_rename_ttp
| WHERE (is_process_ttp) OR (is_rename_ttp AND renamed_file_count > 100 AND distinct_ext_count == 1)
| EVAL TTP = CASE(is_process_ttp AND process_name == "vssadmin.exe", "Shadow Copy Deletion", is_process_ttp AND process_name == "bcdedit.exe", "System Recovery Disabled", is_rename_ttp, "Mass File Renaming")
| EVAL technique = CASE(TTP IN ("Shadow Copy Deletion", "System Recovery Disabled"), "T1490", TTP == "Mass File Renaming", "T1486")
| EVAL tactic = "Impact"
| EVAL process = CASE(is_rename_ttp, "N/A (File System Activity)", process)
| EVAL new_extension = CASE(is_rename_ttp, MV_INDEX(new_extension, 0), NULL)
| EVAL renamed_file_count = CASE(is_rename_ttp, renamed_file_count, NULL)
| WHERE REGEXP(dest, "(?i)HMI|EWS|HISTORIAN")  -- Example FP tuning; replace with ENRICH if using lookup
| KEEP firstTime, lastTime, dest, user, process_name, process, TTP, technique, tactic, renamed_file_count, new_extension
| SORT firstTime DESC
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

-- ES|QL Notes:
-- Assume network_traffic_index for Network_Traffic and endpoint_processes_index for Processes.
-- Use ENRICH policies for macros: ot_asset_policy (on field=DeviceName, with is_ot), corporate_ip_policy (on ip=src/dest, with is_corporate), remote_admin_policy (on process_name, with is_remote_admin).
-- Patterns combined using multiple FROM and conditional EVAL/WHERE for optimization.
-- Filter on ot_assets at the end.

FROM network_traffic_index, endpoint_processes_index
| WHERE
    (action == "allowed" AND
     ((direction == "inbound" AND dest_port IN (3389, 5800, 5900, 5901)) OR
      (direction == "outbound" AND dest_port == 22)))
    OR (process_name IS NOT NULL)  -- For processes
| ENRICH corporate_ip_policy ON src WITH is_corporate_src
| ENRICH corporate_ip_policy ON dest WITH is_corporate_dest
| WHERE (direction == "inbound" AND is_corporate_src != true) OR (direction == "outbound" AND is_corporate_dest != true)
| ENRICH remote_admin_policy ON process_name WITH is_remote_admin
| EVAL is_inbound = CASE(direction == "inbound" AND dest_port IN (3389, 5800, 5900, 5901), true, false)
| EVAL is_outbound_ssh = CASE(direction == "outbound" AND dest_port == 22, true, false)
| EVAL is_remote_exec = CASE(is_remote_admin == true, true, false)
| WHERE is_inbound OR is_outbound_ssh OR is_remote_exec
| STATS count = COUNT(), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp) BY dest, src, dest_port, app, process_name, process, user
| EVAL DeviceName = dest, RemoteIP = src, RemotePort = dest_port, ProcessName = COALESCE(app, process_name), ProcessCommandLine = process, UserName = user
| EVAL Pattern = CASE(is_inbound, "Inbound RDP/VNC from Internet", is_outbound_ssh, "Outbound SSH to Internet", is_remote_exec, "Remote Administration Software Execution")
| EVAL Tactic = CASE(Pattern IN ("Inbound RDP/VNC from Internet"), "Initial Access", true, "Command and Control")
| EVAL Technique = CASE(Pattern IN ("Inbound RDP/VNC from Internet", "Outbound SSH to Internet"), "T1133", Pattern == "Remote Administration Software Execution", "T1219")
| EVAL RemoteIP = CASE(is_remote_exec, "N/A", RemoteIP)
| EVAL RemotePort = CASE(is_remote_exec, "N/A", is_outbound_ssh, 22, RemotePort)
| EVAL ProcessCommandLine = CASE(is_outbound_ssh OR is_inbound, "N/A", ProcessCommandLine)
| EVAL UserName = CASE(is_outbound_ssh OR is_inbound, "N/A", UserName)
| ENRICH ot_asset_policy ON DeviceName WITH is_ot
| WHERE is_ot == true
| KEEP firstTime, lastTime, DeviceName, Pattern, Tactic, Technique, RemoteIP, RemotePort, ProcessName, ProcessCommandLine, UserName
| SORT firstTime DESC
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

-- ES|QL Notes:
-- Assume endpoint_processes_index for Processes and network_traffic_index for Network_Traffic.
-- Use ENRICH for ot_asset_policy (on dest/src=dest_host, with is_ot), corporate_ip_policy (on dest=remote_ip, with is_corporate).
-- Patterns combined with conditionals. Data threshold hardcoded as 10 MB; adjust as needed.
-- Use REGEXP for command-line flags.

FROM endpoint_processes_index, network_traffic_index
| WHERE
    (process_name IN ("ssh.exe", "plink.exe", "putty.exe") AND REGEXP(process, ".*(-D |-L |-R ).*"))
    OR (dest_port == 22 AND direction == "outbound")
| ENRICH ot_asset_policy ON src WITH is_ot_src
| ENRICH ot_asset_policy ON dest WITH is_ot_dest
| WHERE is_ot_src == true OR is_ot_dest == true
| ENRICH corporate_ip_policy ON dest WITH is_corporate
| WHERE is_corporate != true
| EVAL time_bin = CASE(dest_port == 22, DATE_TRUNC(1 hour, @timestamp), @timestamp)
| STATS count = COUNT(), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), bytes_out = SUM(bytes_out), bytes_in = SUM(bytes_in) BY time_bin, src, dest, user, process_name, process, app
| EVAL dest_host = src, remote_ip = dest, user_name = user, process_cmd = process, process_name = COALESCE(process_name, app)
| EVAL is_tunnel = CASE(REGEXP(process_cmd, ".*(-D |-L |-R ).*"), true, false)
| EVAL is_high_data = CASE(dest_port == 22, true, false)
| WHERE is_tunnel OR is_high_data
| EVAL total_bytes = bytes_in + bytes_out
| WHERE (is_tunnel) OR (is_high_data AND total_bytes > (10 * 1024 * 1024))
| EVAL pattern = CASE(is_tunnel, "SSH Tunneling Command Detected", is_high_data, "High Data Transfer over SSH to Public IP")
| EVAL total_bytes_transferred = CASE(is_high_data, CONCAT(TO_STRING(ROUND(total_bytes / 1024 / 1024, 2)), " MB"), "N/A")
| EVAL remote_ip = CASE(is_tunnel, "N/A (check command line)", remote_ip)
| EVAL process_cmd = CASE(is_high_data, "N/A", process_cmd)
| EVAL user_name = CASE(is_high_data, "N/A", user_name)
| KEEP firstTime, lastTime, dest_host, user_name, pattern, process_name, process_cmd, remote_ip, total_bytes_transferred
| SORT firstTime DESC
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

-- ES|QL Notes:
-- Assume endpoint_processes_index.
-- Use REGEXP/LIKE for command-line patterns.
-- For FP tuning on critical systems, use ENRICH critical_systems_policy on dest with is_critical.
-- Optimize with direct filters.

FROM endpoint_processes_index
| WHERE
    (process_name == "procdump.exe" AND process LIKE "%-ma%" AND process LIKE "%lsass.exe%") OR
    (process_name == "rundll32.exe" AND process LIKE "%comsvcs.dll%MiniDump%") OR
    (process_name == "reg.exe" AND process LIKE "%save%" AND (process LIKE "%hklm\\sam%" OR process LIKE "%hklm\\security%" OR process LIKE "%hklm\\system%"))
| STATS count = COUNT(), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp) BY dest, user, parent_process_name, process_name, process
| ENRICH critical_systems_policy ON dest WITH is_critical
| WHERE is_critical == true
| EVAL Pattern = CASE(process_name IN ("procdump.exe", "rundll32.exe"), "LSASS Memory Dumping", process_name == "reg.exe", "Registry Hive Dumping")
| EVAL TechniqueId = CASE(Pattern == "LSASS Memory Dumping", "T1003.001", Pattern == "Registry Hive Dumping", "T1003.002")
| RENAME dest AS DeviceName, user AS AccountName, parent_process_name AS InitiatingProcessFileName, process_name AS FileName, process AS ProcessCommandLine
| KEEP firstTime, lastTime, DeviceName, AccountName, Pattern, TechniqueId, InitiatingProcessFileName, FileName, ProcessCommandLine
| SORT firstTime DESC
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

-- ES|QL Notes:
-- Assume network_traffic_index and endpoint_processes_index.
-- ENRICH for macros: ot_critical_policy (on dest/src=dest_host, with is_critical), corporate_ip_policy (on src/dest, with is_corporate), anomalous_ot_policy (on process_name, with is_anomalous).
-- Patterns combined with conditionals. Thresholds: 200 for DDoS, 50 MB for exfil; adjust as needed.
-- Exclude specific parents for FP.

FROM network_traffic_index, endpoint_processes_index
| WHERE
    (direction == "inbound") OR
    (direction == "outbound") OR
    (process_name IS NOT NULL)
| ENRICH corporate_ip_policy ON src WITH is_corporate_src
| ENRICH corporate_ip_policy ON dest WITH is_corporate_dest
| WHERE (direction == "inbound" AND is_corporate_src != true) OR (direction == "outbound" AND is_corporate_dest != true)
| ENRICH ot_critical_policy ON src WITH is_critical_src
| ENRICH ot_critical_policy ON dest WITH is_critical_dest
| WHERE is_critical_src == true OR is_critical_dest == true
| ENRICH anomalous_ot_policy ON process_name WITH is_anomalous
| EVAL time_bin = CASE(direction == "inbound", DATE_TRUNC(5 minutes, @timestamp), direction == "outbound", DATE_TRUNC(1 hour, @timestamp), @timestamp)
| EVAL is_ddos = CASE(direction == "inbound", true, false)
| EVAL is_anom_proc = CASE(is_anomalous == true AND parent_process != "monitoring_agent.exe", true, false)
| EVAL is_exfil = CASE(direction == "outbound", true, false)
| WHERE is_ddos OR is_anom_proc OR is_exfil
| STATS distinct_remote_ips = DISTINCT_COUNT(src) FILTER (WHERE is_ddos), total_bytes_out = SUM(bytes_out) FILTER (WHERE is_exfil), count = COUNT() BY time_bin, dest, src, user, parent_process, process_name, process, app
| WHERE (is_ddos AND distinct_remote_ips > 200) OR is_anom_proc OR (is_exfil AND total_bytes_out > (50 * 1024 * 1024))
| EVAL dest_host = COALESCE(dest, src), remote_ip = src, user = user, parent_process = parent_process, process_cmd = process, process_name = COALESCE(process_name, app), details = NULL
| EVAL pattern = CASE(is_ddos, "Potential DDoS Symptom (High Inbound Connections)", is_anom_proc, "Anomalous Process on Critical OT Asset", is_exfil, "Large Data Exfiltration from OT Asset")
| EVAL tactic = CASE(pattern LIKE "%DDoS%", "Impact", pattern LIKE "%Process%", "Execution", pattern LIKE "%Exfiltration%", "Exfiltration")
| EVAL technique = CASE(pattern LIKE "%DDoS%", "T1498", pattern LIKE "%Process%", "T1059", pattern LIKE "%Exfiltration%", "T1048")
| EVAL details = CASE(is_ddos, CONCAT("Host ", dest_host, " received connections from ", TO_STRING(distinct_remote_ips), " distinct external IPs in 5 minutes."), is_anom_proc, CONCAT("Process: ", process_name, ", CommandLine: ", process_cmd, ", Initiated by: ", parent_process), is_exfil, CONCAT("Transferred ", TO_STRING(ROUND(total_bytes_out / 1024 / 1024, 2)), " MB from ", dest_host, " to ", remote_ip, " via process ", process_name))
| KEEP time_bin AS _time, dest_host, pattern, tactic, technique, details
| SORT _time DESC
```