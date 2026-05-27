### Silent Harvest: Evading EDR for Windows Secret Extraction
---

The "Silent Harvest" technique describes a novel method for extracting Windows secrets from the SAM and SECURITY registry hives while bypassing common Endpoint Detection and Response (EDR) detections. This is achieved by leveraging undocumented Windows APIs and less-monitored functions to access sensitive registry data directly from memory without writing to disk or triggering typical EDR alerts.

This technique introduces a two-pronged approach to EDR evasion: using NtOpenKeyEx with REG_OPTION_BACKUP_RESTORE to bypass ACLs and RegQueryMultipleValuesW to read data, which is noteworthy because it exploits less-monitored Windows APIs to achieve stealthy credential harvesting, operating without SYSTEM privileges and avoiding on-disk artifacts.

### Actionable Threat Data
---

Monitor for processes enabling SeBackupPrivilege followed by calls to NtOpenKeyEx with the REG_OPTION_BACKUP_RESTORE flag, especially when targeting HKLM\SAM or HKLM\SECURITY registry hives.

Implement detection for unusual or infrequent API calls to RegQueryMultipleValuesW when associated with processes attempting to access sensitive registry paths like HKLM\SAM or HKLM\SECURITY.

Look for processes attempting to access lsass.exe memory or related LSA secrets, as this remains a high-risk activity heavily monitored by security solutions.

Analyze process behavior for credential harvesting activities that do not involve writing registry hive backups to disk, focusing on in-memory operations.

Investigate instances where administrative accounts (not SYSTEM) are used to execute tools that interact with the SAM or SECURITY hives, particularly if executed remotely via methods like WMI.

### Combined Analysis Search
---
```sql
-- Name: Correlated Credential Access, Remote Execution, and Exfiltration
-- Author: RW
-- Date: 2025-08-24
-- Description: This detection correlates multiple suspicious behaviors on a single host to identify advanced credential theft attacks like "Silent Harvest". It triggers when a non-SYSTEM process accesses sensitive registry hives (SAM/SECURITY) AND is either spawned by WMI (indicating remote execution) OR is followed by a large outbound data transfer (indicating exfiltration).
-- MITRE ATT&CK: T1003.002, T1047, T1041, T1134.001
-- False Positive Sensitivity: Medium

FROM logs-sysmon-*
| WHERE event.code IN ("1", "3", "13")
| EVAL event_type = CASE(
  event.code == "1" AND process.parent.executable ILIKE "%\\WmiPrvSE.exe", "wmi_child_process",
  event.code == "13" AND winlog.event_data.TargetObject ILIKE "*\\(SAM|SECURITY)\\*" AND user.name != "NT AUTHORITY\\SYSTEM", "sensitive_reg_access",
  event.code == "3" AND network.direction == "outbound" AND network.transport == "tcp" AND network.bytes > 500000, "large_upload",
  NULL
)
| WHERE event_type IS NOT NULL
| STATS count = COUNT(*), event_types = COLLECT(event_type), users = COLLECT(user.name), processes = COLLECT(process.executable), commands = COLLECT(process.command_line), min_time = MIN(@timestamp), max_time = MAX(@timestamp) BY host.name, process.entity_id
| WHERE ARRAY_CONTAINS(event_types, "sensitive_reg_access")
| EVAL has_wmi_parent = IF(ARRAY_CONTAINS(event_types, "wmi_child_process"), "Yes", "No")
| EVAL has_large_upload = IF(ARRAY_CONTAINS(event_types, "large_upload"), "Yes", "No")
| WHERE has_wmi_parent == "Yes" OR has_large_upload == "Yes"
| WHERE process.executable NOT ILIKE "%\\(outlook.exe|teams.exe|onedrive.exe|msedge.exe|chrome.exe|firefox.exe|gdrive.exe|dropbox.exe|Veeam.EndPoint.Service.exe)"
| EVAL risk_description = CONCAT("Correlated Attack Pattern Detected: ", FIRST(processes), " on ", host.name, " by user ", FIRST(users), ".", IF(has_wmi_parent == "Yes", " | Precursor: Process spawned by WMI.", ""), IF(has_large_upload == "Yes", " | Follow-on: Large outbound data transfer observed.", ""))
| EVAL start_time = TO_STRING(min_time, "yyyy-MM-dd HH:mm:ss"), end_time = TO_STRING(max_time, "yyyy-MM-dd HH:mm:ss")
| KEEP start_time, end_time, host.name, users, processes, commands, has_wmi_parent, has_large_upload, risk_description, count, duration = max_time - min_time
| WHERE duration <= 30m
```