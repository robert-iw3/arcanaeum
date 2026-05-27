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

(sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational OR sourcetype=sysmon) EventCode IN (1, 3, 13)

`comment("Step 1: Filter for and tag three key event types: WMI child process, sensitive registry access, and large network upload.")`
| eval event_type=case(
    EventCode=1 AND (ParentImage LIKE "%\\WmiPrvSE.exe"), "wmi_child_process",
    EventCode=13 AND (TargetObject LIKE "%\\SAM\\%" OR TargetObject LIKE "%\\SECURITY\\%") AND User!="NT AUTHORITY\\SYSTEM", "sensitive_reg_access",
    EventCode=3 AND Direction="outbound" AND Initiated="true" AND SentBytes > 500000, "large_upload"
  )
| where isnotnull(event_type)

`comment("Step 2: Use transaction to group events by the same process instance (ProcessGuid) on the same host within a 30-minute window.")`
| transaction host ProcessGuid maxspan=30m

`comment("Step 3: Filter for transactions that contain the core indicator: sensitive registry access by a non-SYSTEM account.")`
| where mvfind(event_type, "sensitive_reg_access") > -1

`comment("Step 4: Identify which other suspicious activities are present in the transaction.")`
| eval has_wmi_parent = if(mvfind(event_type, "wmi_child_process") > -1, "Yes", "No")
| eval has_large_upload = if(mvfind(event_type, "large_upload") > -1, "Yes", "No")

`comment("Step 5: The alert triggers if the registry access is accompanied by either WMI parentage or a large upload.")`
| where has_wmi_parent="Yes" OR has_large_upload="Yes"

`comment("FP Mitigation: Filter out known legitimate processes that might perform these actions, such as backup, sync, or admin tools. Add to this list as needed.")`
| where NOT (Image LIKE "%\\outlook.exe" OR Image LIKE "%\\teams.exe" OR Image LIKE "%\\onedrive.exe" OR Image LIKE "%\\msedge.exe" OR Image LIKE "%\\chrome.exe" OR Image LIKE "%\\firefox.exe" OR Image LIKE "%\\gdrive.exe" OR Image LIKE "%\\dropbox.exe" OR Image LIKE "%\\Veeam.EndPoint.Service.exe")

`comment("Step 6: Format the results for alerting and investigation.")`
| eval start_time = strftime(startTime, "%Y-%m-%d %H:%M:%S")
| eval end_time = strftime(endTime, "%Y-%m-%d %H:%M:%S")
| eval risk_description = "Correlated Attack Pattern Detected: " . mvindex(Image,0) . " on " . host . " by user " . mvindex(User,0) . "."
| eval wmi_context = if(has_wmi_parent="Yes", " | Precursor: Process spawned by WMI.", "")
| eval exfil_context = if(has_large_upload="Yes", " | Follow-on: Large outbound data transfer observed.", "")
| eval risk_description = risk_description + wmi_context + exfil_context
| table start_time, end_time, host, User, Image, CommandLine, has_wmi_parent, has_large_upload, risk_description, eventcount, duration

`comment("Note on SeBackupPrivilege: The 'Silent Harvest' technique also involves enabling SeBackupPrivilege (Windows Event ID 4703). Correlating this event is difficult in a single query because it often lacks the ProcessGuid. Consider a separate, simpler rule to detect a non-SYSTEM process enabling this privilege shortly before any process accesses SAM/SECURITY on the same host.")`
```