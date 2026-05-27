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

event_platform=Win
| union (
    -- Step 1: WMI child process (EventCode=1, ParentImage=WmiPrvSE.exe)
    ProcessRollup2
    | where ParentBaseFileName="WmiPrvSE.exe"
    | eval event_type="wmi_child_process"
    | select aid, cid, event_platform, ComputerName, UserName, event_simpleName, ProcessId, ParentProcessId, RawProcessId, BaseFileName, CommandLine, ProcessGuid, event_type, eventTime
    ,
    -- Step 2: Sensitive registry access (EventCode=13, SAM/SECURITY, non-SYSTEM)
    RegistryOperation
    | where event_simpleName in ("RegistryValueSet", "RegistryKeyCreate") and TargetObject rlike ".*\\\\(SAM|SECURITY)\\\\.*" and UserName != "NT AUTHORITY\\SYSTEM"
    | eval event_type="sensitive_reg_access"
    | select aid, cid, event_platform, ComputerName, UserName, event_simpleName, ProcessId, TargetObject, ProcessGuid, event_type, eventTime
    ,
    -- Step 3: Large outbound upload (EventCode=3, SentBytes > 500000)
    NetworkConnect
    | where Direction="Outbound" and ConnectionDirection="Initiated" and SentBytes > 500000
    | eval event_type="large_upload"
    | select aid, cid, event_platform, ComputerName, UserName, event_simpleName, ProcessId, SentBytes, SourceIp, DestinationIp, DestinationPort, ProcessGuid, event_type, eventTime
)
| where event_type is not null
| group by aid, ProcessGuid window 30m
| where array_contains(event_type, "sensitive_reg_access")
| eval has_wmi_parent = if(array_contains(event_type, "wmi_child_process"), "Yes", "No")
| eval has_large_upload = if(array_contains(event_type, "large_upload"), "Yes", "No")
| where has_wmi_parent="Yes" or has_large_upload="Yes"
| where BaseFileName !~ ".*\\\\(outlook\\.exe|teams\\.exe|onedrive\\.exe|msedge\\.exe|chrome\\.exe|firefox\\.exe|gdrive\\.exe|dropbox\\.exe|Veeam\\.EndPoint\\.Service\\.exe)"
| project eventTime, rule_name="Correlated Credential Access", ComputerName, UserName, BaseFileName, CommandLine, has_wmi_parent, has_large_upload, risk_description=concat("Correlated Attack Pattern Detected: ", BaseFileName, " on ", ComputerName, " by user ", UserName, ".", if(has_wmi_parent="Yes", " | Precursor: Process spawned by WMI.", ""), if(has_large_upload="Yes", " | Follow-on: Large outbound data transfer observed.", "")), event_count=count(), duration=max(eventTime) - min(eventTime)
| format_time(field=eventTime, format="%Y-%m-%d %H:%M:%S")
```