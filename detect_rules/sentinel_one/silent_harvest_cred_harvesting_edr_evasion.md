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

SELECT
    min(timestamp) AS start_time,
    max(timestamp) AS end_time,
    endpoint_name,
    user_name,
    process_name,
    process_cmdline,
    CASE WHEN COUNT(DISTINCT event_type) >= 2 AND ARRAY_CONTAINS(event_types, 'sensitive_reg_access') THEN 'Yes' ELSE 'No' END AS alert_trigger,
    CASE WHEN ARRAY_CONTAINS(event_types, 'wmi_child_process') THEN 'Yes' ELSE 'No' END AS has_wmi_parent,
    CASE WHEN ARRAY_CONTAINS(event_types, 'large_upload') THEN 'Yes' ELSE 'No' END AS has_large_upload,
    CONCAT('Correlated Attack Pattern Detected: ', process_name, ' on ', endpoint_name, ' by user ', user_name, '.',
           IF(ARRAY_CONTAINS(event_types, 'wmi_child_process'), ' | Precursor: Process spawned by WMI.', ''),
           IF(ARRAY_CONTAINS(event_types, 'large_upload'), ' | Follow-on: Large outbound data transfer observed.', '')) AS risk_description,
    COUNT(*) AS event_count,
    (max(timestamp) - min(timestamp)) / 1000 AS duration_seconds
FROM (
    SELECT
        timestamp,
        endpoint_name,
        user_name,
        process_name,
        process_cmdline,
        process_id,
        'wmi_child_process' AS event_type
    FROM process
    WHERE parent_process_name = 'WmiPrvSE.exe'
    UNION ALL
    SELECT
        timestamp,
        endpoint_name,
        user_name,
        process_name,
        process_cmdline,
        process_id,
        'sensitive_reg_access' AS event_type
    FROM registry
    WHERE registry_key_path LIKE '%\\SAM\\%' OR registry_key_path LIKE '%\\SECURITY\\%'
    AND user_name != 'NT AUTHORITY\\SYSTEM'
    UNION ALL
    SELECT
        timestamp,
        endpoint_name,
        user_name,
        process_name,
        process_cmdline,
        process_id,
        'large_upload' AS event_type
    FROM network
    WHERE direction = 'outbound' AND bytes_sent > 500000
) AS events
WHERE process_name NOT IN ('outlook.exe', 'teams.exe', 'onedrive.exe', 'msedge.exe', 'chrome.exe', 'firefox.exe', 'gdrive.exe', 'dropbox.exe', 'Veeam.EndPoint.Service.exe')
GROUP BY endpoint_name, user_name, process_name, process_cmdline, process_id
HAVING alert_trigger = 'Yes' AND duration_seconds <= 1800
```