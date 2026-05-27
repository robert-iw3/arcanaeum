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

source:sysmon (
    (@EventCode:1 @process.parent.name:WmiPrvSE.exe) OR
    (@EventCode:13 (@TargetObject:*\\SAM\\* OR @TargetObject:*\\SECURITY\\*) @user.name:-\"NT AUTHORITY\\SYSTEM\") OR
    (@EventCode:3 @network.direction:outbound @network.initiated:true @network.bytes_out>500000)
) AND (
    -@process.name:(outlook.exe OR teams.exe OR onedrive.exe OR msedge.exe OR chrome.exe OR firefox.exe OR gdrive.exe OR dropbox.exe OR Veeam.EndPoint.Service.exe)
)
```