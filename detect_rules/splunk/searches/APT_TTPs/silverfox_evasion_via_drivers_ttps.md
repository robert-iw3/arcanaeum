### Silver Fox APT Leverages Vulnerable Drivers for Evasion and ValleyRAT Delivery
---

The Silver Fox APT group is actively exploiting vulnerable, signed drivers to bypass endpoint security solutions and deploy the ValleyRAT backdoor. This campaign utilizes a dual-driver strategy, including a newly identified vulnerable WatchDog Antimalware driver (amsdk.sys), to terminate security processes and maintain stealth on Windows 10 and 11 systems.

Beyond the initial report, recent intelligence indicates Silver Fox APT has expanded its targeting to include healthcare, finance, and government sectors, often using trojanized software like Philips DICOM viewers and fake Chrome updates as initial infection vectors. The group has also demonstrated increased sophistication in evasion, including modifying patched drivers to bypass hash-based blocklists while retaining valid Microsoft signatures.

### Actionable Threat Data
---

Monitor for the creation of the C:\Program Files\RunTime directory and the dropping of RuntimeBroker.exe and Amsdk_Service.sys within it.

Detect the creation of new services, specifically "Termaintor" and "Amsdk_Service", configured for persistence and driver loading.

Look for attempts to load the amsdk.sys (version 1.0.600) or wamsdk.sys (version 1.1.100) drivers, especially if they are not part of legitimate WatchDog Antimalware installations.

Identify processes attempting to communicate with the amsdk device via DeviceIoControl using IOCTLs 0x80002010 (IOCTL_REGISTER_PROCESS) followed by 0x80002048 (IOCTL_TERMINATE_PROCESS).

Alert on network connections to known ValleyRAT C2 servers, particularly those hosted in China, and analyze for XOR-encrypted traffic.

### Combined Analysis Search
---
```sql
-- Title: Silver Fox APT Multi-Stage Activity
-- Description: Detects a combination of TTPs associated with the Silver Fox APT group. This rule correlates persistence mechanisms, vulnerable driver abuse for defense evasion, and C2 communications related to the ValleyRAT backdoor deployment.
-- References: https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/
-- Author: RW
-- Date: 2025-08-30
-- False Positives: Legitimate installations or use of WatchDog Antimalware might trigger parts of this rule. However, the correlation with the specific vulnerable driver hash and at least one other suspicious activity significantly reduces the likelihood of false positives.
-- Level: High

-- This tstats query efficiently searches for multiple indicators across different CIM data models.
| tstats `summariesonly` summariesonly=true allow_old_summaries=true from datamodel=Endpoint
  where (nodename=All_Endpoint.Image_Loads (Image_Loads.file_hash IN ("12b3d8bc5cc1ea6e2acd741d8a80f56cf2a0a7ebfa0998e3f0743fcf83fabb9e", "0be8483c2ea42f1ce4c90e84ac474a4e7017bc6d682e06f96dc1e31922a07b10", "9c394dcab9f711e2bf585edf0d22d2210843885917d409ee56f22a4c24ad225e")))
  OR (nodename=All_Endpoint.Filesystem (Filesystem.file_path="C:\\Program Files\\RunTime\\*" AND (Filesystem.file_name="RuntimeBroker.exe" OR Filesystem.file_name="Amsdk_Service.sys")))
  OR (nodename=All_Endpoint.Registry (Registry.registry_path IN ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Termaintor*", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Amsdk_Service*")))
  OR (nodename=All_Endpoint.Network_Traffic (All_Traffic.dest_ip IN ("47.239.197.97", "8.217.38.238", "156.234.58.194", "156.241.144.66", "1.13.249.217")) AND (All_Traffic.dest_port IN (52116, 52117, 8888, 52110, 52111, 52139, 52160, 9527, 9528)))
  by _time, All_Endpoint.dest, All_Endpoint.user, All_Endpoint.process_name, All_Endpoint.file_hash, All_Endpoint.file_path, All_Endpoint.file_name, All_Endpoint.registry_path, All_Endpoint.dest_ip, All_Endpoint.dest_port
| `drop_dm_object_name("All_Endpoint")`

-- Categorize each event into a specific indicator type for correlation.
| eval indicator_type = case(
    match(file_hash, "(?i)12b3d8bc5cc1ea6e2acd741d8a80f56cf2a0a7ebfa0998e3f0743fcf83fabb9e|0be8483c2ea42f1ce4c90e84ac474a4e7017bc6d682e06f96dc1e31922a07b10|9c394dcab9f711e2bf585edf0d22d2210843885917d409ee56f22a4c24ad225e"), "Vulnerable_Driver_Loaded",
    match(file_path, "(?i)C:\\\\Program Files\\\\RunTime\\\\") AND (file_name="RuntimeBroker.exe" OR file_name="Amsdk_Service.sys"), "Suspicious_File_Written",
    match(registry_path, "(?i)HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\(Termaintor|Amsdk_Service)"), "Suspicious_Service_Created",
    isnotnull(dest_ip), "C2_Traffic_Detected",
    true(), "Other"
  )
| eval indicator_value = case(
    indicator_type=="Vulnerable_Driver_Loaded", file_hash,
    indicator_type=="Suspicious_File_Written", file_path,
    indicator_type=="Suspicious_Service_Created", registry_path,
    indicator_type=="C2_Traffic_Detected", dest_ip + ":" + dest_port,
    true(), "N/A"
  )

-- Group all indicators by host and aggregate the details.
| stats earliest(_time) as first_seen, latest(_time) as last_seen, values(user) as users, dc(indicator_type) as distinct_indicator_count, values(indicator_type) as indicators, values(indicator_value) as indicator_details by dest

-- Apply the core detection logic: a vulnerable driver must be loaded, plus at least one other indicator type must be present.
| where like(indicators, "%Vulnerable_Driver_Loaded%") AND distinct_indicator_count > 1

-- Add a note about IOCTL detection, which requires non-standard EDR logs and is not included in this CIM-based query.
| eval note = "IOCTL detection (DeviceIoControl to 'amsdk' with codes 0x80002010, 0x80002048) requires specific EDR logs. This activity may also be present but is not detected by this query."

-- Format the output for analysts.
| rename dest as host
| table first_seen, last_seen, host, users, indicators, indicator_details, note
| `silver_fox_apt_multi_stage_activity_filter`
```