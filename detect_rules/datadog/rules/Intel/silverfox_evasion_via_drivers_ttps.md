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

-- Search for matching indicators
(
    -- Vulnerable driver loads (file hashes)
    @event_type:module_load @hash.sha256:(
        "12b3d8bc5cc1ea6e2acd741d8a80f56cf2a0a7ebfa0998e3f0743fcf83fabb9e" OR
        "0be8483c2ea42f1ce4c90e84ac474a4e7017bc6d682e06f96dc1e31922a07b10" OR
        "9c394dcab9f711e2bf585edf0d22d2210843885917d409ee56f22a4c24ad225e"
    )
    OR
    -- Suspicious files written
    @event_type:file_write @file.path:"C:\\Program Files\\RunTime\\*" @file.name:("RuntimeBroker.exe" OR "Amsdk_Service.sys")
    OR
    -- Suspicious services created (registry)
    @event_type:registry @registry.path:(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Termaintor*" OR
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Amsdk_Service*"
    )
    OR
    -- C2 traffic
    @event_type:network @destination.ip:(
        "47.239.197.97" OR "8.217.38.238" OR "156.234.58.194" OR "156.241.144.66" OR "1.13.249.217"
    ) @destination.port:(52116 OR 52117 OR 8888 OR 52110 OR 52111 OR 52139 OR 52160 OR 9527 OR 9528)
)
-- Categorize indicators
| eval indicator_type = case(
    @hash.sha256 IN (
        "12b3d8bc5cc1ea6e2acd741d8a80f56cf2a0a7ebfa0998e3f0743fcf83fabb9e",
        "0be8483c2ea42f1ce4c90e84ac474a4e7017bc6d682e06f96dc1e31922a07b10",
        "9c394dcab9f711e2bf585edf0d22d2210843885917d409ee56f22a4c24ad225e"
    ), "Vulnerable_Driver_Loaded",
    @file.path MATCHES "C:\\Program Files\\RunTime\\*" AND @file.name IN ("RuntimeBroker.exe", "Amsdk_Service.sys"), "Suspicious_File_Written",
    @registry.path MATCHES "(HKLM\\SYSTEM\\CurrentControlSet\\Services\\Termaintor.*|HKLM\\SYSTEM\\CurrentControlSet\\Services\\Amsdk_Service.*)", "Suspicious_Service_Created",
    @destination.ip IS NOT NULL, "C2_Traffic_Detected",
    true, "Other"
)
| eval indicator_value = case(
    indicator_type="Vulnerable_Driver_Loaded", @hash.sha256,
    indicator_type="Suspicious_File_Written", @file.path,
    indicator_type="Suspicious_Service_Created", @registry.path,
    indicator_type="C2_Traffic_Detected", @destination.ip + ":" + @destination.port,
    true, "N/A"
)
-- Aggregate by host
| stats by @host
    min(@timestamp) as first_seen
    max(@timestamp) as last_seen
    collect(@user) as users
    count_distinct(indicator_type) as distinct_indicator_count
    collect(indicator_type) as indicators
    collect(indicator_value) as indicator_details
-- Core detection logic
| where indicators MATCHES "Vulnerable_Driver_Loaded" AND distinct_indicator_count > 1
-- Add IOCTL note
| eval note = "IOCTL detection (DeviceIoControl to 'amsdk' with codes 0x80002010, 0x80002048) requires specific EDR logs. This activity may also be present but is not detected by this query."
-- Format output
| select first_seen, last_seen, @host as host, users, indicators, indicator_details, note
```