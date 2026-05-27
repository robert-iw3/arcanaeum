### Crossing the Line: Advanced Techniques to Breach the OT DMZ
---

This report analyzes advanced techniques used to breach the Operational Technology (OT) DMZ, focusing on credential harvesting, RDP session hijacking, RDP shadowing, and hidden desktop (hVNC) attacks. It provides actionable threat data for creating high-fidelity detections to protect critical infrastructure.

Recent intelligence indicates a continued focus by threat actors on exploiting remote access vulnerabilities and leveraging legitimate tools for malicious purposes within OT environments. The increasing sophistication of RDP-related attacks, including the use of hVNC for stealthy persistence, highlights the need for enhanced monitoring beyond traditional perimeter defenses.

### Actionable Threat Data
---

Monitor for the execution of credential harvesting tools such as LaZagne.exe, mimikatz.exe, Seatbelt.exe, and SharpDPAPI.exe on jump servers and other critical systems within the OT DMZ.

Detect abnormal usage of tscon.exe, specifically when used with the /dest:console flag, or any unexpected Logon Type 10 or 7 events without preceding logon/logoff events, indicating potential RDP session hijacking (T1563.002).

Identify RDP shadowing activity by monitoring for shadow.exe execution with /noConsentPrompt or /control flags, and unexpected Session Reconnect events (Event ID 4778), especially from non-helpdesk accounts.

Implement detections for hidden desktop (hVNC) style abuse, looking for unusual desktop creation (e.g., WinSta0\hidden, CreateDesktop, SwitchDesktop), GUI sessions started by non-user processes (e.g., C2 implants), and suspicious API usage like CreateRemoteThread into GUI sessions.

Monitor for modifications to group memberships, particularly the "OT Remote Access Users" group, and alert on unauthorized additions or changes to prevent privilege escalation (T1098).

### Search
---
```sql
-- Name: OT DMZ Breach Techniques
-- Author: RW
-- Date: 2025-08-17
-- Description: This rule combines multiple detection patterns based on intelligence regarding OT DMZ breaches. It detects credential harvesting, various forms of RDP abuse (hijacking, shadowing, hVNC), and sensitive group modifications. Each detection pattern is designed to identify specific adversary TTPs observed in attacks targeting OT environments.
-- MITRE ATT&CK: T1003, T1563, T1563.002, T1098
-- References: https://attack.mitre.org/techniques/T1563/002/
-- https://github.com/WKL-Sec/HiddenDesktop?tab=readme-ov-file
-- https://attack.mitre.org/techniques/T1098/
-- https://attack.mitre.org/techniques/T1003/
-- https://attack.mitre.org/techniques/T1563/
-- False Positive Sensitivity: Medium

-- Data Source:
-- Requires process creation events (e.g., Sysmon EventCode 1) and Windows Security event logs (EventCode=4728 or 4756) mapped to Elastic Common Schema (ECS) fields.

FROM *
| WHERE
    -- Process-based Detections
    (event.category == "process" AND (
        -- Detection for credential harvesting tools execution
        (process.name RLIKE "(?i)(LaZagne|mimikatz|Seatbelt|SharpDPAPI)\\.exe$") OR
        -- Detection for RDP session hijacking via tscon.exe
        (process.name RLIKE "(?i)tscon\\.exe$" AND process.command_line RLIKE "\\s(\\d+|/dest:\\w+)" AND user.id == "S-1-5-18") OR
        -- Detection for RDP shadowing activity
        (((process.name RLIKE "(?i)mstsc\\.exe$" AND process.command_line LIKE "*/shadow*") OR process.name RLIKE "(?i)shadow\\.exe$") AND (process.command_line LIKE "*/noConsentPrompt*" OR process.command_line LIKE "*/control*")) OR
        -- Detection for Hidden Desktop (hVNC) abuse
        (process.name RLIKE "(?i)(explorer|iexplore|chrome|firefox|msedge|winword|excel|powerpnt|outlook|mstsc|cmd|powershell)\\.exe$" AND (process.parent.name RLIKE "(?i)(services|svchost|lsass|wininit|wmiprvse|wmiadap)\\.exe$" OR user.id == "S-1-5-18"))
    ))
    OR
    -- Group Membership Detection
    (winlog.channel == "Security" AND winlog.event_id IN (4728, 4756) AND winlog.event_data.TargetUserName == "OT Remote Access Users")

-- FP Mitigation: Exclude known legitimate activity for any of the above detections.
-- Example: | WHERE NOT (COALESCE(user.name, winlog.event_data.SubjectUserName) IN ("redteam_user1", "helpdesk_admin1", "authorized_support_group"))

-- Use case statements to assign detection-specific details
| EVAL
    DetectionName = CASE(
        process.name RLIKE "(?i)(LaZagne|mimikatz|Seatbelt|SharpDPAPI)\\.exe$", "Credential Harvesting Tool Execution",
        process.name RLIKE "(?i)tscon\\.exe$", "RDP Session Hijacking via tscon.exe",
        ((process.name RLIKE "(?i)mstsc\\.exe$" AND process.command_line LIKE "*/shadow*") OR process.name RLIKE "(?i)shadow\\.exe$"), "RDP Shadowing Activity",
        event.category == "process", "Hidden Desktop (hVNC) Abuse",
        winlog.event_id IN (4728, 4756), "Group Membership Modification to Sensitive OT Group"
    ),
    MITRE_TTP = CASE(
        process.name RLIKE "(?i)(LaZagne|mimikatz|Seatbelt|SharpDPAPI)\\.exe$", "T1003",
        process.name RLIKE "(?i)tscon\\.exe$", "T1563.002",
        ((process.name RLIKE "(?i)mstsc\\.exe$" AND process.command_line LIKE "*/shadow*") OR process.name RLIKE "(?i)shadow\\.exe$"), "T1563.002",
        event.category == "process", "T1563",
        winlog.event_id IN (4728, 4756), "T1098"
    ),
    Details = CASE(
        process.name RLIKE "(?i)(LaZagne|mimikatz|Seatbelt|SharpDPAPI)\\.exe$", CONCAT("Tool executed: ", process.name, ", Command line: ", process.command_line),
        process.name RLIKE "(?i)tscon\\.exe$", CONCAT("tscon.exe executed by SYSTEM with command line: ", process.command_line),
        ((process.name RLIKE "(?i)mstsc\\.exe$" AND process.command_line LIKE "*/shadow*") OR process.name RLIKE "(?i)shadow\\.exe$"), CONCAT("RDP Shadowing tool executed: ", process.name, ", Command line: ", process.command_line),
        event.category == "process", CONCAT("GUI process '", process.name, "' launched by suspicious parent '", process.parent.name, "'"),
        winlog.event_id IN (4728, 4756), CONCAT("User '", winlog.event_data.MemberName, "' added to sensitive group '", winlog.event_data.TargetUserName, "' by '", winlog.event_data.SubjectUserName, "'")
    ),
    DataSource = CASE(
        event.category == "process", "DeviceProcessEvents",
        true, "SecurityEvent"
    ),
    DeviceName = COALESCE(host.name, winlog.computer_name),
    AccountName = COALESCE(user.name, winlog.event_data.SubjectUserName)

-- Normalize field names and select fields for the final output
| KEEP @timestamp, DetectionName, MITRE_TTP, DeviceName, AccountName, Details, DataSource
| RENAME @timestamp AS _time
```