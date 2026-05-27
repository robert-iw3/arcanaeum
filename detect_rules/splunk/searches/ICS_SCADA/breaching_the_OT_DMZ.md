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

-- Part 1: Process-based Detections
-- This search leverages CIM-compliant field names for process creation events (e.g., from Sysmon or EDR).
-- Replace `cim_process_creation_datamodel` with your data source, e.g., `(index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1)`
`cim_process_creation_datamodel`

-- Combine all process-based detection logic into a single where clause for efficiency
| where
    -- Detection for credential harvesting tools execution
    (match(process_name, "(?i)(LaZagne|mimikatz|Seatbelt|SharpDPAPI)\.exe$")) OR
    -- Detection for RDP session hijacking via tscon.exe
    (match(process_name, "(?i)tscon\.exe$") AND match(process, "\s(\d+|/dest:\w+)") AND user_id="S-1-5-18") OR
    -- Detection for RDP shadowing activity
    ((match(process_name, "(?i)mstsc\.exe$") AND like(process, "%/shadow%")) OR match(process_name, "(?i)shadow\.exe$")) AND (like(process, "%/noConsentPrompt%") OR like(process, "%/control%")) OR
    -- Detection for Hidden Desktop (hVNC) abuse
    (match(process_name, "(?i)(explorer|iexplore|chrome|firefox|msedge|winword|excel|powerpnt|outlook|mstsc|cmd|powershell)\.exe$") AND (match(parent_process_name, "(?i)(services|svchost|lsass|wininit|wmiprvse|wmiadap)\.exe$") OR user_id="S-1-5-18"))

-- FP Mitigation: Exclude known legitimate activity for any of the above detections.
-- Example: | search NOT (user IN ("redteam_user1", "helpdesk_admin1", "authorized_support_group"))

-- Use case statements to assign detection-specific details
| eval
    DetectionName=case(
        match(process_name, "(?i)(LaZagne|mimikatz|Seatbelt|SharpDPAPI)\.exe$"), "Credential Harvesting Tool Execution",
        match(process_name, "(?i)tscon\.exe$"), "RDP Session Hijacking via tscon.exe",
        (match(process_name, "(?i)mstsc\.exe$") AND like(process, "%/shadow%")) OR match(process_name, "(?i)shadow\.exe$"), "RDP Shadowing Activity",
        1=1, "Hidden Desktop (hVNC) Abuse"
    ),
    MITRE_TTP=case(
        match(process_name, "(?i)(LaZagne|mimikatz|Seatbelt|SharpDPAPI)\.exe$"), "T1003",
        match(process_name, "(?i)tscon\.exe$"), "T1563.002",
        (match(process_name, "(?i)mstsc\.exe$") AND like(process, "%/shadow%")) OR match(process_name, "(?i)shadow\.exe$"), "T1563.002",
        1=1, "T1563"
    ),
    Details=case(
        match(process_name, "(?i)(LaZagne|mimikatz|Seatbelt|SharpDPAPI)\.exe$"), "Tool executed: " + process_name + ", Command line: " + process,
        match(process_name, "(?i)tscon\.exe$"), "tscon.exe executed by SYSTEM with command line: " + process,
        (match(process_name, "(?i)mstsc\.exe$") AND like(process, "%/shadow%")) OR match(process_name, "(?i)shadow\.exe$"), "RDP Shadowing tool executed: " + process_name + ", Command line: " + process,
        1=1, "GUI process '" + process_name + "' launched by suspicious parent '" + parent_process_name + "'"
    ),
    DataSource="DeviceProcessEvents"

-- Normalize field names and select fields for the final output
| rename dest as DeviceName, user as AccountName
| fields _time, DetectionName, MITRE_TTP, DeviceName, AccountName, Details, DataSource

-- Part 2: Group Membership Detection
| append [
    -- This search leverages Windows Security event logs.
    -- Replace `windows_security_datamodel` with your data source, e.g., `(index=wineventlog sourcetype=WinEventLog:Security)`
    `windows_security_datamodel`
    (EventCode=4728 OR EventCode=4756) TargetUserName="OT Remote Access Users"

    -- FP Mitigation: Exclude changes made by authorized admin or identity management service accounts.
    -- Example: | search NOT (SubjectUserName IN ("authorized_admin1", "IDM_service_account$"))

    -- Create the standard set of fields for this detection
    | eval
        DetectionName="Group Membership Modification to Sensitive OT Group",
        MITRE_TTP="T1098",
        Details="User '" + MemberName + "' added to sensitive group '" + TargetUserName + "' by '" + SubjectUserName + "'",
        DataSource="SecurityEvent"

    -- Normalize field names and select fields for the final output
    | rename Computer as DeviceName, SubjectUserName as AccountName
    | fields _time, DetectionName, MITRE_TTP, DeviceName, AccountName, Details, DataSource
]
```