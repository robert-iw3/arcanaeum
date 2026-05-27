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

-- Rule: Uses ProcessRollup2 for process-based detections and SecurityEvent for group membership changes. Filters for OT assets (e.g., via ComputerName regex) and excludes authorized accounts. Optimizes with regex for command lines and efficient event filtering.
(
-- Part 1: Process-based Detections
event_platform=Win event_simpleName=ProcessRollup2 (
-- Detection for credential harvesting tools execution
(ImageFileName:/(LaZagne|mimikatz|Seatbelt|SharpDPAPI).exe$/i
| eval DetectionName="Credential Harvesting Tool Execution" MITRE_TTP="T1003" Details="Tool executed: " + ImageFileName + ", Command line: " + CommandLine) OR
-- Detection for RDP session hijacking via tscon.exe
(ImageFileName=/tscon.exe$/i CommandLine:/\s(\d+|/dest:\w+)/i SID="S-1-5-18"
| eval DetectionName="RDP Session Hijacking via tscon.exe" MITRE_TTP="T1563.002" Details="tscon.exe executed by SYSTEM with command line: " + CommandLine) OR
-- Detection for RDP shadowing activity
((ImageFileName=/mstsc.exe$/i CommandLine://shadow/i OR ImageFileName=/shadow.exe$/i) (CommandLine://noConsentPrompt/i OR CommandLine://control/i)
| eval DetectionName="RDP Shadowing Activity" MITRE_TTP="T1563.002" Details="RDP Shadowing tool executed: " + ImageFileName + ", Command line: " + CommandLine) OR
-- Detection for Hidden Desktop (hVNC) abuse
(ImageFileName:/(explorer|iexplore|chrome|firefox|msedge|winword|excel|powerpnt|outlook|mstsc|cmd|powershell).exe$/i (ParentBaseFileName:/(services|svchost|lsass|wininit|wmiprvse|wmiadap).exe$/i OR SID="S-1-5-18")
| eval DetectionName="Hidden Desktop (hVNC) Abuse" MITRE_TTP="T1563" Details="GUI process '" + ImageFileName + "' launched by suspicious parent '" + ParentBaseFileName + "'")) +ComputerName:/(PLC|RTU|GRID)/i !LocalUserName IN ("redteam_user1", "helpdesk_admin1", "authorized_support_group")
| eval DataSource="DeviceProcessEvents"
| append [
        -- Part 2: Group Membership Detection
        event_platform=Win event_simpleName=SecurityEvent (EventCode IN (4728, 4756)) TargetAccountName="OT Remote Access Users" !SubjectUserName IN ("authorized_admin1", "IDM_service_account$")
        | eval DetectionName="Group Membership Modification to Sensitive OT Group" MITRE_TTP="T1098" Details="User '" + MemberName + "' added to sensitive group '" + TargetAccountName + "' by '" + SubjectUserName + "'" DataSource="SecurityEvent"
    ]
)
| stats min(@timestamp) as _time values(DetectionName) as DetectionName values(MITRE_TTP) as MITRE_TTP values(Details) as Details values(DataSource) as DataSource by ComputerName LocalUserName
| rename ComputerName as DeviceName LocalUserName as AccountName
| table _time DetectionName MITRE_TTP DeviceName AccountName Details DataSource
-- Potential False Positives:
-- Legitimate use of tools like mimikatz by security teams, authorized RDP shadowing for support, or benign GUI processes launched by system services.
-- Group membership changes by unlisted admin accounts or identity management systems.
```