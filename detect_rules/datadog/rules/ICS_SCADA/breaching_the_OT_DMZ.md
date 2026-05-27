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

-- Purpose: Detects credential harvesting (T1003), RDP session hijacking and shadowing (T1563, T1563.002), hidden desktop (hVNC) abuse (T1563), and group membership modifications (T1098) in OT DMZ environments.
-- Data Sources: Endpoint logs (Sysmon or EDR) for process-based detections and Windows Security logs for group membership changes.
-- False Positive Sensitivity: Medium, mitigated by filtering for critical OT assets and excluding authorized accounts.

-- Part 1: Process-based Detections (Credential Harvesting, RDP Abuse, hVNC)
logs(
  source:endpoint
  @host:(jumpserver* OR hmi* OR ews* OR historian*)
  (
    -- Detection for credential harvesting tools
    process.name:(LaZagne.exe OR mimikatz.exe OR Seatbelt.exe OR SharpDPAPI.exe) OR
    -- Detection for RDP session hijacking via tscon.exe
    (process.name:tscon.exe (*\d+ OR /dest:*) @user:S-1-5-18) OR
    -- Detection for RDP shadowing activity
    ((process.name:mstsc.exe */shadow*) OR process.name:shadow.exe) (*noConsentPrompt* OR *control*) OR
    -- Detection for Hidden Desktop (hVNC) abuse
    (
      process.name:(explorer.exe OR iexplore.exe OR chrome.exe OR firefox.exe OR msedge.exe OR winword.exe OR excel.exe OR powerpnt.exe OR outlook.exe OR mstsc.exe OR cmd.exe OR powershell.exe)
      (
        process.parent.name:(services.exe OR svchost.exe OR lsass.exe OR wininit.exe OR wmiprvse.exe OR wmiadap.exe) OR
        @user:S-1-5-18
      )
    )
  )
  -- FP Mitigation: Exclude known legitimate users or processes
  -@user:(redteam_user1 OR helpdesk_admin1 OR authorized_support_group)
)
| group by @host, @user, process.name, process.command_line, process.parent.name
| select
    @timestamp as Time,
    @host as DeviceName,
    @user as AccountName,
    process.name as ProcessName,
    process.command_line as ProcessCommandLine,
    process.parent.name as ParentProcessName,
    case(
      process.name:(LaZagne.exe OR mimikatz.exe OR Seatbelt.exe OR SharpDPAPI.exe) => "Credential Harvesting Tool Execution",
      process.name:tscon.exe => "RDP Session Hijacking via tscon.exe",
      (process.name:mstsc.exe OR process.name:shadow.exe) => "RDP Shadowing Activity",
      true => "Hidden Desktop (hVNC) Abuse"
    ) as DetectionName,
    case(
      process.name:(LaZagne.exe OR mimikatz.exe OR Seatbelt.exe OR SharpDPAPI.exe) => "T1003",
      process.name:tscon.exe => "T1563.002",
      (process.name:mstsc.exe OR process.name:shadow.exe) => "T1563.002",
      true => "T1563"
    ) as MITRE_TTP,
    case(
      process.name:(LaZagne.exe OR mimikatz.exe OR Seatbelt.exe OR SharpDPAPI.exe) => "Tool executed: " + process.name + ", Command line: " + process.command_line,
      process.name:tscon.exe => "tscon.exe executed by SYSTEM with command line: " + process.command_line,
      (process.name:mstsc.exe OR process.name:shadow.exe) => "RDP Shadowing tool executed: " + process.name + ", Command line: " + process.command_line,
      true => "GUI process '" + process.name + "' launched by suspicious parent '" + process.parent.name + "'"
    ) as Details,
    "DeviceProcessEvents" as DataSource
| display Time, DetectionName, MITRE_TTP, DeviceName, AccountName, Details, DataSource

-- Part 2: Group Membership Detection
| union(
  logs(
    source:windows
    event.code:(4728 OR 4756)
    event.target_user_name:"OT Remote Access Users"
    @host:(jumpserver* OR hmi* OR ews* OR historian*)
    -- FP Mitigation: Exclude authorized admin accounts
    -event.subject_user_name:(authorized_admin1 OR IDM_service_account$)
  )
  | group by @host, event.subject_user_name, event.member_name, event.target_user_name
  | select
      @timestamp as Time,
      @host as DeviceName,
      event.subject_user_name as AccountName,
      "Group Membership Modification to Sensitive OT Group" as DetectionName,
      "T1098" as MITRE_TTP,
      "User '" + event.member_name + "' added to sensitive group '" + event.target_user_name + "' by '" + event.subject_user_name + "'" as Details,
      "SecurityEvent" as DataSource
)
| display Time, DetectionName, MITRE_TTP, DeviceName, AccountName, Details, DataSource
```