### UAT-7237 Threat Report
---

UAT-7237 is a Chinese-speaking APT group that targets web hosting infrastructure in Taiwan, focusing on establishing long-term persistence. They heavily utilize customized open-source tooling and living-off-the-land binaries (LOLBins) to evade detection and achieve their objectives.

UAT-7237, while a subgroup of UAT-5918, distinguishes itself by primarily relying on Cobalt Strike for backdoor access and selectively deploying web shells, contrasting with UAT-5918's use of Meterpreter and widespread web shell deployment. This shift indicates an evolution towards more targeted and potentially stealthier post-compromise operations.

### Actionable Threat Data
---

Monitor for the execution of cmd.exe with arguments related to system information (systeminfo, tasklist, net1 user /domain, whoami /priv, quser), network configuration (ipconfig /all, netstat -ano), and external connectivity checks (ping 8.8.8.8, curl).

Detect the download of remote files using cmd.exe or powershell from suspicious URLs, especially those involving win-x64.rar or vpn.rar to C:\temp\WM7Lite\ or C:\Windows\Temp\vmware-SYSTEM\.

Look for WMI-based tooling execution, specifically SharpWMI.exe and WMICmd.exe, and wmic commands used for remote process creation or command execution.

Identify attempts to modify registry keys related to UAC (HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy) or cleartext password storage (HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential).

Monitor for the execution of SoundBill (VTSB.exe) or Project1.exe (ssp_dump_lsass tool) for credential dumping, particularly when combined with arguments like privilege::debug sekurlsa::logonpasswords exit or SSP.dll.

### Suspicious Reconnaissance Commands
---
```sql
-- Description: Detects a pattern of multiple distinct reconnaissance command types being executed via the command prompt (cmd.exe) in a short period. This behavior is consistent with the initial discovery phase of intrusions by the UAT-7237 threat actor.
-- False Positive Sensitivity: Medium
-- MITRE TTPs: T1082, T1016, T1033, T1049, T1057

`tstats` count from datamodel=Endpoint.Processes where (Processes.parent_process_name=cmd.exe) by _time, Processes.process_name, Processes.process, Processes.dest, Processes.user, Processes.parent_process_id span=15m
| `drop_dm_object_name("Processes")`

-- Categorize known reconnaissance commands into tactical groups.
| eval tactic=case(
    process_name="systeminfo.exe", "System Information Discovery",
    process_name="tasklist.exe", "Process Discovery",
    process_name="ipconfig.exe", "Network Configuration Discovery",
    process_name="netstat.exe", "Network Connection Discovery",
    process_name IN ("net.exe", "net1.exe"), "Account Discovery",
    process_name IN ("whoami.exe", "quser.exe"), "User Discovery",
    process_name IN ("ping.exe", "curl.exe", "nslookup.exe"), "Network Service Discovery"
  )
| where isnotnull(tactic)

-- Group events by host, user, and the parent cmd.exe process ID.
| stats dc(tactic) as distinct_tactic_count, values(process) as recon_commands, min(_time) as start_time, max(_time) as end_time by dest, user, parent_process_id

-- Alert when 3 or more distinct types of reconnaissance are observed.
-- This threshold is tunable. Legitimate admin activity might occasionally trigger this.
-- Consider adding user/host allowlists if this proves to be noisy in your environment.
| where distinct_tactic_count > 2

-- Format the output for readability.
| convert ctime(start_time) ctime(end_time)
| fields - _time
```

### Remote File Download via CMD/PS
---
```sql
-- Description: Detects command prompt or PowerShell being used to initiate the download of files with names or to paths associated with UAT-7237 activity.
-- False Positive Sensitivity: Medium
-- MITRE TTPs: T1105, T1573

-- Start with the Endpoint data model, focusing on process events.
from datamodel=Endpoint.Processes

-- Filter for events where either the process itself or its parent is cmd.exe or powershell.exe.
-- This covers both inline downloads (e.g., PowerShell) and commands launching a separate download tool.
| where (Processes.process_name IN ("cmd.exe", "powershell.exe") OR Processes.parent_process_name IN ("cmd.exe", "powershell.exe"))

-- Look for command lines containing keywords or paths specific to UAT-7237 TTPs.
-- The wildcards help match the strings regardless of their position in the command line.
-- Note: The paths or filenames could be used by legitimate tools. Review any alerts for context.
| where `cim_to_spl_case("Processes.process", "lower")` IN (
    "*win-x64.rar*",
    "*vpn.rar*",
    "*c:\\temp\\wm7lite\\*",
    "*c:\\windows\\temp\\vmware-system\\*"
)

-- Format the results for analysis.
| `drop_dm_object_name("Processes")`
| table _time, dest, user, parent_process_name, parent_process, process_name, process
```

### WMI Tooling Execution
---
```sql
-- Description: Detects the execution of WMI-based tooling for remote command execution and reconnaissance, a technique leveraged by UAT-7237.
-- False Positive Sensitivity: Medium
-- MITRE TTPs: T1047, T1021.006

from datamodel=Endpoint.Processes
| where `cim_to_spl_case(
    # Detects known WMI tools by filename.
    (Processes.process_name IN ("SharpWMI.exe", "WMICmd.exe"))
    OR
    # Detects the native wmic.exe used for remote process creation.
    # This is a common administrative activity, so it's filtered for specific remote execution patterns.
    (
        Processes.process_name = "wmic.exe" AND
        Processes.process LIKE "%/node:%" AND
        Processes.process LIKE "%process%" AND
        Processes.process LIKE "%call%" AND
        Processes.process LIKE "%create%"
    )
, "lower")`

-- Note: Legitimate remote administration using wmic.exe may trigger this rule.
-- Consider adding allowlists for specific source/destination hosts or administrative user accounts if this proves to be noisy.
| `drop_dm_object_name("Processes")`
| table _time, dest, user, parent_process_name, process_name, process
```

### Registry Key Modification
---
```sql
-- Description: Detects attempts to modify specific registry keys to weaken security controls, a technique used by UAT-7237. This includes disabling UAC remote restrictions and enabling WDigest to store credentials in cleartext.
-- False Positive Sensitivity: Medium
-- MITRE TTPs: T1112, T1547.001

-- Start with the Registry data model, which contains registry modification events.
from datamodel=Endpoint.Registry

-- Filter for the specific registry modifications associated with UAC and WDigest weakening.
| where (
    -- Detects disabling of UAC remote restrictions (enables pass-the-hash for local accounts).
    (Registry.registry_path="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\system" AND Registry.registry_value_name="LocalAccountTokenFilterPolicy" AND Registry.registry_value_data="1")
    OR
    -- Detects enabling of WDigest cleartext credential caching.
    (Registry.registry_path="*\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" AND Registry.registry_value_name="UseLogonCredential" AND Registry.registry_value_data="1")
  )
-- Filter for common processes used to make these changes to reduce potential noise.
| search Registry.process_name IN ("reg.exe", "cmd.exe", "powershell.exe")

-- Note: While these changes are highly suspicious, they may be performed by administrators in specific scenarios.
-- Review the user context and justification for any alerts.
| `drop_dm_object_name("Registry")`
| table _time, dest, user, process_name, process, registry_path, registry_value_name, registry_value_data
```

### Credential Dumping Tool Execution
---
```sql
-- Description: Detects the execution of specific credential dumping tools, SoundBill (VTSB.exe) and Project1.exe, used by the UAT-7237 threat actor.
-- False Positive Sensitivity: Medium
-- MITRE TTPs: T1003, T1003.001, T1003.002, T1003.003, T1003.004, T1003.005, T1003.006

-- Start with process execution events from the Endpoint data model.
from datamodel=Endpoint.Processes

-- Filter for the specific tool executions based on process name and command-line arguments.
| where `cim_to_spl_case(
    -- Detects SoundBill (VTSB.exe) used with Mimikatz commands for credential dumping.
    (Processes.process_name="VTSB.exe" AND Processes.process LIKE "%privilege::debug%" AND Processes.process LIKE "%sekurlsa::logonpasswords%")
    OR
    -- Detects the ssp_dump_lsass tool (Project1.exe) used to inject a DLL for dumping LSASS.
    (Processes.process_name="Project1.exe" AND Processes.process LIKE "%SSP.dll%")
    OR
    -- Broader detection for the tool names alone, as they are specific to this threat.
    (Processes.process_name IN ("VTSB.exe", "Project1.exe"))
, "lower")`

-- Note: The filenames VTSB.exe and Project1.exe are specific but could be renamed by the actor.
-- This detection focuses on the known filenames and command line patterns from the report.
-- If false positives occur, consider making the command-line checks more strict.

-- Format the output for analysis.
| `drop_dm_object_name("Processes")`
| table _time, dest, user, parent_process_name, process_name, process
```

### IOC's
---
```sql
-- Description: Detects various Indicators of Compromise (IOCs) associated with UAT-7237 activity, including file hashes, IP addresses, domains, and URLs.
-- False Positive Sensitivity: Medium
-- MITRE TTPs: T1105, T1071.001, T1204.002

-- This query leverages the Splunk Common Information Model (CIM) for broader compatibility. It requires the Endpoint and Network_Traffic data models to be populated, typically by EDR and network data sources like Sysmon or Microsoft Defender for Endpoint.

| tstats `comment("Search for process execution events matching the known malicious hashes.")` summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_hash IN (
    "df8497b9c37b780d6b6904a24133131faed8ea4cf3d75830b53c25d41c5ea386",
    "0952e5409f39824b8a630881d585030a1d656db897adf228ce27dd9243db20b7",
    "7a5f05da3739ad3e11414672d01b8bcf23503a9a8f1dd3f10ba2ead7745cdb1f",
    "450fa9029c59af9edf2126df1d6a657ee6eb024d0341b32e6f6bdb8dc04bae5a",
    "6a72e4b92d6a459fc2c6054e9ddb9819d04ed362bd847333492410b6d7bae5aa",
    "e106716a660c751e37cfc4f4fbf2ea2f833e92c2a49a0b3f40fc36ad77e0a044",
    "b52bf5a644ae96807e6d846b0ce203611d83cc8a782badc68ac46c9616649477",
    "864e67f76ad0ce6d4cc83304af4347384c364ca6735df0797e4b1ff9519689c5"
) by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_hash _time
| `drop_dm_object_name("Processes")`
| rename dest as DeviceName, user as AccountName, process_name as FileName, process as ProcessCommandLine, process_hash as Indicator
| eval EventType="File/Process IOC", IndicatorType="FileHash", RemoteUrl="", RemoteIP=""
| fields _time, DeviceName, AccountName, EventType, Indicator, IndicatorType, FileName, ProcessCommandLine, RemoteUrl, RemoteIP

| append [
    | tstats `comment("Search for network connections to the known malicious IP, domain, or URL.")` summariesonly=true count from datamodel=Endpoint.Network_Traffic where (Network_Traffic.dest_ip="141.164.50.141" OR Network_Traffic.url="*cvbbonwxtgvc3isfqfc52cwzja0kvuqd.lambda-url.ap-northeast-1.on.aws*" OR Network_Traffic.url="http://141.164.50.141/sdksdk608/win-x64.rar") by Network_Traffic.dest Network_Traffic.user Network_Traffic.process_name Network_Traffic.process Network_Traffic.dest_ip Network_Traffic.url _time
    | `drop_dm_object_name("Network_Traffic")`
    | rename dest as DeviceName, user as AccountName, process_name as FileName, process as ProcessCommandLine, dest_ip as RemoteIP, url as RemoteUrl
    | `comment("Identify which network indicator triggered the alert.")`
    | eval EventType="Network IOC",
        Indicator=case(
            RemoteIP=="141.164.50.141", "141.164.50.141",
            like(RemoteUrl, "%cvbbonwxtgvc3isfqfc52cwzja0kvuqd.lambda-url.ap-northeast-1.on.aws%"), "cvbbonwxtgvc3isfqfc52cwzja0kvuqd.lambda-url.ap-northeast-1.on.aws",
            RemoteUrl=="http://141.164.50.141/sdksdk608/win-x64.rar", "http://141.164.50.141/sdksdk608/win-x64.rar"
        ),
        IndicatorType=case(
            isnotnull(Indicator) AND RemoteIP==Indicator, "IP Address",
            isnotnull(Indicator) AND like(RemoteUrl, "%"+Indicator+"%"), "Domain",
            isnotnull(Indicator) AND RemoteUrl==Indicator, "URL"
        )
    | `comment("Note: The IP address IOC is high-fidelity but may become a false positive if re-assigned by the provider.")`
    | fields _time, DeviceName, AccountName, EventType, Indicator, IndicatorType, FileName, ProcessCommandLine, RemoteUrl, RemoteIP
]
| fillnull value="-"
```