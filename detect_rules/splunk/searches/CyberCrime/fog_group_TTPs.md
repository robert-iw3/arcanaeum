### Fog Ransomware Group Activity Report
---

The Fog ransomware group, active since late 2022, has been observed leveraging compromised SonicWall VPN credentials for initial access and deploying a sophisticated toolkit for reconnaissance, exploitation, lateral movement, and persistence. This affiliate's operations span multiple industries and geographies, utilizing tools like Sliver for C2, AnyDesk for persistence, and various Active Directory exploitation tools to achieve their objectives.

Recent intelligence indicates a shift in Fog ransomware's targeting strategy from specific sectors to opportunistic attacks across all industries, alongside the observed use of legitimate employee monitoring software like Syteca, blurring the lines between cybercrime and espionage. This evolution highlights the group's adaptability and resourcefulness, making their attacks harder to detect with traditional security tools.

### Actionable Threat Data
---

Initial Access via Compromised VPN Credentials (T1133): Monitor for successful VPN logins, especially from unusual geographic locations or at unusual times. Specifically, look for successful authentications to `SonicWall` VPNs that may indicate the use of compromised credentials.

Sliver C2 Framework Usage (T1071.001, T1573.002): Detect Sliver C2 activity by monitoring network traffic for beaconing connections to known `Sliver infrastructure IPs and domains`, or by identifying unusual network communication patterns on common C2 ports (e.g., `TCP/443`, `TCP/8888`, `UDP/51820`). Look for process injection attempts where Sliver implants are injected into legitimate processes.

AnyDesk for Persistence (T1543.003): Monitor for the installation and execution of `AnyDesk`, particularly when initiated by PowerShell scripts or with command-line arguments that configure unattended access or set passwords. Pay attention to AnyDesk installations in unusual directories like `C:\ProgramData\AnyDesk`.

Active Directory Exploitation (T1068, T1558.003, T1649):

Certipy (T1649): Detect Certipy execution by monitoring for command-line arguments related to Active Directory Certificate Services (AD CS) enumeration and abuse (e.g., `certipy find`, `certipy req`). Look for file modifications associated with Certipy's information gathering and exfiltration activities.

Zer0dump (CVE-2020-1472) (T1068): Monitor for successful exploitation of `Zerologon` by looking for anomalous authentication events on Domain Controllers, specifically `4624` events with the DC computer name (ending with $) or `anonymous logon`, `NTLM authentication`, and a `null Logon GUID`.

Pachine/noPac (CVE-2021-42278, CVE-2021-42287) (T1068): Detect `noPac` exploitation by monitoring for changes to `sAMAccountName` attributes, particularly the removal of the trailing $ from computer accounts, and subsequent Kerberos ticket requests for these modified accounts.

Proxychains for Command and Control (T1090): Monitor for the execution of `proxychains` or `proxychains4` commands, especially when used in conjunction with other offensive tools like `certipy`, `noPac.py`, or `zer0dump.py`. This indicates traffic tunneling and obfuscation attempts.

### Sliver C2 Framework Activity: Execution & Network Connections
---
```sql
`comment("
    Sliver C2 Framework Usage

    Detects potential command and control activity associated with the Sliver C2 framework.
    Sliver is a popular open-source C2 framework used by various threat actors, including the Fog ransomware group, for post-exploitation activities.
    This rule detects the execution of known Sliver binaries and network connections to default Sliver ports from suspicious file paths.

    references:
         - https://thedfirreport.com/2025/04/28/navigating-through-the-fog/
         - https://www.cybereason.com/blog/sliver-c2-leveraged-by-many-threat-actors
         - https://blogs.vmware.com/security/2023/01/detection-of-lateral-movement-with-the-sliver-c2-framework.html
    author: Rob Weber
    date: 2025-07-27
    tags:
         - attack.command_and_control
         - attack.t1071.001
         - attack.t1573.002
    falsepositives:
         - The network connection logic may trigger on legitimate applications running from user or temporary directories that communicate over common ports. It is recommended to baseline normal activity and exclude known good applications.
         - The process creation detection is higher fidelity but a threat actor could rename the Sliver binary.
    level: medium

-- This query is designed to work with the Splunk Common Information Model (CIM).
-- It requires endpoint data, typically from an EDR, mapped to the 'Endpoint' data model.
-- If you are not using the CIM, you must adapt the query to your specific data source and field names.
-- For example, for Sysmon, you would use `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` and the relevant EventCodes (1 for process creation, 3 for network connection).
")`

-- Part 1: Detects execution of known Sliver binaries by filename. This is a high-fidelity indicator.
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process LIKE "%\\sliver.exe" OR Processes.process LIKE "%\\sliver-client.exe" OR Processes.process LIKE "%\\sliver-server.exe" OR Processes.process LIKE "%\\slv.bin" OR Processes.process LIKE "%/sliver" OR Processes.process LIKE "%/sliver-client" OR Processes.process LIKE "%/sliver-server" OR Processes.process LIKE "%/slv.bin") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.process_guid
| `drop_dm_object_name("Processes")`
| eval reason="Known Sliver binary name executed"

-- Part 2: Combines results from the process creation search with a search for suspicious network connections.
| append [
    -- This part detects network connections from suspicious/temporary locations to common Sliver C2 ports.
    -- This logic is broader and may have more false positives. Tune by excluding known good applications.
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Network_Traffic where (Network_Traffic.dest_port IN (53, 80, 443, 8080, 8443, 8888, 31337)) AND (Network_Traffic.process_path LIKE "C:\\Users\\%" OR Network_Traffic.process_path LIKE "C:\\ProgramData\\%" OR Network_Traffic.process_path LIKE "C:\\Temp\\%" OR Network_Traffic.process_path LIKE "C:\\Windows\\Temp\\%" OR Network_Traffic.process_path LIKE "C:\\Perflogs\\%" OR Network_Traffic.process_path LIKE "/tmp/%" OR Network_Traffic.process_path LIKE "/var/tmp/%" OR Network_Traffic.process_path LIKE "/dev/shm/%") by Network_Traffic.dest Network_Traffic.user Network_Traffic.process_name Network_Traffic.process_path Network_Traffic.dest_ip Network_Traffic.dest_port
    | `drop_dm_object_name("Network_Traffic")`
    | rename process_path as process
    | eval reason="Network connection from suspicious path to common C2 port", parent_process=null(), process_id=null(), process_guid=null()
]

-- Format and present the final results.
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| table firstTime, lastTime, dest, user, parent_process, process_name, process, dest_ip, dest_port, reason, count
| `sliver_c2_framework_usage_filter`
```

### AnyDesk Persistence Installation via Command-Line Configuration
---
```sql
`comment("
    AnyDesk Persistence Installation

    Detects the installation and configuration of AnyDesk for persistence, often via command-line scripts.
    Threat actors, such as the Fog ransomware group, leverage AnyDesk to maintain access to compromised systems.
    This rule identifies suspicious installation commands, particularly the non-interactive setting of a password and the configuration to start with Windows, which are indicative of malicious use.

    references:
         - https://thedfirreport.com/2025/04/28/navigating-through-the-fog/
    author: Rob Weber
    date: 2025-07-27
    tags:
         - attack.persistence
         - attack.t1219
         - attack.t1543.003

    falsepositives:
         - System administrators may use scripts to legitimately deploy and configure AnyDesk in an enterprise environment.
         - It is recommended to baseline legitimate administrative activity and exclude authorized scripts or user accounts. The path `C:\ProgramData\AnyDesk.exe` is a non-standard installation location and increases the fidelity of the detection.
    level: medium
)
-- This query is designed to work with the Splunk Common Information Model (CIM).
-- It requires endpoint data, typically from an EDR, mapped to the 'Endpoint' data model.
-- If you are not using the CIM, you must adapt the query to your specific data source and field names.
-- For example, for Sysmon, you would use `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` EventCode=1 and the relevant field names (e.g., Image, CommandLine, ParentImage).
")`

| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
-- Filter for AnyDesk.exe process executions.
where (Processes.process_name = "AnyDesk.exe" OR Processes.process LIKE "%\\AnyDesk.exe")
-- Apply the core detection logic based on command-line arguments and context.
  AND (
    -- Detects silent installation with persistence flag.
    -- e.g., C:\ProgramData\AnyDesk.exe --install C:\ProgramData\AnyDesk --start-with-win --silent
    (Processes.process LIKE "%--install%" AND Processes.process LIKE "%--start-with-win%")
    OR
    -- Detects setting a password via command line, combined with other suspicious indicators.
    -- e.g., echo <password> | anydesk.exe --set-password
    (
      Processes.process LIKE "%--set-password%"
      AND (
        -- Parent process is often cmd.exe or powershell.exe for scripting the installation.
        (Processes.parent_process LIKE "%\\cmd.exe" OR Processes.parent_process LIKE "%\\powershell.exe")
        OR
        -- The path used by the threat actor in the provided intel.
        (Processes.process = "C:\\ProgramData\\AnyDesk.exe")
      )
    )
  )
-- Group by relevant fields to provide context for each alert.
by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.process_guid
-- Clean up the field names that are prefixed by the data model object name.
| `drop_dm_object_name("Processes")`
-- Format the timestamps for readability.
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
-- Structure the output into a clear, readable table.
| table firstTime, lastTime, dest, user, parent_process, process_name, process, process_id, process_guid, count
-- This macro can be used for global filtering or suppression of known legitimate administrative activity.
| `anydesk_persistence_installation_filter`
```

### Certipy Execution Detected
---
```sql
`comment("
    Certipy Execution

    Detects the execution of Certipy, a tool used for Active Directory Certificate Services (AD CS) enumeration and abuse.
    Threat actors, such as the Fog ransomware group, use Certipy to find and exploit misconfigurations in AD CS to escalate privileges.

    references:
         - https://thedfirreport.com/2025/04/28/navigating-through-the-fog/
         - https://github.com/ly4k/Certipy
    author: Rob Weber
    date: 2025-07-27
    tags:
         - attack.credential_access
         - attack.t1649
         - attack.discovery
    falsepositives:
         - Legitimate use by red teams or security administrators for auditing AD CS configurations. It is recommended to baseline and exclude authorized user accounts or hosts.
    level: high
)
-- This query is designed to work with the Splunk Common Information Model (CIM).
-- It requires endpoint data, typically from an EDR, mapped to the 'Endpoint' data model.
-- If you are not using the CIM, you must adapt the query to your specific data source and field names.
-- For example, for Sysmon, you would use `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` EventCode=1 and the relevant field names (e.g., CommandLine).
")`

| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
-- Filter for process command lines containing 'certipy'
where Processes.process LIKE "%certipy%"
-- Further filter for command lines that also contain specific Certipy actions.
-- The spaces around the keywords help reduce false positives from other tools or scripts that might contain these substrings.
  AND (
    Processes.process LIKE "% find %"
    OR Processes.process LIKE "% req %"
    OR Processes.process LIKE "% auth %"
    OR Processes.process LIKE "% shadow %"
    OR Processes.process LIKE "% backup %"
    OR Processes.process LIKE "% restore %"
    OR Processes.process LIKE "% ca %"
    OR Processes.process LIKE "% account %"
  )
-- Group by relevant fields to provide context for each alert.
by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.process_guid
-- Clean up the field names that are prefixed by the data model object name.
| `drop_dm_object_name("Processes")`
-- Format the timestamps for readability.
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
-- Structure the output into a clear, readable table.
| table firstTime, lastTime, dest, user, parent_process, process_name, process, process_id, process_guid, count
-- This macro can be used for global filtering or suppression of known legitimate activity (e.g., by authorized red team hosts or users).
| `certipy_execution_filter`
```

### Zer0dump (Zerologon) Exploitation Attempt Detected
---
```sql
`comment("
    Zer0dump (Zerologon) Exploitation

    Detects signs of Zerologon (CVE-2020-1472) exploitation, a vulnerability that allows an attacker to gain domain administrator privileges.
    This detection looks for a specific pattern in Windows Security Event ID 4624 on Domain Controllers, where a successful logon occurs for the DC's machine account or an anonymous user via NTLM with a null Logon GUID.
    The Fog ransomware group has been observed using the Zer0dump tool to exploit this vulnerability.

    references:
         - https://thedfirreport.com/2025/04/28/navigating-through-the-fog/
         - https://www.secura.com/blog/zero-logon
         - https://github.com/bb00/zer0dump
    author: Rob Weber
    date: 2025-07-27
    tags:
         - attack.privilege_escalation
         - attack.t1068
         - cve.2020-1472
    falsepositives:
         - This specific combination of event properties is highly indicative of Zerologon exploitation and is not expected to occur during normal operations. False positives are highly unlikely.
         - It is recommended to scope this detection to run only on Domain Controllers.
    level: critical
")`

-- This query is designed to work with Windows Security event logs.
-- It is highly recommended to scope this search to your Domain Controller hosts for performance and accuracy (e.g., by specifying an index or host filter).
`wineventlog_security` EventCode=4624 AuthenticationPackageName="NTLM" LogonGuid="{00000000-0000-0000-0000-000000000000}"
-- The exploit results in a logon from the DC's own machine account (ending in '$') or ANONYMOUS LOGON.
| where (mvcount(split(TargetUserName, "$")) > 1 AND TargetUserName!="ANONYMOUS LOGON") OR (TargetUserName="ANONYMOUS LOGON")
-- Aggregate events to reduce noise and provide a summary of the activity.
| stats count min(_time) as firstTime max(_time) as lastTime by host, TargetUserName, IpAddress, AuthenticationPackageName, LogonGuid
-- Format the timestamps for readability.
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
-- Rename fields for clarity in the final output.
| rename host as TargetDc, TargetUserName as LogonAccount, IpAddress as SourceIp
-- Structure the output into a clear, readable table.
| table firstTime, lastTime, TargetDc, LogonAccount, SourceIp, AuthenticationPackageName, LogonGuid, count
-- This macro can be used for global filtering or suppression if any unexpected false positives arise.
| `zerodump_exploitation_filter`
```

### Pachine/noPac Exploitation: Detects Computer Account sAMAccountName Modification
---
```sql
`comment("
    Pachine/noPac Exploitation

    Detects the modification of a computer account's sAMAccountName to remove the trailing '$'.
    This is a key step in exploiting CVE-2021-42278 and CVE-2021-42287, which allows for privilege escalation to Domain Administrator.
    Threat actors, like the Fog ransomware group, use tools such as Pachine and noPac to automate this attack.
    The attack involves renaming a computer account, requesting a Kerberos ticket for the renamed account, and then using that ticket to impersonate a Domain Controller.

    references:
         - https://thedfirreport.com/2025/04/28/navigating-through-the-fog/
         - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278
         - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287
    author: Rob Weber
    date: 2025-07-27
    tags:
         - attack.privilege_escalation
         - attack.t1068
         - cve.2021.42278
         - cve.2021.42287
    falsepositives:
         - False positives are highly unlikely, as renaming a computer account to not have a trailing '$' is not a standard administrative practice and is a strong indicator of this specific attack.
    level: critical
")`

-- This detection requires "Audit Directory Service Changes" to be enabled on Domain Controllers.
-- It is highly recommended to scope this search to your Domain Controller hosts for performance and accuracy.
`wineventlog_security` EventCode=5136 ObjectClass=computer AttributeLDAPDisplayName=sAMAccountName
-- This is the core detection logic. It triggers when the new sAMAccountName value does NOT end with a '$'.
| where NOT like(AttributeValue, "%$")
-- Grouping events to provide a summary of the activity.
| stats count min(_time) as firstTime max(_time) as lastTime values(AttributeValue) as new_sAMAccountName by host, SubjectUserName, ObjectDN, ObjectClass, AttributeLDAPDisplayName
-- Formatting the timestamps for readability.
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
-- Renaming fields for clarity in the final output.
| rename host as DomainController, SubjectUserName as Actor, ObjectDN as ModifiedComputerObject
-- Structuring the output into a clear, readable table.
| table firstTime, lastTime, DomainController, Actor, ModifiedComputerObject, new_sAMAccountName, count
-- This macro can be used for global filtering or suppression if any unexpected false positives arise.
| `pachine_nopac_exploitation_filter`
```

### Proxychains Execution with Offensive Security Tools
---
```sql
`comment("
    Proxychains for C2

    Detects the execution of Proxychains, a tool used to force any TCP connection made by a given application to follow through a proxy.
    Threat actors, like the Fog ransomware group, use Proxychains to tunnel traffic from their attack infrastructure into a compromised network, often in conjunction with other offensive security tools.
    references:
         - https://thedfirreport.com/2025/04/28/navigating-through-the-fog/
    author: Rob Weber
    date: 2025-07-27
    tags:
         - attack.command_and_control
         - attack.t1090
    falsepositives:
         - Legitimate use by penetration testers, red teams, or system administrators for network testing or routing traffic through specific proxies.
         - Consider excluding known administrative or security testing machines if this activity is expected.
    level: high
")`

-- This query requires process creation logs from Linux systems (e.g., Sysmon for Linux, Auditd, Falco).
-- The macro `linux_process_creation` should be defined to specify the correct index and sourcetype.
`linux_process_creation`
-- Detects the execution of proxychains or proxychains4 by process name or command line.
(
    (process_name IN ("proxychains", "proxychains4"))
    OR
    (process="*proxychains *" OR process="*proxychains4 *")
)
-- Looks for common offensive tools being run through proxychains.
AND
(
    process="* certipy*" OR
    process="* noPac.py*" OR
    process="* zer0dump.py*" OR
    process="* pachine.py*" OR
    process="* nxc *" OR
    process="* dpapi.py*"
)
-- Aggregate results to provide a summary of the activity.
| stats count min(_time) as firstTime max(_time) as lastTime by host, user, parent_process, process_name, process
-- Format the timestamps for readability.
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S")
| eval lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
-- Rename fields for clarity in the final output.
| rename host as Host, user as User, parent_process as ParentProcess, process_name as ProcessName, process as CommandLine
-- Structure the output into a clear, readable table.
| table firstTime, lastTime, Host, User, ParentProcess, ProcessName, CommandLine, count
-- This macro can be used for global filtering or suppression.
-- For example, `| search NOT (Host IN (known_pentest_box1, known_admin_box1))` to reduce false positives from legitimate activity.
| `proxychains_for_c2_filter`
```