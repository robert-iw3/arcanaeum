### HijackLoader Threat Report
---

HijackLoader is a modular malware loader that has continuously evolved its evasion techniques, including the use of steganography with PNG images for payload delivery and advanced anti-analysis modules. It is primarily used to deliver various second-stage malware families, with Amadey being the most prevalent.

Recent updates to HijackLoader include new modules for call stack spoofing (T1055.012), anti-VM checks (T1497.001), and persistence via scheduled tasks (T1053.005), significantly enhancing its stealth and resilience against detection. Additionally, recent campaigns have observed HijackLoader delivering the DeerStealer payload, a new information stealer with extensive data theft capabilities.

### Actionable Threat Data
---

Monitor for the creation of new scheduled tasks (T1053.005) that could indicate persistence mechanisms established by HijackLoader's `modTask` or `modTask64` modules.

Detect process hollowing (T1055.012) and other process injection techniques (T1055) where legitimate processes like `cmd.exe` or `mshtml.dll` are used to host or execute malicious code.

Look for PowerShell commands (T1059.001) that attempt to add exclusions for Windows Defender Antivirus (T1562.001), as this is a known capability of HijackLoader's `WDDATA` module.

Identify attempts to bypass User Account Control (UAC) (T1548.002) using techniques like the `CMSTPLUA` COM interface, which HijackLoader's `modUAC` module leverages.

Monitor for network connections to `apache.org/logos/res/incubator/default.png` (T1071.001) as HijackLoader uses this URL to check for internet connectivity.

### Suspicious Process Creation in Suspended State (Process Hollowing)
---
```sql
`comment("

Suspicious Process Creation in Suspended State

Detects the creation of legitimate Windows processes in a suspended state, a technique often used for process hollowing. HijackLoader was observed using this technique to inject its payload into processes like cmd.exe.

tags:
   - attack.t1055.012
   - attack.execution

falsepositives:
   - Some legitimate software installers, updaters, or security products may create processes in a suspended state for legitimate reasons. Tuning may be required based on the environment by adding legitimate parent processes to the filter.

level: medium

")`

# TUNE sourcetype and index as per your environment. This query assumes Sysmon (EventCode=1) or a similar EDR data source.
(sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational OR sourcetype=sysmon) EventCode=1
# The CreationFlags field in Sysmon (Event ID 1) logs contains 0x00000004 (or 0x4) when a process is created in a suspended state.
CreationFlags="0x4"
# selection of commonly abused legitimate processes
(Image="*\\cmd.exe" OR Image="*\\svchost.exe" OR Image="*\\explorer.exe" OR Image="*\\runtimebroker.exe" OR Image="*\\mshta.exe" OR Image="*\\regsvr32.exe")
# Filter for known legitimate software that might create suspended processes. This list may need to be tuned.
NOT (ParentImage IN ("*\\MsMpEng.exe", "*\\SgrmBroker.exe", "*\\procexp64.exe", "*\\procexp.exe", "*\\procmon.exe", "*\\procmon64.exe"))
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, ParentImage, Image, CommandLine, ProcessId, ParentProcessId, CreationFlags
| rename Computer as host
| convert ctime(firstTime) ctime(lastTime)
```

### Windows Defender Exclusion
---
```sql
`comment("

PowerShell Adding Windows Defender Exclusion

Detects PowerShell being used to add an exclusion to Windows Defender Antivirus. This technique is often used by malware, such as HijackLoader, to prevent detection of its components or activities.

tags:
   - attack.t1562.001
   - attack.t1059.001
   - attack.defense_evasion

falsepositives:
   - Legitimate administrative scripts may add exclusions for performance reasons or to prevent conflicts with legitimate applications. Review the excluded path/process and the parent process to determine legitimacy.

level: medium
")`

# TUNE sourcetype and index as per your environment. This query assumes Sysmon (EventCode=1) or a similar EDR data source.
(sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational OR sourcetype=sysmon) EventCode=1
# Look for PowerShell execution
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
# Detect the use of the Add-MpPreference cmdlet with exclusion parameters
CommandLine="*Add-MpPreference*" (CommandLine="*-ExclusionPath*" OR CommandLine="*-ExclusionProcess*" OR CommandLine="*-ExclusionExtension*")
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, ParentImage, Image, CommandLine, ProcessId, ParentProcessId
| rename Computer as host
| convert ctime(firstTime) ctime(lastTime)
```

### UAC Bypass Attempt
---
```sql
`comment("

UAC Bypass via CMSTP

Detects a User Account Control (UAC) bypass attempt using the CMSTP.exe utility. This technique, leveraged by malware like HijackLoader, involves executing cmstp.exe with a malicious INF file to run code with elevated privileges.

tags:
   - attack.t1548.002
   - attack.privilege_escalation
   - attack.defense_evasion

falsepositives:
   - Legitimate use of cmstp.exe by administrators to install or remove connection manager profiles, although this is uncommon. Scrutinize the parent process and the location of the INF file.

level: high

")`

# TUNE sourcetype and index as per your environment. This query assumes Sysmon (EventCode=1) or a similar EDR data source.
(sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational OR sourcetype=sysmon) EventCode=1
# Look for the execution of cmstp.exe, the Connection Manager Profile Installer
Image="*\\cmstp.exe"
# The /au switch is used to automatically install a profile, which is a key part of this UAC bypass.
CommandLine IN ("*/au*", "*/s*")
# The command must also reference an INF file to install.
CommandLine="*.inf*"
# Filter out common legitimate parent processes. Execution from script hosts or temp directories is highly suspicious.
NOT (ParentImage IN ("*\\explorer.exe", "*\\svchost.exe"))
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, ParentImage, Image, CommandLine, ProcessId, ParentProcessId
| rename Computer as host
| convert ctime(firstTime) ctime(lastTime)
```

### Suspicious Connectivity Check
---
```sql
# TUNE sourcetype, index, and field names (e.g., url, dest_host, uri_path) as per your environment's network data source (e.g., proxy, firewall, EDR).
(index=* sourcetype=stream:http OR sourcetype=zscaler:nss:web OR sourcetype=paloalto:traffic)
# Look for the specific URL used by HijackLoader for its connectivity check.
url="*apache.org/logos/res/incubator/default.png*"
| stats count min(_time) as firstTime max(_time) as lastTime by src_ip, dest_ip, url, user, process_name
| rename src_ip as src, dest_ip as dest, process_name as process
| convert ctime(firstTime) ctime(lastTime)
```
