### Malware Identified in Attacks Exploiting Ivanti Connect Secure Vulnerabilities
---

This report details the continued exploitation of Ivanti Connect Secure vulnerabilities (CVE-2025-0282 and CVE-2025-22457) by attackers, observed from December 2024 to July 2025. The attackers are deploying various malware, including MDifyLoader, Cobalt Strike Beacon, vshell, and Fscan, to establish persistence, move laterally, and evade defenses within compromised networks.

Attackers are employing sophisticated obfuscation techniques in MDifyLoader, such as junk code insertion and RC4 decryption with keys derived from MD5 hashes of legitimate executables, making analysis and detection more challenging. Additionally, the use of vshell, a multi-platform RAT, with a hardcoded language check for Chinese, and Fscan's loader incorporating an ETW bypass, highlight evolving defense evasion tactics.

### Actionable Threat Data
---

DLL Side-Loading with Legitimate Processes: Monitor for rmic.exe, push_detect.exe, and python.exe loading unusual or newly created DLLs (e.g., jli.dll, Microsoft.WindowsAppRuntime.Bootstrap.dll, python311.dll) from non-standard directories. This activity is indicative of MDifyLoader and Fscan loader execution. (T1574.001)

Cobalt Strike Beacon with RC4 "google" Key: Look for Cobalt Strike Beacon configurations that utilize RC4 decryption with the hardcoded key "google". This is a specific indicator of the observed Cobalt Strike version 4.5. (T1027)

vshell Network Communication: Identify outbound network connections from internal hosts to proxy.objectlook[.]com:80 using WebSocket protocol, which is a known C2 communication method for vshell. (T1071.001)

Fscan Execution and Network Scanning: Detect the execution of k.bin (SHA256: cff2afc651a9cba84a11a4e275cc9ec49e29af5fd968352d40aeee07fb00445e) or other Fscan binaries, especially when initiated via DLL side-loading from python.exe. Additionally, monitor for excessive ICMP pings or other rapid network scanning activities originating from compromised hosts. (T1046, T1018)

Persistence Mechanisms: Look for the creation of new domain accounts, modification of existing group memberships, and the registration of new services or scheduled tasks that point to unusual or newly introduced executables. (T1136.002, T1098, T1543.003, T1053.005)

ETW Bypass: Monitor for attempts to patch ntdll.dll or other system DLLs, specifically targeting Event Tracing for Windows (ETW) functions, which is a defense evasion technique used by the Fscan loader. (T1562.001)

Brute-Force Attacks and Lateral Movement: Alert on multiple failed authentication attempts against AD, FTP, MSSQL, or SSH servers, followed by successful logins from unusual sources. Also, monitor for exploitation attempts of SMB vulnerability MS17-010 and subsequent lateral movement via RDP or SMB. (T1110.001, T1210, T1021.001, T1021.002)

### Search
---
Name: Comprehensive Ivanti Exploitation TTPs

Author: RW

Date: 2025-08-14

Description:

A composite rule that detects multiple tactics, techniques, and procedures (TTPs) associated with attacks exploiting Ivanti Connect Secure vulnerabilities, as detailed by JPCERT/CC. This includes DLL side-loading, specific malware artifacts, C2 communication, persistence mechanisms, defense evasion, and lateral movement patterns.

Tactic: Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Command and Control, Lateral Movement

Technique: T1574.001, T1027, T1071.001, T1046, T1018, T1136.002, T1098, T1543.003, T1053.005, T1562.001, T1110.001, T1021.001, T1021.002

False Positive Sensitivity: Medium

```sql
-- ------------- Part 1: DLL Side-Loading via Legitimate Processes -------------
-- Key Logic: Identifies specific legitimate processes loading DLLs associated with MDifyLoader or the Fscan loader. Assumes Sysmon EventCode 7.
(index=sysmon sourcetype=Sysmon EventCode=7)
(
    (Image="*\\rmic.exe" ImageLoaded="*\\jli.dll") OR
    (Image="*\\push_detect.exe" ImageLoaded="*\\Microsoft.WindowsAppRuntime.Bootstrap.dll") OR
    (Image="*\\python.exe" ImageLoaded="*\\python311.dll")
)
| rex field=Image "(?<ProcessPath>.*)\\\\"
| rex field=ImageLoaded "(?<DllPath>.*)\\\\"
-- FP Tuning: A common pattern for DLL side-loading is for the malicious DLL to be in the same directory as the legitimate executable.
| where ProcessPath = DllPath AND NOT (match(ProcessPath, "(?i)^C:\\(Program Files|Windows\\System32|Program Files \(x86\)|Windows\\SysWOW64)"))
| rex field=Image ".*\\\\(?<InitiatingProcessFileName>[^\\\\]+)$"
| rex field=ImageLoaded ".*\\\\(?<FileName>[^\\\\]+)$"
| eval DetectionType="DLL Side-Loading", ActionType="ImageLoaded"
| eval Details = "Legitimate process '".InitiatingProcessFileName."' loaded suspicious DLL '".FileName."' from '".DllPath."'."
| rename Computer as host, User as AccountName, CommandLine as InitiatingProcessCommandLine
| eval ReferenceTechnique="T1574.001"
| fields _time, host, DetectionType, ActionType, Details, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, ReferenceTechnique

| append [
    -- ------------- Part 2: Cobalt Strike & Fscan Artifacts -------------
    -- Key Logic: Detects the creation of known Cobalt Strike beacon files or the Fscan binary. Assumes Sysmon EventCode 11.
    search (index=sysmon sourcetype=Sysmon EventCode=11)
    (
        (SHA256 IN (
            "09087fc4f8c261a810479bb574b0ecbf8173d4a8365a73113025bd506b95e3d7",
            "1652ab693512cd4f26cc73e253b5b9b0e342ac70aa767524264fef08706d0e69",
            "cff2afc651a9cba84a11a4e275cc9ec49e29af5fd968352d40aeee07fb00445e"
        )) OR
        (TargetFilename IN ("*\\update.dat", "*\\config.ini") Image IN ("*\\rmic.exe", "*\\push_detect.exe"))
    )
    -- FP Tuning: The behavioral part (process + filename) may have FPs. Add exclusions for known legitimate updaters if needed.
    | rex field=Image ".*\\\\(?<InitiatingProcessFileName>[^\\\\]+)$"
    | rex field=TargetFilename ".*\\\\(?<FileName>[^\\\\]+)$"
    | eval DetectionType = case(SHA256=="cff2afc651a9cba84a11a4e275cc9ec49e29af5fd968352d40aeee07fb00445e", "Fscan Binary Dropped", 1=1, "Cobalt Strike Beacon Dropped")
    | eval ReferenceTechnique = case(SHA256=="cff2afc651a9cba84a11a4e275cc9ec49e29af5fd968352d40aeee07fb00445e", "T1046", 1=1, "T1027")
    | eval ActionType="FileCreated"
    | eval Details = "File '".FileName."' (SHA256: ".SHA256.") created by '".InitiatingProcessFileName."'."
    | rename Computer as host, User as AccountName, ProcessCommandLine as InitiatingProcessCommandLine
    | fields _time, host, DetectionType, ActionType, Details, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, ReferenceTechnique
]
| append [
    -- ------------- Part 3: Vshell C2 Communication -------------
    -- Key Logic: Detects network traffic to the known vshell C2 domain on port 80. Assumes Sysmon EventCode 3.
    search (index=sysmon sourcetype=Sysmon EventCode=3) DestinationHostname="proxy.objectlook.com" DestinationPort=80
    -- FP Tuning: This IOC is specific. If the domain is sinkholed or repurposed, it could generate FPs.
    | rex field=Image ".*\\\\(?<InitiatingProcessFileName>[^\\\\]+)$"
    | eval DetectionType="Vshell C2 Communication", ActionType="NetworkConnection"
    | eval Details = "Connection to known C2 URL: ".DestinationHostname.":" .DestinationPort
    | rename Computer as host, User as AccountName, CommandLine as InitiatingProcessCommandLine
    | eval ReferenceTechnique="T1071.001"
    | fields _time, host, DetectionType, ActionType, Details, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, ReferenceTechnique
]
| append [
    -- ------------- Part 4: Account Manipulation via CLI -------------
    -- Key Logic: Looks for command lines used to add users or add members to privileged groups. Assumes Sysmon EventCode 1.
    search (index=sysmon sourcetype=Sysmon EventCode=1) (Image="*\\net.exe" OR Image="*\\net1.exe")
    (CommandLine IN ("* user /add *", "* group /add *", "* localgroup /add *"))
    (CommandLine IN ("* /domain *", "* Administrators *", "* Domain Admins *", "* Enterprise Admins *", "* Remote Desktop Users *"))
    -- FP Tuning: Legitimate administrative activity will trigger this. Filter by known admin accounts or look for execution from unexpected parent processes if noisy.
    | rex field=Image ".*\\\\(?<InitiatingProcessFileName>[^\\\\]+)$"
    | rex field=ParentImage ".*\\\\(?<ParentProcessFileName>[^\\\\]+)$"
    | eval DetectionType="Account Manipulation via CLI", ActionType="ProcessCreated"
    | rename Computer as host, User as AccountName, CommandLine as Details, ParentCommandLine as InitiatingProcessCommandLine
    | eval InitiatingProcessFileName=ParentProcessFileName
    | eval ReferenceTechnique="T1136.002, T1098"
    | fields _time, host, DetectionType, ActionType, Details, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, ReferenceTechnique
]
| append [
    -- ------------- Part 5: Suspicious Service or Scheduled Task Creation -------------
    -- Key Logic: Identifies services or tasks whose executable path is in a suspicious, user-writable location. Assumes Sysmon EventCodes 1 and 13.
    search (index=sysmon sourcetype=Sysmon)
    (
        (EventCode=13 TargetObject="*\\System\\CurrentControlSet\\Services\\*\\ImagePath" Details IN ("*C:\\Users\\*", "*C:\\ProgramData\\*", "*C:\\Temp\\*", "*C:\\Windows\\Temp\\*", "*\\AppData\\*")) OR
        (EventCode=1 Image="*\\schtasks.exe" CommandLine IN ("*/create*", "*/change*") CommandLine IN ("*C:\\Users\\*", "*C:\\ProgramData\\*", "*C:\\Temp\\*", "*C:\\Windows\\Temp\\*", "*\\AppData\\*"))
    )
    -- FP Tuning: Legitimate software may use these locations. Exclude known good software by Image or path.
    | rex field=Image ".*\\\\(?<InitiatingProcessFileName>[^\\\\]+)$"
    | eval DetectionType = if(EventCode=13, "Suspicious Service Creation", "Suspicious Scheduled Task")
    | eval ActionType = if(EventCode=13, "ServiceCreated", "ScheduledTaskCreated")
    | eval Details = if(EventCode=13, "Service Name: ".TargetObject.", Image Path: ".Details, CommandLine)
    | eval ReferenceTechnique = if(EventCode=13, "T1543.003", "T1053.005")
    | rename Computer as host, User as AccountName, ParentImage as InitiatingProcessFileName, ParentCommandLine as InitiatingProcessCommandLine
    | fields _time, host, DetectionType, ActionType, Details, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, ReferenceTechnique
]
| append [
    -- ------------- Part 6: ETW Bypass via ntdll.dll Patching -------------
    -- Key Logic: Detects a process making the ntdll.dll memory region writable. This uses MDE data (DeviceEvents table) as it maps directly to the KQL. Sysmon EventCode 25 is a less precise alternative.
    search (index=mde sourcetype="mde:device_events") ActionType="VirtualProtectApiCall" FileName="ntdll.dll" (NewMemoryProtection="ExecuteReadWrite" OR NewMemoryProtection="0x40")
    | where InitiatingProcessId == ModifiedProcessId
    -- FP Tuning: Legitimate software like anti-cheat or DRM may do this. Exclude known legitimate processes if they generate FPs.
    | eval DetectionType="ETW Bypass via ntdll.dll Patching"
    | eval Details = "Process '".InitiatingProcessFileName."' changed memory protection for '".FileName."' to '".NewMemoryProtection."'."
    | rename DeviceName as host
    | eval ReferenceTechnique="T1562.001"
    | fields _time, host, DetectionType, ActionType, Details, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, ReferenceTechnique
]
| append [
    -- ------------- Part 7: Brute-Force Followed by Successful Logon -------------
    -- Key Logic: Correlate a high number of logon failures with a subsequent success from the same source IP. Assumes Windows Security Event Logs.
    search (index=wineventlog sourcetype="WinEventLog:Security") (EventCode=4624 OR EventCode=4625) Logon_Type IN (3, 10)
    | sort 0 + _time
    -- FP Tuning: Adjust the timeframe (window) and failure_threshold to fit your environment's baseline.
    | streamstats count(eval(EventCode=4625)) as FailureCount window=1h by Ip_Address, dest, Logon_Type
    | where EventCode=4624 AND FailureCount > 20
    -- FP Tuning: Exclude known vulnerability scanners or misconfigured servers if they cause noise.
    | eval LogonProtocol = if(Logon_Type==3, "SMB", "RDP")
    | eval DetectionType = "Brute-Force Followed by Successful Logon", ActionType="LogonSuccess"
    | eval Details = "Successful ".LogonProtocol." logon from ".Ip_Address." after ".FailureCount." failures."
    | rename dest as host, User as AccountName
    | eval InitiatingProcessFileName="N/A", InitiatingProcessCommandLine="N/A"
    | eval ReferenceTechnique="T1110.001, T1021.001, T1021.002"
    | fields _time, host, DetectionType, ActionType, Details, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, ReferenceTechnique
]
```