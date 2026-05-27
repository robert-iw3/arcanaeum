### UKC-1230 "Comburglar" Persistence via COM Hijack# UKC-1230 "Comburglar" Persistence via COM Hijacking
---

The threat actor UKC-1230 establishes long-term persistence by modifying specific Windows Scheduled Tasks to execute malicious code via COM hijacking. This technique involves altering User_Feed_Synchronization tasks to use a ComHandler that points to a malicious surrogate DLL, which then establishes command-and-control (C2) communications.

The tactics, techniques, and indicators of compromise detailed in the initial report remain the most current intelligence. No new variants, targeted tasks, or C2 infrastructure associated with UKC-1230 or the c4f69d93110080cc2432c9cc3d2c58ab imphash have been publicly reported since the article's publication. The use of COM hijacking for persistence is a well-established, though less common, technique that proves difficult to detect as it abuses legitimate Windows functions.

### Actionable Threat Data
---

TTP: Look for modifications to the User_Feed_Synchronization-{GUID} scheduled task, specifically the replacement of the expected msfeedsync.exe command with a <ComHandler> action.

File Indicator: Hunt for the creation of DLL files that match a GUID file name pattern ({[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}}.dll) in directories such as C:\ProgramData\Microsoft\Windows\ and C:\Users\*\AppData\Local\Microsoft\Windows\.

Malware Indicator: The most reliable indicator for the malicious DLLs used in this campaign is the imphash c4f69d93110080cc2432c9cc3d2c58ab. Searching for this value is more effective than using individual file hashes.

Registry Modification: Monitor for the creation or modification of registry keys under HKEY_CLASSES_ROOT\CLSID\{GUID}\InprocServer32 where the default value points to a GUID-named DLL in an unusual path (e.g., C:\ProgramData).

Network Indicator: Block and alert on any network traffic to or from the techdataservice.us domain and its known subdomains or associated IP addresses.

### Layered Search
---

```sql
`comment("Name: UKC-1230 Comburglar Persistence and Execution")`
`comment("Author: RW")`
`comment("Date: 2026-01-10")`
`comment("Description: This detection identifies potential 'Comburglar' (UKC-1230) activity by correlating multiple indicators. It looks for the creation of GUID-named DLLs used for COM hijacking, the specific malware imphash, suspicious COM surrogate process execution, and C2 network connections to known malicious domains.")`
`comment("References: https://www.blackhillsinfosec.com/the-curious-case-of-the-comburglar/")`
`comment("MITRE ATT&CK: T1546.015 (Component Object Model Hijacking), T1053.005 (Scheduled Task), T1059.001 (PowerShell), TA0011 (Command and Control)")`

| `comment("This tstats block efficiently searches for high-fidelity indicators: the specific imphash or C2 domains.")`
| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where (Filesystem.file_hash_imphash="c4f69d93110080cc2432c9cc3d2c58ab") by Filesystem.dest, Filesystem.file_name, Filesystem.file_path
| `rename("Filesystem.*" as *)`
| eval signal="High-Fidelity Imphash Match", file_path=if(isnull(file_path), "N/A", file_path)
| append [
    | tstats `summariesonly` count from datamodel=Network_Resolution.DNS where (DNS.query="*techdataservice.us") by DNS.dest, DNS.query
    | `rename("DNS.*" as *)`
    | eval signal="High-Fidelity C2 DNS Query"
]
| append [
    `comment("This search block looks for behavioral indicators: GUID-named DLL creation and suspicious COM surrogate execution.")`
    search (index=* sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational OR sourcetype=symantec:ep:sysmon:xml)
    `comment("Signal: GUID-named DLL file creation in a suspicious path.")`
    (EventCode=11 (TargetFilename="C:\\ProgramData\\Microsoft\\Windows\\*" OR TargetFilename="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\*") AND TargetFilename="*.dll" AND match(TargetFilename, ".*\\\{[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}\.dll$"))
    OR
    `comment("Signal: COM surrogate process (dllhost.exe) launched by the Task Scheduler service (svchost.exe), which is how the hijacked User_Feed_Synchronization task executes.")`
    (EventCode=1 Image="*\\dllhost.exe" ParentImage="*\\svchost.exe" CommandLine="*/Processid:{*")
    | `rename Computer as dest`
    | eval signal=if(EventCode=11, "Behavioral: GUID-named DLL Created", "Behavioral: Suspicious COM Surrogate Execution"), file_name=if(EventCode=11, TargetFilename, Image), file_path=if(EventCode=11, TargetFilename, "N/A"), query="N/A"
    | fields dest, signal, file_name, file_path, query
]
`comment("The following section correlates these findings. An alert is generated if a high-fidelity indicator is found, or if two distinct behavioral indicators are seen on the same host.")`
| stats
    values(signal) as signals,
    dc(signal) as distinct_signals,
    values(file_name) as file_names,
    values(file_path) as file_paths,
    values(query) as c2_queries
    by dest
| where (like(signals, "High-Fidelity%")) OR (distinct_signals >= 2 AND like(signals, "Behavioral%"))
`comment("FP Tuning: This search is high-fidelity but could trigger on legitimate software that uses COM surrogates and GUID-named files. If false positives occur, consider adding process names or parent processes to an exclusion list within the search or via a lookup.")`
| rename dest as host
| fields host, signals, distinct_signals, file_names, file_paths, c2_queries
```