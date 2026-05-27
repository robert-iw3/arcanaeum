### CrossC2 Expanding Cobalt Strike Beacon to Cross-Platform Attacks
---

JPCERT/CC has observed incidents from September to December 2024 involving CrossC2, an extension tool that enables Cobalt Strike Beacon functionality on Linux and macOS, alongside other tools like PsExec and Plink, to compromise Active Directory. The attackers utilized a custom loader, "ReadNimeLoader," written in Nim, to deploy Cobalt Strike, with potential links to the BlackBasta ransomware group.

The report highlights the increasing use of CrossC2 to extend Cobalt Strike's reach to Linux and macOS environments, which often lack robust EDR solutions, making them attractive targets for lateral movement and further compromise. Additionally, the custom ReadNimeLoader, with its sophisticated anti-analysis techniques and use of OdinLdr for in-memory execution, represents an evolving evasion strategy for deploying Cobalt Strike.

### Actionable Threat Data
---

DLL Sideloading and Execution from Recycle Bin: Monitor for java.exe loading jli.dll from unusual directories, specifically C:\$recycle.bin\, and subsequent execution of readme.txt by jli.dll. This indicates potential DLL sideloading (T1574.001) and execution from a non-standard location (T1070.004).

CrossC2 Process Behavior: Look for instances of CrossC2 (e.g., gds, gss binaries) forking itself and communicating with Cobalt Strike TeamServers. While CrossC2 is designed for Linux/macOS, its execution and C2 communication patterns can be indicative of malicious activity (T1071.001).

Anti-Analysis Techniques in ReadNimeLoader: Implement detections for anti-analysis techniques (T1497) such as checks for debuggers (e.g., BeingDebugged flag, CONTEXT_DEBUG_REGISTER), time elapsed differences, and exception handling checks. While these are internal to the malware, their presence can be a strong indicator of malicious intent during dynamic analysis.

OdinLdr In-Memory Execution: Monitor for the string "OdinLdr1337" in newly allocated heap memory, which is a distinctive characteristic of OdinLdr after it decrypts and executes the Cobalt Strike Beacon in memory (T1055).

Cobalt Strike C2 Indicators: Identify and alert on network connections to the listed C2 servers and domains (e.g., 64.52.80[.]62:443, api.glazeceramics[.]com:443, doc.docu-duplicator[.]com:53) using the specified User-Agent (Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.4.00.2879 Chrome/80.0.3987.165 Electron/8.5.1 Safari/537.36) and HTTP POST URI (/MkuiIJzM2IZs). These are specific indicators of Cobalt Strike communication (T1071.001).

### Search
```sql
-- This query combines multiple detection patterns for the ReadNimeLoader and CrossC2 campaign. It assumes a standard EDR data source (like CrowdStrike, SentinelOne, Carbon Black) is indexed in Splunk. Field names like `process_name`, `parent_process_name`, `file_name`, `file_path`, `process_command_line`, `dest_ip`, `dest_url`, `host`, and `os` should be replaced with the actual field names from your EDR data. The query is broken into three parts, each corresponding to a specific TTP, and the results are combined at the end

-- Part 1: ReadNimeLoader DLL Sideloading via java.exe
search `your_edr_index` (event_type="ImageLoad" process_name="java.exe" file_name="jli.dll" file_path="*:\\$recycle.bin\\*") OR (event_type="FileCreated" process_name="java.exe" file_name="readme.txt" file_path="*:\\$recycle.bin\\*")
| transaction process_guid, host maxspan=5m
-- Ensure both the DLL load and the file creation event occurred for the same process within the time window.
| where mvcount(event_type) > 1 AND isnotnull(mvfind(event_type, "ImageLoad")) AND isnotnull(mvfind(event_type, "FileCreated"))
| eval Timestamp = _time
| eval DetectionName = "ReadNimeLoader DLL Sideloading"
| eval Tactic = "Execution, Defense Evasion", Technique = "T1574.001"
| eval Details = "java.exe loaded jli.dll from recycle bin and accessed readme.txt"
| rename host as DeviceName, process_name as InitiatingProcessFileName, process_command_line as InitiatingProcessCommandLine
| table Timestamp, DeviceName, DetectionName, Tactic, Technique, InitiatingProcessFileName, InitiatingProcessCommandLine, Details

| append [
    -- Part 2: CrossC2 Process Forking and Network Activity on Linux/macOS
    search `your_edr_index` event_type="ProcessCreate" (os="Linux" OR os="macOS") (process_name IN ("gds", "gss")) (parent_process_name IN ("gds", "gss"))
    | rename _time as process_time, process_name as child_process, process_command_line as child_cmd, parent_process_name as parent_process
    -- Join the process creation event with subsequent network connections from the same process.
    | join type=inner host, child_process [
        search `your_edr_index` event_type="NetworkConnection" (os="Linux" OR os="macOS") (process_name IN ("gds", "gss"))
        | rename process_name as child_process, _time as network_time
    ]
    | where network_time > process_time AND (network_time - process_time) < 300
    | stats earliest(process_time) as Timestamp, values(dest_ip) as RemoteIPs, values(dest_url) as RemoteUrls by host, parent_process, child_process, child_cmd
    | eval DetectionName = "CrossC2 Forking and Network Activity"
    | eval Tactic = "Command and Control", Technique = "T1071.001"
    | eval Details = "Process ".child_process." forked from ".parent_process." and connected to IPs: ".mvjoin(RemoteIPs, ", ").", and URLs: ".mvjoin(RemoteUrls, ", ")
    | rename host as DeviceName, child_process as InitiatingProcessFileName, child_cmd as InitiatingProcessCommandLine
    | table Timestamp, DeviceName, DetectionName, Tactic, Technique, InitiatingProcessFileName, InitiatingProcessCommandLine, Details
]

| append [
    -- Part 3: Network Connections to known Cobalt Strike C2 IOCs. Using a lookup file is the recommended practice for managing IOCs.
    search `your_edr_index` event_type="NetworkConnection"
        (dest_ip IN ("64.52.80.62", "64.95.10.209", "67.217.228.55", "137.184.155.92", "159.65.241.37", "162.33.179.247", "165.227.113.183", "179.60.149.209", "192.241.190.181")
        OR dest_url LIKE "%api.glazeceramics.com%"
        OR dest_url LIKE "%doc.docu-duplicator.com%"
        OR dest_url LIKE "%doc2.docu-duplicator.com%"
        OR dest_url LIKE "%comdoc1.docu-duplicator.com%")
    | eval Timestamp = _time
    | eval DetectionName = "Known Cobalt Strike C2 Connection"
    | eval Tactic = "Command and Control", Technique = "T1071.001"
    | eval Details = "Connection to C2: " + coalesce(dest_url, dest_ip)
    | rename host as DeviceName, process_name as InitiatingProcessFileName, process_command_line as InitiatingProcessCommandLine
    | table Timestamp, DeviceName, DetectionName, Tactic, Technique, InitiatingProcessFileName, InitiatingProcessCommandLine, Details
]
```