### The Worst ICS/OT Cybersecurity Love Story
---

This report summarizes the evolving landscape of ICS/OT threats, highlighting the increasing convergence of state-sponsored adversaries and hacktivist groups, particularly those aligned with Russia. It emphasizes the growing threat of ransomware attacks against industrial organizations and the persistent vulnerabilities in remote access to OT environments.

The 2025 Dragos Year in Review report indicates a significant 87% increase in ransomware attacks against industrial organizations and a 60% rise in active ransomware groups impacting OT/ICS in 2024. Additionally, new intelligence reveals that state-sponsored APT44 (Sandworm) is leveraging hacktivist personas like Cyber Army of Russia Reborn (CARR), XakNet, and Solntsepek to manipulate critical infrastructure, blurring the lines between state-backed and hacktivist operations.

### Actionable Threat Data
---

Monitor for increased ransomware activity, specifically targeting industrial control systems and manufacturing entities, as these have seen a significant surge in attacks.

Implement robust security measures for remote access to OT/ICS environments, addressing insecure configurations, unpatched systems, and poor network architecture, as 65% of assessed sites had such vulnerabilities.

Detect and prevent the use of SSH for general-purpose encrypted communication to publicly routable addresses, as 45% of OT Watch customers had this vulnerability, which can be leveraged for C2 tunnels and proxies.

Focus on detecting initial access attempts by groups like KAMACITE (APT44), which often target IT networks to gain footholds in OT/ICS infrastructure, and look for credential harvesting activities.

Be aware of hacktivist groups like Cyber Army of Russia Reborn (CARR), KillNet, XakNet, and Solntsepek, especially their use of DDoS attacks, data leaks, and attempts to manipulate SCADA systems, as they may act as fronts for more advanced state-sponsored operations.

### Search
---
```sql
-- Name: Ransomware Activity in ICS/OT Environment
-- Author: RW
-- Date: 2025-08-17
-- Description: Detects common ransomware TTPs that are highly anomalous in an Industrial Control Systems (ICS) or Operational Technology (OT) environment. The query identifies shadow copy deletion, disabling of recovery features, and mass file renaming indicative of encryption. The detection is focused on behaviors that are particularly suspicious on critical assets like Engineering Workstations (EWS) or Human-Machine Interfaces (HMI).
-- False Positive Sensitivity: Medium
-- Tactic: Impact
-- Technique: T1490, T1486

-- This search requires endpoint data from Crowdstrike Falcon, focusing on process and file events.
-- Optimization: Use efficient regex for command lines, aggregate file renames over short windows to reduce query load, and filter early on OT assets via host groups or naming conventions (e.g., via ComputerName regex).

-- TTP 1 & 2: Inhibit System Recovery (T1490)
event_platform=Win (event_simpleName=ProcessRollup2 (ImageFileName=vssadmin.exe CommandLine=/delete shadows/i
| ImageFileName=bcdedit.exe (CommandLine=/recoveryenabled no/i
| CommandLine=/bootstatuspolicy ignoreallfailures/i)))
| stats min(@timestamp) as firstTime max(@timestamp) as lastTime count by ComputerName LocalUserName ImageFileName CommandLine
| eval TTP=case(ImageFileName="vssadmin.exe", "Shadow Copy Deletion", ImageFileName="bcdedit.exe", "System Recovery Disabled"), technique="T1490", tactic="Impact" | table firstTime lastTime ComputerName LocalUserName ImageFileName CommandLine TTP technique tactic-- Combine with mass file rename detection
| append [
    -- TTP 3: Data Encrypted for Impact (T1486)
    event_platform=Win event_simpleName=FileRename
    | stats count by @timestamp span=5m ComputerName TargetFileName ImageFileName LocalUserName
    | rex field=TargetFileName "\.(?<new_ext>[^.\\]+)$"
    | stats count as renamed_file_count dc(new_ext) as distinct_ext_count values(new_ext) as new_extension by @timestamp ComputerName LocalUserName ImageFileName
    | where renamed_file_count > 100 AND distinct_ext_count = 1
    | rename @timestamp as firstTime | eval lastTime=firstTime, TTP="Mass File Renaming", technique="T1486", tactic="Impact", CommandLine="N/A (File System Activity)", new_extension=mvindex(new_extension, 0)
    | table firstTime lastTime ComputerName LocalUserName ImageFileName CommandLine TTP technique tactic renamed_file_count new_extension
]-- FP Tuning: To focus this detection on critical ICS/OT assets, filter by device groups or naming conventions.
-- Example: +ComputerName:/(HMI|EWS|HISTORIAN)/i
```
---
```sql
-- Name: Insecure Remote Access Pattern in ICS/OT Environment
-- Author: RW
-- Date: 2025-08-17
-- Description: Detects multiple patterns of insecure or highly anomalous remote access to or from critical Industrial Control Systems (ICS) or Operational Technology (OT) assets. This includes inbound RDP/VNC from the internet, outbound SSH to the internet, and the use of common remote administration software. Such activity is often forbidden by policy in OT environments and can be an indicator of misconfiguration or malicious activity. This detection is based on intelligence indicating that 65% of assessed OT sites have insecure remote conditions.
-- False Positive Sensitivity: Medium
-- Tactic: Initial Access, Command and Control
-- Technique: T1133, T1219

-- Optimization: Filter early on OT assets via ComputerName, use CIDR exclusions for corporate ranges, and aggregate over time to minimize results. Assumes Falcon Network Protection for traffic events.
-- FP Tuning: Define filters for OT assets (e.g., ComputerName regex), corporate IPs (e.g., via !RemoteAddressIP4:/^10.|^192.168./), and remote tools (e.g., ImageFileName in list).

-- Pattern 1: Detects inbound connections from the public internet on common remote access ports.
event_simpleName=NetworkAcceptTCPv4 Direction=inbound RemotePort IN (3389, 5800, 5900, 5901) !RemoteAddressIP4:/^10.|^192.168.|^172.(1[6-9]|2[0-9]|3[0-1])./
| stats min(@timestamp) as firstTime max(@timestamp) as lastTime count by ComputerName RemoteAddressIP4 RemotePort
| eval Pattern="Inbound RDP/VNC from Internet", Tactic="Initial Access", Technique="T1133", ImageFileName="N/A", CommandLine="N/A", LocalUserName="N/A"
| table firstTime lastTime ComputerName Pattern Tactic Technique RemoteAddressIP4 RemotePort ImageFileName CommandLine LocalUserName
| append [
    -- Pattern 2: Detects outbound SSH connections from OT assets to the public internet.
    event_simpleName=NetworkConnectTCPv4 Direction=outbound RemotePort=22 !RemoteAddressIP4:/^10.|^192.168.|^172.(1[6-9]|2[0-9]|3[0-1])./
    | stats min(@timestamp) as firstTime max(@timestamp) as lastTime count by ComputerName RemoteAddressIP4 ImageFileName
    | eval Pattern="Outbound SSH to Internet", Tactic="Command and Control", Technique="T1133", RemotePort=22, CommandLine="N/A", LocalUserName="N/A"
    | table firstTime lastTime ComputerName Pattern Tactic Technique RemoteAddressIP4 RemotePort ImageFileName CommandLine LocalUserName
    ]
| append [
        -- Pattern 3: Detects the execution of common remote administration software on OT assets.
        event_simpleName=ProcessRollup2 ImageFileName IN ("TeamViewer.exe", "AnyDesk.exe", "tv_w32.exe", "tv_x64.exe", "LogMeIn.exe", "ScreenConnect.exe", "splashtop.exe", "vncviewer.exe")
        | stats min(@timestamp) as firstTime max(@timestamp) as lastTime count by ComputerName ImageFileName CommandLine LocalUserName
        | eval Pattern="Remote Administration Software Execution", Tactic="Command and Control", Technique="T1219", RemoteAddressIP4="N/A", RemotePort="N/A"
        | table firstTime lastTime ComputerName Pattern Tactic Technique RemoteAddressIP4 RemotePort ImageFileName CommandLine LocalUserName
        ]
-- Filter for activity on designated OT assets. This is the most important step to reduce noise.
-- Example: +ComputerName:/(HMI|EWS|HISTORIAN)/i
```
---
```sql
-- Name: Outbound SSH Tunneling or High Data Transfer from ICS/OT Asset
-- Author: RW
-- Date: 2025-08-17
-- Description: Detects outbound SSH from critical ICS/OT assets to the public internet that exhibits signs of being used for C2 or proxying. The rule looks for either explicit command-line flags used for tunneling or high-volume data transfers over SSH. According to intelligence, 45% of assessed OT environments have SSH communicating to public addresses, which can be leveraged by adversaries for C2 tunnels and proxies.
-- False Positive Sensitivity: Medium
-- Tactic: Command and Control
-- Technique: T1090, T1572

-- Optimization: Use regex for command lines to catch tunneling flags efficiently, aggregate traffic bytes over 1h spans to optimize for volume detection. Filter OT assets early.
-- FP Tuning: Define OT assets (e.g., ComputerName regex), corporate IPs (e.g., !RemoteAddressIP4 CIDR), and adjust thresholds.

-- Pattern 1: Detects command-line arguments indicating SSH tunneling. This is a high-fidelity indicator of proxying.
event_simpleName=ProcessRollup2 ImageFileName IN ("ssh.exe", "plink.exe", "putty.exe") CommandLine=/(-D |-L |-R )/i
| stats min(@timestamp) as firstTime max(@timestamp) as lastTime count by ComputerName LocalUserName ImageFileName CommandLine
| eval pattern="SSH Tunneling Command Detected", total_bytes_transferred="N/A", remote_ip="N/A (check command line)"
| table firstTime lastTime ComputerName LocalUserName pattern ImageFileName CommandLine remote_ip total_bytes_transferred
-- Combine with high data transfer detection
| append [
    -- Pattern 2: Detects high-volume data transfers over SSH to a public IP address.
    event_simpleName=NetworkConnectTCPv4 RemotePort=22 !RemoteAddressIP4:/^10.|^192.168.|^172.(1[6-9]|2[0-9]|3[0-1])./
    | stats sum(TransmitBytes) as bytes_out sum(ReceiveBytes) as bytes_in by @timestamp span=1h ComputerName RemoteAddressIP4 ImageFileName
    | eval total_bytes = bytes_in + bytes_out
    | where total_bytes > (10 * 1024 * 1024)
    | eval total_bytes_transferred = tostring(round(total_bytes/1024/1024, 2)) + " MB"
    | rename @timestamp as firstTime
    | eval lastTime = firstTime, pattern="High Data Transfer over SSH to Public IP", CommandLine="N/A", LocalUserName="N/A"
    | table firstTime lastTime ComputerName LocalUserName pattern ImageFileName CommandLine RemoteAddressIP4 total_bytes_transferred
    ]
-- Example OT Filter: +ComputerName:/(HMI|EWS|HISTORIAN)/i
```
---
```sql
-- Name: KAMACITE Initial Access and Credential Harvesting
-- Author: RW
-- Date: 2025-08-17
-- Description: Detects credential harvesting techniques commonly used by threat actors like KAMACITE (APT44) after gaining initial access to IT networks that bridge to OT/ICS environments. This rule identifies LSASS memory dumping and registry hive dumping, which are critical steps for adversaries to escalate privileges and move laterally. Detecting these activities is crucial to preventing deeper compromise of OT/ICS environments.
-- False Positive Sensitivity: Medium
-- Tactic: Credential Access
-- Technique: T1003.001, T1003.002

event_platform=Win event_simpleName=ProcessRollup2 (
    (ImageFileName=procdump.exe CommandLine=/ -ma /i CommandLine=/lsass.exe/i)
    | (ImageFileName=rundll32.exe CommandLine=/comsvcs.dll.*MiniDump/i)
    | (ImageFileName=reg.exe CommandLine=/save/i (CommandLine=/hklm\sam/i
    | CommandLine=/hklm\security/i
    | CommandLine=/hklm\system/i))
    )
| stats min(@timestamp) as firstTime max(@timestamp) as lastTime count by ComputerName LocalUserName ParentBaseFileName ImageFileName CommandLine
| eval Pattern=case(
    (ImageFileName="procdump.exe" OR ImageFileName="rundll32.exe"), "LSASS Memory Dumping",
    ImageFileName="reg.exe", "Registry Hive Dumping"
  ), TechniqueId=case(
    Pattern=="LSASS Memory Dumping", "T1003.001",
    Pattern=="Registry Hive Dumping", "T1003.002"
  )
| rename ComputerName as DeviceName, LocalUserName as AccountName, ParentBaseFileName as InitiatingProcessFileName, ImageFileName as FileName, CommandLine as ProcessCommandLine
| table firstTime lastTime DeviceName AccountName Pattern TechniqueId InitiatingProcessFileName FileName ProcessCommandLine
-- FP Tuning: This rule may generate alerts from legitimate administrative or security tool activity.
-- To reduce noise, filter for critical systems that bridge IT and OT, such as jump servers, EWS, or historian servers.
-- Example: +ComputerName:/(JUMP|EWS|HISTORIAN)/i
```
---
```sql
-- Name: Hacktivist Activity on SCADA/OT Systems
-- Author: RW
-- Date: 2025-08-17
-- Description: This rule detects TTPs associated with hacktivist groups like CARR and KillNet targeting ICS/OT environments. It identifies potential DDoS symptoms, anomalous administrative tool usage on critical OT assets (HMIs, EWS), and large-scale data exfiltration. These activities can indicate attempts to manipulate SCADA systems or serve as a distraction for other malicious actions.
-- False Positive Sensitivity: Medium
-- Tactic: Impact, Execution, Exfiltration
-- Technique: T1498, T1059, T1048

-- Optimization: Aggregate inbound connections for DDoS detection to reduce volume, filter anomalous processes with exclusions, and threshold exfiltration bytes. Early OT asset filtering.
-- FP Tuning: Define OT assets (e.g., ComputerName regex), corporate IPs (!RemoteAddressIP4 CIDR), anomalous tools (ImageFileName in list), and adjust thresholds/parent exclusions.

-- Pattern 1: Detects host-level symptoms of a DDoS or network flood attack.
event_simpleName=NetworkAcceptTCPv4 Direction=inbound !RemoteAddressIP4:/^10.|^192.168.|^172.(1[6-9]|2[0-9]|3[0-1])./
| stats dc(RemoteAddressIP4) as distinct_remote_ips by @timestamp span=5m ComputerName
| where distinct_remote_ips > 200
| eval pattern="Potential DDoS Symptom (High Inbound Connections)", tactic="Impact", technique="T1498", details="Host " + ComputerName + " received connections from " + distinct_remote_ips + " distinct external IPs in 5 minutes."
| table @timestamp ComputerName pattern tactic technique details
| append [
    -- Pattern 2: Detects execution of anomalous tools on critical OT assets.
    event_simpleName=ProcessRollup2 ImageFileName IN ("powershell.exe", "cmd.exe", "cscript.exe", "wscript.exe", "nmap.exe", "netcat.exe", "nc.exe", "net.exe", "netsh.exe", "plink.exe", "putty.exe", "mstsc.exe") ParentBaseFileName!="monitoring_agent.exe"
    | stats count by ComputerName LocalUserName ParentBaseFileName ImageFileName CommandLine
    | eval pattern="Anomalous Process on Critical OT Asset", tactic="Execution", technique="T1059", details="Process: " + ImageFileName + ", CommandLine: " + CommandLine + ", Initiated by: " + ParentBaseFileName
    | table @timestamp ComputerName pattern tactic technique details
    ]
| append [
    -- Pattern 3: Detects large data transfers from critical OT assets to external destinations.
    event_simpleName=NetworkConnectTCPv4 Direction=outbound !RemoteAddressIP4:/^10.|^192.168.|^172.(1[6-9]|2[0-9]|3[0-1])./
    | stats sum(TransmitBytes) as total_bytes_out by @timestamp span=1h ComputerName RemoteAddressIP4 ImageFileName
    | where total_bytes_out > (50 * 1024 * 1024)
    | eval pattern="Large Data Exfiltration from OT Asset", tactic="Exfiltration", technique="T1048", details="Transferred " + tostring(round(total_bytes_out/1024/1024, 2)) + " MB from " + ComputerName + " to " + RemoteAddressIP4 + " via process " + ImageFileName
    | table @timestamp ComputerName pattern tactic technique details
    ]
-- Example OT Filter: +ComputerName:/(HMI|EWS)/i
```