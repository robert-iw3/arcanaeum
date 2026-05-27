### Warlock Ransomware Threat Report
---

Warlock is a rapidly evolving ransomware group that exploits unpatched Microsoft SharePoint vulnerabilities to gain initial access, escalate privileges, steal credentials, and deploy ransomware with data exfiltration. The group's tactics include the use of custom malware, built-in Windows tools, and a customized derivative of the leaked LockBit 3.0 builder.

Warlock ransomware, attributed to the China-based threat actor Storm-2603, has rapidly escalated its operations since its public debut in June 2025, claiming at least 16 successful attacks in its first month, with nearly half targeting government entities. The group has been observed exploiting the "ToolShell" SharePoint exploit chain (CVE-2025-49706, CVE-2025-49704, CVE-2025-53770, and CVE-2025-53771) to compromise over 400 SharePoint servers across 148 organizations.

### Actionable Threat Data
---

Initial Access & Privilege Escalation: Warlock exploits unpatched Microsoft SharePoint servers, specifically leveraging vulnerabilities like CVE-2025-49706, CVE-2025-49704, CVE-2025-53770, and CVE-2025-53771. They establish higher privileges by creating new Group Policy Objects (GPOs) and manipulating the built-in "guest" account to add it to the local "administrators" group.

```sql
index=* (New-GPO -name * OR net user guest * OR net localgroup administrators guest /add)
```

Defense Evasion: The threat actor deploys a binary (e.g., vmtools.exe identified as Trojan.Win64.KILLLAV.I) to enumerate and terminate security-related processes listed in a log.txt file. This binary drops and installs a malicious driver (e.g., googleApiUtil64.sys) as a service to facilitate process termination.

```sql
index=* (process_name=vmtools.exe OR file_name=googleApiUtil64.sys OR service_name=googleApiUtil64) AND (process_command_line="*taskkill /f /im *" OR process_command_line="*net stop *")
```

Discovery & Credential Access: Warlock uses native Windows utilities like nltest for domain trust discovery (nltest /domain_trusts), and wmic to query installed applications (wmic product get name,identifyingnumber). They also employ Mimikatz for credential dumping and dump Windows registry hives (SAM and SECURITY) to extract password hashes.

```sql
index=* (process_command_line="*nltest /domain_trusts*" OR process_command_line="*wmic product get name,identifyingnumber*" OR process_command_line="*net group \"domain admins\"*" OR process_command_line="*net group \"domain computers\"*" OR process_command_line="*net group \"domain controllers\"*" OR process_command_line="*quser*")
```
```sql
index=* (process_name=mimikatz.exe OR file_name=*.tmp AND (parent_process_name=svchost.exe OR process_command_line="*reg save HKLM\\SAM*" OR process_command_line="*reg save HKLM\\SECURITY*"))
```

Lateral Movement & Persistence: The attackers utilize Server Message Block (SMB) for copying payloads and tools across machines (e.g., copy C:\ProgramData\Mozilla\debug.exe \\<REDACTED>\c$\users\public\). They also enable RDP access by modifying registry values HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fdenytsconnections to 0 and disabling Network Level Authentication (NLA) by setting HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\userauthentication to 0.

```sql
index=* (process_command_line="*copy * \\\\*c$\\users\\public\\*" OR (registry_key="*HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server*" AND registry_value_name="fdenytsconnections" AND registry_value_data="0") OR (registry_key="*HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp*" AND registry_value_name="userauthentication" AND registry_value_data="0"))
```

Command and Control & Exfiltration: Warlock establishes stealthy C2 channels using protocol tunneling with a renamed Cloudflare binary (e.g., hpmews03.exe or macfee_agent.exe). Data exfiltration is performed using RClone, often disguised as legitimate tools (e.g., TrendSecurity.exe), to copy specific file types to cloud storage.

```sql
index=* (process_command_line="*tunnel run --token *" OR process_command_line="*curl.exe -L -o *cloudflared-windows-amd64.exe*")
```
```sql
index=* (process_name=rclone.exe OR process_name=TrendSecurity.exe) AND process_command_line="*copy * --protondrive-username * --protondrive-password *"
```

### Warlock Ransomware TTPs
---
```sql
-- Name: Warlock Ransomware Activity
-- Description: This rule detects a combination of Tactics, Techniques, and Procedures (TTPs) associated with Warlock ransomware campaigns.
-- It looks for evidence of discovery, credential access, defense evasion, lateral movement, and exfiltration by correlating multiple weak signals on a single host.
-- Author: RW
-- Date: 2025-08-21
-- References: https://www.trendmicro.com/en_us/research/25/h/warlock-ransomware.html
-- False Positive Sensitivity: Medium. This is a correlation rule that combines multiple weak signals.
-- Individual components, such as copying files to C$ or modifying RDP settings, might be legitimate administrative behavior.
-- The rule's strength comes from detecting multiple distinct TTPs on the same host in a short period. Consider tuning by adding known administrative accounts or tools to an exclusion list.

-- Tactic: Initial Access & Privilege Escalation via SharePoint
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name=w3wp.exe Processes.parent_process="*SharePoint*") AND (Processes.process="*net user guest /active:yes*" OR Processes.process="*net localgroup administrators guest /add*" OR Processes.process="*New-GPO*") by Processes.dest Processes.user Processes.process
| `drop_dm_object_name("Processes")`
| eval Tactic="Initial Access & Privilege Escalation", Signature=process

| append [
    -- Tactic: Discovery
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process IN ("*nltest /domain_trusts*", "*wmic product get name,identifyingnumber*", "*net group \\\"domain admins\\\"*", "*net group \\\"domain computers\\\"*", "*net group \\\"domain controllers\\\"*", "*quser*") by Processes.dest Processes.user Processes.process
    | `drop_dm_object_name("Processes")`
    | eval Tactic="Discovery", Signature=process
]

| append [
    -- Tactic: Credential Access
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=mimikatz.exe OR Processes.process="*reg*save*hklm\\sam*" OR Processes.process="*reg*save*hklm\\security*") by Processes.dest Processes.user Processes.process_name Processes.process
    | `drop_dm_object_name("Processes")`
    | eval Tactic="Credential Access", Signature=if(process_name="mimikatz.exe", process_name, process)
]

| append [
    -- Tactic: Defense Evasion - Kill AV
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name=vmtools.exe) AND (Processes.process="*taskkill*" OR Processes.process="*net stop*") by Processes.dest Processes.user Processes.process
    | `drop_dm_object_name("Processes")`
    | eval Tactic="Defense Evasion", Signature="vmtools.exe killing processes: " + process
]

| append [
    -- Tactic: Defense Evasion - Malicious Driver
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name=googleApiUtil64.sys) by Filesystem.dest Filesystem.user Filesystem.file_path
    | `drop_dm_object_name("Filesystem")`
    | eval Tactic="Defense Evasion", Signature="Malicious driver created: " + file_path
]

| append [
    -- Tactic: Command and Control
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*tunnel*run*--token*") by Processes.dest Processes.user Processes.process
    | `drop_dm_object_name("Processes")`
    | eval Tactic="Command and Control", Signature=process
]

| append [
    -- Tactic: Lateral Movement
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*copy*\\c$\\users\\public*") by Processes.dest Processes.user Processes.process
    | `drop_dm_object_name("Processes")`
    | eval Tactic="Lateral Movement", Signature=process
]

| append [
    -- Tactic: Persistence & Defense Evasion - RDP Modification
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_path="*\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections" OR Registry.registry_path="*\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication") AND Registry.registry_value_data="0" by Registry.dest Registry.user Registry.registry_path
    | `drop_dm_object_name("Registry")`
    | eval Tactic="Persistence & Defense Evasion", Signature="RDP setting modified: " + registry_path
]

| append [
    -- Tactic: Exfiltration
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("rclone.exe", "TrendSecurity.exe")) AND (Processes.process="*copy*--protondrive-username*--protondrive-password*") by Processes.dest Processes.user Processes.process
    | `drop_dm_object_name("Processes")`
    | eval Tactic="Exfiltration", Signature=process
]

-- Correlate all TTPs on a single host and trigger if 2 or more distinct tactics are seen.
| stats dc(Tactic) as distinct_tactics, values(Tactic) as tactics_observed, values(Signature) as evidence, earliest(firstTime) as first_activity, latest(lastTime) as last_activity by dest, user
| where distinct_tactics >= 2
| `ctime(first_activity)`
| `ctime(last_activity)`
| rename dest as host
| table host, user, first_activity, last_activity, distinct_tactics, tactics_observed, evidence
```