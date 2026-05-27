### Salt Typhoon Threat Intelligence Report
---

Salt Typhoon is a sophisticated, state-sponsored APT group, believed to be backed by China's Ministry of State Security (MSS), primarily focused on cyber espionage and data theft from critical U.S. infrastructure, government agencies, and telecommunications companies. The group employs a mix of Living Off the Land Binaries (LOLBins), custom tools, and exploitation of known vulnerabilities to maintain stealthy, long-term presence in compromised networks for intelligence gathering.

Recent intelligence indicates Salt Typhoon has continued to target U.S. telecommunications firms, exploiting vulnerabilities in network infrastructure, including Cisco IOS XE devices, and utilizing a custom backdoor called 'JumbledPath' (and 'GhostSpider') for persistent access and data exfiltration. This highlights an ongoing focus on critical communication infrastructure and the development of specialized tools for these environments.

### Actionable Threat Data
---

Exploitation of Public-Facing Application Vulnerabilities:

Salt Typhoon actively exploits vulnerabilities in public-facing applications and network devices for initial access and persistence. This includes `CVE-2023-46805/CVE-2024-21887 (Ivanti Secure Connect VPN)`, `CVE-2023-48788 (Fortinet FortiClient EMS)`, `CVE-2022-3236 (Sophos Firewall)`, `Microsoft Exchange ProxyLogon` vulnerabilities, and `Cisco IOS XE vulnerabilities (CVE-2023-20198, CVE-2023-20273)`.

Living Off the Land Binaries (LOLBins) and Scripting:

The group heavily utilizes legitimate system tools to evade detection. Monitor for suspicious usage of `BITSAdmin`, `CertUtil`, `PowerShell`, `WMI` for command execution, `SMB` for lateral movement, and `PsExec` for command execution/lateral movement.

Custom Backdoors and Malware:

Salt Typhoon deploys custom backdoors like '`JumbledPath`' and '`GhostSpider`' for persistent access and network traffic monitoring. Look for unusual network connections, especially outbound, and new or modified services that could indicate backdoor installation.

Data Staging and Exfiltration:

The group uses `rar.exe` to compress sensitive data, often into directories like `C:\Users\Public\Music`, before exfiltration. Monitor for large archives being created in unusual locations or suspicious outbound network traffic from these locations.

Persistence Mechanisms:

Salt Typhoon establishes persistence through modification of `registry run keys` and creation of `Windows Services`. Monitor for new or modified registry run keys and the creation of new, unusual Windows services.

Information Gathering and Reconnaissance:

The group performs reconnaissance by retrieving '`Domain Admin`' group details. Monitor for unusual queries or enumeration of privileged groups.

### LOLBins for Execution
---
```sql
`comment("This detection rule identifies suspicious command-line execution of BITSAdmin, CertUtil, and PowerShell, which are LOLBins (Living Off the Land Binaries) frequently abused by the threat actor Salt Typhoon.")`
`tstats` summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
// Filter for the specific LOLBins used by Salt Typhoon
where (Processes.process_name IN ("bitsadmin.exe", "certutil.exe", "powershell.exe"))
// Define suspicious command-line patterns for each LOLBin
AND (
    (Processes.process_name="bitsadmin.exe" AND (Processes.process="* /transfer *" OR Processes.process="* /create *" OR Processes.process="* /addfile *"))
    OR
    (Processes.process_name="certutil.exe" AND (Processes.process="* -urlcache *" OR Processes.process="* -f *" OR Processes.process="* -split *" OR Processes.process="* -encode *" OR Processes.process="* -decode *"))
    OR
    (Processes.process_name="powershell.exe" AND (Processes.process="* -enc *" OR Processes.process="* -encodedcommand *" OR Processes.process="* IEX *" OR Processes.process="* Invoke-Expression *" OR Processes.process="* Hidden *"))
)
// Group by key fields to identify unique events
by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| rename "Processes.*" as "*"
`comment("The following line is a placeholder for filtering false positives. Legitimate administrative scripts or software deployment tools may trigger this detection. Tune this search by filtering known good parent processes, users, or specific command-line arguments. Example: `| search NOT (user IN (service_acct_1) OR parent_process_name IN (sccm.exe))`")`
// Format the output table for triage
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process, count
| sort - count
```

### WMI/PsExec for Lateral Movement
---
```sql
`comment("This detection rule identifies potential lateral movement using PsExec or WMI, techniques frequently employed by the threat actor Salt Typhoon (MITRE T1021.006, T1047). It looks for the execution of PsExec targeting remote systems, the PsExec service running on a host, or remote process execution via WMI.")`
tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
where
    (
        // Detects PsExec execution targeting a remote system
        (Processes.process_name="psexec.exe" AND Processes.process="*\\\\*")
        OR
        // Detects the PsExec service running on a target host
        (Processes.process_name="psexesvc.exe" AND Processes.parent_process_name="services.exe")
        OR
        // Detects wmic.exe used for remote process creation
        (Processes.process_name="wmic.exe" AND (Processes.process="*/node:*" OR Processes.process="* process call create *"))
        OR
        // Detects processes spawned by the WMI Provider Host, a common indicator of WMI-based execution
        (Processes.parent_process_name="WmiPrvSE.exe")
    )
by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| rename "Processes.*" as "*"
`comment("The following line is a placeholder for filtering false positives. Legitimate administrative tools, scripts, or monitoring software may use WMI for remote execution. Tune this search by filtering known good parent processes or specific processes spawned by WmiPrvSE.exe. Example: `| search NOT (parent_process_name=\"WmiPrvSE.exe\" AND process_name=\"legit_process.exe\")`")`
// Format the output table for triage
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process, count
| sort - count
```

### SMB for Lateral Movement
---
```sql
`comment("This detection rule identifies potential lateral movement using SMB admin shares (e.g., C$, ADMIN$), a technique associated with MITRE T1021.002 and used by threat actors like Salt Typhoon. It detects when a source system connects to an administrative share on a destination system.")`
tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Network_Shares
// Filter for access to the most common administrative shares, C$ and ADMIN$.
where (Network_Shares.share_name="*\\C$" OR Network_Shares.share_name="*\\ADMIN$")
// Group by the source, destination, user, and share to identify unique access patterns.
by Network_Shares.dest, Network_Shares.src, Network_Shares.user, Network_Shares.share_name
| rename "Network_Shares.*" as *
`comment("The following line is a placeholder for filtering false positives. Legitimate administrative activity, such as from IT helpdesk staff or system management tools (e.g., SCCM), frequently uses admin shares. Tune this search by filtering out known administrative source hosts and service accounts. Example: `| search NOT (src IN (SCCMSRV01, JUMPBOX01) OR user IN (domain\\admin_acct))`")`
`comment("To further increase fidelity, focus on workstation-to-workstation SMB admin share access, which is highly anomalous. This may require enriching events with asset information via a lookup. Example: `| lookup asset_lookup host as src OUTPUT is_server as src_is_server | lookup asset_lookup host as dest OUTPUT is_server as dest_is_server | where src_is_server=\"false\" AND dest_is_server=\"false\"`")`
// Format the output table for triage.
| table firstTime, lastTime, src, dest, user, share_name, count
| sort - count
```

### Registry Run Key Persistence
---
```sql
`comment("This detection rule identifies the creation or modification of registry run keys, a common persistence technique (T1547.001) used by threat actors like Salt Typhoon to ensure their malware executes on system startup.")`
tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.action=created OR Registry.action=modified)
// Filter for common registry paths used for persistence.
by Registry.dest, Registry.user, Registry.process_name, Registry.registry_path, Registry.registry_value_name, Registry.registry_value_data
| rename "Registry.*" as *
| where match(registry_path, "(?i)(CurrentVersion\\\\Run(Once)?|CurrentVersion\\\\Policies\\\\Explorer\\\\Run)$")
`comment("The following line is a placeholder for filtering false positives. Legitimate software installers and updaters frequently write to these keys. Tune this search by filtering out known good processes or specific registry values. Example: `| search NOT (process_name IN (msiexec.exe, trusted_updater.exe))`")`
`comment("To increase fidelity, you can also filter for suspicious data written to the key, such as scripts or LOLBins. Example: `| where match(registry_value_data, \"(?i)(mshta|rundll32|powershell|cscript|wscript|\\.vbs|\\.js)\")`")`
// Format the output table for triage.
| table firstTime, lastTime, dest, user, process_name, registry_path, registry_value_name, registry_value_data, count
| sort - count
```

### Windows Service Persistence
---
```sql
`comment("This detection rule identifies the creation of a new Windows Service using common command-line tools. This is a well-known persistence technique (T1543.003) used by threat actors like Salt Typhoon to maintain access to a compromised system.")`
tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
where (
    `comment("Detects service creation using the native sc.exe utility.")`
    (Processes.process_name="sc.exe" AND Processes.process="* create *")
    OR
    `comment("Detects service creation using the PowerShell New-Service cmdlet.")`
    (Processes.process_name IN ("powershell.exe", "pwsh.exe") AND Processes.process="*New-Service*")
)
by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| rename "Processes.*" as *
`comment("The following line is a placeholder for filtering false positives. Legitimate software installers and administrators frequently create services. Tune this search by filtering out known good parent processes (e.g., msiexec.exe, setup.exe, TrustedInstaller.exe) and administrative user accounts.")`
`comment("To increase fidelity, you can also filter for services where the binary path (binPath) points to an unusual location or is a LOLBin. Example: `| where match(process, \"(?i)binPath=.*(temp|users|public|appdata|programdata|rundll32|powershell|mshta)\")`")`
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process, count
| sort - count
```

### RAR for Data Staging
---
```sql
`comment("This detection rule identifies the use of rar.exe to compress and stage data in unusual or world-writable directories. This is a known data staging technique (T1074.001) used by threat actors like Salt Typhoon before exfiltration.")`
tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
where Processes.process_name IN ("rar.exe", "winrar.exe")
`comment("Looks for rar.exe command lines creating an archive in a suspicious, often world-writable, location like Public, ProgramData, or Temp folders.")`
AND (
    Processes.process like "%\\Users\\Public\\%"
    OR Processes.process like "%\\ProgramData\\%"
    OR Processes.process like "%\\Temp\\%"
    OR Processes.process like "%\\PerfLogs\\%"
)
by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| rename "Processes.*" as *
`comment("The following line is a placeholder for filtering false positives. While command-line RAR usage is uncommon for typical users, some scripts or power users might use it legitimately. Tune by filtering known user accounts or parent processes that are expected to perform such actions. Example: `| search NOT user IN (power_user_1)`")`
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process, count
| sort - count
```

### Domain Admin Group Recon
---
```sql
`comment("This detection rule identifies the enumeration of the 'Domain Admins' group using common command-line tools. This is a classic reconnaissance technique (T1069.002) used by threat actors like Salt Typhoon to identify high-privilege accounts.")`
tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
where
    (
        `comment("Detects enumeration via 'net group \"Domain Admins\" /domain'")`
        (Processes.process_name IN ("net.exe", "net1.exe") AND Processes.process like "%group%" AND Processes.process like "%Domain Admins%")
        OR
        `comment("Detects enumeration via PowerShell's 'Get-ADGroupMember' cmdlet")`
        (Processes.process_name IN ("powershell.exe", "pwsh.exe") AND Processes.process like "%Get-ADGroupMember%" AND Processes.process like "%Domain Admins%")
    )
by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| rename "Processes.*" as *
`comment("The following line is a placeholder for filtering false positives. Legitimate administrative or auditing activity may trigger this detection. Tune by filtering known administrative user accounts, source hosts, or parent processes. Example: `| search NOT (user IN (admin_user, audit_svc_acct) OR parent_process_name=\"monitoring_tool.exe\")`")`
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process, count
| sort - count
```