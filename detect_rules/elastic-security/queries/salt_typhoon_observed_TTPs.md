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
from * | where process.name IN ("bitsadmin.exe", "certutil.exe", "powershell.exe")
  and (
    (process.name == "bitsadmin.exe" and (process.command_line like "*/transfer*" OR process.command_line like "*/create*" OR process.command_line like "*/addfile*"))
    OR
    (process.name == "certutil.exe" and (process.command_line like "*-urlcache*" OR process.command_line like "*-f*" OR process.command_line like "*-split*" OR process.command_line like "*-encode*" OR process.command_line like "*-decode*"))
    OR
    (process.name == "powershell.exe" and (process.command_line like "*-enc*" OR process.command_line like "*-encodedcommand*" OR process.command_line like "*IEX*" OR process.command_line like "*Invoke-Expression*" OR process.command_line like "*Hidden*"))
  )
| stats COUNT, MIN(@timestamp) AS firstTime, MAX(@timestamp) AS lastTime
  BY host.name, user.name, process.parent.name, process.name, process.command_line
| rename host.name AS dest, user.name AS user, process.parent.name AS parent_process_name, process.name AS process_name, process.command_line AS process
| sort COUNT desc
```

### WMI/PsExec for Lateral Movement
---
```sql
from *
| where (
    (process.name == "psexec.exe" and process.command_line like "*\\\\*")
    OR
    (process.name == "psexesvc.exe" and process.parent.name == "services.exe")
    OR
    (process.name == "wmic.exe" and (process.command_line like "*/node:*" OR process.command_line like "*process call create*"))
    OR
    (process.parent.name == "WmiPrvSE.exe")
  )
| stats COUNT, MIN(@timestamp) AS firstTime, MAX(@timestamp) AS lastTime
  BY host.name, user.name, process.parent.name, process.name, process.command_line
| rename host.name AS dest, user.name AS user, process.parent.name AS parent_process_name, process.name AS process_name, process.command_line AS process
| sort COUNT desc
```

### SMB for Lateral Movement
---
```sql
from *
| where network.share.name like "*\\C$" OR network.share.name like "*\\ADMIN$"
| stats COUNT, MIN(@timestamp) AS firstTime, MAX(@timestamp) AS lastTime
  BY destination.ip, source.ip, user.name, network.share.name
| rename destination.ip AS dest, source.ip AS src, user.name AS user, network.share.name AS share_name
| sort COUNT desc
```

### Registry Run Key Persistence
---
```sql
from *
| where registry.action IN ("created", "modified")
  and registry.path Rlike "(?i).*(CurrentVersion\\\\Run(Once)?|CurrentVersion\\\\Policies\\\\Explorer\\\\Run)$"
| stats COUNT, MIN(@timestamp) AS firstTime, MAX(@timestamp) AS lastTime
  BY host.name, user.name, process.name, registry.path, registry.value.name, registry.value.data
| rename host.name AS dest, user.name AS user, process.name AS process_name, registry.path AS registry_path, registry.value.name AS registry_value_name, registry.value.data AS registry_value_data
| sort COUNT desc
```

### Windows Service Persistence
---
```sql
from *
| where (
    (process.name == "sc.exe" and process.command_line like "*create*")
    OR
    (process.name IN ("powershell.exe", "pwsh.exe") and process.command_line like "*New-Service*")
  )
| stats COUNT, MIN(@timestamp) AS firstTime, MAX(@timestamp) AS lastTime
  BY host.name, user.name, process.parent.name, process.name, process.command_line
| rename host.name AS dest, user.name AS user, process.parent.name AS parent_process_name, process.name AS process_name, process.command_line AS process
| sort COUNT desc
```

### RAR for Data Staging
---
```sql
from *
| where process.name IN ("rar.exe", "winrar.exe")
  and (
    process.command_line like "*\\Users\\Public\\*"
    OR process.command_line like "*\\ProgramData\\*"
    OR process.command_line like "*\\Temp\\*"
    OR process.command_line like "*\\PerfLogs\\*"
  )
| stats COUNT, MIN(@timestamp) AS firstTime, MAX(@timestamp) AS lastTime
  BY host.name, user.name, process.parent.name, process.name, process.command_line
| rename host.name AS dest, user.name AS user, process.parent.name AS parent_process_name, process.name AS process_name, process.command_line AS process
| sort COUNT desc
```

### Domain Admin Group Recon
---
```sql
from *
| where (
    (process.name IN ("net.exe", "net1.exe") and process.command_line like "*group*" and process.command_line like "*Domain Admins*")
    OR
    (process.name IN ("powershell.exe", "pwsh.exe") and process.command_line like "*Get-ADGroupMember*" and process.command_line like "*Domain Admins*")
  )
| stats COUNT, MIN(@timestamp) AS firstTime, MAX(@timestamp) AS lastTime
  BY host.name, user.name, process.parent.name, process.name, process.command_line
| rename host.name AS dest, user.name AS user, process.parent.name AS parent_process_name, process.name AS process_name, process.command_line AS process
| sort COUNT desc
```