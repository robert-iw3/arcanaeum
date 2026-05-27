### netsh

Enumeration netsh

```sh
netsh interface firewall show all

netsh interface portproxy show all

netsh interface portproxy show v4tov4

netsh firewall show all

netsh portproxy show v4tov4
```

### sigma rule

```yaml
title: Hunting Query APT Enumeration of the Environment
id: 4c49dc62-f519-4805-be9b-0389557091c7
status: experimental
description: Detects commands were used by the actor to enumerate the network topology [T1016], the active directory structure [T1069.002], and other information about the target environment [T1069.001] [T1082]
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a
author: _sim...
date:
tags:
    - attack.discovery
    - attack.attack.t1016 #System Network Configuration Discovery
    - attack.t1069.001 #Permission Groups Discovery: Local Groups
    - attack.t1069.002 #Permission Groups Discovery: Domain Groups
    - attack.t1082 #System Information Discovery
    - attack.t1047 #Windows Management Instrumentation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'ipconfig /all'
            - 'netsh interface show interface'
            - 'netsh interface firewall show all'
            - 'arp -a'
            - 'nbtstat -n'
            - 'net config'
            - 'net group /dom'
            - 'net group "Domain Admins" /dom'
            - 'route print'
            - 'curl www.ip-api.com'
            - 'dnscmd'
            - 'ldifde.exe -f c:\windows\temp\.txt -p subtree'
            - 'netlocalgroup'
            - 'netsh interface portproxy show'
            - 'netstat -ano'
            - 'reg query hklm\software\'
            - 'systeminfo'
            - 'tasklist /v '
            - 'wmic volume list brief'
            - 'wmic service brief'
            - 'wmic product list brief'
            - 'wmic baseboard list brief'
            - 'wevtutil qe security /rd:true /f:text /q:*[System[(EventID=4624) '
    condition: selection
falsepositives:
    - administration of the system
level: high
```

Splunk:

```sql
index=* source="WinEventLog:*" AND ((Image="*\\netsh.exe" OR OriginalFileName="netsh.exe") AND ((CommandLine="*netsh *") AND (CommandLine="*show *") AND (CommandLine="*firewall *") AND (CommandLine="*config *" OR CommandLine="*state *" OR CommandLine="*rule *" OR CommandLine="*name=all*")))
```

MDE:

```sql
DeviceProcessEvents | where ((FolderPath endswith @'\netsh.exe' or InitiatingProcessVersionInfoOriginalFileName =~ @'netsh.exe' or ProcessVersionInfoOriginalFileName =~ @'netsh.exe') and (ProcessCommandLine contains @'netsh ‘ and ProcessCommandLine contains @'show ‘ and ProcessCommandLine contains @'firewall ‘ and (ProcessCommandLine contains @'config ‘ or ProcessCommandLine contains @'state ‘ or ProcessCommandLine contains @'rule ‘ or ProcessCommandLine contains @'name=all')))
```