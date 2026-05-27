### Enumeration all

The following commands were used by the actor to enumerate the network topology [T1016], the active directory structure [T1069.002], and other information about the target environment [T1069.001], [T1082]:

```pwsh
arp -a

curl www.ip-api.com

dnscmd . /enumrecords /zone {REDACTED}

dnscmd . /enumzones

dnscmd /enumrecords {REDACTED} . /additional

ipconfig /all

ldifde.exe -f c:\windows\temp\.txt -p subtree

net localgroup administrators

net group /dom

net group “Domain Admins" /dom

netsh interface firewall show all

netsh interface portproxy show all

netsh interface portproxy show v4tov4

netsh firewall show all

netsh portproxy show v4tov4

netstat -ano

reg query hklm\software\ systeminfo tasklist /v

whoami

wmic volume list brief

wmic service brief

wmic product list brief

wmic baseboard list full

wevtutil qe security /rd:true /f:text /q:*[System[(EventID=4624) and TimeCreated[@SystemTime>='{REDACTED}']] and EventData[Data='{REDACTED}']]
```

Sigma:

```yaml
title: Hunting Query APT Enumeration of the Environment
id: 4c49dc62-f519-4805-be9b-0389557091c7
status: experimental
description: Detects commands were used by the actor to enumerate the network topology [T1016], the active directory structure [T1069.002], and other information about the target environment [T1069.001] [T1082]
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a
author: sim
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

MDE:
```sql
DeviceProcessEvents | where (ProcessCommandLine contains @'ipconfig /all' or ProcessCommandLine contains @'netsh interface show interface' or ProcessCommandLine contains @'netsh interface firewall show all' or ProcessCommandLine contains @'arp -a' or ProcessCommandLine contains @'nbtstat -n' or ProcessCommandLine contains @'net config' or ProcessCommandLine contains @'net group /dom' or ProcessCommandLine contains @'net group “Domain Admins" /dom' or ProcessCommandLine contains @'route print' or ProcessCommandLine contains @'curl www.ip-api.com' or ProcessCommandLine contains @'dnscmd' or ProcessCommandLine contains @'ldifde.exe -f c:\windows\temp\.txt -p subtree' or ProcessCommandLine contains @'netlocalgroup' or ProcessCommandLine contains @'netsh interface portproxy show' or ProcessCommandLine contains @'netstat -ano' or ProcessCommandLine contains @'reg query hklm\software\' or ProcessCommandLine contains @'systeminfo' or ProcessCommandLine contains @'tasklist /v ‘ or ProcessCommandLine contains @'wmic volume list brief' or ProcessCommandLine contains @'wmic service brief' or ProcessCommandLine contains @'wmic product list brief' or ProcessCommandLine contains @'wmic baseboard list brief' or ProcessCommandLine contains @'wevtutil qe security /rd:true /f:text /q:*[System[(EventID=4624) ‘)
```

Sigma:

```yaml
title: Suspicious Network Command
id: a29c1813-ab1f-4dde-b489-330b952e91ae
status: test
description: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1016/T1016.md#atomic-test-1---system-network-configuration-discovery-on-windows
author: frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
date: 2021-12-07
modified: 2022-04-11
tags:
    - attack.discovery
    - attack.t1016
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'ipconfig /all'
            - 'netsh interface show interface'
            - 'arp -a'
            - 'nbtstat -n'
            - 'net config'
            - 'route print'
    condition: selection
falsepositives:
    - Administrator, hotline ask to user
level: low
```

MDE
```sql
DeviceProcessEvents | where (ProcessCommandLine contains @'ipconfig /all' or ProcessCommandLine contains @'netsh interface show interface' or ProcessCommandLine contains @'arp -a' or ProcessCommandLine contains @'nbtstat -n' or ProcessCommandLine contains @'net config' or ProcessCommandLine contains @'route print')
```
