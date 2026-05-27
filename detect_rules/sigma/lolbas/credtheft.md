### Credential Theft

The actor also used the following commands to identify additional opportunities for obtaining credentials in the environment [T1555], [T1003]:

```pwsh
dir C:\Users\{REDACTED}\.ssh\known_hosts

dir

C:\users\{REDACTED}\appdata\roaming\Mozilla\firefox\profile s

mimikatz.exe

reg query hklm\software\OpenSSH

reg query hklm\software\OpenSSH\Agent

reg query hklm\software\realvnc

reg query hklm\software\realvnc\vncserver

reg query hklm\software\realvnc\Allusers

reg query hklm\software\realvnc\Allusers\vncserver

reg query hkcu\software\{REDACTED}\putty\session

reg save hklm\sam ss.dat

reg save hklm\system sy.dat
```

MDE
```sql
DeviceProcessEvents | where ((FolderPath endswith @'\reg.exe' or InitiatingProcessVersionInfoOriginalFileName =~ @'reg.exe' or ProcessVersionInfoOriginalFileName =~ @'reg.exe') and ProcessCommandLine contains @'save' and (ProcessCommandLine contains @'reg save hklm\sam ss.dat' or ProcessCommandLine contains @'reg save hklm\system sy.dat' or ProcessCommandLine contains @'reg save hklm\system' or ProcessCommandLine contains @'reg save hklm\sam'))
```


Sigma:

```yaml
title: APT Credential Theft Query Registry Software
id: 589d84ea-9ffc-4189-a4b4-94861ab4b6e5
status: experimental
description: Detects the usage of "reg.exe" in order to query information from the registry like software.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a
author: sim
date:
tags:
    - attack.discovery
    - attack.t1012
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\reg.exe'
        - OriginalFileName: 'reg.exe'
    selection_flag:
        CommandLine|contains: 'query'
    selection_key:
        CommandLine|contains:
            - 'reg query hklm\software\OpenSSH'
            - 'reg query hklm\software\OpenSSH\Agent'
            - 'reg query hklm\software\realvnc'
            - 'reg query hklm\software\realvnc\vncserver'
            - 'reg query hklm\software\realvnc\Allusers'
            - 'reg query hklm\software\realvnc\Allusers\vncserver'
            - 'reg query hkcu\software\*\putty\session'
    condition: all of selection_*
falsepositives:
    - not known
level: high
```

MDE:
```sql
DeviceProcessEvents | where ((FolderPath endswith @'\reg.exe' or InitiatingProcessVersionInfoOriginalFileName =~ @'reg.exe' or ProcessVersionInfoOriginalFileName =~ @'reg.exe') and ProcessCommandLine contains @'query' and (ProcessCommandLine contains @'reg query hklm\software\OpenSSH' or ProcessCommandLine contains @'reg query hklm\software\OpenSSH\Agent' or ProcessCommandLine contains @'reg query hklm\software\realvnc' or ProcessCommandLine contains @'reg query hklm\software\realvnc\vncserver' or ProcessCommandLine contains @'reg query hklm\software\realvnc\Allusers' or ProcessCommandLine contains @'reg query hklm\software\realvnc\Allusers\vncserver' or ProcessCommandLine contains @'reg query hkcu\software\*\putty\session'))
```


Sigma:

```yaml
title: Exports Critical Registry Keys To a File
id: 82880171-b475-4201-b811-e9c826cd5eaa
related:
    - id: f0e53e89-8d22-46ea-9db5-9d4796ee2f8a
      type: similar
status: test
description: Detects the export of a crital Registry key to a file.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Regedit/
    - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
author: Oddvar Moe, Sander Wiebing, oscd.community
date: 2020-10-12
modified: 2024-03-13
tags:
    - attack.exfiltration
    - attack.discovery
    - attack.t1012
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\regedit.exe'
        - OriginalFileName: 'REGEDIT.EXE'
    selection_cli_1:
        CommandLine|contains|windash: ' -E '
    selection_cli_2:
        CommandLine|contains:
            - 'hklm'
            - 'hkey_local_machine'
    selection_cli_3:
        CommandLine|endswith:
            - '\system'
            - '\sam'
            - '\security'
    condition: all of selection_*
fields:
    - ParentImage
    - CommandLine
falsepositives:
    - Dumping hives for legitimate purpouse i.e. backup or forensic investigation
level: high
```


MDE:
```sql
DeviceProcessEvents | where (FolderPath endswith @'\regedit.exe' and (ProcessCommandLine contains @' /E ‘ or ProcessCommandLine contains @' -E ‘) and (ProcessCommandLine contains @'hklm' or ProcessCommandLine contains @'hkey_local_machine') and (ProcessCommandLine endswith @'\system' or ProcessCommandLine endswith @'\sam' or ProcessCommandLine endswith @'\security'))
```

