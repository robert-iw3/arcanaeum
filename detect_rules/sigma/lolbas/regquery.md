### req query/save

Sigma Rule — APT Credential Theft Query Registry Software

```yaml
title: APT Credential Theft Query Registry Software
id: 589d84ea-9ffc-4189-a4b4-94861ab4b6e5
status: experimental
description: Detects the usage of "reg.exe" in order to query information from the registry like software.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a
author: _sim...
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

Sigma Rule — APT Credential Theft Save Registry SAM and SYSTEM

```yaml
title: APT Credential Theft Save Registry SAM and System
id: ea519d6b-0daf-4b9c-b258-cfa5f482bd79
status: experimental
description: Detects the usage of "reg.exe" in order to save registry sam and system.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a
author: _sim...
date:
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\reg.exe'
        - OriginalFileName: 'reg.exe'
    selection_flag:
        CommandLine|contains: 'save'
    selection_key:
        CommandLine|contains:
            - 'reg save hklm\sam ss.dat'
            - 'reg save hklm\system sy.dat'
            - 'reg save hklm\system'
            - 'reg save hklm\sam'
    condition: all of selection_*
falsepositives:
    - not known
level: high
```

