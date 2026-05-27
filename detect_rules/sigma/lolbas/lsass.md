### LSASS T1003.001

```pwsh
cmd.exe /c powershell -exec bypass -W hidden -nop -E rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 552 C:\Windows\Temp\vmware-vhost.dmp full
```

Sigma:

```yaml
title: Lsass Memory Dump via Comsvcs DLL
id: a49fa4d5-11db-418c-8473-1e014a8dd462
status: test
description: Detects adversaries leveraging the MiniDump export function from comsvcs.dll via rundll32 to perform a memory dump from lsass.
references:
    - https://twitter.com/shantanukhande/status/1229348874298388484
    - https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020-10-20
modified: 2023-11-29
tags:
    - attack.credential-access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        SourceImage|endswith: '\rundll32.exe'
        CallTrace|contains: 'comsvcs.dll'
    condition: selection
falsepositives:
    - Unknown
level: high

```

```yaml
title: Unusual Process Accessing LSASS Memory
id: 878f782b-dfc6-4f9a-9ab2-e373859d1091
status: experimental
description: Detects when a process, not on a list of known legitimate system or security processes, accesses the memory of the LSASS process with high privileges. This is a strong indicator of credential dumping attempts using tools like Mimikatz. The provided intelligence specifically highlights `rundll32.exe` as an example of an unusual process used for this purpose.
references:
author: RW
date: 2025-08-06
tags:
  - attack.t1003.001
  - attack.credential_access
logsource:
  product: windows
  category: process_access   # Primarily Sysmon Event ID 10
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
            # Medium comment: These access masks are commonly requested by credential dumping tools.
      - '0x1FFFFF'       # PROCESS_ALL_ACCESS
      - '0x1F0FFF'       # A common combination used by Mimikatz
      - '0x1410'       # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION
      - '0x1010'       # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
  filter_legit_processes:
        # Medium comment: Filter for legitimate processes that are known to access LSASS. This list should be customized for your environment.
    SourceImage|endswith:
      - '\MsMpEng.exe'       # Microsoft Defender
      - '\NisSrv.exe'       # Microsoft Network Realtime Inspection Service
      - '\svchost.exe'
      - '\wininit.exe'
      - '\csrss.exe'
      - '\procexp.exe'
      - '\procexp64.exe'
      - '\procmon.exe'
      - '\vmtoolsd.exe'
      - '\healthservice.exe'       # SCOM
      - '\MonitoringHost.exe'       # SCOM
      - '\dwm.exe'       # Desktop Window Manager
      - '\taskmgr.exe'       # Task Manager
      - '\WerFault.exe'       # Windows Error Reporting
      - '\WerFaultSecure.exe'
  condition: selection and not filter_legit_processes
falsepositives:
  - Legitimate security software (EDR, AV, vulnerability scanners) or system administration tools not included in the filter list may access LSASS memory for inspection. It is crucial to baseline and add legitimate tools from your environment to the filter list.
level: high
```