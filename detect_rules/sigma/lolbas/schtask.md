### Schtask

    State-sponsored cyber actors have been observed using Cobalt Strike, webshells, or command line interface tools, such as schtask or crontab to create and schedule tasks that enumerate victim devices and networks. Note: this technique also applies to Persistence [TA0003] and Privilege Escalation [TA0004]. Monitor scheduled task creation from common utilities using command-line invocation and compare for any changes that do not correlate with known software, patch cycles, or other administrative activity. Configure event logging for scheduled task creation and monitor process execution from svchost.exe (Windows 10) and Windows Task Scheduler (Older version of Windows) to look for changes in %systemroot%\System32\Tasks that do not correlate with known software, patch cycles, or other administrative activity. Additionally monitor for any scheduled tasks created via command line utilities — such as PowerShell or Windows Management Instrumentation (WMI) — that do not conform to typical administrator or user actions.

Sigma:

```yaml
title: Scheduled Task Creation Via Schtasks.EXE
id: 92626ddd-662c-49e3-ac59-f6535f12d189
status: test
description: Detects the creation of scheduled tasks by user accounts via the "schtasks" utility.
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create
author: Florian Roth (Nextron Systems)
date: 2019-01-16
modified: 2024-01-18
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1053.005
    - attack.s0111
    - car.2013-08-001
    - stp.1u
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: ' /create '
    filter_main_system_user:
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Administrative activity
    - Software installation
level: low

```

MDE:
```sql
DeviceProcessEvents | where ((FolderPath endswith @'\schtasks.exe' and ProcessCommandLine contains @' /create ‘) and not (((InitiatingProcessAccountName contains @'AUTHORI' or InitiatingProcessAccountName contains @'AUTORI') or (InitiatingProcessAccountDomain contains @'AUTHORI' or InitiatingProcessAccountDomain contains @'AUTORI'))))
```

Sigma:

```yaml
title: Scheduled Task Executed Uncommon LOLBIN
id: f0767f15-0fb3-44b9-851e-e8d9a6d0005d
status: test
description: Detects the execution of Scheduled Tasks where the program being run is located in a suspicious location or where it is an unusual program to be run from a Scheduled Task
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-05
modified: 2023-02-07
tags:
    - attack.persistence
    - attack.t1053.005
logsource:
    product: windows
    service: taskscheduler
    definition: 'Requirements: The "Microsoft-Windows-TaskScheduler/Operational" is disabled by default and needs to be enabled in order for this detection to trigger'
detection:
    selection:
        EventID: 129 # Created Task Process
        Path|endswith:
            - '\calc.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\mspaint.exe'
            - '\notepad.exe'
            - '\regsvr32.exe'
            # - '\rundll32.exe'
            - '\wscript.exe'
    # filter_system:
    #     Path|endswith: '\rundll32.exe'
    #     TaskName|startswith: '\Microsoft\Windows\'
    # condition: selection and not 1 of filter_*
    condition: selection
falsepositives:
    - False positives may occur with some of the selected binaries if you have tasks using them (which could be very common in your environment). Exclude all the specific trusted tasks before using this rule
level: medium

```


Sigma:

```yaml
title: Scheduled Task Executing Encoded Payload from Registry
id: c4eeeeae-89f4-43a7-8b48-8d1bdfa66c78
status: test
description: Detects the creation of a schtask that potentially executes a base64 encoded payload stored in the Windows Registry using PowerShell.
references:
    - https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/
author: pH-T (Nextron Systems), @Kostastsale, TheDFIRReport, X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022-02-12
modified: 2023-02-04
tags:
    - attack.execution
    - attack.persistence
    - attack.t1053.005
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        # schtasks.exe /Create /F /TN "{97F2F70B-10D1-4447-A2F3-9B070C86E261}" /TR "cmd /c start /min \"\" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\SOFTWARE\Pvoeooxf).yzbbvhhdypa))) " /SC MINUTE /MO 30
        - Image|endswith: '\schtasks.exe'
        - OriginalFileName: 'schtasks.exe'
    selection_cli_create:
        CommandLine|contains: '/Create'
    selection_cli_encoding:
        CommandLine|contains:
            - 'FromBase64String'
            - 'encodedcommand'
    selection_cli_get:
        CommandLine|contains:
            - 'Get-ItemProperty'
            - ' gp ' # Alias
    selection_cli_hive:
        CommandLine|contains:
            - 'HKCU:'
            - 'HKLM:'
            - 'registry::'
            - 'HKEY_'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high

```

MDE
```sql
DeviceProcessEvents | where ((FolderPath endswith @'\schtasks.exe' or InitiatingProcessVersionInfoOriginalFileName =~ @'schtasks.exe' or ProcessVersionInfoOriginalFileName =~ @'schtasks.exe') and ProcessCommandLine contains @'/Create' and (ProcessCommandLine contains @'FromBase64String' or ProcessCommandLine contains @'encodedcommand') and (ProcessCommandLine contains @'Get-ItemProperty' or ProcessCommandLine contains @' gp ‘) and (ProcessCommandLine contains @'HKCU:' or ProcessCommandLine contains @'HKLM:' or ProcessCommandLine contains @'registry::' or ProcessCommandLine contains @'HKEY_'))
```

Sigma:

```yaml
title: Schtasks From Suspicious Folders
id: 8a8379b8-780b-4dbf-b1e9-31c8d112fefb
status: test
description: Detects scheduled task creations that have suspicious action command and folder combinations
references:
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/lazarus-dream-job-chemical
author: Florian Roth (Nextron Systems)
date: 2022-04-15
modified: 2022-11-18
tags:
    - attack.execution
    - attack.t1053.005
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\schtasks.exe'
        - OriginalFileName: 'schtasks.exe'
    selection_create:
        CommandLine|contains: ' /create '
    selection_command:
        CommandLine|contains:
            - 'powershell'
            - 'pwsh'
            - 'cmd /c '
            - 'cmd /k '
            - 'cmd /r '
            - 'cmd.exe /c '
            - 'cmd.exe /k '
            - 'cmd.exe /r '
    selection_all_folders:
        CommandLine|contains:
            - 'C:\ProgramData\'
            - '%ProgramData%'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```

MDE:
```sql
DeviceProcessEvents | where ((FolderPath endswith @'\schtasks.exe' or InitiatingProcessVersionInfoOriginalFileName =~ @'schtasks.exe' or ProcessVersionInfoOriginalFileName =~ @'schtasks.exe') and ProcessCommandLine contains @' /create ‘ and (ProcessCommandLine contains @'powershell' or ProcessCommandLine contains @'pwsh' or ProcessCommandLine contains @'cmd /c ‘ or ProcessCommandLine contains @'cmd /k ‘ or ProcessCommandLine contains @'cmd /r ‘ or ProcessCommandLine contains @'cmd.exe /c ‘ or ProcessCommandLine contains @'cmd.exe /k ‘ or ProcessCommandLine contains @'cmd.exe /r ‘) and (ProcessCommandLine contains @'C:\ProgramData\' or ProcessCommandLine contains @'%ProgramData%'))
```

