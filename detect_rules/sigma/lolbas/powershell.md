### PowerShell

    The actor has used the following PowerShell [T1059.001] command to identify successful logons to the host [T1033]:

```pwsh
Get-EventLog security -instanceid 4624
```

    Note: Event ID 4624 is logged when a user successfully logs on to a host and contains useful information such as the logon type (e.g., interactive or networking), associated user and computer account names, and the logon time. Event ID 4624 entries can be viewed in Windows Event Viewer by navigating to: Windows Logs | Security. PowerShell logs can be viewed in Event Viewer: Applications and Service Logs | Windows PowerShell. This command identifies what user account they are currently leveraging to access the network, identify other users logged on to the host, or identify how their actions are being logged. If the actor is using a password spray technique [T1110.003], there may be several failed logon (Event ID 4625) events for several different user accounts, followed by one or more successful logons (Event ID 4624) within a short period of time. This period may vary by actor but can range from a few seconds to a few minutes. If the actor is using brute force password attempts [T1110] against a single user account, there may be several Event ID 4625 entries for that account, followed by a successful logon Event ID 4624. Defenders should also look for abnormal account activity, such as logons outside of normal working hours and impossible time-anddistance logons (e.g., a user logging on from two geographically separated locations at the same time).

### sigma rule

```yaml
title: APT Succesful Logon on Host
id: ca23c06c-c6c9-49e8-9406-217f13fb0a38
status: experimental
description: Detects the PowerShell command to identify successful logons to the host.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a
author: _sim...
date:
tags:
    - attack.discovery
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\powershell.exe'
        - OriginalFileName: 'powershell.exe'
    selection_flag:
        CommandLine|contains: 'Get-EventLog'
    selection_key:
        CommandLine|contains:
            - 'Get-EventLog security -instanceid 4624'
            - 'Get-Eventlog security'
    condition: all of selection_*
falsepositives:
    - not known
level: high
```

Splunk:
```sql
index=* source="WinEventLog:*" AND ((Image="*\\powershell.exe" OR OriginalFileName="powershell.exe") AND CommandLine="*Get-EventLog*" AND (CommandLine="*Get-EventLog security -instanceid 4624*" OR CommandLine="*Get-Eventlog security*"))
```

MDE:
```sql
DeviceProcessEvents | where ((FolderPath endswith @'\powershell.exe' or InitiatingProcessVersionInfoOriginalFileName =~ @'powershell.exe' or ProcessVersionInfoOriginalFileName =~ @'powershell.exe') and ProcessCommandLine contains @'Get-EventLog' and (ProcessCommandLine contains @'Get-EventLog security -instanceid 4624' or ProcessCommandLine contains @'Get-Eventlog security'))
```
