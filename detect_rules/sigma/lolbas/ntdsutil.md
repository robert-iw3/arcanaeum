### Ntdsutil.exe

    The actor may try to exfiltrate the ntds.dit file and the SYSTEM registry hive from Windows domain controllers (DCs) out of the network to perform password cracking [T1003.003]. (The ntds.dit file is the main Active Directory (AD) database file and, by default, is stored at %SystemRoot%\NTDS\ntds.dit. This file contains information about users, groups, group memberships, and password hashes for all users in the domain; the SYSTEM registry hive contains the boot key that is used to encrypt information in the ntds.dit file.) Although the ntds.dit file is locked while in use by AD, a copy can be made by creating a Volume Shadow Copy and extracting the ntds.dit file from the Shadow Copy. The SYSTEM registry hive may also be obtained from the Shadow Copy. The following example commands show the actor creating a Shadow Copy and then extracting a copy of the ntds.dit file from it

```pwsh
cmd /c vssadmin create shadow /for=C: > C:\Windows\Temp\.tmp

cmd /c copy

\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\Windows\NTD S\ntds.dit C:\Windows\Temp > C:\Windows\Temp\.tmp
```

Sigma:

```yaml
title: Shadow Copies Creation Using Operating Systems Utilities
id: b17ea6f7-6e90-447e-a799-e6c0a493d6ce
status: test
description: Shadow Copies creation using operating systems utilities, possible credential access
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
    - https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/tutorial-for-ntds-goodness-vssadmin-wmis-ntdsdit-system/
author: Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
date: 2019-10-22
modified: 2022-11-10
tags:
    - attack.credential-access
    - attack.t1003
    - attack.t1003.002
    - attack.t1003.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\powershell.exe'
              - '\pwsh.exe'
              - '\wmic.exe'
              - '\vssadmin.exe'
        - OriginalFileName:
              - 'PowerShell.EXE'
              - 'pwsh.dll'
              - 'wmic.exe'
              - 'VSSADMIN.EXE'
    selection_cli:
        CommandLine|contains|all:
            - 'shadow'
            - 'create'
    condition: all of selection_*
falsepositives:
    - Legitimate administrator working with shadow copies, access for backup purposes
level: medium
```



MDE:
```sql
DeviceProcessEvents | where (((FolderPath endswith @'\powershell.exe' or FolderPath endswith @'\pwsh.exe' or FolderPath endswith @'\wmic.exe' or FolderPath endswith @'\vssadmin.exe') or InitiatingProcessVersionInfoOriginalFileName in~ (@'PowerShell.EXE', @'pwsh.dll', @'wmic.exe', @'VSSADMIN.EXE') or ProcessVersionInfoOriginalFileName in~ (@'PowerShell.EXE', @'pwsh.dll', @'wmic.exe', @'VSSADMIN.EXE')) and (ProcessCommandLine contains @'shadow' and ProcessCommandLine contains @'create'))
```

    The built-in Ntdsutil.exe tool performs all these actions using a single command. There are several ways to execute Ntdsutil.exe, including running from an elevated command prompt (cmd.exe), using WMI/WMIC, or PowerShell. Defenders should look for the execution of Ntdsutil.exe commands using long, short, or a combination of the notations. For example, the long notation command activate instance ntds ifm can also be executed using the short notation ac i ntds i. Table 1 provides the long and short forms of the arguments used in the sample Ntdsutil.exe command, along with a brief description of the arguments.


Ntdsutil.exe creates two subfolders in the directory specified in the command: an Active Directory folder that contains the ntds.dit and ntds.jfm files, and a registry folder that contains the SYSTEM and SECURITY hives. Defenders should look for this folder structure across their network. Please read also my article Sensor Mappings to ATT&CK (SMAP) — a concrete example of how to use the SMAP for a real world adversary behavior to get a deep technical understanding about it how threat actor abuse ntds.dit and ntdsutil and how you can prevent and detect it.

```pwsh
\Active Directory\ntds.dit \

Active Directory\ntds.jfm

\registry\SECURITY

\registry\SYSTEM
```

    When one of the example commands is executed, several successive log entries are created in the Application log, under the ESENT Source. Associated events can be viewed in Windows Event Viewer by navigating to: Windows Logs | Application. To narrow results to relevant events, select Filter Current Log from the Actions menu on the right side of the screen. In the Event sources dropdown, check the box next to ESENT, then limit the logs to ID numbers 216, 325, 326, and 327. Clicking the OK box will apply the filters to the results. Since ESENT logging is used extensively throughout Windows, defenders should focus on events that reference ntds.dit. If such events are present, the events' details should contain the file path where the file copies were created. Since these files can be deleted, or enhanced logging may not be configured on hosts, the file path can greatly aid in a hunt operation. Identifying the user associated with this activity is also a critical step in a hunt operation as other actions by the compromised — or actor-created — user account can be helpful to understand additional actor TTPs, as well as the breadth of the actor's actions.

    Note: If an actor can exfiltrate the ntds.dit and SYSTEM registry hive, the entire domain should be considered compromised, as the actor will generally be able to crack the password hashes for domain user accounts, create their own accounts, and/or join unauthorized systems to the domain. If this occurs, defenders should follow guidance for removing malicious actors from victim networks, such as CISA's Eviction Guidance for Network Affected by the SolarWinds and Active Directory/M365 Compromise. In addition to the above TTPs used by the actor to copy the ntds.dit file, the following tools could be used by an actor to obtain the same information:

Secretsdump.py

This script is a component of Impacket, which the actor has been known to use

· Invoke-NinjaCopy (PowerShell)

· DSInternals (PowerShell)

· FgDump

· Metasploit

If you don't use such tools, the recommendation would be to block them as a great opportunity to set choke points.

Sigma:

```yaml
title: Possible Impacket SecretDump Remote Activity
id: 252902e3-5830-4cf6-bf21-c22083dfd5cf
status: test
description: Detect AD credential dumping using impacket secretdump HKTL
references:
    - https://web.archive.org/web/20230329153811/https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html
author: Samir Bousseaden, wagga
date: 2019-04-03
modified: 2022-08-11
tags:
    - attack.credential-access
    - attack.t1003.002
    - attack.t1003.004
    - attack.t1003.003
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: '\\\\\*\\ADMIN$'  # looking for the string  \\*\ADMIN$
        RelativeTargetName|contains|all:
            - 'SYSTEM32\'
            - '.tmp'
    condition: selection
falsepositives:
    - Unknown
level: high
```


Best practices for securing ntds.dit include hardening Domain Controllers and monitoring event logs for ntdsutil.exe and similar process creations. Additionally, any use of administrator privileges should be audited and validated to confirm the legitimacy of executed commands.

### Data Sources for NTDS.dit

Command Execution

    Monitor executed commands and arguments that may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights. Look for command-lines that invoke attempts to access or copy the NTDS.dit.

    Note: Events 4688 (Microsoft Windows Security Auditing) and 1 (Microsoft Windows Sysmon) provide context of commands and parameters being executed via creation of a new process. Event 800 (PowerShell) provides context of commands and parameters being executed via PowerShell. This detection is based on known Windows utilities commands and parameters that can be used to copy the ntds.dit file. It is recommended to keep the list of commands and parameters up to date.

Analytic 1 — Command line attempt to access or create a copy of ntds.dit file

`suspicious_command = filter command_execution where ( (event_id = “4688" OR event_id = “1" OR event_id = “800") AND ((command_line = “*ntds*" AND command_line = “*ntdsutil*" AND command_line = “*create*") OR (command_line = “**vssadmin" AND command_line = “*create*" AMD command_line = “*shadow*") OR (command_line = “*copy*" AND command_line = “*ntds.dit*")) `

### File Access

Monitor for access or copy of the NTDS.dit.

    Note: Events 4656 and 4663 (Microsoft Windows Security Auditing) provide context of processes and users requesting access or accessing file objects (ObjectType = File) such as C:\Windows\NTDS\ntds.dit. It is important to note that, in order to generate these events, a System Access Control List (SACL) must be defined for the ntds.dit file. Access rights that allow read operations on file objects and its attributes are %%4416 Read file data, %%4419 Read extended file attributes, %%4423 Read file attributes. If you search for just the name of the file and not the entire directory, you may get access events related to the ntds.dit file within a snapshot or volume shadow copy.

    Events 4656 and 4663 (Microsoft Windows Security Auditing) provide context of processes and users creating or copying file objects (ObjectType = File) such as C:\Windows\NTDS\ntds.dit. It is important to note that, in order to generate these events, a System Access Control List (SACL) must be defined for the ntds.dit file. In order to filter file creation events, filter access rigths %%4417 Write data to the file and %%4424 Write file attributes.

    Event 11 (Microsoft Windows Sysmon) provide context of processes and users creating or copying files. Unfortunately, this event provides context of the file being created or copied, but not the file being copied. A good starting point would be to look for new files created or copied with extension .dit.

Analytic 1

`suspicious_file = filter file_access where ((event_id = “4656" OR event_id = “4663") AND (object_type = “File") AND (file_name = “*ntds.dit*") AND (access_list = “*%%4416*" OR access_list = “*%%4419*" OR access_list = “*%%4416*")`

Analytic 2

`suspicious_file = filter file_access where ((event_id = “4656" OR event_id = “4663") AND (object_type = “File") AND (file_name = “*ntds.dit*") AND (access_list = “*%%4417*" OR access_list = “*%%4424*")`

Analytic 3

`suspicious_file = filter file_access where ((event_id = “11") AND (file_name = “*.dit") `

Sigma:

```yaml
title: NTDS.DIT Created
id: 0b8baa3f-575c-46ee-8715-d6f28cc7d33c
status: test
description: Detects creation of a file named "ntds.dit" (Active Directory Database)
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-05
tags:
    - attack.credential-access
    - attack.t1003.003
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: 'ntds.dit'
    condition: selection
falsepositives:
    - Unknown
level: low
```

Hunting Translation Microsoft Defender — Keep it simple
```sql
DeviceFileEvents | where FolderPath endswith @'ntds.dit'
```

