### Windows Management Instrumentation WMI/WMIC

Windows management instrumentation (WMI/WMIC) The actor has executed the following command to gather information about local drives [T1082]:

```pwsh
cmd.exe /C “wmic path win32_logicaldisk get caption,filesystem,freespace,size,volumename"
```

    This command does not require administrative credentials to return results. The command uses a command prompt [T1059.003] to execute a Windows Management Instrumentation Command Line (WMIC) query, collecting information about the storage devices on the local host, including drive letter, file system (e.g., new technology file system [NTFS]), free space and drive size in bytes, and an optional volume name. Windows Management Instrumentation (WMI) is a built-in Windows tool that allows a user to access management information from hosts in an enterprise environment. The command line version of WMI is called WMIC. By default, WMI Tracing is not enabled, so the WMI commands being executed and the associated user might not be available. Additional information on WMI events and tracing can be found in the References section of the advisory.

    The actor has executed WMIC commands [T1047] to create a copy of the ntds.dit file and SYSTEM registry hive using ntdsutil.exe. Each of the following actor commands is a standalone example; multiple examples are provided to show how syntax and file paths may differ per environment.

```pwsh
wmic process call create “ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\pro

wmic process call create “cmd.exe /c ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\Pro"

wmic process call create “cmd.exe /c mkdir C:\Windows\Temp\tmp & ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\tmp\"

“cmd.exe" /c wmic process call create “cmd.exe /c mkdir C:\windows\Temp\McAfee_Logs & ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\McAfee_Logs\"

cmd.exe /Q /c wmic process call create “cmd.exe /c mkdir C:\Windows\Temp\tmp & ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\tmp\" 1> \\127.0.0.1\ADMIN$\ 2>&1
```

Sigma:

```yaml
title: Suspicious Process Patterns NTDS.DIT Exfil
id: 8bc64091-6875-4881-aaf9-7bd25b5dda08
status: test
description: Detects suspicious process patterns used in NTDS.DIT exfiltration
references:
    - https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration
    - https://www.n00py.io/2022/03/manipulating-user-passwords-without-mimikatz/
    - https://pentestlab.blog/tag/ntds-dit/
    - https://github.com/samratashok/nishang/blob/414ee1104526d7057f9adaeee196d91ae447283e/Gather/Copy-VSS.ps1
    - https://github.com/zcgonvh/NTDSDumpEx
    - https://github.com/rapid7/metasploit-framework/blob/d297adcebb5c1df6fe30b12ca79b161deb71571c/data/post/powershell/NTDSgrab.ps1
    - https://blog.talosintelligence.com/2022/08/recent-cyber-attack.html?m=1
author: Florian Roth (Nextron Systems)
date: 2022-03-11
modified: 2022-11-10
tags:
    - attack.credential-access
    - attack.t1003.003
logsource:
    product: windows
    category: process_creation
detection:
    selection_tool:
        # https://github.com/zcgonvh/NTDSDumpEx
        - Image|endswith:
              - '\NTDSDump.exe'
              - '\NTDSDumpEx.exe'
        - CommandLine|contains|all:
              # ntdsdumpex.exe -d ntds.dit -o hash.txt -s system.hiv
              - 'ntds.dit'
              - 'system.hiv'
        - CommandLine|contains: 'NTDSgrab.ps1'
    selection_oneliner_1:
        # powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"
        CommandLine|contains|all:
            - 'ac i ntds'
            - 'create full'
    selection_onliner_2:
        # cmd.exe /c copy z:\windows\ntds\ntds.dit c:\exfil\ntds.dit
        CommandLine|contains|all:
            - '/c copy '
            - '\windows\ntds\ntds.dit'
    selection_onliner_3:
        # ntdsutil "activate instance ntds" "ifm" "create full c:\windows\temp\data\" "quit" "quit"
        CommandLine|contains|all:
            - 'activate instance ntds'
            - 'create full'
    selection_powershell:
        CommandLine|contains|all:
            - 'powershell'
            - 'ntds.dit'
    set1_selection_ntds_dit:
        CommandLine|contains: 'ntds.dit'
    set1_selection_image_folder:
        - ParentImage|contains:
              - '\apache'
              - '\tomcat'
              - '\AppData\'
              - '\Temp\'
              - '\Public\'
              - '\PerfLogs\'
        - Image|contains:
              - '\apache'
              - '\tomcat'
              - '\AppData\'
              - '\Temp\'
              - '\Public\'
              - '\PerfLogs\'
    condition: 1 of selection* or all of set1*
falsepositives:
    - Unknown
level: high
```

MDE:
```sql
DeviceProcessEvents | where ((((FolderPath endswith @'\NTDSDump.exe' or FolderPath endswith @'\NTDSDumpEx.exe') or (ProcessCommandLine contains @'ntds.dit' and ProcessCommandLine contains @'system.hiv') or ProcessCommandLine contains @'NTDSgrab.ps1') or (ProcessCommandLine contains @'ac i ntds' and ProcessCommandLine contains @'create full') or (ProcessCommandLine contains @'/c copy ‘ and ProcessCommandLine contains @'\windows\ntds\ntds.dit') or (ProcessCommandLine contains @'activate instance ntds' and ProcessCommandLine contains @'create full') or (ProcessCommandLine contains @'powershell' and ProcessCommandLine contains @'ntds.dit')) or (ProcessCommandLine contains @'ntds.dit' and ((InitiatingProcessFolderPath contains @'\apache' or InitiatingProcessFolderPath contains @'\tomcat' or InitiatingProcessFolderPath contains @'\AppData\' or InitiatingProcessFolderPath contains @'\Temp\' or InitiatingProcessFolderPath contains @'\Public\' or InitiatingProcessFolderPath contains @'\PerfLogs\') or (FolderPath contains @'\apache' or FolderPath contains @'\tomcat' or FolderPath contains @'\AppData\' or FolderPath contains @'\Temp\' or FolderPath contains @'\Public\' or FolderPath contains @'\PerfLogs\'))))
```


    Note: The would be an epoch timestamp following the format like “__1684956600.123456". Each actor command above creates a copy of the ntds.dit database and the SYSTEM and SECURITY registry hives in the C:\Windows\Temp\ directory, where is replaced with the path specified in the command (e.g., pro, tmp, or McAfee_Logs). By default, the hidden ADMIN$ share is mapped to C:\Windows\, so the last command will direct standard output and error messages from the command to a file within the folder specified. The actor has also saved the files directly to the C:\Windows\Temp and C:\Users\Public directories, so the entirety of those directory structures should be analyzed.

Sigma:

```yaml
title: NTDS.DIT Creation By Uncommon Parent Process
id: 4e7050dd-e548-483f-b7d6-527ab4fa784d
related:
    - id: 11b1ed55-154d-4e82-8ad7-83739298f720
      type: similar
status: test
description: Detects creation of a file named "ntds.dit" (Active Directory Database) by an uncommon parent process or directory
references:
    - https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration
    - https://www.n00py.io/2022/03/manipulating-user-passwords-without-mimikatz/
    - https://pentestlab.blog/tag/ntds-dit/
    - https://github.com/samratashok/nishang/blob/414ee1104526d7057f9adaeee196d91ae447283e/Gather/Copy-VSS.ps1
author: Florian Roth (Nextron Systems)
date: 2022-03-11
modified: 2023-01-05
tags:
    - attack.credential-access
    - attack.t1003.003
logsource:
    product: windows
    category: file_event
    definition: 'Requirements: The "ParentImage" field is not available by default on EID 11 of Sysmon logs. To be able to use this rule to the full extent you need to enrich the log with additional ParentImage data'
detection:
    selection_file:
        TargetFilename|endswith: '\ntds.dit'
    selection_process_parent:
        # Note: ParentImage is a custom field and is not available by default on Sysmon EID 11
        ParentImage|endswith:
            - '\cscript.exe'
            - '\httpd.exe'
            - '\nginx.exe'
            - '\php-cgi.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\w3wp.exe'
            - '\wscript.exe'
    selection_process_parent_path:
        # Note: ParentImage is a custom field and is not available by default on Sysmon EID 11
        ParentImage|contains:
            - '\apache'
            - '\tomcat'
            - '\AppData\'
            - '\Temp\'
            - '\Public\'
            - '\PerfLogs\'
    condition: selection_file and 1 of selection_process_*
falsepositives:
    - Unknown
level: high
```


MDE:
```sql
DeviceFileEvents | where (FolderPath endswith @'\ntds.dit' and ((InitiatingProcessFolderPath endswith @'\cscript.exe' or InitiatingProcessFolderPath endswith @'\httpd.exe' or InitiatingProcessFolderPath endswith @'\nginx.exe' or InitiatingProcessFolderPath endswith @'\php-cgi.exe' or InitiatingProcessFolderPath endswith @'\powershell.exe' or InitiatingProcessFolderPath endswith @'\pwsh.exe' or InitiatingProcessFolderPath endswith @'\w3wp.exe' or InitiatingProcessFolderPath endswith @'\wscript.exe') or (InitiatingProcessFolderPath contains @'\apache' or InitiatingProcessFolderPath contains @'\tomcat' or InitiatingProcessFolderPath contains @'\AppData\' or InitiatingProcessFolderPath contains @'\Temp\' or InitiatingProcessFolderPath contains @'\Public\' or InitiatingProcessFolderPath contains @'\PerfLogs\')))
```

MDE 2:
```sql
DeviceFileEvents | where (FolderPath endswith @'\ntds.dit' and ((InitiatingProcessFolderPath endswith @'\cmd.exe' or InitiatingProcessFolderPath endswith @'\cscript.exe' or InitiatingProcessFolderPath endswith @'\mshta.exe' or InitiatingProcessFolderPath endswith @'\powershell.exe' or InitiatingProcessFolderPath endswith @'\pwsh.exe' or InitiatingProcessFolderPath endswith @'\regsvr32.exe' or InitiatingProcessFolderPath endswith @'\rundll32.exe' or InitiatingProcessFolderPath endswith @'\wscript.exe' or InitiatingProcessFolderPath endswith @'\wsl.exe' or InitiatingProcessFolderPath endswith @'\wt.exe') or (InitiatingProcessFolderPath contains @'\AppData\' or InitiatingProcessFolderPath contains @'\Temp\' or InitiatingProcessFolderPath contains @'\Public\' or InitiatingProcessFolderPath contains @'\PerfLogs\')))
```



