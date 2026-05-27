<p align="center">
  <img src="https://www.elastic.co/security-labs/grid.svg" />
</p>

## BLISTER malware campaign

    Stealthy malware campaign that leverages valid code signing certificates to evade detection

    A novel malware loader, BLISTER was used to execute second stage malware payloads in-memory and maintain persistence

    The identified malware samples have very low or no detections on VirusTotal

    Elastic provided layered prevention coverage from this threat out of the box

## Hunting queries

These queries can be used in Kibana's Security -\> Timelines -\> Create new timeline -\> Correlation query editor. While these queries will identify this intrusion set, they can also identify other events of note that, once investigated, could lead to other malicious activities.

Proxy Execution via Renamed Rundll32

Hunt for renamed instances of rundll32.exe

```sql
process where event.action == "start" and
process.name != null and
(process.pe.original_file_name == "RUNDLL32.EXE" and not process.name : "RUNDLL32.EXE")
```

Masquerading as WerFault

Hunt for potential rogue instances of WerFault.exe (Windows Errors Reporting) in an attempt to masquerade as a legitimate system process that is often excluded from behavior-based detection as a known frequent false positive:

```sql
process where event.action == "start" and
  process.executable :
   ("?:\\Windows\\Syswow64\\WerFault.exe" ,"?:\\Windows\\System32\\WerFault.exe") and
   /*
     legit WerFault will have more than one argument in process.command_line
   */
  process.args_count == 1
```

Persistence via Registry Run Keys / Startup Folder

Malware creates a new run key for persistence:

```sql
registry where registry.data.strings != null and
 registry.path : (
  /* Machine Hive */      "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",  "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\*",

 /* Users Hive */
"HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
"HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*", "HKEY_USERS\\*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\*"
     )
```

Suspicious Startup Shell Folder Modification

Modify the default Startup value in the registry via COM (dllhost.exe) and then write a shortcut file for persistence in the new modified Startup folder:

```sql
sequence by host.id with maxspan=1m
 [registry where
  /* Modify User default Startup Folder */
  registry.path : (
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Startup",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup"
     ) ]
  /* Write File to Modified Startup Folder */
    [file where event.type : ("creation", "change") and file.path : "?:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\*"]
```

