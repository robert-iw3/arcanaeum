### Ransomware Final Stage Activities and Detection Opportunities
---

This report details common final-stage activities observed in ransomware attacks, focusing on system modification, data exfiltration, evidence removal, and the encryption phase. It also provides actionable threat data to enhance detection capabilities against these evolving threats.

Recent intelligence indicates a significant increase in data exfiltration as a primary tactic, with cases rising from 76% to 87% in Q4 2024, highlighting a shift towards double and triple extortion models even if encryption fails. Additionally, new ransomware groups like FunkSec are leveraging AI for malware development and bypassing EDR systems, signifying a growing sophistication in attack methodologies.

### Actionable Threat Data
---

Monitor for bcdedit commands that modify boot configuration, especially those disabling recovery modes or suppressing error messages, as these are common ransomware persistence mechanisms. (T1562.001 - Impair Defenses: Disable or Modify System Recovery)

Detect attempts to disable security services or modify Microsoft Defender preferences using `sc stop`, `sc config`, or PowerShell cmdlets like `Set-MpPreference` and `Add-MpPreference` with arguments such as "`ExclusionProcess`" or "`ExclusionPath`". (T1562.001 - Impair Defenses: Disable or Modify System Recovery)

Look for command-line activity exporting data to `.txt` or `.csv` files, particularly when originating from unusual processes or locations, as this can indicate data staging for exfiltration. (T1020 - Automated Exfiltration, T1041 - Exfiltration Over C2 Channel)

Identify modifications to registry keys related to Remote Desktop Protocol (RDP) enablement, specifically `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Terminal Server\fDenyTSConnections` being set to `0`, which suggests an attempt to enable RDP for remote access. (T1021.001 - Remote Services: Remote Desktop Protocol)

Monitor for the clearing of security event logs using `wevtutil` commands with arguments like "`cl`" or "`clear-log`", or direct `SecurityLogCleared` events, as attackers often remove forensic evidence. (T1070.001 - Indicator Removal: Clear Windows Event Logs)

Detect the deletion of Prefetch files (e.g., `del C:\Windows\Prefetch\*.pf`), which indicates an attempt to remove traces of executed programs. (T1070.004 - Indicator Removal: File Deletion)

Implement detection for known ransomware extensions being appended to filenames during file modification events, indicating the encryption phase. (T1486 - Data Encrypted for Impact)

Monitor for commands that delete Volume Shadow Copies, such as `vssadmin delete shadows /all /quiet` or `wmic shadowcopy delete`, as this prevents system recovery. (T1490 - Inhibit System Recovery)

Look for suspicious modifications to desktop background registry keys (e.g., `HKCU\Control Panel\Desktop` or `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop`) or the dropping of suspicious files in the `C:\Users\Public` folder, which are common methods for ransomware notification. (T1491.001 - Defacement: Internal Defacement)

### Boot Configuration Modification via Bcdedit
---
```sql
-- comment: This search requires you to be ingesting process creation logs from your endpoints, mapped to the Endpoint data model.
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where \
    (Processes.process_name = "bcdedit.exe") AND \
    (Processes.process LIKE "%recoveryenabled No%" OR Processes.process LIKE "%bootstatuspolicy ignoreallfailures%") \
    by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process \
| rename "Processes.*" as "*" \
| convert ctime(firstTime) \
| convert ctime(lastTime) \
| fields firstTime, lastTime, dest, user, parent_process, process_name, process, count
```

### Security Service Disable
---
```sql
-- comment: This search requires process creation logs (e.g., Sysmon Event ID 1, CrowdStrike, etc.) mapped to the Endpoint data model.
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where
    ( (Processes.process_name = "sc.exe" AND (Processes.process LIKE "% config % disabled" OR Processes.process LIKE "% stop %")) OR
      (Processes.process_name IN ("powershell.exe", "pwsh.exe") AND (Processes.process LIKE "%Set-MpPreference%" OR Processes.process LIKE "%Add-MpPreference%") AND (Processes.process LIKE "%ExclusionPath%" OR Processes.process LIKE "%ExclusionProcess%")) )
    by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process
| rename "Processes.*" as "*"
| convert ctime(firstTime) ctime(lastTime)

-- comment: Legitimate administrators may use these commands for system maintenance. To reduce false positives, consider filtering for non-standard parent processes or non-administrative user accounts. You could also add specific high-value service names to the 'sc stop' clause to narrow the focus (e.g., `... AND Processes.process LIKE "% stop WinDefend%"`).
| fields firstTime, lastTime, dest, user, parent_process, process_name, process, count
```

### Data Staging via Command Line Redirection
---
```sql
-- comment: This search requires process creation logs (e.g., Sysmon Event ID 1, CrowdStrike, etc.) mapped to the Endpoint data model.
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where
    (Processes.process LIKE "%>%.txt" OR Processes.process LIKE "%>%.csv") AND Processes.process NOT LIKE "Start-Process %"
    by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process
| rename "Processes.*" as "*"
| convert ctime(firstTime) ctime(lastTime)

-- comment: Legitimate administrative scripts and diagnostic commands often redirect output to files. To reduce noise, consider filtering for unusual parent processes (e.g., not cmd.exe or powershell.exe) or processes that should not be performing this activity (e.g., office applications).
| fields firstTime, lastTime, dest, user, parent_process, process_name, process, count
```

### RDP Enablement via Registry Modification
---
```sql
-- comment: This search requires registry modification events (e.g., Sysmon Event ID 13) mapped to the Endpoint.Registry data model.
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where
    (Registry.registry_path="*\\SYSTEM\\*ControlSet*\\Control\\Terminal Server\\fDenyTSConnections" AND (Registry.registry_value_data="0" OR Registry.registry_value_data="0x00000000"))
    by Registry.dest, Registry.user, Registry.process_name, Registry.registry_path, Registry.registry_value_name, Registry.registry_value_data
| rename "Registry.*" as "*"
| convert ctime(firstTime) ctime(lastTime)

-- comment: Legitimate administrative activity might involve enabling RDP. To reduce false positives, investigate the user and process making the change. Correlate this activity with other suspicious behaviors. Consider creating a baseline of systems where RDP is expected to be enabled or changed and filter them from the results.
| fields firstTime, lastTime, dest, user, process_name, registry_path, registry_value_name, registry_value_data, count
```

### Event Log Clearing
---
```sql
-- comment: This search combines two detection methods. The first requires process creation logs (e.g., Sysmon Event ID 1) mapped to the Endpoint.Processes data model. The second requires Windows Security Event Logs (Event ID 1102).
`comment("Detect log clearing via wevtutil.exe command")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="wevtutil.exe" AND (Processes.process LIKE "% cl %" OR Processes.process LIKE "% clear-log %")) by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process
| rename "Processes.*" as "*"
| eval method="wevtutil command"
| append [
    `comment("Detect direct clearing of the Security Log via Windows Event ID 1102")`
    | search (index=* sourcetype="WinEventLog:Security" EventCode=1102)
    | stats count min(_time) as firstTime max(_time) as lastTime by host as dest, User as user
    | eval parent_process="N/A", process_name="services.exe", process="The Security audit log was cleared.", method="Windows Event ID 1102"
]
| convert ctime(firstTime) ctime(lastTime)

-- comment: While administrators can clear event logs, clearing the Security log is highly unusual and often against policy. Investigate any findings immediately. Correlate with other suspicious activity on the host or by the user.
| fields firstTime, lastTime, dest, user, parent_process, process_name, process, method, count
```

### Prefetch File Deletion
---
```sql
-- comment: This search requires process creation logs (e.g., Sysmon Event ID 1) mapped to the Endpoint.Processes data model.
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="cmd.exe" AND Processes.process LIKE "%del%" AND Processes.process LIKE "%\\Windows\\Prefetch\\%.pf%") by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process
| rename "Processes.*" as "*"
| convert ctime(firstTime) ctime(lastTime)

-- comment: Legitimate use of this command is extremely rare. Investigate any findings immediately. Correlate with other suspicious activity on the host or by the user.
| fields firstTime, lastTime, dest, user, parent_process, process_name, process, count
```

### Ransomware Extension Appended
---
```sql
-- comment: This search requires file creation events (e.g., Sysmon Event ID 11) mapped to the Endpoint.Filesystem data model.
| from datamodel=Endpoint.Filesystem
| where Filesystem.action = "created"
`comment("Filter for files created with known ransomware extensions. This list should be updated as new threats emerge.")`
| search (
    Filesystem.file_name=*.lockbit OR
    Filesystem.file_name=*.ryuk OR
    Filesystem.file_name=*.conti OR
    Filesystem.file_name=*.clop OR
    Filesystem.file_name=*.abyss OR
    Filesystem.file_name=*.akira OR
    Filesystem.file_name=*.avdn OR
    Filesystem.file_name=*.blackcat OR
    Filesystem.file_name=*.blackmatter OR
    Filesystem.file_name=*.hydra OR
    Filesystem.file_name=*.dharma OR
    Filesystem.file_name=*.hive OR
    Filesystem.file_name=*.phobos OR
    Filesystem.file_name=*.quantum OR
    Filesystem.file_name=*.revil
)
`comment("Aggregate results by host, user, and process to show the scope of the encryption activity.")`
| stats earliest(_time) as firstTime, latest(_time) as lastTime, values(Filesystem.file_name) as encrypted_files, dc(Filesystem.file_name) as distinct_encrypted_files, values(Filesystem.file_path) as locations by Filesystem.dest, Filesystem.user, Filesystem.process_name
| rename "Filesystem.*" as "*"
| convert ctime(firstTime) ctime(lastTime)

-- comment: The main source of false positives is an extension collision with legitimate software. Maintain a high-quality, up-to-date extension list. If false positives occur, consider excluding specific processes or file paths known to be safe in your environment.
| fields firstTime, lastTime, dest, user, process_name, distinct_encrypted_files, encrypted_files, locations
```

```sql
-- comment: This search requires file creation events (e.g., Sysmon Event ID 11) mapped to the Endpoint.Filesystem data model. It also requires a lookup file named 'ransomware_extensions.csv' with a single column 'extension' containing known ransomware file extensions (e.g., .lockbit, .rhysida).
| from datamodel=Endpoint.Filesystem
| where Filesystem.action = "created"
`comment("Use a subsearch to dynamically generate a filter for known ransomware extensions from a lookup file.")`
| search [| inputlookup ransomware_extensions.csv | format "OR" "" "" "" "" "(Filesystem.file_name=*" "extension" ")"]
`comment("Aggregate results by host, user, and process to show the scope of the encryption activity.")`
| stats earliest(_time) as firstTime, latest(_time) as lastTime, values(Filesystem.file_name) as encrypted_files, dc(Filesystem.file_name) as distinct_encrypted_files, values(Filesystem.file_path) as locations by Filesystem.dest, Filesystem.user, Filesystem.process_name
| rename "Filesystem.*" as "*"
| convert ctime(firstTime) ctime(lastTime)

-- comment: The main source of false positives is an extension collision with legitimate software. Maintain a high-quality, up-to-date extension list. If false positives occur, consider excluding specific processes or file paths known to be safe in your environment.
| fields firstTime, lastTime, dest, user, process_name, distinct_encrypted_files, encrypted_files, locations
```

```sql
| tstats `security_content_summariesonly` min(_time) as firstTime max(_time) as lastTime count latest(Filesystem.user) as user values(Filesystem.file_path) as file_path from datamodel=Endpoint.Filesystem by Filesystem.action Filesystem.dest Filesystem.file_access_time Filesystem.file_create_time Filesystem.file_hash Filesystem.file_modify_time Filesystem.file_name Filesystem.file_path Filesystem.file_acl Filesystem.file_size Filesystem.process_guid Filesystem.process_id Filesystem.user Filesystem.vendor_product
| `drop_dm_object_name(Filesystem)`
| rex field=file_name "(?<file_extension>\.[^\.]+)$"
| lookup update=true ransomware_extensions_lookup Extensions AS file_extension OUTPUT Extensions Name
| search Name !=False
| stats min(firstTime) as firstTime max(lastTime) as lastTime dc(file_path) as path_count dc(file_name) as file_count values(action) as action values(file_access_time) as file_access_time values(file_create_time) as file_create_time values(file_hash) as file_hash values(file_modify_time) as file_modify_time values(file_acl) as file_acl values(file_size) as file_size values(process_guid) as process_guid values(process_id) as process_id values(user) as user values(vendor_product) as vendor_product values(file_name) as file_name values(file_extension) as file_extension values(Name) as Name by dest
| where path_count > 1 OR file_count > 20
| `common_ransomware_extensions_filter`
```

### Shadow Copy Deletion
---
```sql
-- comment: This search requires process creation logs (e.g., Sysmon Event ID 1, CrowdStrike, etc.) mapped to the Endpoint data model.
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where
    (
        (Processes.process_name = "vssadmin.exe" AND Processes.process LIKE "%delete shadows%") OR
        (Processes.process_name = "wmic.exe" AND Processes.process LIKE "%shadowcopy delete%") OR
        (Processes.process_name = "wbadmin.exe" AND (Processes.process LIKE "%delete catalog%" OR Processes.process LIKE "%delete systemstatebackup%")) OR
        (Processes.process_name IN ("powershell.exe", "pwsh.exe") AND Processes.process LIKE "%Get-WmiObject Win32_Shadowcopy%" AND Processes.process LIKE "%Delete()%") OR
        (Processes.process_name = "schtasks.exe" AND Processes.process LIKE "%/Change%" AND Processes.process LIKE "%SystemRestore\\SR%" AND Processes.process LIKE "%/disable%") OR
        (Processes.process_name = "reg.exe" AND Processes.process LIKE "%add%HKLM\\SOFTWARE\\%SystemRestore%" AND (Processes.process LIKE "%DisableConfig%1%" OR Processes.process LIKE "%DisableSR%1%")) OR
        (Processes.process_name = "cmd.exe" AND Processes.process LIKE "%del %" AND (Processes.process LIKE "%*.VHD%" OR Processes.process LIKE "%*.bak%" OR Processes.process LIKE "%*.bkf%" OR Processes.process LIKE "%*Backup*.*%"))
    )
    by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process
| rename "Processes.*" as "*"
| convert ctime(firstTime) ctime(lastTime)

-- comment: Legitimate system administration may involve these commands. However, their execution, especially in combination with other suspicious activity, is a strong indicator of a ransomware attack. The 'del' command for backup files may be noisy; consider tuning it to specific paths or parent processes if false positives occur.
| fields firstTime, lastTime, dest, user, parent_process, process_name, process, count
```

### Desktop Background Modification and Ransom Note Drop
---
```sql
-- comment: This search combines process creation logs (for registry changes) and file creation events (for file drops), mapped to the Endpoint data model.
`comment("Detects registry modifications to change the desktop wallpaper, a common ransomware tactic.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="reg.exe" AND (Processes.process LIKE "%delete%HKCU\\Control Panel\\Desktop%" OR (Processes.process LIKE "%add%HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop%" AND Processes.process LIKE "%NoChangingWallPaper%"))) by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process
| rename "Processes.*" as "*"
| eval detection_method="Registry Modification", detail=process
| append [
    `comment("Detects suspicious files dropped into the Public user folder, often used for ransom notes.")`
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as detail from datamodel=Endpoint.Filesystem where (Filesystem.action="created" AND Filesystem.file_path LIKE "C:\\Users\\Public\\%" AND Filesystem.file_name!="*.lnk") by Filesystem.dest, Filesystem.user, Filesystem.process_name
    | rename "Filesystem.*" as "*"
    | eval detection_method="Public Folder File Drop", parent_process="N/A", process=process_name
]
| convert ctime(firstTime) ctime(lastTime)

-- comment: While these registry changes are highly suspicious, some legitimate software installers may drop files in the C:\Users\Public directory. If false positives occur, consider excluding known legitimate process names from the file drop portion of the search.
| fields firstTime, lastTime, dest, user, parent_process, process_name, process, detection_method, detail, count
```