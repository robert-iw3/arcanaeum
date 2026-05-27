### EDR Evasion Tools Threat Report
---

This report details the evolving landscape of EDR evasion tools, specifically focusing on EDRSilencer, EDRSandblast, Killer Ultra, Kill AV, and AVNeutralizer. These tools are actively used by ransomware groups and other threat actors to disable or bypass endpoint security solutions, primarily leveraging vulnerable drivers and Windows Filtering Platform (WFP) manipulation to achieve defense evasion.

Recent intelligence indicates a continued trend of threat actors leveraging Bring Your Own Vulnerable Driver (BYOVD) techniques and API unhooking to bypass EDRs, with tools like AVNeutralizer being actively sold and updated on underground forums by groups like FIN7. This highlights a significant shift towards commercialized and continuously evolving EDR evasion capabilities, making detection more challenging.

### Actionable Threat Data
---

EDRSilencer Activity: Monitor for `EDRSilencer.exe` execution with command-line arguments such as `block`, `blockedr`, `unblock`, or `unblockall`. Look for associated network communication to `172[.]64[.]149[.]23` and file write operations to `\Device\KsecDD` with `OpenModify` access.

EDRSandblast Vulnerable Driver Loading: Detect the loading of known vulnerable drivers used by `EDRSandblast`, specifically `GDRV.sys`, `RTCore64.sys`, and `DBUtil_2_3.sys`, by monitoring driver load events.

Killer Ultra Service Creation and Dropped Files: Look for the creation of a service named "`StopGuard`" and the dropping of a driver file named "`trevor`" (SHA256: `ACDDC320EA03B29F091D1FD8C1F20A771DA19671D60B0F5B51CCA18DC9585D58`) in user directories.

AVNeutralizer (AuKill) Driver Abuse: Monitor for the loading of `ProcLaunchMon.sys` and `PED.sys` (Process Explorer driver) in conjunction with suspicious process terminations or service manipulations, as `AVNeutralizer` leverages these for EDR evasion.

CVE-2024-1853 Exploitation: Implement detections for attempts to exploit CVE-2024-1853, which involves triggering the `0x80002048` IOCTL code of `zam64.sys` and `zamguard64.sys` drivers to terminate processes. This vulnerability is leveraged by tools like "Terminator" and Killer Ultra.

### EDRSilencer Execution Detected
---
```sql
`comment(
-- title: EDRSilencer Execution

-- description: Detects the execution of EDRSilencer, a tool used to disable or tamper with EDR security solutions by manipulating Windows Filtering Platform (WFP) filters.

-- tags:
   - attack.t1562.001

-- falsepositives:
   - This tool may be used by red teams or security researchers.
   - The executable name can be easily changed by an attacker.
   - Legitimate security testing.

-- level: high
)`

#--------------------------------------------------------------------------------
# This search requires data from process creation events (e.g., Sysmon Event Code 1, CrowdStrike Falcon, etc.)
# mapped to the Endpoint data model, Processes node.
#--------------------------------------------------------------------------------

`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where \
    # Detects known tool names (EDRSilencer.exe, silencer.exe) or its distinctive command-line arguments.
    (Processes.process_name IN ("*EDRSilencer.exe", "*silencer.exe") OR Processes.process IN ("* block *", "* blockedr*", "* unblock *", "* unblockall*")) \
    by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process \
| `drop_dm_object_name("Processes")` \
# Rename fields for better readability.
| rename dest as host, user as user, parent_process_name as parent_process, process_name as process_name, process as process_command_line \
# Convert timestamps to a human-readable format.
| `ctime(firstTime)` \
| `ctime(lastTime)` \
# Table of results.
| table firstTime, lastTime, host, user, parent_process, process_name, process_command_line, count

# Comment: The command-line arguments "block" and "unblock" can be generic and may generate false positives.
# If noise is observed, consider making the logic more strict by requiring both the process name and the command line.
# Example: (Processes.process_name IN ("*EDRSilencer.exe", "*silencer.exe") AND Processes.process IN ("* block *", ...))
# Alternatively, filter out known legitimate processes that use these arguments.
```

### EDRSilencer File Write
---
```sql
`comment(
-- title: EDRSilencer File Write

-- description: Detects file write or modification operations to the `\\Device\\KsecDD` path. This behavior is a known indicator of the EDRSilencer tool, which is used by threat actors to impair or disable endpoint security solutions by interacting with the Kernel Security Support Provider Interface.

-- tags:
   - attack.t1562.001

-- falsepositives:
   - Legitimate system processes or security tools might interact with the KSecDD device driver, although direct modification is rare. If false positives occur, investigate the parent process and command line of the process performing the action to determine legitimacy.

-- level: high
)`

#--------------------------------------------------------------------------------
# This search requires data from file system monitoring tools (e.g., Sysmon, EDR)
# mapped to the Endpoint.Filesystem data model.
#--------------------------------------------------------------------------------

`tstats` summariesonly count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="\\Device\\KsecDD" AND Filesystem.action="modified" by Filesystem.dest, Filesystem.user, Filesystem.process_name, Filesystem.file_path, Filesystem.action
| `drop_dm_object_name("Filesystem")`

# Rename fields for better readability
| rename dest as host, process_name as process, file_path as target_device, action as file_action

# Convert timestamps to human-readable format
| `ctime(firstTime)`
| `ctime(lastTime)`

# Organize the output table
| table firstTime, lastTime, host, user, process, target_device, file_action, count

# Comment: The threat intel mentions the operation "OpenModify". This rule maps that to the CIM action "modified".
# You may need to adjust `Filesystem.action="modified"` to match the specific value your EDR logs for this type of kernel device interaction.
```

### EDRSandblast Driver Load
---
```sql
`comment(
-- title: EDRSandblast Driver Load

-- description: Detects the loading of vulnerable drivers (GDRV.sys, RTCore64.sys, DBUtil_2_3.sys) commonly exploited by the EDRSandblast tool to disable or impair security solutions. The loading of these specific drivers is a strong indicator of EDRSandblast activity.

-- tags:
  - attack.t1562.001

-- falsepositives:
  - These drivers can be part of legitimate, albeit vulnerable, software installations (e.g., RTCore64.sys is used by MSI Afterburner). The context of the loading process and user should be investigated to determine malicious intent.

-- level: high
)`

#--------------------------------------------------------------------------------
# This search requires data from driver load events (e.g., Sysmon Event Code 6)
# mapped to the Endpoint.Drivers data model.
#--------------------------------------------------------------------------------

`tstats` summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Drivers where Drivers.driver_name IN ("*gdrv.sys", "*RTCore64.sys", "*DBUtil_2_3.sys") by Drivers.dest, Drivers.user, Drivers.process_name, Drivers.driver_name
| `drop_dm_object_name("Drivers")`

# Rename fields for better readability.
| rename dest as host, process_name as process, driver_name as vulnerable_driver

# Convert timestamps to human-readable format.
| `ctime(firstTime)`
| `ctime(lastTime)`

# Organize the output table.
| table firstTime, lastTime, host, user, process, vulnerable_driver, count

# Comment: This detection looks for known vulnerable drivers used by EDRSandblast.
# Since these drivers can exist legitimately on a system, an alert warrants investigation
# into the process that loaded the driver to confirm malicious activity.
```

### Killer Ultra Service Creation
---
```sql
`comment(
-- title: Killer Ultra Service Creation

-- description: Detects the creation of the "StopGuard" service. This is a specific indicator of the Killer Ultra malware, a tool used by ransomware groups to disable EDR and other security products by exploiting vulnerable drivers.

-- tags:
  - attack.t1562.001

-- falsepositives:
  - The service name "StopGuard" is highly specific to this tool, making false positives unlikely.

-- level: high
)`

# --------------------------------------------------------------------------------
# This search requires Windows Security Event Logs (EventCode=4697: A service was installed in the system).
# Ensure the data is ingested, typically via the Splunk Add-on for Microsoft Windows.
# --------------------------------------------------------------------------------

`wineventlog_security`
# Filter for service creation events where the service name is "StopGuard".
| where EventCode=4697 AND Service_Name="StopGuard"
| stats count min(_time) as firstTime max(_time) as lastTime by host, user, Account_Domain, Service_Name, Service_File_Name
# Rename fields for clarity and consistency.
| rename host as dest, user as user, Account_Domain as user_domain, Service_Name as service_name, Service_File_Name as service_path
# Convert epoch time to human-readable format.
| `ctime(firstTime)`
| `ctime(lastTime)`
# Format the results table.
| table firstTime, lastTime, dest, user, user_domain, service_name, service_path, count

# Comment: This detection is highly specific to the "StopGuard" service name. While effective, sophisticated attackers may change this artifact.
# Consider creating broader detections based on the loading of the associated vulnerable driver (e.g., "trevor" or "amsdk.sys").
```

### Killer Ultra Dropped File
---
```sql
`comment(
-- title: Killer Ultra Dropped File
-- description: Detects the creation of a file with a hash matching the 'trevor' driver, which is dropped by the Killer Ultra malware. This tool is used by ransomware groups to disable security solutions by exploiting vulnerable drivers.

-- tags:
  - attack.t1562.001

-- falsepositives:
  - Extremely unlikely. This detection is based on a specific file hash associated with known malware.

-- level: high
)`

# --------------------------------------------------------------------------------
# This search requires data from file creation events (e.g., Sysmon, EDR)
# mapped to the Endpoint.Filesystem data model, with file hashes populated.
# --------------------------------------------------------------------------------

`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash="ACDDC320EA03B29F091D1FD8C1F20A771DA19671D60B0F5B51CCA18DC9585D58" by Filesystem.dest, Filesystem.user, Filesystem.file_name, Filesystem.file_path, Filesystem.file_hash
# Drop the data model prefix for cleaner field names.
| `drop_dm_object_name("Filesystem")`
# Rename fields for clarity.
| rename dest as host
# Convert epoch time to human-readable format.
| `ctime(firstTime)`
| `ctime(lastTime)`
# Format the results table.
| table firstTime, lastTime, host, user, file_name, file_path, file_hash, count

# Comment: This rule detects a specific SHA256 hash. Ensure your data source populates the 'file_hash' field in the Endpoint.Filesystem data model. You may need to specify the hash field directly (e.g., Filesystem.file_hash_sha256) depending on your data mapping.
```

### AVNeutralizer Driver Load
---
```sql
`comment(
-- title: AVNeutralizer Driver Load

-- description: Detects the loading of ProcLaunchMon.sys or PED.sys. These drivers are leveraged by the AVNeutralizer (also known as AuKill) tool to bypass EDRs and other security solutions as part of its defense evasion capabilities.

-- tags:
  - attack.t1562.001

-- falsepositives:
  - PED.sys is a renamed Process Explorer driver. While Process Explorer is a legitimate tool, its use by AVNeutralizer makes any instance of a driver named PED.sys highly suspicious. False positives are possible if an administrator legitimately renames and uses the driver under this name. Investigation of the loading process is recommended.

-- level: high
)`

#--------------------------------------------------------------------------------
# This search requires data from driver load events (e.g., Sysmon Event Code 6)
# mapped to the Endpoint.Drivers data model.
#--------------------------------------------------------------------------------

`tstats` summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Drivers where (Drivers.driver_name="*ProcLaunchMon.sys" OR Drivers.driver_name="*PED.sys") by Drivers.dest, Drivers.user, Drivers.process_name, Drivers.driver_name
| `drop_dm_object_name("Drivers")`

# Rename fields for better readability.
| rename dest as host, process_name as loading_process, driver_name as loaded_driver

# Convert timestamps to human-readable format.
| `ctime(firstTime)`
| `ctime(lastTime)`

# Organize the output table.
| table firstTime, lastTime, host, user, loading_process, loaded_driver, count

# Comment: This detection specifically targets drivers known to be used by AVNeutralizer/AuKill.
# The context of the loading_process is critical for triage.
```

### CVE-2024-1853 Exploitation
---
```sql
`comment(
-- title: CVE-2024-1853 Exploitation via IOCTL

-- description: Detects the use of the specific IOCTL code 0x80002048, which is used to exploit CVE-2024-1853 in the vulnerable Zemana AntiLogger driver (amsdk.sys). Tools like Killer Ultra and Terminator leverage this vulnerability to terminate security processes and impair defenses.

-- tags:
  - attack.t1562.001

-- falsepositives:
  - This IOCTL code is highly specific to the vulnerable Zemana driver function. False positives are unlikely but could occur if another driver reuses this code. Investigation of the initiating process and the target device/driver is crucial for triage.

-- level: high
)`

#--------------------------------------------------------------------------------
# This search requires a data source that logs DeviceIoControl events, such as Microsoft Defender for Endpoint (DeviceIoControlEvents).
# Replace 'index=edr sourcetype=edr:ioctl' with the index and sourcetype containing your EDRs IOCTL event data.
# The fields `IoControlCode` and `DeviceName` (or equivalents) are required.
#--------------------------------------------------------------------------------

index=edr sourcetype=edr:ioctl
# Filter for the specific IOCTL code associated with CVE-2024-1853.
| where IoControlCode="0x80002048"

| stats count min(_time) as firstTime max(_time) as lastTime by dest, user, process_name, process_command_line, DeviceName, IoControlCode

# Rename fields for clarity.
| rename process_name as process, process_command_line as process_cmd, DeviceName as target_device, IoControlCode as ioctl_code

# Convert epoch time to human-readable format.
| `ctime(firstTime)`
| `ctime(lastTime)`

# Format the results table.
| table firstTime, lastTime, dest, user, process, process_cmd, target_device, ioctl_code, count

# Comment: For a more targeted search and to reduce potential noise, you can filter for the known vulnerable driver names.
# This may, however, miss cases where the driver is renamed.
# | search target_device IN ("*\\amsdk.sys", "*\\trevor", "*\\zam64.sys", "*\\zamguard64.sys")
```