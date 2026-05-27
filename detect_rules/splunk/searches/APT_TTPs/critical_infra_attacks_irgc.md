### Intrusion into Middle East Critical National Infrastructure
---

Author: RW

An Iranian state-sponsored threat group conducted a long-term cyber intrusion targeting critical national infrastructure (CNI) in the Middle East, focusing on extensive espionage and network prepositioning. The attackers maintained persistence through various web shells and custom backdoors, bypassing network segmentation and actively targeting virtualization infrastructure.

Recent analysis highlights the use of heavily obfuscated ASPX web shells, such as "UpdateChecker.aspx," which employ advanced techniques like Unicode encoding and encryption for C# code and constant values, making detection and analysis significantly more challenging than typical web shells. This obfuscation, combined with JSON-formatted, encrypted command and control (C2) traffic, represents an evolution in web shell sophistication for this threat actor.

### Actionable Threat Data
---

Initial Access & Persistence:

Monitor for successful VPN logins, especially those using stolen credentials. Implement multi-factor authentication (MFA) for all VPN and privileged accounts.

Detect the deployment of web shells (e.g., `UpdateChecker.aspx`, `RecShell` Web Shell, `DropShell` Web Shell, `EmbedShell` Web Shell, File Upload Web Shell) on public-facing web servers, particularly on Microsoft IIS. Look for newly created `.aspx` files with highly obfuscated C# code, Unicode characters in variable/method names, and encrypted constant values.

Identify the creation of scheduled tasks designed to blend in with legitimate Windows processes for persistence. Monitor for new scheduled tasks (Event ID 4698) that execute unusual or unrecognized binaries, especially those with randomized names or non-Microsoft signed executables.

Lateral Movement & Internal Reconnaissance:

Detect the use of remote access tools and open-source proxying tools like `plink`, `Ngrok`, `glider proxy`, and `ReverseSocks5` for bypassing network segmentation and lateral movement. Monitor for process execution of these tools and unusual network connections.

Monitor for `RDP` and `PsExec` usage for lateral movement. Look for suspicious RDP logins (Event ID 1149 from `TerminalServices-LocalSessionManager/Operational log`) and `PsExec` activity (Windows Security Event ID `7045`, Sysmon Event ID 1 for `PSEXESVC.exe` or randomly named executables in `C:\Windows`).

Detect reconnaissance activities targeting virtualization infrastructure. Look for commands or scripts that enumerate virtual machines, hypervisor configurations, or virtualization software.

Malware & Tooling:

Detect the presence and execution of custom backdoors such as `HanifNet` (.NET-based), `HXLibrary` (malicious IIS module), and `NeoExpressRAT` (Golang-based). Look for their unique file signatures, process behaviors, and network communications.

Identify the deployment and in-memory execution of `Havoc` and `SystemBC`. Monitor for Havoc C2 traffic (HTTP/HTTPS POST requests with encrypted data) and SystemBC (`SOCKS5` proxy activity, custom binary protocol over TCP with RC4 encryption).

Monitor for the exploitation of vulnerabilities in `ZKTeco ZKBioTime` software. Keep all public-facing applications and infrastructure patched and up-to-date.

Credential Theft & Exfiltration:

Detect targeted phishing attacks aimed at stealing administrator credentials. Implement robust email security solutions that analyze sender reputation, content, and attachments for phishing indicators. Educate users on identifying and reporting phishing attempts.

Monitor for exfiltration of targeted email data. Look for unusual email activity, such as large volumes of emails sent to external addresses, emails with sensitive content, or emails sent to personal accounts.

### Suspicious ASPX File Creation in IIS Web Directory
---
```sql
((source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11) OR (sourcetype=sysmon EventCode=11)) TargetFilename LIKE "%\\inetpub\\wwwroot\\%"

| where ( (match(TargetFilename, "(?i)(UpdateChecker|RecShell|DropShell|EmbedShell)\.aspx$")) OR (Image LIKE "%w3wp.exe" AND TargetFilename LIKE "%.aspx") )

# comment: Aggregate results to show key details for investigation.
| stats count min(_time) as firstTime max(_time) as lastTime by host, Image, TargetFilename
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(lastTime)
| rename host as endpoint, Image as process_path, TargetFilename as file_path
```

### Suspicious Scheduled Task Creation
---
```sql
source="WinEventLog:Security" EventCode=4698

# comment: The logic filters for tasks executing from common temporary/user-writable directories, using suspicious tools, or involving executables with potentially randomized names.
| where (
    match(Command, "(?i)(\\temp\\|\\tmp\\|\\users\\public\\|\\appdata\\|\\programdata\\|\\recycler\\)") OR
    match(Command, "(?i)(powershell.*(enc|invoke|iex|iwr|download)|cmd /c|mshta\.exe|certutil\.exe|bitsadmin\.exe|wscript\.exe|cscript\.exe|rundll32\.exe)") OR
    match(Command, "(?i)\\[a-zA-Z0-9]{12,}\.exe")
)

# comment: Add exclusions for known good software or administrative scripts to reduce noise.
# | where NOT ( match(TaskName, "(?i)KnownGoodTaskName") OR match(Command, "(?i)KnownGoodCommand") )

# comment: Aggregate results for review. Note: This event (4698) does not contain binary signature info. Correlate with process execution logs (e.g., Sysmon EID 1) to verify if the binary is unsigned or not signed by Microsoft.
| stats count min(_time) as firstTime max(_time) as lastTime by host, TaskName, Command, AccountName
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(lastTime)
| rename host as endpoint, TaskName as task_name, Command as task_command, AccountName as user
```

### Proxy and Tunneling Tool Execution
---
```sql
((source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) OR (sourcetype=sysmon EventCode=1))

# comment: Filters for the execution of specific proxy tool executable names. Also searches the command line for "ReverseSocks5" as its executable name may be changed.
| where (
    match(Image, "(?i)(plink\.exe|ngrok\.exe|glider\.exe)$") OR
    match(CommandLine, "(?i)ReverseSocks5")
)

# comment: Add exclusions for known legitimate use cases to reduce noise.
# | where NOT (User="KNOWN_ADMIN_ACCOUNT" AND match(CommandLine, "LEGITIMATE_COMMAND"))

# comment: Aggregate results for review. The execution of these tools implies network activity. Correlate with network logs (e.g., Sysmon EID 3) using the process_guid to investigate the destination of the connections.
| stats count min(_time) as firstTime max(_time) as lastTime by host, User, ParentImage, Image, CommandLine, ProcessGuid
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(lastTime)
| rename host as endpoint, User as user, ParentImage as parent_process, Image as process_path, CommandLine as process_command_line, ProcessGuid as process_guid
```

### RDP or PsExec Lateral Movement Activity
---
```sql
( (source="WinEventLog:System" EventCode=7045) OR \
  ((source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) OR (sourcetype=sysmon EventCode=1)) OR \
  (source="WinEventLog:Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" EventCode=1149) )

# comment: Filter for specific PsExec and RDP indicators across different log sources.
| where ( \
    (EventCode=7045 AND (ServiceName="PSEXESVC" OR match(ServiceFileName, "(?i)PSEXESVC\\.exe$"))) OR \
    (EventCode=1 AND (Image LIKE "%PSEXESVC.exe" OR (Image LIKE "C:\\Windows\\%.exe" AND match(Image, "(?i)C:\\\\Windows\\\\[a-zA-Z0-9]{8,}\\.exe$")))) OR \
    (EventCode=1149) \
  )

# comment: Normalize fields from different event sources to provide a consistent output.
| eval activity_type=case( \
    EventCode=7045, "PsExec Service Installation", \
    EventCode=1, "PsExec-like Process Execution", \
    EventCode=1149, "Successful RDP Logon" \
  ), \
  user=coalesce(AccountName, user, User), \
  details=coalesce(ServiceFileName, Image, CommandLine, 'Source IP: '.src_ip, 'Source Network Address: '.param1)

# comment: Aggregate results for easier analysis and to reduce alert volume.
| stats count min(_time) as firstTime max(_time) as lastTime values(activity_type) as activities values(user) as users values(details) as activity_details by host
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(lastTime)
| rename host as endpoint
```

### Virtualization Infrastructure Reconnaissance
---
```sql
((source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) OR (sourcetype=sysmon EventCode=1))

# comment: The logic filters for PowerShell cmdlets for Hyper-V, VMware command-line tools, WMI queries for virtualization info, and service queries for virtualization components.
| where (
    (Image LIKE "%powershell.exe" AND match(CommandLine, "(?i)(Get-VM|Get-VMSwitch|Get-VMNetworkAdapter|Get-VHD)")) OR
    match(Image, "(?i)vmware-toolbox-cmd.exe") OR
    (Image LIKE "%wmic.exe" AND match(CommandLine, "(?i)root\\\\virtualization")) OR
    (Image LIKE "%sc.exe" AND match(CommandLine, "(?i)query\s+(vmms|vmmemctl|vmtools|vboxservice)"))
)

# comment: Consider excluding known administrative users or scripts to reduce false positives from legitimate management activities.
# | where NOT (User IN ("KNOWN_ADMIN_1", "VIRTUAL_ADMIN_SVC") OR ParentImage IN ("C:\\legit_scripts\\manage_vms.exe"))

# comment: Aggregate results for review, showing the user, host, and specific command used.
| stats count min(_time) as firstTime max(_time) as lastTime by host, User, ParentImage, Image, CommandLine
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(lastTime)
| rename host as endpoint, User as user, ParentImage as parent_process, Image as process_path, CommandLine as process_command_line
```

### Suspicious IIS Module Load for Custom Backdoor
---
```sql
((source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7) OR (sourcetype=sysmon EventCode=7))
Image LIKE "%\\w3wp.exe"

# comment: Filters for modules that are not signed by Microsoft, a key attribute of many malicious IIS modules.
| where NOT (Signature LIKE "Microsoft%")

# comment: Further narrows the search to modules loaded from common web-writable or temporary directories, which are highly suspicious locations for IIS modules.
| where (
    ImageLoaded LIKE "%\\inetpub\\wwwroot\\%" OR
    ImageLoaded LIKE "%\\Temp\\%" OR
    ImageLoaded LIKE "%\\tmp\\%" OR
    ImageLoaded LIKE "%\\ProgramData\\%"
)

# comment: Consider adding exclusions for known legitimate third-party modules to reduce false positives.
# | where NOT match(ImageLoaded, "(?i)known_good_module.dll")

# comment: Aggregate results for review, showing the host, the loaded module, and its signature details.
| stats count min(_time) as firstTime max(_time) as lastTime by host, Image, ImageLoaded, Signature, Signed, Description
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(lastTime)
| rename host as endpoint, Image as process_path, ImageLoaded as module_path, Signature as signature, Signed as is_signed, Description as module_description
```

### Suspicious In-Memory Execution via Process Injection (Havoc/SystemBC)
---
```sql
((source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8) OR (sourcetype=sysmon EventCode=8))

# comment: Filters for injections where the injected threads start address does not map to a known module on disk. This is a key indicator of reflectively loaded shellcode, common to Havoc and SystemBC loaders.
| where StartModule IS NULL OR StartModule LIKE "%UNKNOWN%"

# comment: Further focus on common injection patterns where legitimate system processes are used as the source or target of the injection to blend in.
| where (
    (SourceImage LIKE "%\\rundll32.exe" OR SourceImage LIKE "%\\svchost.exe" OR SourceImage LIKE "%\\regsvr32.exe" OR SourceImage LIKE "%\\powershell.exe")
    AND
    (TargetImage LIKE "%\\explorer.exe" OR TargetImage LIKE "%\\svchost.exe" OR TargetImage LIKE "%\\notepad.exe" OR TargetImage LIKE "%\\msiexec.exe" OR TargetImage LIKE "%\\aspnet_compiler.exe")
)

# comment: Consider excluding known legitimate software that performs process injection for functionality like hooking or debugging.
# | where NOT (SourceImage="C:\\Program Files\\GoodSoftware\\injector.exe" AND TargetImage="C:\\Program Files\\GoodSoftware\\target.exe")

# comment: Aggregate results for investigation, highlighting the source and target of the injection.
| stats count min(_time) as firstTime max(_time) as lastTime by host, SourceImage, TargetImage, SourceProcessGuid, TargetProcessGuid, StartAddress, StartModule, User
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(lastTime)
| rename host as endpoint, SourceImage as source_process, TargetImage as target_process, SourceProcessGuid as source_process_guid, TargetProcessGuid as target_process_guid, StartAddress as start_address, StartModule as start_module, User as user
```

### ZKTeco ZKBioTime Post-Exploitation Activity
---
```sql
((source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) OR (sourcetype=sysmon EventCode=1))

# comment: Identifies parent processes associated with ZKTeco ZKBioTime software.
| where (match(ParentImage, "(?i)(BioTime|ZKBioTime|ZKTimeNet)"))

# comment: Looks for the spawning of common command-line interpreters and LOLBAS often used for post-exploitation.
| where (
    match(Image, "(?i)(\\cmd\.exe|\\powershell\.exe|\\wscript\.exe|\\cscript\.exe|\\rundll32\.exe|\\certutil\.exe|\\bitsadmin\.exe|\\whoami\.exe|\\net\.exe|\\net1\.exe|\\systeminfo\.exe|\\mshta\.exe)$")
)

# comment: Aggregate results for investigation, showing the parent process, the suspicious child process, and the command line used.
| stats count min(_time) as firstTime max(_time) as lastTime by host, User, ParentImage, Image, CommandLine, ProcessGuid
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(lastTime)
| rename host as endpoint, User as user, ParentImage as parent_process, Image as process_path, CommandLine as process_command_line, ProcessGuid as process_guid
```

### Targeted Phishing for Administrator Credentials
---
```sql
# Data Source:
# - This rule requires email security gateway logs (e.g., Proofpoint, Mimecast) or mail server logs (e.g., Microsoft 365, Exchange) that have been normalized for the Splunk Common Information Model (CIM).
`cim_email` status="delivered"

# comment: Use a macro or lookup to identify emails sent to administrative or high-privilege users.
# Example macro `get_admin_users(user)`: `lookup admin_users.csv user OUTPUT is_admin | where is_admin="true"`
| `get_admin_users(recipient)`

# comment: Use a macro or lookup to filter for emails from external domains.
# Example macro `is_external_sender(domain_field)`: `search NOT [| inputlookup internal_domains.csv | rename domain as domain_field | fields domain_field]`
| `is_external_sender(sender_domain)`

# comment: Filters for common phishing keywords in the subject line or high-risk attachment file types.
| where (
    match(subject, "(?i)(password|verify|urgent|action required|suspension|invoice|credentials|security alert|account validation)") OR
    match(file_name, "(?i)\.(html|htm|zip|iso|lnk|vbs|js)$")
)

# comment: Aggregate results for investigation.
| stats count min(_time) as firstTime max(_time) as lastTime by sender, recipient, subject, file_name, src_ip
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(lastTime)
| rename sender as email_sender, recipient as email_recipient, subject as email_subject, file_name as attachment_name, src_ip as source_ip
```

### Email Data Exfiltration via High Volume or Suspicious Destination
---
```sql
# Data Source:
# - This rule requires email security gateway logs (e.g., Proofpoint, Mimecast) or mail server logs (e.g., Microsoft 365, Exchange) that have been normalized for the Splunk Common Information Model (CIM).
# - Required fields: `action`, `src_user`, `dest_domain`, `subject`, `bytes_out`.
#
`cim_email` action="sent"

# comment: Use a macro or lookup to identify emails sent from internal users.
# Example macro `is_internal_sender(user_field)`: `search [| inputlookup internal_users.csv | rename user as user_field | fields user_field]`
| `is_internal_sender(src_user)`

# comment: Use a macro or lookup to identify emails sent to external domains.
# Example macro `is_external_recipient(domain_field)`: `search NOT [| inputlookup internal_domains.csv | rename domain as domain_field | fields domain_field]`
| `is_external_recipient(dest_domain)`

# comment: Create flags for different risk factors: sending to personal email domains and using sensitive keywords in the subject.
| eval is_personal_domain = if(match(dest_domain, "(?i)(gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|aol\.com|protonmail\.com|icloud\.com)"), 1, 0)
| eval has_sensitive_subject = if(match(subject, "(?i)(confidential|secret|internal use only|proprietary|private)"), 1, 0)

# comment: Aggregate email activity per user over a 24-hour period.
| bin _time span=1d
| stats count as email_count, sum(bytes_out) as total_bytes_sent, dc(dest_domain) as distinct_recipient_domains, values(dest_domain) as recipient_domains, sum(is_personal_domain) as personal_email_count, sum(has_sensitive_subject) as sensitive_subject_count by _time, src_user

# comment: Trigger an alert if thresholds for high volume, excessive personal email usage, or sensitive content are met. These thresholds should be tuned for your environment.
| where (email_count > 100 AND total_bytes_sent > 52428800) OR personal_email_count > 20 OR sensitive_subject_count > 5

# comment: Format the results for investigation.
| convert ctime(_time)
| rename src_user as user, _time as time_window_start
| eval total_mb_sent = round(total_bytes_sent / 1024 / 1024, 2)
| fields time_window_start, user, email_count, total_mb_sent, distinct_recipient_domains, personal_email_count, sensitive_subject_count, recipient_domains
```
