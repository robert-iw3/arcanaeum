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
source:sysmon EventCode:11 file.path:*\\inetpub\\wwwroot\\* (file.path:/(UpdateChecker|RecShell|DropShell|EmbedShell)\.aspx$/ OR (process.path:*w3wp.exe AND file.path:*.aspx))
| select host, process.path AS process_path, file.path AS file_path, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, process_path, file_path
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host AS endpoint, process_path, file_path
```

### Suspicious Scheduled Task Creation
---
```sql
source:windows_event_log EventCode:4698 (task.command:/(\\\temp\\\|\\tmp\\\|\\users\\public\\\|\\appdata\\\|\\programdata\\\|\\recycler\\)/ OR task.command:/(powershell.*(enc|invoke|iex|iwr|download)|cmd \/c|mshta\.exe|certutil\.exe|bitsadmin\.exe|wscript\.exe|cscript\.exe|rundll32\.exe)/ OR task.command:/\\[a-zA-Z0-9]{12,}\.exe/)
| select host, task.name AS task_name, task.command AS task_command, user.name AS user, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, task_name, task_command, user
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host AS endpoint, task_name, task_command, user
```

### Proxy and Tunneling Tool Execution
---
```sql
source:sysmon EventCode:1 (process.path:/(plink\.exe|ngrok\.exe|glider\.exe)$/ OR process.cmdline:ReverseSocks5)
| select host, user, parent_process.path AS parent_process, process.path AS process_path, process.cmdline AS process_command_line, process.guid AS process_guid, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, parent_process, process_path, process_command_line, process_guid
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host AS endpoint, user, parent_process, process_path, process_command_line, process_guid
```

### RDP or PsExec Lateral Movement Activity
---
```sql
(source:windows_event_log EventCode:7045 (service.name:PSEXESVC OR service.path:/PSEXESVC\.exe$/) OR source:sysmon EventCode:1 (process.path:*PSEXESVC.exe OR process.path:/C:\\Windows\\[a-zA-Z0-9]{8,}\.exe$/) OR source:windows_event_log EventCode:1149)
| select host, coalesce(user.name, user) AS user, case(EventCode=7045 => "PsExec Service Installation", EventCode=1 => "PsExec-like Process Execution", EventCode=1149 => "Successful RDP Logon") AS activity_type, coalesce(service.path, process.path, process.cmdline, "Source IP: " + ip.src, "Source Network Address: " + param1) AS details, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count, collect(activity_type) AS activities, collect(user) AS users, collect(details) AS activity_details by host
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host AS endpoint, activities, users, activity_details
```

### Virtualization Infrastructure Reconnaissance
---
```sql
source:sysmon EventCode:1 ((process.path:*powershell.exe process.cmdline:/(Get-VM|Get-VMSwitch|Get-VMNetworkAdapter|Get-VHD)/) OR process.path:/vmware-toolbox-cmd\.exe/ OR (process.path:*wmic.exe process.cmdline:root\\virtualization) OR (process.path:*sc.exe process.cmdline:/query\s+(vmms|vmmemctl|vmtools|vboxservice)/))
| select host, user, parent_process.path AS parent_process, process.path AS process_path, process.cmdline AS process_command_line, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, parent_process, process_path, process_command_line
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host AS endpoint, user, parent_process, process_path, process_command_line
```

### Suspicious IIS Module Load for Custom Backdoor
---
```sql
source:sysmon EventCode:7 process.path:*\\w3wp.exe NOT image_load.signature:Microsoft* (image_load.path:*\\inetpub\\wwwroot\\* OR image_load.path:*\\Temp\\* OR image_load.path:*\\tmp\\* OR image_load.path:*\\ProgramData\\*)
| select host, process.path AS process_path, image_load.path AS module_path, image_load.signature AS signature, image_load.signed AS is_signed, image_load.description AS module_description, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, process_path, module_path, signature, is_signed, module_description
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host AS endpoint, process_path, module_path, signature, is_signed, module_description
```

### Suspicious In-Memory Execution via Process Injection (Havoc/SystemBC)
---
```sql
source:sysmon EventCode:8 (start_module:NULL OR start_module:*UNKNOWN*) source_process.path:(*\\rundll32.exe OR *\\svchost.exe OR *\\regsvr32.exe OR *\\powershell.exe) target_process.path:(*\\explorer.exe OR *\\svchost.exe OR *\\notepad.exe OR *\\msiexec.exe OR *\\aspnet_compiler.exe)
| select host, source_process.path AS source_process, target_process.path AS target_process, source_process.guid AS source_process_guid, target_process.guid AS target_process_guid, start_address, start_module, user, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, source_process, target_process, source_process_guid, target_process_guid, start_address, start_module, user
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host AS endpoint, source_process, target_process, source_process_guid, target_process_guid, start_address, start_module, user
```

### ZKTeco ZKBioTime Post-Exploitation Activity
---
```sql
source:sysmon EventCode:1 parent_process.path:/(BioTime|ZKBioTime|ZKTimeNet)/ process.path:/(\\cmd\.exe|\\powershell\.exe|\\wscript\.exe|\\cscript\.exe|\\rundll32\.exe|\\certutil\.exe|\\bitsadmin\.exe|\\whoami\.exe|\\net\.exe|\\net1\.exe|\\systeminfo\.exe|\\mshta\.exe)$/
| select host, user, parent_process.path AS parent_process, process.path AS process_path, process.cmdline AS process_command_line, process.guid AS process_guid, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by host, user, parent_process, process_path, process_command_line, process_guid
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, host AS endpoint, user, parent_process, process_path, process_command_line, process_guid
```

### Targeted Phishing for Administrator Credentials
---
```sql
source:email status:delivered recipient.is_admin:true NOT sender_domain:internal_domains (subject:/(password|verify|urgent|action required|suspension|invoice|credentials|security alert|account validation)/ OR file.name:/\.(html|htm|zip|iso|lnk|vbs|js)$/)
| select sender AS email_sender, recipient AS email_recipient, subject AS email_subject, file.name AS attachment_name, ip.src AS source_ip, min(timestamp) AS firstTime, max(timestamp) AS lastTime
| aggregate count by email_sender, email_recipient, email_subject, attachment_name, source_ip
| select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, email_sender, email_recipient, email_subject, attachment_name, source_ip
```

### Email Data Exfiltration via High Volume or Suspicious Destination
---
```sql
source:email action:sent src_user:internal_users NOT dest_domain:internal_domains
| select src_user AS user, dest_domain, subject, bytes_out, timestamp
| eval is_personal_domain = case(dest_domain:/(gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|aol\.com|protonmail\.com|icloud\.com)/ => 1, true => 0), has_sensitive_subject = case(subject:/(confidential|secret|internal use only|proprietary|private)/ => 1, true => 0)
| aggregate count AS email_count, sum(bytes_out) AS total_bytes_sent, distinct_count(dest_domain) AS distinct_recipient_domains, collect(dest_domain) AS recipient_domains, sum(is_personal_domain) AS personal_email_count, sum(has_sensitive_subject) AS sensitive_subject_count by user window 1d
| where (email_count > 100 AND total_bytes_sent > 52428800) OR personal_email_count > 20 OR sensitive_subject_count > 5
| select strftime(timestamp, "%Y-%m-%d %H:%M:%S") AS time_window_start, user, email_count, round(total_bytes_sent / 1024 / 1024, 2) AS total_mb_sent, distinct_recipient_domains, personal_email_count, sensitive_subject_count, recipient_domains
```
