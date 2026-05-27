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
from winlogbeat-*
| where event.module = "sysmon" and event.code = "11"
  and file.path rlike ".*\\\\inetpub\\\\wwwroot\\\\.*"
  and (
    file.path rlike "(?i).*(UpdateChecker|RecShell|DropShell|EmbedShell)\\.aspx$"
    or (process.executable rlike ".*w3wp\\.exe$" and file.path rlike ".*\\.aspx$")
  )
| stats
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  by host.name, process.executable, file.path
| keep firstTime, lastTime, host.name, process.executable, file.path, count
| eval firstTime = TO_STRING(firstTime, "yyyy-MM-dd HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd HH:mm:ss")
| rename host.name as endpoint, process.executable as process_path, file.path as file_path
| sort firstTime asc
```

### Suspicious Scheduled Task Creation
---
```sql
from winlogbeat-*
| where winlog.channel = "Security" and winlog.event_id = "4698"
  and (
    winlog.event_data.Command rlike "(?i).*(temp|tmp|users\\\\public|appdata|programdata|recycler)\\\\.*"
    or winlog.event_data.Command rlike "(?i).*(powershell.*(enc|invoke|iex|iwr|download)|cmd /c|mshta\\.exe|certutil\\.exe|bitsadmin\\.exe|wscript\\.exe|cscript\\.exe|rundll32\\.exe).*"
    or winlog.event_data.Command rlike "(?i).*[a-zA-Z0-9]{12,}\\.exe"
  )
| stats
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  by host.name, winlog.event_data.TaskName, winlog.event_data.Command, winlog.event_data.AccountName
| keep firstTime, lastTime, host.name, winlog.event_data.TaskName, winlog.event_data.Command, winlog.event_data.AccountName, count
| eval firstTime = TO_STRING(firstTime, "yyyy-MM-dd HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd HH:mm:ss")
| rename host.name as endpoint, winlog.event_data.TaskName as task_name, winlog.event_data.Command as task_command, winlog.event_data.AccountName as user
| sort firstTime asc
```

### Proxy and Tunneling Tool Execution
---
```sql
from winlogbeat-*
| where event.module = "sysmon" and event.code = "1"
  and (
    process.executable rlike "(?i).*(plink\\.exe|ngrok\\.exe|glider\\.exe)$"
    or process.command_line rlike "(?i).*ReverseSocks5.*"
  )
| stats
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  by host.name, user.name, process.parent.executable, process.executable, process.command_line, process.entity_id
| keep firstTime, lastTime, host.name, user.name, process.parent.executable, process.executable, process.command_line, process.entity_id, count
| eval firstTime = TO_STRING(firstTime, "yyyy-MM-dd HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd HH:mm:ss")
| rename host.name as endpoint, user.name as user, process.parent.executable as parent_process, process.executable as process_path, process.command_line as process_command_line, process.entity_id as process_guid
| sort firstTime asc
```

### RDP or PsExec Lateral Movement Activity
---
```sql
from winlogbeat-*
| where (
    (winlog.channel = "System" and winlog.event_id = "7045" and (
      winlog.event_data.ServiceName = "PSEXESVC"
      or winlog.event_data.ServiceFileName rlike "(?i).*PSEXESVC\\.exe$"
    ))
    or (event.module = "sysmon" and event.code = "1" and (
      process.executable rlike ".*PSEXESVC\\.exe$"
      or (process.executable rlike ".*[C|c]:\\\\[W|w][I|i][N|n][D|d][O|o][W|w][S|s]\\\\.*\\.exe$"
          and process.executable rlike "(?i).*[C|c]:\\\\[W|w][I|i][N|n][D|d][O|o][W|w][S|s]\\\\[a-zA-Z0-9]{8,}\\.exe$")
    ))
    or (winlog.channel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" and winlog.event_id = "1149")
  )
| eval activity_type = case(
    winlog.event_id = "7045" or event.code = "7045", "PsExec Service Installation",
    winlog.event_id = "1" or event.code = "1", "PsExec-like Process Execution",
    winlog.event_id = "1149", "Successful RDP Logon",
    "Unknown"
  ),
  user = COALESCE(winlog.event_data.AccountName, user.name),
  details = COALESCE(
    winlog.event_data.ServiceFileName,
    process.executable,
    process.command_line,
    CONCAT("Source IP: ", source.ip),
    winlog.event_data.param1
  )
| stats
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp),
    activities = GROUP_CONCAT(activity_type),
    users = GROUP_CONCAT(user),
    activity_details = GROUP_CONCAT(details)
  by host.name
| keep firstTime, lastTime, host.name, activities, users, activity_details, count
| eval firstTime = TO_STRING(firstTime, "yyyy-MM-dd HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd HH:mm:ss")
| rename host.name as endpoint
| sort firstTime asc
```

### Virtualization Infrastructure Reconnaissance
---
```sql
from winlogbeat-*
| where event.module = "sysmon" and event.code = "1"
  and (
    (process.executable rlike ".*powershell\\.exe$" and process.command_line rlike "(?i).*(Get-VM|Get-VMSwitch|Get-VMNetworkAdapter|Get-VHD).*")
    or process.executable rlike "(?i).*vmware-toolbox-cmd\\.exe$"
    or (process.executable rlike ".*wmic\\.exe$" and process.command_line rlike "(?i).*root\\\\virtualization.*")
    or (process.executable rlike ".*sc\\.exe$" and process.command_line rlike "(?i).*query\\s+(vmms|vmmemctl|vmtools|vboxservice).*")
  )
| stats
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  by host.name, user.name, process.parent.executable, process.executable, process.command_line
| keep firstTime, lastTime, host.name, user.name, process.parent.executable, process.executable, process.command_line, count
| eval firstTime = TO_STRING(firstTime, "yyyy-MM-dd HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd HH:mm:ss")
| rename host.name as endpoint, user.name as user, process.parent.executable as parent_process, process.executable as process_path, process.command_line as process_command_line
| sort firstTime asc
```

### Suspicious IIS Module Load for Custom Backdoor
---
```sql
from winlogbeat-*
| where event.module = "sysmon" and event.code = "7"
  and process.executable rlike ".*\\\\w3wp\\.exe$"
  and not (winlog.event_data.Signature rlike "Microsoft.*")
  and (
    file.path rlike ".*\\\\inetpub\\\\wwwroot\\\\.*"
    or file.path rlike ".*\\\\Temp\\\\.*"
    or file.path rlike ".*\\\\tmp\\\\.*"
    or file.path rlike ".*\\\\ProgramData\\\\.*"
  )
| stats
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  by host.name, process.executable, file.path, winlog.event_data.Signature, winlog.event_data.Signed, winlog.event_data.Description
| keep firstTime, lastTime, host.name, process.executable, file.path, winlog.event_data.Signature, winlog.event_data.Signed, winlog.event_data.Description, count
| eval firstTime = TO_STRING(firstTime, "yyyy-MM-dd HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd HH:mm:ss")
| rename host.name as endpoint, process.executable as process_path, file.path as module_path, winlog.event_data.Signature as signature, winlog.event_data.Signed as is_signed, winlog.event_data.Description as module_description
| sort firstTime asc
```

### Suspicious In-Memory Execution via Process Injection (Havoc/SystemBC)
---
```sql
from winlogbeat-*
| where event.module = "sysmon" and event.code = "8"
  and (winlog.event_data.StartModule IS NULL OR winlog.event_data.StartModule rlike ".*UNKNOWN.*")
  and (
    (process.executable rlike ".*\\\\(rundll32\\.exe|svchost\\.exe|regsvr32\\.exe|powershell\\.exe)$")
    and (winlog.event_data.TargetImage rlike ".*\\\\(explorer\\.exe|svchost\\.exe|notepad\\.exe|msiexec\\.exe|aspnet_compiler\\.exe)$")
  )
| stats
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  by host.name, process.executable, winlog.event_data.TargetImage, winlog.event_data.SourceProcessGuid, winlog.event_data.TargetProcessGuid, winlog.event_data.StartAddress, winlog.event_data.StartModule, user.name
| keep firstTime, lastTime, host.name, process.executable, winlog.event_data.TargetImage, winlog.event_data.SourceProcessGuid, winlog.event_data.TargetProcessGuid, winlog.event_data.StartAddress, winlog.event_data.StartModule, user.name, count
| eval firstTime = TO_STRING(firstTime, "yyyy-MM-dd HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd HH:mm:ss")
| rename host.name as endpoint, process.executable as source_process, winlog.event_data.TargetImage as target_process, winlog.event_data.SourceProcessGuid as source_process_guid, winlog.event_data.TargetProcessGuid as target_process_guid, winlog.event_data.StartAddress as start_address, winlog.event_data.StartModule as start_module, user.name as user
| sort firstTime asc
```

### ZKTeco ZKBioTime Post-Exploitation Activity
---
```sql
from winlogbeat-*
| where event.module = "sysmon" and event.code = "1"
  and process.parent.executable rlike "(?i).*(BioTime|ZKBioTime|ZKTimeNet).*"
  and process.executable rlike "(?i).*\\\\(cmd\\.exe|powershell\\.exe|wscript\\.exe|cscript\\.exe|rundll32\\.exe|certutil\\.exe|bitsadmin\\.exe|whoami\\.exe|net\\.exe|net1\\.exe|systeminfo\\.exe|mshta\\.exe)$"
| stats
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  by host.name, user.name, process.parent.executable, process.executable, process.command_line, process.entity_id
| keep firstTime, lastTime, host.name, user.name, process.parent.executable, process.executable, process.command_line, process.entity_id, count
| eval firstTime = TO_STRING(firstTime, "yyyy-MM-dd HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd HH:mm:ss")
| rename host.name as endpoint, user.name as user, process.parent.executable as parent_process, process.executable as process_path, process.command_line as process_command_line, process.entity_id as process_guid
| sort firstTime asc
```

### Targeted Phishing for Administrator Credentials
---
```sql
from logs-email-*
| where email.status = "delivered"
  and email.to.address in (
    select email_address from admin_users where is_admin = true
  )
  and email.from.domain not in (
    select domain from internal_domains
  )
  and (
    email.subject rlike "(?i).*(password|verify|urgent|action required|suspension|invoice|credentials|security alert|account validation).*"
    or email.attachment.file.name rlike "(?i).*(html|htm|zip|iso|lnk|vbs|js)$"
  )
| stats
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  by email.from.address, email.to.address, email.subject, email.attachment.file.name, source.ip
| keep firstTime, lastTime, email.from.address, email.to.address, email.subject, email.attachment.file.name, source.ip, count
| eval firstTime = TO_STRING(firstTime, "yyyy-MM-dd HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd HH:mm:ss")
| rename email.from.address as email_sender, email.to.address as email_recipient, email.subject as email_subject, email.attachment.file.name as attachment_name, source.ip as source_ip
| sort firstTime asc
```

### Email Data Exfiltration via High Volume or Suspicious Destination
---
```sql
from logs-email-*
| where email.direction = "outbound"
  and email.from.address in (
    select email_address from internal_users where is_internal = true
  )
  and email.to.domain not in (
    select domain from internal_domains
  )
| eval
    is_personal_domain = case(
      email.to.domain RLIKE "(?i).*(gmail\\.com|yahoo\\.com|outlook\\.com|hotmail\\.com|aol\\.com|protonmail\\.com|icloud\\.com)", 1, 0
    ),
    has_sensitive_subject = case(
      email.subject RLIKE "(?i).*(confidential|secret|internal use only|proprietary|private)", 1, 0
    )
| stats
    email_count = COUNT(*),
    total_bytes_sent = SUM(email.message_size),
    distinct_recipient_domains = COUNT(DISTINCT email.to.domain),
    recipient_domains = GROUP_CONCAT(email.to.domain),
    personal_email_count = SUM(is_personal_domain),
    sensitive_subject_count = SUM(has_sensitive_subject),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp)
  by DATE_TRUNC(1 day, @timestamp) AS time_window_start, email.from.address
| where (email_count > 100 and total_bytes_sent > 52428800)
    or personal_email_count > 20
    or sensitive_subject_count > 5
| eval
    firstTime = TO_STRING(firstTime, "yyyy-MM-dd HH:mm:ss"),
    lastTime = TO_STRING(lastTime, "yyyy-MM-dd HH:mm:ss"),
    total_mb_sent = ROUND(total_bytes_sent / 1024 / 1024, 2)
| keep time_window_start, email.from.address, email_count, total_mb_sent, distinct_recipient_domains, personal_email_count, sensitive_subject_count, recipient_domains
| rename email.from.address as user
| sort time_window_start asc
```
