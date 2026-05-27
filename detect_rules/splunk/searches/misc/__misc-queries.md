## Miscellaneous Queries

### Credential Dumping to ADMIN localhost
---

Detects the credential dumping, creating a dump in the ADMIN tmp.


```sql
index=* source="WinEventLog:*" AND ((Image="*\\cmd.exe" OR OriginalFileName="cmd.exe") AND CommandLine="*/c wmic process call create*" AND (CommandLine="*\"cmd.exe /c mkdir C:\\Windows\\Temp\\tmp*" OR CommandLine="*& ntdsutil \\\"ac i ntds\\\" ifm \\\"create full C:\\Windows\\Temp\\tmp\\\" 1> \\127.0.0.1\\ADMIN$\\ 2>&1*"))
```

### Enumeration techniques
---

The following commands were used by the actor to enumerate the network topology [T1016], the active directory structure [T1069.002], and other information about the target environment [T1069.001], [T1082]:


```sql
index=* source="WinEventLog:*" AND (CommandLine="*ipconfig /all*" OR CommandLine="*netsh interface show interface*" OR CommandLine="*netsh interface firewall show all*" OR CommandLine="*arp -a*" OR CommandLine="*nbtstat -n*" OR CommandLine="*net config*" OR CommandLine="*net group /dom*" OR CommandLine="*net group \"Domain Admins\" /dom*" OR CommandLine="*route print*" OR CommandLine="*curl www.ip-api.com*" OR CommandLine="*dnscmd*" OR CommandLine="*ldifde.exe -f c:\\windows\\temp\\.txt -p subtree*" OR CommandLine="*netlocalgroup*" OR CommandLine="*netsh interface portproxy show*" OR CommandLine="*netstat -ano*" OR CommandLine="*reg query hklm\\software\\*" OR CommandLine="*systeminfo*" OR CommandLine="*tasklist /v *" OR CommandLine="*wmic volume list brief*" OR CommandLine="*wmic service brief*" OR CommandLine="*wmic product list brief*" OR CommandLine="*wmic baseboard list brief*" OR CommandLine="*wevtutil qe security /rd:true /f:text /q:*[System[(EventID=4624) *")
```

```sql
index=* source="WinEventLog:*" AND (CommandLine="*ipconfig /all*" OR CommandLine="*netsh interface show interface*" OR CommandLine="*arp -a*" OR CommandLine="*nbtstat -n*" OR CommandLine="*net config*" OR CommandLine="*route print*")
```

### Illicit Consent Grant
---

This rule detects when an application consent operation occurs in Azure Active Directory, specifically looking for broad consent types such as 'AllPrincipals' or when an administrator has granted consent. This can indicate a malicious application gaining wide permissions within the Azure AD tenant.

T1078.004 - Cloud Accounts

DS0015 - Application Log

TA0001 - Initial Access

T1528 - Steal Application Access Token

TA0006 - Credential Access

```sql
index="o365" sourcetype="audit" Operation="Consent to application." app="AzureActiveDirectory"
| where mvfind('modified_properties', "ConsentType.*AllPrincipals") >= 0 OR mvfind('modified_properties', "IsAdminConsent.*True") = 0
| rex field=modified_properties "Scope:\s*(?<scope_list>[^\]]+)"
| eval scope_array = split(scope_list, ", ")
| mvexpand scope_array
| eval Timestamp=strftime(_time,"%Y-%m-%d %H:%M:%S:%Q")
| stats values(Timestamp) as timestamp values(AppId) as AppId values(user) as user values(user_agent) as user_agent values(scope_array) as scope_array values(modified_properties) as modified_properties values(result) as result count by object, ObjectId
```

### Uncommon Network Connection Initiated By Certutil.exe
---

Within a few hours of initial exploitation, APT41 used the storescyncsvc.dll BEACON backdoor to download a secondary backdoor with a different C2 address that uses Microsoft CertUtil, a common TTP that we've observed APT41 use in past intrusions, which they then used to download 2.exe (MD5: 3e856162c36b532925c8226b4ed3481c). The file 2.exe was a VMProtected Meterpreter downloader used to download Cobalt Strike BEACON shellcode. The usage of VMProtected binaries is another very common TTP that we've observed this group leverage in multiple intrusions in order to delay analysis of other tools in their toolkit.


```sql
index=* source="WinEventLog:*" AND (Image="*\\certutil.exe" AND Initiated="true" AND (DestinationPort="80" OR DestinationPort="135" OR DestinationPort="443" OR DestinationPort="445"))
```

### Credential/Info Theft
---
```sql
--
-- metadata:
--   author: Rob Weber
--   date: 2025-07-24
--   name: Non-Browser Process Accessing Browser Credential Store
--   description: >
--     Detects when a process, that is not a standard web browser, accesses files known to store user credentials for browsers like Chrome, Edge, and Firefox. This behavior is a common TTP for information-stealing malware, which aims to exfiltrate sensitive data.
--
`cim_Endpoint_Filesystem`

`# Filter for access to known browser credential database files.`
| where (
    match(file_path, /(?i)AppData\\Local\\Google\\Chrome\\User Data\\.*\\Login Data/) OR
    match(file_path, /(?i)AppData\\Local\\Microsoft\\Edge\\User Data\\.*\\Login Data/) OR
    match(file_path, /(?i)AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\.*\\logins\.json/) OR
    match(file_path, /(?i)AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\.*\\key4\.db/) OR
    match(file_path, /(?i)AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\.*\\Login Data/) OR
    match(file_path, /(?i)AppData\\Roaming\\Opera Software\\Opera Stable\\Login Data/)
)

`# Exclude legitimate browser processes that are expected to access these files.`
| where NOT (process_name IN ("chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "opera.exe"))

`# False Positive Tuning: Legitimate applications like password managers or system backup tools might access these files.`
`# Add known legitimate processes to the exclusion list below to reduce noise.`
`# Example: | search NOT process_name IN ("LastPass.exe", "backup_tool.exe")`

`# Group the results to create a clear alert.`
| stats count, values(file_path) as accessed_files, values(action) as actions_taken by _time, dest, user, process_name, process_path
| rename dest as "Endpoint", user as "User", process_name as "Process_Name", process_path as "Process_Path", accessed_files as "Accessed_Credential_Files", actions_taken as "File_Actions"
```

### Credential Theft
---

The actor also used the following commands to identify additional opportunities for obtaining credentials in the environment [T1555], [T1003]:

Detects the usage of "reg.exe" in order to query information from the registry like software.


```sql
index=* source="WinEventLog:*" AND ((Image="*\\reg.exe" OR OriginalFileName="reg.exe") AND CommandLine="*save*" AND (CommandLine="*reg save hklm\\sam ss.dat*" OR CommandLine="*reg save hklm\\system sy.dat*" OR CommandLine="*reg save hklm\\system*" OR CommandLine="*reg save hklm\\sam*"))
```

```sql
index=* source="WinEventLog:*" AND ((Image="*\\reg.exe" OR OriginalFileName="reg.exe") AND CommandLine="*query*" AND (CommandLine="*reg query hklm\\software\\OpenSSH*" OR CommandLine="*reg query hklm\\software\\OpenSSH\\Agent*" OR CommandLine="*reg query hklm\\software\\realvnc*" OR CommandLine="*reg query hklm\\software\\realvnc\\vncserver*" OR CommandLine="*reg query hklm\\software\\realvnc\\Allusers*" OR CommandLine="*reg query hklm\\software\\realvnc\\Allusers\\vncserver*" OR CommandLine="*reg query hkcu\\software\*\\putty\\session*"))
```

```sql
index=* source="WinEventLog:*" AND (Image="*\\regedit.exe" AND (CommandLine="* /E *" OR CommandLine="* -E *") AND (CommandLine="*hklm*" OR CommandLine="*hkey_local_machine*") AND (CommandLine="*\\system" OR CommandLine="*\\sam" OR CommandLine="*\\security")) | table ParentImage,CommandLine
```

### Possible DCSync Attack Detected via AD Replication and Network Indicators
---

Detects potential DCSync attacks by correlating Active Directory replication requests (Event ID 4662) with suspicious network activity (Sysmon Event ID 3). DCSync allows attackers with replication privileges to request credential data from domain controllers, mimicking legitimate replication traffic.

```sql
index=* (sourcetype=WinEventLog:Security OR sourcetype=WinEventLog:ForwardedEvents) EventCode=4662
| where like(Object_Type, "%19195a5b-6da0-11d0-afd3-00c04fd930c9%") OR
        like(Object_Type, "%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%") OR
        like(Object_Type, "%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%") OR
        like(Object_Type, "%89e95b76-444d-4c62-991a-0facbeda640c%") OR
        like(Object_Type, "%replicationSynchronization%") OR
        like(Object_Type, "%replicating Directory Changes All%")
| search Access_Mask=0x100
| eval Ticket_Time = _time
| eval Account_Name=lower(Account_Name)
| eval Descriptive_Object_Type = case(
    like(Object_Type, "%19195a5b-6da0-11d0-afd3-00c04fd930c9%"), "Directory Replication",
    like(Object_Type, "%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%"), "Replicating Directory Changes",
    like(Object_Type, "%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%"), "Replicating Directory Changes All",
    like(Object_Type, "%89e95b76-444d-4c62-991a-0facbeda640c%"), "Replicating Directory Changes In Filtered Set",
    like(Object_Type, "%replicationSynchronization%"), "General Replication Synchronization",
    like(Object_Type, "%replicating Directory Changes All%"), "General Replication of All Directory Changes",
    1==1, "Unknown"
)
| table Account_Name, Ticket_Time, Descriptive_Object_Type
| append [
    search index=* sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=3
    (DestinationPort=135 OR DestinationPort=389 OR DestinationPort=88)
    | rex field=_raw "User:\s(?[^\s]+)"
    | eval Account_Name=lower(mvindex(split(user_domain, "\\"),1))
    | eval Network_Time = _time
    | table Account_Name, Network_Time, Image, DestinationPort
]
| stats values(Descriptive_Object_Type) as Object_Type, values(Image) as Image, values(DestinationPort) as DestinationPort,
        min(Ticket_Time) as Ticket_Time, min(Network_Time) as Network_Time,
        count(eval(isnotnull(Ticket_Time))) as Ticket_Count,
        count(eval(isnotnull(Network_Time))) as Network_Count by Account_Name
| where isnotnull(Object_Type) AND isnotnull(Network_Time)
| where abs(Ticket_Time - Network_Time) <= 1800
| eval Network_Time=strftime(Network_Time, "%Y-%m-%d %H:%M:%S")
| eval Ticket_Time=strftime(Ticket_Time, "%Y-%m-%d %H:%M:%S")
| table Account_Name, Object_Type, Image, DestinationPorts, Network_Time, Network_Count. Ticket_Time, Ticket_Count
```

### Defender Exclusion Added via WMIC
---

    T1047 - Windows Management Instrumentation
    T1562.001 - Disable or Modify Tools
    TA0002 - Execution
    TA0005 - Defense Evasion
    Process Creation
    Windows
    Windows Event Log (Security)

```sql
index=* sourcetype=WinEventLog EventCode=4688 NewProcessName="*wmic.exe" CommandLine="*defender*" CommandLine="*msft_mppreference*" CommandLine="*call*" CommandLine="*add*" CommandLine="*exclusionpath*" "4688" "wmic.exe"
```

### Failed Authentication to Non-existing Accounts
---

    T1110 - Brute Force
    T1078.002 - Domain Accounts
    TA0006 - Credential Access
    TA0005 - Defense Evasion
    TA0003 - Persistence
    TA0004 - Privilege Escalation
    TA0001 - Initial Access

```sql
source="WinEventLog:security" sourcetype="WinEventLog:Security" EventCode=4625 Sub_Status=0xC0000064
| eval Date=strftime(_time, "%Y/%m/%d")
| rex "Which\sLogon\sFailed:\s+Security\sID:\s+\S.*\s+\w+\s\w+\S\s.(?<uacct>\S.*)"
| stats count by Date, uacct, host
| rename count as "Attempts"
| sort - Attempts
```

### Lsass Memory Dump via Comsvcs DLL
---

Detects adversaries leveraging the MiniDump export function from comsvcs.dll via rundll32 to perform a memory dump from lsass.

```sql
index=* source="WinEventLog:*" AND (TargetImage="*\\lsass.exe" AND SourceImage="C:\\Windows\\System32\\rundll32.exe" AND CallTrace="*comsvcs.dll*")
```

### MiTM Proxy Detection

```sql
| tstats count from datamodel=Web.Web where Web.http_method IN ("GET", "POST") Web.url="*.php" OR Web.url="*login*" OR Web.url="*auth*" by Web.src, Web.dest, Web.url, Web.http_user_agent, Web.http_status, Web.ssl_issuer
| where Web.http_status IN (200, 301, 302) AND (Web.url="*.php" OR Web.url="*login*" OR Web.url="*auth*")
| eval is_suspicious_ssl=if(Web.ssl_issuer LIKE "%Let’s Encrypt%" OR Web.ssl_issuer="unknown" OR isnull(Web.ssl_issuer), 1, 0)
| search is_suspicious_ssl=1
| stats count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_user_agent) as user_agents values(Web.ssl_issuer) as ssl_issuers by Web.src, Web.dest
| where count > 5
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rename Web.src as src_ip, Web.dest as dest_host
| eval potential_mitm=if(match(dest_host, "(microsoftonline|office365|login|outlook|okta|github|linkedin|amazon)\S*\.(com|org|eu|shop)"), "Possible phishing proxy", "Other suspicious proxy")
| table firstTime, lastTime, src_ip, dest_host, urls, user_agents, ssl_issuers, potential_mitm, count
```

### Potential Recon Activity Via Nltest.exe
---

Detects nltest commands that can be used for information discovery.

```sql
index=* source="WinEventLog:*" AND (Image="*\\nltest.exe" OR OriginalFileName="nltestrk.exe")
```

```sql
index=* source="WinEventLog:*" AND ((Image="*\\nltest.exe" OR OriginalFileName="nltestrk.exe") AND (((CommandLine="*/server*") AND (CommandLine="*/query*")) OR (CommandLine="*/dclist:*" OR CommandLine="*/parentdomain*" OR CommandLine="*/domain_trusts*" OR CommandLine="*/all_trusts*" OR CommandLine="*/trusted_domains*" OR CommandLine="*/user*"))) | table Image,User,CommandLine,ParentCommandLine
```

### Port Proxy T1090
---

The actor has used the following commands to enable port forwarding [T1090] on the host: “cmd.exe /c “netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress= connectport=8443 protocol=tcp""


```sql
index=* source="WinEventLog:*" AND ((Image="*\\cmd.exe" OR OriginalFileName="cmd.exe") AND ((CommandLine="*netsh *") AND (CommandLine="*interface *") AND (CommandLine="*portproxy *") AND (CommandLine="*add *" OR CommandLine="*listenport *" OR CommandLine="*connetaddress= *" OR CommandLine="*connectport=1433*")))
```

### Process Injection T1055
---

State-sponsored cyber actors have been observed: Injecting into the rundll32.exe process to hide usage of Mimikatz, as well as injecting into a running legitimate explorer.exe process for lateral movement.

```sql
index=* source="WinEventLog:*" AND ((CommandLine="*DumpCreds*" OR CommandLine="*mimikatz*") OR (CommandLine="*::aadcookie*" OR CommandLine="*::detours*" OR CommandLine="*::memssp*" OR CommandLine="*::mflt*" OR CommandLine="*::ncroutemon*" OR CommandLine="*::ngcsign*" OR CommandLine="*::printnightmare*" OR CommandLine="*::skeleton*" OR CommandLine="*::preshutdown*" OR CommandLine="*::mstsc*" OR CommandLine="*::multirdp*") OR (CommandLine="*rpc::*" OR CommandLine="*token::*" OR CommandLine="*crypto::*" OR CommandLine="*dpapi::*" OR CommandLine="*sekurlsa::*" OR CommandLine="*kerberos::*" OR CommandLine="*lsadump::*" OR CommandLine="*privilege::*" OR CommandLine="*process::*" OR CommandLine="*vault::*"))
```

### Detect Web Shell Activity (Command Execution from Web Directory)
---

This rule detects the execution of common command-line utilities (wget, curl, nc, bash, python, perl, php, sh) within web server directories. This activity is highly suspicious as it could indicate an attacker attempting to download malicious files, execute web shells, or perform other post-exploitation activities on a compromised web server.

T1105 - Ingress Tool Transfer

T1059 - Command and Scripting Interpreter

T1059.004 - Unix Shell

T1059.006 - Python

T1505.003 - Web Shell

TA0011 - Command and Control

TA0002 - Execution

TA0003 - Persistence

```sql
index=os_logs OR index=webserver_logs
(process_name="*" OR cmdline="*")
| search cmdline IN ("wget*", "curl*", "nc*", "bash*", "python*", "perl*", "php*", "sh*")
| where like(file_path, "/var/www%") OR like(file_path, "C:\\inetpub\\wwwroot%")
| stats count by host, user, file_path, cmdline, _time
```

### Suspicious File Activity by mstsc.exe
---

T1021.001 - Remote Desktop Protocol

T1219.002 - Remote Desktop Software

T1563.002 - RDP Hijacking

TA0008 - Lateral Movement

TA0011 - Command and Control

```sql
| tstats `security_content_summaries` from datamodel=Endpoint.Filesystem where Filesystem.EventCode=11 AND (Filesystem.Image="*\\mstsc.exe" OR Filesystem.ParentImage="*\\mstsc.exe") NOT (Filesystem.TargetFilename="*\\AppData\\Local\\Temp\\_TS*.tmp" OR Filesystem.TargetFilename="*\\AppData\\Local\\Microsoft\\Terminal Server Client\\*") by Filesystem.dest, Filesystem.Image, Filesystem.ParentImage, Filesystem.TargetFilename, Filesystem.User, Filesystem.CommandLine
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### Mshta Launching Certutil with Malicious HTA
---

https://redcanary.com/threat-detection-report/techniques/mshta/

Detects suspicious use of mshta.exe to execute HTA files followed by certutil.exe for potential data decoding operations related to executable file downloads.

T1218.005 - Mshta

S0160 - certutil

T1105 - Ingress Tool Transfer

TA0005 - Defense Evasion

TA0011 - Command and Control

```sql
| tstats `security_content_summaries` from datamodel=Endpoint.Processes
    where (Processes.process_name="mshta.exe" OR Processes.process_name="certutil.exe" OR Processes.process_name="dialer.exe")
    by Processes.process_id, Processes.parent_process_id, Processes.process_name, Processes.process, Processes.command_line, Processes.user, Processes.dest, _time
| `drop_dm_object_name(Processes)`
| rename process_id as proc_id, parent_process_id as pproc_id, process_name as proc_name, process as proc, command_line as cmd, user as user, dest as dest
| join pproc_id [
    | tstats `security_content_summaries` from datamodel=Endpoint.Processes
        where Processes.process_name="mshta.exe"
        by Processes.process_id, Processes.process, Processes.command_line, _time
    | `drop_dm_object_name(Processes)`
    | rename process_id as mshta_proc_id, process as mshta_proc, command_line as mshta_cmd, _time as mshta_time
]
| where mshta_proc_id = pproc_id AND proc_name="certutil.exe"
| where (mshta_cmd LIKE "%temp%\\%.hta%" OR mshta_cmd LIKE "%AppData\\Local\\Temp\\%.hta%")
    AND (cmd LIKE "%-decode%" AND (cmd LIKE "%temp%\\%" OR cmd LIKE "%AppData\\Local\\Temp\\%"))
    AND (cmd LIKE "%.pdf" OR cmd LIKE "%.dll" OR cmd LIKE "%.txt" OR cmd LIKE "%.zip")
| `security_content_ctime(mshta_time)`
| fields _time, user, dest, mshta_proc, mshta_cmd, proc, cmd
```

### Suspicious Volume Shadow Copy Deletion
---

This detection identifies attempts to delete volume shadow copies using common utilities like vssadmin, wmic, or PowerShell. This is a technique frequently used by ransomware before encryption to prevent easy restoration of files.

T1490 - Inhibit System Recovery

TA0040 - Impact

```sql
-- This detection rule requires process execution logs (e.g., Sysmon Event ID 1, Windows Security Event ID 4688) mapped to the Endpoint.Processes CIM data model.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
  where (
    (Processes.process_name="vssadmin.exe" AND Processes.process="*delete*" AND Processes.process="*shadows*") OR
    (Processes.process_name="wmic.exe" AND Processes.process="*shadowcopy*" AND Processes.process="*delete*") OR
    (Processes.process_name IN ("powershell.exe", "pwsh.exe") AND Processes.process="*Win32_ShadowCopy*" AND (Processes.process="*Delete*" OR Processes.process="*Remove-CimInstance*"))
  )
  by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`

`#
# FP & Tuning
#
# While this activity is highly suspicious, legitimate administrators may occasionally perform it for maintenance.
# If this generates noise from specific admin accounts or servers, consider adding them to an allow-list.
# Example: | search NOT (user IN ("authorized_admin_account") AND dest IN ("utility_server*"))
#`

`#
# OUTPUT FORMATTING
#`
| rename dest as host, user as executing_user, parent_process_name as parent_process, process_name as process, process as command_line
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, executing_user, parent_process, process, command_line, count
```

### Search Common EventCodes (EventID's) for Suspicious Behavior
---

mappings:

    T1003 - OS Credential Dumping
    T1078 - Valid Accounts
    T1086 - PowerShell
    T1055 - Process Injection
    TA0006 - Credential Access
    TA0005 - Defense Evasion
    TA0003 - Persistence
    TA0004 - Privilege Escalation
    TA0001 - Initial Access
    TA0002 - Execution

```sql
source="wineventlog:security" user!="DWM-*" user!="UMFD-*" user!=SYSTEM user!="LOCAL SERVICE" user!="NETWORK SERVICE" user!="*$" user!="ANONYMOUS LOGON" user!="IUSR"
| eval Trigger=case(EventCode=516, "Audit Logs Modified",EventCode=517, "Audit Logs Modified",EventCode=612, "Audit Logs Modified",EventCode=623, "Audit Logs Modified",EventCode=806, "Audit Logs Modified",EventCode=807, "Audit Logs Modified",EventCode=1101, "Audit Logs Modified",EventCode=1102, "Audit Logs Modified",EventCode=4612, "Audit Logs Modified",EventCode=4621, "Audit Logs Modified",EventCode=4694, "Audit Logs Modified",EventCode=4695, "Audit Logs Modified",EventCode=4715, "Audit Logs Modified",EventCode=4719, "Audit Logs Modified",EventCode=4817, "Audit Logs Modified",EventCode=4885, "Audit Logs Modified",EventCode=4902, "Audit Logs Modified",EventCode=4906, "Audit Logs Modified",EventCode=4907, "Audit Logs Modified",EventCode=4912, "Audit Logs Modified", EventCode=642, "Account Modification",EventCode=646, "Account Modification",EventCode=685, "Account Modification",EventCode=4738, "Account Modification",EventCode=4742, "Account Modification",EventCode=4781, "Account Modification", EventCode=1102, "Audit Logs Cleared/Deleted",EventCode=517, "Audit Logs Cleared/Deleted", EventCode=628, "Passwords Changed",EventCode=627, "Passwords Changed",EventCode=4723, "Passwords Changed",EventCode=4724, "Passwords Changed", EventCode=528, "Successful Logons",EventCode=540, "Successful Logons",EventCode=4624, "Successful Logons", EventCode=4625, "Failed Logons",EventCode=529, "Failed Logons",EventCode=530, "Failed Logons",EventCode=531, "Failed Logons",EventCode=532, "Failed Logons",EventCode=533, "Failed Logons",EventCode=534, "Failed Logons",EventCode=535, "Failed Logons",EventCode=536, "Failed Logons",EventCode=537, "Failed Logons",EventCode=539, "Failed Logons", EventCode=576, "Escalation of Privileges",EventCode=4672, "Escalation of Privileges",EventCode=577, "Escalation of Privileges",EventCode=4673, "Escalation of Privileges",EventCode=578, "Escalation of Privileges",EventCode=4674, "Escalation of Privileges")
| stats earliest(_time) as Initial_Occurrence latest(_time) as Latest_Occurrence values(user) as Users values(host) as Hosts count sparkline by Trigger
| sort - count
| convert ctime(Initial_Occurrence) ctime(Latest_Occurrence)
```

### APT Creating a 7z Archive in temp
---

Detects the suspicious creation of a 7z achrive into the c:\windows\temp\ folder.

```sql
index=* source="WinEventLog:*" AND ((Image="*\\7z.exe" OR OriginalFileName="7z.exe") AND CommandLine="*a -p*" AND (CommandLine="*c:\\windows\\temp\\*"))
```

```sql
index=* source="WinEventLog:*" AND ((Image="*\\powershell.exe" OR OriginalFileName="powershell.exe") AND CommandLine="*start-process*" AND ((CommandLine="*filepath c:\\windows\\temp\\*") AND (CommandLine="*windowstyle Hidden rar.exe*")))
```

### Schtask
---

State-sponsored cyber actors have been observed using Cobalt Strike, webshells, or command line interface tools, such as schtask or crontab to create and schedule tasks that enumerate victim devices and networks. Note: this technique also applies to Persistence [TA0003] and Privilege Escalation [TA0004]. Monitor scheduled task creation from common utilities using command-line invocation and compare for any changes that do not correlate with known software, patch cycles, or other administrative activity. Configure event logging for scheduled task creation and monitor process execution from svchost.exe (Windows 10) and Windows Task Scheduler (Older version of Windows) to look for changes in %systemroot%\System32\Tasks that do not correlate with known software, patch cycles, or other administrative activity. Additionally monitor for any scheduled tasks created via command line utilities — such as PowerShell or Windows Management Instrumentation (WMI) — that do not conform to typical administrator or user actions.

```sql
index=* source="WinEventLog:*" AND ((Image="*\\schtasks.exe" AND CommandLine="* /create *") AND NOT (User="*AUTHORI*" OR User="*AUTORI*")) | table CommandLine,ParentCommandLine
```

```sql
index=* source="WinEventLog:Microsoft-Windows-TaskScheduler/Operational" AND (EventCode="129" AND (Path="*\\calc.exe" OR Path="*\\cscript.exe" OR Path="*\\mshta.exe" OR Path="*\\mspaint.exe" OR Path="*\\notepad.exe" OR Path="*\\regsvr32.exe" OR Path="*\\wscript.exe"))
```

```sql
index=* source="WinEventLog:*" AND ((Image="*\\schtasks.exe" OR OriginalFileName="schtasks.exe") AND CommandLine="*/Create*" AND (CommandLine="*FromBase64String*" OR CommandLine="*encodedcommand*") AND (CommandLine="*Get-ItemProperty*" OR CommandLine="* gp *") AND (CommandLine="*HKCU:*" OR CommandLine="*HKLM:*" OR CommandLine="*registry::*" OR CommandLine="*HKEY_*"))
```

```sql
index=* source="WinEventLog:*" AND ((Image="*\\schtasks.exe" OR OriginalFileName="schtasks.exe") AND CommandLine="* /create *" AND (CommandLine="*powershell*" OR CommandLine="*pwsh*" OR CommandLine="*cmd /c *" OR CommandLine="*cmd /k *" OR CommandLine="*cmd /r *" OR CommandLine="*cmd.exe /c *" OR CommandLine="*cmd.exe /k *" OR CommandLine="*cmd.exe /r *") AND (CommandLine="*C:\\ProgramData\\*" OR CommandLine="*%ProgramData%*")
```

### Remote Access of Windows Shares
---

The primary focus is to detect network access to administrative or system drive shares (C$, D$, E$, F$, U$, Admin$) while excluding local access (Event Code 5140). Specifically identifying remote session and other forms of login.

Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.

```sql
index=* sourcetype="WinEventLog:Security" LogName="Security" (EventCode=1149 OR (EventCode=4624 (Logon_Type=10 OR Logon_Type=7))) OR (EventCode=5140 (Share_Name="*\\C$" OR Share_Name="*D$" OR Share_Name="*E$" OR Share_Name="*F$" OR Share_Name="*U$" OR Share_Name="*Admin$") NOT Source_Address="::1")
| rename host AS Destination
| rename Account_Domain AS Domain
| stats values(Destination) as Destination values(Share_Name) as "Share Name" values(Share_Path) as "Share Path" values(Source_Address) as "SMB Source Address" values(Source_Network_Address) as "Login Source Address" values(Workstation_Name) as "Login Workstation Name" values(EventCode) as EventCode dc(EventCode) as EventCodeCount by Account_Name Logon_ID
| where EventCodeCount>1
```

### Powershell encoded command observed
---

```sql
index=windows LogName=Security TaskCategory="Process Creation" new_process_name IN (powershell.exe,pwsh.exe) OR Creator_Process_Name IN (*powershell.exe,*pwsh.exe) Process_Command_Line IN ("*EncodedCommand*","*-E *","*-Enc*","*-enco *","*-encod *", "*frombase64string*", "*gnirtS46esaBmorF*")
| rex field=Process_Command_Line ".+-EncodedCommand(?P<EncodedCommand>.+)"
| rex field=EncodedCommand "(?<check>^.{0,300})"
| stats values(host) as host values(Account_Name) AS user values(Creator_Process_Name) AS parent_process values(new_process_name) AS process_name values(EncodedCommand) as EncodedCommand by check, _time
| eval EncodedCommand = mvindex(EncodedCommand, 0)
| stats latest(_time) as time values(user) as user by host parent_process process_name EncodedCommand
| decrypt field=EncodedCommand b64 emit('decrypted_command')
| eval time=strftime(time, "%d-%m-%Y %X")
| table time host user parent_process process_name decrypted_command EncodedCommand
```

### Potential Proxy Bypass Detected
---

This rule detects potential proxy bypass attempts by identifying network connections on common web ports (80, 443) that are allowed by the network firewall but do not appear in the proxy logs. It correlates network traffic from the Network_Traffic data model with proxy traffic from the Web data model. The rule specifically filters for external-bound traffic by excluding private and multicast IP addresses.

T1090 - Proxy

T1090.002 - External Proxy

TA0011 - Command and Control

```sql
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.action=allowed (All_Traffic.dest_port=80 OR All_Traffic.dest_port=443) by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
-- Get all allowed network traffic on common web ports (80, 443) from the Network_Traffic data model. This represents all connections, including those that may have bypassed the proxy.")`
| `drop_dm_object_name("All_Traffic")`
| join type=left src, dest, dest_port [
    | tstats `summariesonly` count from datamodel=Web by Web.src, Web.dest, Web.dest_port
    -- Subsearch: Get all traffic from the Web data model to identify connections that correctly went through the proxy.")`
    | `drop_dm_object_name("Web")`
    | rename count as proxy_event_count
]
-- Correlate all network traffic with proxy-specific traffic using a left join. The goal is to find network events that have no matching proxy event for the same source, destination, and port.")`
| where isnull(proxy_event_count)
-- Filter for events that exist in Network_Traffic but are missing from the Web data model. This is the core logic to identify a potential proxy bypass.")`
| where NOT (cidrmatch("10.0.0.0/8", dest) OR cidrmatch("172.16.0.0/12", dest) OR cidrmatch("192.168.0.0/16", dest) OR cidrmatch("224.0.0.0/4", dest))
-- Filter out internal, private, and multicast destination addresses to focus on external-bound traffic.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, src, dest, dest_port, count
-- This detection may generate false positives for legitimate applications that do not use system proxy settings (e.g., some software updaters, thick clients) or for network segments intentionally not routed through the proxy. Consider filtering by adding a line like: | where dest NOT IN (known_good_bypassed_dest1, known_good_bypassed_dest2)")`
```

### NTDS.DIT Exfiltration Detection
---

The actor may try to exfiltrate the ntds.dit file and the SYSTEM registry hive from Windows domain controllers (DCs) out of the network to perform password cracking [T1003.003]. (The ntds.dit file is the main Active Directory (AD) database file and, by default, is stored at %SystemRoot%\NTDS\ntds.dit. This file contains information about users, groups, group memberships, and password hashes for all users in the domain; the SYSTEM registry hive contains the boot key that is used to encrypt information in the ntds.dit file.) Although the ntds.dit file is locked while in use by AD, a copy can be made by creating a Volume Shadow Copy and extracting the ntds.dit file from the Shadow Copy. The SYSTEM registry hive may also be obtained from the Shadow Copy.

Hunting Translation Splunk — Keep it simple

```sql
index=* source="WinEventLog:*" AND TargetFilename="*ntds.dit"
```

```sql
index=* source="WinEventLog:*" AND ((((Image="*\\NTDSDump.exe" OR Image="*\\NTDSDumpEx.exe") OR ((CommandLine="*ntds.dit*") AND (CommandLine="*system.hiv*")) OR CommandLine="*NTDSgrab.ps1*") OR ((CommandLine="*ac i ntds*") AND (CommandLine="*create full*")) OR ((CommandLine="*/c copy *") AND (CommandLine="*\\windows\\ntds\\ntds.dit*")) OR ((CommandLine="*activate instance ntds*") AND (CommandLine="*create full*")) OR ((CommandLine="*powershell*") AND (CommandLine="*ntds.dit*"))) OR (CommandLine="*ntds.dit*" AND ((ParentImage="*\\apache*" OR ParentImage="*\\tomcat*" OR ParentImage="*\\AppData\\*" OR ParentImage="*\\Temp\\*" OR ParentImage="*\\Public\\*" OR ParentImage="*\\PerfLogs\\*") OR (Image="*\\apache*" OR Image="*\\tomcat*" OR Image="*\\AppData\\*" OR Image="*\\Temp\\*" OR Image="*\\Public\\*" OR Image="*\\PerfLogs\\*"))))
```

```sql
index=* source="WinEventLog:*" AND (TargetFilename="*\\ntds.dit" AND ((ParentImage="*\\cscript.exe" OR ParentImage="*\\httpd.exe" OR ParentImage="*\\nginx.exe" OR ParentImage="*\\php-cgi.exe" OR ParentImage="*\\powershell.exe" OR ParentImage="*\\pwsh.exe" OR ParentImage="*\\w3wp.exe" OR ParentImage="*\\wscript.exe") OR (ParentImage="*\\apache*" OR ParentImage="*\\tomcat*" OR ParentImage="*\\AppData\\*" OR ParentImage="*\\Temp\\*" OR ParentImage="*\\Public\\*" OR ParentImage="*\\PerfLogs\\*")))
```

```sql
index=* source="WinEventLog:*" AND (TargetFilename="*\\ntds.dit" AND ((Image="*\\cmd.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\wscript.exe" OR Image="*\\wsl.exe" OR Image="*\\wt.exe") OR (Image="*\\AppData\\*" OR Image="*\\Temp\\*" OR Image="*\\Public\\*" OR Image="*\\PerfLogs\\*")))
```

### Nighteagle APT
---

https://thehackernews.com/2025/07/nighteagle-apt-exploits-microsoft.html

```sql
| tstats `security_content_summariesonly` count from datamodel=Network_Resolution where nodename=DNS query IN ("app.flowgw.com", "cloud.synologyupdates.com", "comfyupdate.org", "coremailtech.com", "dashboard.daihou360.com", "e-mailrelay.com", "fastapi-cdn.com", "fortisys.net", "liveupdate.wsupdatecloud.net", "mirror1.mirrors-openjdk.org", "ms.wsupdatecloud.net", "ms-nipre.com", "rhel.lvusdupdates.org", "sangsoft.net", "shangjuyike.com", "threatbookav.com", "tracking.doubleclicked.com", "update.haprxy.org", "update.saperpcloud.com", "updates.ccproxy.org", "wechatutilities.com") by query, DNS.src, DNS.dest, DNS.answer, _time
| `drop_dm_object_dims`
| `security_content_ctime(first_time)`
| `security_content_ctime(last_time)`
| rename DNS.src as src_ip, DNS.dest as dest_ip, DNS.answer as dns_answer
| `nighteagle_apt_q_95_malicious_domain_dns_query_filter`
```

### MaaS Behavioral Indicators
---

```sql
`# This detection rule identifies modular malware behavior, a common TTP for MaaS platforms like DanaBot.`
`# It looks for a process that writes a potentially executable file to disk and then launches that same file shortly after.`

`# Step 1: Ingest process creation and file creation events from the Endpoint datamodel.`
(`cim_Endpoint_Processes`) OR (`cim_Endpoint_Filesystem` action=created)

`# Step 2: Filter for file types commonly used by malware to reduce noise. Process creation events are kept by the isnull() check.`
| where isnull(file_name) OR match(file_name, /(?i)\.(exe|dll|scr|ps1|vbs|bat|com|js)$/)

`# Step 3: Create a common field for the "actor" process that performs both the write and launch actions.`
| eval actor_process = coalesce(parent_process, process_name)

`# Step 4: Group related file writes and process executions by the same actor on the same host within a 30-second window.`
| transaction dest, actor_process maxspan=30s

`# Step 5: Filter for transactions containing both a file write (has a file_path) and a process launch (has a process).`
| where eventcount > 1 AND isnotnull(file_path) AND isnotnull(process)

`# Step 6: The core detection logic. Expand the events by each launched process and check if it matches a file that was just written in the same transaction.`
| eval written_files = mvdedup(file_path)
| eval launched_procs = mvdedup(process)
| mvexpand launched_procs
| where mvfind(written_files, launched_procs) IS NOT NULL

`# False Positive Tuning: This behavior can be legitimate for software installers, updaters, or self-extracting archives.`
`# Exclude known legitimate actor processes and paths common in your environment to improve fidelity.`
`# Example: | search NOT (actor_process IN ("GoogleUpdate.exe", "msiexec.exe", "Update.exe") OR launched_procs IN ("C:\\Program Files\\*"))`

`# Step 7: Format the results for alerting.`
| stats values(written_files) as written_files by _time, dest, user, actor_process, launched_procs
| rename dest as "Endpoint", user as "User", actor_process as "Actor_Process", launched_procs as "Launched_Process", written_files as "Associated_Written_Files"
```

### Stealth Falcon WebDAV Executable Hijacking Detection
---

    T1204.002 - Malicious File

    T1574.001 - DLL

    T1105 - Ingress Tool Transfer

    TA0002 - Execution

    TA0003 - Persistence

    TA0004 - Privilege Escalation

    TA0005 - Defense Evasion

    TA0011 - Command and Control

```sql
| tstats `security_content_summaries` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.ParentProcessName="iediagcmd.exe" OR Processes.ParentProcessName="CustomShellHost.exe") Processes.ProcessPath="\\\\*" (Processes.ProcessName="route.exe" OR Processes.ProcessName="ipconfig.exe" OR Processes.ProcessName="netsh.exe" OR Processes.ProcessName="explorer.exe") by Processes.dest Processes.ParentProcessName Processes.ProcessName Processes.ProcessPath Processes.CommandLine
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rename ParentProcessName as parent_process_name, ProcessName as process_name, ProcessPath as process_path, CommandLine as command_line
| eval severity="high",
    rule_name="Stealth Falcon - WebDAV Executable Hijacking via CVE-2025-33053",
    description="Detects suspicious process creation where iediagcmd.exe or CustomShellHost.exe (legitimate Windows utilities) launch executables from a network share, a technique used by the Stealth Falcon APT group to exploit CVE-2025-33053 and load malicious binaries from WebDAV servers.",
    date="2025-07-04",
    references="https://research.checkpoint.com/2025/stealth-falcon-zero-day/",
    mitre_attack_tactics="Execution, Defense Evasion",
    mitre_attack_techniques="T1204.002 (User Execution: Malicious File), T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking - Executable Search Order Hijacking), T1105 (Ingress Tool Transfer)"
```

### Cobalt Strike Operators Leverage PowerShell Loaders Across Chinese, Russian, and Global Infrastructure.
---

The decrypted shellcode initiates a connection to a second-stage command-and-control server hosted on Baidu Cloud Function Compute (y2n273y10j[.]cfc-execute[.]bj.baidubce[.]com). It uses API hashing to obfuscate function names, sets a forged User-Agent string, and employs reflective DLL injection to load the payload directly into memory.

Analysis of the decoded payload configuration revealed a Cobalt Strike Beacon communicating with the IP address 46.173.27.142, associated with Beget LLC (Russia).

SSL metadata indicates a certificate subject of "Major Cobalt Strike" and issuer "cobaltstrike." These findings are consistent with known Cobalt Strike infrastructure and usage patterns in post-exploitation and threat actor activity.

While most of the IOCs in this case are linked to Chinese and Russian servers, we also identified a few hosted in the United States, Singapore, and Hong Kong. This suggests that although the core staging environment relies heavily on infrastructure in China and Russia, cloud platforms in other regions are occasionally used to support distribution.

##

```sql
index=*
| COMMENT "Rule Name: Cobalt Strike PowerShell In-Memory Loader"
| COMMENT "Description: Detects PowerShell scripts leveraging reflective techniques for in-memory execution and subsequent Cobalt Strike C2 communication, as observed in recent campaigns."
| COMMENT "Author: RW"
| COMMENT "Date: 2025-06-28"
| COMMENT "Severity: High"
| COMMENT "Tactics: Execution, Command and Control"
| COMMENT "Techniques: T1059.001 (PowerShell), T1027 (Obfuscated Files or Information), T1055 (Process Injection), T1071.001 (Application Layer Protocol: Web Protocols), T1102 (Web Service), T1573.002 (Encrypted Channel: Asymmetric Cryptography)"
| COMMENT "References: https://hunt.io/blog/cobaltstrike-powershell-loader-chinese-russian-infrastructure"
(sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104
  (Message="*func_get_delegate_type*" OR Message="*func_get_proc_address*")
  (Message="*System.Convert::FromBase64String*" AND Message="*VirtualAlloc*")
)
OR
(sourcetype=stream:http
  (dest_ip="46.173.27.142" OR dest_domain="y2n273y10j.cfc-execute.bj.baidubce.com")
  (http_user_agent="Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; yie9)")
)
OR
(sourcetype=stream:ssl
  (dest_ip="46.173.27.142" OR dest_domain="y2n273y10j.cfc-execute.bj.baidubce.com")
  (ssl_issuer_organization="cobaltstrike" OR ssl_subject_common_name="Major Cobalt Strike")
)
```

```sql
| search (
    (
        (index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104) OR
        (index=windows sourcetype=WinEventLog:Security EventCode=4688)
    )
    AND (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
    AND (
        (CommandLine="*func_get_delegate_type*" OR CommandLine="*FromBase64String*" OR CommandLine="*VirtualAlloc*" OR CommandLine="*Add-Type*" OR CommandLine="*Set-StrictMode*") OR
        (ScriptBlockText="*func_get_delegate_type*" OR ScriptBlockText="*FromBase64String*" OR ScriptBlockText="*VirtualAlloc*" OR ScriptBlockText="*Add-Type*" OR ScriptBlockText="*Set-StrictMode*") OR
        (Message="*func_get_delegate_type*" OR Message="*FromBase64String*" OR Message="*VirtualAlloc*" OR Message="*Add-Type*" OR Message="*Set-StrictMode*")
    )
)
OR (
    (index=network sourcetype=stream:http OR sourcetype=stream:tcp)
    AND (
        dest_ip="46.173.27.142" OR
        dest_host="y2n273y10j.cfc-execute.bj.baidubce.com"
    )
)
OR (
    (index=network sourcetype=stream:http)
    AND http_user_agent="Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; yie9)"
)
| table _time, host, Image, CommandLine, ScriptBlockText, Message, dest_ip, dest_host, http_user_agent, EventCode, sourcetype
```

### DEVMAN Ransomware: Analysis of New DragonForce Variant
---

https://any.run/cybersecurity-blog/devman-ransomware-analysis/

MITRE ATT&CK Mapping

    T1204.002 – User Execution: Malicious File

    T1053.005 – Scheduled Task/Job: Scheduled Task

    T1027 – Obfuscated Files or Information

    T1070 – Indicator Removal on Host

    T1135 – Network Share Discovery

    6T1021.002 – SMB/Windows Admin Shares

    T1005 – Data from Local System

    T1486 – Data Encrypted for Impact

    T1490 – Inhibit System Recovery

```sql
(index=* sourcetype IN ("WinEventLog:Microsoft-Windows-Sysmon/Operational", "edr_logs")
    (
        # Detect unique mutex creation (Sysmon EventCode 1 for process creation, EDRs might have specific mutex events)
        (EventCode=1 AND MutexName="hsfjuukjzloqu28oajh727190")
        OR
        # Detect file encryption patterns (Sysmon EventCode 11 for file create/rename, EventCode 1 for process creation with file_name)
        (EventCode IN (1, 11) AND (TargetFilename="*.devman" OR NewFileName="*.devman" OR file_name="*.devman" OR TargetFilename="*e47qfsnz2trbkhnt.devman" OR NewFileName="*e47qfsnz2trbkhnt.devman" OR file_name="*e47qfsnz2trbkhnt.devman"))
        OR
        # Detect Restart Manager registry activity (Sysmon EventCode 12, 13, 14 for registry events)
        (EventCode IN (12, 13, 14) AND RegistryKey="*\\Software\\Microsoft\\RestartManager\\Session0000*" AND (RegistryValueName="Owner" OR RegistryValueName="SessionHash" OR RegistryValueName="RegFiles0000" OR RegistryValueName="RegFilesHash"))
    )
)
| stats count by _time, host, user, Image, CommandLine, ParentImage, ParentCommandLine, MutexName, TargetFilename, NewFileName, file_name, RegistryKey, RegistryValueName, RegistryValueData, EventCode
| `security_content_ctime(first_time)`
```

### In the Wild: Malware Prototype with Embedded Prompt Injection
---

https://research.checkpoint.com/2025/ai-evasion-prompt-injection/

This rule identifies the specific Tor proxy setup behavior observed in the "Skynet" malware, which is known for embedding prompt injection strings. The malware drops tor.exe into a temporary directory and executes it with unique command-line arguments to establish a SOCKS proxy for C2 communication.

##

```sql
| tstats `security_content_summaries` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="tor.exe" Processes.process="*--ControlPort 127.0.0.1:24616 --SocksPort 127.0.0.1:24615 --Log \"notice stdout\"*" Processes.process_path="*\\Temp\\skynet\\tor.exe" by Processes.dest Processes.user Processes.parent_process_name Processes.process Processes.process_id Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rename process_name as process_name
| rename process as process
| rename process_path as process_path
| rename dest as dest
| rename user as user
| rename parent_process_name as parent_process_name
| rename process_id as process_id
| `skynet_malware_tor_proxy_setup_filter`
```

### Malicious VSCode Extension Activity Detection
---
```sql
-- Name: Malicious VSCode Extension Activity
-- Author: RW
-- Date: 2025-08-20
-- Description: This search combines multiple detection techniques for malicious Visual Studio Code extension activity. It looks for extension installation via URI handlers or the command line, suspicious network connections from VSCode, file writes to extension directories, and the loading of unusual Node modules. These activities can indicate an attacker using VSCode for initial access or persistence.

-- Data Source: Endpoint data model (Processes, Network_Traffic, Filesystem, Image_Loads)

| from datamodel=Endpoint.All_Models
-- Use a case statement to identify which detection method was triggered based on data from different Endpoint data models.
| eval detection_method=case(
    -- Part 1: Detects VSCode being launched to install an extension from a URL.
    nodename="Processes" AND Processes.process_name="Code.exe" AND match(Processes.process, "(?i)--open-url") AND match(Processes.process, "(?i)vscode://"), "VSCode URI Handler Installation",

    -- Part 2: Detects VSCode extensions being installed from the command line.
    nodename="Processes" AND Processes.process_name="Code.exe" AND match(Processes.process, "(?i)--install-extension") AND match(Processes.process, "(?i)\.vsix"), "VSCode Extension CLI Installation",

    -- Part 3: Detects suspicious network connections from VSCode. FP-Medium: Legitimate extensions may communicate with their own backends. This list may need to be expanded with trusted publisher domains.
    nodename="Network_Traffic" AND Network_Traffic.process_name="Code.exe" AND isnotnull(Network_Traffic.url) AND NOT match(Network_Traffic.url, "(?i)marketplace\.visualstudio\.com|vscode\.blob\.core\.windows\.net|update\.code\.visualstudio\.com|gallerycdn\.vsassets\.io"), "Suspicious Outbound Connection from VSCode",

    -- Part 4: Detects files being created in VSCode extension directories. FP-Medium: This can be noisy during legitimate extension installs. Review the parent_process for suspicious origins (e.g., browsers, office apps).
    nodename="Filesystem" AND Filesystem.action="created" AND (match(Filesystem.file_path, "(?i)\\\\.vscode\\\\extensions\\\\") OR match(Filesystem.file_path, "(?i)\\\\Microsoft VS Code\\\\resources\\\\app\\\\extensions\\\\")), "File Write to VSCode Extension Directory",

    -- Part 5: Detects VSCode loading a Node native addon (.node file) from a suspicious path.
    nodename="Image_Loads" AND Image_Loads.process_name="Code.exe" AND match(Image_Loads.file_name, "(?i)\.node$") AND (match(Image_Loads.file_path, "(?i)\\\\AppData\\\\Local") OR match(Image_Loads.file_path, "(?i)\\\\Temp")) AND NOT (match(Image_Loads.file_path, "(?i)\\\.vscode\\\\extensions|Microsoft VS Code")), "Suspicious Node Module Loaded by VSCode"
)
-- Filter out any events that did not match one of the detection criteria.
| where isnotnull(detection_method)
-- Create a details field to provide context specific to the detection method.
| eval details=case(
    detection_method="VSCode URI Handler Installation", "URI Command: " + Processes.process,
    detection_method="VSCode Extension CLI Installation", "Install Command: " + Processes.process,
    detection_method="Suspicious Outbound Connection from VSCode", "Destination: " + Network_Traffic.url,
    detection_method="File Write to VSCode Extension Directory", "File: " + Filesystem.file_path + Filesystem.file_name,
    detection_method="Suspicious Node Module Loaded by VSCode", "Module: " + Image_Loads.file_path + Image_Loads.file_name
)
-- Unify fields from different data models into a common set of field names for consistent alerting.
| eval timestamp=_time,
       actor_process=coalesce(Processes.process, Network_Traffic.process, Filesystem.process, Image_Loads.process),
       actor_process_name=coalesce(Processes.process_name, Network_Traffic.process_name, Filesystem.process_name, Image_Loads.process_name),
       parent_process=coalesce(Processes.parent_process, Filesystem.parent_process),
       user=coalesce(Processes.user, Network_Traffic.user, Filesystem.user, Image_Loads.user),
       dest=coalesce(Processes.dest, Network_Traffic.dest, Filesystem.dest, Image_Loads.dest)
-- Format the final output table with the most relevant fields for an analyst.
| table timestamp, dest, user, parent_process, actor_process_name, actor_process, detection_method, details
| `malicious_vscode_extension_activity_filter`
```

### Salty 2FA Phishing Campaign
---
```sql
-- title: Comprehensive Salty 2FA Phishing Kit Detection
-- description: Detects various web-based indicators of the Salty 2FA phishing kit. This rule identifies the unique landing page domain structure, Cloudflare evasion, anti-analysis techniques, and the specific data exfiltration pattern.
-- author: RW
-- date: 2025-08-20
-- references:
--   - https://any.run/cybersecurity-blog/salty2fa-technical-analysis/
-- tags:
--   - attack.initial_access
--   - attack.t1566
--   - attack.exfiltration
--   - attack.t1041
--   - attack.defense_evasion
--   - attack.t1622
--   - threat_actor.storm-1575
--   - phishing.salty_2fa
-- falsepositives:
--   - The data exfiltration pattern is highly specific and has a low probability of false positives.
--   - The landing page detection may trigger on legitimate services that use a similar domain structure and integrate both Cloudflare and Microsoft authentication, although the combination of indicators reduces this risk. Consider creating an allowlist for known good domains.
-- level: high

-- This search targets CIM-compliant web proxy data. You may need to adjust field names (e.g., dest, uri_path, http_method, http_user_agent, bytes_in, bytes_out) for your specific data source.")`
(index=* sourcetype=stream:http) OR `cim_Web_proxy`
| where
    -- This first block detects the specific data exfiltration pattern.")`
    (
        http_method="POST" AND
        dest="*.ru" AND
        match(uri_path, "/\d{5,6}\.php$") AND
        (form_data LIKE "%request=%" AND form_data LIKE "%session=%")
    )
    OR
    -- This second block detects the phishing landing page.")`
    (
        match(dest, "\.[a-z]{2}\.com$") AND
        (
            -- Looks for Cloudflare Turnstile on a Microsoft-themed login page.")`
            (
                http_response_body LIKE "%challenges.cloudflare.com/turnstile/%" AND
                http_response_body LIKE "%Microsoft%" AND
                http_response_body LIKE "%Sign in%"
            )
            OR
            -- Looks for a common anti-analysis/debugging technique.")`
            (
                http_response_body LIKE "%new Date()%" AND
                http_response_body LIKE "%debugger%"
            )
        )
    )
| eval detection_type=if(http_method=="POST" AND like(dest, "%.ru"), "Salty 2FA Exfiltration", "Salty 2FA Landing Page")
-- Categorizes the alert for easier triage.")`
| table _time, user, src, dest, uri_path, http_method, form_data, detection_type
```

### QuirkyLoader Malware Activity
---
```sql
-- Rule Title: QuirkyLoader Malware Activity
--
-- Description:
-- This rule detects potential QuirkyLoader malware activity by searching for a combination of behavioral and indicator-based threats identified by IBM X-Force. It looks for specific processes targeted for hollowing, known malicious file hashes (SHA256), and network connections to known command-and-control (C2) infrastructure. This rule requires data to be mapped to the Splunk Common Information Model (CIM).
--
-- Author: RW
-- Date: 2025-08-20
--
-- References:
-- - https://www.ibm.com/think/x-force/ibm-x-force-threat-analysis-quirkyloader
--
-- False Positive Sensitivity: Medium
-- The processes targeted for hollowing (AddInProcess32.exe, InstallUtil.exe, aspnet_wp.exe) are legitimate Microsoft .NET components. Benign execution is common, especially in development environments. If false positives occur, consider filtering by parent process or command-line arguments.
--
-- Tactic(s): Execution, Defense Evasion
-- Technique(s): Process Hollowing (T1055.012), DLL Side-Loading (T1574.001)

(index=* (tag=process OR tag=network))
(
    -- Match process hollowing targets
    (process_name IN ("AddInProcess32.exe", "InstallUtil.exe", "aspnet_wp.exe")) OR

    -- Match known malicious file hashes (SHA256)
    (file_hash IN (
        "011257eb766f2539828bdd45f8aa4ce3c4048ac2699d988329783290a7b4a0d3",
        "0ea3a55141405ee0e2dfbf333de01fe93c12cf34555550e4f7bb3fdec2a7673b",
        "a64a99b8451038f2bbcd322fd729edf5e6ae0eb70a244e342b2f8eff12219d03",
        "9726e5c7f9800b36b671b064e89784fb10465210198fbbb75816224e85bd1306",
        "a1994ba84e255eb02a6140cab9fc4dd9a6371a84b1dd631bd649525ac247c111",
        "d954b235bde6ad02451cab6ee1138790eea569cf8fd0b95de9dc505957c533cd",
        "5d5b3e3b78aa25664fb2bfdbf061fc1190310f5046d969adab3e7565978b96ff",
        "6f53c1780b92f3d5affcf095ae0ad803974de6687a4938a2e1c9133bf1081eb6",
        "ea65cf2d5634a81f37d3241a77f9cd319e45c1b13ffbaf5f8a637b34141292eb",
        "1b8c6d3268a5706fb41ddfff99c8579ef029333057b911bb4905e24aacc05460",
        "d0a3a1ee914bcbfcf709d367417f8c85bd0a22d8ede0829a66e5be34e5e53bb9",
        "b22d878395ac2f2d927b78b16c9f5e9b98e006d6357c98dbe04b3fd78633ddde",
        "a83aa955608e9463f272adca205c9e1a7cbe9d1ced1e10c9d517b4d1177366f6",
        "3391b0f865f4c13dcd9f08c6d3e3be844e89fa3afbcd95b5d1a1c5abcacf41f4",
        "b2fdf10bd28c781ca354475be6db40b8834f33d395f7b5850be43ccace722c13",
        "bf3093f7453e4d0290511ea6a036cd3a66f456cd4a85b7ec8fbfea6b9c548504",
        "97aee6ca1bc79064d21e1eb7b86e497adb7ece6376f355e47b2ac60f366e843d",
        "b42bc8b2aeec39f25babdcbbdaab806c339e4397debfde2ff1b69dca5081eb44",
        "5aaf02e4348dc6e962ec54d5d31095f055bd7fb1e58317682003552fd6fe25dc",
        "8e0770383c03ce69210798799d543b10de088bac147dce4703f13f79620b68b1",
        "049ef50ec0fac1b99857a6d2beb8134be67ae67ae134f9a3c53699cdaa7c89ac",
        "cba8bb455d577314959602eb15edcaa34d0b164e2ef9d89b08733ed64381c6e0"
    )) OR

    -- Match known malicious domains (from DNS logs)
    (query IN ("catherinereynolds.info", "mail.catherinereynolds.info")) OR

    -- Match known malicious IPs (from any network traffic)
    (dest_ip IN ("157.66.22.11", "103.75.77.90", "161.248.178.212"))
)
-- Group events by host and provide a summary of activities
| stats
    count,
    values(process_name) as processes_observed,
    values(process) as process_command_lines,
    values(parent_process) as parent_processes,
    values(file_hash) as matched_hashes,
    values(query) as dns_queries,
    values(dest_ip) as destination_ips,
    earliest(_time) as first_seen,
    latest(_time) as last_seen
    by dest, user
-- Add a reason for the detection for easier analysis
| eval detection_reason = case(
    mvcount(matched_hashes) > 0, "IOC Match: Known QuirkyLoader file hash detected.",
    mvcount(dns_queries) > 0 OR mvcount(destination_ips) > 0, "IOC Match: Network connection to QuirkyLoader C2 detected.",
    mvcount(processes_observed) > 0, "TTP Match: Execution of a known QuirkyLoader process hollowing target."
    )
-- Reformat timestamps to be human-readable
| convert ctime(first_seen) ctime(last_seen)
-- Organize fields for clear output
| table
    dest,
    user,
    detection_reason,
    processes_observed,
    parent_processes,
    process_command_lines,
    matched_hashes,
    dns_queries,
    destination_ips,
    first_seen,
    last_seen,
    count
```

### PipeMagic Backdoor Activity
---
```sql
-- Name: PipeMagic Backdoor Activity
-- Description: Detects various Tactics, Techniques, and Procedures (TTPs) associated with the PipeMagic backdoor framework used by the Storm-2460 threat actor.

-- Author: RW
-- Date: 2025-08-20

-- Tactic: TA0002, TA0005, TA0006, TA0011
-- Technique: T1059, T1218.010, T1140, T1003.001, T1071.001, T1055

-- False Positives: Legitimate use of certutil for file downloads, though the combination of arguments is suspicious. 'dllhost.exe' accessing 'lsass.exe' can be legitimate; requires investigation of parent process context. The named pipe pattern could potentially collide with legitimate software.

-- References:
-- - https://www.microsoft.com/en-us/security/blog/2025/08/18/dissecting-pipemagic-inside-the-architecture-of-a-modular-backdoor-framework/
-- - https://securelist.com/pipemagic/117270/

(index=* sourcetype IN (stream:http, pan:traffic, suricata, zeek, *sysmon*, *windows*))
(
  -- Clause 1: IOC Hashes for PipeMagic components
  (sha256 IN ("dc54117b965674bad3d7cd203ecf5e7fc822423a3f692895cf5e96e83fb88f6a", "4843429e2e8871847bc1e97a0f12fa1f4166baa4735dff585cb3b4736e3fe49e", "297ea881aa2b39461997baf75d83b390f2c36a9a0a4815c81b5cf8be42840fd1") OR file_hash IN ("dc54117b965674bad3d7cd203ecf5e7fc822423a3f692895cf5e96e83fb88f6a", "4843429e2e8871847bc1e97a0f12fa1f4166baa4735dff585cb3b4736e3fe49e", "297ea881aa2b39461997baf75d83b390f2c36a9a0a4815c81b5cf8be42840fd1"))
) OR (
  -- Clause 2: PipeMagic Named Pipe Creation. Requires Sysmon EventCode 17.
  (EventCode=17 AND match(PipeName, "^\\\\.\\pipe\\1\\.[0-9a-fA-F]{32}$"))
) OR (
  -- Clause 3: PipeMagic C2 Communication. Requires network connection logs (e.g., Sysmon EventCode 3).
  (EventCode=3 AND (DestinationHostname="aaaaabbbbbbb.eastus.cloudapp.azure.com" OR DestinationIp="127.0.0.1") AND DestinationPort IN (443, 8082))
) OR (
  -- Clause 4: PipeMagic C2 HTTP Request Pattern. Requires proxy or web logs.
  (match(url, ".*/[a-fA-F0-9]{16}$") AND "*Upgrade: websocket*" AND "*Connection: Upgrade*")
) OR (
  -- Clause 5: Initial access using certutil. Requires process creation logs (e.g., Sysmon EventCode 1).
  (EventCode=1 AND (Image LIKE "%\\certutil.exe" OR process_name="certutil.exe") AND CommandLine LIKE "%-urlcache%" AND CommandLine LIKE "%-f%" AND (CommandLine LIKE "%.tmp%" OR CommandLine LIKE "%.dat%" OR CommandLine LIKE "%.msbuild%"))
) OR (
  -- Clause 6: Execution via MSBuild. Requires process creation logs (e.g., Sysmon EventCode 1).
  (EventCode=1 AND (ParentImage LIKE "%\\msbuild.exe" OR parent_process_name="msbuild.exe") AND CommandLine LIKE "%.mshi%")
) OR (
  -- Clause 7: Credential dumping via LSASS access. Requires Sysmon EventCode 10.
  (EventCode=10 AND TargetImage LIKE "%\\lsass.exe" AND SourceImage LIKE "%\\dllhost.exe")
)
| eval timestamp=strftime(_time, "%Y-%m-%d %H:%M:%S")
| eval detection_clause=case(
    (sha256 IN ("dc54117b965674bad3d7cd203ecf5e7fc822423a3f692895cf5e96e83fb88f6a", "4843429e2e8871847bc1e97a0f12fa1f4166baa4735dff585cb3b4736e3fe49e", "297ea881aa2b39461997baf75d83b390f2c36a9a0a4815c81b5cf8be42840fd1") OR file_hash IN ("dc54117b965674bad3d7cd203ecf5e7fc822423a3f692895cf5e96e83fb88f6a", "4843429e2e8871847bc1e97a0f12fa1f4166baa4735dff585cb3b4736e3fe49e", "297ea881aa2b39461997baf75d83b390f2c36a9a0a4815c81b5cf8be42840fd1")), "PipeMagic File Hash IOC",
    (EventCode=17 AND match(PipeName, "^\\\\.\\pipe\\1\\.[0-9a-fA-F]{32}$")), "PipeMagic Named Pipe",
    (EventCode=3 AND (DestinationHostname="aaaaabbbbbbb.eastus.cloudapp.azure.com" OR DestinationIp="127.0.0.1") AND DestinationPort IN (443, 8082)), "PipeMagic C2 Connection",
    (match(url, ".*/[a-fA-F0-9]{16}$") AND "*Upgrade: websocket*" AND "*Connection: Upgrade*"), "PipeMagic C2 HTTP Pattern",
    (EventCode=1 AND (Image LIKE "%\\certutil.exe" OR process_name="certutil.exe") AND CommandLine LIKE "%-urlcache%"), "PipeMagic Certutil Download",
    (EventCode=1 AND (ParentImage LIKE "%\\msbuild.exe" OR parent_process_name="msbuild.exe") AND CommandLine LIKE "%.mshi%"), "PipeMagic MSBuild Execution",
    (EventCode=10 AND TargetImage LIKE "%\\lsass.exe" AND SourceImage LIKE "%\\dllhost.exe"), "PipeMagic LSASS Access",
    1=1, "Unknown PipeMagic Activity"
  )
| eval process_name=coalesce(process_name, ProcessName, process), parent_process_name=coalesce(parent_process_name, ParentProcessName, parent_process), command_line=coalesce(CommandLine, ProcessCommandLine), file_hash=coalesce(sha256, file_hash, process_hash, Hashes), dest_host=coalesce(dest_host, DestinationHostname, RemoteUrl, url), dest_ip=coalesce(dest_ip, DestinationIp, RemoteIP), dest_port=coalesce(dest_port, DestinationPort, RemotePort), pipe_name=PipeName, source_image=SourceImage, target_image=TargetImage
| table timestamp, detection_clause, host, user, process_name, parent_process_name, command_line, file_hash, dest_host, dest_ip, dest_port, pipe_name, source_image, target_image
```

### ESXi Host Suspicious Activity Detection (Recon, Privilege Escalation, Exfil, Evasion)
---
```sql
`esxi_syslog`
(* comment: This OR clause identifies various suspicious activities on ESXi hosts, covering reconnaissance, privilege escalation, defense evasion, and exfiltration based on common ransomware TTPs. *)
(
    (Message="*esxcli system*" AND (Message="* get*" OR Message="* list*") AND NOT Message="*filesystem*") OR
    (Message="*root*" AND Message="*logged in*") OR
    (Message="*esxcli system permission set*" AND Message="*role Admin*") OR
    (Message="*esxcli software acceptance set*") OR
    (Message="*SSH access has been enabled*") OR
    (Message="*system settings encryption set*" AND (Message LIKE "%--require-secure-boot=0%" OR Message LIKE "%--require-exec-installed-only=0%" OR Message LIKE "%execInstalledOnly=false%")) OR
    (Message="*File download from path*" AND Message="*was initiated from*") OR
    (Message="*esxcli system auditrecords*") OR
    (Message="*syslog config set*" AND Message="*esxcli*") OR
    (Message="*Set called with key*" AND (Message="*Syslog.global.logHost*" OR Message="*Syslog.global.logdir*")) OR
    (Message="*NTPClock*" AND Message="*system clock stepped*")
)
(* comment: Extract relevant entities like user, command, and source IP from different log formats. *)
| rex field=_raw "shell\[\d+\]: \[(?<user>[^\]]+)\]: (?<command>.+)"
| rex field=_raw "root@(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| rex field=_raw "initiated from ''[^/]+/[^@]+@(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})''"
(* comment: Categorize the event into a specific tactic and create a summary detail field for context. *)
| eval tactic_description=case(
    Message LIKE "%esxcli system% get%" OR Message LIKE "%esxcli system% list%", "ESXi System Reconnaissance",
    Message LIKE "%root%logged in%", "External Root Login to ESXi UI",
    Message LIKE "%esxcli system permission set%role Admin%", "User Granted Admin Role on ESXi",
    Message LIKE "%esxcli software acceptance set%", "VIB Acceptance Level Tampering",
    Message LIKE "%SSH access has been enabled%", "SSH Enabled on ESXi Host",
    Message LIKE "%system settings encryption set%", "ESXi Encryption Settings Modified",
    Message LIKE "%File download from path%", "VM Exported via Remote Tool",
    Message LIKE "%esxcli system auditrecords%", "ESXi Audit Tampering",
    Message LIKE "%syslog config set%" OR Message LIKE "%Syslog.global.logHost%" OR Message LIKE "%Syslog.global.logdir%", "ESXi Syslog Tampering",
    Message LIKE "%NTPClock%system clock stepped%", "ESXi System Clock Manipulation",
    1=1, "Unknown ESXi Activity"
),
details=case(
    isnotnull(command), command,
    isnotnull(src_ip), "Login from " + src_ip,
    tactic_description=="SSH Enabled on ESXi Host", Message,
    tactic_description=="ESXi Syslog Tampering", Message,
    tactic_description=="ESXi System Clock Manipulation", Message,
    1=1, _raw
)
(* comment: Filter out root logins from private IP space to reduce false positives. This may need to be tuned for your specific environment by adding known admin subnets or management IPs. *)
| where NOT (tactic_description="External Root Login to ESXi UI" AND (cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("172.16.0.0/12", src_ip) OR cidrmatch("192.168.0.0/16", src_ip) OR src_ip="127.0.0.1" OR isnull(src_ip)))
(* comment: Aggregate results to provide a summary of suspicious activities per host and user. *)
| stats earliest(_time) as firstTime, latest(_time) as lastTime, values(details) as activity_details, count by dest, user, tactic_description
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rename dest as esxi_host
```

### CastleBot MaaS Activity Detection: File Hashes, C2 IPs, User-Agent, Persistence
---
```sql
-- title: CastleBot Malware-as-a-Service Activity
-- description: Detects various indicators and behaviors associated with the CastleBot MaaS framework, including C2 communication, known file hashes, and persistence techniques.
-- references:
--   - https://www.ibm.com/think/x-force/dissecting-castlebot-maas-operation
-- author: RW
-- date: 2025-08-22
-- tags:
--   - attack.execution
--   - attack.persistence
--   - attack.command_and_control
--   - attack.t1059
--   - attack.t1218
--   - attack.t1071.001
--   - attack.t1543.003
--   - malware.castlebot
--   - malware.warmcookie
--   - malware.netsupport
--   - malware.rhadamanthys
--   - malware.remcos
--   - malware.deerstealer
--   - malware.hijackloader
--   - malware.monsterv2

-- This search combines endpoint and network indicators to detect CastleBot MaaS activity. It is best applied on CIM-compliant data sources (e.g., from Sysmon, EDR, or proxy logs).")`
(
    (
        -- IOCs - File Hashes from process or file events")`
        (tag=process OR tag=file)
        AND
        (
            file_hash IN (
                "202f6b6631ade2c41e4762e5877ce0063a3beabce0c3f8564b6499a1164c1e04", "b45cce4ede6ffb7b6f28f75a0cbb60e65592840d98dcb63155b9fa0324a88be2", /* CastleBot Core */
                "d6eea6cf20a744f3394fb0c1a30431f1ef79d6992b552622ad17d86490b7aa7b", "cbaf513e7fd4322b14adcc34b34d793d79076ad310925981548e8d3cff886527", "8bf93cef46fda2bdb9d2a426fbcd35ffedea9ed9bd97bf78cc51282bd1fb2095", "53dddae886017fbfbb43ef236996b9a4d9fb670833dfa0c3eac982815dc8d2a5", /* CastleBot Stager */
                "a2898897d3ada2990e523b61f3efaacf6f67af1a52e0996d3f9651b41a1c59c9", "8b2ebeff16a20cfcf794e8f314c37795261619d96d602c8ee13bc6255e951a43", "05ecf871c7382b0c74e5bac267bb5d12446f52368bb1bfe5d2a4200d0f43c1d8", "bf21161c808ae74bf08e8d7f83334ba926ffa0bab96ccac42dde418270387890", "e6aab1b6a150ee3cbc721ac2575c57309f307f69cd1b478d494c25cde0baaf85", /* Loaders / Scripts */
                "2a2cd6377ad69a298af55f29359d67e4586ec16e6c02c1b8ad27c38471145569", "5bca7f1942e07e8c12ecd9c802ecdb96570dfaaa1f44a6753ebb9ffda0604cb4", "03122e46a3e48141553e7567c659642b1938b2d3641432f916375c163df819c1", "12de997634859d1f93273e552dec855bfae440dcf11159ada19ca0ae13d53dff", "c8f95f436c1f618a8ef5c490555c6a1380d018f44e1644837f19cb71f6584a8a", "4834bc71fc5d3729ad5280e44a13e9627e3a82fd4db1bb992fa8ae52602825c6", "ab725f5ab19eec691b66c37c715abd0e9ab44556708094a911b84987d700aa62" /* Payloads */
            )
        )
    )
    OR
    (
        -- IOCs - Network Indicators from network or web logs")`
        (tag=network OR tag=web)
        AND
        (
            dest_ip IN ("173.44.141.89", "80.77.23.48", "62.60.226.73", "107.158.128.45", "170.130.165.112", "107.158.128.105")
            OR
            match(url, "(?i)(mhousecreative\.com|google\.herionhelpline\.com)$")
            OR
            url IN ("*/service/*", "*/c91252f9ab114f26.php")
        )
    )
    OR
    (
        -- TTP - Suspicious User-Agent to known C2 IPs. Requires web proxy logs.")`
        (tag=web)
        AND
        (http_user_agent="*Googlebot*")
        AND
        (dest_ip IN ("173.44.141.89", "80.77.23.48", "62.60.226.73", "107.158.128.45"))
    )
    OR
    (
        -- TTP - Persistence via Scheduled Task. May require tuning to filter legitimate admin activity.")`
        (tag=process tag=command)
        AND
        (process_name="schtasks.exe")
        AND
        (process="*/create*" AND process="*/sc*" AND process="*onlogon*")
    )
)
| -- Consolidate fields for review.")`
| stats values(process) as process, values(file_hash) as file_hash, values(url) as url, values(http_user_agent) as http_user_agent by _time, dest, user, process_name, dest_ip
| `castlebot_malware_as_a_service_activity_filter`
```

### Quasar RAT Indicators: Process, File, and Network Activity
---
```sql
-- Tactic: Multiple, Technique: Multiple")`
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where
    (Processes.hash="7300535ef26158bdb916366b717390fc36eb570473ed7805c18b101367c68af5") OR
    (Processes.process_name="schtasks.exe" Processes.process="*/rl *" Processes.process="* highest *") OR
    (Processes.process_name="shutdown.exe" (Processes.process="*/s /t 0*" OR Processes.process="*/r /t 0*"))
  by _time Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| rename parent_process_name as parent_process, process as details
| eval detection_rationale=case(
    match(details, "schtasks.exe"), "Scheduled Task with Highest Privileges (T1053.005)",
    match(details, "shutdown.exe"), "System Shutdown/Reboot Attempt (T1529)",
    true(), "Known Quasar RAT Loader Hash")
| eval detection_type="Process"
| fields _time, dest, user, parent_process, process_name, details, process_id, parent_process_id, detection_rationale, detection_type
| append [
  | tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Filesystem where
      (Filesystem.file_path IN ("*\\FileZilla\\recentservers.xml", "*\\FileZilla\\sitemanager.xml") AND Filesystem.process_name NOT IN ("filezilla.exe")) OR
      (Filesystem.file_path="*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*.url" AND Filesystem.action="created") OR
      (Filesystem.file_name="*:Zone.Identifier" AND Filesystem.action="deleted")
    by _time Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path Filesystem.action
  | `drop_dm_object_name(Filesystem)`
  | eval detection_rationale=case(
      like(file_path, "%FileZilla%"), "Unusual FileZilla Config Access (T1552.001)",
      like(file_path, "%Startup%.url"), "Startup Folder URL Shortcut for Persistence (T1547.001)",
      like(file_name, "%:Zone.Identifier"), "Mark-of-the-Web Bypass (T1553.005)"),
      details = "Action: " + action + " on file " + file_path
  | eval detection_type="File"
  | fields _time, dest, user, process_name, details, detection_rationale, detection_type
]
| append [
  | tstats `security_content_summariesonly` count FROM datamodel=Network_Resolution.DNS where
      DNS.query IN ("*wtfismyip.com", "*checkip.*", "*ipecho.net", "*ipinfo.io", "*api.ipify.org", "*icanhazip.com", "*ip.anysrc.com","*api.ip.sb", "ident.me", "www.myexternalip.com", "*zen.spamhaus.org", "*cbl.abuseat.org", "*b.barracudacentral.org", "*dnsbl-1.uceprotect.net", "*spam.dnsbl.sorbs.net", "*iplogger.org*", "*ip-api.com*", "*geoip.*", "*icanhazip.*", "*ipwho.is*", "*ifconfig.me*", "*myip.com*", "*ipstack.com*", "*myexternalip.com*", "*ip-api.io*", "*trackip.net*", "*ipgeolocation.io*", "*ipfind.io*", "*freegeoip.app*", "*ipv4bot.whatismyipaddress.com*", "*hacker-target.com/iptools*")
    by _time DNS.dest DNS.user DNS.process_name DNS.query
  | `drop_dm_object_name(DNS)`
  | eval detection_rationale="Network Reconnaissance via IP Check Service (T1082)",
      details = "DNS Query: " + query
  | eval detection_type="DNS"
  | fields _time, dest, user, process_name, details, detection_rationale, detection_type
]
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| stats min(_time) as firstTime, max(_time) as lastTime, values(detection_rationale) as detection_rationale, values(details) as details by dest, user, process_name, parent_process, process_id, parent_process_id, detection_type
-- The logic for FileZilla access may be prone to false positives if other legitimate tools or scripts in the environment interact with these files. Consider adding more specific process names to the exclusion list. The DNS query portion may also trigger on legitimate admin tools or user activity. Consider filtering by process_name for known browsers or scripting engines if noise is high.")`
| `quasar_rat_ttp_indicators_filter`
```

### Kerberoasting, AS-REP Roasting, DCSync, and AD DACL Modifications
---
```sql
-- index=*
`wineventlog_security`
| where
    (
        comment="Detects potential Kerberoasting attacks via RC4 ticket requests (T1558.003)"
        EventCode=4769 Status="0x0" Ticket_Encryption_Type="0x17" NOT match(Service_Name, "\$$")
    ) OR (
        comment="Detects potential AS-REP Roasting attacks (T1558.004)"
        EventCode=4768 Status="0x0" Service_Name="krbtgt" Pre_Authentication_Type="0" NOT match(Target_User_Name, "\$$")
    ) OR (
        comment="Detects potential DCSync attacks by non-machine accounts (T1003.006)"
        EventCode=4662 Object_Server="DS" Object_Type="{19195a5b-6da0-11d0-afd3-00c04fd930c9}"
        (like(Properties, "%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%") OR like(Properties, "%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%"))
        NOT match(Subject_Account_Name, "\$$")
    ) OR (
        comment="Detects modification of the AdminSDHolder DACL for persistence (T1098)"
        EventCode=5136 LDAP_Display_Name="nTSecurityDescriptor" like(Object_DN, "%CN=AdminSDHolder,CN=System,%")
        Subject_User_Sid!="S-1-5-18"
    ) OR (
        comment="Detects addition of high-privilege rights to an object's DACL (T1098)"
        EventCode=5136 LDAP_Display_Name="nTSecurityDescriptor"
        (like(Value, "%(A;;GA;;;%") OR like(Value, "%(A;;WD;;;%") OR like(Value, "%(A;;WO;;;%"))
        Subject_User_Sid!="S-1-5-18"
    )
| eval rule_name = case(
    EventCode=5136 AND like(Object_DN, "%CN=AdminSDHolder,CN=System,%"), "AdminSDHolder DACL Modification",
    EventCode=5136, "Malicious AD DACL Modification",
    EventCode=4769, "Potential Kerberoasting (RC4)",
    EventCode=4768, "Potential AS-REP Roasting",
    EventCode=4662, "Potential DCSync Attack",
    true(), "Unknown"
  )
| eval Target_Object = coalesce(Service_Name, Target_User_Name, Object_Name, Object_DN)
| eval Description = case(
    rule_name=="AdminSDHolder DACL Modification", "Account " + Subject_Account_Name + " modified the DACL of the AdminSDHolder object.",
    rule_name=="Malicious AD DACL Modification", "Account " + Subject_Account_Name + " granted high-privilege rights on object: " + Target_Object,
    rule_name=="Potential Kerberoasting (RC4)", "Account " + Subject_Account_Name + " requested an RC4-encrypted service ticket for SPN: " + Target_Object,
    rule_name=="Potential AS-REP Roasting", "TGT requested for account " + Target_Object + " which has pre-authentication disabled.",
    rule_name=="Potential DCSync Attack", "Account " + Subject_Account_Name + " attempted a DCSync-style attack to replicate directory changes.",
    true(), "N/A"
  )
| table _time, host, rule_name, Subject_Account_Name, Target_Object, Description
```

### Silk Typhoon Threat Actor: Anomalous Activity, Exfiltration, Webshells & Exploits
---
```sql
--Name: Silk Typhoon Associated Activity
-- Author: RW
-- Date: 2025-08-22

-- This is a composite query to detect multiple TTPs associated with the Silk Typhoon threat actor.
-- It combines searches for:
-- 1. Anomalous Entra Connect Activity
-- 2. Suspicious App/Service Principal creation
-- 3. Potential Cloud Data Exfiltration
-- 4. Web Shell execution
-- 5. Known Vulnerabilities exploited by the actor
-- This query is intended to be run as a scheduled search. Sourcetypes and indexes should be adapted to your environment.

-- Part 1: Detect anomalous Entra Connect activity. This may require tuning to filter legitimate administrative actions or service accounts.")`
(search (index=* sourcetype=ms:aad:signin OR sourcetype=AzureAD:SignInLogs) user IN ("*AAD_*", "*MSOL_*") category=signIn
| eval user=user, dest=appDisplayName, src_ip=ipaddr, activity="Suspicious Interactive Logon by Entra Connect Account", details="User: " + user + " from IP: " + src_ip + " to App: " + dest
| fields _time, user, dest, src_ip, activity, details)

| append [
    search (index=* sourcetype=ms:aad:audit OR sourcetype=AzureAD:AuditLogs) category=UserManagement activityDisplayName="Reset user password" result=success initiatedBy.user.userPrincipalName IN ("*AAD_*", "*MSOL_*")
    | eval user=initiatedBy.user.userPrincipalName, dest=targetResources{}.userPrincipalName, src_ip=initiatedBy.user.ipAddress, activity="Password Reset by Entra Connect Account", details="Entra Connect account " + user + " reset password for " + dest
    | fields _time, user, dest, src_ip, activity, details
]

| append [
    -- Part 2: Detect suspicious Service Principal or OAuth App activity. Review these changes against change management records.")`
    search (index=* sourcetype=ms:aad:audit OR sourcetype=AzureAD:AuditLogs) category=ApplicationManagement (activityDisplayName="Add service principal" OR activityDisplayName="Add OAuth2 permission grant" OR activityDisplayName="Add owner to service principal" OR activityDisplayName="Update application - Certificates and secrets management")
    | eval user=initiatedBy.user.userPrincipalName, dest=targetResources{}.displayName, src_ip=initiatedBy.user.ipAddress, activity=activityDisplayName, details="User " + user + " performed action '" + activity + "' on application " + dest
    | fields _time, user, dest, src_ip, activity, details
]

| append [
    -- Part 3: Detect potential data exfiltration via MSGraph or EWS. The threshold for 'accessed_items_count' should be tuned for your environment to reduce false positives.")`
    search (index=* sourcetype=o365:management:activity) (Operation=MailItemsAccessed OR Operation=FileDownloaded)
    | stats dc(ObjectId) as accessed_items_count by _time, User as user, ClientIP as src_ip, AppId, Operation
    | where accessed_items_count > 100
    | eval activity="Potential High-Volume Data Access", dest=AppId, details="User " + user + " accessed " + accessed_items_count + " items via " + Operation + " using AppId " + AppId
    | fields _time, user, dest, src_ip, activity, details
]

| append [
    -- Part 4: Detect web shell process execution. Field names may need to be aliased depending on your EDR source using the 'rename' or 'eval/coalesce' commands.")`
    search (index=* sourcetype=sysmon EventCode=1) OR (index=* sourcetype IN (crowdstrike:falcon:process_creation, carbonblack:process, microsoft:windows:security:4688))
    | eval user=coalesce(UserName, user_name, User), dest=coalesce(ComputerName, host, dvc_host), parent_process=coalesce(ParentImage, ParentProcessName, ParentBaseFileName), process=coalesce(Image, FileName, NewProcessName), cmdline=coalesce(CommandLine, ProcessCommandLine)
    | search parent_process IN ("*\\w3wp.exe", "*\\httpd.exe", "*\\nginx.exe", "*\\tomcat*.exe") process IN ("*\\cmd.exe", "*\\powershell.exe", "*\\pwsh.exe", "*\\sh", "*\\bash")
    | eval activity="Potential Web Shell Execution", details="Parent: " + parent_process + " spawned Child: " + process + ". Command: " + cmdline
    | fields _time, user, dest, activity, details
]

| append [
    -- Part 5: Identify vulnerable devices based on CVEs exploited by Silk Typhoon. This requires vulnerability scan data to be indexed in Splunk.")`
    search (index=* sourcetype IN (tenable:sc, qualys:vm, nessus:scan)) cve IN ("CVE-2025-0282", "CVE-2024-3400", "CVE-2023-3519", "CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065")
    | eval activity="Vulnerable Device Identified", dest=coalesce(host, dest_host, dest), details="Device " + dest + " is vulnerable to " + cve + " (Plugin/Signature: " + coalesce(signature, plugin_name, signature_id) + ")", user="N/A", src_ip="N/A"
    | fields _time, user, dest, src_ip, activity, details
]

-- Final formatting of results from all detection parts.")`
| table _time, activity, user, src_ip, dest, details
```

### CORNFLAKE.V3 Backdoor Activity Detection
---
```sql
-- RW

-- This rule is designed to detect a wide range of activities associated with the CORNFLAKE.V3 backdoor, as detailed in observed/disseminated threat intelligence.

-- It combines multiple detection patterns covering execution, persistence, command and control, and post-exploitation behavior into a single query.

(sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational OR sourcetype=wineventlog:microsoft-windows-sysmon/operational)
| eval
  detection_reason=case(
    -- Match 1: Detects CORNFLAKE.V3 execution (Node.js or PHP variant) spawned from PowerShell.")`
    EventCode=1 AND match(ParentImage, "(?i)\\\\powershell\.exe$") AND match(Image, "(?i)\\\\AppData\\\\Roaming") AND ((match(Image, "(?i)\\\\node\.exe$") AND match(CommandLine, "(?i)-e\s+")) OR (match(Image, "(?i)\\\\php\.exe$") AND match(CommandLine, "(?i)-d\s+") AND match(CommandLine, "(?i)\s1$"))), "Execution: CORNFLAKE.V3 (Node.js/PHP) spawned from PowerShell",

    -- Match 2: Detects CORNFLAKE.V3 spawning shell processes for reconnaissance or command execution.")`
    EventCode=1 AND match(ParentImage, "(?i)\\\\AppData\\\\Roaming\\\\.*(node|php)\.exe$") AND match(Image, "(?i)\\\\(cmd|powershell)\.exe$") AND match(CommandLine, "(?i)systeminfo|tasklist|arp\s-a|nltest|setspn|whoami\s/all|Get-LocalGroup|KerberosRequestorSecurityToken"), "Post-Exploitation: CORNFLAKE process spawning shell for reconnaissance",

    -- Match 3: Detects the registry run key persistence mechanism.")`
    EventCode IN (12, 13) AND match(TargetObject, "(?i)HKU.*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run") AND match(Details, "(?i)AppData\\\\Roaming\\\\.*(node|php)\.exe"), "Persistence: Registry Run Key points to CORNFLAKE in AppData",

    -- Match 4: Detects network connections to known CORNFLAKE C2/Distro infrastructure.")`
    EventCode=3 AND (DestinationIp IN ("138.199.161.141", "159.69.3.151", "167.235.235.151", "128.140.120.188", "177.136.225.135") OR DestinationHostname IN ("varying-rentals-calgary-predict.trycloudflare.com", "dnsmicrosoftds-data.com", "windows-msg-as.live")), "C2: Network connection to known CORNFLAKE infrastructure",

    -- Match 5: Detects known file hashes associated with CORNFLAKE and related tools.")`
    EventCode IN (1, 11) AND match(Hashes, "(?i)MD5=(04668c6f39b0a67c4bd73d5459f8c3a3|bcdffaaf882582941af152d8028d1abe|ec82216a2b42114d23d59eecb876ccfc)"), "IOC: Known CORNFLAKE or WINDYTWIST file hash detected",

    -- Match 6: Detects initial dropper downloading Node.js/PHP runtime. This may be prone to FPs in developer environments.")`
    EventCode=3 AND match(Image, "(?i)\\\\(powershell\.exe|mshta\.exe)$") AND DestinationHostname IN ("nodejs.org", "windows.php.net"), "Initial Access: PowerShell/MSHTA downloading Node.js/PHP runtime",

    -- Match 7: Detects the execution of the dropped WINDYTWIST.SEA backdoor DLL.")`
    EventCode=1 AND match(Image, "(?i)\\\\rundll32\.exe$") AND match(CommandLine, "(?i)\\\\AppData\\\\Roaming\\\\.*\.png"), "Execution: Rundll32 executing a .png file from AppData (WINDYTWIST.SEA)",

    1=1, null()
  )
| where isnotnull(detection_reason)
| stats
  count
  min(_time) as firstTime
  max(_time) as lastTime
  values(detection_reason) as detection_reasons
  values(ParentImage) as parent_process
  values(Image) as process
  values(CommandLine) as command_line
  values(TargetObject) as registry_path
  values(Details) as registry_details
  values(DestinationIp) as dest_ip
  values(DestinationHostname) as dest_hostname
  values(Hashes) as file_hashes
  by Computer, User
| rename Computer as host, User as user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### DPRK Threat Actor Hunting: Impossible Travel, Phishing, Suspicious Processes, Persistence, and Crypto Activity
---
```sql
-- RW

-- This is a broad hunting query designed to identify various tactics, techniques, and procedures (TTPs) associated with DPRK threat actors,
-- as outlined in the DTEX "Exposing DPRK's Cyber Syndicate" report. This query combines several detection concepts into one search.
-- Due to its broad nature, it is intended for threat hunting or as a dashboard panel, not for high-fidelity alerting.
-- Each section should be tested and tuned for your specific environment to reduce false positives.

-- Data sources required: Authentication logs, Endpoint Detection and Response (EDR) logs, Web Proxy/Firewall logs, DNS logs, Email Security logs.
-- Ensure data is CIM compliant or adjust field names accordingly.


-- ================================================================================
-- 1. Fraudulent IT Worker Activity - Impossible Travel / Multi-Geo Logins
-- Identifies a user logging in from multiple countries in a short time frame.
-- FP Tuning: Exclude service accounts or users who legitimately travel or use VPNs that terminate in different countries.
-- Increase the time span or country_count threshold to reduce noise.

| tstats `summariesonly` earliest(_time) as firstTime, latest(_time) as lastTime, dc(src_ip_country) as country_count, values(src_ip_country) as countries from datamodel=Authentication where nodename=All_Authentication by user, _time span=4h
| `drop_dm_object_name("Authentication")`
| where country_count > 1
| eval detection_type="Impossible Travel - Multi-Geo Login"
| eval description=user." logged in from ".country_count." countries: ".mvjoin(countries,", "). " within 4 hours."
| table _time, user, countries, description, detection_type

-- ================================================================================
-- Append: 2. Social Engineering/Phishing - Malicious Link Clicks
-- Identifies users clicking on links categorized as phishing or visiting suspicious TLDs often used in phishing campaigns.
-- FP Tuning: Whitelist legitimate domains that may fall into these categories. Add or remove TLDs based on your threat intelligence.

| append [
    | tstats `summariesonly` count from datamodel=Web where Web.category IN ("Phishing & Fraud", "Malware") by _time, Web.user, Web.url, Web.dest
    | `drop_dm_object_name("Web")`
    | rename Web.* as *
    | eval detection_type="Phishing Link Click"
    | eval description=user." accessed a URL categorized as phishing/malware: ".url
    | table _time, user, url, dest, description, detection_type
]
| append [
    search `proxy` OR `dns`
    | rex field=url "https?:\/\/(?:[^\/]+\.)?(?<domain>[^\/]+\.(?:xyz|top|online|club|live|icu|gq|buzz))"
    | where isnotnull(domain)
    | stats count by _time, user, src, dest, url, domain
    | eval detection_type="Suspicious TLD Visited"
    | eval description=user." visited a URL with a suspicious TLD: ".url
    | table _time, user, src, dest, url, description, detection_type
]

-- ================================================================================
-- Append: 3. RAT/Backdoor/Malware - Suspicious Process Execution
-- Identifies command-line activity often associated with malware execution, backdoors, or hands-on-keyboard activity.
-- FP Tuning: This requires significant tuning. Exclude legitimate administrative scripts and software deployment tools.
-- Focus on parent-child process relationships to add context (e.g., Word -> cmd.exe -> powershell.exe).

| append [
    | tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process_name IN ("powershell.exe", "pwsh.exe") AND Processes.process IN ("* -enc *", "* -encoded *", "* -w hidden *", "* IEX *", "* Invoke-Expression *")) OR (Processes.process_name="mshta.exe" AND Processes.process IN ("*http:*", "*https:*", "*javascript:*")) by _time, Processes.user, Processes.dest, Processes.process_name, Processes.process
    | `drop_dm_object_name("Processes")`
    | rename Processes.* as *
    | eval detection_type="Suspicious Process Execution"
    | eval description=user." executed a suspicious command on ".dest.": ".process
    | table _time, user, dest, process_name, process, description, detection_type
]

-- ================================================================================
-- Append: 4. RAT/Backdoor/Malware - Persistence Mechanisms
-- Identifies the creation of new services or scheduled tasks, common persistence techniques.
-- FP Tuning: Exclude legitimate software installers and system management tools that create services/tasks (e.g., SCCM, Tanium).
-- Baseline your environment to understand normal behavior.

| append [
    search `wineventlog` EventCode=4697 source="Microsoft-Windows-Security-Auditing"
    | rename "Service Name" as service_name, "Service File Name" as service_path
    | stats values(service_path) as service_path by _time, user, dest, service_name
    | eval detection_type="New Service Created"
    | eval description="A new service '".service_name."' pointing to '".service_path."' was created on ".dest." by ".user
    | table _time, user, dest, service_name, service_path, description, detection_type
]
| append [
    search `wineventlog` source="Microsoft-Windows-TaskScheduler/Operational" EventCode=106
    | rex "Task Scheduler registered task \"(?<task_name>[^\"]+)\""
    | stats count by _time, user, dest, task_name
    | eval detection_type="New Scheduled Task Created"
    | eval description="A new scheduled task '".task_name."' was created on ".dest." by ".user
    | table _time, user, dest, task_name, description, detection_type
]

-- ================================================================================
-- Append: 5. Cryptocurrency Theft Indicators - Web Activity
-- Identifies users accessing cryptocurrency exchanges or wallet sites.
-- FP Tuning: This is a low-fidelity indicator and may be very noisy.
-- This should be correlated with other suspicious activity. Whitelist users/departments with a business need.

| append [
    search `proxy`
    | `get_risk_object`
    | search (url="*binance.com*" OR url="*coinbase.com*" OR url="*kraken.com*" OR url="*kucoin.com*" OR url="*bybit.com*" OR url="*metamask.io*")
    | stats count by _time, user, src, dest, url
    | eval detection_type="Cryptocurrency Site Visited"
    | eval description=user." accessed a cryptocurrency-related website: ".url
    | table _time, user, src, dest, url, description, detection_type
]
```

### SHELLTER Evasion Framework Activity Detection
---
```sql
-- Name: SHELLTER Evasion Framework Activity
-- Author: RW
-- Date: 2025-08-23
-- Description: This rule detects indicators and behaviors associated with the SHELLTER evasion framework. It identifies known malicious file hashes, C2 network communications, and TTPs like remapping ntdll.dll to bypass API hooks. This rule is written for Sysmon data but can be adapted for other EDR sources.
-- References: https://www.elastic.co/security-labs/taking-shellter
-- False Positive Sensitivity: Medium
-- Tactic: Defense Evasion, Command and Control
-- Technique: T1055, T1574.002, T1071

-- Part 1: Detect known malicious file hashes
`sysmon` EventCode=1 (sha256 IN ("c865f24e4b9b0855b8b559fc3769239b0aa6e8d680406616a13d9a36fbbc2d30", "7d0c9855167e7c19a67f800892e974c4387e1004b40efb25a2a1d25a99b03a10", "b3e93bfef12678294d9944e61d90ca4aa03b7e3dae5e909c3b2166f122a14dad", "da59d67ced88beae618b9d6c805f40385d0301d412b787e9f9c9559d00d2c880", "70ec2e65f77a940fd0b2b5c0a78a83646dec17583611741521e0992c1bf974f1", "263ab8c9ec821ae573979ef2d5ad98cda5009a39e17398cd31b0fad98d862892"))
| eval DetectionMethod="Known SHELLTER-related hash", Tactic="Execution", Technique="T1204"
| rename Image as process_path, sha256 as process_hash, CommandLine as process_command_line
| fields _time, host, User, process_path, process_command_line, process_hash, DetectionMethod, Tactic, Technique

| append [
    -- Part 2: Detect known C2 network indicators
    search `sysmon` EventCode=3 (DestinationIp IN ("185.156.72.80", "94.141.12.182") OR DestinationHostname="eaglekl.digital")
    | eval DetectionMethod="Known SHELLTER-related C2", Tactic="Command and Control", Technique="T1071"
    | rename Image as process_path, DestinationIp as dest_ip, DestinationHostname as dest_domain
    | fields _time, host, User, process_path, dest_ip, dest_domain, DetectionMethod, Tactic, Technique
]

| append [
    -- Part 3: Detect ntdll.dll unhooking via process access (proxy for file mapping)
    -- SHELLTER maps a fresh copy of ntdll.dll to bypass user-mode API hooks placed by security products.
    search `sysmon` EventCode=10 TargetImage="*\\ntdll.dll"
    -- FP Tuning: Legitimate security products or packers might perform this action.
    -- Consider excluding known good processes if this is noisy in your environment.
    -- | where NOT (SourceImage IN ("C:\\Program Files\\SomeSecProduct\\sec.exe"))
    | eval DetectionMethod="Behavioral - NTDLL Remapping for Hook Evasion", Tactic="Defense Evasion", Technique="T1055"
    | rename SourceImage as process_path, TargetImage as target_path
    | fields _time, host, User, process_path, target_path, DetectionMethod, Tactic, Technique
]

| append [
    -- Part 4: Detect suspicious preloading of modules
    -- SHELLTER can preload multiple modules to support its payload. This looks for a suspicious combination.
    search `sysmon` EventCode=7 (ImageLoaded IN ("*\\wininet.dll", "*\\crypt32.dll", "*\\advapi32.dll", "*\\urlmon.dll"))
    | stats dc(ImageLoaded) as module_count, values(ImageLoaded) as loaded_modules by _time, host, User, Image, ProcessId, CommandLine
    -- The report mentions specific sets of preloaded modules. This looks for a combination of key DLLs.
    | where module_count >= 3
    -- FP Tuning: This behavior can be common for legitimate applications like web browsers.
    -- Increase the module_count threshold or filter by unusual initiating processes to improve fidelity.
    -- | where NOT (match(Image, "(?i)chrome.exe|msedge.exe|explorer.exe"))
    | eval DetectionMethod="Behavioral - Suspicious Module Preloading", Tactic="Defense Evasion", Technique="T1574.002"
    | rename Image as process_path, ProcessId as process_id, CommandLine as process_command_line
    | fields _time, host, User, process_path, process_id, process_command_line, loaded_modules, module_count, DetectionMethod, Tactic, Technique
]
| rex field=process_path "(?<process_name>[^\\\\]+)$"
| fillnull value="N/A"
| table _time, host, User, process_name, process_path, process_command_line, process_hash, dest_ip, dest_domain, target_path, loaded_modules, module_count, DetectionMethod, Tactic, Technique
```

### Interlock Ransomware Activity
---
```sql
-- Name: Interlock Ransomware Activity
-- Author: RW
-- Date: 2025-08-23
-- Description: This rule detects various Tactics, Techniques, and Procedures (TTPs) associated with the Interlock ransomware group (aka Nefarious Mantis). It combines network, process, file, and registry events to identify initial access, execution, persistence, and C2 communication patterns.
-- False Positive Sensitivity: Medium
-- References: https://arcticwolf.com/resources/blog/threat-actor-profile-interlock-ransomware/
-- Tactics: Initial Access, Execution, Persistence, Command and Control
-- Techniques: T1204.002, T1059.001, T1547.001, T1071.001, T1053.005

-- This rule references macros for IOCs. Please create them in your environment.
-- Example macro `interlock_hashes`: `(sha256="2acaa9856ee58537c06cc2858fd71b860f53219504e6756faa3812019b5df5a6" OR sha256="0b47e53f2ada0555588aa8a6a4491e14d7b2528c9a829ebb6f7e9463963cd0e4" OR ...)`
-- Example macro `interlock_c2_ips`: `(dest_ip="168.119.96.41" OR dest_ip="95.217.22.175" OR ...)`
-- Example macro `interlock_domains`: `(dest_host="cluders.org" OR dest_host="bronxy.cc" OR ...)`
-- Example macro `interlock_reg_values`: `(registry_value_name="ChromeUpdater" OR registry_value_name="0neDrive")`

-- Detection for file or process creation with known Interlock hashes
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `interlock_hashes` by Processes.process_name Processes.process Processes.parent_process Processes.dest Processes.user Processes.sha256
| `drop_dm_object_name("Processes")`
| eval Tactic="Execution", Technique="T1204.002", DetectionMethod="Known Malicious Hash"

-- Detection for suspicious PowerShell execution patterns
| append [
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=powershell.exe OR Processes.process="*powershell*") AND (Processes.process="*irm *" OR Processes.process="*iex *" OR Processes.process="*Invoke-RestMethod*" OR Processes.process="*Invoke-Expression*" OR Processes.process="*-w h*" OR Processes.process="*-windowstyle hidden*") by Processes.process_name Processes.process Processes.parent_process Processes.dest Processes.user Processes.sha256
    | `drop_dm_object_name("Processes")`
    | eval Tactic="Execution", Technique="T1059.001", DetectionMethod="Suspicious PowerShell Command"
]

-- Detection for persistence via known Interlock Registry Run Keys
| append [
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*" AND `interlock_reg_values` by Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid Registry.dest Registry.user
    | `drop_dm_object_name("Registry")`
    | rename process_guid as guid
    | join type=left guid [
        | tstats `summariesonly` count from datamodel=Endpoint.Processes where earliest=-1d by Processes.process_name Processes.process Processes.parent_process Processes.guid
        | `drop_dm_object_name("Processes")`
    ]
    | eval Tactic="Persistence", Technique="T1547.001", DetectionMethod="Registry Run Key Modification"
]

-- Detection for C2 communication to known infrastructure or abused services
| append [
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (`interlock_c2_ips` OR `interlock_domains` OR dest_host="*trycloudflare.com*") by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_host All_Traffic.process_guid All_Traffic.dest All_Traffic.user
    | `drop_dm_object_name("All_Traffic")`
    -- FP-Tip: The 'trycloudflare.com' domain is legitimate but often abused. Filter by specific processes if this is too noisy.
    -- For example: `| search NOT (process_name IN (legit_app1.exe, legit_app2.exe))`
    | rename process_guid as guid
    | join type=left guid [
        | tstats `summariesonly` count from datamodel=Endpoint.Processes where earliest=-1d by Processes.process_name Processes.process Processes.parent_process Processes.guid
        | `drop_dm_object_name("Processes")`
    ]
    | eval Tactic="Command and Control", Technique="T1071.001", DetectionMethod="C2 Communication"
]

-- Detection for scheduled task creation for persistence
| append [
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=schtasks.exe AND Processes.process="*/create*" AND (Processes.process="*cmd*" OR Processes.process="*powershell*") by Processes.process_name Processes.process Processes.parent_process Processes.dest Processes.user Processes.sha256
    | `drop_dm_object_name("Processes")`
    -- FP-Tip: This can be a common administrative action. Correlate with other suspicious activity or filter based on the user context or command line specifics.
    | eval Tactic="Persistence", Technique="T1053.005", DetectionMethod="Scheduled Task Creation"
]

-- Consolidate and format results
| rename dest as DeviceName, process_name as FileName, process as ProcessCommandLine, parent_process as InitiatingProcess, sha256 as SHA256, registry_path as RegistryKey, registry_value_name as RegistryValueName, registry_value_data as RegistryValueData, src_ip as SourceIP, dest_ip as DestinationIP, dest_host as DestinationHost
| table firstTime, lastTime, DeviceName, user, Tactic, Technique, DetectionMethod, FileName, ProcessCommandLine, InitiatingProcess, SHA256, RegistryKey, RegistryValueName, RegistryValueData, SourceIP, DestinationIP, DestinationHost
```

### Water Curse Threat Actor - Multi-Stage
---
```sql
-- This detection rule identifies multiple Tactics, Techniques, and Procedures (TTPs) associated with the Water Curse threat actor.
-- Water Curse leverages compromised GitHub repositories to distribute malware, targeting developers and cybersecurity professionals.
-- This rule detects the entire attack chain, from initial execution via malicious Visual Studio project files to defense evasion, persistence, and C2 communication.
-- Source: https://www.trendmicro.com/en_us/research/25/f/water-curse.html
-- Data source: Splunk Common Information Model (CIM). This rule requires the Endpoint, Registry, and Network_Traffic data models to be populated.
-- RW

-- TTP 1: Initial execution via malicious Visual Studio project file (.csproj). Looks for MSBuild spawning cmd.exe to execute a temporary batch file.
[| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="MSBuild.exe" AND Processes.process_name="cmd.exe" AND Processes.process="*/c*" AND Processes.process="*.exec.cmd*" AND Processes.process="*Temp\\MSBuildTemp*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name("Processes")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval Tactic="Execution", Technique="T1129", Activity="WaterCurse: Initial Execution via MSBuild"
]

-- TTP 2: Defense Evasion via PowerShell to disable Windows Defender and System Restore.
| append [
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="powershell.exe" AND (Processes.process="*Set-MpPreference* -ExclusionPath*C:\\*" OR Processes.process="*vssadmin*delete*shadows*/all*" OR Processes.process="*Set-ItemProperty*HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore*DisableSR*") by Processes.dest Processes.user Processes.process_name Processes.process
| `drop_dm_object_name("Processes")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval Tactic="Defense Evasion", Technique="T1562.001", Activity="WaterCurse: Defense Evasion via PowerShell"
]

-- TTP 3: UAC Bypass via ms-settings protocol handler hijack.
| append [
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\Software\\Classes\\ms-settings\\shell\\open\\command*" AND (Registry.registry_value_name="(Default)" OR Registry.registry_value_name="DelegateExecute") by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name
| `drop_dm_object_name("Registry")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval Tactic="Privilege Escalation", Technique="T1548.002", Activity="WaterCurse: UAC Bypass via ms-settings Hijack"
]

-- TTP 4: Persistence via unusually configured Scheduled Task.
| append [
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="schtasks.exe" AND Processes.process="*/create*" AND (Processes.process="*/du 9999:59*" OR (Processes.process="*BitLocker Encrypt All Drives*" AND Processes.process="*\\OneDriveCloud\\taskhostw.exe*")) by Processes.dest Processes.user Processes.process_name Processes.process
| `drop_dm_object_name("Processes")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| -- Legitimate software may create scheduled tasks. This logic is tuned to specific arguments from the campaign, but may require further filtering in some environments.", "fp_notes")`
| eval Tactic="Persistence", Technique="T1053.005", Activity="WaterCurse: Persistence via Scheduled Task"
]

-- TTP 5: Data Staging and Reconnaissance.
| append [
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.process_name="7z.exe" AND Processes.process_path="C:\\ProgramData\\sevenZip\\*" AND Processes.process="*-p*") OR (Processes.parent_process_name="NVIDIA Control Panel.exe" AND Processes.parent_process_path="*\\Microsoft\\Vault\\UserRoamingTiles\\NVIDIAContainer*" AND Processes.process_name IN ("curl.exe", "wmic.exe", "tasklist.exe"))) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process_path Processes.process_name Processes.process_path Processes.process
| `drop_dm_object_name("Processes")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| -- 7-zip usage from ProgramData is unusual but could be legitimate in some developer environments. The NVIDIA Control Panel logic is more specific.", "fp_notes")`
| eval Tactic="Collection", Technique="T1560", Activity="WaterCurse: Staging and Reconnaissance"
]

-- TTP 6: Malicious File Artifacts Creation.
| append [
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where ((Filesystem.file_path="*\\.vs-script\\*" AND Filesystem.file_name IN ("antiDebug.ps1", "disabledefender.ps1")) OR (Filesystem.file_path="*\\AppData\\Local\\Temp\\*" AND Filesystem.file_name="SearchFilter.exe") OR (Filesystem.file_path="*\\Microsoft\\Vault\\UserRoamingTiles\\NVIDIAContainer*" AND Filesystem.file_name="NVIDIA Control Panel.exe")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name("Filesystem")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval Tactic="Initial Access", Technique="T1195.002", Activity="WaterCurse: Malicious File Artifact Creation"
]

-- TTP 7: C2 and Exfiltration Network Activity.
| append [
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Network_Traffic where (Network_Traffic.url IN ("*store-eu-par-2.gofile.io*", "*api.telegram.org*", "*popcorn-soft.glitch.me*", "*pastejustit.com*", "*pastesio.com*") OR Network_Traffic.dest_ip="46.101.236.176" OR Network_Traffic.process_name="RegAsm.exe") by Network_Traffic.dest Network_Traffic.user Network_Traffic.process_name Network_Traffic.url Network_Traffic.dest_ip
| `drop_dm_object_name("Network_Traffic")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval process_name=if(process_name=="RegAsm.exe", "RegAsm.exe (Suspicious C2)", process_name)
| eval Tactic="Command and Control", Technique="T1071", Activity="WaterCurse: C2/Exfiltration Network Connection"
]

-- Final result formatting.", "comment")`
| fillnull value="N/A"
| table firstTime, lastTime, dest, user, Activity, Tactic, Technique, parent_process_name, process_name, process, file_path, file_name, registry_path, registry_value_name, url, dest_ip
```

### PPL Abuse & Defender Tampering
---
```sql
-- Name: PPL Abuse and Defender Tampering Techniques
-- Author: RW
-- Date: 2025-08-23
-- Description: This is a consolidated detection rule that identifies multiple techniques associated with the abuse of Protected Process Light (PPL) to tamper with security products, specifically Windows Defender. It detects the use of the 'CreateProcessAsPPL.exe' tool, anomalous execution of 'ClipUp.exe' to write to protected directories, suspicious auto-start service creation for persistence, and direct file modification in Defender directories by unauthorized processes.
-- False Positives: This detection combines several high-fidelity indicators. False positives may occur if legitimate administrative tools create auto-start services from user/temp paths, or if third-party software installers legitimately write to Defender folders. These should be investigated and can be added to exclusion lists if benign.
-- MITRE ATT&CK: T1055, T1543.003, T1562.001

-- This assumes a Splunk Add-on for Microsoft Sysmon is in use.
-- Replace `sysmon` with your specific index and sourcetype if different (e.g., `index=winevents sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`)
`sysmon`
-- Focus on Process Creation (1) and File Creation (11) events.
(EventCode=1 OR EventCode=11)

-- Use the case statement to categorize different attack patterns into a single 'technique' field.
| eval technique = case(
    -- Tactic 1: Detects the specific PPL loader tool from the research launching ClipUp.exe.
    EventCode=1 AND like(ParentImage, "%\\CreateProcessAsPPL.exe") AND like(Image, "%\\clipup.exe"),
    "PPL Loader launching ClipUp",

    -- Tactic 2: Detects ClipUp.exe being used to write a log file to a sensitive Defender directory.
    EventCode=1 AND like(Image, "%\\System32\\clipup.exe") AND like(CommandLine, "%-ppl%") AND (like(CommandLine, "%\\ProgramData\\Microsoft\\Windows Defender\\%") OR like(CommandLine, "%\\Program Files\\Windows Defender\\%") OR like(CommandLine, "%\\Program Files (x86)\\Windows Defender\\%") OR match(CommandLine, "-ppl\s+.*PROGRA~\d")),
    "Anomalous ClipUp Execution for File Write",

    -- Tactic 3: Detects a new auto-start service pointing to the PPL loader or other suspicious paths.
    EventCode=1 AND like(Image, "%\\sc.exe") AND like(CommandLine, "%create%") AND like(CommandLine, "%start=auto%") AND (like(CommandLine, "%binPath=%CreateProcessAsPPL.exe%") OR like(CommandLine, "%binPath=%\\Users\\%") OR like(CommandLine, "%binPath=%\\ProgramData\\%") OR like(CommandLine, "%binPath=%\\Windows\\Temp\\%") OR like(CommandLine, "%binPath=%\\Temp\\%") OR match(CommandLine, "binPath=.*(cmd|powershell|pwsh)\.exe")),
    "Suspicious Auto-Start Service Creation",

    -- Tactic 4: Detects file creation/modification in Defender directories by non-Defender processes.
    EventCode=11 AND (like(TargetFilename, "C:\\ProgramData\\Microsoft\\Windows Defender\\%") OR like(TargetFilename, "C:\\Program Files\\Windows Defender\\%") OR like(TargetFilename, "C:\\Program Files (x86)\\Windows Defender\\%")) AND NOT (like(Image, "%\\MsMpEng.exe") OR like(Image, "%\\NisSrv.exe") OR like(Image, "%\\MsMpEngCP.exe") OR like(Image, "%\\MpCmdRun.exe") OR like(Image, "%\\TiWorker.exe") OR like(Image, "%\\TrustedInstaller.exe") OR like(Image, "%\\svchost.exe") OR like(Image, "%\\setup.exe")),
    "Unauthorized Defender Directory File Modification"
)
-- Filter for events that matched one of the techniques.
| where isnotnull(technique)

-- Provide a clean, readable output for analysts.
| table _time, Computer, User, technique, ParentImage, Image, CommandLine, TargetFilename
```

### Process CommandLine Spoofing
---
```sql
-- Name: Process CommandLine Spoofing via Symbolic Link
-- Author: RW
-- Date: 2025-08-23
-- Tactic: Defense Evasion
-- Technique: T1036.004
-- Description: Detects instances where the process image path (the actual file on disk) differs from the executable path specified in the command line. This can indicate command line spoofing techniques, such as the one using symbolic links described in the reference, to evade defenses and mislead analysts.

-- This search uses process creation events from the Endpoint data model for efficiency.")`
| tstats `summariesonly` count values(Processes.process) as ProcessCommandLine, values(Processes.process_path) as FolderPath, values(Processes.parent_process_name) as InitiatingProcessFileName from datamodel=Endpoint.Processes by _time, Processes.dest, Processes.user, Processes.process_name
| `drop_dm_object_name("Processes")`
| rename dest as DeviceName, user as AccountName, process_name as FileName

-- Extract the executable path from the command line, handling both quoted and unquoted paths.")`
| rex field=ProcessCommandLine "^(?<CommandLineExecutable>\".*?\"|\S+)"
| eval CommandLineExecutable = trim(CommandLineExecutable, "\"")

-- Core logic: Identify when the resolved image path differs from the command line path.")`
| where isnotnull(FolderPath) AND isnotnull(CommandLineExecutable) AND lower(FolderPath) != lower(CommandLineExecutable)

-- Refine detection by ensuring the executable name is the same, filtering out legitimate launchers.")`
| eval CommandLineFileName = replace(CommandLineExecutable, "^.*\\\\", "")
| where lower(FileName) == lower(CommandLineFileName)

-- FP Filtering: Exclude common legitimate processes and paths. This list may require tuning for your environment.")`
| where NOT (InitiatingProcessFileName IN ("services.exe", "svchost.exe", "WmiPrvSE.exe", "msiexec.exe", "TiWorker.exe") OR match(FolderPath, "(?i)C:\\Windows\\(System32|SysWOW64|servicing)|C:\\Program Files|AppData\\Local\\Temp|\\Windows\\Temp"))

-- Project final fields for investigation.")`
| table _time, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, CommandLineExecutable, InitiatingProcessFileName
```

### EDR Evasion: Process/Module/File Creation with Long File Path
---
```sql
-- Name: EDR File Collection Evasion via Long File Path
-- Author: RW
-- Date: 2025-08-23
-- Description: Detects the creation of processes, files, or the loading of modules at a path that exceeds the standard Windows MAX_PATH limit of 260 characters. Attackers leverage this behavior to cause EDRs and automated collection scripts to fail when trying to access the file, leading to "file not exist" errors and evasion of analysis. This rule combines checks for Sysmon Event Codes 1 (ProcessCreate), 7 (ImageLoad), and 11 (FileCreate).
-- MITRE ATT&CK: T1562.001, T1073
-- False Positive Sensitivity: Medium

(index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational) EventCode IN (1, 7, 11)
-- This base search can be replaced by a more specific index or a macro for Sysmon data (e.g., `sysmon`)

-- Extract the relevant path field based on the event type.
| eval FilePath = case(EventCode=1, Image, EventCode=7, ImageLoaded, EventCode=11, TargetFilename)

-- Filter for events where the path is abnormally long.
| where isnotnull(FilePath) AND len(FilePath) > 260

-- FP Tuning: Legitimate developer tools (e.g., npm, maven) or some installers can create very long paths.
-- Consider excluding known developer processes or trusted parent directories if false positives occur.
-- For example: | search NOT (ParentImage="*\\node.exe" OR ParentImage="*\\devenv.exe")

-- Normalize fields for consistent output.
| eval EventType = case(
    EventCode=1, "Process Creation with Long Path",
    EventCode=7, "Module Load from Long Path",
    EventCode=11, "File Creation with Long Path"
  )
| rename Computer as dest, User as user, ParentImage as parent_process_path, Image as process_path, CommandLine as process, ParentCommandLine as parent_process

-- Create a summary of the findings.
| table _time, dest, user, EventType, process_path, parent_process_path, process, parent_process, FilePath
```

### Suspicious SQL Server Activity
---
```sql
-- Name: Suspicious SQL Server Activity
-- Author: RW
-- Date: 2025-08-23
-- Description: Detects a variety of suspicious activities related to Microsoft SQL Server that could indicate reconnaissance, execution, or persistence. This includes enabling high-risk procedures, sqlservr.exe spawning shells, suspicious use of sqlcmd or Invoke-Sqlcmd, loading of untrusted CLR assemblies, and execution of suspicious startup procedures.
-- MITRE ATT&CK: T1543.003, T1059.001, T1059.003, T1059.006, T1003, T1041

-- Part 1: Detect high-risk configuration changes and suspicious startup procedures from Windows Event Logs.
`wineventlog_application` (EventCode=15457 OR EventCode=17135)
| rex field=EventData "<Data>(?<field1>[^<]+)</Data>(?:<Data>(?<field2>[^<]+)</Data>)?(?:<Data>(?<field3>[^<]+)</Data>)?"
| eval rule_name = case(
    EventCode=15457 AND field1 IN ("xp_cmdshell", "Ole Automation Procedures") AND field2="1", "High-Risk SQL Procedure Enabled",
    EventCode=15457 AND field1="clr enabled" AND field2="1", "SQL CLR Enabled",
    EventCode=15457 AND field1="clr strict security" AND field2="0", "SQL CLR Strict Security Disabled",
    EventCode=17135 AND (lower(field1) LIKE "%xp_%" OR lower(field1) LIKE "%sp_%" OR lower(field1) LIKE "%cmdshell%" OR lower(field1) LIKE "%shell%" OR lower(field1) LIKE "%exec%"), "Suspicious SQL Startup Procedure"
  ),
  details = case(
    EventCode=15457, "Config: " . field1 . ", Old Value: " . field3 . ", New Value: " . field2,
    EventCode=17135, "Procedure: " . field1
  ),
  user="N/A (From Event Log)", command=details, parent_process="sqlservr.exe"
| where isnotnull(rule_name)
| rename host as dest
| table _time, dest, user, rule_name, details, command, parent_process

-- Part 2: Append detections for sqlservr.exe spawning a shell from endpoint data.
| append [
  | tstats `security_content_summariesonly` count from datamodel=Endpoint.Processes where Processes.parent_process_name="sqlservr.exe" AND Processes.process_name IN ("cmd.exe", "powershell.exe") by _time, Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process
  | `drop_dm_object_name(Processes)`
  | eval rule_name="SQL Server Spawning Shell", details=process_name . " spawned by sqlservr.exe.", command=process, parent_process=parent_process
  | table _time, dest, user, rule_name, details, command, parent_process
]

-- Part 3: Append detections for suspicious usage of sqlcmd.exe from endpoint data.
| append [
  | tstats `security_content_summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name="sqlcmd.exe" AND (Processes.process="*xp_cmdshell*" OR Processes.process="*sp_oacreate*" OR Processes.process="*sp_add_trusted_assembly*" OR Processes.process="*sp_configure*" OR Processes.process="*OPENROWSET*" OR Processes.process="*-o *" OR Processes.process="*--outputfile*" OR Processes.process="*http*//*" OR Processes.process="*-t 0*" OR Processes.process="*--query_timeout=0*") by _time, Processes.dest, Processes.user, Processes.parent_process, Processes.process
  | `drop_dm_object_name(Processes)`
  | eval rule_name="Suspicious sqlcmd.exe Usage", details="sqlcmd.exe executed with suspicious arguments.", command=process, parent_process=parent_process
  | table _time, dest, user, rule_name, details, command, parent_process
]

-- Part 4: Append detections for potential CLR assembly loading from endpoint data.
| append [
  | tstats `security_content_summariesonly` count from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.file_name=*.dll Filesystem.file_path="*\\Microsoft SQL Server\\*\\MSSQL\\Binn\\*" by _time, Filesystem.dest, Filesystem.user, Filesystem.file_name, Filesystem.file_path, Filesystem.process_name
  | `drop_dm_object_name(Filesystem)`
  | eval rule_name="Potential SQL CLR Assembly Loaded", details="DLL " . file_name . " created in " . file_path, command=file_name, parent_process=process_name
  | table _time, dest, user, rule_name, details, command, parent_process
]

-- Part 5: Append detections for suspicious Invoke-Sqlcmd usage from PowerShell logs.
| append [
  search `powershell_script_block_log` EventCode=4104 ScriptBlockText="*Invoke-Sqlcmd*" AND (ScriptBlockText="*xp_cmdshell*" OR ScriptBlockText="*sp_oacreate*" OR ScriptBlockText="*sp_add_trusted_assembly*" OR ScriptBlockText="*sp_configure*" OR ScriptBlockText="*OPENROWSET*" OR ScriptBlockText="*-QueryTimeout 0*")
  | rename ComputerName as dest, ScriptBlockText as command
  | eval rule_name="Suspicious Invoke-Sqlcmd Usage", details="PowerShell Invoke-Sqlcmd used with suspicious arguments.", parent_process="powershell.exe"
  | table _time, dest, user, rule_name, details, command, parent_process
]

-- FP Tuning: This is a broad correlation search. Each sub-search may have its own false positives.
-- Review alerts to identify normal administrative activity. For example, legitimate database scripts may use sqlcmd.exe with output files, or administrators may enable CLR for a specific purpose.
-- Consider creating specific allowlists or exclusions for known benign behaviors in each sub-search before the `append` commands.
```

### SQL Injection (SQLi) Attempts
---
```sql
-- Name: Combined SQL Injection (SQLi) Detection
-- Author: RW
-- Date: 2025-08-23

-- This rule combines multiple SQLi detection techniques into a single query.
-- It identifies general attempts, error-based, time-based, database reconnaissance, and authentication bypass attacks.
-- Note: This is a broad query. For performance, replace `index=*` with specific indexes for your web, database, and authentication logs.

-- Start of the main search query targeting relevant sourcetypes.")`
index=* (sourcetype=iis OR sourcetype=W3CIISLog OR sourcetype=apache:access OR sourcetype=pan:traffic OR sourcetype=aws:waf* OR sourcetype=azuresql:audit OR sourcetype=ms:aad:signin OR sourcetype=AzureDiagnostics)

-- Normalize common fields from different sourcetypes for unified analysis.")`
| eval src_ip = coalesce(c_ip, clientip, src, ClientIP, IPAddress, clientIp_s, client_ip_s),
       user = coalesce(cs_username, user, UserPrincipalName, principal_name_s),
       url = lower(coalesce(uri, url, request, requestUri_s)),
       http_response_data = lower(coalesce(response_body, message, details_message_s, details_data_s)),
       sql_query = lower(coalesce(query, statement_s)),
       time_taken_sec = coalesce(time_taken, time_taken_s),
       outcome = lower(coalesce(status, ResultType, action, action_s))

-- Define detection logic using a case statement to categorize the type of SQLi.")`
| eval detection_type=case(
    -- Auth Bypass: Looks for successful logins where the username contains a classic SQLi payload.")`
    ( (outcome="0" OR outcome="success" OR outcome="allow" OR outcome="accepted") AND (like(user, "%' or %") OR like(user, "%'or'--%") OR like(user, "% or 1=1%") OR like(user, "%admin'--%")) ), "SQLi Authentication Bypass",

    -- Time-Based Blind: Identifies requests with time-delay functions that took longer than 5 seconds to respond.")`
    ( time_taken_sec > 5 AND (like(url, "%sleep(%)") OR like(url, "%waitfor delay%") OR like(url, "%benchmark(%") OR like(url, "%pg_sleep(%")) ), "Time-Based Blind SQLi",

    -- Error-Based: Detects common database error messages returned in the server's response.")`
    ( like(http_response_data, "%error in your sql syntax%") OR like(http_response_data, "%unclosed quotation mark%") OR like(http_response_data, "%ora-[0-9][0-9][0-9][0-9][0-9]%") OR like(http_response_data, "%invalid column name%") ), "Error-Based SQLi",

    -- DB Recon: Searches database audit logs for queries targeting sensitive schema information.")`
    ( isnotnull(sql_query) AND (like(sql_query, "%information_schema%") OR like(sql_query, "%sys.objects%") OR like(sql_query, "%pg_catalog%") OR like(sql_query, "%sqlite_master%")) ), "SQLi DB Reconnaissance",

    -- General Attempt: A broad catch-all for common SQLi keywords in the URL.")`
    ( like(url, "%' or %") OR like(url, "% union %select %") OR like(url, "%--%") OR like(url, "%/*%") OR like(url, "%';%")), "General SQLi Attempt"
  )

-- Filter out events that did not match any detection logic.")`
| where isnotnull(detection_type)

-- FP Tuning: Exclude known vulnerability scanners, trusted IPs, or benign user agents.")`
-- Example: | search NOT (src_ip IN (10.0.0.0/8) OR user IN (\"scanner_account\"))")`

-- Group similar events to reduce alert volume. Adjust the span and by-fields as needed.")`
| stats count, values(url) as urls, values(sql_query) as queries, values(outcome) as outcomes by _time, detection_type, src_ip, user, dest, sourcetype

-- Project key fields for investigation.")`
| rename src_ip as SourceIP, user as User, dest as Destination, sourcetype as LogSource
| table _time, detection_type, SourceIP, User, Destination, urls, queries, outcomes, count, LogSource
```

### Container Security: Vulnerabilities, Runtime, API, and Supply Chain Threat Detection
---
```sql
-- Name: Container Security Threat Detection
-- Author: RW
-- Date: 2025-08-23

-- Description: This rule combines multiple detection logics to identify various threats in a containerized environment,
-- including vulnerable images, runtime escape attempts, insecure API usage, and supply chain risks.
-- Note: This query appends data from multiple sources (vulnerability management, Kubernetes audit, EDR).
-- You may need to adjust index, sourcetype, and field names to match your environment.

-- FP Tuning: Create a macro or lookup for trusted_actors_spl to filter legitimate admin users/service accounts, e.g., `| where NOT user.username IN (\"system:masters\", \"cluster-admin\")`")`
-- FP Tuning: Create a macro or lookup for trusted_registries_spl to filter legitimate container registries, e.g., `| where NOT Registry IN (\"mcr.microsoft.com\", \"docker.io\")`")`

-- Part 1: Detect high/critical severity vulnerabilities in container images.")`
(index=your_vuln_index sourcetype=your_vuln_sourcetype earliest=-1d (VulnerabilitySeverity="High" OR VulnerabilitySeverity="Critical")
| sort 0 - _time
| dedup VulnerabilityId, ContainerImage
| eval Tactic = "Initial Access",
       Technique = "Exploit Public-Facing Application",
       DetectionSource = "Vulnerability Scan",
       Entity = ContainerImage,
       Description = "High/Critical severity vulnerability '".VulnerabilityId."' detected in image '".ContainerImage."'."
| fields _time, Tactic, Technique, DetectionSource, Entity, Description
)

| append [
    -- Part 2a: Detect insecure container configurations - privileged containers.")`
    search index=your_kube_audit_index sourcetype=kube:audit earliest=-1d "requestObject.spec.containers{}.securityContext.privileged"=true
    | where NOT 'user.username' IN ("system:masters", "cluster-admin", "azure-operator") -- Consider replacing with `trusted_actors_spl` macro/lookup")`
    | eval Tactic = "Privilege Escalation",
           Technique = "Escape to Host",
           DetectionSource = "Kubernetes Audit",
           Entity = 'user.username',
           Description = "Privileged container '".mvindex('requestObject.spec.containers{}.name',0)."' created by user '".'user.username'."' in namespace '".'objectRef.namespace'."."
    | fields _time, Tactic, Technique, DetectionSource, Entity, Description
]

| append [
    -- Part 2b: Detect runtime escape attempts - suspicious processes.")`
    search index=your_edr_index earliest=-1d (ParentImage="*runc*" OR ParentImage="*containerd-shim*") process_name IN ("nsenter", "insmod", "modprobe", "chroot")
    -- FP Tuning: Some legitimate tools might use these commands. Profile baseline behavior and add more specific path or command-line exclusions if needed.")`
    | eval Tactic = "Privilege Escalation",
           Technique = "Escape to Host",
           DetectionSource = "EDR",
           Entity = dest,
           Description = "Suspicious process '".process_name."' with command line '".cmdline."' executed from a container context on host '".dest."'."
    | fields _time, Tactic, Technique, DetectionSource, Entity, Description
]

| append [
    -- Part 3: Detect insecure API access patterns in Kubernetes.")`
    search index=your_kube_audit_index sourcetype=kube:audit earliest=-1d verb="create" objectRef.resource="clusterrolebindings" ('requestObject.roleRef.name'="cluster-admin" OR 'requestObject.roleRef.name'="admin")
    | where NOT 'user.username' IN ("system:masters", "cluster-admin", "azure-operator") -- Consider replacing with `trusted_actors_spl` macro/lookup")`
    | eval Tactic = "Privilege Escalation",
           Technique = "Valid Accounts",
           DetectionSource = "Kubernetes Audit",
           Entity = 'user.username',
           Description = "User '".'user.username'."' created a cluster role binding to a privileged role '".'requestObject.roleRef.name'."."
    | fields _time, Tactic, Technique, DetectionSource, Entity, Description
]

| append [
    -- Part 4: Detect supply chain threats, such as using images from untrusted registries.")`
    search index=your_container_inventory_index earliest=-1d Image=*
    | rex field=Image "(?<Registry>[^/]+)/.*"
    | where isnotnull(Registry) AND NOT Registry IN ("mcr.microsoft.com", "docker.io", "k8s.gcr.io", "quay.io", "gcr.io") -- Consider replacing with `trusted_registries_spl` macro/lookup")`
    | stats count by _time, Image, Computer
    | bin _time span=1h
    | eval Tactic = "Initial Access",
           Technique = "Supply Chain Compromise",
           DetectionSource = "Container Inventory",
           Entity = Image,
           Description = "Container started from untrusted registry: '".Image."' on host '".Computer."'."
    | fields _time, Tactic, Technique, DetectionSource, Entity, Description
]
```

### UNC6384 (Mustang Panda) Campaign IOCs and TTPs
---
```sql
-- title: UNC6384 Mustang Panda Campaign IOCs and TTPs
-- description: Detects multiple indicators of compromise (IOCs) and tactics, techniques, and procedures (TTPs) associated with a UNC6384 (Mustang Panda) campaign targeting diplomats, as reported by Google in August 2025. This rule covers file hashes, network indicators, persistence mechanisms, and behavioral patterns related to the STATICPLUGIN, CANONSTAGER, and SOGU.SEC malware families.
-- author: RW
-- date: 2025-08-26

-- This query combines multiple detection methods. Ensure you have the necessary data sources, such as Sysmon (or equivalent EDR) and network traffic/proxy logs, mapped to the CIM.
search (index=* tag=endpoint) OR (index=* tag=network)
(
    -- High-fidelity file hash indicators
    (hash_sha256 IN ("65c42a7ea18162a92ee982eded91653a5358a7129c7672715ce8ddb6027ec124", "3299866538aff40ca85276f87dd0cefe4eafe167bd64732d67b06af4f3349916", "e787f64af048b9cb8a153a0759555785c8fd3ee1e8efbca312a29f2acb1e4011", "cc4db3d8049043fa62326d0b3341960f9a0cf9b54c2fbbdffdbd8761d99add79", "d1626c35ff69e7e5bde5eea9f9a242713421e59197f4b6d77b914ed46976b933") OR file_hash_sha256 IN ("65c42a7ea18162a92ee982eded91653a5358a7129c7672715ce8ddb6027ec124", "3299866538aff40ca85276f87dd0cefe4eafe167bd64732d67b06af4f3349916", "e787f64af048b9cb8a153a0759555785c8fd3ee1e8efbca312a29f2acb1e4011", "cc4db3d8049043fa62326d0b3341960f9a0cf9b54c2fbbdffdbd8761d99add79", "d1626c35ff69e7e5bde5eea9f9a242713421e59197f4b6d77b914ed46976b933"))
    OR
    -- Network indicators for C2 and payload hosting
    (dest_ip IN ("103.79.120.72", "166.88.2.90") OR dest_host="mediareleaseupdates.com")
    OR
    -- Specific User-Agent used by SOGU.SEC
    (http_user_agent="Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 10.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)")
    OR
    -- Persistence via Run key (Sysmon EventCode 12, 13, 14)
    (EventCode IN (12,13,14) AND TargetObject="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\CanonPrinter" AND Details="*cnmpaui.exe*")
    OR
    -- DLL side-loading TTP (Sysmon EventCode 7)
    (EventCode=7 AND Image="*\\cnmpaui.exe" AND ImageLoaded="*\\cnmpaui.dll")
    OR
    -- Suspicious file paths used by the malware (Sysmon EventCode 1)
    (EventCode=1 AND (TargetFilename="*\\DNVjzaXMFO\\*" OR TargetFilename="*C:\\Users\\Public\\Intelnet\\*" OR TargetFilename="*C:\\Users\\Public\\SecurityScan\\*"))
)

-- Normalize fields and add detection metadata
| eval timestamp=strftime(_time, "%Y-%m-%d %H:%M:%S")
| eval detection_name=case(
    isnotnull(hash_sha256) OR isnotnull(file_hash_sha256), "UNC6384 - Malicious File Hash",
    isnotnull(dest_ip) OR isnotnull(dest_host), "UNC6384 - Malicious Network Connection",
    match(http_user_agent, "MSIE 9.0"), "UNC6384 - SOGU.SEC User Agent",
    EventCode IN (12,13,14), "UNC6384 - CanonPrinter Persistence",
    EventCode=7, "UNC6384 - CANONSTAGER DLL Sideloading",
    EventCode=1, "UNC6384 - Suspicious File Path",
    1=1, "UNC6384 - Fallback Match"
  )
-- FP Note: The persistence rule may trigger on legitimate Canon software. Investigate the process command line and file properties.
| eval victim_host=coalesce(host, dvc, dest_host, ComputerName, dest)
| eval src_process=coalesce(process, Image, process_name, file_name)
| eval user=coalesce(user, User)
| eval ioc_indicator=coalesce(hash_sha256, file_hash_sha256, dest_ip, dest_host, http_user_agent, TargetObject, ImageLoaded, TargetFilename)

-- Group results for alerting
| stats count values(timestamp) as event_times values(detection_name) as detections values(ioc_indicator) as matched_iocs values(src_process) as processes values(user) as users by victim_host
| rename victim_host as "Victim Host", event_times as "Event Times", detections as "Detections", matched_iocs as "Matched IOCs", processes as "Associated Processes", users as "Associated Users"
```

### APT28 NotDoor Backdoor Activity Detection
---
```sql
-- Name: APT28 NotDoor Backdoor Activity
-- Author: RW
-- Date: 2025-09-03
-- Description: This rule detects various activities associated with the NotDoor backdoor, used by APT28. It looks for specific file creation events, process command lines, registry modifications, and network communications.
-- False Positive Sensitivity: Medium
-- Data Model: This query is written for Sysmon data but can be adapted for the Splunk Common Information Model (CIM) or other data sources.

-- Specify indexes and sourcetypes for Sysmon, network, and email data
(
(index=* (sourcetype="xmlwineventlog" OR sourcetype="stash")) OR (sourcetype="stream:dns" OR sourcetype="stream:http") OR (sourcetype="your_email_log_sourcetype")
)
-- The 'your_email_log_sourcetype' should be replaced with your specific email log source.

-- Use eval and case to create a field that describes which specific behavior was detected
| eval detection_method=case(
    -- File events: Malicious hashes, initial backdoor drop, and staging files
    (EventCode=11 AND (sha256="5a88a15a1d764e635462f78a0cd958b17e6d22c716740febc114a408eef66705" OR sha256="8f4bca3c62268fff0458322d111a511e0bcfba255d5ab78c45973bd293379901")), "Malicious File Hash Detected (SSPICLI.dll or testtemp.ini)",
    (EventCode=11 AND TargetFilename="C:\\ProgramData\\testtemp.ini"), "Initial Backdoor File Drop (testtemp.ini)",
    (EventCode=11 AND match(TargetFilename, "(?i)\\\\AppData\\\\Local\\\\Temp\\\\Test\\\\(report|invoice|contract|photo|scheme|document)_[^\\\\]+\\.(jpg|jpeg|gif|bmp|ico|png|pdf|doc|docx|xls|xlsx|ppt|pptx|mp3|mp4|xml)$")), "Staging File Creation for Exfiltration",

    -- Process creation: PowerShell installation and C2 verification
    (EventCode=1 AND match(CommandLine, "(?i)copy.*c:\\\\programdata\\\\testtemp.ini.*\\\\Microsoft\\\\Outlook\\\\VbaProject.OTM")), "Backdoor Macro Installation Command",
    (EventCode=1 AND process_name="nslookup.exe" AND match(CommandLine, "(?i)\\.dnshook\\.site")), "C2 Verification via nslookup",
    (EventCode=1 AND process_name="curl.exe" AND match(CommandLine, "(?i)webhook\\.site")), "C2 Verification via curl",

    -- Registry modification: Outlook persistence and warning suppression
    (EventCode=13 AND match(TargetObject, "(?i)\\\\Software\\\\Microsoft\\\\Office\\\\[^\\\\]+\\\\Outlook\\\\LoadMacroProviderOnBoot$") AND Details="1"), "Outlook Persistence via LoadMacroProviderOnBoot",
    -- FP Note: Setting macro security to 'Enable all' is suspicious but may be legitimate.
    (EventCode=13 AND match(TargetObject, "(?i)\\\\Software\\\\Microsoft\\\\Office\\\\[^\\\\]+\\\\Outlook\\\\Security\\\\Level$") AND Details="1"), "Outlook Macro Security Disabled",
    (EventCode=13 AND match(TargetObject, "(?i)\\\\Software\\\\Microsoft\\\\Office\\\\[^\\\\]+\\\\Outlook\\\\Options\\\\General\\\\PONT_STRING$") AND Details=";"), "Outlook Macro Warning Disabled",

    -- Network events: C2 communication
    -- FP Note: Legitimate use of webhook.site or dnshook.site may occur.
    (EventCode=22 AND match(QueryName, "(?i)(webhook|dnshook)\\.site$")) OR (sourcetype="stream:dns" AND match(query, "(?i)(webhook|dnshook)\\.site$")), "C2 DNS Query",
    (sourcetype="stream:http" AND match(dest_host, "(?i)(webhook|dnshook)\\.site$")), "C2 HTTP Connection",

    -- Email events: Exfiltration
    (sourcetype="your_email_log_sourcetype" AND to="a.matti444@proton.me" AND subject="Re: 0"), "Exfiltration Email Sent"
)
-- Filter for events that matched one of the detection criteria
| where isnotnull(detection_method)

-- Table of relevant fields for investigation
| table _time, host, user, process_name, CommandLine, TargetFilename, sha256, TargetObject, Details, QueryName, dest_host, to, subject, detection_method
```

### MeetC2 C2 Activity via Google Calendar API
---
```sql
-- Author: RW
-- Date: 2025-09-06
-- Description: Detects potential Command and Control (C2) activity using Google Calendar, inspired by the MeetC2 framework. This rule combines searches across Google Workspace audit logs and network traffic to identify suspicious event content and API beaconing patterns.
-- Tactic: Command and Control
-- Technique: T1071.001 (Web Protocols), T1102.002 (Web Service)
-- False Positives: Legitimate applications using the Google Calendar API may generate a high volume of requests. Calendar sharing with service accounts for legitimate automation purposes can also trigger this rule. Tuning of the beaconing threshold and process exclusion list is recommended.
-- Severity: Medium

-- Part 1: Detects suspicious Google Calendar event creation, updates, or sharing based on the MeetC2 framework. This requires Google Workspace audit logs.
(index=gcp OR index=google_workspace) sourcetype IN ("google:gsuite:reports:admin", "google:workspace:activity") name IN ("calendar.events.insert", "calendar.events.update", "calendar.acl.create")
(
    ("parameters.summary"="*Meeting from nobody:*[COMMAND]*") OR
    ("parameters.description"="*[OUTPUT]*" AND "parameters.description"="*[/OUTPUT]*") OR
    ("parameters.acl.scope.value"="*gserviceaccount.com")
)
| spath
| rename actor.email as user, ipAddress as src_ip, name as event_name, parameters.* as *
| eval detection_method=case(
    like(summary, "%Meeting from nobody:%[COMMAND]%"), "MeetC2 Command Pattern in Event Summary",
    like(description, "%[OUTPUT]%") AND like(description, "%[/OUTPUT]%"), "MeetC2 Output Pattern in Event Description",
    event_name=="calendar.acl.create" AND like(acl.scope.value, "%gserviceaccount.com"), "Calendar Shared with Service Account"
  )
| eval details="Event Name: " + event_name + ", Summary: " + coalesce(summary, "N/A") + ", Recipient: " + coalesce(acl.scope.value, "N/A")
| table _time, user, src_ip, detection_method, details

-- Part 2: Appends results from network traffic analysis to detect C2 beaconing to the Google Calendar API. This requires proxy, firewall, or EDR network logs.
| append [
    (index=proxy OR index=network OR index=*) (sourcetype=pan:traffic OR sourcetype=zscaler OR sourcetype=stream:http OR sourcetype=crowdstrike:streaming:api) url="*www.googleapis.com/calendar/v3/calendars/*/events*"
    -- The following line attempts to filter out legitimate browser and application traffic. This list may need to be customized for your environment.
    | where isnull(process_path) OR NOT match(process_path, "(?i)(chrome|msedge|firefox|outlook|teams)\.exe$")
    | bin _time span=10m
    | stats count as request_count, values(url) as urls by src_ip, process_path, user, _time
    -- The threshold below is based on the PoC's 30-second polling interval. Adjust as needed based on observed false positives from legitimate applications.
    | where request_count > 15
    | eval detection_method="Potential C2 Beaconing to Google Calendar API"
    | eval details=printf("Process '%s' made %d requests to Google Calendar API in 10 minutes.", coalesce(process_path, "N/A"), request_count)
    | table _time, user, src_ip, detection_method, details
]
```

### Exposed Docker APIs Are Targeted in New Malware Strain
---
```sql
-- author: RW

-- This detection rule identifies a multi-stage attack targeting exposed Docker APIs.
-- The malware strain aims to establish persistent root access, create a botnet, and perform reconnaissance.
-- This rule combines several detection concepts into a single query to provide a broad overview of related malicious activities.

-- Tactic: Initial Access, Execution - Detects exploitation of the Docker API to create malicious containers.
(index=* sourcetype IN (stream:http, suricata, zeek:http:*) http_method=POST uri_path IN ("/containers/create*", "/images/create*") dest_port=2375
-- FP-Note: Legitimate Docker API usage will trigger this. Filter by known-good source IPs or user agents if necessary.
| eval Tactic="Initial Access", Technique="Exposed Docker Daemon API", Description="Potential Docker API exploitation attempt on port 2375."
| fields _time, src_ip, dest_ip, user_agent, Tactic, Technique, Description)

-- Append logic for post-exploitation command execution within a new container.
| append [
    search (index=* sourcetype IN (linux:audit, sysmon:linux, falco) (process_name IN ("sh", "bash") process_args IN ("*curl*", "*wget*")) OR (process_name IN ("apk", "apt", "yum")))
    -- This looks for package installers or downloaders running, common in initial container setup for malware.
    | stats earliest(_time) as first_seen, latest(_time) as last_seen, values(process_name) as processes, values(process_args) as args by host, container_id
    | where mvcount(processes) > 1 AND (like(args, "%curl%") OR like(args, "%wget%"))
    | eval Tactic="Execution", Technique="Command and Scripting Interpreter", Description="Suspicious package installation followed by downloader execution in a container."
    | rename host as dest_host, container_id as container.id
    | fields first_seen, last_seen, dest_host, container.id, processes, args, Tactic, Technique, Description
]

-- Append logic for persistence techniques like SSH key and crontab modification.
| append [
    search (index=* sourcetype IN (linux:audit, sysmon:linux, osquery) file_path IN ("/root/.ssh/authorized_keys", "/etc/crontab", "/etc/cron.d/*", "/var/spool/cron/*") file_operation IN (write, create))
    OR (index=* sourcetype IN (linux:audit, sysmon:linux) process_name IN ("firewall-cmd", "iptables") process_args IN ("*--add-rich-rule*", "*--reload*", "*-A INPUT*", "*-p tcp*"))
    | eval Tactic="Persistence", Technique="SSH Authorized Keys or Cron Job Modification", Description="Modification of sensitive files for persistence (SSH keys, cron) or firewall rules for defense evasion."
    | fields _time, host, user, process_name, process_args, file_path, Tactic, Technique, Description
]

-- Append logic for discovery and lateral movement via scanning.
| append [
    search (index=* sourcetype IN (linux:audit, sysmon:linux) process_name="masscan")
    OR (index=* sourcetype IN (stream:tcp, suricata, zeek:conn:*) dest_port IN (23, 9222, 2375))
    -- FP-Note: Connections to Telnet (23), Chrome Debug (9222), or Docker API (2375) may be legitimate. Baseline normal activity and focus on anomalous sources.
    | eval Tactic="Discovery/Lateral Movement", Technique="Network Service Scanning", Description="Execution of masscan or connection attempts to Telnet, Chrome Debug, or Docker API ports."
    | fields _time, src_ip, dest_ip, dest_port, process_name, Tactic, Technique, Description
]

-- Append logic for C2 communication over Tor.
| append [
    search (index=* sourcetype IN (stream:dns, zeek:dns:*) query="*.onion")
    OR (index=* sourcetype IN (linux:audit, sysmon:linux) process_name="torsocks")
    | eval Tactic="Command and Control", Technique="Proxy: Tor", Description="Tor-related activity detected (torsocks process or .onion domain query)."
    | fields _time, host, src_ip, query, process_name, Tactic, Technique, Description
]

| -- Combine and format results.
| table _time, Tactic, Technique, Description, src_ip, dest_ip, dest_host, host, user, process_name, process_args, file_path, query, container.id
```