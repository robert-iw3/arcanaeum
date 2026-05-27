## Miscellaneous Queries

### Credential Dumping to ADMIN localhost

Detects the credential dumping, creating a dump in the ADMIN tmp.

##

```sql
from win_logs* -- replace with windows log index
| where source like "WinEventLog%"
  and (Image like "%\\cmd.exe" or originalFileName = "cmd.exe")
  and CommandLine like "%/c wmic process call create%"
  and (CommandLine like "%\"cmd.exe /c mkdir C:\\Windows\\Temp\\tmp%"
       or CommandLine like "%& ntdsutil \"ac i ntds\" ifm \"create full C:\\Windows\\Temp\\tmp\" 1> \\127.0.0.1\\ADMIN$\\ 2>&1%")
```

### Enumeration techniques
---

The following commands were used by the actor to enumerate the network topology [T1016], the active directory structure [T1069.002], and other information about the target environment [T1069.001], [T1082]:


```sql
from win_logs* -- ECS data source (replace with yours)
| where winlog.channel like "Security%" or winlog.channel like "System%"
  and (
    process.command_line like "%ipconfig /all%"
    or process.command_line like "%netsh interface show interface%"
    or process.command_line like "%netsh interface firewall show all%"
    or process.command_line like "%arp -a%"
    or process.command_line like "%nbtstat -n%"
    or process.command_line like "%net config%"
    or process.command_line like "%net group /dom%"
    or process.command_line like "%net group \"Domain Admins\" /dom%"
    or process.command_line like "%route print%"
    or process.command_line like "%curl www.ip-api.com%"
    or process.command_line like "%dnscmd%"
    or process.command_line like "%ldifde.exe -f c:\\windows\\temp\\.txt -p subtree%"
    or process.command_line like "%netlocalgroup%"
    or process.command_line like "%netsh interface portproxy show%"
    or process.command_line like "%netstat -ano%"
    or process.command_line like "%reg query hklm\\software\\%"
    or process.command_line like "%systeminfo%"
    or process.command_line like "%tasklist /v %"
    or process.command_line like "%wmic volume list brief%"
    or process.command_line like "%wmic service brief%"
    or process.command_line like "%wmic product list brief%"
    or process.command_line like "%wmic baseboard list brief%"
    or process.command_line like "%wevtutil qe security /rd:true /f:text /q:%[System[(EventID=4624)]%"
  )
```

```sql
from win_logs* -- replace with yours
| where winlog.channel like "Security%" or winlog.channel like "System%"
  and (
    process.command_line like "%ipconfig /all%"
    or process.command_line like "%netsh interface show interface%"
    or process.command_line like "%arp -a%"
    or process.command_line like "%nbtstat -n%"
    or process.command_line like "%net config%"
    or process.command_line like "%route print%"
  )
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
from o365_audit_logs* -- replace with yours
| where event.dataset like "audit%"
  and event.action = "Consent to application."
  and o365audit.App = "AzureActiveDirectory"
  and (
    o365audit.ModifiedProperties like "%ConsentType%AllPrincipals%"
    or o365audit.ModifiedProperties like "%IsAdminConsent%True%"
  )
| eval scope_list = REGEXP_EXTRACT(o365audit.ModifiedProperties, "Scope:\\s*([^\\]]+)", 1)
| eval scope_array = SPLIT(scope_list, ", ")
| dissect scope_array AS scope_item
| eval Timestamp = TO_STRING(from_TIMESTAMP(@timestamp, "yyyy-MM-dd HH:mm:ss:SSS"))
| stats
    timestamp = VALUES(Timestamp),
    AppId = VALUES(o365audit.AppId),
    user = VALUES(user.id),
    user_agent = VALUES(user_agent),
    scope_array = VALUES(scope_item),
    modified_properties = VALUES(o365audit.ModifiedProperties),
    result = VALUES(event.outcome),
    count = COUNT(*)
  by o365audit.Object, o365audit.ObjectId
```

### Uncommon Network Connection Initiated by Certutil.exe
---

Within a few hours of initial exploitation, APT41 used the storescyncsvc.dll BEACON backdoor to download a secondary backdoor with a different C2 address that uses Microsoft CertUtil, a common TTP that we've observed APT41 use in past intrusions, which they then used to download 2.exe (MD5: 3e856162c36b532925c8226b4ed3481c). The file 2.exe was a VMProtected Meterpreter downloader used to download Cobalt Strike BEACON shellcode. The usage of VMProtected binaries is another very common TTP that we've observed this group leverage in multiple intrusions in order to delay analysis of other tools in their toolkit.


```sql
from win_logs* -- replace with yours
| where winlog.channel like "Security%" OR winlog.channel like "System%"
  and process.executable like "%\\certutil.exe"
  and network.initiated = true
  and (destination.port = 80 OR destination.port = 135 OR destination.port = 443 OR destination.port = 445)
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

from endpoint_filesystem_logs* -- replace with your data source
| where (
    file.path like "%AppData\\Local\\Google\\Chrome\\User Data%\\Login Data%"
    OR file.path like "%AppData\\Local\\Microsoft\\Edge\\User Data%\\Login Data%"
    OR file.path like "%AppData\\Roaming\\Mozilla\\Firefox\\Profiles%\\logins.json%"
    OR file.path like "%AppData\\Roaming\\Mozilla\\Firefox\\Profiles%\\key4.db%"
    OR file.path like "%AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data%\\Login Data%"
    OR file.path like "%AppData\\Roaming\\Opera Software\\Opera Stable\\Login Data%"
)
  and NOT process.name IN ("chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "opera.exe")
| stats
    count = COUNT(*),
    accessed_files = VALUES(file.path),
    actions_taken = VALUES(event.action)
  BY @timestamp, host.name, user.name, process.name, process.executable
| RENAME
    host.name AS Endpoint,
    user.name AS User,
    process.name AS Process_Name,
    process.executable AS Process_Path,
    accessed_files AS Accessed_Credential_Files,
    actions_taken AS File_Actions
```

### Credential Theft
---

The actor also used the following commands to identify additional opportunities for obtaining credentials in the environment [T1555], [T1003]:

Detects the usage of "reg.exe" in order to query information from the registry like software.


```sql
from win_logs*
| where winlog.channel like "Security%" OR winlog.channel like "System%"
  and (process.executable like "%\\reg.exe" OR winlog.event_data.OriginalFileName = "reg.exe")
  and process.command_line like "%save%"
  and (
    process.command_line like "%reg save hklm\\sam ss.dat%"
    OR process.command_line like "%reg save hklm\\system sy.dat%"
    OR process.command_line like "%reg save hklm\\system%"
    OR process.command_line like "%reg save hklm\\sam%"
  )
```

```sql
from win_logs*
| where winlog.channel like "Security%" OR winlog.channel like "System%"
  and (process.executable like "%\\reg.exe" OR winlog.event_data.OriginalFileName = "reg.exe")
  and process.command_line like "%query%"
  and (
    process.command_line like "%reg query hklm\\software\\OpenSSH%"
    OR process.command_line like "%reg query hklm\\software\\OpenSSH\\Agent%"
    OR process.command_line like "%reg query hklm\\software\\realvnc%"
    OR process.command_line like "%reg query hklm\\software\\realvnc\\vncserver%"
    OR process.command_line like "%reg query hklm\\software\\realvnc\\Allusers%"
    OR process.command_line like "%reg query hklm\\software\\realvnc\\Allusers\\vncserver%"
    OR process.command_line like "%reg query hkcu\\software%\\putty\\session%"
  )
```

```sql
from win_logs*
| where winlog.channel like "Security%" OR winlog.channel like "System%"
  and process.executable like "%\\regedit.exe"
  and (process.command_line like "% /E %" OR process.command_line like "% -E %")
  and (process.command_line like "%hklm%" OR process.command_line like "%hkey_local_machine%")
  and (process.command_line like "%\\system" OR process.command_line like "%\\sam" OR process.command_line like "%\\security")
| keep process.parent.executable, process.command_line
| RENAME process.parent.executable AS ParentImage, process.command_line AS CommandLine
```

### Possible DCSync Attack Detected via AD Replication and Network Indicators
---

Detects potential DCSync attacks by correlating Active Directory replication requests (Event ID 4662) with suspicious network activity (Sysmon Event ID 3). DCSync allows attackers with replication privileges to request credential data from domain controllers, mimicking legitimate replication traffic.

```sql
from win_logs*
| where (winlog.channel like "Security%" OR winlog.channel = "Microsoft-Windows-Sysmon/Operational")
  and (
    (
      event.code = "4662"
      and (
        winlog.event_data.ObjectType like "%19195a5b-6da0-11d0-afd3-00c04fd930c9%"
        OR winlog.event_data.ObjectType like "%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%"
        OR winlog.event_data.ObjectType like "%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%"
        OR winlog.event_data.ObjectType like "%89e95b76-444d-4c62-991a-0facbeda640c%"
        OR winlog.event_data.ObjectType like "%replicationSynchronization%"
        OR winlog.event_data.ObjectType like "%replicating Directory Changes All%"
      )
      and winlog.event_data.AccessMask = "0x100"
    )
    OR (
      event.code = "3"
      and (destination.port = 135 OR destination.port = 389 OR destination.port = 88)
    )
  )
| EVAL Account_Name = LOWER(
    CASE(
      event.code = "4662", winlog.event_data.AccountName,
      event.code = "3", REGEXP_EXTRACT(winlog.event_data.User, "User:\\s([^\\s]+)", 1)
    )
  )
| EVAL Descriptive_Object_Type = CASE(
    winlog.event_data.ObjectType like "%19195a5b-6da0-11d0-afd3-00c04fd930c9%", "Directory Replication",
    winlog.event_data.ObjectType like "%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%", "Replicating Directory Changes",
    winlog.event_data.ObjectType like "%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%", "Replicating Directory Changes All",
    winlog.event_data.ObjectType like "%89e95b76-444d-4c62-991a-0facbeda640c%", "Replicating Directory Changes In Filtered Set",
    winlog.event_data.ObjectType like "%replicationSynchronization%", "General Replication Synchronization",
    winlog.event_data.ObjectType like "%replicating Directory Changes All%", "General Replication of All Directory Changes",
    true, "Unknown"
  )
| EVAL Ticket_Time = CASE(event.code = "4662", @timestamp, NULL)
| EVAL Network_Time = CASE(event.code = "3", @timestamp, NULL)
| stats
    Object_Type = VALUES(Descriptive_Object_Type),
    Image = VALUES(process.executable),
    DestinationPort = VALUES(destination.port),
    Ticket_Time = MIN(Ticket_Time),
    Network_Time = MIN(Network_Time),
    Ticket_Count = COUNT_IF(Ticket_Time IS NOT NULL),
    Network_Count = COUNT_IF(Network_Time IS NOT NULL)
  BY Account_Name
| where Object_Type IS NOT NULL and Network_Time IS NOT NULL
| where ABS(Ticket_Time - Network_Time) <= 1800
| EVAL Network_Time = TO_STRING(from_TIMESTAMP(Network_Time, "yyyy-MM-dd HH:mm:ss"))
| EVAL Ticket_Time = TO_STRING(from_TIMESTAMP(Ticket_Time, "yyyy-MM-dd HH:mm:ss"))
| keep Account_Name, Object_Type, Image, DestinationPort, Network_Time, Network_Count, Ticket_Time, Ticket_Count
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
from win_logs*
| where winlog.channel like "Security%" OR winlog.channel like "System%"
  and event.code = "4688"
  and process.executable like "%wmic.exe"
  and process.command_line like "%defender%"
  and process.command_line like "%msft_mppreference%"
  and process.command_line like "%call%"
  and process.command_line like "%add%"
  and process.command_line like "%exclusionpath%"
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
from win_logs*
| where winlog.channel = "Security"
  and event.code = "4625"
  and winlog.event_data.SubStatus = "0xC0000064"
| EVAL Date = TO_STRING(from_TIMESTAMP(@timestamp, "yyyy/MM/dd"))
| EVAL uacct = REGEXP_EXTRACT(message, "Which\\sLogon\\sFailed:\\s+Security\\sID:\\s+\\S.*\\s+\\w+\\s\\w+\\S\\s.(.*)", 1)
| stats Attempts = COUNT(*) BY Date, uacct, host.name
| sort Attempts DESC
```

### Lsass Memory Dump via Comsvcs DLL
---

Detects adversaries leveraging the MiniDump export function from comsvcs.dll via rundll32 to perform a memory dump from lsass.

```sql
from win_logs*
| where winlog.channel like "Security%" OR winlog.channel like "System%"
  and process.target.executable like "%\\lsass.exe"
  and process.executable = "C:\\Windows\\System32\\rundll32.exe"
  and process.call_trace like "%comsvcs.dll%"
```

### MiTM Proxy Detection
---

```sql
from packetbeat-* # or whatever source contains network traffic analytics data
| where http.request.method IN ("GET", "POST")
  and (http.request.url like "%.php%" or http.request.url like "%login%" or http.request.url like "%auth%")
  and http.response.status_code IN (200, 301, 302)
  and (tls.server.issuer like "%Let’s Encrypt%" or tls.server.issuer IS NULL or tls.server.issuer == "unknown")
| eval potential_mitm = CASE(
    destination.domain Rlike ".*(microsoftonline|office365|login|outlook|okta|github|linkedin|amazon).*(com|org|eu|shop)",
    "Possible phishing proxy",
    "Other suspicious proxy"
  )
| stats
    count = COUNT(*),
    firstTime = MIN(@timestamp),
    lastTime = MAX(@timestamp),
    urls = GROUP_CONCAT(http.request.url),
    user_agents = GROUP_CONCAT(http.request.user_agent),
    ssl_issuers = GROUP_CONCAT(tls.server.issuer)
  by source.ip, destination.domain
| where count > 5
| keep firstTime, lastTime, source.ip, destination.domain, urls, user_agents, ssl_issuers, potential_mitm, count
| sort firstTime ASC
```

### Potential Recon Activity Via Nltest.exe
---

Detects nltest commands that can be used for information discovery.

```sql
from win_logs*
| where winlog.channel like "Security%" OR winlog.channel like "System%"
  and (process.executable like "%\\nltest.exe" OR winlog.event_data.OriginalFileName = "nltestrk.exe")
```

```sql
from win_logs*
| where winlog.channel like "Security%" OR winlog.channel like "System%"
  and (process.executable like "%\\nltest.exe" OR winlog.event_data.OriginalFileName = "nltestrk.exe")
  and (
    (process.commindex=* source="WinEventLog:*" and ((CommandLine="*DumpCreds*" or CommandLine="*mimikatz*") or (CommandLine="*::aadcookie*" or CommandLine="*::detours*" or CommandLine="*::memssp*" or CommandLine="*::mflt*" or CommandLine="*::ncroutemon*" or CommandLine="*::ngcsign*" or CommandLine="*::printnightmare*" or CommandLine="*::skeleton*" or CommandLine="*::preshutdown*" or CommandLine="*::mstsc*" or CommandLine="*::multirdp*") or (CommandLine="*rpc::*" or CommandLine="*token::*" or CommandLine="*crypto::*" or CommandLine="*dpapi::*" or CommandLine="*sekurlsa::*" or CommandLine="*kerberos::*" or CommandLine="*lsadump::*" or CommandLine="*privilege::*" or CommandLine="*process::*" or CommandLine="*vault::*"))and_line like "%/server%" and process.command_line like "%/query%")
    OR process.command_line like "%/dclist:%"
    OR process.command_line like "%/parentdomain%"
    OR process.command_line like "%/domain_trusts%"
    OR process.command_line like "%/all_trusts%"
    OR process.command_line like "%/trusted_domains%"
    OR process.command_line like "%/user%"
  )
| KEEP process.executable, user.name, process.command_line, process.parent.command_line
| RENAME process.executable AS Image, user.name AS User, process.command_line AS CommandLine, process.parent.command_line AS ParentCommandLine
```

### Port Proxy T1090
---

The actor has used the following commands to enable port forwarding [T1090] on the host: “cmd.exe /c “netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress= connectport=8443 protocol=tcp""


```sql
from win_logs*
| where winlog.channel like "Security%" OR winlog.channel like "System%"
  and (process.executable like "%\\cmd.exe" OR winlog.event_data.OriginalFileName = "cmd.exe")
  and (
    process.command_line like "%netsh %"
    and process.command_line like "%interface %"
    and process.command_line like "%portproxy %"
    and (
      process.command_line like "%add %"
      OR process.command_line like "%listenport %"
      OR process.command_line like "%connectaddress= %"
      OR process.command_line like "%connectport=1433%"
    )
  )
```

### Malicious VSCode Extension Activity Detection
---
```sql
-- Name: Malicious VSCode Extension Activity
-- Author: RW
-- Date: 2025-08-20
-- Description: This search combines multiple detection techniques for malicious Visual Studio Code extension activity. It looks for extension installation via URI handlers or the command line, suspicious network connections from VSCode, file writes to extension directories, and the loading of unusual Node modules. These activities can indicate an attacker using VSCode for initial access or persistence.

FROM logs-endpoint.events.*
| WHERE
  /* VSCode URI Handler Installation */
  (event.category == "process" AND event.action == "start" AND process.name ILIKE "Code.exe" AND process.command_line ILIKE "*--open-url*" AND process.command_line ILIKE "*vscode://*") OR
  /* VSCode Extension CLI Installation */
  (event.category == "process" AND event.action == "start" AND process.name ILIKE "Code.exe" AND process.command_line ILIKE "*--install-extension*" AND process.command_line ILIKE "*.vsix*") OR
  /* Suspicious Outbound Connection from VSCode */
  (event.category == "network" AND process.name ILIKE "Code.exe" AND url.full IS NOT NULL AND url.full NOT ILIKE "*marketplace.visualstudio.com*" AND url.full NOT ILIKE "*vscode.blob.core.windows.net*" AND url.full NOT ILIKE "*update.code.visualstudio.com*" AND url.full NOT ILIKE "*gallerycdn.vsassets.io*") OR
  /* File Write to VSCode Extension Directory */
  (event.category == "file" AND event.action == "creation" AND (file.path ILIKE "*\\.vscode\\extensions\\*" OR file.path ILIKE "*\\Microsoft VS Code\\resources\\app\\extensions\\*")) OR
  /* Suspicious Node Module Loaded by VSCode */
  (event.category == "library" AND event.action == "load" AND process.name ILIKE "Code.exe" AND dll.name ILIKE "*.node" AND (dll.path ILIKE "*\\AppData\\Local*" OR dll.path ILIKE "*\\Temp*") AND dll.path NOT ILIKE "*\\.vscode\\extensions*" AND dll.path NOT ILIKE "*Microsoft VS Code*")
| EVAL detection_method = CASE(
  process.command_line ILIKE "*--open-url*" AND process.command_line ILIKE "*vscode://*", "VSCode URI Handler Installation",
  process.command_line ILIKE "*--install-extension*" AND process.command_line ILIKE "*.vsix*", "VSCode Extension CLI Installation",
  process.name ILIKE "Code.exe" AND url.full IS NOT NULL, "Suspicious Outbound Connection from VSCode",
  file.path ILIKE "*extensions*", "File Write to VSCode Extension Directory",
  dll.name ILIKE "*.node" AND dll.path ILIKE "*\\AppData\\Local*" OR dll.path ILIKE "*\\Temp*", "Suspicious Node Module Loaded by VSCode",
  true, null
)
| WHERE detection_method IS NOT NULL
| EVAL details = CASE(
  detection_method == "VSCode URI Handler Installation", "URI Command: " + process.command_line,
  detection_method == "VSCode Extension CLI Installation", "Install Command: " + process.command_line,
  detection_method == "Suspicious Outbound Connection from VSCode", "Destination: " + url.full,
  detection_method == "File Write to VSCode Extension Directory", "File: " + file.path + file.name,
  detection_method == "Suspicious Node Module Loaded by VSCode", "Module: " + dll.path + dll.name,
  true, null
)
| EVAL timestamp = @timestamp, actor_process = COALESCE(process.command_line, url.full, file.path, dll.path), actor_process_name = COALESCE(process.name, file.name, dll.name), parent_process = COALESCE(process.parent.command_line, file.parent_path), user = user.name, dest = host.name
| KEEP timestamp, dest, user, parent_process, actor_process_name, actor_process, detection_method, details
| SORT timestamp DESC
| LIMIT 1000
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

FROM logs-network.*
| WHERE event.category == "web" AND (
  /* Salty 2FA Exfiltration */
  (http.request.method == "POST" AND destination.domain LIKE "*.ru" AND url.path LIKE "*/[0-9]{5,6}.php" AND http.request.body.content LIKE "*request=%" AND http.request.body.content LIKE "*session=%") OR
  /* Salty 2FA Landing Page */
  (destination.domain LIKE "*.[a-z]{2}.com" AND (
    (http.response.body.content LIKE "*challenges.cloudflare.com/turnstile/*" AND http.response.body.content LIKE "*Microsoft*" AND http.response.body.content LIKE "*Sign in*") OR
    (http.response.body.content LIKE "*new Date()*" AND http.response.body.content LIKE "*debugger*")
  ))
)
| EVAL detection_type = IF(http.request.method == "POST" AND destination.domain LIKE "%.ru", "Salty 2FA Exfiltration", "Salty 2FA Landing Page")
| KEEP @timestamp AS _time, user.name AS user, source.ip AS src, destination.domain AS dest, url.path AS uri_path, http.request.method AS http_method, http.request.body.content AS form_data, detection_type
| SORT _time DESC
| LIMIT 1000
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

FROM logs-endpoint.events.*,logs-network.*
| WHERE
  (process.name IN ("AddInProcess32.exe", "InstallUtil.exe", "aspnet_wp.exe")) OR
  (file.hash.sha256 IN ("011257eb766f253982b717b390fc36eb570473ed7805c18b101367c68af5", "0ea3a55141405ee0e2dfbf333de01fe93c12cf34555550e4f7bb3fdec2a7673b", ... /* list all hashes */)) OR
  (dns.question.name IN ("catherinereynolds.info", "mail.catherinereynolds.info")) OR
  (destination.ip IN ("157.66.22.11", "103.75.77.90", "161.248.178.212"))
| STATS count = COUNT(*), processes_observed = CONCAT_ARRAY(process.name), process_command_lines = CONCAT_ARRAY(process.command_line), parent_processes = CONCAT_ARRAY(process.parent.name), matched_hashes = CONCAT_ARRAY(file.hash.sha256), dns_queries = CONCAT_ARRAY(dns.question.name), destination_ips = CONCAT_ARRAY(destination.ip), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY host.name AS dest, user.name AS user
| EVAL detection_reason = CASE(
  matched_hashes IS NOT NULL, "IOC Match: Known QuirkyLoader file hash detected.",
  dns_queries IS NOT NULL OR destination_ips IS NOT NULL, "IOC Match: Network connection to QuirkyLoader C2 detected.",
  processes_observed IS NOT NULL, "TTP Match: Execution of a known QuirkyLoader process hollowing target.",
  true, null
)
| EVAL first_seen = TO_STRING(first_seen), last_seen = TO_STRING(last_seen)
| KEEP dest, user, detection_reason, processes_observed, parent_processes, process_command_lines, matched_hashes, dns_queries, destination_ips, first_seen, last_seen, count
| SORT count DESC
| LIMIT 1000
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

FROM logs-endpoint.events.*,logs-system.*
| WHERE
  (file.hash.sha256 IN ("dc54117b965674bad3d7cd203ecf5e7fc822423a3f692895cf5e96e83fb88f6a", "4843429e2e8871847bc1e97a0f12fa1f4166baa4735dff585cb3b4736e3fe49e", "297ea881aa2b39461997baf75d83b390f2c36a9a0a4815c81b5cf8be42840fd1")) OR
  (winlog.event_id == 17 AND winlog.event_data.PipeName LIKE "\\.\\pipe\\1\\.[0-9a-fA-F]{32}") OR
  (winlog.event_id == 3 AND (destination.domain == "aaaaabbbbbbb.eastus.cloudapp.azure.com" OR destination.ip == "127.0.0.1") AND destination.port IN (443, 8082)) OR
  (url.full LIKE "*.*/[a-fA-F0-9]{16}" AND http.request.headers LIKE "*Upgrade: websocket*" AND http.request.headers LIKE "*Connection: Upgrade*") OR
  (winlog.event_id == 1 AND process.name ILIKE "certutil.exe" AND process.command_line LIKE "*-urlcache*" AND process.command_line LIKE "*-f*" AND (process.command_line LIKE "%.tmp*" OR process.command_line LIKE "%.dat*" OR process.command_line LIKE "%.msbuild*")) OR
  (winlog.event_id == 1 AND process.parent.name ILIKE "msbuild.exe" AND process.command_line LIKE "%.mshi*") OR
  (winlog.event_id == 10 AND winlog.event_data.TargetImage LIKE "*\\lsass.exe" AND winlog.event_data.SourceImage LIKE "*\\dllhost.exe")
| EVAL timestamp = TO_STRING(@timestamp), detection_clause = CASE(
  file.hash.sha256 IN ("dc54117b965674bad3d7cd203ecf5e7fc822423a3f692895cf5e96e83fb88f6a", ...), "PipeMagic File Hash IOC",
  winlog.event_id == 17, "PipeMagic Named Pipe",
  winlog.event_id == 3, "PipeMagic C2 Connection",
  url.full LIKE "*.*/[a-fA-F0-9]{16}", "PipeMagic C2 HTTP Pattern",
  process.name ILIKE "certutil.exe", "PipeMagic Certutil Download",
  process.parent.name ILIKE "msbuild.exe", "PipeMagic MSBuild Execution",
  winlog.event_id == 10, "PipeMagic LSASS Access",
  true, "Unknown PipeMagic Activity"
)
| EVAL process_name = COALESCE(process.name, winlog.event_data.Image), parent_process_name = COALESCE(process.parent.name, winlog.event_data.ParentImage), command_line = process.command_line, file_hash = file.hash.sha256, dest_host = destination.domain, dest_ip = destination.ip, dest_port = destination.port, pipe_name = winlog.event_data.PipeName, source_image = winlog.event_data.SourceImage, target_image = winlog.event_data.TargetImage
| KEEP timestamp, detection_clause, host.name AS host, user.name AS user, process_name, parent_process_name, command_line, file_hash, dest_host, dest_ip, dest_port, pipe_name, source_image, target_image
| SORT timestamp DESC
| LIMIT 1000
```

### ESXi Host Suspicious Activity Detection (Recon, Privilege Escalation, Exfil, Evasion)
---
```sql
FROM logs-esxi.*
| WHERE message LIKE "*esxcli system*" AND (message LIKE "* get*" OR message LIKE "* list*") AND message NOT LIKE "*filesystem*" OR
  message LIKE "*root*logged in*" OR
  message LIKE "*esxcli system permission set*" AND message LIKE "*role Admin*" OR
  message LIKE "*esxcli software acceptance set*" OR
  message LIKE "*SSH access has been enabled*" OR
  message LIKE "*system settings encryption set*" AND (message LIKE "*--require-secure-boot=0*" OR message LIKE "*--require-exec-installed-only=0*" OR message LIKE "*execInstalledOnly=false*") OR
  message LIKE "*File download from path*" AND message LIKE "*was initiated from*" OR
  message LIKE "*esxcli system auditrecords*" OR
  message LIKE "*syslog config set*" AND message LIKE "*esxcli*" OR
  message LIKE "*Set called with key*" AND (message LIKE "*Syslog.global.logHost*" OR message LIKE "*Syslog.global.logdir*") OR
  message LIKE "*NTPClock*" AND message LIKE "*system clock stepped*"
| EVAL user = REGEX_STRING(message, "shell\\[\\d+\\]: \\[([^\\]]+)\\]:", 1), command = REGEX_STRING(message, "shell\\[\\d+\\]: \\[.+\\]: (.+)", 1), src_ip = REGEX_STRING(message, "root@(\\d{1,3}(?:\\.\\d{1,3}){3})", 1)
| EVAL tactic_description = CASE(
  message LIKE "*esxcli system* get*" OR message LIKE "*esxcli system* list*", "ESXi System Reconnaissance",
  message LIKE "*root*logged in*", "External Root Login to ESXi UI",
  message LIKE "*esxcli system permission set*role Admin*", "User Granted Admin Role on ESXi",
  message LIKE "*esxcli software acceptance set*", "VIB Acceptance Level Tampering",
  message LIKE "*SSH access has been enabled*", "SSH Enabled on ESXi Host",
  message LIKE "*system settings encryption set*", "ESXi Encryption Settings Modified",
  message LIKE "*File download from path*", "VM Exported via Remote Tool",
  message LIKE "*esxcli system auditrecords*", "ESXi Audit Tampering",
  message LIKE "*syslog config set*" OR message LIKE "*Syslog.global.logHost*" OR message LIKE "*Syslog.global.logdir*", "ESXi Syslog Tampering",
  message LIKE "*NTPClock*system clock stepped*", "ESXi System Clock Manipulation",
  true, "Unknown ESXi Activity"
), details = CASE(
  command IS NOT NULL, command,
  src_ip IS NOT NULL, "Login from " + src_ip,
  tactic_description == "SSH Enabled on ESXi Host", message,
  tactic_description == "ESXi Syslog Tampering", message,
  tactic_description == "ESXi System Clock Manipulation", message,
  true, message
)
| WHERE NOT (tactic_description == "External Root Login to ESXi UI" AND (src_ip LIKE "10.*" OR src_ip LIKE "172.16-31.*" OR src_ip LIKE "192.168.*" OR src_ip == "127.0.0.1" OR src_ip IS NULL))
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), activity_details = CONCAT_ARRAY(details), count = COUNT(*) BY host.name AS esxi_host, user, tactic_description
| EVAL firstTime = TO_STRING(firstTime), lastTime = TO_STRING(lastTime)
| KEEP esxi_host, user, firstTime, lastTime, activity_details, count, tactic_description
| SORT count DESC
| LIMIT 1000
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

FROM logs-endpoint.events.*,logs-network.*
| WHERE
  (file.hash.sha256 IN ("202f6b6631ade2c41e4762b5877ce0063a3beabce0c3f8564b6499a1164c1e04", /* list all */)) OR
  (destination.ip IN ("173.44.141.89", "80.77.23.48", "62.60.226.73", "107.158.128.45", "170.130.165.112", "107.158.128.105")) OR
  (url.full LIKE "*mhousecreative.com*" OR url.full LIKE "*google.herionhelpline.com*" OR url.full LIKE "*/service/*" OR url.full LIKE "*/c91252f9ab114f26.php") OR
  (http.request.user_agent LIKE "*Googlebot*" AND destination.ip IN ("173.44.141.89", "80.77.23.48", "62.60.226.73", "107.158.128.45")) OR
  (process.name == "schtasks.exe" AND process.command_line LIKE "*/create*" AND process.command_line LIKE "*/sc*" AND process.command_line LIKE "*onlogon*")
| STATS process = CONCAT_ARRAY(process.command_line), file_hash = CONCAT_ARRAY(file.hash.sha256), url = CONCAT_ARRAY(url.full), http_user_agent = CONCAT_ARRAY(http.request.user_agent) BY @timestamp AS _time, host.name AS dest, user.name AS user, process.name AS process_name, destination.ip AS dest_ip
| SORT _time DESC
| LIMIT 1000
```

### Quasar RAT Indicators: Process, File, and Network Activity
---
```sql
FROM logs-endpoint.events.*,logs-network.*
| WHERE
  (process.hash.sha256 == "7300535ef26158bdb916b717390fc36eb570473ed7805c18b101367c68af5") OR
  (process.name ILIKE "schtasks.exe" AND process.command_line LIKE "*/rl *" AND process.command_line LIKE "* highest *") OR
  (process.name ILIKE "shutdown.exe" AND (process.command_line LIKE "*/s /t 0*" OR process.command_line LIKE "*/r /t 0*")) OR
  (file.path IN ("*\\FileZilla\\recentservers.xml", "*\\FileZilla\\sitemanager.xml") AND process.name NOT IN ("filezilla.exe")) OR
  (file.path LIKE "*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*.url" AND event.action == "creation") OR
  (file.name LIKE "*:Zone.Identifier" AND event.action == "deletion") OR
  (dns.question.name IN ("*wtfismyip.com", "*checkip.*", "*ipecho.net", "*ipinfo.io", "*api.ipify.org", "*icanhazip.com", "*ip.anysrc.com","*api.ip.sb", "ident.me", "www.myexternalip.com", "*zen.spamhaus.org", "*cbl.abuseat.org", "*b.barracudacentral.org", "*dnsbl-1.uceprotect.net", "*spam.dnsbl.sorbs.net", "*iplogger.org*", "*ip-api.com*", "*geoip.*", "*icanhazip.*", "*ipwho.is*", "*ifconfig.me*", "*myip.com*", "*ipstack.com*", "*myexternalip.com*", "*ip-api.io*", "*trackip.net*", "*ipgeolocation.io*", "*ipfind.io*", "*freegeoip.app*", "*ipv4bot.whatismyipaddress.com*", "*hacker-target.com/iptools*"))
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), detection_rationale = CONCAT_ARRAY(CASE(
  process.command_line LIKE "*/rl * highest *", "Scheduled Task with Highest Privileges (T1055.005)",
  process.name ILIKE "shutdown.exe", "System Shutdown/Reboot Attempt (T1529)",
  process.hash.sha256 IS NOT NULL, "Known Quasar RAT Loader Hash",
  file.path LIKE "*FileZilla*", "Unusual FileZilla Config Access (T1552.001)",
  file.path LIKE "*Startup*.url", "Startup Folder URL Shortcut for Persistence (T1547.001)",
  file.name LIKE "*:Zone.Identifier", "Mark-of-the-Web Bypass (T1553.005)",
  dns.question.name IS NOT NULL, "Network Reconnaissance via IP Check Service (T1082)",
  true, null
)), details = CONCAT_ARRAY(COALESCE(process.command_line, file.path, dns.question.name)) BY host.name AS dest, user.name AS user, process.name, process.parent.name AS parent_process, process.pid AS process_id, process.parent.pid AS parent_process_id, event.category AS detection_type
| EVAL firstTime = TO_STRING(firstTime), lastTime = TO_STRING(lastTime)
| KEEP dest, user, firstTime, lastTime, detection_rationale, details
| SORT firstTime DESC
| LIMIT 1000
```

### Kerberoasting, AS-REP Roasting, DCSync, and AD DACL Modifications
---
```sql
FROM logs-winlogbeat.*
| WHERE winlog.channel == "Security" AND (
  /* Potential Kerberoasting (RC4) */
  (winlog.event_id == 4769 AND winlog.event_data.Status == "0x0" AND winlog.event_data.TicketEncryptionType == "0x17" AND winlog.event_data.ServiceName NOT LIKE "*$*") OR
  /* Potential AS-REP Roasting */
  (winlog.event_id == 4768 AND winlog.event_data.Status == "0x0" AND winlog.event_data.ServiceName == "krbtgt" AND winlog.event_data.PreAuthType == "0" AND winlog.event_data.TargetUserName NOT LIKE "*$*") OR
  /* Potential DCSync Attack */
  (winlog.event_id == 4662 AND winlog.event_data.ObjectServer == "DS" AND winlog.event_data.ObjectType == "{19195a5b-6da0-11d0-afd3-00c04fd930c9}" AND (winlog.event_data.Properties LIKE "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR winlog.event_data.Properties LIKE "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*") AND winlog.event_data.SubjectUserName NOT LIKE "*$*") OR
  /* AdminSDHolder DACL Modification */
  (winlog.event_id == 5136 AND winlog.event_data.LDAPDisplayName == "nTSecurityDescriptor" AND winlog.event_data.ObjectDN LIKE "*CN=AdminSDHolder,CN=System,*" AND winlog.event_data.SubjectUserSid != "S-1-5-18") OR
  /* Malicious AD DACL Modification */
  (winlog.event_id == 5136 AND winlog.event_data.LDAPDisplayName == "nTSecurityDescriptor" AND (winlog.event_data.Value LIKE "*(A;;GA;;*" OR winlog.event_data.Value LIKE "*(A;;WD;;*" OR winlog.event_data.Value LIKE "*(A;;WO;;*") AND winlog.event_data.SubjectUserSid != "S-1-5-18")
)
| EVAL rule_name = CASE(
  winlog.event_id == 5136 AND winlog.event_data.ObjectDN LIKE "*CN=AdminSDHolder,CN=System,*", "AdminSDHolder DACL Modification",
  winlog.event_id == 5136, "Malicious AD DACL Modification",
  winlog.event_id == 4769, "Potential Kerberoasting (RC4)",
  winlog.event_id == 4768, "Potential AS-REP Roasting",
  winlog.event_id == 4662, "Potential DCSync Attack",
  true, "Unknown"
), Target_Object = COALESCE(winlog.event_data.ServiceName, winlog.event_data.TargetUserName, winlog.event_data.ObjectName, winlog.event_data.ObjectDN)
| EVAL Description = CASE(
  rule_name == "AdminSDHolder DACL Modification", "Account " + winlog.event_data.SubjectUserName + " modified the DACL of the AdminSDHolder object.",
  rule_name == "Malicious AD DACL Modification", "Account " + winlog.event_data.SubjectUserName + " granted high-privilege rights on object: " + Target_Object,
  rule_name == "Potential Kerberoasting (RC4)", "Account " + winlog.event_data.SubjectUserName + " requested an RC4-encrypted service ticket for SPN: " + Target_Object,
  rule_name == "Potential AS-REP Roasting", "TGT requested for account " + Target_Object + " which has pre-authentication disabled.",
  rule_name == "Potential DCSync Attack", "Account " + winlog.event_data.SubjectUserName + " attempted a DCSync-style attack to replicate directory changes.",
  true, "N/A"
)
| KEEP @timestamp AS _time, host.name AS host, rule_name, winlog.event_data.SubjectUserName AS Subject_Account_Name, Target_Object, Description
| SORT _time DESC
| LIMIT 1000
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

FROM logs-azure.signinlogs.*,logs-azure.auditlogs.*,logs-office365.*,logs-endpoint.events.*,logs-vulnscan.*
| WHERE
  /* Anomalous Entra Connect Activity */
  (user.name LIKE "*AAD_*" OR user.name LIKE "*MSOL_*") AND event.category == "signin" OR
  (event.action == "Reset user password" AND event.outcome == "success" AND event.initiated_by.user.userPrincipalName LIKE "*AAD_*" OR event.initiated_by.user.userPrincipalName LIKE "*MSOL_*") OR
  /* Suspicious App/Service Principal creation */
  (event.category == "ApplicationManagement" AND (event.action == "Add service principal" OR event.action == "Add OAuth2 permission grant" OR event.action == "Add owner to service principal" OR event.action == "Update application - Certificates and secrets management")) OR
  /* Potential Cloud Data Exfiltration */
  (event.action IN ("MailItemsAccessed", "FileDownloaded")) OR
  /* Web Shell execution */
  (winlog.event_id == 1 AND process.parent.name IN ("*\\w3wp.exe", "*\\httpd.exe", "*\\nginx.exe", "*\\tomcat*.exe") AND process.name IN ("*\\cmd.exe", "*\\powershell.exe", "*\\pwsh.exe", "*\\sh", "*\\bash")) OR
  /* Known Vulnerabilities */
  (vulnerability.id IN ("CVE-2025-0282", "CVE-2024-3400", "CVE-2023-3519", "CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065"))
| EVAL activity = CASE(
  user.name LIKE "*AAD_*" OR user.name LIKE "*MSOL_*", "Suspicious Interactive Logon by Entra Connect Account",
  event.action == "Reset user password", "Password Reset by Entra Connect Account",
  event.category == "ApplicationManagement", event.action,
  event.action IN ("MailItemsAccessed", "FileDownloaded"), "Potential High-Volume Data Access",
  process.parent.name LIKE "*w3wp.exe*" OR process.parent.name LIKE "*httpd.exe*", "Potential Web Shell Execution",
  vulnerability.id IS NOT NULL, "Vulnerable Device Identified",
  true, null
), details = CASE(
  activity == "Suspicious Interactive Logon by Entra Connect Account", "User: " + user.name + " from IP: " + source.ip + " to App: " + event.app_display_name,
  activity == "Password Reset by Entra Connect Account", "Entra Connect account " + event.initiated_by.user.userPrincipalName + " reset password for " + event.targetResources.userPrincipalName,
  event.category == "ApplicationManagement", "User " + event.initiated_by.user.userPrincipalName + " performed action '" + activity + "' on application " + event.targetResources.displayName,
  event.action IN ("MailItemsAccessed", "FileDownloaded"), "User " + user.name + " accessed " + event.object_id_count + " items via " + event.action + " using AppId " + event.app_id,
  process.parent.name LIKE "*w3wp.exe*", "Parent: " + process.parent.executable + " spawned Child: " + process.executable + ". Command: " + process.command_line,
  vulnerability.id IS NOT NULL, "Device " + host.name + " is vulnerable to " + vulnerability.id + " (Plugin/Signature: " + vulnerability.signature,
  true, null
), src_ip = source.ip, dest = COALESCE(event.app_display_name, event.targetResources.displayName, event.app_id, host.name)
| STATS values(activity) AS activity, values(details) AS details BY @timestamp AS _time, activity, user.name AS user, src_ip, dest
| KEEP _time, activity, user, src_ip, dest, details
| SORT _time DESC
| LIMIT 1000
```

### CORNFLAKE.V3 Backdoor Activity Detection
---
```sql
-- RW

-- This rule is designed to detect a wide range of activities associated with the CORNFLAKE.V3 backdoor, as detailed in observed/disseminated threat intelligence.

-- It combines multiple detection patterns covering execution, persistence, command and control, and post-exploitation behavior into a single query.

FROM logs-winlogbeat.*
| WHERE winlog.channel == "Microsoft-Windows-Sysmon/Operational" AND (
  (winlog.event_id == 1 AND process.parent.executable LIKE "*\\powershell.exe" AND process.executable LIKE "*\\AppData\\Roaming*" AND ((process.executable LIKE "*\\node.exe" AND process.command_line LIKE "*-e *") OR (process.executable LIKE "*\\php.exe" AND process.command_line LIKE "*-d *" AND process.command_line LIKE "* 1"))) OR
  (winlog.event_id == 1 AND process.parent.executable LIKE "*\\AppData\\Roaming\\*(node|php).exe" AND process.executable LIKE "*\\(cmd|powershell).exe" AND process.command_line LIKE "*systeminfo*" OR process.command_line LIKE "*tasklist*" OR process.command_line LIKE "*arp -a*" OR process.command_line LIKE "*nltest*" OR process.command_line LIKE "*setspn*" OR process.command_line LIKE "*whoami /all*" OR process.command_line LIKE "*Get-LocalGroup*" OR process.command_line LIKE "*KerberosRequestorSecurityToken*") OR
  (winlog.event_id IN (12, 13) AND winlog.event_data.TargetObject LIKE "*HKU*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" AND winlog.event_data.Details LIKE "*AppData\\Roaming\\*(node|php).exe*") OR
  (winlog.event_id == 3 AND (destination.ip IN ("138.199.161.141", "159.69.3.151", "167.235.235.151", "128.140.120.188", "177.136.225.135") OR destination.domain IN ("varying-rentals-calgary-predict.trycloudflare.com", "dnsmicrosoftds-data.com", "windows-msg-as.live"))) OR
  (winlog.event_id IN (1, 11) AND winlog.event_data.Hashes LIKE "*MD5=(04668c6f39b0a67c4bd73d5459f8c3a3,bcdffa955608e9463f272adca205c9e65592840d98dcb63155b9fa0324a88be2,ec82216a2b42114d23d59eecb876ccfc)*") OR
  (winlog.event_id == 3 AND process.executable IN ("*\\powershell.exe", "*\\mshta.exe") AND destination.domain IN ("nodejs.org", "windows.php.net")) OR
  (winlog.event_id == 1 AND process.executable LIKE "*\\rundll32.exe" AND process.command_line LIKE "*\\AppData\\Roaming\\*.png*")
)
| EVAL detection_reason = CASE(
  process.parent.executable LIKE "*powershell.exe" AND process.executable LIKE "*AppData\\Roaming*", "Execution: CORNFLAKE.V3 (Node.js/PHP) spawned from PowerShell",
  process.parent.executable LIKE "*AppData\\Roaming\\*(node|php).exe" AND process.executable LIKE "*\\(cmd|powershell).exe", "Post-Exploitation: CORNFLAKE process spawning shell for reconnaissance",
  winlog.event_id IN (12, 13), "Persistence: Registry Run Key points to CORNFLAKE in AppData",
  winlog.event_id == 3 AND destination.ip IS NOT NULL OR destination.domain IS NOT NULL, "C2: Network connection to known CORNFLAKE infrastructure",
  winlog.event_data.Hashes LIKE "*MD5=*", "IOC: Known CORNFLAKE or WINDYTWIST file hash detected",
  process.executable IN ("*powershell.exe", "*mshta.exe") AND destination.domain IN ("nodejs.org", "windows.php.net"), "Initial Access: PowerShell/MSHTA downloading Node.js/PHP runtime",
  process.executable LIKE "*rundll32.exe" AND process.command_line LIKE "*AppData\\Roaming\\*.png*", "Execution: Rundll32 executing a .png file from AppData (WINDYTWIST.SEA)",
  true, null
)
| WHERE detection_reason IS NOT NULL
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), detection_reasons = CONCAT_ARRAY(detection_reason), parent_process = CONCAT_ARRAY(process.parent.executable), process = CONCAT_ARRAY(process.executable), command_line = CONCAT_ARRAY(process.command_line), registry_path = CONCAT_ARRAY(winlog.event_data.TargetObject), registry_details = CONCAT_ARRAY(winlog.event_data.Details), dest_ip = CONCAT_ARRAY(destination.ip), dest_hostname = CONCAT_ARRAY(destination.domain), file_hashes = CONCAT_ARRAY(winlog.event_data.Hashes) BY host.name AS host, user.name AS user
| EVAL firstTime = TO_STRING(firstTime), lastTime = TO_STRING(lastTime)
| KEEP host, user, firstTime, lastTime, detection_reasons, parent_process, process, command_line, registry_path, registry_details, dest_ip, dest_hostname, file_hashes, count
| SORT count DESC
| LIMIT 1000
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

FROM logs-authentication.*,logs-web.*,logs-dns.*,logs-endpoint.events.*,logs-vulnscan.*
| WHERE
  /* Impossible Travel */
  (event.category == "authentication" AND event.outcome == "success") OR
  /* Phishing Link Click */
  (event.category == "web" AND vulnerability.category IN ("Phishing & Fraud", "Malware")) OR
  /* Suspicious TLD Visited */
  (url.domain LIKE "*.(xyz|top|online|club|live|icu|gq|buzz)") OR
  /* Suspicious Process Execution */
  (process.name IN ("powershell.exe", "pwsh.exe") AND process.command_line LIKE "* -enc *" OR process.command_line LIKE "* -encoded *" OR process.command_line LIKE "* -w hidden *" OR process.command_line LIKE "* IEX *" OR process.command_line LIKE "* Invoke-Expression *") OR
  (process.name == "mshta.exe" AND process.command_line LIKE "*http:*" OR process.command_line LIKE "*https:*" OR process.command_line LIKE "*javascript:*") OR
  /* New Service Created */
  (winlog.event_id == 4697) OR
  /* New Scheduled Task Created */
  (winlog.event_id == 106 AND winlog.channel == "Microsoft-Windows-TaskScheduler/Operational") OR
  /* Cryptocurrency Site Visited */
  (url.full LIKE "*binance.com*" OR url.full LIKE "*coinbase.com*" OR url.full LIKE "*kraken.com*" OR url.full LIKE "*kucoin.com*" OR url.full LIKE "*bybit.com*" OR url.full LIKE "*metamask.io*")
| EVAL detection_type = CASE(
  event.category == "authentication", "Impossible Travel - Multi-Geo Login",
  vulnerability.category IN ("Phishing & Fraud", "Malware"), "Phishing Link Click",
  url.domain LIKE "*.(xyz|top|online|club|live|icu|gq|buzz)", "Suspicious TLD Visited",
  process.name IN ("powershell.exe", "pwsh.exe") OR process.name == "mshta.exe", "Suspicious Process Execution",
  winlog.event_id == 4697, "New Service Created",
  winlog.event_id == 106, "New Scheduled Task Created",
  url.full LIKE "*binance.com*", "Cryptocurrency Site Visited",
  true, null
), description = CASE(
  detection_type == "Impossible Travel - Multi-Geo Login", user.name + " logged in from " + geo.country_name_count + " countries: " + CONCAT(geo.country_name, ", ") + " within 4 hours.",
  detection_type == "Phishing Link Click", user.name + " accessed a URL categorized as phishing/malware: " + url.full,
  detection_type == "Suspicious TLD Visited", user.name + " visited a URL with a suspicious TLD: " + url.full,
  detection_type == "Suspicious Process Execution", user.name + " executed a suspicious command on " + host.name + ": " + process.command_line,
  detection_type == "New Service Created", "A new service '" + winlog.event_data.ServiceName + "' pointing to '" + winlog.event_data.ServiceFileName + "' was created on " + host.name + " by " + user.name,
  detection_type == "New Scheduled Task Created", "A new scheduled task '" + REGEX_STRING(winlog.event_data.Message, "Task Scheduler registered task \"([^\"]+)\"", 1) + "' was created on " + host.name + " by " + user.name,
  detection_type == "Cryptocurrency Site Visited", user.name + " accessed a cryptocurrency-related website: " + url.full,
  true, null
)
| STATS country_count = COUNT_DISTINCT(geo.country_name), countries = CONCAT_ARRAY(geo.country_name) BY @timestamp AS _time, user.name AS user, detection_type span=4h
| WHERE country_count > 1 OR detection_type != "Impossible Travel - Multi-Geo Login"
| KEEP _time, detection_type, user, countries, description
| SORT _time DESC
| LIMIT 1000
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

FROM logs-endpoint.events.*
| WHERE
  /* Known malicious file hashes */
  (event.category == "process" AND event.action == "start" AND process.hash.sha256 IN ("c865f24e4b9b0855b8b559fc3769239b0aa6e8d680406616a13d9a36fbbc2d30", "7d0c9855167e7c19a67f800892e974c4387e1004b40efb25a2a1d25a99b03a10", "b3e93bfef12678294d9944e61d90ca4aa03b7e3dae5e909c3b2166f122a14dad", "da59d67ced88beae618b9d6c805f40385d0301d412b787e9f9c9559d00d2c880", "70ec2e65f77a940fd0b2b5c0a78a83646dec175836552622ad17fb974f1", "263ab8c9ec821ae573979ef2d5ad98cda5009a39e17398cd31b0fad98d862892")) OR
  /* Known C2 network indicators */
  (event.category == "network" AND (destination.ip IN ("185.156.72.80", "94.141.12.182") OR destination.domain == "eaglekl.digital")) OR
  /* ntdll.dll unhooking via process access */
  (winlog.event_id == 10 AND winlog.event_data.TargetImage LIKE "*\\ntdll.dll") OR
  /* Suspicious preloading of modules */
  (event.category == "library" AND event.action == "load" AND dll.name IN ("wininet.dll", "crypt32.dll", "advapi32.dll", "urlmon.dll"))
| STATS module_count = COUNT_DISTINCT(dll.name), loaded_modules = CONCAT_ARRAY(dll.name) BY @timestamp AS _time, host.name AS host, user.name AS user, process.executable AS process_path, dll.path AS dll_path, process.command_line AS command_line, process.pid AS process_id, process.parent.pid AS parent_process_id GROUP BY process_id WHERE module_count >= 3 OR module_count IS NULL
| EVAL DetectionMethod = CASE(
  process.hash.sha256 IS NOT NULL, "Known SHELLTER-related hash",
  destination.ip IS NOT NULL OR destination.domain IS NOT NULL, "Known SHELLTER-related C2",
  winlog.event_id == 10, "Behavioral - NTDLL Remapping for Hook Evasion",
  module_count >= 3, "Behavioral - Suspicious Module Preloading",
  true, null
), Tactic = CASE(
  DetectionMethod LIKE "Known SHELLTER-related hash", "Execution",
  DetectionMethod LIKE "Known SHELLTER-related C2", "Command and Control",
  DetectionMethod LIKE "Behavioral - NTDLL Remapping*", "Defense Evasion",
  DetectionMethod LIKE "Behavioral - Suspicious Module Preloading", "Defense Evasion",
  true, null
), Technique = CASE(
  Tactic == "Execution", "T1204",
  Tactic == "Command and Control", "T1071",
  Tactic == "Defense Evasion", "T1055",
  true, null
), process_name = SUBSTRING(process_path, LAST_INDEX(process_path, "\\") + 1)
| KEEP _time, host, user, process_name, process_path, command_line, process.hash.sha256 AS process_hash, destination.ip AS dest_ip, destination.domain AS dest_domain, winlog.event_data.TargetImage AS target_path, loaded_modules, module_count, DetectionMethod, Tactic, Technique
| SORT _time DESC
| LIMIT 1000
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

FROM logs-endpoint.events.*,logs-network.*,logs-registry.*
| WHERE
  /* Known Interlock hashes */
  (process.hash.sha256 IN ("2acaa9856ee29337c06cc2858fd71b860f53219504e6756faa3812019b5df5a6", "0b47e53f2ada0555588aa8a6a4491e14d7b2528c9a829ebb6f7e9463963cd0e4", /* list all */)) OR
  /* Suspicious PowerShell execution patterns */
  (process.name == "powershell.exe" AND (process.command_line LIKE "*irm *" OR process.command_line LIKE "*iex *" OR process.command_line LIKE "*Invoke-RestMethod*" OR process.command_line LIKE "*Invoke-Expression*" OR process.command_line LIKE "*-w h*" OR process.command_line LIKE "*-windowstyle hidden*")) OR
  /* Persistence via known Interlock Registry Run Keys */
  (registry.path LIKE "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*" AND registry.value IN ("ChromeUpdater", "0neDrive")) OR
  /* C2 communication to known infrastructure or abused services */
  (destination.ip IN ("168.119.96.41", "95.217.22.175", /* list all */) OR destination.domain IN ("cluders.org", "bronxy.cc", /* list all */) OR destination.domain LIKE "*trycloudflare.com*") OR
  /* Scheduled task creation for persistence */
  (process.name == "schtasks.exe" AND process.command_line LIKE "*/create*" AND (process.command_line LIKE "*/du 9999:59*" OR (process.command_line LIKE "*BitLocker Encrypt All Drives*" AND process.command_line LIKE "*\\OneDriveCloud\\taskhostw.exe*")))
| EVAL Tactic = CASE(
  process.hash.sha256 IS NOT NULL, "Execution",
  process.name == "powershell.exe", "Execution",
  registry.path LIKE "*Run*", "Persistence",
  destination.ip IS NOT NULL OR destination.domain IS NOT NULL, "Command and Control",
  process.name == "schtasks.exe", "Persistence",
  true, null
), Technique = CASE(
  Tactic == "Execution" AND process.hash.sha256 IS NOT NULL, "T1204.002",
  Tactic == "Execution" AND process.name == "powershell.exe", "T1059.001",
  Tactic == "Persistence" AND registry.path LIKE "*Run*", "T1547.001",
  Tactic == "Command and Control", "T1071.001",
  Tactic == "Persistence" AND process.name == "schtasks.exe", "T1053.005",
  true, null
), DetectionMethod = CASE(
  process.hash.sha256 IS NOT NULL, "Known Malicious Hash",
  process.name == "powershell.exe", "Suspicious PowerShell Command",
  registry.path LIKE "*Run*", "Registry Run Key Modification",
  destination.ip IS NOT NULL OR destination.domain IS NOT NULL, "C2 Communication",
  process.name == "schtasks.exe", "Scheduled Task Creation",
  true, null
)
| KEEP @timestamp AS firstTime, host.name AS DeviceName, user.name AS user, Tactic, Technique, DetectionMethod, process.name AS FileName, process.command_line AS ProcessCommandLine, process.parent.name AS InitiatingProcess, process.hash.sha256 AS SHA256, registry.path AS RegistryKey, registry.value AS RegistryValueName, registry.data.strings AS RegistryValueData, source.ip AS SourceIP, destination.ip AS DestinationIP, destination.domain AS DestinationHost
| SORT firstTime DESC
| LIMIT 1000
```

### Water Curse Threat Actor - Multi-Stage
---
```sql
-- This detection rule identifies multiple Tactics, Techniques, and Procedures (TTPs) associated with the Water Curse threat actor.
-- Water Curse leverages compromised GitHub repositories to distribute malware, targeting developers and cybersecurity professionals.
-- This rule detects the entire attack chain, from initial execution via malicious Visual Studio project files to defense evasion, persistence, and C2 communication.
-- Source: https://www.trendmicro.com/en_us/research/25/f/water-curse.html
-- RW

FROM logs-endpoint.events.*,logs-network.*,logs-registry.*
| WHERE
  /* Initial execution via malicious Visual Studio project file */
  (process.parent.name == "MSBuild.exe" AND process.name == "cmd.exe" AND process.command_line LIKE "*/c*" AND process.command_line LIKE "*.exec.cmd*" AND process.command_line LIKE "*Temp\\MSBuildTemp*") OR
  /* Defense Evasion via PowerShell to disable Windows Defender and System Restore */
  (process.name == "powershell.exe" AND (process.command_line LIKE "*Set-MpPreference* -ExclusionPath*C:\\*" OR process.command_line LIKE "*vssadmin*delete*shadows*/all*" OR process.command_line LIKE "*Set-ItemProperty*HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore*DisableSR*")) OR
  /* UAC Bypass via ms-settings protocol handler hijack */
  (registry.path LIKE "*\\Software\\Classes\\ms-settings\\shell\\open\\command*" AND (registry.value == "(Default)" OR registry.value == "DelegateExecute")) OR
  /* Persistence via unusually configured Scheduled Task */
  (process.name == "schtasks.exe" AND process.command_line LIKE "*/create*" AND (process.command_line LIKE "*/du 9999:59*" OR (process.command_line LIKE "*BitLocker Encrypt All Drives*" AND process.command_line LIKE "*\\OneDriveCloud\\taskhostw.exe*"))) OR
  /* Data Staging and Reconnaissance */
  (process.name == "7z.exe" AND process.executable LIKE "C:\\ProgramData\\sevenZip\\*" AND process.command_line LIKE "*-p*") OR
  (process.parent.name == "NVIDIA Control Panel.exe" AND process.parent.executable LIKE "*\\Microsoft\\Vault\\UserRoamingTiles\\NVIDIAContainer*" AND process.name IN ("curl.exe", "wmic.exe", "tasklist.exe")) OR
  /* Malicious File Artifacts Creation */
  (file.path LIKE "*\\.vs-script\\*" AND file.name IN ("antiDebug.ps1", "disabledefender.ps1")) OR
  (file.path LIKE "*\\AppData\\Local\\Temp\\*" AND file.name == "SearchFilter.exe") OR
  (file.path LIKE "*\\Microsoft\\Vault\\UserRoamingTiles\\NVIDIAContainer*" AND file.name == "NVIDIA Control Panel.exe") OR
  /* C2 and Exfiltration Network Activity */
  (url.full IN ("*store-eu-par-2.gofile.io*", "*api.telegram.org*", "*popcorn-soft.glitch.me*", "*pastejustit.com*", "*pastesio.com*") OR destination.ip == "46.101.236.176" OR process.name == "RegAsm.exe")
| EVAL Tactic = CASE(
  process.parent.name == "MSBuild.exe", "Execution",
  process.name == "powershell.exe" AND process.command_line LIKE "*Set-MpPreference*", "Defense Evasion",
  registry.path LIKE "*ms-settings*", "Privilege Escalation",
  process.name == "schtasks.exe", "Persistence",
  process.name == "7z.exe" OR process.parent.name == "NVIDIA Control Panel.exe", "Collection",
  file.path LIKE "*\\.vs-script\\*", "Initial Access",
  url.full LIKE "*gofile.io*", "Command and Control",
  true, null
), Technique = CASE(
  Tactic == "Execution", "T1129",
  Tactic == "Defense Evasion", "T1562.001",
  Tactic == "Privilege Escalation", "T1548.002",
  Tactic == "Persistence", "T1053.005",
  Tactic == "Collection", "T1560",
  Tactic == "Initial Access", "T1195.002",
  Tactic == "Command and Control", "T1071",
  true, null
), Activity = CASE(
  process.parent.name == "MSBuild.exe", "WaterCurse: Initial Execution via MSBuild",
  process.name == "powershell.exe" AND process.command_line LIKE "*Set-MpPreference*", "WaterCurse: Defense Evasion via PowerShell",
  registry.path LIKE "*ms-settings*", "WaterCurse: UAC Bypass via ms-settings Hijack",
  process.name == "schtasks.exe", "WaterCurse: Persistence via Scheduled Task",
  process.name == "7z.exe", "WaterCurse: Staging and Reconnaissance",
  file.path LIKE "*\\.vs-script\\*", "WaterCurse: Malicious File Artifact Creation",
  url.full LIKE "*gofile.io*", "WaterCurse: C2/Exfiltration Network Connection",
  true, null
)
| KEEP @timestamp AS firstTime, host.name AS dest, user.name AS user, Tactic, Technique, Activity, process.parent.name AS parent_process_name, process.name AS process_name, process.command_line AS process, file.path AS file_path, file.name AS file_name, registry.path AS registry_path, registry.value AS registry_value_name, url.full AS url, destination.ip AS dest_ip
| SORT firstTime DESC
| LIMIT 1000
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

FROM logs-winlogbeat.*
| WHERE winlog.channel == "Microsoft-Windows-Sysmon/Operational" AND (winlog.event_id == 1 OR winlog.event_id == 11) AND (
  /* PPL Loader launching ClipUp */
  (winlog.event_id == 1 AND process.parent.executable LIKE "*\\CreateProcessAsPPL.exe" AND process.executable LIKE "*\\clipup.exe") OR
  /* Anomalous ClipUp Execution for File Write */
  (winlog.event_id == 1 AND process.executable LIKE "*\\System32\\clipup.exe" AND process.command_line LIKE "*-ppl*" AND (process.command_line LIKE "*\\ProgramData\\Microsoft\\Windows Defender\\*" OR process.command_line LIKE "*\\Program Files\\Windows Defender\\*" OR process.command_line LIKE "*\\Program Files (x86)\\Windows Defender\\*" OR process.command_line LIKE "*-ppl *PROGRA~*")) OR
  /* Suspicious Auto-Start Service Creation */
  (winlog.event_id == 1 AND process.executable LIKE "*\\sc.exe" AND process.command_line LIKE "*create*" AND process.command_line LIKE "*start=auto*" AND (process.command_line LIKE "*binPath=*CreateProcessAsPPL.exe*" OR process.command_line LIKE "*binPath=*\\Users\\*" OR process.command_line LIKE "*binPath=*\\ProgramData\\*" OR process.command_line LIKE "*binPath=*\\Windows\\Temp\\*" OR process.command_line LIKE "*binPath=*\\Temp\\*" OR process.command_line LIKE "*binPath=.*(cmd|powershell|pwsh).exe*")) OR
  /* Unauthorized Defender Directory File Modification */
  (winlog.event_id == 11 AND (file.path LIKE "C:\\ProgramData\\Microsoft\\Windows Defender\\*" OR file.path LIKE "C:\\Program Files\\Windows Defender\\*" OR file.path LIKE "C:\\Program Files (x86)\\Windows Defender\\*") AND process.executable NOT IN ("*\\MsMpEng.exe", "*\\NisSrv.exe", "*\\MsMpEngCP.exe", "*\\MpCmdRun.exe", "*\\TiWorker.exe", "*\\TrustedInstaller.exe", "*\\svchost.exe", "*\\setup.exe"))
)
| EVAL technique = CASE(
  process.parent.executable LIKE "*CreateProcessAsPPL.exe" AND process.executable LIKE "*clipup.exe", "PPL Loader launching ClipUp",
  process.executable LIKE "*clipup.exe" AND process.command_line LIKE "*-ppl*", "Anomalous ClipUp Execution for File Write",
  process.executable LIKE "*sc.exe" AND process.command_line LIKE "*create*", "Suspicious Auto-Start Service Creation",
  winlog.event_id == 11, "Unauthorized Defender Directory File Modification",
  true, null
)
| KEEP @timestamp AS _time, host.name AS Computer, user.name AS User, technique, process.parent.executable AS ParentImage, process.executable AS Image, process.command_line AS CommandLine, file.path AS TargetFilename
| SORT _time DESC
| LIMIT 1000
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

FROM logs-endpoint.events.*
| WHERE event.category == "process" AND event.action == "start" AND process.executable IS NOT NULL AND process.command_line IS NOT NULL
| EVAL CommandLineExecutable = REGEX_STRING(process.command_line, '^(?:"(.*?)("|\\s)|(\\S+))', 1), CommandLineExecutable = TRIM(CommandLineExecutable, '"')
| EVAL CommandLineFileName = SUBSTRING(CommandLineExecutable, LAST_INDEX(CommandLineExecutable, "\\") + 1)
| WHERE LOWER(process.executable) != LOWER(CommandLineExecutable) AND LOWER(process.name) == LOWER(CommandLineFileName) AND
  process.parent.name NOT IN ("services.exe", "svchost.exe", "WmiPrvSE.exe", "msiexec.exe", "TiWorker.exe") AND
  process.executable NOT REGEX "*?(?i)C:\\Windows\\(System32|SysWOW64|servicing)|C:\\Program Files|AppData\\Local\\Temp|\\Windows\\Temp*"
| KEEP @timestamp AS _time, host.name AS DeviceName, user.name AS AccountName, process.name AS FileName, process.executable AS FolderPath, process.command_line AS ProcessCommandLine, CommandLineExecutable, process.parent.name AS InitiatingProcessFileName
| SORT _time DESC
| LIMIT 1000
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

FROM logs-endpoint.events.*
| WHERE (event.category == "process" AND event.action == "start" AND LENGTH(process.executable) > 260) OR
  (event.category == "library" AND event.action == "load" AND LENGTH(dll.path) > 260) OR
  (event.category == "file" AND event.action == "creation" AND LENGTH(file.path) > 260)
| EVAL EventType = CASE(
  event.category == "process", "Process Creation with Long Path",
  event.category == "library", "Module Load from Long Path",
  event.category == "file", "File Creation with Long Path",
  true, null
)
| KEEP @timestamp AS _time, host.name AS dest, user.name AS user, EventType, process.command_line AS process, process.parent.executable AS parent_process, process.executable AS process_path, file.path AS FilePath
| SORT _time DESC
| LIMIT 1000
```

### Suspicious SQL Server Activity
---
```sql
-- Name: Suspicious SQL Server Activity
-- Author: RW
-- Date: 2025-08-23
-- Description: Detects a variety of suspicious activities related to Microsoft SQL Server that could indicate reconnaissance, execution, or persistence. This includes enabling high-risk procedures, sqlservr.exe spawning shells, suspicious use of sqlcmd or Invoke-Sqlcmd, loading of untrusted CLR assemblies, and execution of suspicious startup procedures.
-- MITRE ATT&CK: T1543.003, T1059.001, T1059.003, T1059.006, T1003, T1041

FROM logs-winlogbeat.*,logs-endpoint.events.*
| WHERE (
  /* High-Risk SQL Procedure Enabled */
  (winlog.event_id == 15457 AND winlog.event_data.Data1 IN ("xp_cmdshell", "Ole Automation Procedures") AND winlog.event_data.Data2 == "1") OR
  /* SQL CLR Enabled */
  (winlog.event_id == 15457 AND winlog.event_data.Data1 == "clr enabled" AND winlog.event_data.Data2 == "1") OR
  /* SQL CLR Strict Security Disabled */
  (winlog.event_id == 15457 AND winlog.event_data.Data1 == "clr strict security" AND winlog.event_data.Data2 == "0") OR
  /* Suspicious SQL Startup Procedure */
  (winlog.event_id == 17135 AND (winlog.event_data.Data1 LIKE "*xp_*" OR winlog.event_data.Data1 LIKE "*sp_*" OR winlog.event_data.Data1 LIKE "*cmdshell*" OR winlog.event_data.Data1 LIKE "*shell*" OR winlog.event_data.Data1 LIKE "*exec*")) OR
  /* SQL Server Spawning Shell */
  (process.parent.name == "sqlservr.exe" AND process.name IN ("cmd.exe", "powershell.exe")) OR
  /* Suspicious sqlcmd.exe Usage */
  (process.name == "sqlcmd.exe" AND (process.command_line LIKE "*xp_cmdshell*" OR process.command_line LIKE "*sp_oacreate*" OR process.command_line LIKE "*sp_add_trusted_assembly*" OR process.command_line LIKE "*sp_configure*" OR process.command_line LIKE "*OPENROWSET*" OR process.command_line LIKE "*-o *" OR process.command_line LIKE "*--outputfile*" OR process.command_line LIKE "*http*//*" OR process.command_line LIKE "*-t 0*" OR process.command_line LIKE "*--query_timeout=0*")) OR
  /* Potential SQL CLR Assembly Loaded */
  (event.action == "creation" AND file.name LIKE "*.dll" AND file.path LIKE "*\\Microsoft SQL Server\\*\\MSSQL\\Binn\\*") OR
  /* Suspicious Invoke-Sqlcmd Usage */
  (winlog.event_id == 4104 AND winlog.event_data.ScriptBlockText LIKE "*Invoke-Sqlcmd*" AND (winlog.event_data.ScriptBlockText LIKE "*xp_cmdshell*" OR winlog.event_data.ScriptBlockText LIKE "*sp_oacreate*" OR winlog.event_data.ScriptBlockText LIKE "*sp_add_trusted_assembly*" OR winlog.event_data.ScriptBlockText LIKE "*sp_configure*" OR winlog.event_data.ScriptBlockText LIKE "*OPENROWSET*" OR winlog.event_data.ScriptBlockText LIKE "*-QueryTimeout 0*"))
)
| EVAL rule_name = CASE(
  winlog.event_id == 15457 AND winlog.event_data.Data1 IN ("xp_cmdshell", "Ole Automation Procedures"), "High-Risk SQL Procedure Enabled",
  winlog.event_id == 15457 AND winlog.event_data.Data1 == "clr enabled", "SQL CLR Enabled",
  winlog.event_id == 15457 AND winlog.event_data.Data1 == "clr strict security", "SQL CLR Strict Security Disabled",
  winlog.event_id == 17135, "Suspicious SQL Startup Procedure",
  process.parent.name == "sqlservr.exe", "SQL Server Spawning Shell",
  process.name == "sqlcmd.exe", "Suspicious sqlcmd.exe Usage",
  file.name LIKE "*.dll" AND file.path LIKE "*MSSQL\\Binn\\*", "Potential SQL CLR Assembly Loaded",
  winlog.event_id == 4104, "Suspicious Invoke-Sqlcmd Usage",
  true, null
), details = CASE(
  winlog.event_id == 15457, "Config: " + winlog.event_data.Data1 + ", Old Value: " + winlog.event_data.Data3 + ", New Value: " + winlog.event_data.Data2,
  winlog.event_id == 17135, "Procedure: " + winlog.event_data.Data1,
  process.parent.name == "sqlservr.exe", process.name + " spawned by sqlservr.exe.",
  process.name == "sqlcmd.exe", "sqlcmd.exe executed with suspicious arguments.",
  file.name LIKE "*.dll", "DLL " + file.name + " created in " + file.path,
  winlog.event_id == 4104, "PowerShell Invoke-Sqlcmd used with suspicious arguments.",
  true, null
), user = "N/A (From Event Log)", command = COALESCE(process.command_line, winlog.event_data.ScriptBlockText, details), parent_process = "sqlservr.exe"
| KEEP @timestamp AS _time, host.name AS dest, user.name AS user, rule_name, details, command, parent_process
| SORT _time DESC
| LIMIT 1000
```

### SQL Injection (SQLi) Attempts
---
```sql
-- Name: Combined SQL Injection (SQLi) Detection
-- Author: RW
-- Date: 2025-08-23

-- This rule combines multiple SQLi detection techniques into a single query.
-- It identifies general attempts, error-based, time-based, database reconnaissance, and authentication bypass attacks.

FROM logs-iis.*,logs-apache.*,logs-paloalto.*,logs-aws.waf.*,logs-azuresql.*,logs-ms_aad.*,logs-azurediagnostics.*
| WHERE (
  /* Auth Bypass */
  (event.outcome IN ("0", "success", "allow", "accepted") AND (user.name LIKE "*' or *" OR user.name LIKE "*'or'--*" OR user.name LIKE "* or 1=1*" OR user.name LIKE "*admin'--*")) OR
  /* Time-Based Blind */
  (http.response.time_taken > 5 AND (url.full LIKE "*sleep(*)*" OR url.full LIKE "*waitfor delay*" OR url.full LIKE "*benchmark(*)*" OR url.full LIKE "*pg_sleep(*)*")) OR
  /* Error-Based */
  (http.response.body.content LIKE "*error in your sql syntax*" OR http.response.body.content LIKE "*unclosed quotation mark*" OR http.response.body.content LIKE "*ora-[0-9][0-9][0-9][0-9][0-9]*" OR http.response.body.content LIKE "*invalid column name*") OR
  /* DB Recon */
  (sql.query IS NOT NULL AND (sql.query LIKE "*information_schema*" OR sql.query LIKE "*sys.objects*" OR sql.query LIKE "*pg_catalog*" OR sql.query LIKE "*sqlite_master*")) OR
  /* General Attempt */
  (url.full LIKE "*' or *" OR url.full LIKE "* union *select *" OR url.full LIKE "*--*" OR url.full LIKE "*/*%*" OR url.full LIKE "*';*")
)
| EVAL detection_type = CASE(
  event.outcome IN ("0", "success", "allow", "accepted") AND (user.name LIKE "*' or *" OR user.name LIKE "*'or'--*" OR user.name LIKE "* or 1=1*" OR user.name LIKE "*admin'--*"), "SQLi Authentication Bypass",
  http.response.time_taken > 5 AND (url.full LIKE "*sleep(*)*" OR url.full LIKE "*waitfor delay*" OR url.full LIKE "*benchmark(*)*" OR url.full LIKE "*pg_sleep(*)*"), "Time-Based Blind SQLi",
  http.response.body.content LIKE "*error in your sql syntax*" OR http.response.body.content LIKE "*unclosed quotation mark*" OR http.response.body.content LIKE "*ora-[0-9][0-9][0-9][0-9][0-9]*" OR http.response.body.content LIKE "*invalid column name*", "Error-Based SQLi",
  sql.query IS NOT NULL AND (sql.query LIKE "*information_schema*" OR sql.query LIKE "*sys.objects*" OR sql.query LIKE "*pg_catalog*" OR sql.query LIKE "*sqlite_master*"), "SQLi DB Reconnaissance",
  url.full LIKE "*' or *" OR url.full LIKE "* union *select *" OR url.full LIKE "*--*" OR url.full LIKE "*/*%*" OR url.full LIKE "*';*", "General SQLi Attempt",
  TRUE, NULL
)
| WHERE detection_type IS NOT NULL
| STATS count = COUNT(*), urls = ARRAY_AGG(url.full), queries = ARRAY_AGG(sql.query), outcomes = ARRAY_AGG(event.outcome) BY @timestamp, detection_type, client.ip AS SourceIP, user.name AS User, destination.ip AS Destination, event.dataset AS LogSource
| KEEP @timestamp AS _time, detection_type, SourceIP, User, Destination, urls, queries, outcomes, count, LogSource
| SORT _time DESC
| LIMIT 1000
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

FROM logs-vuln.*,logs-kube_audit.*,logs-endpoint.events.*,logs-container_inventory.*
| WHERE (
  /* Part 1: High/Critical Vulnerabilities */
  (event.module == "vulnerability" AND vulnerability.severity IN ("High", "Critical")) OR
  /* Part 2a: Privileged Containers */
  (event.module == "kubernetes" AND kubernetes.pod.security_context.privileged == true AND kubernetes.audit.user.username NOT IN ("system:masters", "cluster-admin", "azure-operator")) OR
  /* Part 2b: Runtime Escape Attempts */
  (process.parent.executable LIKE "*runc*" OR process.parent.executable LIKE "*containerd-shim*") AND process.name IN ("nsenter", "insmod", "modprobe", "chroot") OR
  /* Part 3: Insecure API Access */
  (event.module == "kubernetes" AND kubernetes.audit.verb == "create" AND kubernetes.audit.objectRef.resource == "clusterrolebindings" AND kubernetes.audit.requestObject.roleRef.name IN ("cluster-admin", "admin") AND kubernetes.audit.user.username NOT IN ("system:masters", "cluster-admin", "azure-operator")) OR
  /* Part 4: Untrusted Registry */
  (event.module == "container" AND container.image.name IS NOT NULL AND container.image.name NOT LIKE "mcr.microsoft.com/*" AND container.image.name NOT LIKE "docker.io/*" AND container.image.name NOT LIKE "k8s.gcr.io/*" AND container.image.name NOT LIKE "quay.io/*" AND container.image.name NOT LIKE "gcr.io/*")
)
| EVAL Tactic = CASE(
  vulnerability.severity IN ("High", "Critical"), "Initial Access",
  kubernetes.pod.security_context.privileged == true, "Privilege Escalation",
  process.name IN ("nsenter", "insmod", "modprobe", "chroot"), "Privilege Escalation",
  kubernetes.audit.verb == "create", "Privilege Escalation",
  container.image.name IS NOT NULL, "Initial Access",
  TRUE, NULL
), Technique = CASE(
  vulnerability.severity IN ("High", "Critical"), "Exploit Public-Facing Application",
  kubernetes.pod.security_context.privileged == true, "Escape to Host",
  process.name IN ("nsenter", "insmod", "modprobe", "chroot"), "Escape to Host",
  kubernetes.audit.verb == "create", "Valid Accounts",
  container.image.name IS NOT NULL, "Supply Chain Compromise",
  TRUE, NULL
), DetectionSource = CASE(
  vulnerability.severity IS NOT NULL, "Vulnerability Scan",
  kubernetes.pod.security_context.privileged IS NOT NULL, "Kubernetes Audit",
  process.name IN ("nsenter", "insmod", "modprobe", "chroot"), "EDR",
  kubernetes.audit.verb == "create", "Kubernetes Audit",
  container.image.name IS NOT NULL, "Container Inventory",
  TRUE, NULL
), Entity = COALESCE(container.image.name, kubernetes.audit.user.username, host.name, container.image.name),
  Description = CASE(
    vulnerability.severity IN ("High", "Critical"), "High/Critical severity vulnerability '" + vulnerability.id + "' detected in image '" + container.image.name + "'.",
    kubernetes.pod.security_context.privileged == true, "Privileged container '" + kubernetes.pod.name + "' created by user '" + kubernetes.audit.user.username + "' in namespace '" + kubernetes.namespace + "'.",
    process.name IN ("nsenter", "insmod", "modprobe", "chroot"), "Suspicious process '" + process.name + "' with command line '" + process.args + "' executed from a container context on host '" + host.name + "'.",
    kubernetes.audit.verb == "create", "User '" + kubernetes.audit.user.username + "' created a cluster role binding to a privileged role '" + kubernetes.audit.requestObject.roleRef.name + "'.",
    container.image.name IS NOT NULL, "Container started from untrusted registry: '" + container.image.name + "' on host '" + host.name + "'.",
    TRUE, NULL
  )
| WHERE Tactic IS NOT NULL
| STATS count = COUNT(*) BY @timestamp AS _time, Tactic, Technique, DetectionSource, Entity, Description
| KEEP _time, Tactic, Technique, DetectionSource, Entity, Description
| SORT _time DESC
| LIMIT 1000
```

### UNC6384 (Mustang Panda) Campaign IOCs and TTPs
---
```sql
-- title: UNC6384 Mustang Panda Campaign IOCs and TTPs
-- description: Detects multiple indicators of compromise (IOCs) and tactics, techniques, and procedures (TTPs) associated with a UNC6384 (Mustang Panda) campaign targeting diplomats, as reported by Google in August 2025. This rule covers file hashes, network indicators, persistence mechanisms, and behavioral patterns related to the STATICPLUGIN, CANONSTAGER, and SOGU.SEC malware families.
-- author: RW
-- date: 2025-08-26

FROM logs-endpoint.events.*, logs-network.*
| WHERE file.hash.sha256 IN ("65c42a7ea18162a92ee982eded91653a5358a7129c7672715ce8ddb6027ec124", "3299866538aff40ca85276f87dd0cefe4eafe167bd64732d67b06af4f3349916", "e787f64af048b9cb8a153a0759555785c8fd3ee1e8efbca312a29f2acb1e4011", "cc4db3d8049043fa62326d0b3341960f9a0cf9b54c2fbbdffdbd8761d99add79", "d1626c35ff69e7e5bde5eea9f9a242713421e59197f4b6d77b914ed46976b933")
  OR destination.ip IN ("103.79.120.72", "166.88.2.90")
  OR destination.domain = "mediareleaseupdates.com"
  OR user_agent.original = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 10.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)"
  OR (registry.key LIKE "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\CanonPrinter" AND registry.value LIKE "*cnmpaui.exe*")
  OR (process.executable LIKE "*\\cnmpaui.exe" AND dll.path LIKE "*\\cnmpaui.dll")
  OR process.executable LIKE "*\\DNVjzaXMFO\\*"
  OR process.executable LIKE "*C:\\Users\\Public\\Intelnet\\*"
  OR process.executable LIKE "*C:\\Users\\Public\\SecurityScan\\*"
| EVAL timestamp = TO_STRING(@timestamp, "yyyy-MM-dd HH:mm:ss")
| EVAL detection_name = CASE(
    file.hash.sha256 IS NOT NULL, "UNC6384 - Malicious File Hash",
    destination.ip IS NOT NULL OR destination.domain IS NOT NULL, "UNC6384 - Malicious Network Connection",
    user_agent.original LIKE "*MSIE 9.0*", "UNC6384 - SOGU.SEC User Agent",
    registry.key IS NOT NULL, "UNC6384 - CanonPrinter Persistence",
    dll.path IS NOT NULL, "UNC6384 - CANONSTAGER DLL Sideloading",
    process.executable LIKE "*\\DNVjzaXMFO\\*" OR process.executable LIKE "*C:\\Users\\Public\\Intelnet\\*" OR process.executable LIKE "*C:\\Users\\Public\\SecurityScan\\*", "UNC6384 - Suspicious File Path",
    TRUE, "UNC6384 - Fallback Match"
  )
| EVAL victim_host = COALESCE(host.name, host.hostname),
  src_process = COALESCE(process.name, process.executable, file.name),
  user = COALESCE(user.name),
  ioc_indicator = COALESCE(file.hash.sha256, destination.ip, destination.domain, user_agent.original, registry.key, dll.path, process.executable)
| STATS count = COUNT(), event_times = VALUES(timestamp), detections = VALUES(detection_name), matched_iocs = VALUES(ioc_indicator), processes = VALUES(src_process), users = VALUES(user) BY victim_host
| RENAME victim_host AS "Victim Host", event_times AS "Event Times", detections AS "Detections", matched_iocs AS "Matched IOCs", processes AS "Associated Processes", users AS "Associated Users"
```

### CCP Network Device Activity
---
```sql
-- description: Detects TTPs associated with CCP actors targeting network infrastructure, including enabling backdoors, modifying ACLs, creating users, and capturing traffic.
-- author: RW
-- date: 2025-08-29
-- references: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a
-- tags: persistence, defense_evasion, credential_access, collection, t1021.004, t1562.004, t1136.001, t1040, t1059.008, t1571
-- falsepositives: Legitimate administrative activity may trigger command-line matches. High-port SSH (xxx22) may match legitimate services. Baseline normal activity and filter known good IPs.
-- level: high

FROM logs-cisco*,logs-paloalto*,logs-linux*,logs-firewall*,logs-netflow*
WHERE
    -- Part 1: Suspicious commands and filenames
    (
        process.command_line LIKE "%service sshd_operns start%" OR
        process.command_line LIKE "%access-list 10%" OR
        process.command_line LIKE "%access-list 20%" OR
        process.command_line LIKE "%access-list 50%" OR
        process.command_line LIKE "%useradd cisco%" OR
        process.command_line LIKE "%vi /etc/sudoers%" OR
        process.command_line LIKE "%monitor capture%" OR
        process.command_line LIKE "%span%" OR
        process.command_line LIKE "%erspan%" OR
        file.name LIKE "%mycap.pcap" OR
        file.name LIKE "%tac.pcap" OR
        file.name LIKE "%1.pcap"
    )
    OR
    -- Part 2: Suspicious network connections
    (
        destination.port = 57722 OR
        destination.port MATCHES "^\\d{3,5}22$"
        -- FP-Tuning: Add AND NOT destination.ip IN (known_good_ips) to reduce false positives
    )
| EVAL reason = CASE(
    process.command_line LIKE "%service sshd_operns start%", "Suspicious Service Started: sshd_operns",
    process.command_line LIKE "%access-list 10%" OR process.command_line LIKE "%access-list 20%" OR process.command_line LIKE "%access-list 50%", "Suspicious ACL Modification Detected",
    process.command_line LIKE "%useradd cisco%", "Suspicious User Creation: cisco",
    process.command_line LIKE "%vi /etc/sudoers%", "Sudoers File Edited",
    process.command_line LIKE "%monitor capture%" OR process.command_line LIKE "%span%" OR process.command_line LIKE "%erspan%", "Packet/Traffic Capture Command Detected",
    file.name LIKE "%mycap.pcap" OR file.name LIKE "%tac.pcap" OR file.name LIKE "%1.pcap", "Suspicious PCAP Filename Detected",
    destination.port = 57722, "Network Connection to IOS XR Backdoor Port 57722",
    destination.port MATCHES "^\\d{3,5}22$", "Network Connection to High Port Ending in '22'",
    true, "Unknown Match - Check Raw Event"
)
| KEEP @timestamp, reason, user.name, source.ip, destination.ip, destination.port, process.command_line, file.name, event.original
| SORT @timestamp DESC
```

### Silver Fox APT Leverages Vulnerable Drivers for Evasion and ValleyRAT Delivery
---
```sql
-- Title: Silver Fox APT Multi-Stage Activity
-- Description: Detects a combination of TTPs associated with the Silver Fox APT group. This rule correlates persistence mechanisms, vulnerable driver abuse for defense evasion, and C2 communications related to the ValleyRAT backdoor deployment.
-- References: https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/
-- Author: RW
-- Date: 2025-08-30
-- False Positives: Legitimate installations or use of WatchDog Antimalware might trigger parts of this rule. However, the correlation with the specific vulnerable driver hash and at least one other suspicious activity significantly reduces the likelihood of false positives.
-- Level: High

-- Search for matching indicators
FROM logs-endpoint.events.*
WHERE (
    -- Vulnerable driver loads (file hashes)
    event.category = "library" AND event.action = "load" AND file.hash.sha256 IN (
        "12b3d8bc5cc1ea6e2acd741d8a80f56cf2a0a7ebfa0998e3f0743fcf83fabb9e",
        "0be8483c2ea42f1ce4c90e84ac474a4e7017bc6d682e06f96dc1e31922a07b10",
        "9c394dcab9f711e2bf585edf0d22d2210843885917d409ee56f22a4c24ad225e"
    )
    OR
    -- Suspicious files written
    event.category = "file" AND event.action = "create" AND file.path LIKE "C:\\Program Files\\RunTime\\%" AND file.name IN ("RuntimeBroker.exe", "Amsdk_Service.sys")
    OR
    -- Suspicious services created (registry)
    event.category = "registry" AND event.action IN ("create", "modify") AND registry.path LIKE (
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Termaintor%" OR
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Amsdk_Service%"
    )
    OR
    -- C2 traffic
    event.category = "network" AND event.action = "connection" AND destination.ip IN (
        "47.239.197.97", "8.217.38.238", "156.234.58.194", "156.241.144.66", "1.13.249.217"
    ) AND destination.port IN (52116, 52117, 8888, 52110, 52111, 52139, 52160, 9527, 9528)
)
-- Categorize indicators
| EVAL indicator_type = CASE(
    file.hash.sha256 IN (
        "12b3d8bc5cc1ea6e2acd741d8a80f56cf2a0a7ebfa0998e3f0743fcf83fabb9e",
        "0be8483c2ea42f1ce4c90e84ac474a4e7017bc6d682e06f96dc1e31922a07b10",
        "9c394dcab9f711e2bf585edf0d22d2210843885917d409ee56f22a4c24ad225e"
    ), "Vulnerable_Driver_Loaded",
    file.path LIKE "C:\\Program Files\\RunTime\\%" AND file.name IN ("RuntimeBroker.exe", "Amsdk_Service.sys"), "Suspicious_File_Written",
    registry.path LIKE (
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Termaintor%" OR
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Amsdk_Service%"
    ), "Suspicious_Service_Created",
    destination.ip IS NOT NULL, "C2_Traffic_Detected",
    true, "Other"
)
| EVAL indicator_value = CASE(
    indicator_type = "Vulnerable_Driver_Loaded", file.hash.sha256,
    indicator_type = "Suspicious_File_Written", file.path,
    indicator_type = "Suspicious_Service_Created", registry.path,
    indicator_type = "C2_Traffic_Detected", CONCAT(destination.ip, ":", CAST(destination.port AS STRING)),
    true, "N/A"
)
-- Aggregate by host
| STATS
    first_seen = MIN(@timestamp),
    last_seen = MAX(@timestamp),
    users = COLLECT(user.name),
    distinct_indicator_count = COUNT_DISTINCT(indicator_type),
    indicators = COLLECT(indicator_type),
    indicator_details = COLLECT(indicator_value)
    BY host.name
-- Core detection logic
| WHERE indicators LIKE "%Vulnerable_Driver_Loaded%" AND distinct_indicator_count > 1
-- Add IOCTL note
| EVAL note = "IOCTL detection (DeviceIoControl to 'amsdk' with codes 0x80002010, 0x80002048) requires specific EDR logs. This activity may also be present but is not detected by this query."
-- Format output
| KEEP first_seen, last_seen, host.name AS host, users, indicators, indicator_details, note
```

### APT28 NotDoor Backdoor Activity Detection
---
```sql
-- Name: APT28 NotDoor Backdoor Activity
-- Author: RW
-- Date: 2025-09-03
-- Description: This rule detects various activities associated with the NotDoor backdoor, used by APT28. It looks for specific file creation events, process command lines, registry modifications, and network communications.
-- False Positive Sensitivity: Medium

FROM sysmon-*
| WHERE
  (event.code == 11 AND (file.sha256 IN ("5a88a15a1d764e635462f78a0cd958b17e6d22c716740febc114a408eef66705","8f4bca3c62268fff0458322d111a511e0bcfba255d5ab78c45973bd293379901") OR file.path == "C:\\ProgramData\\testtemp.ini" OR file.path REGEXP "(?i)\\\\AppData\\\\Local\\\\Temp\\\\Test\\\\(report|invoice|contract|photo|scheme|document)_[^\\\\]+\\.(jpg|jpeg|gif|bmp|ico|png|pdf|doc|docx|xls|xlsx|ppt|pptx|mp3|mp4|xml)$")) OR
  (event.code == 1 AND (process.name == "nslookup.exe" AND process.args REGEXP "(?i)\\.dnshook\\.site" OR process.name == "curl.exe" AND process.args REGEXP "(?i)webhook\\.site" OR process.args REGEXP "(?i)copy.*c:\\\\programdata\\\\testtemp.ini.*\\\\Microsoft\\\\Outlook\\\\VbaProject.OTM")) OR
  (event.code == 13 AND (registry.path REGEXP "(?i)\\\\Software\\\\Microsoft\\\\Office\\\\[^\\\\]+\\\\Outlook\\\\LoadMacroProviderOnBoot$" AND registry.data.values == 1 OR registry.path REGEXP "(?i)\\\\Software\\\\Microsoft\\\\Office\\\\[^\\\\]+\\\\Outlook\\\\Security\\\\Level$" AND registry.data.values == 1 OR registry.path REGEXP "(?i)\\\\Software\\\\Microsoft\\\\Office\\\\[^\\\\]+\\\\Outlook\\\\Options\\\\General\\\\PONT_STRING$" AND registry.data.values == ";")) OR
  ((event.code == 22 AND dns.question.name REGEXP "(?i)(webhook|dnshook)\\.site$" OR sourcetype == "stream:dns" AND dns.question.name REGEXP "(?i)(webhook|dnshook)\\.site$") OR (sourcetype == "stream:http" AND destination.domain REGEXP "(?i)(webhook|dnshook)\\.site$")) OR
  (sourcetype == "your_email_log_sourcetype" AND email.to == "a.matti444@proton.me" AND email.subject == "Re: 0")
| EVAL detection_method = CASE(
  event.code == 11 AND file.sha256 IN ("5a88a15a1d764e635462f78a0cd958b17e6d22c716740febc114a408eef66705","8f4bca3c62268fff0458322d111a511e0bcfba255d5ab78c45973bd293379901"), "Malicious File Hash Detected (SSPICLI.dll or testtemp.ini)",
  event.code == 11 AND file.path == "C:\\ProgramData\\testtemp.ini", "Initial Backdoor File Drop (testtemp.ini)",
  event.code == 11 AND file.path REGEXP "(?i)\\\\AppData\\\\Local\\\\Temp\\\\Test\\\\(report|invoice|contract|photo|scheme|document)_[^\\\\]+\\.(jpg|jpeg|gif|bmp|ico|png|pdf|doc|docx|xls|xlsx|ppt|pptx|mp3|mp4|xml)$", "Staging File Creation for Exfiltration",
  event.code == 1 AND process.args REGEXP "(?i)copy.*c:\\\\programdata\\\\testtemp.ini.*\\\\Microsoft\\\\Outlook\\\\VbaProject.OTM", "Backdoor Macro Installation Command",
  event.code == 1 AND process.name == "nslookup.exe" AND process.args REGEXP "(?i)\\.dnshook\\.site", "C2 Verification via nslookup",
  event.code == 1 AND process.name == "curl.exe" AND process.args REGEXP "(?i)webhook\\.site", "C2 Verification via curl",
  event.code == 13 AND registry.path REGEXP "(?i)\\\\Software\\\\Microsoft\\\\Office\\\\[^\\\\]+\\\\Outlook\\\\LoadMacroProviderOnBoot$" AND registry.data.values == 1, "Outlook Persistence via LoadMacroProviderOnBoot",
  event.code == 13 AND registry.path REGEXP "(?i)\\\\Software\\\\Microsoft\\\\Office\\\\[^\\\\]+\\\\Outlook\\\\Security\\\\Level$" AND registry.data.values == 1, "Outlook Macro Security Disabled",
  event.code == 13 AND registry.path REGEXP "(?i)\\\\Software\\\\Microsoft\\\\Office\\\\[^\\\\]+\\\\Outlook\\\\Options\\\\General\\\\PONT_STRING$" AND registry.data.values == ";", "Outlook Macro Warning Disabled",
  (event.code == 22 OR sourcetype == "stream:dns") AND dns.question.name REGEXP "(?i)(webhook|dnshook)\\.site$", "C2 DNS Query",
  sourcetype == "stream:http" AND destination.domain REGEXP "(?i)(webhook|dnshook)\\.site$", "C2 HTTP Connection",
  sourcetype == "your_email_log_sourcetype" AND email.to == "a.matti444@proton.me" AND email.subject == "Re: 0", "Exfiltration Email Sent"
)
| WHERE !isnull(detection_method)
| KEEP @timestamp, host.name, user.name, process.name, process.args, file.path, file.sha256, registry.path, registry.data.values, dns.question.name, destination.domain, email.to, email.subject, detection_method
| SORT @timestamp
```

### MeetC2 C2 Activity via Google Calendar API
---
```sql
-- Part 1: ES|QL for suspicious Google Calendar events
FROM gcp-,google_workspace-
| WHERE event.action IN ("calendar.events.insert", "calendar.events.update", "calendar.acl.create")
AND (parameters.summary LIKE "%Meeting from nobody:%[COMMAND]%"
OR (parameters.description LIKE "%[OUTPUT]%" AND parameters.description LIKE "%[/OUTPUT]%")
OR parameters.acl.scope.value LIKE "%gserviceaccount.com")
| EVAL detection_method = CASE(
parameters.summary LIKE "%Meeting from nobody:%[COMMAND]%", "MeetC2 Command Pattern in Event Summary",
parameters.description LIKE "%[OUTPUT]%" AND parameters.description LIKE "%[/OUTPUT]%", "MeetC2 Output Pattern in Event Description",
event.action == "calendar.acl.create" AND parameters.acl.scope.value LIKE "%gserviceaccount.com", "Calendar Shared with Service Account"
)
| EVAL details = "Event Name: " + event.action + ", Summary: " + COALESCE(parameters.summary, "N/A") + ", Recipient: " + COALESCE(parameters.acl.scope.value, "N/A")
| KEEP @timestamp, user.name, source.ip, detection_method, details
| SORT @timestamp DESC
| LIMIT 10000
-- Part 2: ES|QL for potential C2 beaconing
FROM proxy-,network-
| WHERE url.original LIKE "%www.googleapis.com/calendar/v3/calendars/%/events%"
AND (process.executable IS NULL OR NOT (process.executable RLIKE "(?i)(chrome|msedge|firefox|outlook|teams)\.exe$"))
| EVAL time_bin = DATE_TRUNC("10m", @timestamp)
| STATS request_count = COUNT(*) , urls = VALUES(url.original) BY source.ip, process.executable, user.name, time_bin
| WHERE request_count > 15
| EVAL detection_method = "Potential C2 Beaconing to Google Calendar API"
| EVAL details = "Process '" + COALESCE(process.executable, "N/A") + "' made " + TO_STRING(request_count) + " requests to Google Calendar API in 10 minutes."
| KEEP @timestamp, user.name, source.ip, detection_method, details
| SORT @timestamp DESC
| LIMIT 10000
```

### APT37 Rustonotto, Chinotto, and FadeStealer Activity
---
```sql
FROM sysmon-*,zscaler-*,pan-*,suricata-*
| WHERE event.code IN ("1", "11", "13") OR url.original LIKE "%U=%*"
| EVAL rule_trigger = CASE(
    event.code IN ("1", "11") AND file.hash.md5 IN (
      "b9900bef33c6cc9911a5cd7eeda8e093",
      "7967156e138a66f3ee1bfce81836d8d0",
      "77a70e87429c4e552649235a9a2cf11a",
      "04b5e068e6f0079c2c205a42df8a3a84",
      "d2b34b8bfafd6b17b1cf931bb3fdd3db",
      "3d6b999d65c775c1d27c8efa615ee520",
      "89986806a298ffd6367cf43f36136311",
      "4caa44930e5587a0c9914bda9d240acc"
    ), "File Hash IOC",
    event.code == "11" AND (
      file.path IN (
        "C:\\ProgramData\\3HNoWZd.exe",
        "C:\\ProgramData\\wonder.cab",
        "C:\\ProgramData\\tele_update.exe",
        "C:\\ProgramData\\tele.conf",
        "C:\\ProgramData\\tele.dat",
        "C:\\ProgramData\\Password.chm",
        "C:\\ProgramData\\1.html"
      ) OR file.path RLIKE "(?i)\\\\VSTelems_Fade\\\\(NgenPdbk|NgenPdbc|NgenPdbm|VSTelems_FadeOut|VSTelems_FadeIn)" OR file.path RLIKE "(?i)(watch_|usb_|data_).+\\.rar$"
    ), "Malicious File Artifact",
    event.code == "1" AND (
      process.command_line RLIKE "(?i)schtasks.* /create .*MicrosoftUpdate.*3HNoWZd\\.exe" OR
      (process.executable LIKE "%\\mshta.exe" AND process.command_line LIKE "%http%") OR
      (parent.process.executable LIKE "%\\cmd.exe" AND process.executable LIKE "%\\expand.exe" AND process.command_line LIKE "%c:\\programdata\\wonder.cab%") OR
      process.executable == "c:\\programdata\\tele_update.exe"
    ), "Suspicious Process Execution",
    event.code == "13" AND registry.key RLIKE "(?i)\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\OnedriveStandaloneUpdater" AND registry.data RLIKE "(?i)mshta.*http", "Registry Run Key Persistence",
    url.original LIKE "%U=%*" AND (url.original LIKE "%R=%*" OR url.original LIKE "%_file=%*"), "C2 Communication Pattern"
  )
| WHERE rule_trigger IS NOT NULL
| KEEP @timestamp, destination.domain, user.name, rule_trigger, process.executable, process.command_line, parent.process.executable, file.path, file.hash.md5, registry.key, registry.data, url.original
| DISTINCT @timestamp, destination.domain, rule_trigger, process.command_line
| SORT @timestamp DESC
| LIMIT 10000
```

### Exposed Docker APIs Are Targeted in New Malware Strain
---
```sql
-- author: RW

-- This detection rule identifies a multi-stage attack targeting exposed Docker APIs.
-- The malware strain aims to establish persistent root access, create a botnet, and perform reconnaissance.
-- This rule combines several detection concepts into a single query to provide a broad overview of related malicious activities.

-- Detects Docker API exploitation attempts on port 2375 (T1190).
-- Data requirement: Indices http-*, suricata-*, zeek-* with ECS fields.
-- FP Tuning: Filter source.ip against known-good IPs or user agents.
FROM http-*,suricata-*,zeek-*
| WHERE http.request.method == "POST" AND url.path LIKE "/containers/create%" OR "/images/create%" AND destination.port == 2375
| EVAL Tactic = "Initial Access", Technique = "Exposed Docker Daemon API", Description = "Potential Docker API exploitation attempt on port 2375."
| KEEP @timestamp, source.ip AS src_ip, destination.ip AS dest_ip, http.request.user_agent AS user_agent, Tactic, Technique, Description
| SORT @timestamp DESC
| LIMIT 10000

-- Detects post-exploitation command execution in containers (T1059).
-- Data requirement: Indices linux-*, sysmon-linux-*, falco-* with ECS fields.
-- FP Tuning: Filter for multiple processes (curl+wget) via STATS.
FROM linux-*,sysmon-linux-*,falco-*
| WHERE (process.name IN ("sh", "bash") AND process.command_line LIKE "%curl%" OR "%wget%") OR process.name IN ("apk", "apt", "yum")
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), processes = VALUES(process.name), args = VALUES(process.command_line) BY host.name, container.id
| WHERE ARRAY_LENGTH(processes) > 1 AND (args LIKE "%curl%" OR args LIKE "%wget%")
| EVAL Tactic = "Execution", Technique = "Command and Scripting Interpreter", Description = "Suspicious package installation followed by downloader execution in a container."
| KEEP first_seen, last_seen, host.name AS dest_host, container.id, processes, args, Tactic, Technique, Description
| SORT first_seen DESC
| LIMIT 10000

-- Detects persistence via SSH keys, cron jobs, or firewall rule changes (T1547, T1070).
-- Data requirement: Indices linux-*, sysmon-linux-*, osquery-* with ECS fields.
-- FP Tuning: Review user context for authorized changes.
FROM linux-*,sysmon-linux-*,osquery-*
| WHERE (file.path IN ("/root/.ssh/authorized_keys", "/etc/crontab", "/etc/cron.d/*", "/var/spool/cron/*") AND file.operation IN ("write", "create")) OR (process.name IN ("firewall-cmd", "iptables") AND process.command_line LIKE "%--add-rich-rule%" OR "%--reload%" OR "%-A INPUT%" OR "%-p tcp%")
| EVAL Tactic = "Persistence", Technique = "SSH Authorized Keys or Cron Job Modification", Description = "Modification of sensitive files for persistence or firewall rules for defense evasion."
| KEEP @timestamp, host.name AS host, user.name AS user, process.name, process.command_line AS process_args, file.path, Tactic, Technique, Description
| SORT @timestamp DESC
| LIMIT 10000

-- Detects discovery/lateral movement via masscan or connections to specific ports (T1018, T1021).
-- Data requirement: Indices linux-*, tcp-*, suricata-*, zeek-* with ECS fields.
-- FP Tuning: Baseline legitimate traffic to ports 23, 9222, 2375.
FROM linux-*,tcp-*,suricata-*,zeek-*
| WHERE process.name == "masscan" OR destination.port IN (23, 9222, 2375)
| EVAL Tactic = "Discovery/Lateral Movement", Technique = "Network Service Scanning", Description = "Execution of masscan or connection attempts to Telnet, Chrome Debug, or Docker API ports."
| KEEP @timestamp, source.ip AS src_ip, destination.ip AS dest_ip, destination.port AS dest_port, process.name, Tactic, Technique, Description
| SORT @timestamp DESC
| LIMIT 10000

-- Detects Tor-related C2 activity (T1071).
-- Data requirement: Indices dns-*, zeek-dns-*, linux-*, sysmon-linux-* with ECS fields.
-- FP Tuning: Review legitimate Tor usage in environment.
FROM dns-*,zeek-dns-*,linux-*,sysmon-linux-*
| WHERE dns.question.name LIKE "%.onion" OR process.name == "torsocks"
| EVAL Tactic = "Command and Control", Technique = "Proxy: Tor", Description = "Tor-related activity detected (torsocks process or .onion domain query)."
| KEEP @timestamp, host.name AS host, source.ip AS src_ip, dns.question.name AS query, process.name, Tactic, Technique, Description
| SORT @timestamp DESC
| LIMIT 10000
```