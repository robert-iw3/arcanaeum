### Man-in-the-Malware: Intercepting Adversarial Comms
---

This report details the use of infostealers, particularly Nova, that leverage Telegram as a Command and Control (C2) channel for data exfiltration. It highlights how threat actors exploit operational security (OPSEC) failures to gain intelligence and maintain persistence.

Recent intelligence indicates a new Golang-based backdoor also uses Telegram for C2, often masquerading as svchost.exe in C:\Windows\Temp, and that Lumma Stealer, Vidar, and other infostealers continue to leverage Telegram for C2, sometimes embedding C2 information in social media profiles.

### Actionable Threat Data
---

Monitor for PowerShell execution that downloads and executes files from suspicious or untrusted domains, especially those using Base64 encoded commands or Invoke-Expression (IEX).

Detect network traffic to api.telegram.org from non-Telegram applications or from systems not expected to communicate with Telegram, as this could indicate C2 activity or data exfiltration.

Look for the creation or execution of svchost.exe from unusual directories like C:\Windows\Temp, as this is a known persistence mechanism for Telegram C2 malware.

Identify the use of archive file formats such as .rar, .7z, and .gz in email attachments, particularly in malspam campaigns impersonating legitimate entities like DHL or DocuSign, as these are frequently used for malware delivery.

Search for process injection into RegAsm.exe or other legitimate Windows processes, which infostealers like Nova use to inject their final payload.

### PowerShell Download Cradle
---
Name: PowerShell Download Cradle

Author: RW

Date: 2025-08-12

MITRE ATT&CK: T1059.001, T1105

Description:

Detects suspicious PowerShell execution that includes command-line parameters often used to download and execute remote payloads.

This is a common technique for initial access and code execution by infostealers and other malware, as seen in the "Man-in-the-Malware" intelligence.

False Positive Sensitivity: Medium. Legitimate administrative or deployment scripts may sometimes use these patterns.

Consider tuning by excluding known safe parent processes (e.g., configuration management tools) or scripts.

splunk:
```sql
`tstats` `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=powershell.exe AND (Processes.process="*-NoProfile*" AND Processes.process="*-ExecutionPolicy*" AND Processes.process="*RemoteSigned*") AND (Processes.process="*IEX*" OR Processes.process="*Invoke-Expression*" OR Processes.process="*DownloadString*" OR (Processes.process="*New-Object*" AND Processes.process="*System.Net.WebClient*")) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
--_-- rename for clarity
| rename process as process_command_line, dest as endpoint, user as user_name, parent_process as parent_process_name
--_-- comment: Legitimate administrative or deployment scripts may sometimes use these patterns. Consider tuning by excluding known safe parent processes (e.g., sccm.exe, vmmagent.exe) or scripts.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

crowdstrike fql:
```sql
event_simpleName=ProcessRollup2 ImageFileName=*powershell.exe
| filter CommandLine LIKE "*-NoProfile*" AND CommandLine LIKE "*-ExecutionPolicy*" AND CommandLine LIKE "*RemoteSigned*"
| filter (CommandLine LIKE "*IEX*" OR CommandLine LIKE "*Invoke-Expression*" OR CommandLine LIKE "*DownloadString*" OR (CommandLine LIKE "*New-Object*" AND CommandLine LIKE "*System.Net.WebClient*"))
| stats count, min(timestamp) AS firstTime, max(timestamp) AS lastTime BY ComputerName, UserName, ParentImageFileName, ImageFileName, CommandLine, ProcessId, ParentProcessId
| project firstTime, lastTime, count, ComputerName AS endpoint, UserName AS user_name, ParentImageFileName AS parent_process_name, ImageFileName AS process_name, CommandLine AS process_command_line, ProcessId AS process_id, ParentProcessId AS parent_process_id
```

datadog:
```sql
source:endpoint ProcessName:powershell.exe (ProcessCommandLine:*-NoProfile* AND ProcessCommandLine:*-ExecutionPolicy* AND ProcessCommandLine:*RemoteSigned*) (ProcessCommandLine:*IEX* OR ProcessCommandLine:*Invoke-Expression* OR ProcessCommandLine:*DownloadString* OR (ProcessCommandLine:*New-Object* AND ProcessCommandLine:*System.Net.WebClient*))
| stats count, min(@timestamp) as firstTime, max(@timestamp) as lastTime by host as endpoint, UserName as user_name, ParentProcessName as parent_process_name, ProcessName as process_name, ProcessCommandLine as process_command_line, ProcessId as process_id, ParentProcessId as parent_process_id
```

elastic:
```sql
FROM logs-endpoint.events.process-*
| WHERE process.name == "powershell.exe"
  AND process.command_line LIKE "*[Nn][Oo][Pp][Rr][Oo][Ff][Ii][Ll][Ee]*"
  AND process.command_line LIKE "*[Ee][Xx][Ee][Cc][Uu][Tt][Ii][Oo][Nn][Pp][Oo][Ll][Ii][Cc][Yy]*"
  AND process.command_line LIKE "*[Rr][Ee][Mm][Oo][Tt][Ee][Ss][Ii][Gg][Nn][Ee][Dd]*"
  AND (
      process.command_line LIKE "*[Ii][Ee][Xx]*" OR
      process.command_line LIKE "*[Ii][Nn][Vv][Oo][Kk][Ee]-[Ee][Xx][Pp][Rr][Ee][Ss][Ss][Ii][Oo][Nn]*" OR
      process.command_line LIKE "*[Dd][Oo][Ww][Nn][Ll][Oo][Aa][Dd][Ss][Tt][Rr][Ii][Nn][Gg]*" OR
      (process.command_line LIKE "*[Nn][Ee][Ww]-[Oo][Bb][Jj][Ee][Cc][Tt]*" AND process.command_line LIKE "*[Ss][Yy][Ss][Tt][Ee][Mm].[Nn][Ee][Tt].[Ww][Ee][Bb][Cc][Ll][Ii][Ee][Nn][Tt]*")
  )
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY host.hostname AS endpoint, user.name AS user_name, process.parent.executable AS parent_process_name, process.name AS process_name, process.command_line AS process_command_line, process.pid AS process_id, process.parent.pid AS parent_process_id
| KEEP firstTime, lastTime, count, endpoint, user_name, parent_process_name, process_name, process_command_line, process_id, parent_process_id
```

sentinel one:
```sql
EventType = "Process Creation" AND ProcessName = "powershell.exe"
AND ProcessCommandLine LIKE "%-NoProfile%" AND ProcessCommandLine LIKE "%-ExecutionPolicy%" AND ProcessCommandLine LIKE "%RemoteSigned%"
AND (
    ProcessCommandLine LIKE "%IEX%" OR
    ProcessCommandLine LIKE "%Invoke-Expression%" OR
    ProcessCommandLine LIKE "%DownloadString%" OR
    (ProcessCommandLine LIKE "%New-Object%" AND ProcessCommandLine LIKE "%System.Net.WebClient%")
)
| SELECT MIN(Timestamp) AS firstTime, MAX(Timestamp) AS lastTime, COUNT(*) AS count,
         EndpointName AS endpoint, UserName AS user_name, ParentProcessName AS parent_process_name,
         ProcessName AS process_name, ProcessCommandLine AS process_command_line,
         ProcessId AS process_id, ParentProcessId AS parent_process_id
| GROUP BY endpoint, user_name, parent_process_name, process_name, process_command_line, process_id, parent_process_id
```

### Svchost Making Telegram C2 Connections
---
Name: Suspicious Svchost Making Telegram C2 Connections

Author: RW

Date: 2025-08-12

MITRE ATT&CK: T1036.003, T1574.001, T1071.001, T1572

Description: Detects a process named svchost.exe executing from the C:\Windows\Temp directory that subsequently makes network connections to the Telegram Bot API (api.telegram.org). This is a high-fidelity indicator of compromise, as threat actors use this combination of techniques for persistence and C2 communications.

False Positive Sensitivity: Low. The combination of these two anomalous behaviors is highly indicative of malicious activity. However, it's theoretically possible for a legitimate but poorly written application to exhibit this behavior.

splunk:
```sql
--_-- Find process and network events that match our criteria
`tstats` summariesonly=true allow_old_summaries=true count from datamodel=Endpoint where (nodm=Endpoint.Processes Processes.process_name=svchost.exe Processes.process_path="C:\\Windows\\Temp\\*") OR (nodm=Endpoint.Network_Traffic Network_Traffic.url="*api.telegram.org*") by _time, Processes.process_name, Processes.process_path, Processes.process, Processes.user, Processes.dest, Processes.process_id, Processes.file_hash, Network_Traffic.url, Network_Traffic.dest_ip
| `drop_dm_object_name(Processes)`
| `drop_dm_object_name(Network_Traffic)`
--_-- Correlate the events by destination host and process ID
| stats min(_time) as firstTime, max(_time) as lastTime, values(process_name) as ProcessFileName, values(process_path) as FolderPath, values(process) as ProcessCommandLine, values(user) as AccountName, values(file_hash) as SHA1, values(url) as RemoteUrl, values(dest_ip) as RemoteIP by dest as DeviceName, process_id as ProcessId
--_-- Filter for correlations where both the suspicious process and the network connection were observed for the same process ID
| where isnotnull(ProcessFileName) AND isnotnull(RemoteUrl)
--_-- Add time formatting
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rename firstTime as ProcessCreationTime, lastTime as NetworkEventTime
--_-- Final field selection
| table ProcessCreationTime, NetworkEventTime, DeviceName, AccountName, ProcessFileName, FolderPath, ProcessCommandLine, SHA1, RemoteUrl, RemoteIP, ProcessId
```

crowdstrike fql:
```sql
(event_simpleName=ProcessRollup2 ImageFileName=svchost.exe FilePath LIKE "C:\\Windows\\Temp\\*") OR (event_simpleName=HttpRequest TargetUrl LIKE "*api.telegram.org*")
| stats min(timestamp) AS ProcessCreationTime, max(timestamp) AS NetworkEventTime,
        values(ImageFileName) AS ProcessFileName, values(FilePath) AS FolderPath,
        values(CommandLine) AS ProcessCommandLine, values(UserName) AS AccountName,
        values(SHA1HashData) AS SHA1, values(TargetUrl) AS RemoteUrl,
        values(DestinationIPAddress) AS RemoteIP
  BY ComputerName AS DeviceName, ProcessId
| filter isnotnull(ProcessFileName) AND isnotnull(RemoteUrl)
| project ProcessCreationTime, NetworkEventTime, DeviceName, AccountName, ProcessFileName, FolderPath, ProcessCommandLine, SHA1, RemoteUrl, RemoteIP, ProcessId
```

datadog:
```sql
(source:endpoint ProcessName:svchost.exe ProcessPath:*C:\\Windows\\Temp\\*) OR (source:network Url:*api.telegram.org*)
| stats min(@timestamp) as ProcessCreationTime, max(@timestamp) as NetworkEventTime,
        values(ProcessName) as ProcessFileName, values(ProcessPath) as FolderPath,
        values(ProcessCommandLine) as ProcessCommandLine, values(UserName) as AccountName,
        values(FileHash) as SHA1, values(Url) as RemoteUrl, values(DestinationIp) as RemoteIP
  by host as DeviceName, ProcessId
| filter ProcessFileName IS NOT NULL AND RemoteUrl IS NOT NULL
| select ProcessCreationTime, NetworkEventTime, DeviceName, AccountName, ProcessFileName, FolderPath, ProcessCommandLine, SHA1, RemoteUrl, RemoteIP, ProcessId
```

elastic:
```sql
FROM logs-endpoint.events.process-* , logs-endpoint.events.network-*
| WHERE (process.name == "svchost.exe" AND process.executable LIKE "C:\\Windows\\Temp\\*")
  OR (network.direction == "outgoing" AND http.request.url LIKE "*api.telegram.org*")
| STATS ProcessCreationTime = MIN(@timestamp), NetworkEventTime = MAX(@timestamp),
        ProcessFileName = ARRAY_DISTINCT(VALUES(process.name)),
        FolderPath = ARRAY_DISTINCT(VALUES(process.executable)),
        ProcessCommandLine = ARRAY_DISTINCT(VALUES(process.command_line)),
        AccountName = ARRAY_DISTINCT(VALUES(user.name)),
        SHA1 = ARRAY_DISTINCT(VALUES(file.hash.sha1)),
        RemoteUrl = ARRAY_DISTINCT(VALUES(http.request.url)),
        RemoteIP = ARRAY_DISTINCT(VALUES(destination.ip))
  BY host.hostname AS DeviceName, process.pid AS ProcessId
| WHERE ProcessFileName IS NOT NULL AND RemoteUrl IS NOT NULL
| KEEP ProcessCreationTime, NetworkEventTime, DeviceName, AccountName, ProcessFileName, FolderPath, ProcessCommandLine, SHA1, RemoteUrl, RemoteIP, ProcessId
```

sentinel one:
```sql
(EventType = "Process Creation" AND ProcessName = "svchost.exe" AND ProcessPath LIKE "%C:\\Windows\\Temp\\%")
OR (EventType = "Network Connection" AND TargetUrl LIKE "%api.telegram.org%")
| SELECT MIN(Timestamp) AS ProcessCreationTime, MAX(Timestamp) AS NetworkEventTime,
         ARRAY_DISTINCT(VALUES(ProcessName)) AS ProcessFileName,
         ARRAY_DISTINCT(VALUES(ProcessPath)) AS FolderPath,
         ARRAY_DISTINCT(VALUES(ProcessCommandLine)) AS ProcessCommandLine,
         ARRAY_DISTINCT(VALUES(UserName)) AS AccountName,
         ARRAY_DISTINCT(VALUES(SHA1)) AS SHA1,
         ARRAY_DISTINCT(VALUES(TargetUrl)) AS RemoteUrl,
         ARRAY_DISTINCT(VALUES(DestinationIPAddress)) AS RemoteIP
  GROUP BY EndpointName AS DeviceName, ProcessId
| WHERE ProcessFileName IS NOT NULL AND RemoteUrl IS NOT NULL
| SELECT ProcessCreationTime, NetworkEventTime, DeviceName, AccountName, ProcessFileName, FolderPath, ProcessCommandLine, SHA1, RemoteUrl, RemoteIP, ProcessId
```

### Malspam Campaign Activity
---
Name: Consolidated Malspam Campaign Activity

Author: RW

Date: 2025-08-12

MITRE ATT&CK: T1566.001, T1071.001

Description:

This query consolidates multiple detections related to a widespread malspam campaign delivering the Nova infostealer. It hunts for activity across email, network, DNS, and firewall logs associated with known malicious domains, IPs, and specific TTPs like suspicious archive attachments from impersonated brands.

False Positive Sensitivity: Medium. This is a broad query combining high-fidelity IOCs with more behavioral patterns. Legitimate activity could overlap, especially with the attachment detection. Tuning may be required by excluding trusted senders or specific internal processes.

Indicators:

Domains: windhym.site, bioccon.com, hanhanggroup.com, sprinterstravels.co.uk

IPs: 79.141.165.17, 185.81.114.43, 185.117.90.49, 185.80.53.203

TTPs: .rar/.7z/.gz attachments in emails impersonating DHL/DocuSign

splunk:
```sql
-- Required Data Models: Email, Network_Traffic, Network_Resolution, Endpoint
-- Define IOCs in macros for easier management.
-- Macro: `malicious_domains_spl` = `("windhym.site", "bioccon.com", "hanhanggroup.com", "sprinterstravels.co.uk")`
-- Macro: `malicious_ips_spl` = `("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203")`
-- Macro: `suspicious_extensions_spl` = `("*.rar", "*.7z", "*.gz")`
-- Macro: `impersonated_keywords_spl` = `("*dhl*", "*docusign*")`

-- Method 1: Suspicious Archive Attachments from impersonated brands
(index=* tag=email) (file_name IN `suspicious_extensions_spl`) (subject IN `impersonated_keywords_spl` OR src_user IN `impersonated_keywords_spl`)
| eval DetectionMethod="Suspicious Archive Attachment", DeviceName="N/A", AccountName=dest, Process=subject, CommandLine="N/A", Indicator=file_name, IndicatorType="Attachment", Details="Sender: " + src_user + ", Subject: " + subject
| fields _time, DetectionMethod, DeviceName, AccountName, Process, CommandLine, Indicator, IndicatorType, Details

| append [
    -- Method 2: Network Connections to Malicious Domains/IPs (using Endpoint data for process context)
    tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.dest_name IN `malicious_domains_spl` OR Processes.dest_ip IN `malicious_ips_spl`) by _time, Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.dest_ip, Processes.dest_name
    | `drop_dm_object_name("Processes")`
    | eval DetectionMethod="Malicious Network Connection", DeviceName=dest, AccountName=user, Process=process_name, CommandLine=process
    | eval Indicator=if(in(dest_name, `malicious_domains_spl`), dest_name, dest_ip), IndicatorType=if(in(dest_name, `malicious_domains_spl`), "Domain", "IP Address")
    | eval Details="RemoteIP: " + dest_ip + ", RemoteUrl: " + dest_name
    | fields _time, DetectionMethod, DeviceName, AccountName, Process, CommandLine, Indicator, IndicatorType, Details
]

| append [
    -- Method 3: DNS Activity for Malicious Domains/IPs
    tstats `summariesonly` count from datamodel=Network_Resolution where (DNS.query IN `malicious_domains_spl` OR DNS.answer IN `malicious_ips_spl`) by _time, DNS.src, DNS.process, DNS.query, DNS.answer
    | `drop_dm_object_name("DNS")`
    | eval DetectionMethod="Malicious DNS Activity", DeviceName=src, AccountName="N/A", Process=process, CommandLine="N/A", Indicator=query, IndicatorType="Domain", Details="Query: " + query + ", Response: " + answer
    | fields _time, DetectionMethod, DeviceName, AccountName, Process, CommandLine, Indicator, IndicatorType, Details
]

| append [
    -- Method 4: Emails from Malicious Senders/IPs
    (index=* tag=email) (src_domain IN `malicious_domains_spl` OR src_ip IN `malicious_ips_spl`)
    | eval DetectionMethod="Email from Malicious Infrastructure", DeviceName="N/A", AccountName=dest, Process=subject, CommandLine="N/A", Indicator=src_user, IndicatorType="Sender", Details="Sender: " + src_user + ", ConnectingIP: " + src_ip
    | fields _time, DetectionMethod, DeviceName, AccountName, Process, CommandLine, Indicator, IndicatorType, Details
]

| append [
    -- Method 5: Malicious URLs in Emails
    -- This part is most effective with data sources that explicitly extract URLs, like Proofpoint TAP.
    (index=* tag=email) (url IN ("*windhym.site*", "*bioccon.com*", "*hanhanggroup.com*", "*sprinterstravels.co.uk*"))
    | eval DetectionMethod="Malicious URL in Email", DeviceName="N/A", AccountName=dest, Process=subject, CommandLine="N/A", Indicator=url, IndicatorType="URL", Details="Sender: " + src_user + ", Subject: " + subject
    | fields _time, DetectionMethod, DeviceName, AccountName, Process, CommandLine, Indicator, IndicatorType, Details
]

| append [
    -- Method 6: Firewall Logs for Malicious IPs
    tstats `summariesonly` count from datamodel=Network_Traffic where (All_Traffic.src_ip IN `malicious_ips_spl` OR All_Traffic.dest_ip IN `malicious_ips_spl`) by _time, All_Traffic.dvc, All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port
    | `drop_dm_object_name("All_Traffic")`
    | eval DetectionMethod="Malicious IP in Firewall Log", DeviceName=dvc, AccountName="N/A", Process="Firewall Traffic", CommandLine="N/A"
    | eval Indicator=if(in(src_ip, `malicious_ips_spl`), src_ip, dest_ip), IndicatorType="IP Address"
    | eval Details="Source: " + src_ip + ", Destination: " + dest_ip + ", Port: " + dest_port
    | fields _time, DetectionMethod, DeviceName, AccountName, Process, CommandLine, Indicator, IndicatorType, Details
]
```

crowdstrike fql:
```sql
(
  (event_simpleName=EmailEvent FileName IN ("*.rar", "*.7z", "*.gz") (Subject LIKE "*dhl*" OR Sender LIKE "*dhl*" OR Subject LIKE "*docusign*" OR Sender LIKE "*docusign*"))
  | project timestamp, DetectionMethod="Suspicious Archive Attachment", DeviceName="N/A", AccountName=Recipient, Process=Subject, CommandLine="N/A", Indicator=FileName, IndicatorType="Attachment", Details="Sender: " + Sender + ", Subject: " + Subject
)
UNION
(
  event_simpleName=ProcessRollup2 (TargetDomainName IN ("windhym.site", "bioccon.com", "hanhanggroup.com", "sprinterstravels.co.uk") OR TargetIPAddress IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203"))
  | stats min(timestamp) AS _time, count BY ComputerName, UserName, ImageFileName, CommandLine, TargetIPAddress, TargetDomainName
  | project _time, DetectionMethod="Malicious Network Connection", DeviceName=ComputerName, AccountName=UserName, Process=ImageFileName, CommandLine=CommandLine, Indicator=if(TargetDomainName IN ("windhym.site", "bioccon.com", "hanhanggroup.com", "sprinterstravels.co.uk"), TargetDomainName, TargetIPAddress), IndicatorType=if(TargetDomainName IN ("windhym.site", "bioccon.com", "hanhanggroup.com", "sprinterstravels.co.uk"), "Domain", "IP Address"), Details="RemoteIP: " + TargetIPAddress + ", RemoteUrl: " + TargetDomainName
)
UNION
(
  event_simpleName=DnsRequest (QueryName IN ("windhym.site", "bioccon.com", "hanhanggroup.com", "sprinterstravels.co.uk") OR ResponseIPAddress IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203"))
  | stats min(timestamp) AS _time, count BY ComputerName, ProcessName, QueryName, ResponseIPAddress
  | project _time, DetectionMethod="Malicious DNS Activity", DeviceName=ComputerName, AccountName="N/A", Process=ProcessName, CommandLine="N/A", Indicator=QueryName, IndicatorType="Domain", Details="Query: " + QueryName + ", Response: " + ResponseIPAddress
)
UNION
(
  event_simpleName=EmailEvent (SenderDomain IN ("windhym.site", "bioccon.com", "hanhanggroup.com", "sprinterstravels.co.uk") OR SourceIPAddress IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203"))
  | project timestamp AS _time, DetectionMethod="Email from Malicious Infrastructure", DeviceName="N/A", AccountName=Recipient, Process=Subject, CommandLine="N/A", Indicator=Sender, IndicatorType="Sender", Details="Sender: " + Sender + ", ConnectingIP: " + SourceIPAddress
)
UNION
(
  event_simpleName=EmailEvent Url LIKE ("*windhym.site*", "*bioccon.com*", "*hanhanggroup.com*", "*sprinterstravels.co.uk*")
  | project timestamp AS _time, DetectionMethod="Malicious URL in Email", DeviceName="N/A", AccountName=Recipient, Process=Subject, CommandLine="N/A", Indicator=Url, IndicatorType="URL", Details="Sender: " + Sender + ", Subject: " + Subject
)
UNION
(
  event_simpleName=NetworkConnect (SourceIPAddress IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203") OR DestinationIPAddress IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203"))
  | stats min(timestamp) AS _time, count BY DeviceName, SourceIPAddress, DestinationIPAddress, DestinationPort
  | project _time, DetectionMethod="Malicious IP in Firewall Log", DeviceName=DeviceName, AccountName="N/A", Process="Firewall Traffic", CommandLine="N/A", Indicator=if(SourceIPAddress IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203"), SourceIPAddress, DestinationIPAddress), IndicatorType="IP Address", Details="Source: " + SourceIPAddress + ", Destination: " + DestinationIPAddress + ", Port: " + DestinationPort
)
```

datadog:
```sql
(
  source:email FileName:(*.rar OR *.7z OR *.gz) (Subject:*dhl* OR Sender:*dhl* OR Subject:*docusign* OR Sender:*docusign*)
  | select @timestamp as _time, "Suspicious Archive Attachment" as DetectionMethod, "N/A" as DeviceName, Recipient as AccountName, Subject as Process, "N/A" as CommandLine, FileName as Indicator, "Attachment" as IndicatorType, "Sender: " + Sender + ", Subject: " + Subject as Details
)
OR
(
  source:endpoint (TargetDomain:(windhym.site OR bioccon.com OR hanhanggroup.com OR sprinterstravels.co.uk) OR TargetIp:(79.141.165.17 OR 185.81.114.43 OR 185.117.90.49 OR 185.80.53.203))
  | stats min(@timestamp) as _time, count by host as DeviceName, UserName as AccountName, ProcessName as Process, ProcessCommandLine as CommandLine, TargetIp, TargetDomain
  | select _time, "Malicious Network Connection" as DetectionMethod, DeviceName, AccountName, Process, CommandLine, if(TargetDomain IN (windhym.site, bioccon.com, hanhanggroup.com, sprinterstravels.co.uk), TargetDomain, TargetIp) as Indicator, if(TargetDomain IN (windhym.site, bioccon.com, hanhanggroup.com, sprinterstravels.co.uk), "Domain", "IP Address") as IndicatorType, "RemoteIP: " + TargetIp + ", RemoteUrl: " + TargetDomain as Details
)
OR
(
  source:dns (Query:(windhym.site OR bioccon.com OR hanhanggroup.com OR sprinterstravels.co.uk) OR ResponseIp:(79.141.165.17 OR 185.81.114.43 OR 185.117.90.49 OR 185.80.53.203))
  | stats min(@timestamp) as _time, count by host as DeviceName, ProcessName as Process, Query, ResponseIp
  | select _time, "Malicious DNS Activity" as DetectionMethod, DeviceName, "N/A" as AccountName, Process, "N/A" as CommandLine, Query as Indicator, "Domain" as IndicatorType, "Query: " + Query + ", Response: " + ResponseIp as Details
)
OR
(
  source:email (SenderDomain:(windhym.site OR bioccon.com OR hanhanggroup.com OR sprinterstravels.co.uk) OR SourceIp:(79.141.165.17 OR 185.81.114.43 OR 185.117.90.49 OR 185.80.53.203))
  | select @timestamp as _time, "Email from Malicious Infrastructure" as DetectionMethod, "N/A" as DeviceName, Recipient as AccountName, Subject as Process, "N/A" as CommandLine, Sender as Indicator, "Sender" as IndicatorType, "Sender: " + Sender + ", ConnectingIP: " + SourceIp as Details
)
OR
(
  source:email Url:(*windhym.site* OR *bioccon.com* OR *hanhanggroup.com* OR *sprinterstravels.co.uk*)
  | select @timestamp as _time, "Malicious URL in Email" as DetectionMethod, "N/A" as DeviceName, Recipient as AccountName, Subject as Process, "N/A" as CommandLine, Url as Indicator, "URL" as IndicatorType, "Sender: " + Sender + ", Subject: " + Subject as Details
)
OR
(
  source:firewall (SourceIp:(79.141.165.17 OR 185.81.114.43 OR 185.117.90.49 OR 185.80.53.203) OR DestinationIp:(79.141.165.17 OR 185.81.114.43 OR 185.117.90.49 OR 185.80.53.203))
  | stats min(@timestamp) as _time, count by DeviceName, SourceIp, DestinationIp, DestinationPort
  | select _time, "Malicious IP in Firewall Log" as DetectionMethod, DeviceName, "N/A" as AccountName, "Firewall Traffic" as Process, "N/A" as CommandLine, if(SourceIp IN (79.141.165.17, 185.81.114.43, 185.117.90.49, 185.80.53.203), SourceIp, DestinationIp) as Indicator, "IP Address" as IndicatorType, "Source: " + SourceIp + ", Destination: " + DestinationIp + ", Port: " + DestinationPort as Details
)
```

elastic:
```sql
(
  FROM logs-email-*
  | WHERE email.attachment.file.name IN ("*.rar", "*.7z", "*.gz")
    AND (email.subject LIKE "*dhl*" OR email.from.address LIKE "*dhl*" OR email.subject LIKE "*docusign*" OR email.from.address LIKE "*docusign*")
  | EVAL DetectionMethod = "Suspicious Archive Attachment", DeviceName = "N/A", AccountName = email.to.address,
         Process = email.subject, CommandLine = "N/A", Indicator = email.attachment.file.name,
         IndicatorType = "Attachment", Details = "Sender: " + email.from.address + ", Subject: " + email.subject
  | KEEP @timestamp, DetectionMethod, DeviceName, AccountName, Process, CommandLine, Indicator, IndicatorType, Details
)
UNION
(
  FROM logs-endpoint.events.process-*
  | WHERE destination.domain IN ("windhym.site", "bioccon.com", "hanhanggroup.com", "sprinterstravels.co.uk")
    OR destination.ip IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203")
  | STATS _time = MIN(@timestamp), count = COUNT(*)
    BY host.hostname AS DeviceName, user.name AS AccountName, process.name AS Process, process.command_line AS CommandLine, destination.ip, destination.domain
  | EVAL DetectionMethod = "Malicious Network Connection",
         Indicator = CASE(destination.domain IN ("windhym.site", "bioccon.com", "hanhanggroup.com", "sprinterstravels.co.uk"), destination.domain, destination.ip),
         IndicatorType = CASE(destination.domain IN ("windhym.site", "bioccon.com", "hanhanggroup.com", "sprinterstravels.co.uk"), "Domain", "IP Address"),
         Details = "RemoteIP: " + destination.ip + ", RemoteUrl: " + destination.domain
  | KEEP _time, DetectionMethod, DeviceName, AccountName, Process, CommandLine, Indicator, IndicatorType, Details
)
UNION
(
  FROM logs-endpoint.events.network-*
  | WHERE dns.question.name IN ("windhym.site", "bioccon.com", "hanhanggroup.com", "sprinterstravels.co.uk")
    OR dns.answer IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203")
  | STATS _time = MIN(@timestamp), count = COUNT(*)
    BY host.hostname AS DeviceName, process.name AS Process, dns.question.name AS query, dns.answer
  | EVAL DetectionMethod = "Malicious DNS Activity", AccountName = "N/A", CommandLine = "N/A",
         Indicator = query, IndicatorType = "Domain", Details = "Query: " + query + ", Response: " + dns.answer
  | KEEP _time, DetectionMethod, DeviceName, AccountName, Process, CommandLine, Indicator, IndicatorType, Details
)
UNION
(
  FROM logs-email-*
  | WHERE email.from.domain IN ("windhym.site", "bioccon.com", "hanhanggroup.com", "sprinterstravels.co.uk")
    OR source.ip IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203")
  | EVAL DetectionMethod = "Email from Malicious Infrastructure", DeviceName = "N/A", AccountName = email.to.address,
         Process = email.subject, CommandLine = "N/A", Indicator = email.from.address,
         IndicatorType = "Sender", Details = "Sender: " + email.from.address + ", ConnectingIP: " + source.ip
  | KEEP @timestamp AS _time, DetectionMethod, DeviceName, AccountName, Process, CommandLine, Indicator, IndicatorType, Details
)
UNION
(
  FROM logs-email-*
  | WHERE email.url LIKE ("*windhym.site*" OR "*bioccon.com*" OR "*hanhanggroup.com*" OR "*sprinterstravels.co.uk*")
  | EVAL DetectionMethod = "Malicious URL in Email", DeviceName = "N/A", AccountName = email.to.address,
         Process = email.subject, CommandLine = "N/A", Indicator = email.url,
         IndicatorType = "URL", Details = "Sender: " + email.from.address + ", Subject: " + email.subject
  | KEEP @timestamp AS _time, DetectionMethod, DeviceName, AccountName, Process, CommandLine, Indicator, IndicatorType, Details
)
UNION
(
  FROM logs-network-traffic.firewall-*
  | WHERE source.ip IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203")
    OR destination.ip IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203")
  | STATS _time = MIN(@timestamp), count = COUNT(*)
    BY host.hostname AS DeviceName, source.ip, destination.ip, destination.port
  | EVAL DetectionMethod = "Malicious IP in Firewall Log", AccountName = "N/A", Process = "Firewall Traffic",
         CommandLine = "N/A", Indicator = CASE(source.ip IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203"), source.ip, destination.ip),
         IndicatorType = "IP Address", Details = "Source: " + source.ip + ", Destination: " + destination.ip + ", Port: " + destination.port
  | KEEP _time, DetectionMethod, DeviceName, AccountName, Process, CommandLine, Indicator, IndicatorType, Details
)
```

sentinel one:
```sql
(
  EventType = "Email Received" AND FileName IN ("*.rar", "*.7z", "*.gz")
  AND (Subject LIKE "%dhl%" OR Sender LIKE "%dhl%" OR Subject LIKE "%docusign%" OR Sender LIKE "%docusign%")
  | SELECT Timestamp AS _time, "Suspicious Archive Attachment" AS DetectionMethod, "N/A" AS DeviceName,
          Recipient AS AccountName, Subject AS Process, "N/A" AS CommandLine,
          FileName AS Indicator, "Attachment" AS IndicatorType,
          "Sender: " + Sender + ", Subject: " + Subject AS Details
)
UNION
(
  EventType = "Process Creation"
  AND (TargetDomain IN ("windhym.site", "bioccon.com", "hanhanggroup.com", "sprinterstravels.co.uk")
       OR TargetIPAddress IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203"))
  | SELECT MIN(Timestamp) AS _time, COUNT(*) AS count,
          EndpointName AS DeviceName, UserName AS AccountName, ProcessName AS Process,
          ProcessCommandLine AS CommandLine, TargetIPAddress, TargetDomain
  | SELECT _time, "Malicious Network Connection" AS DetectionMethod, DeviceName, AccountName, Process, CommandLine,
          IF(TargetDomain IN ("windhym.site", "bioccon.com", "hanhanggroup.com", "sprinterstravels.co.uk"), TargetDomain, TargetIPAddress) AS Indicator,
          IF(TargetDomain IN ("windhym.site", "bioccon.com", "hanhanggroup.com", "sprinterstravels.co.uk"), "Domain", "IP Address") AS IndicatorType,
          "RemoteIP: " + TargetIPAddress + ", RemoteUrl: " + TargetDomain AS Details
)
UNION
(
  EventType = "DNS Query"
  AND (QueryName IN ("windhym.site", "bioccon.com", "hanhanggroup.com", "sprinterstravels.co.uk")
       OR ResponseIPAddress IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203"))
  | SELECT MIN(Timestamp) AS _time, COUNT(*) AS count,
          EndpointName AS DeviceName, ProcessName AS Process, QueryName AS query, ResponseIPAddress
  | SELECT _time, "Malicious DNS Activity" AS DetectionMethod, DeviceName, "N/A" AS AccountName,
          Process, "N/A" AS CommandLine, query AS Indicator, "Domain" AS IndicatorType,
          "Query: " + query + ", Response: " + ResponseIPAddress AS Details
)
UNION
(
  EventType = "Email Received"
  AND (SenderDomain IN ("windhym.site", "bioccon.com", "hanhanggroup.com", "sprinterstravels.co.uk")
       OR SourceIPAddress IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203"))
  | SELECT Timestamp AS _time, "Email from Malicious Infrastructure" AS DetectionMethod, "N/A" AS DeviceName,
          Recipient AS AccountName, Subject AS Process, "N/A" AS CommandLine,
          Sender AS Indicator, "Sender" AS IndicatorType,
          "Sender: " + Sender + ", ConnectingIP: " + SourceIPAddress AS Details
)
UNION
(
  EventType = "Email Received" AND Url LIKE ("%windhym.site%" OR "%bioccon.com%" OR "%hanhanggroup.com%" OR "%sprinterstravels.co.uk%")
  | SELECT Timestamp AS _time, "Malicious URL in Email" AS DetectionMethod, "N/A" AS DeviceName,
          Recipient AS AccountName, Subject AS Process, "N/A" AS CommandLine,
          Url AS Indicator, "URL" AS IndicatorType,
          "Sender: " + Sender + ", Subject: " + Subject AS Details
)
UNION
(
  EventType = "Network Connection"
  AND (SourceIPAddress IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203")
       OR DestinationIPAddress IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203"))
  | SELECT MIN(Timestamp) AS _time, COUNT(*) AS count,
          EndpointName AS DeviceName, SourceIPAddress, DestinationIPAddress, DestinationPort
  | SELECT _time, "Malicious IP in Firewall Log" AS DetectionMethod, DeviceName, "N/A" AS AccountName,
          "Firewall Traffic" AS Process, "N/A" AS CommandLine,
          IF(SourceIPAddress IN ("79.141.165.17", "185.81.114.43", "185.117.90.49", "185.80.53.203"), SourceIPAddress, DestinationIPAddress) AS Indicator,
          "IP Address" AS IndicatorType,
          "Source: " + SourceIPAddress + ", Destination: " + DestinationIPAddress + ", Port: " + DestinationPort AS Details
)
```

### Process Injection / RegAsm.exe
---

Name: Process Injection into RegAsm.exe

Author: RW

Date: 2025-08-12

MITRE ATT&CK: T1055

Description:

Detects process injection activity targeting the legitimate .NET Assembly Registration Tool (RegAsm.exe).

This technique is used by infostealers like Nova to evade defenses by running malicious code within the address space of a trusted Microsoft utility.

False Positive Sensitivity: Medium.

Legitimate applications, particularly security software or system management tools, may perform process injection. Tuning may be required by excluding trusted parent processes or signers specific to your environment.

splunk:
```sql
-- Required Data: Sysmon Event ID 8
`comment("This query uses Sysmon Event ID 8 (CreateRemoteThread) to detect process injection.")`
(index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=8)
-- The target of the injection is RegAsm.exe
| search TargetImage="*\\regasm.exe"
-- Exclude self-injection, which is typically not malicious
| where SourceProcessGuid!=TargetProcessGuid
-- Exclude injections from common legitimate system locations to reduce noise.
| where NOT (like(SourceImage, "C:\\Windows\\System32\\%"))
-- Further reduce false positives by focusing on suspicious initiators
| where ( \
    `comment("The injecting process is running from a common temporary or user-writable location")` \
    (like(SourceImage, "C:\\Users\\%") OR like(SourceImage, "%\\AppData\\%") OR like(SourceImage, "C:\\ProgramData\\%") OR like(SourceImage, "C:\\Windows\\Temp\\%")) \
    OR \
    `comment("Or the injecting process is not signed by a trusted authority")` \
    (SignatureStatus!="Valid") \
    )
-- Format the results for readability and analyst investigation
| table _time, host, User, SourceImage, SourceProcessGuid, Signature, SignatureStatus, TargetImage, TargetProcessGuid, StartAddress
| rename \
    host as DeviceName, \
    User as AccountName, \
    SourceImage as InjectingProcess, \
    SourceProcessGuid as InjectingProcessGuid, \
    TargetImage as TargetProcess, \
    TargetProcessGuid as TargetProcessGuid, \
    Signature as InjectingProcessSigner, \
    SignatureStatus as InjectingProcessSignerStatus, \
    StartAddress as InjectedStartAddress
```

crowdstrike fql:
```sql
event_simpleName=CreateRemoteThreadEvent EventID=8 TargetImage LIKE "*\\regasm.exe"
| filter SourceProcessGuid != TargetProcessGuid
| filter SourceImage !LIKE "C:\\Windows\\System32\\%"
| filter (
    (SourceImage LIKE "C:\\Users\\%" OR SourceImage LIKE "%\\AppData\\%" OR SourceImage LIKE "C:\\ProgramData\\%" OR SourceImage LIKE "C:\\Windows\\Temp\\%") OR
    SignatureStatus != "Valid"
)
| project timestamp, ComputerName, UserName, SourceImage, SourceProcessGuid, Signature, SignatureStatus, TargetImage, TargetProcessGuid, StartAddress
| rename ComputerName="DeviceName", UserName="AccountName", SourceImage="InjectingProcess", SourceProcessGuid="InjectingProcessGuid", TargetImage="TargetProcess", TargetProcessGuid="TargetProcessGuid", Signature="InjectingProcessSigner", SignatureStatus="InjectingProcessSignerStatus", StartAddress="InjectedStartAddress"
```

datadog:
```sql
source:sysmon EventId:8 TargetImage:*\\regasm.exe -SourceProcessGuid:TargetProcessGuid -SourceImage:C:\\Windows\\System32\\* (SourceImage:(C:\\Users\\* OR *\\AppData\\* OR C:\\ProgramData\\* OR C:\\Windows\\Temp\\*) OR SignatureStatus:-Valid)
| select @timestamp as _time, host as DeviceName, UserName as AccountName, SourceImage as InjectingProcess, SourceProcessGuid as InjectingProcessGuid, Signature as InjectingProcessSigner, SignatureStatus as InjectingProcessSignerStatus, TargetImage as TargetProcess, TargetProcessGuid as TargetProcessGuid, StartAddress as InjectedStartAddress
```

elastic:
```sql
FROM logs-sysmon-*
| WHERE event.code == "8" AND process.target.executable LIKE "*\\regasm.exe"
  AND process.source.entity_id != process.target.entity_id
  AND NOT process.source.executable LIKE "C:\\Windows\\System32\\*"
  AND (
      (process.source.executable LIKE "C:\\Users\\*" OR
       process.source.executable LIKE "*\\AppData\\*" OR
       process.source.executable LIKE "C:\\ProgramData\\*" OR
       process.source.executable LIKE "C:\\Windows\\Temp\\*") OR
      file.signature.status != "Valid"
  )
| KEEP @timestamp, host.hostname, user.name, process.source.executable, process.source.entity_id, file.signature.issuer_name, file.signature.status, process.target.executable, process.target.entity_id, process.thread.start_address
| EVAL DeviceName = host.hostname,
       AccountName = user.name,
       InjectingProcess = process.source.executable,
       InjectingProcessGuid = process.source.entity_id,
       InjectingProcessSigner = file.signature.issuer_name,
       InjectingProcessSignerStatus = file.signature.status,
       TargetProcess = process.target.executable,
       TargetProcessGuid = process.target.entity_id,
       InjectedStartAddress = process.thread.start_address
| DROP host.hostname, user.name, process.source.executable, process.source.entity_id, file.signature.issuer_name, file.signature.status, process.target.executable, process.target.entity_id, process.thread.start_address
```

sentinel one:
```sql
EventType = "Sysmon CreateRemoteThread" AND EventID = 8 AND TargetImage LIKE "%\\regasm.exe"
AND SourceProcessGuid != TargetProcessGuid
AND SourceImage NOT LIKE "C:\\Windows\\System32\\%"
AND (
    (SourceImage LIKE "%C:\\Users\\%" OR SourceImage LIKE "%\\AppData\\%" OR SourceImage LIKE "%C:\\ProgramData\\%" OR SourceImage LIKE "%C:\\Windows\\Temp\\%")
    OR SignatureStatus != "Valid"
)
| SELECT Timestamp AS _time,
         EndpointName AS DeviceName,
         UserName AS AccountName,
         SourceImage AS InjectingProcess,
         SourceProcessGuid AS InjectingProcessGuid,
         Signature AS InjectingProcessSigner,
         SignatureStatus AS InjectingProcessSignerStatus,
         TargetImage AS TargetProcess,
         TargetProcessGuid AS TargetProcessGuid,
         StartAddress AS InjectedStartAddress
```