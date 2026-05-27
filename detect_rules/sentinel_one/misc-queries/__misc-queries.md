## Miscellaneous Queries

### Malicious VSCode Extension Activity Detection
---
```sql
-- Name: Malicious VSCode Extension Activity
-- Author: RW
-- Date: 2025-08-20
-- Description: This search combines multiple detection techniques for malicious Visual Studio Code extension activity. It looks for extension installation via URI handlers or the command line, suspicious network connections from VSCode, file writes to extension directories, and the loading of unusual Node modules. These activities can indicate an attacker using VSCode for initial access or persistence.

SELECT EventTime AS timestamp, EndpointName AS dest, UserName AS user, SrcProcParentCmdLine AS parent_process, SrcProcName AS actor_process_name, SrcProcCmdLine AS actor_process,
  CASE
    WHEN SrcProcName = 'Code.exe' AND SrcProcCmdLine LIKE '%--open-url%' AND SrcProcCmdLine LIKE '%vscode://%' THEN 'VSCode URI Handler Installation'
    WHEN SrcProcName = 'Code.exe' AND SrcProcCmdLine LIKE '%--install-extension%' AND SrcProcCmdLine LIKE '%.vsix%' THEN 'VSCode Extension CLI Installation'
    WHEN SrcProcName = 'Code.exe' AND NetworkUrl IS NOT NULL AND NetworkUrl NOT LIKE '%marketplace.visualstudio.com%' AND NetworkUrl NOT LIKE '%vscode.blob.core.windows.net%' AND NetworkUrl NOT LIKE '%update.code.visualstudio.com%' AND NetworkUrl NOT LIKE '%gallerycdn.vsassets.io%' THEN 'Suspicious Outbound Connection from VSCode'
    WHEN TgtFilePath LIKE '%\.vscode\extensions\%' OR TgtFilePath LIKE '%\Microsoft VS Code\resources\app\extensions\%' THEN 'File Write to VSCode Extension Directory'
    WHEN SrcProcName = 'Code.exe' AND LoadedModuleName LIKE '%.node' AND (LoadedModulePath LIKE '%\AppData\Local%' OR LoadedModulePath LIKE '%\Temp%') AND LoadedModulePath NOT LIKE '%\.vscode\extensions%' AND LoadedModulePath NOT LIKE '%Microsoft VS Code%' THEN 'Suspicious Node Module Loaded by VSCode'
  END AS detection_method,
  CASE
    WHEN detection_method = 'VSCode URI Handler Installation' THEN 'URI Command: ' || SrcProcCmdLine
    WHEN detection_method = 'VSCode Extension CLI Installation' THEN 'Install Command: ' || SrcProcCmdLine
    WHEN detection_method = 'Suspicious Outbound Connection from VSCode' THEN 'Destination: ' || NetworkUrl
    WHEN detection_method = 'File Write to VSCode Extension Directory' THEN 'File: ' || TgtFilePath || TgtFileName
    WHEN detection_method = 'Suspicious Node Module Loaded by VSCode' THEN 'Module: ' || LoadedModulePath || LoadedModuleName
  END AS details
FROM deep_visibility
WHERE detection_method IS NOT NULL AND (
  (EventType = 'Process Start' AND SrcProcName = 'Code.exe') OR
  (EventType = 'Network Connect' AND SrcProcName = 'Code.exe') OR
  (EventType = 'File Creation' AND TgtFilePath LIKE '%extensions%') OR
  (EventType = 'Module Load' AND SrcProcName = 'Code.exe')
)
ORDER BY timestamp DESC
LIMIT 1000
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

SELECT EventTime AS _time, UserName AS user, NetworkSrcIP AS src, NetworkDestDomain AS dest, NetworkUrlPath AS uri_path, NetworkHttpMethod AS http_method, NetworkHttpRequestBody AS form_data,
  IF(NetworkHttpMethod = 'POST' AND NetworkDestDomain LIKE '%.ru' AND NetworkUrlPath LIKE '%/[0-9]{5,6}.php' AND NetworkHttpRequestBody LIKE '%request=%%' AND NetworkHttpRequestBody LIKE '%session=%%', 'Salty 2FA Exfiltration', 'Salty 2FA Landing Page') AS detection_type
FROM deep_visibility
WHERE EventType = 'Network Connect' AND detection_type IS NOT NULL
ORDER BY _time DESC
LIMIT 1000
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

SELECT EndpointName AS dest, UserName AS user, COUNT(*) AS count, GROUP_CONCAT(DISTINCT SrcProcName) AS processes_observed, GROUP_CONCAT(DISTINCT SrcProcCmdLine) AS process_command_lines, GROUP_CONCAT(DISTINCT SrcProcParentName) AS parent_processes, GROUP_CONCAT(DISTINCT SHA256) AS matched_hashes, GROUP_CONCAT(DISTINCT DnsRequestDomainName) AS dns_queries, GROUP_CONCAT(DISTINCT NetworkDestIP) AS destination_ips, MIN(EventTime) AS first_seen, MAX(EventTime) AS last_seen,
  CASE
    WHEN SHA256 IS NOT NULL THEN 'IOC Match: Known QuirkyLoader file hash detected.'
    WHEN DnsRequestDomainName IS NOT NULL OR NetworkDestIP IS NOT NULL THEN 'IOC Match: Network connection to QuirkyLoader C2 detected.'
    WHEN SrcProcName IN ('AddInProcess32.exe', 'InstallUtil.exe', 'aspnet_wp.exe') THEN 'TTP Match: Execution of a known QuirkyLoader process hollowing target.'
  END AS detection_reason
FROM deep_visibility
WHERE (
  (EventType = 'Process Start' AND SrcProcName IN ('AddInProcess32.exe', 'InstallUtil.exe', 'aspnet_wp.exe')) OR
  (EventType IN ('Process Start', 'File Creation') AND SHA256 IN ('011257eb766f253982b717b390fc36eb570473ed7805c18b101367c68af5', '0ea3a55141405ee0e2dfbf333de01fe93c12cf34555550e4f7bb3fdec2a7673b', /* list all */)) OR
  (EventType = 'DNS Query' AND DnsRequestDomainName IN ('catherinereynolds.info', 'mail.catherinereynolds.info')) OR
  (EventType = 'Network Connect' AND NetworkDestIP IN ('157.66.22.11', '103.75.77.90', '161.248.178.212'))
)
GROUP BY dest, user
ORDER BY count DESC
LIMIT 1000
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

SELECT STRFTIME(EventTime, '%Y-%m-%d %H:%M:%S') AS timestamp,
  CASE
    WHEN SHA256 IN ('dc54117b965674bad3d7cd203ecf5e7fc822423a3f692895cf5e96e83fb88f6a', '4843429e2e8871847bc1e97a0f12fa1f4166baa4735dff585cb3b4736e3fe49e', '297ea881aa2b39461997baf75d83b390f2c36a9a0a4815c81b5cf8be42840fd1') THEN 'PipeMagic File Hash IOC'
    WHEN EventType = 'Pipe Created' AND PipeName LIKE '\\.\\pipe\\1\\.[0-9a-fA-F]{32}' THEN 'PipeMagic Named Pipe'
    WHEN EventType = 'Network Connect' AND (NetworkDestDomain = 'aaaaabbbbbbb.eastus.cloudapp.azure.com' OR NetworkDestIP = '127.0.0.1') AND NetworkDestPort IN ('443', '8082') THEN 'PipeMagic C2 Connection'
    WHEN NetworkUrl LIKE '%/[a-fA-F0-9]{16}' AND NetworkHttpHeaders LIKE '%Upgrade: websocket%' AND NetworkHttpHeaders LIKE '%Connection: Upgrade%' THEN 'PipeMagic C2 HTTP Pattern'
    WHEN EventType = 'Process Start' AND SrcProcName = 'certutil.exe' AND SrcProcCmdLine LIKE '%-urlcache%' AND SrcProcCmdLine LIKE '%-f%' AND (SrcProcCmdLine LIKE '%.tmp%' OR SrcProcCmdLine LIKE '%.dat%' OR SrcProcCmdLine LIKE '%.msbuild%') THEN 'PipeMagic Certutil Download'
    WHEN EventType = 'Process Start' AND SrcProcParentName = 'msbuild.exe' AND SrcProcCmdLine LIKE '%.mshi%' THEN 'PipeMagic MSBuild Execution'
    WHEN EventType = 'Process Access' AND TgtProcName LIKE '%lsass.exe' AND SrcProcName LIKE '%dllhost.exe' THEN 'PipeMagic LSASS Access'
  END AS detection_clause,
  EndpointName AS host, UserName AS user, SrcProcName AS process_name, SrcProcParentName AS parent_process_name, SrcProcCmdLine AS command_line, SHA256 AS file_hash, NetworkDestDomain AS dest_host, NetworkDestIP AS dest_ip, NetworkDestPort AS dest_port, PipeName AS pipe_name, SrcProcImagePath AS source_image, TgtProcImagePath AS target_image
FROM deep_visibility
WHERE detection_clause IS NOT NULL
ORDER BY timestamp DESC
LIMIT 1000
```

### ESXi Host Suspicious Activity Detection (Recon, Privilege Escalation, Exfil, Evasion)
---
```sql
SELECT MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime, GROUP_CONCAT(DISTINCT details) AS activity_details, COUNT(*) AS count, EndpointName AS esxi_host, UserName AS user, tactic_description
FROM (
  SELECT EventTime, EndpointName, UserName,
    REGEXP_REPLACE(Message, 'shell\\[\\d+\\]: \\[([^\\]]+)\\]: (.+)', '\\2') AS command,
    REGEXP_REPLACE(Message, 'root@(\\d{1,3}(?:\\.\\d{1,3}){3})', '\\1') AS src_ip,
    CASE
      WHEN Message LIKE '%esxcli system% get%' OR Message LIKE '%esxcli system% list%' THEN 'ESXi System Reconnaissance'
      WHEN Message LIKE '%root%logged in%' THEN 'External Root Login to ESXi UI'
      WHEN Message LIKE '%esxcli system permission set%role Admin%' THEN 'User Granted Admin Role on ESXi'
      WHEN Message LIKE '%esxcli software acceptance set%' THEN 'VIB Acceptance Level Tampering'
      WHEN Message LIKE '%SSH access has been enabled%' THEN 'SSH Enabled on ESXi Host'
      WHEN Message LIKE '%system settings encryption set%' AND (Message LIKE '%--require-secure-boot=0%' OR Message LIKE '%--require-exec-installed-only=0%' OR Message LIKE '%execInstalledOnly=false%') THEN 'ESXi Encryption Settings Modified'
      WHEN Message LIKE '%File download from path%was initiated from%' THEN 'VM Exported via Remote Tool'
      WHEN Message LIKE '%esxcli system auditrecords%' THEN 'ESXi Audit Tampering'
      WHEN Message LIKE '%syslog config set%esxcli%' OR Message LIKE '%Set called with key%Syslog.global.logHost%' OR Message LIKE '%Set called with key%Syslog.global.logdir%' THEN 'ESXi Syslog Tampering'
      WHEN Message LIKE '%NTPClock%system clock stepped%' THEN 'ESXi System Clock Manipulation'
    END AS tactic_description,
    CASE
      WHEN command IS NOT NULL THEN command
      WHEN src_ip IS NOT NULL THEN 'Login from ' || src_ip
      ELSE Message
    END AS details
  FROM deep_visibility
  WHERE EventType = 'Log Entry' AND tactic_description IS NOT NULL AND NOT (tactic_description = 'External Root Login to ESXi UI' AND (src_ip LIKE '10.%' OR src_ip LIKE '172.16-31.%' OR src_ip LIKE '192.168.%' OR src_ip = '127.0.0.1' OR src_ip IS NULL))
)
GROUP BY esxi_host, user, tactic_description
ORDER BY count DESC
LIMIT 1000
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

SELECT EventTime AS _time, EndpointName AS dest, UserName AS user, SrcProcName AS process_name, NetworkDestIP AS dest_ip, GROUP_CONCAT(DISTINCT SrcProcCmdLine) AS process, GROUP_CONCAT(DISTINCT SHA256) AS file_hash, GROUP_CONCAT(DISTINCT NetworkUrl) AS url, GROUP_CONCAT(DISTINCT NetworkHttpUserAgent) AS http_user_agent
FROM deep_visibility
WHERE (
  (EventType IN ('Process Start', 'File Creation') AND SHA256 IN ('202f6b6631ade2c41e4762b5877ce0063a3beabce0c3f8564b6499a1164c1e04', /* list all */)) OR
  (EventType = 'Network Connect' AND NetworkDestIP IN ('173.44.141.89', '80.77.23.48', '62.60.226.73', '107.158.128.45', '170.130.165.112', '107.158.128.105')) OR
  (EventType = 'Network Connect' AND (NetworkUrl LIKE '%mhousecreative.com%' OR NetworkUrl LIKE '%google.herionhelpline.com%' OR NetworkUrl LIKE '%/service/%' OR NetworkUrl LIKE '%/c91252f9ab114f26.php')) OR
  (EventType = 'Network Connect' AND NetworkHttpUserAgent LIKE '%Googlebot%' AND NetworkDestIP IN ('173.44.141.89', '80.77.23.48', '62.60.226.73', '107.158.128.45')) OR
  (EventType = 'Process Start' AND SrcProcName = 'schtasks.exe' AND SrcProcCmdLine LIKE '%/create%' AND SrcProcCmdLine LIKE '%/sc%' AND SrcProcCmdLine LIKE '%onlogon%')
)
GROUP BY _time, dest, user, process_name, dest_ip
ORDER BY _time DESC
LIMIT 1000
```

### Quasar RAT Indicators: Process, File, and Network Activity
---
```sql
SELECT MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime, GROUP_CONCAT(DISTINCT detection_rationale) AS detection_rationale, GROUP_CONCAT(DISTINCT details) AS details, EndpointName AS dest, UserName AS user, SrcProcName AS process_name, SrcProcParentName AS parent_process, SrcProcPID AS process_id, SrcProcParentPID AS parent_process_id, EventType AS detection_type
FROM (
  SELECT EventTime, EndpointName, UserName, SrcProcName, SrcProcParentName, SrcProcPID, SrcProcParentPID, EventType,
    CASE
      WHEN SrcProcCmdLine LIKE '%/rl % highest %' THEN 'Scheduled Task with Highest Privileges (T1055.005)'
      WHEN SrcProcName = 'shutdown.exe' THEN 'System Shutdown/Reboot Attempt (T1529)'
      WHEN SHA256 = '7300535ef26158bdb916b717390fc36eb570473ed7805c18b101367c68af5' THEN 'Known Quasar RAT Loader Hash'
      WHEN TgtFilePath LIKE '%FileZilla%' THEN 'Unusual FileZilla Config Access (T1552.001)'
      WHEN TgtFilePath LIKE '%Startup%.url' THEN 'Startup Folder URL Shortcut for Persistence (T1547.001)'
      WHEN TgtFileName LIKE '%:Zone.Identifier' THEN 'Mark-of-the-Web Bypass (T1553.005)'
      WHEN DnsRequestDomainName IN ('*wtfismyip.com', /* list all */) THEN 'Network Reconnaissance via IP Check Service (T1082)'
    END AS detection_rationale,
    CASE
      WHEN detection_rationale LIKE 'Scheduled%' THEN 'Action: ' || SrcProcCmdLine
      WHEN detection_rationale LIKE 'Unusual%' THEN 'Action: ' || EventType || ' on file ' || TgtFilePath
      WHEN detection_rationale LIKE 'Network%' THEN 'DNS Query: ' || DnsRequestDomainName
      ELSE SrcProcCmdLine
    END AS details
  FROM deep_visibility
  WHERE detection_rationale IS NOT NULL
)
GROUP BY dest, user, process_name, parent_process, process_id, parent_process_id, detection_type
ORDER BY firstTime DESC
LIMIT 1000
```

### Kerberoasting, AS-REP Roasting, DCSync, and AD DACL Modifications
---
```sql
SELECT EventTime AS _time, EndpointName AS host,
  CASE
    WHEN EventID = '5136' AND ObjectDN LIKE '%CN=AdminSDHolder,CN=System,%' THEN 'AdminSDHolder DACL Modification'
    WHEN EventID = '5136' THEN 'Malicious AD DACL Modification'
    WHEN EventID = '4769' THEN 'Potential Kerberoasting (RC4)'
    WHEN EventID = '4768' THEN 'Potential AS-REP Roasting'
    WHEN EventID = '4662' THEN 'Potential DCSync Attack'
  END AS rule_name,
  SubjectUserName AS Subject_Account_Name,
  COALESCE(ServiceName, TargetUserName, ObjectName, ObjectDN) AS Target_Object,
  CASE
    WHEN rule_name = 'AdminSDHolder DACL Modification' THEN 'Account ' || SubjectUserName || ' modified the DACL of the AdminSDHolder object.'
    WHEN rule_name = 'Malicious AD DACL Modification' THEN 'Account ' || SubjectUserName || ' granted high-privilege rights on object: ' || Target_Object
    WHEN rule_name = 'Potential Kerberoasting (RC4)' THEN 'Account ' || SubjectUserName || ' requested an RC4-encrypted service ticket for SPN: ' || Target_Object
    WHEN rule_name = 'Potential AS-REP Roasting' THEN 'TGT requested for account ' || Target_Object || ' which has pre-authentication disabled.'
    WHEN rule_name = 'Potential DCSync Attack' THEN 'Account ' || SubjectUserName || ' attempted a DCSync-style attack to replicate directory changes.'
    ELSE 'N/A'
  END AS Description
FROM deep_visibility
WHERE EventType = 'Event Log' AND Channel = 'Security' AND rule_name IS NOT NULL
ORDER BY _time DESC
LIMIT 1000
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

SELECT EventTime AS _time, 'Suspicious Interactive Logon by Entra Connect Account' AS activity, UserName AS user, NetworkSrcIP AS src_ip, AppDisplayName AS dest, 'User: ' || UserName || ' from IP: ' || NetworkSrcIP || ' to App: ' || AppDisplayName AS details
FROM deep_visibility
WHERE EventType = 'Sign In' AND (UserName LIKE '%AAD_%' OR UserName LIKE '%MSOL_%')
UNION
SELECT EventTime AS _time, 'Password Reset by Entra Connect Account' AS activity, InitiatedByUserPrincipalName AS user, NetworkSrcIP AS src_ip, TargetResourcesUserPrincipalName AS dest, 'Entra Connect account ' || InitiatedByUserPrincipalName || ' reset password for ' || TargetResourcesUserPrincipalName AS details
FROM deep_visibility
WHERE EventType = 'Audit' AND Action = 'Reset user password' AND Outcome = 'success' AND (InitiatedByUserPrincipalName LIKE '%AAD_%' OR InitiatedByUserPrincipalName LIKE '%MSOL_%')
UNION
SELECT EventTime AS _time, Action AS activity, InitiatedByUserPrincipalName AS user, NetworkSrcIP AS src_ip, TargetResourcesDisplayName AS dest, 'User ' || InitiatedByUserPrincipalName || ' performed action \'' || Action || '\' on application ' || TargetResourcesDisplayName AS details
FROM deep_visibility
WHERE EventType = 'Audit' AND Category = 'ApplicationManagement' AND Action IN ('Add service principal', 'Add OAuth2 permission grant', 'Add owner to service principal', 'Update application - Certificates and secrets management')
UNION
SELECT EventTime AS _time, 'Potential High-Volume Data Access' AS activity, UserName AS user, NetworkSrcIP AS src_ip, AppID AS dest, 'User ' || UserName || ' accessed ' || ObjectIDCount || ' items via ' || Action || ' using AppId ' || AppID AS details
FROM deep_visibility
WHERE EventType = 'Audit' AND Action IN ('MailItemsAccessed', 'FileDownloaded')
UNION
SELECT EventTime AS _time, 'Potential Web Shell Execution' AS activity, UserName AS user, NULL AS src_ip, EndpointName AS dest, 'Parent: ' || SrcProcParentImagePath || ' spawned Child: ' || SrcProcImagePath || '. Command: ' || SrcProcCmdLine AS details
FROM deep_visibility
WHERE EventType = 'Process Start' AND SrcProcParentName IN ('w3wp.exe', 'httpd.exe', 'nginx.exe', 'tomcat.exe') AND SrcProcName IN ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'sh', 'bash')
UNION
SELECT EventTime AS _time, 'Vulnerable Device Identified' AS activity, NULL AS user, NULL AS src_ip, EndpointName AS dest, 'Device ' || EndpointName || ' is vulnerable to ' || VulnerabilityID || ' (Plugin/Signature: ' || VulnerabilitySignature AS details
FROM deep_visibility
WHERE EventType = 'Vulnerability' AND VulnerabilityID IN ('CVE-2025-0282', 'CVE-2024-3400', 'CVE-2023-3519', 'CVE-2021-26855', 'CVE-2021-26857', 'CVE-2021-26858', 'CVE-2021-27065')
ORDER BY _time DESC
LIMIT 1000
```

### CORNFLAKE.V3 Backdoor Activity Detection
---
```sql
-- RW

-- This rule is designed to detect a wide range of activities associated with the CORNFLAKE.V3 backdoor, as detailed in observed/disseminated threat intelligence.

-- It combines multiple detection patterns covering execution, persistence, command and control, and post-exploitation behavior into a single query.

SELECT COUNT(*) AS count, MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime, GROUP_CONCAT(DISTINCT detection_reason) AS detection_reasons, GROUP_CONCAT(DISTINCT SrcProcParentImagePath) AS parent_process, GROUP_CONCAT(DISTINCT SrcProcImagePath) AS process, GROUP_CONCAT(DISTINCT SrcProcCmdLine) AS command_line, GROUP_CONCAT(DISTINCT RegistryPath) AS registry_path, GROUP_CONCAT(DISTINCT RegistryValue) AS registry_details, GROUP_CONCAT(DISTINCT NetworkDestIP) AS dest_ip, GROUP_CONCAT(DISTINCT NetworkDestDomain) AS dest_hostname, GROUP_CONCAT(DISTINCT MD5) AS file_hashes, EndpointName AS host, UserName AS user
FROM deep_visibility
WHERE (
  (EventType = 'Process Start' AND SrcProcParentName = 'powershell.exe' AND SrcProcImagePath LIKE '%\AppData\Roaming%' AND ((SrcProcName = 'node.exe' AND SrcProcCmdLine LIKE '%-e %') OR (SrcProcName = 'php.exe' AND SrcProcCmdLine LIKE '%-d %' AND SrcProcCmdLine LIKE '% 1'))) OR
  (EventType = 'Process Start' AND SrcProcParentImagePath LIKE '%\AppData\Roaming\%(node|php).exe' AND SrcProcImagePath LIKE '%\(cmd|powershell).exe' AND SrcProcCmdLine LIKE '%systeminfo%' OR SrcProcCmdLine LIKE '%tasklist%' OR SrcProcCmdLine LIKE '%arp -a%' OR SrcProcCmdLine LIKE '%nltest%' OR SrcProcCmdLine LIKE '%setspn%' OR SrcProcCmdLine LIKE '%whoami /all%' OR SrcProcCmdLine LIKE '%Get-LocalGroup%' OR SrcProcCmdLine LIKE '%KerberosRequestorSecurityToken%') OR
  (EventType = 'Registry Value Set' AND RegistryPath LIKE '%HKU%\Software\Microsoft\Windows\CurrentVersion\Run' AND RegistryValue LIKE '%AppData\Roaming\%(node|php).exe%') OR
  (EventType = 'Network Connect' AND (NetworkDestIP IN ('138.199.161.141', '159.69.3.151', '167.235.235.151', '128.140.120.188', '177.136.225.135') OR NetworkDestDomain IN ('varying-rentals-calgary-predict.trycloudflare.com', 'dnsmicrosoftds-data.com', 'windows-msg-as.live'))) OR
  (EventType IN ('Process Start', 'File Creation') AND MD5 IN ('04668c6f39b0a67c4bd73d5459f8c3a3', 'bcdffa955608e9463f272adca205c9e65592840d98dcb63155b9fa0324a88be2', 'ec82216a2b42114d23d59eecb876ccfc')) OR
  (EventType = 'Network Connect' AND SrcProcImagePath IN ('powershell.exe', 'mshta.exe') AND NetworkDestDomain IN ('nodejs.org', 'windows.php.net')) OR
  (EventType = 'Process Start' AND SrcProcImagePath = 'rundll32.exe' AND SrcProcCmdLine LIKE '%\AppData\Roaming\%.png%')
)
GROUP BY host, user
ORDER BY count DESC
LIMIT 1000
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

SELECT _time, detection_type, user, countries, description
FROM (
  /* Impossible Travel - Multi-Geo Login */
  SELECT EventTime AS _time, 'Impossible Travel - Multi-Geo Login' AS detection_type, UserName AS user, GROUP_CONCAT(DISTINCT NetworkSrcIPGeoCountry) AS countries, UserName || ' logged in from ' || COUNT(DISTINCT NetworkSrcIPGeoCountry) || ' countries: ' || GROUP_CONCAT(DISTINCT NetworkSrcIPGeoCountry) || ' within 4 hours.' AS description
  FROM deep_visibility
  WHERE EventType = 'Authentication' AND Outcome = 'success' AND NetworkSrcIPGeoCountry IS NOT NULL
  GROUP BY UserName, strftime(EventTime, '%Y-%m-%d %H') /* 4-hour span approximated */
  HAVING COUNT(DISTINCT NetworkSrcIPGeoCountry) > 1
  UNION
  /* Phishing Link Click */
  SELECT EventTime AS _time, 'Phishing Link Click' AS detection_type, UserName AS user, NULL AS countries, UserName || ' accessed a URL categorized as phishing/malware: ' || NetworkUrl AS description
  FROM deep_visibility
  WHERE EventType = 'Network Connect' AND VulnerabilityCategory IN ('Phishing & Fraud', 'Malware')
  UNION
  /* Suspicious TLD Visited */
  SELECT EventTime AS _time, 'Suspicious TLD Visited' AS detection_type, UserName AS user, NULL AS countries, UserName || ' visited a URL with a suspicious TLD: ' || NetworkUrl AS description
  FROM deep_visibility
  WHERE EventType = 'Network Connect' AND REGEXP_LIKE(NetworkUrl, 'https?://(?:[^/]+\.)?[^/]+\.(xyz|top|online|club|live|icu|gq|buzz)')
  UNION
  /* Suspicious Process Execution */
  SELECT EventTime AS _time, 'Suspicious Process Execution' AS detection_type, UserName AS user, NULL AS countries, UserName || ' executed a suspicious command on ' || EndpointName || ': ' || SrcProcCmdLine AS description
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND (
    (SrcProcName IN ('powershell.exe', 'pwsh.exe') AND SrcProcCmdLine LIKE '% -enc %' OR SrcProcCmdLine LIKE '% -encoded %' OR SrcProcCmdLine LIKE '% -w hidden %' OR SrcProcCmdLine LIKE '% IEX %' OR SrcProcCmdLine LIKE '% Invoke-Expression %') OR
    (SrcProcName = 'mshta.exe' AND SrcProcCmdLine LIKE '%http:%' OR SrcProcCmdLine LIKE '%https:%' OR SrcProcCmdLine LIKE '%javascript:%')
  )
  UNION
  /* New Service Created */
  SELECT EventTime AS _time, 'New Service Created' AS detection_type, UserName AS user, NULL AS countries, 'A new service \'' || ServiceName || '\' pointing to \'' || ServiceFileName || '\' was created on ' || EndpointName || ' by ' || UserName AS description
  FROM deep_visibility
  WHERE EventType = 'Event Log' AND EventID = '4697' AND Source = 'Microsoft-Windows-Security-Auditing'
  UNION
  /* New Scheduled Task Created */
  SELECT EventTime AS _time, 'New Scheduled Task Created' AS detection_type, UserName AS user, NULL AS countries, 'A new scheduled task \'' || REGEXP_REPLACE(Message, 'Task Scheduler registered task "([^"]+)"', '\1') || '\' was created on ' || EndpointName || ' by ' || UserName AS description
  FROM deep_visibility
  WHERE EventType = 'Event Log' AND EventID = '106' AND Source = 'Microsoft-Windows-TaskScheduler/Operational'
  UNION
  /* Cryptocurrency Site Visited */
  SELECT EventTime AS _time, 'Cryptocurrency Site Visited' AS detection_type, UserName AS user, NULL AS countries, UserName || ' accessed a cryptocurrency-related website: ' || NetworkUrl AS description
  FROM deep_visibility
  WHERE EventType = 'Network Connect' AND NetworkUrl LIKE '%binance.com%' OR NetworkUrl LIKE '%coinbase.com%' OR NetworkUrl LIKE '%kraken.com%' OR NetworkUrl LIKE '%kucoin.com%' OR NetworkUrl LIKE '%bybit.com%' OR NetworkUrl LIKE '%metamask.io%'
)
ORDER BY _time DESC
LIMIT 1000
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

SELECT EventTime AS _time, EndpointName AS host, UserName AS User,
  CASE
    WHEN EventType = 'Process Start' AND SHA256 IN ('c865f24e4b9b0855b8b559fc3769239b0aa6e8d680406616a13d9a36fbbc2d30', '7d0c9855167e7c19a67f800892e974c4387e1004b40efb25a2a1d25a99b03a10', 'b3e93bfef12678294d9944e61d90ca4aa03b7e3dae5e909c3b2166f122a14dad', 'da59d67ced88beae618b9d6c805f40385d0301d412b787e9f9c9559d00d2c880', '70ec2e65f77a940fd0b2b5c0a78a83646dec175836552622ad17fb974f1', '263ab8c9ec821ae573979ef2d5ad98cda5009a39e17398cd31b0fad98d862892') THEN 'Known SHELLTER-related hash'
    WHEN EventType = 'Network Connect' AND (NetworkDestIP IN ('185.156.72.80', '94.141.12.182') OR NetworkDestDomain = 'eaglekl.digital') THEN 'Known SHELLTER-related C2'
    WHEN EventType = 'Process Access' AND TgtProcImagePath LIKE '%\ntdll.dll' THEN 'Behavioral - NTDLL Remapping for Hook Evasion'
    WHEN EventType = 'Module Load' AND LoadedModuleName IN ('wininet.dll', 'crypt32.dll', 'advapi32.dll', 'urlmon.dll') THEN 'Behavioral - Suspicious Module Preloading'
  END AS DetectionMethod,
  CASE
    WHEN DetectionMethod LIKE 'Known SHELLTER-related hash' THEN 'Execution'
    WHEN DetectionMethod LIKE 'Known SHELLTER-related C2' THEN 'Command and Control'
    WHEN DetectionMethod LIKE 'Behavioral%' THEN 'Defense Evasion'
  END AS Tactic,
  CASE
    WHEN Tactic = 'Execution' THEN 'T1204'
    WHEN Tactic = 'Command and Control' THEN 'T1071'
    WHEN Tactic = 'Defense Evasion' THEN 'T1055'
  END AS Technique,
  REGEXP_REPLACE(SrcProcImagePath, '.*\\(.*)', '\\1') AS process_name,
  SrcProcImagePath AS process_path,
  SrcProcCmdLine AS process_command_line,
  SHA256 AS process_hash,
  NetworkDestIP AS dest_ip,
  NetworkDestDomain AS dest_domain,
  TgtProcImagePath AS target_path,
  GROUP_CONCAT(DISTINCT LoadedModuleName) AS loaded_modules,
  COUNT(DISTINCT LoadedModuleName) AS module_count
FROM deep_visibility
WHERE DetectionMethod IS NOT NULL
GROUP BY _time, host, User, SrcProcPID
HAVING module_count >= 3 OR module_count IS NULL
ORDER BY _time DESC
LIMIT 1000
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

SELECT MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime, EndpointName AS DeviceName, UserName AS user, Tactic, Technique, DetectionMethod, SrcProcName AS FileName, SrcProcCmdLine AS ProcessCommandLine, SrcProcParentName AS InitiatingProcess, SHA256 AS SHA256, RegistryPath AS RegistryKey, RegistryValueName AS RegistryValueName, RegistryValue AS RegistryValueData, NetworkSrcIP AS SourceIP, NetworkDestIP AS DestinationIP, NetworkDestDomain AS DestinationHost
FROM (
  /* Known Interlock hashes */
  SELECT EventTime, EndpointName, UserName, 'Execution' AS Tactic, 'T1204.002' AS Technique, 'Known Malicious Hash' AS DetectionMethod, SrcProcName, SrcProcCmdLine, SrcProcParentName, SHA256, NULL AS RegistryKey, NULL AS RegistryValueName, NULL AS RegistryValue, NULL AS SourceIP, NULL AS DestinationIP, NULL AS DestinationHost
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND SHA256 IN ('2acaa9856ee29337c06cc2858fd71b860f53219504e6756faa3812019b5df5a6', '0b47e53f2ada0555588aa8a6a4491e14d7b2528c9a829ebb6f7e9463963cd0e4', /* list all */)
  UNION
  /* Suspicious PowerShell execution patterns */
  SELECT EventTime, EndpointName, UserName, 'Execution' AS Tactic, 'T1059.001' AS Technique, 'Suspicious PowerShell Command' AS DetectionMethod, SrcProcName, SrcProcCmdLine, SrcProcParentName, SHA256, NULL, NULL, NULL, NULL, NULL, NULL
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND SrcProcName = 'powershell.exe' AND (SrcProcCmdLine LIKE '%irm %' OR SrcProcCmdLine LIKE '%iex %' OR SrcProcCmdLine LIKE '%Invoke-RestMethod%' OR SrcProcCmdLine LIKE '%Invoke-Expression%' OR SrcProcCmdLine LIKE '%-w h%' OR SrcProcCmdLine LIKE '%-windowstyle hidden%')
  UNION
  /* Persistence via known Interlock Registry Run Keys */
  SELECT EventTime, EndpointName, UserName, 'Persistence' AS Tactic, 'T1547.001' AS Technique, 'Registry Run Key Modification' AS DetectionMethod, NULL, NULL, NULL, NULL, RegistryPath, RegistryValueName, RegistryValue, NULL, NULL, NULL
  FROM deep_visibility
  WHERE EventType = 'Registry Value Set' AND RegistryPath LIKE '%\Software\Microsoft\Windows\CurrentVersion\Run%' AND RegistryValueName IN ('ChromeUpdater', '0neDrive')
  UNION
  /* C2 communication to known infrastructure or abused services */
  SELECT EventTime, EndpointName, UserName, 'Command and Control' AS Tactic, 'T1071.001' AS Technique, 'C2 Communication' AS DetectionMethod, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NetworkSrcIP, NetworkDestIP, NetworkDestDomain
  FROM deep_visibility
  WHERE EventType = 'Network Connect' AND (NetworkDestIP IN ('168.119.96.41', '95.217.22.175', /* list all */) OR NetworkDestDomain IN ('cluders.org', 'bronxy.cc', /* list all */) OR NetworkDestDomain LIKE '%trycloudflare.com%')
  UNION
  /* Scheduled task creation for persistence */
  SELECT EventTime, EndpointName, UserName, 'Persistence' AS Tactic, 'T1053.005' AS Technique, 'Scheduled Task Creation' AS DetectionMethod, SrcProcName, SrcProcCmdLine, SrcProcParentName, SHA256, NULL, NULL, NULL, NULL, NULL, NULL
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND SrcProcName = 'schtasks.exe' AND SrcProcCmdLine LIKE '%/create%' AND (SrcProcCmdLine LIKE '%/du 9999:59%' OR (SrcProcCmdLine LIKE '%BitLocker Encrypt All Drives%' AND SrcProcCmdLine LIKE '%\OneDriveCloud\taskhostw.exe%'))
)
GROUP BY firstTime, lastTime, DeviceName, user, Tactic, Technique, DetectionMethod, FileName, ProcessCommandLine, InitiatingProcess, SHA256, RegistryKey, RegistryValueName, RegistryValueData, SourceIP, DestinationIP, DestinationHost
ORDER BY firstTime DESC
LIMIT 1000
```

### Water Curse Threat Actor - Multi-Stage
---
```sql
-- This detection rule identifies multiple Tactics, Techniques, and Procedures (TTPs) associated with the Water Curse threat actor.
-- Water Curse leverages compromised GitHub repositories to distribute malware, targeting developers and cybersecurity professionals.
-- This rule detects the entire attack chain, from initial execution via malicious Visual Studio project files to defense evasion, persistence, and C2 communication.
-- Source: https://www.trendmicro.com/en_us/research/25/f/water-curse.html
-- RW

SELECT MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime, EndpointName AS dest, UserName AS user, Tactic, Technique, Activity, SrcProcParentName AS parent_process_name, SrcProcName AS process_name, SrcProcCmdLine AS process, TgtFilePath AS file_path, TgtFileName AS file_name, RegistryPath AS registry_path, RegistryValueName AS registry_value_name, NetworkUrl AS url, NetworkDestIP AS dest_ip
FROM (
  /* Initial execution via malicious Visual Studio project file */
  SELECT EventTime, EndpointName, UserName, 'Execution' AS Tactic, 'T1129' AS Technique, 'WaterCurse: Initial Execution via MSBuild' AS Activity, SrcProcParentName, SrcProcName, SrcProcCmdLine, NULL AS file_path, NULL AS file_name, NULL AS registry_path, NULL AS registry_value_name, NULL AS url, NULL AS dest_ip
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND SrcProcParentName = 'MSBuild.exe' AND SrcProcName = 'cmd.exe' AND SrcProcCmdLine LIKE '%/c%' AND SrcProcCmdLine LIKE '%.exec.cmd%' AND SrcProcCmdLine LIKE '%Temp\MSBuildTemp%'
  UNION
  /* Defense Evasion via PowerShell to disable Windows Defender and System Restore */
  SELECT EventTime, EndpointName, UserName, 'Defense Evasion' AS Tactic, 'T1562.001' AS Technique, 'WaterCurse: Defense Evasion via PowerShell' AS Activity, SrcProcParentName, SrcProcName, SrcProcCmdLine, NULL, NULL, NULL, NULL, NULL, NULL
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND SrcProcName = 'powershell.exe' AND (SrcProcCmdLine LIKE '%Set-MpPreference% -ExclusionPath%C:\\%' OR SrcProcCmdLine LIKE '%vssadmin%delete%shadows%/all%' OR SrcProcCmdLine LIKE '%Set-ItemProperty%HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore%DisableSR%')
  UNION
  /* UAC Bypass via ms-settings protocol handler hijack */
  SELECT EventTime, EndpointName, UserName, 'Privilege Escalation' AS Tactic, 'T1548.002' AS Technique, 'WaterCurse: UAC Bypass via ms-settings Hijack' AS Activity, NULL, NULL, NULL, NULL, NULL, RegistryPath, RegistryValueName, NULL, NULL
  FROM deep_visibility
  WHERE EventType = 'Registry Value Set' AND RegistryPath LIKE '%\Software\Classes\ms-settings\shell\open\command%' AND (RegistryValueName = '(Default)' OR RegistryValueName = 'DelegateExecute')
  UNION
  /* Persistence via unusually configured Scheduled Task */
  SELECT EventTime, EndpointName, UserName, 'Persistence' AS Tactic, 'T1053.005' AS Technique, 'WaterCurse: Persistence via Scheduled Task' AS Activity, SrcProcParentName, SrcProcName, SrcProcCmdLine, NULL, NULL, NULL, NULL, NULL, NULL
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND SrcProcName = 'schtasks.exe' AND SrcProcCmdLine LIKE '%/create%' AND (SrcProcCmdLine LIKE '%/du 9999:59%' OR (SrcProcCmdLine LIKE '%BitLocker Encrypt All Drives%' AND SrcProcCmdLine LIKE '%\OneDriveCloud\taskhostw.exe%'))
  UNION
  /* Data Staging and Reconnaissance */
  SELECT EventTime, EndpointName, UserName, 'Collection' AS Tactic, 'T1560' AS Technique, 'WaterCurse: Staging and Reconnaissance' AS Activity, SrcProcParentName, SrcProcName, SrcProcCmdLine, NULL, NULL, NULL, NULL, NULL, NULL
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND (SrcProcName = '7z.exe' AND SrcProcImagePath LIKE 'C:\ProgramData\sevenZip\%' AND SrcProcCmdLine LIKE '%-p%') OR (SrcProcParentName = 'NVIDIA Control Panel.exe' AND SrcProcParentImagePath LIKE '%\Microsoft\Vault\UserRoamingTiles\NVIDIAContainer%' AND SrcProcName IN ('curl.exe', 'wmic.exe', 'tasklist.exe'))
  UNION
  /* Malicious File Artifacts Creation */
  SELECT EventTime, EndpointName, UserName, 'Initial Access' AS Tactic, 'T1195.002' AS Technique, 'WaterCurse: Malicious File Artifact Creation' AS Activity, NULL, NULL, NULL, TgtFilePath, TgtFileName, NULL, NULL, NULL, NULL
  FROM deep_visibility
  WHERE EventType = 'File Creation' AND ((TgtFilePath LIKE '%\.vs-script\%' AND TgtFileName IN ('antiDebug.ps1', 'disabledefender.ps1')) OR (TgtFilePath LIKE '%\AppData\Local\Temp\%' AND TgtFileName = 'SearchFilter.exe') OR (TgtFilePath LIKE '%\Microsoft\Vault\UserRoamingTiles\NVIDIAContainer%' AND TgtFileName = 'NVIDIA Control Panel.exe'))
  UNION
  /* C2 and Exfiltration Network Activity */
  SELECT EventTime, EndpointName, UserName, 'Command and Control' AS Tactic, 'T1071' AS Technique, 'WaterCurse: C2/Exfiltration Network Connection' AS Activity, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NetworkUrl, NetworkDestIP
  FROM deep_visibility
  WHERE EventType = 'Network Connect' AND (NetworkUrl IN ('%store-eu-par-2.gofile.io%', '%api.telegram.org%', '%popcorn-soft.glitch.me%', '%pastejustit.com%', '%pastesio.com%') OR NetworkDestIP = '46.101.236.176' OR SrcProcName = 'RegAsm.exe')
)
GROUP BY firstTime, lastTime, dest, user, Tactic, Technique, Activity, parent_process_name, process_name, process, file_path, file_name, registry_path, registry_value_name, url, dest_ip
ORDER BY firstTime DESC
LIMIT 1000
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

SELECT EventTime AS _time, EndpointName AS Computer, UserName AS User,
  CASE
    WHEN EventType = 'Process Start' AND SrcProcParentImagePath LIKE '%\CreateProcessAsPPL.exe' AND SrcProcImagePath LIKE '%\clipup.exe' THEN 'PPL Loader launching ClipUp'
    WHEN EventType = 'Process Start' AND SrcProcImagePath LIKE '%\System32\clipup.exe' AND SrcProcCmdLine LIKE '%-ppl%' AND (SrcProcCmdLine LIKE '%\ProgramData\Microsoft\Windows Defender\%' OR SrcProcCmdLine LIKE '%\Program Files\Windows Defender\%' OR SrcProcCmdLine LIKE '%\Program Files (x86)\Windows Defender\%' OR SrcProcCmdLine LIKE '-ppl %PROGRA~%') THEN 'Anomalous ClipUp Execution for File Write'
    WHEN EventType = 'Process Start' AND SrcProcImagePath LIKE '%\sc.exe' AND SrcProcCmdLine LIKE '%create%' AND SrcProcCmdLine LIKE '%start=auto%' AND (SrcProcCmdLine LIKE '%binPath=%CreateProcessAsPPL.exe%' OR SrcProcCmdLine LIKE '%binPath=%\Users\%' OR SrcProcCmdLine LIKE '%binPath=%\ProgramData\%' OR SrcProcCmdLine LIKE '%binPath=%\Windows\Temp\%' OR SrcProcCmdLine LIKE '%binPath=%\Temp\%' OR SrcProcCmdLine LIKE 'binPath=.%(cmd|powershell|pwsh).exe') THEN 'Suspicious Auto-Start Service Creation'
    WHEN EventType = 'File Creation' AND (TgtFilePath LIKE 'C:\ProgramData\Microsoft\Windows Defender\%' OR TgtFilePath LIKE 'C:\Program Files\Windows Defender\%' OR TgtFilePath LIKE 'C:\Program Files (x86)\Windows Defender\%') AND SrcProcImagePath NOT IN ('\MsMpEng.exe', '\NisSrv.exe', '\MsMpEngCP.exe', '\MpCmdRun.exe', '\TiWorker.exe', '\TrustedInstaller.exe', '\svchost.exe', '\setup.exe') THEN 'Unauthorized Defender Directory File Modification'
  END AS technique,
  SrcProcParentImagePath AS ParentImage, SrcProcImagePath AS Image, SrcProcCmdLine AS CommandLine, TgtFilePath AS TargetFilename
FROM deep_visibility
WHERE technique IS NOT NULL
ORDER BY _time DESC
LIMIT 1000
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

SELECT EventTime AS _time, EndpointName AS DeviceName, UserName AS AccountName, SrcProcName AS FileName, SrcProcImagePath AS FolderPath, SrcProcCmdLine AS ProcessCommandLine, REGEXP_REPLACE(SrcProcCmdLine, '^(?:"(.*?)"(|\\s)|(\\S+))', '\\1') AS CommandLineExecutable, SrcProcParentName AS InitiatingProcessFileName
FROM deep_visibility
WHERE EventType = 'Process Start' AND SrcProcImagePath IS NOT NULL AND SrcProcCmdLine IS NOT NULL
HAVING LOWER(SrcProcImagePath) != LOWER(CommandLineExecutable) AND LOWER(SrcProcName) == LOWER(REGEXP_REPLACE(CommandLineExecutable, '.*\\(.*)', '\\1')) AND
  SrcProcParentName NOT IN ('services.exe', 'svchost.exe', 'WmiPrvSE.exe', 'msiexec.exe', 'TiWorker.exe') AND
  SrcProcImagePath NOT REGEXP '(?i)C:\\Windows\\(System32|SysWOW64|servicing)|C:\\Program Files|AppData\\Local\\Temp|\\Windows\\Temp'
ORDER BY _time DESC
LIMIT 1000
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

SELECT EventTime AS _time, EndpointName AS dest, UserName AS user,
  CASE
    WHEN EventType = 'Process Start' AND LENGTH(SrcProcImagePath) > 260 THEN 'Process Creation with Long Path'
    WHEN EventType = 'Module Load' AND LENGTH(LoadedModulePath) > 260 THEN 'Module Load from Long Path'
    WHEN EventType = 'File Creation' AND LENGTH(TgtFilePath) > 260 THEN 'File Creation with Long Path'
  END AS EventType,
  SrcProcCmdLine AS process, SrcProcParentImagePath AS parent_process, SrcProcImagePath AS process_path, TgtFilePath AS FilePath
FROM deep_visibility
WHERE EventType IN ('Process Start', 'Module Load', 'File Creation') AND EventType IS NOT NULL
ORDER BY _time DESC
LIMIT 1000
```

### Suspicious SQL Server Activity
---
```sql
-- Name: Suspicious SQL Server Activity
-- Author: RW
-- Date: 2025-08-23
-- Description: Detects a variety of suspicious activities related to Microsoft SQL Server that could indicate reconnaissance, execution, or persistence. This includes enabling high-risk procedures, sqlservr.exe spawning shells, suspicious use of sqlcmd or Invoke-Sqlcmd, loading of untrusted CLR assemblies, and execution of suspicious startup procedures.
-- MITRE ATT&CK: T1543.003, T1059.001, T1059.003, T1059.006, T1003, T1041

SELECT EventTime AS _time, EndpointName AS dest, UserName AS user, rule_name, details, command, parent_process
FROM (
  /* High-Risk SQL Procedure Enabled */
  SELECT EventTime, EndpointName, UserName, 'High-Risk SQL Procedure Enabled' AS rule_name, 'Config: ' || Data1 || ', Old Value: ' || Data3 || ', New Value: ' || Data2 AS details, details AS command, 'sqlservr.exe' AS parent_process
  FROM deep_visibility
  WHERE EventType = 'Event Log' AND EventID = '15457' AND Data1 IN ('xp_cmdshell', 'Ole Automation Procedures') AND Data2 = '1'
  UNION
  /* SQL CLR Enabled */
  SELECT EventTime, EndpointName, UserName, 'SQL CLR Enabled' AS rule_name, 'Config: ' || Data1 || ', Old Value: ' || Data3 || ', New Value: ' || Data2 AS details, details AS command, 'sqlservr.exe' AS parent_process
  FROM deep_visibility
  WHERE EventType = 'Event Log' AND EventID = '15457' AND Data1 = 'clr enabled' AND Data2 = '1'
  UNION
  /* SQL CLR Strict Security Disabled */
  SELECT EventTime, EndpointName, UserName, 'SQL CLR Strict Security Disabled' AS rule_name, 'Config: ' || Data1 || ', Old Value: ' || Data3 || ', New Value: ' || Data2 AS details, details AS command, 'sqlservr.exe' AS parent_process
  FROM deep_visibility
  WHERE EventType = 'Event Log' AND EventID = '15457' AND Data1 = 'clr strict security' AND Data2 = '0'
  UNION
  /* Suspicious SQL Startup Procedure */
  SELECT EventTime, EndpointName, UserName, 'Suspicious SQL Startup Procedure' AS rule_name, 'Procedure: ' || Data1 AS details, details AS command, 'sqlservr.exe' AS parent_process
  FROM deep_visibility
  WHERE EventType = 'Event Log' AND EventID = '17135' AND (Data1 LIKE '%xp_%' OR Data1 LIKE '%sp_%' OR Data1 LIKE '%cmdshell%' OR Data1 LIKE '%shell%' OR Data1 LIKE '%exec%')
  UNION
  /* SQL Server Spawning Shell */
  SELECT EventTime, EndpointName, UserName, 'SQL Server Spawning Shell' AS rule_name, SrcProcName || ' spawned by sqlservr.exe.' AS details, SrcProcCmdLine AS command, SrcProcParentName AS parent_process
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND SrcProcParentName = 'sqlservr.exe' AND SrcProcName IN ('cmd.exe', 'powershell.exe')
  UNION
  /* Suspicious sqlcmd.exe Usage */
  SELECT EventTime, EndpointName, UserName, 'Suspicious sqlcmd.exe Usage' AS rule_name, 'sqlcmd.exe executed with suspicious arguments.' AS details, SrcProcCmdLine AS command, SrcProcParentName AS parent_process
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND SrcProcName = 'sqlcmd.exe' AND (SrcProcCmdLine LIKE '%xp_cmdshell%' OR SrcProcCmdLine LIKE '%sp_oacreate%' OR SrcProcCmdLine LIKE '%sp_add_trusted_assembly%' OR SrcProcCmdLine LIKE '%sp_configure%' OR SrcProcCmdLine LIKE '%OPENROWSET%' OR SrcProcCmdLine LIKE '%-o %' OR SrcProcCmdLine LIKE '%--outputfile%' OR SrcProcCmdLine LIKE '%http%//%' OR SrcProcCmdLine LIKE '%-t 0%' OR SrcProcCmdLine LIKE '%--query_timeout=0%')
  UNION
  /* Potential SQL CLR Assembly Loaded */
  SELECT EventTime, EndpointName, UserName, 'Potential SQL CLR Assembly Loaded' AS rule_name, 'DLL ' || TgtFileName || ' created in ' || TgtFilePath AS details, TgtFileName AS command, SrcProcName AS parent_process
  FROM deep_visibility
  WHERE EventType = 'File Creation' AND TgtFileName LIKE '%.dll' AND TgtFilePath LIKE '%\Microsoft SQL Server\%\MSSQL\Binn\%'
  UNION
  /* Suspicious Invoke-Sqlcmd Usage */
  SELECT EventTime, EndpointName, UserName, 'Suspicious Invoke-Sqlcmd Usage' AS rule_name, 'PowerShell Invoke-Sqlcmd used with suspicious arguments.' AS details, ScriptBlockText AS command, 'powershell.exe' AS parent_process
  FROM deep_visibility
  WHERE EventType = 'Script Block' AND EventID = '4104' AND ScriptBlockText LIKE '%Invoke-Sqlcmd%' AND (ScriptBlockText LIKE '%xp_cmdshell%' OR ScriptBlockText LIKE '%sp_oacreate%' OR ScriptBlockText LIKE '%sp_add_trusted_assembly%' OR ScriptBlockText LIKE '%sp_configure%' OR ScriptBlockText LIKE '%OPENROWSET%' OR ScriptBlockText LIKE '%-QueryTimeout 0%')
)
ORDER BY _time DESC
LIMIT 1000
```

### SQL Injection (SQLi) Attempts
---
```sql
-- Name: Combined SQL Injection (SQLi) Detection
-- Author: RW
-- Date: 2025-08-23

-- This rule combines multiple SQLi detection techniques into a single query.
-- It identifies general attempts, error-based, time-based, database reconnaissance, and authentication bypass attacks.

SELECT EventTime AS _time, EndpointName AS Destination, UserName AS User, SrcIP AS SourceIP, detection_type, GROUP_CONCAT(Url) AS urls, GROUP_CONCAT(SqlQuery) AS queries, GROUP_CONCAT(Outcome) AS outcomes, COUNT(*) AS count, LogSource
FROM (
  /* Auth Bypass */
  SELECT EventTime, EndpointName, UserName, SrcIP, 'SQLi Authentication Bypass' AS detection_type, Url, SqlQuery, Outcome, EventSource AS LogSource
  FROM deep_visibility
  WHERE EventType IN ('Web Access', 'Database Audit', 'Authentication') AND Outcome IN ('0', 'success', 'allow', 'accepted') AND (UserName LIKE '%\' or %' OR UserName LIKE '%\'or\'--%' OR UserName LIKE '% or 1=1%' OR UserName LIKE '%admin\'--%')
  UNION
  /* Time-Based Blind */
  SELECT EventTime, EndpointName, UserName, SrcIP, 'Time-Based Blind SQLi' AS detection_type, Url, SqlQuery, Outcome, EventSource AS LogSource
  FROM deep_visibility
  WHERE EventType = 'Web Access' AND ResponseTimeSec > 5 AND (Url LIKE '%sleep(%' OR Url LIKE '%waitfor delay%' OR Url LIKE '%benchmark(%' OR Url LIKE '%pg_sleep(%')
  UNION
  /* Error-Based */
  SELECT EventTime, EndpointName, UserName, SrcIP, 'Error-Based SQLi' AS detection_type, Url, SqlQuery, Outcome, EventSource AS LogSource
  FROM deep_visibility
  WHERE EventType = 'Web Access' AND (ResponseBody LIKE '%error in your sql syntax%' OR ResponseBody LIKE '%unclosed quotation mark%' OR ResponseBody LIKE '%ora-[0-9][0-9][0-9][0-9][0-9]%' OR ResponseBody LIKE '%invalid column name%')
  UNION
  /* DB Recon */
  SELECT EventTime, EndpointName, UserName, SrcIP, 'SQLi DB Reconnaissance' AS detection_type, Url, SqlQuery, Outcome, EventSource AS LogSource
  FROM deep_visibility
  WHERE EventType = 'Database Audit' AND SqlQuery IS NOT NULL AND (SqlQuery LIKE '%information_schema%' OR SqlQuery LIKE '%sys.objects%' OR SqlQuery LIKE '%pg_catalog%' OR SqlQuery LIKE '%sqlite_master%')
  UNION
  /* General Attempt */
  SELECT EventTime, EndpointName, UserName, SrcIP, 'General SQLi Attempt' AS detection_type, Url, SqlQuery, Outcome, EventSource AS LogSource
  FROM deep_visibility
  WHERE EventType = 'Web Access' AND (Url LIKE '%\' or %' OR Url LIKE '% union %select %' OR Url LIKE '%--%' OR Url LIKE '%/*%' OR Url LIKE '%\';%')
)
GROUP BY EventTime, detection_type, SrcIP, UserName, EndpointName, LogSource
ORDER BY EventTime DESC
LIMIT 1000
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

SELECT EventTime AS _time, Tactic, Technique, DetectionSource, Entity, Description
FROM (
  /* Part 1: High/Critical Vulnerabilities */
  SELECT EventTime, 'Initial Access' AS Tactic, 'Exploit Public-Facing Application' AS Technique, 'Vulnerability Scan' AS DetectionSource, ContainerImage AS Entity, 'High/Critical severity vulnerability \'' || VulnerabilityId || '\' detected in image \'' || ContainerImage || '\'.' AS Description
  FROM deep_visibility
  WHERE EventType = 'Vulnerability Scan' AND VulnerabilitySeverity IN ('High', 'Critical')
  UNION
  /* Part 2a: Privileged Containers */
  SELECT EventTime, 'Privilege Escalation' AS Tactic, 'Escape to Host' AS Technique, 'Kubernetes Audit' AS DetectionSource, KubeUserName AS Entity, 'Privileged container \'' || ContainerName || '\' created by user \'' || KubeUserName || '\' in namespace \'' || Namespace || '\'.' AS Description
  FROM deep_visibility
  WHERE EventType = 'Kubernetes Audit' AND SecurityContextPrivileged = 'true' AND KubeUserName NOT IN ('system:masters', 'cluster-admin', 'azure-operator')
  UNION
  /* Part 2b: Runtime Escape Attempts */
  SELECT EventTime, 'Privilege Escalation' AS Tactic, 'Escape to Host' AS Technique, 'EDR' AS DetectionSource, EndpointName AS Entity, 'Suspicious process \'' || SrcProcName || '\' with command line \'' || SrcProcCmdLine || '\' executed from a container context on host \'' || EndpointName || '\'.' AS Description
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND (SrcProcParentImagePath LIKE '%runc%' OR SrcProcParentImagePath LIKE '%containerd-shim%') AND SrcProcName IN ('nsenter', 'insmod', 'modprobe', 'chroot')
  UNION
  /* Part 3: Insecure API Access */
  SELECT EventTime, 'Privilege Escalation' AS Tactic, 'Valid Accounts' AS Technique, 'Kubernetes Audit' AS DetectionSource, KubeUserName AS Entity, 'User \'' || KubeUserName || '\' created a cluster role binding to a privileged role \'' || RoleRefName || '\'.' AS Description
  FROM deep_visibility
  WHERE EventType = 'Kubernetes Audit' AND KubeVerb = 'create' AND KubeResource = 'clusterrolebindings' AND RoleRefName IN ('cluster-admin', 'admin') AND KubeUserName NOT IN ('system:masters', 'cluster-admin', 'azure-operator')
  UNION
  /* Part 4: Untrusted Registry */
  SELECT EventTime, 'Initial Access' AS Tactic, 'Supply Chain Compromise' AS Technique, 'Container Inventory' AS DetectionSource, Image AS Entity, 'Container started from untrusted registry: \'' || Image || '\' on host \'' || EndpointName || '\'.' AS Description
  FROM deep_visibility
  WHERE EventType = 'Container Start' AND Image IS NOT NULL AND Image NOT LIKE 'mcr.microsoft.com/%' AND Image NOT LIKE 'docker.io/%' AND Image NOT LIKE 'k8s.gcr.io/%' AND Image NOT LIKE 'quay.io/%' AND Image NOT LIKE 'gcr.io/%'
)
GROUP BY EventTime, Tactic, Technique, DetectionSource, Entity, Description
ORDER BY EventTime DESC
LIMIT 1000
```

### UNC6384 (Mustang Panda) Campaign IOCs and TTPs
---
```sql
-- title: UNC6384 Mustang Panda Campaign IOCs and TTPs
-- description: Detects multiple indicators of compromise (IOCs) and tactics, techniques, and procedures (TTPs) associated with a UNC6384 (Mustang Panda) campaign targeting diplomats, as reported by Google in August 2025. This rule covers file hashes, network indicators, persistence mechanisms, and behavioral patterns related to the STATICPLUGIN, CANONSTAGER, and SOGU.SEC malware families.
-- author: RW
-- date: 2025-08-26

SELECT
  EndpointName AS "Victim Host",
  GROUP_CONCAT(CreatedAt) AS "Event Times",
  GROUP_CONCAT(detection_name) AS "Detections",
  GROUP_CONCAT(ioc_indicator) AS "Matched IOCs",
  GROUP_CONCAT(SrcProcImagePath) AS "Associated Processes",
  GROUP_CONCAT(UserName) AS "Associated Users",
  COUNT(*) AS count
FROM (
  SELECT
    CreatedAt,
    CASE
      WHEN SHA256 IS NOT NULL THEN 'UNC6384 - Malicious File Hash'
      WHEN RemoteIP IS NOT NULL OR DnsResponse IS NOT NULL THEN 'UNC6384 - Malicious Network Connection'
      WHEN UserAgent LIKE '%MSIE 9.0%' THEN 'UNC6384 - SOGU.SEC User Agent'
      WHEN EventType = 'Registry Value Set' THEN 'UNC6384 - CanonPrinter Persistence'
      WHEN EventType = 'Module Load' THEN 'UNC6384 - CANONSTAGER DLL Sideloading'
      WHEN EventType = 'Process Creation' THEN 'UNC6384 - Suspicious File Path'
      ELSE 'UNC6384 - Fallback Match'
    END AS detection_name,
    EndpointName,
    SrcProcImagePath,
    UserName,
    COALESCE(SHA256, RemoteIP, DnsResponse, UserAgent, RegistryKeyPath, DllPath, TgtProcImagePath) AS ioc_indicator
  FROM deep_visibility
  WHERE
    (SHA256 IN ('65c42a7ea18162a92ee982eded91653a5358a7129c7672715ce8ddb6027ec124', '3299866538aff40ca85276f87dd0cefe4eafe167bd64732d67b06af4f3349916', 'e787f64af048b9cb8a153a0759555785c8fd3ee1e8efbca312a29f2acb1e4011', 'cc4db3d8049043fa62326d0b3341960f9a0cf9b54c2fbbdffdbd8761d99add79', 'd1626c35ff69e7e5bde5eea9f9a242713421e59197f4b6d77b914ed46976b933'))
    OR (EventType = 'IP Connect' AND RemoteIP IN ('103.79.120.72', '166.88.2.90'))
    OR (EventType = 'DNS Resolution' AND DnsResponse LIKE '%mediareleaseupdates.com%')
    OR (UserAgent = 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 10.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)')
    OR (EventType = 'Registry Value Set' AND RegistryKeyPath LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\CanonPrinter' AND RegistryValueData LIKE '%cnmpaui.exe%')
    OR (EventType = 'Module Load' AND SrcProcImagePath LIKE '%\\cnmpaui.exe' AND DllPath LIKE '%\\cnmpaui.dll')
    OR (EventType = 'Process Creation' AND (TgtProcImagePath LIKE '%\\DNVjzaXMFO\\%' OR TgtProcImagePath LIKE '%C:\\Users\\Public\\Intelnet\\%' OR TgtProcImagePath LIKE '%C:\\Users\\Public\\SecurityScan\\%'))
) AS subquery
GROUP BY EndpointName
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

(
    -- Part 1: Suspicious commands and file activity
    (EventType = "Process" AND (
        ProcessCmdLine CONTAINS "service sshd_operns start" OR
        ProcessCmdLine CONTAINS "access-list 10" OR
        ProcessCmdLine CONTAINS "access-list 20" OR
        ProcessCmdLine CONTAINS "access-list 50" OR
        ProcessCmdLine CONTAINS "useradd cisco" OR
        ProcessCmdLine CONTAINS "vi /etc/sudoers" OR
        ProcessCmdLine CONTAINS "monitor capture" OR
        ProcessCmdLine CONTAINS "span" OR
        ProcessCmdLine CONTAINS "erspan"
    ))
    OR
    (EventType = "File" AND (
        FileName ENDSWITH "mycap.pcap" OR
        FileName ENDSWITH "tac.pcap" OR
        FileName ENDSWITH "1.pcap"
    ))
    OR
    -- Part 2: Suspicious network connections
    (EventType = "Network" AND (
        DstPort = 57722 OR
        DstPort MATCHES "^\d{3,5}22$"
        -- FP-Tuning: Add AND NOT DstIP IN (known_good_ips) to reduce false positives
    ))
)
-- Enrich with reason for triage
| SELECT Time, EventType, ProcessCmdLine, FileName, SrcIP, DstIP, DstPort, UserName,
    CASE
        WHEN ProcessCmdLine CONTAINS "service sshd_operns start" THEN "Suspicious Service Started: sshd_operns"
        WHEN ProcessCmdLine CONTAINS "access-list 10" OR ProcessCmdLine CONTAINS "access-list 20" OR ProcessCmdLine CONTAINS "access-list 50" THEN "Suspicious ACL Modification Detected"
        WHEN ProcessCmdLine CONTAINS "useradd cisco" THEN "Suspicious User Creation: cisco"
        WHEN ProcessCmdLine CONTAINS "vi /etc/sudoers" THEN "Sudoers File Edited"
        WHEN ProcessCmdLine CONTAINS "monitor capture" OR ProcessCmdLine CONTAINS "span" OR ProcessCmdLine CONTAINS "erspan" THEN "Packet/Traffic Capture Command Detected"
        WHEN FileName ENDSWITH "mycap.pcap" OR FileName ENDSWITH "tac.pcap" OR FileName ENDSWITH "1.pcap" THEN "Suspicious PCAP Filename Detected"
        WHEN DstPort = 57722 THEN "Network Connection to IOS XR Backdoor Port 57722"
        WHEN DstPort MATCHES "^\d{3,5}22$" THEN "Network Connection to High Port Ending in '22'"
        ELSE "Unknown Match - Check Raw Event"
    END AS Reason
| ORDER BY Time DESC
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
(
    -- Vulnerable driver loads (file hashes)
    event.type = "Module Load" AND file.sha256 IN (
        "12b3d8bc5cc1ea6e2acd741d8a80f56cf2a0a7ebfa0998e3f0743fcf83fabb9e",
        "0be8483c2ea42f1ce4c90e84ac474a4e7017bc6d682e06f96dc1e31922a07b10",
        "9c394dcab9f711e2bf585edf0d22d2210843885917d409ee56f22a4c24ad225e"
    )
    OR
    -- Suspicious files written
    event.type = "File Creation" AND file.path LIKE "C:\\Program Files\\RunTime\\%" AND file.name IN ("RuntimeBroker.exe", "Amsdk_Service.sys")
    OR
    -- Suspicious services created (registry)
    event.type = "Registry Modification" AND registry.path LIKE (
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Termaintor%" OR
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Amsdk_Service%"
    )
    OR
    -- C2 traffic
    event.type = "Network" AND network.remote.ip IN (
        "47.239.197.97", "8.217.38.238", "156.234.58.194", "156.241.144.66", "1.13.249.217"
    ) AND network.remote.port IN (52116, 52117, 8888, 52110, 52111, 52139, 52160, 9527, 9528)
)
-- Categorize indicators
| eval indicator_type = case(
    file.sha256 IN (
        "12b3d8bc5cc1ea6e2acd741d8a80f56cf2a0a7ebfa0998e3f0743fcf83fabb9e",
        "0be8483c2ea42f1ce4c90e84ac474a4e7017bc6d682e06f96dc1e31922a07b10",
        "9c394dcab9f711e2bf585edf0d22d2210843885917d409ee56f22a4c24ad225e"
    ), "Vulnerable_Driver_Loaded",
    file.path LIKE "C:\\Program Files\\RunTime\\%" AND file.name IN ("RuntimeBroker.exe", "Amsdk_Service.sys"), "Suspicious_File_Written",
    registry.path LIKE (
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Termaintor%" OR
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Amsdk_Service%"
    ), "Suspicious_Service_Created",
    network.remote.ip IS NOT NULL, "C2_Traffic_Detected",
    true, "Other"
)
| eval indicator_value = case(
    indicator_type = "Vulnerable_Driver_Loaded", file.sha256,
    indicator_type = "Suspicious_File_Written", file.path,
    indicator_type = "Suspicious_Service_Created", registry.path,
    indicator_type = "C2_Traffic_Detected", network.remote.ip + ":" + network.remote.port,
    true, "N/A"
)
-- Aggregate by endpoint
| stats
    first_seen = min(event.time),
    last_seen = max(event.time),
    users = collect(user.name),
    distinct_indicator_count = count_distinct(indicator_type),
    indicators = collect(indicator_type),
    indicator_details = collect(indicator_value)
    by endpoint.name
-- Core detection logic
| where indicators LIKE "%Vulnerable_Driver_Loaded%" AND distinct_indicator_count > 1
-- Add IOCTL note
| eval note = "IOCTL detection (DeviceIoControl to 'amsdk' with codes 0x80002010, 0x80002048) requires specific EDR logs. This activity may also be present but is not detected by this query."
-- Format output
| select first_seen, last_seen, endpoint.name as host, users, indicators, indicator_details, note
```

### APT28 NotDoor Backdoor Activity Detection
---
```sql
-- Name: APT28 NotDoor Backdoor Activity
-- Author: RW
-- Date: 2025-09-03
-- Description: This rule detects various activities associated with the NotDoor backdoor, used by APT28. It looks for specific file creation events, process command lines, registry modifications, and network communications.
-- False Positive Sensitivity: Medium

(process WHERE (file.sha256 IN ("5a88a15a1d764e635462f78a0cd958b17e6d22c716740febc114a408eef66705","8f4bca3c62268fff0458322d111a511e0bcfba255d5ab78c45973bd293379901") OR file.full_name = "C:\\ProgramData\\testtemp.ini" OR file.full_name REGEXP "(?i)\\\\AppData\\\\Local\\\\Temp\\\\Test\\\\(report|invoice|contract|photo|scheme|document)_[^\\\\]+\\.(jpg|jpeg|gif|bmp|ico|png|pdf|doc|docx|xls|xlsx|ppt|pptx|mp3|mp4|xml)$" AND process.name = "powershell.exe" AND process.cmd REGEXP "(?i)copy.*c:\\\\programdata\\\\testtemp.ini.*\\\\Microsoft\\\\Outlook\\\\VbaProject.OTM" OR process.name = "nslookup.exe" AND process.cmd REGEXP "(?i)\\.dnshook\\.site" OR process.name = "curl.exe" AND process.cmd REGEXP "(?i)webhook\\.site")) OR
(registry WHERE registry.path REGEXP "(?i)\\\\Software\\\\Microsoft\\\\Office\\\\[^\\\\]+\\\\Outlook\\\\LoadMacroProviderOnBoot$" AND registry.value = "1" OR registry.path REGEXP "(?i)\\\\Software\\\\Microsoft\\\\Office\\\\[^\\\\]+\\\\Outlook\\\\Security\\\\Level$" AND registry.value = "1" OR registry.path REGEXP "(?i)\\\\Software\\\\Microsoft\\\\Office\\\\[^\\\\]+\\\\Outlook\\\\Options\\\\General\\\\PONT_STRING$" AND registry.value = ";") OR
(dns WHERE dns.request REGEXP "(?i)(webhook|dnshook)\\.site$") OR
(network WHERE network.url REGEXP "(?i)(webhook|dnshook)\\.site$" AND network.method IN ("GET","POST")) OR
(your_email_logs WHERE to = "a.matti444@proton.me" AND subject = "Re: 0")
```

### MeetC2 C2 Activity via Google Calendar API
---
```sql
-- Part 1: S1QL for suspicious Google Calendar events (assuming custom fields for logs)
EventName IN ("calendar.events.insert", "calendar.events.update", "calendar.acl.create") AND
(ParametersSummary LIKE "%Meeting from nobody:%[COMMAND]%" OR
(ParametersDescription LIKE "%[OUTPUT]%" AND ParametersDescription LIKE "%[/OUTPUT]%") OR
ParametersAclScopeValue LIKE "%gserviceaccount.com")
-- To approximate eval/table, post-process results for detection_method/details (e.g., via UI export/script).
-- Part 2: S1QL for potential C2 beaconing
NetworkUrl LIKE "%www.googleapis.com/calendar/v3/calendars/%/events%" AND
(SrcProcImagePath IS NULL OR NOT (SrcProcImagePath LIKE "%\(chrome|msedge|firefox|outlook|teams).exe"))
-- For beaconing stats (approximate 10m bins via subquery or multiple runs; S1QL supports GROUP BY):
SELECT COUNT(*) AS request_count, NetworkUrl AS urls
FROM network_events
WHERE NetworkUrl LIKE "%www.googleapis.com/calendar/v3/calendars/%/events%"
AND (SrcProcImagePath IS NULL OR NOT (SrcProcImagePath LIKE "%\(chrome|msedge|firefox|outlook|teams).exe"))
GROUP BY DstIP, SrcProcImagePath, User, DATEADD(minute, FLOOR(DATEDIFF(minute, '2000-01-01', EventTime)/10)*10, '2000-01-01')
HAVING request_count > 15
```

### APT37 Rustonotto, Chinotto, and FadeStealer Activity
---
```sql
SELECT EventTime, DstHost, User, EventName, SrcProcImagePath, SrcProcCmdLine, ParentProcImagePath, TargetFilePath, FileMd5, RegistryKeyPath, RegistryValueData, NetworkUrl
FROM events
WHERE EventName IN ('1', '11', '13') OR NetworkUrl LIKE '%U=%%'
AND (
  (EventName IN ('1', '11') AND FileMd5 IN (
    'b9900bef33c6cc9911a5cd7eeda8e093',
    '7967156e138a66f3ee1bfce81836d8d0',
    '77a70e87429c4e552649235a9a2cf11a',
    '04b5e068e6f0079c2c205a42df8a3a84',
    'd2b34b8bfafd6b17b1cf931bb3fdd3db',
    '3d6b999d65c775c1d27c8efa615ee520',
    '89986806a298ffd6367cf43f36136311',
    '4caa44930e5587a0c9914bda9d240acc'
  ))
  OR
  (EventName = '11' AND (
    TargetFilePath IN (
      'C:\\ProgramData\\3HNoWZd.exe',
      'C:\\ProgramData\\wonder.cab',
      'C:\\ProgramData\\tele_update.exe',
      'C:\\ProgramData\\tele.conf',
      'C:\\ProgramData\\tele.dat',
      'C:\\ProgramData\\Password.chm',
      'C:\\ProgramData\\1.html'
    ) OR TargetFilePath LIKE '%\\VSTelems_Fade\\(NgenPdbk|NgenPdbc|NgenPdbm|VSTelems_FadeOut|VSTelems_FadeIn)%' OR TargetFilePath LIKE '%(watch_|usb_|data_)%.rar'
  ))
  OR
  (EventName = '1' AND (
    SrcProcCmdLine LIKE '%schtasks% /create %MicrosoftUpdate%3HNoWZd.exe%' OR
    (SrcProcImagePath LIKE '%\\mshta.exe' AND SrcProcCmdLine LIKE '%http%') OR
    (ParentProcImagePath LIKE '%\\cmd.exe' AND SrcProcImagePath LIKE '%\\expand.exe' AND SrcProcCmdLine LIKE '%c:\\programdata\\wonder.cab%') OR
    SrcProcImagePath = 'c:\\programdata\\tele_update.exe'
  ))
  OR
  (EventName = '13' AND RegistryKeyPath LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OnedriveStandaloneUpdater%' AND RegistryValueData LIKE '%mshta%http%')
  OR
  (NetworkUrl LIKE '%U=%%' AND (NetworkUrl LIKE '%R=%%' OR NetworkUrl LIKE '%_file=%%'))
)
GROUP BY EventTime, DstHost, EventName, SrcProcCmdLine
```

### Exposed Docker APIs Are Targeted in New Malware Strain
---
```sql
-- author: RW

-- This detection rule identifies a multi-stage attack targeting exposed Docker APIs.
-- The malware strain aims to establish persistent root access, create a botnet, and perform reconnaissance.
-- This rule combines several detection concepts into a single query to provide a broad overview of related malicious activities.

-- Detects Docker API exploitation attempts on port 2375 (T1190).
-- Data requirement: network_events with HttpMethod, UriPath, NetworkDestPort.
-- FP Tuning: Filter SrcHost against known-good IPs or user agents.
SELECT EventTime, SrcHost AS src_ip, NetworkDest AS dest_ip, HttpUserAgent AS user_agent
FROM network_events
WHERE HttpMethod = 'POST' AND UriPath LIKE '/containers/create%' OR '/images/create%' AND NetworkDestPort = '2375'
-- Post-process: Add Tactic="Initial Access", Technique="Exposed Docker Daemon API", Description="Potential Docker API exploitation attempt on port 2375."

-- Detects post-exploitation command execution in containers (T1059).
-- Data requirement: process_events with SrcProcImagePath, SrcProcCmdLine, ContainerId.
-- FP Tuning: Filter for multiple processes (curl+wget) via GROUP BY.
SELECT MIN(EventTime) AS first_seen, MAX(EventTime) AS last_seen, VALUES(SrcProcImagePath) AS processes, VALUES(SrcProcCmdLine) AS args
FROM process_events
WHERE (SrcProcImagePath IN ('sh', 'bash') AND SrcProcCmdLine LIKE '%curl%' OR '%wget%') OR SrcProcImagePath IN ('apk', 'apt', 'yum')
GROUP BY DstHost, ContainerId
HAVING COUNT(DISTINCT SrcProcImagePath) > 1 AND (SrcProcCmdLine LIKE '%curl%' OR SrcProcCmdLine LIKE '%wget%')
-- Post-process: Add Tactic="Execution", Technique="Command and Scripting Interpreter", Description="Suspicious package installation followed by downloader execution in a container."

-- Detects persistence via SSH keys, cron jobs, or firewall rule changes (T1547, T1070).
-- Data requirement: file_events, process_events with TargetFilePath, SrcProcImagePath, SrcProcCmdLine.
-- FP Tuning: Review user context for authorized changes.
SELECT EventTime, DstHost AS host, User, SrcProcImagePath AS process_name, SrcProcCmdLine AS process_args, TargetFilePath AS file_path
FROM (SELECT * FROM file_events UNION SELECT * FROM process_events)
WHERE (TargetFilePath IN ('/root/.ssh/authorized_keys', '/etc/crontab', '/etc/cron.d/*', '/var/spool/cron/*') AND FileOperation IN ('write', 'create')) OR (SrcProcImagePath IN ('firewall-cmd', 'iptables') AND SrcProcCmdLine LIKE '%--add-rich-rule%' OR '%--reload%' OR '%-A INPUT%' OR '%-p tcp%')
-- Post-process: Add Tactic="Persistence", Technique="SSH Authorized Keys or Cron Job Modification", Description="Modification of sensitive files for persistence or firewall rules for defense evasion."

-- Detects discovery/lateral movement via masscan or connections to specific ports (T1018, T1021).
-- Data requirement: process_events, network_events with SrcProcImagePath, NetworkDestPort.
-- FP Tuning: Baseline legitimate traffic to ports 23, 9222, 2375.
SELECT EventTime, SrcHost AS src_ip, NetworkDest AS dest_ip, NetworkDestPort AS dest_port, SrcProcImagePath AS process_name
FROM (SELECT * FROM process_events UNION SELECT * FROM network_events)
WHERE SrcProcImagePath = 'masscan' OR NetworkDestPort IN ('23', '9222', '2375')
-- Post-process: Add Tactic="Discovery/Lateral Movement", Technique="Network Service Scanning", Description="Execution of masscan or connection attempts to Telnet, Chrome Debug, or Docker API ports."

-- Detects Tor-related C2 activity (T1071).
-- Data requirement: dns_events, process_events with DnsQuery, SrcProcImagePath.
-- FP Tuning: Review legitimate Tor usage in environment.
SELECT EventTime, DstHost AS host, SrcHost AS src_ip, DnsQuery AS query, SrcProcImagePath AS process_name
FROM (SELECT * FROM dns_events UNION SELECT * FROM process_events)
WHERE DnsQuery LIKE '%.onion' OR SrcProcImagePath = 'torsocks'
-- Post-process: Add Tactic="Command and Control", Technique="Proxy: Tor", Description="Tor-related activity detected (torsocks process or .onion domain query)."
```