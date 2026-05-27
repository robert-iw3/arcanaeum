## Miscellaneous Queries

### Malicious VSCode Extension Activity Detection
---
```sql
-- Name: Malicious VSCode Extension Activity
-- Author: RW
-- Date: 2025-08-20
-- Description: This search combines multiple detection techniques for malicious Visual Studio Code extension activity. It looks for extension installation via URI handlers or the command line, suspicious network connections from VSCode, file writes to extension directories, and the loading of unusual Node modules. These activities can indicate an attacker using VSCode for initial access or persistence.

event_platform:'Win' + (
  /* VSCode URI Handler Installation */
  (ImageFileName:'Code.exe' + CommandLine:'*--open-url*' + CommandLine:'*vscode://*') ,
  /* VSCode Extension CLI Installation */
  (ImageFileName:'Code.exe' + CommandLine:'*--install-extension*' + CommandLine:'*.vsix*') ,
  /* Suspicious Outbound Connection from VSCode */
  (ImageFileName:'Code.exe' + TargetUrl!:'(*marketplace.visualstudio.com* , *vscode.blob.core.windows.net* , *update.code.visualstudio.com* , *gallerycdn.vsassets.io*'),
  /* File Write to VSCode Extension Directory */
  (TargetFilePath:'*\\.vscode\\extensions\\*' , TargetFilePath:'*\\Microsoft VS Code\\resources\\app\\extensions\\*') ,
  /* Suspicious Node Module Loaded by VSCode */
  (ImageFileName:'Code.exe' + LoadedImageName:'*.node' + (LoadedImagePath:'*\\AppData\\Local*' , LoadedImagePath:'*\\Temp*') + LoadedImagePath!:'(*\\.vscode\\extensions* , *Microsoft VS Code*')
)
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

(HttpMethod:'POST' + DomainName:'*.ru' + TargetUrl:'*/[0-9]{5,6}.php' + HttpRequestBody:'*request=%*' + HttpRequestBody:'*session=*') ,
(DomainName:'*.[a-z]{2}.com' + (HttpResponseBody:'*challenges.cloudflare.com/turnstile/*' + HttpResponseBody:'*Microsoft*' + HttpResponseBody:'*Sign in*') , (HttpResponseBody:'*new Date()*' + HttpResponseBody:'*debugger*'))
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

(ImageFileName:('AddInProcess32.exe','InstallUtil.exe','aspnet_wp.exe')) ,
(SHA256HashData:('011257eb766f253982b717b390fc36eb570473ed7805c18b101367c68af5','0ea3a55141405ee0e2dfbf333de01fe93c12cf34555550e4f7bb3fdec2a7673b', /* list all */)) ,
(QueryName:('catherinereynolds.info','mail.catherinereynolds.info')) ,
(RemoteAddress:('157.66.22.11','103.75.77.90','161.248.178.212'))
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

(SHA256HashData:('dc54117b965674bad3d7cd203ecf5e7fc822423a3f692895cf5e96e83fb88f6a','4843429e2e8871847bc1e97a0f12fa1f4166baa4735dff585cb3b4736e3fe49e','297ea881aa2b39461997baf75d83b390f2c36a9a0a4815c81b5cf8be42840fd1')) ,
(EventID:'17' + PipeName:'^\\.\\pipe\\1\\.[0-9a-fA-F]{32}$') ,
(EventID:'3' + (DestinationHostname:'aaaaabbbbbbb.eastus.cloudapp.azure.com' , DestinationIp:'127.0.0.1') + DestinationPort:('443','8082')) ,
(TargetUrl:'.*/[a-fA-F0-9]{16}$' + HttpHeader:'*Upgrade: websocket*' + HttpHeader:'*Connection: Upgrade*') ,
(EventID:'1' + ImageFileName:'certutil.exe' + CommandLine:'*-urlcache*' + CommandLine:'*-f*' + (CommandLine:'*.tmp*' , CommandLine:'*.dat*' , CommandLine:'*.msbuild*')) ,
(EventID:'1' + ParentBaseFileName:'msbuild.exe' + CommandLine:'*.mshi*') ,
(EventID:'10' + TargetImageName:'*\\lsass.exe' + SourceImageName:'*\\dllhost.exe')
```

### ESXi Host Suspicious Activity Detection (Recon, Privilege Escalation, Exfil, Evasion)
---
```sql
(Message:'*esxcli system*' + (Message:'* get*' , Message:'* list*') + Message!:'*filesystem*') ,
(Message:'*root*' + Message:'*logged in*') ,
(Message:'*esxcli system permission set*' + Message:'*role Admin*') ,
Message:'*esxcli software acceptance set*' ,
Message:'*SSH access has been enabled*' ,
(Message:'*system settings encryption set*' + (Message:'*--require-secure-boot=0*' , Message:'*--require-exec-installed-only=0*' , Message:'*execInstalledOnly=false*')) ,
(Message:'*File download from path*' + Message:'*was initiated from*') ,
Message:'*esxcli system auditrecords*' ,
(Message:'*syslog config set*' + Message:'*esxcli*') ,
(Message:'*Set called with key*' + (Message:'*Syslog.global.logHost*' , Message:'*Syslog.global.logdir*')) ,
(Message:'*NTPClock*' + Message:'*system clock stepped*')
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

(SHA256HashData:('202f6b6631ade2c41e4762b5877ce0063a3beabce0c3f8564b6499a1164c1e04', /* list all */)) ,
(RemoteAddress:('173.44.141.89','80.77.23.48','62.60.226.73','107.158.128.45','170.130.165.112','107.158.128.105')) ,
(TargetUrl:'*mhousecreative.com*' , TargetUrl:'*google.herionhelpline.com*' , TargetUrl:'*/service/*' , TargetUrl:'*/c91252f9ab114f26.php') ,
(HttpUserAgent:'*Googlebot*' + RemoteAddress:('173.44.141.89','80.77.23.48','62.60.226.73','107.158.128.45')) ,
(ImageFileName:'schtasks.exe' + CommandLine:'*/create*' + CommandLine:'*/sc*' + CommandLine:'*onlogon*')
```

### Quasar RAT Indicators: Process, File, and Network Activity
---
```sql
(SHA256HashData:'7300535ef26158bdb916b717390fc36eb570473ed7805c18b101367c68af5') ,
(ImageFileName:'schtasks.exe' + CommandLine:'*/rl *' + CommandLine:'* highest *') ,
(ImageFileName:'shutdown.exe' + (CommandLine:'*/s /t 0*' , CommandLine:'*/r /t 0*')) ,
(TargetFilePath:('*\\FileZilla\\recentservers.xml','*\\FileZilla\\sitemanager.xml') + ImageFileName!:'filezilla.exe') ,
(TargetFilePath:'*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*.url') ,
(TargetFileName:'*:Zone.Identifier') ,
(QueryName:('*wtfismyip.com','*checkip.*','*ipecho.net','*ipinfo.io','*api.ipify.org','*icanhazip.com','*ip.anysrc.com','*api.ip.sb','ident.me','www.myexternalip.com','*zen.spamhaus.org','*cbl.abuseat.org','*b.barracudacentral.org','*dnsbl-1.uceprotect.net','*spam.dnsbl.sorbs.net','*iplogger.org*','*ip-api.com*','*geoip.*','*icanhazip.*','*ipwho.is*','*ifconfig.me*','*myip.com*','*ipstack.com*','*myexternalip.com*','*ip-api.io*','*trackip.net*','*ipgeolocation.io*','*ipfind.io*','*freegeoip.app*','*ipv4bot.whatismyipaddress.com*','*hacker-target.com/iptools*'))
```

### Kerberoasting, AS-REP Roasting, DCSync, and AD DACL Modifications
---
```sql
EventID:'4769' + Status:'0x0' + TicketEncryptionType:'0x17' + ServiceName!:'*$*' ,
EventID:'4768' + Status:'0x0' + ServiceName:'krbtgt' + PreAuthenticationType:'0' + TargetUserName!:'*$*' ,
EventID:'4662' + ObjectServer:'DS' + ObjectType:'{19195a5b-6da0-11d0-afd3-00c04fd930c9}' + (Properties:'*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*' , Properties:'*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*') + SubjectAccountName!:'*$*' ,
EventID:'5136' + LDAPDisplayName:'nTSecurityDescriptor' + ObjectDN:'*CN=AdminSDHolder,CN=System,*' + SubjectUserSid!:'S-1-5-18' ,
EventID:'5136' + LDAPDisplayName:'nTSecurityDescriptor' + (Value:'*(A;;GA;;*' , Value:'*(A;;WD;;*' , Value:'*(A;;WO;;*') + SubjectUserSid!:'S-1-5-18'
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

(UserName:('*AAD_*','*MSOL_*') + EventCategory:'signin') ,
(EventAction:'Reset user password' + EventOutcome:'success' + InitiatedByUserPrincipalName:('*AAD_*','*MSOL_*')) ,
(EventCategory:'ApplicationManagement' + EventAction:'Add service principal') ,
(EventCategory:'ApplicationManagement' + EventAction:'Add OAuth2 permission grant') ,
(EventCategory:'ApplicationManagement' + EventAction:'Add owner to service principal') ,
(EventCategory:'ApplicationManagement' + EventAction:'Update application - Certificates and secrets management') ,
(EventAction:('MailItemsAccessed','FileDownloaded')) ,
(ParentBaseFileName:('*\\w3wp.exe','*\\httpd.exe','*\\nginx.exe','*\\tomcat*.exe') + ImageFileName:('*\\cmd.exe','*\\powershell.exe','*\\pwsh.exe','*\\sh','*\\bash')) ,
(VulnerabilityID:('CVE-2025-0282','CVE-2024-3400','CVE-2023-3519','CVE-2021-26855','CVE-2021-26857','CVE-2021-26858','CVE-2021-27065'))
```

### CORNFLAKE.V3 Backdoor Activity Detection
---
```sql
-- RW

-- This rule is designed to detect a wide range of activities associated with the CORNFLAKE.V3 backdoor, as detailed in observed/disseminated threat intelligence.

-- It combines multiple detection patterns covering execution, persistence, command and control, and post-exploitation behavior into a single query.

EventID:'1' + ParentImage:'*\\powershell.exe' + RawProcessName:'*\\AppData\\Roaming*' + ((RawProcessName:'*\\node.exe' + CommandLine:'*-e *') , (RawProcessName:'*\\php.exe' + CommandLine:'*-d *' + CommandLine:'* 1')) ,
EventID:'1' + ParentImage:'*\\AppData\\Roaming\\*(node|php).exe' + Image:'*\\(cmd|powershell).exe' + CommandLine:'(*systeminfo* , *tasklist* , *arp -a* , *nltest* , *setspn* , *whoami /all* , *Get-LocalGroup* , *KerberosRequestorSecurityToken*') ,
EventID:('12','13') + TargetObject:'*HKU*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' + Details:'*AppData\\Roaming\\*(node|php).exe*' ,
EventID:'3' + (RemoteAddress:('138.199.161.141','159.69.3.151','167.235.235.151','128.140.120.188','177.136.225.135') , DestinationHostname:('varying-rentals-calgary-predict.trycloudflare.com','dnsmicrosoftds-data.com','windows-msg-as.live')) ,
EventID:('1','11') + Hashes:'*MD5=(04668c6f39b0a67c4bd73d5459f8c3a3,bcdffa955608e9463f272adca205c9e65592840d98dcb63155b9fa0324a88be2,ec82216a2b42114d23d59eecb876ccfc)*' ,
EventID:'3' + Image:('*\\powershell.exe','*\\mshta.exe') + DestinationHostname:('nodejs.org','windows.php.net') ,
EventID:'1' + Image:'*\\rundll32.exe' + CommandLine:'*\\AppData\\Roaming\\*.png*'
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

(
  /* Impossible Travel - Multi-Geo Login */
  EventType:'Authentication' + EventOutcome:'success' + SourceIpGeoCountryName!='' | stats dc(SourceIpGeoCountryName) as country_count, values(SourceIpGeoCountryName) as countries by UserName, time span=4h | where country_count > 1 | eval detection_type='Impossible Travel - Multi-Geo Login', description=UserName + ' logged in from ' + country_count + ' countries: ' + countries + ' within 4 hours.' | fields time, UserName, countries, description, detection_type
) ,
(
  /* Phishing Link Click */
  EventType:'WebRequest' + VulnerabilityCategory:('Phishing & Fraud','Malware') | eval detection_type='Phishing Link Click', description=UserName + ' accessed a URL categorized as phishing/malware: ' + TargetUrl | fields time, UserName, TargetUrl, TargetHostname, description, detection_type
) ,
(
  /* Suspicious TLD Visited */
  EventType:'WebRequest' + TargetUrl:'*.xyz' , TargetUrl:'*.top' , TargetUrl:'*.online' , TargetUrl:'*.club' , TargetUrl:'*.live' , TargetUrl:'*.icu' , TargetUrl:'*.gq' , TargetUrl:'*.buzz' | eval detection_type='Suspicious TLD Visited', description=UserName + ' visited a URL with a suspicious TLD: ' + TargetUrl | fields time, UserName, SourceIp, TargetHostname, TargetUrl, description, detection_type
) ,
(
  /* Suspicious Process Execution */
  EventType:'ProcessRollup2' + (
    (ImageFileName:('powershell.exe','pwsh.exe') + CommandLine:('*-enc *' , '*-encoded *' , '*-w hidden *' , '* IEX *' , '* Invoke-Expression *')) ,
    (ImageFileName:'mshta.exe' + CommandLine:('*http:*' , '*https:*' , '*javascript:*'))
  ) | eval detection_type='Suspicious Process Execution', description=UserName + ' executed a suspicious command on ' + ComputerName + ': ' + CommandLine | fields time, UserName, ComputerName, ImageFileName, CommandLine, description, detection_type
) ,
(
  /* New Service Created */
  EventID:'4697' + SourceName:'Microsoft-Windows-Security-Auditing' | eval detection_type='New Service Created', description='A new service \'' + ServiceName + '\' pointing to \'' + ServiceFileName + '\' was created on ' + ComputerName + ' by ' + UserName | fields time, UserName, ComputerName, ServiceName, ServiceFileName, description, detection_type
) ,
(
  /* New Scheduled Task Created */
  EventID:'106' + SourceName:'Microsoft-Windows-TaskScheduler/Operational' | eval detection_type='New Scheduled Task Created', description='A new scheduled task \'' + TaskName + '\' was created on ' + ComputerName + ' by ' + UserName | fields time, UserName, ComputerName, TaskName, description, detection_type
) ,
(
  /* Cryptocurrency Site Visited */
  EventType:'WebRequest' + TargetUrl:('*binance.com*' , '*coinbase.com*' , '*kraken.com*' , '*kucoin.com*' , '*bybit.com*' , '*metamask.io*') | eval detection_type='Cryptocurrency Site Visited', description=UserName + ' accessed a cryptocurrency-related website: ' + TargetUrl | fields time, UserName, SourceIp, TargetHostname, TargetUrl, description, detection_type
)
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

(
  /* Known malicious file hashes */
  SHA256HashData:('c865f24e4b9b0855b8b559fc3769239b0aa6e8d680406616a13d9a36fbbc2d30','7d0c9855167e7c19a67f800892e974c4387e1004b40efb25a2a1d25a99b03a10','b3e93bfef12678294d9944e61d90ca4aa03b7e3dae5e909c3b2166f122a14dad','da59d67ced88beae618b9d6c805f40385d0301d412b787e9f9c9559d00d2c880','70ec2e65f77a940fd0b2b5c0a78a83646dec175836552622ad17fb974f1','263ab8c9ec821ae573979ef2d5ad98cda5009a39e17398cd31b0fad98d862892')
) ,
(
  /* Known C2 network indicators */
  (RemoteAddress:('185.156.72.80','94.141.12.182') , DestinationHostname:'eaglekl.digital')
) ,
(
  /* ntdll.dll unhooking via process access */
  EventID:'10' + TargetImage:'*\\ntdll.dll'
) ,
(
  /* Suspicious preloading of modules */
  LoadedImageName:('*\\wininet.dll','*\\crypt32.dll','*\\advapi32.dll','*\\urlmon.dll')
  | stats dc(LoadedImageName) as module_count, values(LoadedImageName) as loaded_modules by time, ComputerName, UserName, Image, ProcessId, CommandLine
  | where module_count >= 3
)
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

(SHA256HashData:('2acaa9856ee29337c06cc2858fd71b860f53219504e6756faa3812019b5df5a6','0b47e53f2ada0555588aa8a6a4491e14d7b2528c9a829ebb6f7e9463963cd0e4', /* list all */)) ,
(ImageFileName:'powershell.exe' + CommandLine:('*irm *' , '*iex *' , '*Invoke-RestMethod*' , '*Invoke-Expression*' , '*-w h*' , '*-windowstyle hidden*')) ,
(RegistryPath:'*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*' + RegistryValueName:('ChromeUpdater','0neDrive')) ,
(RemoteAddress:('168.119.96.41','95.217.22.175', /* list all */) , DestinationHostname:('cluders.org','bronxy.cc', /* list all */) , DestinationHostname:'*trycloudflare.com*') ,
(ImageFileName:'schtasks.exe' + CommandLine:'*/create*' + (CommandLine:'*/du 9999:59*' , CommandLine:'*BitLocker Encrypt All Drives*' + CommandLine:'*\\OneDriveCloud\\taskhostw.exe*'))
```

### Water Curse Threat Actor - Multi-Stage
---
```sql
-- This detection rule identifies multiple Tactics, Techniques, and Procedures (TTPs) associated with the Water Curse threat actor.
-- Water Curse leverages compromised GitHub repositories to distribute malware, targeting developers and cybersecurity professionals.
-- This rule detects the entire attack chain, from initial execution via malicious Visual Studio project files to defense evasion, persistence, and C2 communication.
-- Source: https://www.trendmicro.com/en_us/research/25/f/water-curse.html
-- RW

(
  /* Initial execution via malicious Visual Studio project file */
  ParentImageName:'MSBuild.exe' + ImageFileName:'cmd.exe' + CommandLine:'*/c*' + CommandLine:'*.exec.cmd*' + CommandLine:'*Temp\\MSBuildTemp*'
) ,
(
  /* Defense Evasion via PowerShell to disable Windows Defender and System Restore */
  ImageFileName:'powershell.exe' + CommandLine:'*Set-MpPreference* -ExclusionPath*C:\\*' , CommandLine:'*vssadmin*delete*shadows*/all*' , CommandLine:'*Set-ItemProperty*HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore*DisableSR*'
) ,
(
  /* UAC Bypass via ms-settings protocol handler hijack */
  RegistryPath:'*\\Software\\Classes\\ms-settings\\shell\\open\\command*' + (RegistryValueName:'(Default)' , RegistryValueName:'DelegateExecute')
) ,
(
  /* Persistence via unusually configured Scheduled Task */
  ImageFileName:'schtasks.exe' + CommandLine:'*/create*' + (CommandLine:'*/du 9999:59*' , CommandLine:'*BitLocker Encrypt All Drives*' + CommandLine:'*\\OneDriveCloud\\taskhostw.exe*')
) ,
(
  /* Data Staging and Reconnaissance */
  (ImageFileName:'7z.exe' + RawProcessName:'C:\\ProgramData\\sevenZip\\*' + CommandLine:'*-p*') ,
  (ParentImageName:'NVIDIA Control Panel.exe' + ParentImage:'*\\Microsoft\\Vault\\UserRoamingTiles\\NVIDIAContainer*' + ImageFileName:('curl.exe','wmic.exe','tasklist.exe'))
) ,
(
  /* Malicious File Artifacts Creation */
  (TargetFilePath:'*\\.vs-script\\*' + TargetFileName:('antiDebug.ps1','disabledefender.ps1')) ,
  (TargetFilePath:'*\\AppData\\Local\\Temp\\*' + TargetFileName:'SearchFilter.exe') ,
  (TargetFilePath:'*\\Microsoft\\Vault\\UserRoamingTiles\\NVIDIAContainer*' + TargetFileName:'NVIDIA Control Panel.exe')
) ,
(
  /* C2 and Exfiltration Network Activity */
  TargetUrl:('*store-eu-par-2.gofile.io*','*api.telegram.org*','*popcorn-soft.glitch.me*','*pastejustit.com*','*pastesio.com*') , RemoteAddress:'46.101.236.176' , ImageFileName:'RegAsm.exe'
)
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

EventID:('1','11') + (
  /* PPL Loader launching ClipUp */
  (EventID:'1' + ParentImageName:'CreateProcessAsPPL.exe' + ImageFileName:'clipup.exe') ,
  /* Anomalous ClipUp Execution for File Write */
  (EventID:'1' + ImageFileName:'clipup.exe' + CommandLine:'*-ppl*' + (CommandLine:'*\\ProgramData\\Microsoft\\Windows Defender\\*' , CommandLine:'*\\Program Files\\Windows Defender\\*' , CommandLine:'*\\Program Files (x86)\\Windows Defender\\*' , CommandLine:'-ppl *.*PROGRA~*')) ,
  /* Suspicious Auto-Start Service Creation */
  (EventID:'1' + ImageFileName:'sc.exe' + CommandLine:'*create*' + CommandLine:'*start=auto*' + (CommandLine:'*binPath=*CreateProcessAsPPL.exe*' , CommandLine:'*binPath=*\\Users\\*' , CommandLine:'*binPath=*\\ProgramData\\*' , CommandLine:'*binPath=*\\Windows\\Temp\\*' , CommandLine:'*binPath=*\\Temp\\*' , CommandLine:'binPath=.*(cmd|powershell|pwsh).exe')) ,
  /* Unauthorized Defender Directory File Modification */
  (EventID:'11' + (TargetFileName:'C:\\ProgramData\\Microsoft\\Windows Defender\\*' , TargetFileName:'C:\\Program Files\\Windows Defender\\*' , TargetFileName:'C:\\Program Files (x86)\\Windows Defender\\*') + ImageFileName!:'(\\MsMpEng.exe , \\NisSrv.exe , \\MsMpEngCP.exe , \\MpCmdRun.exe , \\TiWorker.exe , \\TrustedInstaller.exe , \\svchost.exe , \\setup.exe)')
)
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

EventType:'ProcessRollup2' + isnotnull(RawProcessName) + isnotnull(CommandLine) + (
  eval CommandLineExecutable = replace(CommandLine, '^(".*?("|\\s)|\\S+)', '\\1')
  | eval CommandLineExecutable = trim(CommandLineExecutable, '"')
  | eval CommandLineFileName = replace(CommandLineExecutable, '^.*\\\\', '')
  | where lower(RawProcessName) != lower(CommandLineExecutable) AND lower(ImageFileName) == lower(CommandLineFileName) AND ParentImageName!:'(services.exe , svchost.exe , WmiPrvSE.exe , msiexec.exe , TiWorker.exe)' AND RawProcessName!:'(?i)C:\\Windows\\(System32|SysWOW64|servicing)|C:\\Program Files|AppData\\Local\\Temp|\\Windows\\Temp'
) | fields time, ComputerName, UserName, ImageFileName, RawProcessName, CommandLine, CommandLineExecutable, ParentImageName
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

EventID:('1','7','11') + (
  (EventID:'1' + len(Image) > 260) ,
  (EventID:'7' + len(LoadedImageName) > 260) ,
  (EventID:'11' + len(TargetFileName) > 260)
) | fields time, ComputerName, UserName, ImageFileName, RawProcessName, CommandLine, TargetFileName, EventType = case(EventID=='1', 'Process Creation with Long Path', EventID=='7', 'Module Load from Long Path', EventID=='11', 'File Creation with Long Path', true(), null)
```

### Suspicious SQL Server Activity
---
```sql
-- Name: Suspicious SQL Server Activity
-- Author: RW
-- Date: 2025-08-23
-- Description: Detects a variety of suspicious activities related to Microsoft SQL Server that could indicate reconnaissance, execution, or persistence. This includes enabling high-risk procedures, sqlservr.exe spawning shells, suspicious use of sqlcmd or Invoke-Sqlcmd, loading of untrusted CLR assemblies, and execution of suspicious startup procedures.
-- MITRE ATT&CK: T1543.003, T1059.001, T1059.003, T1059.006, T1003, T1041

EventID:('15457','17135') + (
  /* High-Risk SQL Procedure Enabled, SQL CLR Enabled, SQL CLR Strict Security Disabled */
  (EventID:'15457' + Data1:('xp_cmdshell','Ole Automation Procedures') + Data2:'1') ,
  (EventID:'15457' + Data1:'clr enabled' + Data2:'1') ,
  (EventID:'15457' + Data1:'clr strict security' + Data2:'0') ,
  /* Suspicious SQL Startup Procedure */
  (EventID:'17135' + Data1:'(*xp_* , *sp_* , *cmdshell* , *shell* , *exec*)')
) ,
(
  /* SQL Server Spawning Shell */
  ParentImageName:'sqlservr.exe' + ImageFileName:('cmd.exe','powershell.exe')
) ,
(
  /* Suspicious sqlcmd.exe Usage */
  ImageFileName:'sqlcmd.exe' + CommandLine:('*xp_cmdshell*' , '*sp_oacreate*' , '*sp_add_trusted_assembly*' , '*sp_configure*' , '*OPENROWSET*' , '*-o *' , '*--outputfile*' , '*http*//*' , '*-t 0*' , '*--query_timeout=0*')
) ,
(
  /* Potential SQL CLR Assembly Loaded */
  EventType:'FileCreation' + TargetFileName:'*.dll' + TargetFilePath:'*\\Microsoft SQL Server\\*\\MSSQL\\Binn\\*'
) ,
(
  /* Suspicious Invoke-Sqlcmd Usage from PowerShell logs */
  EventID:'4104' + ScriptBlockText:'*Invoke-Sqlcmd*' + (ScriptBlockText:'*xp_cmdshell*' , ScriptBlockText:'*sp_oacreate*' , ScriptBlockText:'*sp_add_trusted_assembly*' , ScriptBlockText:'*sp_configure*' , ScriptBlockText:'*OPENROWSET*' , ScriptBlockText:'*-QueryTimeout 0*')
)
```

### SQL Injection (SQLi) Attempts
---
```sql
-- Name: Combined SQL Injection (SQLi) Detection
-- Author: RW
-- Date: 2025-08-23

-- This rule combines multiple SQLi detection techniques into a single query.
-- It identifies general attempts, error-based, time-based, database reconnaissance, and authentication bypass attacks.

(
  /* Auth Bypass */
  (Action:('0','success','allow','accepted') + (UserName:'*\' or *' , UserName:'*\'or\'--*' , UserName:'* or 1=1*' , UserName:'*admin\'--*')) ,
  /* Time-Based Blind */
  (ResponseTime>5000 + (Uri:'*sleep(*)' , Uri:'*waitfor delay*' , Uri:'*benchmark(*)' , Uri:'*pg_sleep(*)' )) ,
  /* Error-Based */
  (ResponseBody:'(*error in your sql syntax* , *unclosed quotation mark* , *ora-[0-9][0-9][0-9][0-9][0-9]* , *invalid column name*)') ,
  /* DB Recon */
  (SqlQuery:* + (SqlQuery:'*information_schema*' , SqlQuery:'*sys.objects*' , SqlQuery:'*pg_catalog*' , SqlQuery:'*sqlite_master*')) ,
  /* General Attempt */
  (Uri:'(*\' or * , * union *select * , *--* , *\/** , *\';*)')
) | eval detection_type = case(
  Action:('0','success','allow','accepted') + (UserName:'*\' or *' , UserName:'*\'or\'--*' , UserName:'* or 1=1*' , UserName:'*admin\'--*'), 'SQLi Authentication Bypass',
  ResponseTime>5000 + (Uri:'*sleep(*)' , Uri:'*waitfor delay*' , Uri:'*benchmark(*)' , Uri:'*pg_sleep(*)' ), 'Time-Based Blind SQLi',
  ResponseBody:'(*error in your sql syntax* , *unclosed quotation mark* , *ora-[0-9][0-9][0-9][0-9][0-9]* , *invalid column name*)', 'Error-Based SQLi',
  SqlQuery:* + (SqlQuery:'*information_schema*' , SqlQuery:'*sys.objects*' , SqlQuery:'*pg_catalog*' , SqlQuery:'*sqlite_master*'), 'SQLi DB Reconnaissance',
  Uri:'(*\' or * , * union *select * , *--* , *\/** , *\';*)', 'General SQLi Attempt',
  true(), null
) | where detection_type != null | stats count, values(Uri) as urls, values(SqlQuery) as queries, values(Action) as outcomes by time, detection_type, ClientIP as SourceIP, UserName as User, ComputerName as Destination, event_simpleName as LogSource | fields time, detection_type, SourceIP, User, Destination, urls, queries, outcomes, count, LogSource
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

(
  /* Part 1: High/Critical Vulnerabilities */
  (event_simpleName:'VulnerabilityDetected' + VulnerabilitySeverity:('High','Critical') | eval Tactic='Initial Access', Technique='Exploit Public-Facing Application', DetectionSource='Vulnerability Scan', Entity=ContainerImage, Description='High/Critical severity vulnerability \'' + VulnerabilityId + '\' detected in image \'' + ContainerImage + '\'.') ,
  /* Part 2a: Privileged Containers */
  (event_simpleName:'KubernetesAudit' + SecurityContextPrivileged:'true' + UserName!:'(system:masters , cluster-admin , azure-operator)' | eval Tactic='Privilege Escalation', Technique='Escape to Host', DetectionSource='Kubernetes Audit', Entity=UserName, Description='Privileged container \'' + ContainerName + '\' created by user \'' + UserName + '\' in namespace \'' + Namespace + '\'.') ,
  /* Part 2b: Runtime Escape Attempts */
  (ParentImageName:('*runc*' , '*containerd-shim*') + ImageFileName:('nsenter','insmod','modprobe','chroot') | eval Tactic='Privilege Escalation', Technique='Escape to Host', DetectionSource='EDR', Entity=ComputerName, Description='Suspicious process \'' + ImageFileName + '\' with command line \'' + CommandLine + '\' executed from a container context on host \'' + ComputerName + '\'.') ,
  /* Part 3: Insecure API Access */
  (event_simpleName:'KubernetesAudit' + Verb:'create' + Resource:'clusterrolebindings' + RoleRefName:('cluster-admin','admin') + UserName!:'(system:masters , cluster-admin , azure-operator)' | eval Tactic='Privilege Escalation', Technique='Valid Accounts', DetectionSource='Kubernetes Audit', Entity=UserName, Description='User \'' + UserName + '\' created a cluster role binding to a privileged role \'' + RoleRefName + '\'.') ,
  /* Part 4: Untrusted Registry */
  (event_simpleName:'ContainerStart' + Image:* + Image!:'(mcr.microsoft.com/* , docker.io/* , k8s.gcr.io/* , quay.io/* , gcr.io/*)' | eval Registry=replace(Image,'^([^/]+)/.*','\\1'), Tactic='Initial Access', Technique='Supply Chain Compromise', DetectionSource='Container Inventory', Entity=Image, Description='Container started from untrusted registry: \'' + Image + '\' on host \'' + ComputerName + '\'.')
) | stats count by time, Tactic, Technique, DetectionSource, Entity, Description | fields time, Tactic, Technique, DetectionSource, Entity, Description
```

### UNC6384 (Mustang Panda) Campaign IOCs and TTPs
---
```sql
-- title: UNC6384 Mustang Panda Campaign IOCs and TTPs
-- description: Detects multiple indicators of compromise (IOCs) and tactics, techniques, and procedures (TTPs) associated with a UNC6384 (Mustang Panda) campaign targeting diplomats, as reported by Google in August 2025. This rule covers file hashes, network indicators, persistence mechanisms, and behavioral patterns related to the STATICPLUGIN, CANONSTAGER, and SOGU.SEC malware families.
-- author: RW
-- date: 2025-08-26

(event_simpleName:"SyntheticProcessRollup2"+SHA256HashData IN ("65c42a7ea18162a92ee982eded91653a5358a7129c7672715ce8ddb6027ec124","3299866538aff40ca85276f87dd0cefe4eafe167bd64732d67b06af4f3349916","e787f64af048b9cb8a153a0759555785c8fd3ee1e8efbca312a29f2acb1e4011","cc4db3d8049043fa62326d0b3341960f9a0cf9b54c2fbbdffdbd8761d99add79","d1626c35ff69e7e5bde5eea9f9a242713421e59197f4b6d77b914ed46976b933")),
(event_simpleName:"NetworkConnectIP4"+RemoteAddressIP4 IN ("103.79.120.72","166.88.2.90")),
(event_simpleName:"DnsRequest"+DNSDomainName:"mediareleaseupdates.com"),
(event_simpleName:"HttpRequest"+HTTPUserAgent:"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 10.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)"),
(event_simpleName IN ("RegistryCreateKey","RegistrySetValue","RegistryRenameKey")+RegistryPath:"*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\CanonPrinter"+RegistryValueData:"*cnmpaui.exe*"),
(event_simpleName:"ModuleLoad"+ImageFileName:"*\\cnmpaui.exe"+LoadedImageName:"*\\cnmpaui.dll"),
(event_simpleName:"ProcessRollup2"+ImageFileName:"*\\DNVjzaXMFO\\*"),
(event_simpleName:"ProcessRollup2"+ImageFileName:"*C:\\Users\\Public\\Intelnet\\*"),
(event_simpleName:"ProcessRollup2"+ImageFileName:"*C:\\Users\\Public\\SecurityScan\\*")
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

event_platform IN ("Win", "Linux")
(
    -- Part 1: Suspicious commands and file activity
    (event_type IN ("ProcessRollup2", "SyntheticProcessRollup2")
     AND (
         CommandLine CONTAINS "service sshd_operns start"
         OR CommandLine CONTAINS "access-list 10"
         OR CommandLine CONTAINS "access-list 20"
         OR CommandLine CONTAINS "access-list 50"
         OR CommandLine CONTAINS "useradd cisco"
         OR CommandLine CONTAINS "vi /etc/sudoers"
         OR CommandLine CONTAINS "monitor capture"
         OR CommandLine CONTAINS "span"
         OR CommandLine CONTAINS "erspan"
     ))
    OR
    (event_type = "FileCreate"
     AND (
         TargetFileName ENDSWITH "mycap.pcap"
         OR TargetFileName ENDSWITH "tac.pcap"
         OR TargetFileName ENDSWITH "1.pcap"
     ))
    OR
    -- Part 2: Suspicious network connections
    (event_type = "NetworkConnect"
     AND (
         RemotePort = 57722
         OR RemotePort MATCHES_REGEX "^\d{3,5}22$"
     )
     -- FP-Tuning: Add NOT RemoteAddress IN (known_good_ips) to reduce false positives
    )
)
-- Enrich results with context
| project TimeStamp, event_type, CommandLine, TargetFileName, RemoteAddress, RemotePort, ProcessName, UserName
| eval reason = case(
     CommandLine CONTAINS "service sshd_operns start", "Suspicious Service Started: sshd_operns",
     CommandLine CONTAINS "access-list 10" OR CommandLine CONTAINS "access-list 20" OR CommandLine CONTAINS "access-list 50", "Suspicious ACL Modification Detected",
     CommandLine CONTAINS "useradd cisco", "Suspicious User Creation: cisco",
     CommandLine CONTAINS "vi /etc/sudoers", "Sudoers File Edited",
     CommandLine CONTAINS "monitor capture" OR CommandLine CONTAINS "span" OR CommandLine CONTAINS "erspan", "Packet/Traffic Capture Command Detected",
     TargetFileName ENDSWITH "mycap.pcap" OR TargetFileName ENDSWITH "tac.pcap" OR TargetFileName ENDSWITH "1.pcap", "Suspicious PCAP Filename Detected",
     RemotePort = 57722, "Network Connection to IOS XR Backdoor Port 57722",
     RemotePort MATCHES_REGEX "^\d{3,5}22$", "Network Connection to High Port Ending in '22'",
     true, "Unknown Match - Check Raw Event"
 )
| sort TimeStamp desc
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

-- Search for events matching the specified indicators
event_platform IN ("Win", "Mac", "Linux")
| search (
    -- Vulnerable driver loads (file hashes)
    event_simpleName=ModuleLoad AND SHA256HashData IN (
        "12b3d8bc5cc1ea6e2acd741d8a80f56cf2a0a7ebfa0998e3f0743fcf83fabb9e",
        "0be8483c2ea42f1ce4c90e84ac474a4e7017bc6d682e06f96dc1e31922a07b10",
        "9c394dcab9f711e2bf585edf0d22d2210843885917d409ee56f22a4c24ad225e"
    )
    OR
    -- Suspicious files written
    event_simpleName=FileWrite AND FilePath LIKE "C:\\Program Files\\RunTime\\%" AND FileName IN ("RuntimeBroker.exe", "Amsdk_Service.sys")
    OR
    -- Suspicious services created (registry)
    event_simpleName=RegistryActivity AND RegistryPath LIKE IN (
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Termaintor%",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Amsdk_Service%"
    )
    OR
    -- C2 traffic
    event_simpleName=NetworkConnectIP4 AND RemoteAddressIP4 IN (
        "47.239.197.97", "8.217.38.238", "156.234.58.194", "156.241.144.66", "1.13.249.217"
    ) AND RemotePort IN (52116, 52117, 8888, 52110, 52111, 52139, 52160, 9527, 9528)
)
-- Categorize indicators
| eval indicator_type = case(
    SHA256HashData IN (
        "12b3d8bc5cc1ea6e2acd741d8a80f56cf2a0a7ebfa0998e3f0743fcf83fabb9e",
        "0be8483c2ea42f1ce4c90e84ac474a4e7017bc6d682e06f96dc1e31922a07b10",
        "9c394dcab9f711e2bf585edf0d22d2210843885917d409ee56f22a4c24ad225e"
    ), "Vulnerable_Driver_Loaded",
    FilePath LIKE "C:\\Program Files\\RunTime\\%" AND FileName IN ("RuntimeBroker.exe", "Amsdk_Service.sys"), "Suspicious_File_Written",
    RegistryPath LIKE IN (
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Termaintor%",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Amsdk_Service%"
    ), "Suspicious_Service_Created",
    RemoteAddressIP4 IS NOT NULL, "C2_Traffic_Detected",
    true, "Other"
)
| eval indicator_value = case(
    indicator_type="Vulnerable_Driver_Loaded", SHA256HashData,
    indicator_type="Suspicious_File_Written", FilePath,
    indicator_type="Suspicious_Service_Created", RegistryPath,
    indicator_type="C2_Traffic_Detected", RemoteAddressIP4 + ":" + RemotePort,
    true, "N/A"
)
-- Aggregate by device
| groupBy field=aid
    earliest=event_timestamp as first_seen
    latest=event_timestamp as last_seen
    collect=UserName as users
    distinct_count=indicator_type as distinct_indicator_count
    collect=indicator_type as indicators
    collect=indicator_value as indicator_details
-- Core detection logic: vulnerable driver + another indicator
| where indicators LIKE "%Vulnerable_Driver_Loaded%" AND distinct_indicator_count > 1
-- Add IOCTL note
| eval note = "IOCTL detection (DeviceIoControl to 'amsdk' with codes 0x80002010, 0x80002048) requires specific EDR logs. This activity may also be present but is not detected by this query."
-- Format output
| project first_seen, last_seen, aid as host, users, indicators, indicator_details, note
```

### APT28 NotDoor Backdoor Activity Detection
---
```sql
-- Name: APT28 NotDoor Backdoor Activity
-- Author: RW
-- Date: 2025-09-03
-- Description: This rule detects various activities associated with the NotDoor backdoor, used by APT28. It looks for specific file creation events, process command lines, registry modifications, and network communications.
-- False Positive Sensitivity: Medium

filter="
(event_simpleName=FileCreate AND (SHA256HashData IN ('5a88a15a1d764e635462f78a0cd958b17e6d22c716740febc114a408eef66705','8f4bca3c62268fff0458322d111a511e0bcfba255d5ab78c45973bd293379901') OR TargetFileName='C:\\ProgramData\\testtemp.ini' OR icontains(TargetFileName,'\\\\AppData\\\\Local\\\\Temp\\\\Test\\\\(report|invoice|contract|photo|scheme|document)_[^\\\\]+\\.(jpg|jpeg|gif|bmp|ico|png|pdf|doc|docx|xls|xlsx|ppt|pptx|mp3|mp4|xml)$'))) OR
(event_simpleName=ProcessRollup2 AND (FileName='nslookup.exe' AND icontains(CommandLine,'\\.dnshook\\.site') OR FileName='curl.exe' AND icontains(CommandLine,'webhook\\.site') OR icontains(CommandLine,'copy.*c:\\\\programdata\\\\testtemp.ini.*\\\\Microsoft\\\\Outlook\\\\VbaProject.OTM'))) OR
(event_simpleName=RegValueModified AND (icontains(TargetObject,'\\\\Software\\\\Microsoft\\\\Office\\\\[^\\\\]+\\\\Outlook\\\\LoadMacroProviderOnBoot$') AND Details=1 OR icontains(TargetObject,'\\\\Software\\\\Microsoft\\\\Office\\\\[^\\\\]+\\\\Outlook\\\\Security\\\\Level$') AND Details=1 OR icontains(TargetObject,'\\\\Software\\\\Microsoft\\\\Office\\\\[^\\\\]+\\\\Outlook\\\\Options\\\\General\\\\PONT_STRING$') AND Details=';')) OR
((event_simpleName=DnsRequest AND icontains(DomainName,'(webhook|dnshook)\\.site$')) OR (event_simpleName=NetworkConnectIP4 AND icontains(RemoteAddressIP4,'(webhook|dnshook)\\.site'))) OR
(your_email_sourcetype AND RecipientEmailAddress='a.matti444@proton.me' AND Subject='Re: 0')
"
| sort asc
```

### MeetC2 C2 Activity via Google Calendar API
---
```sql
-- Part 1: FQL filter for suspicious Google Calendar events (assuming Google Workspace logs ingested as events)
event_name:("calendar.events.insert" OR "calendar.events.update" OR "calendar.acl.create") + (parameters.summary:"Meeting from nobody:[COMMAND]" OR (parameters.description:"[OUTPUT]" AND parameters.description:"[/OUTPUT]*") OR parameters.acl.scope.value:"*gserviceaccount.com")
-- Part 2: FQL filter for potential C2 beaconing (using NetworkConnect or similar events)
url:"www.googleapis.com/calendar/v3/calendars/*/events" + (process_path:null OR process_path:!~"(chrome|msedge|firefox|outlook|teams).exe$")
```

### APT37 Rustonotto, Chinotto, and FadeStealer Activity
---
```sql
event.EventCode:("1" OR "11" OR "13") OR event.url:"*U=%*"
+ (
  (event.EventCode:("1" OR "11") + event.md5:("b9900bef33c6cc9911a5cd7eeda8e093" OR "7967156e138a66f3ee1bfce81836d8d0" OR "77a70e87429c4e552649235a9a2cf11a" OR "04b5e068e6f0079c2c205a42df8a3a84" OR "d2b34b8bfafd6b17b1cf931bb3fdd3db" OR "3d6b999d65c775c1d27c8efa615ee520" OR "89986806a298ffd6367cf43f36136311" OR "4caa44930e5587a0c9914bda9d240acc"))
  OR
  (event.EventCode:"11" + (event.TargetFilename:("C:\\ProgramData\\3HNoWZd.exe" OR "C:\\ProgramData\\wonder.cab" OR "C:\\ProgramData\\tele_update.exe" OR "C:\\ProgramData\\tele.conf" OR "C:\\ProgramData\\tele.dat" OR "C:\\ProgramData\\Password.chm" OR "C:\\ProgramData\\1.html") OR event.TargetFilename:"*\\VSTelems_Fade\\(NgenPdbk|NgenPdbc|NgenPdbm|VSTelems_FadeOut|VSTelems_FadeIn)*" OR event.TargetFilename:"*(watch_|usb_|data_)*.rar"))
  OR
  (event.EventCode:"1" + (event.CommandLine:"*schtasks* /create *MicrosoftUpdate*3HNoWZd.exe*" OR (event.Image:"*\\mshta.exe" + event.CommandLine:"*http*") OR (event.ParentImage:"*\\cmd.exe" + event.Image:"*\\expand.exe" + event.CommandLine:"*c:\\programdata\\wonder.cab*") OR event.Image:"c:\\programdata\\tele_update.exe"))
  OR
  (event.EventCode:"13" + event.TargetObject:"*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OnedriveStandaloneUpdater*" + event.Details:"*mshta*http*")
  OR
  (event.url:"*U=%*" + (event.url:"*R=%*" OR event.url:"*_file=%*"))
)
```

### Exposed Docker APIs Are Targeted in New Malware Strain
---
```sql
-- author: RW

-- This detection rule identifies a multi-stage attack targeting exposed Docker APIs.
-- The malware strain aims to establish persistent root access, create a botnet, and perform reconnaissance.
-- This rule combines several detection concepts into a single query to provide a broad overview of related malicious activities.

-- Detects Docker API exploitation attempts on port 2375 (T1190).
-- Data requirement: NetworkConnect events with http_method, uri_path, dest_port.
-- FP Tuning: Filter src_ip against known-good IPs or user agents via external lookup.
event.http_method:"POST" + event.uri_path:("/containers/create*" OR "/images/create*") + event.dest_port:"2375"
-- Post-process: Output _time, src_ip, dest_ip, user_agent with Tactic="Initial Access", Technique="Exposed Docker Daemon API", Description="Potential Docker API exploitation attempt on port 2375."

-- Detects post-exploitation command execution in containers (T1059).
-- Data requirement: ProcessStart events with process_name, process_args, container_id.
-- FP Tuning: Filter for multiple processes (e.g., curl+wget) via API/UI grouping.
event.process_name:("sh" OR "bash" OR "apk" OR "apt" OR "yum") + event.process_args:("*curl*" OR "*wget*")
-- Post-process: Group by host, container_id; filter mvcount(processes)>1 and args~curl/wget; output first_seen, last_seen, dest_host, container.id, processes, args, Tactic="Execution", Technique="Command and Scripting Interpreter", Description="Suspicious package installation followed by downloader execution in a container."

-- Detects persistence via SSH keys, cron jobs, or firewall rule changes (T1547, T1070).
-- Data requirement: FileWrite or ProcessStart events with file_path, process_name, process_args.
-- FP Tuning: Review user context for authorized changes.
event.file_path:("/root/.ssh/authorized_keys" OR "/etc/crontab" OR "/etc/cron.d/*" OR "/var/spool/cron/*") + event.file_operation:("write" OR "create") OR event.process_name:("firewall-cmd" OR "iptables") + event.process_args:("*--add-rich-rule*" OR "*--reload*" OR "*-A INPUT*" OR "*-p tcp*")
-- Post-process: Output _time, host, user, process_name, process_args, file_path, Tactic="Persistence", Technique="SSH Authorized Keys or Cron Job Modification", Description="Modification of sensitive files for persistence or firewall rules for defense evasion."

-- Detects discovery/lateral movement via masscan or connections to specific ports (T1018, T1021).
-- Data requirement: ProcessStart or NetworkConnect events with process_name, dest_port.
-- FP Tuning: Baseline legitimate traffic to ports 23, 9222, 2375.
event.process_name:"masscan" OR event.dest_port:("23" OR "9222" OR "2375")
-- Post-process: Output _time, src_ip, dest_ip, dest_port, process_name, Tactic="Discovery/Lateral Movement", Technique="Network Service Scanning", Description="Execution of masscan or connection attempts to Telnet, Chrome Debug, or Docker API ports."

-- Detects Tor-related C2 activity (T1071).
-- Data requirement: DNSQuery or ProcessStart events with query, process_name.
-- FP Tuning: Review legitimate Tor usage in environment.
event.query:"*.onion" OR event.process_name:"torsocks"
-- Post-process: Output _time, host, src_ip, query, process_name, Tactic="Command and Control", Technique="Proxy: Tor", Description="Tor-related activity detected (torsocks process or .onion domain query)."
```