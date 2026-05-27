### Warlock Ransomware Threat Report
---

Warlock is a rapidly evolving ransomware group that exploits unpatched Microsoft SharePoint vulnerabilities to gain initial access, escalate privileges, steal credentials, and deploy ransomware with data exfiltration. The group's tactics include the use of custom malware, built-in Windows tools, and a customized derivative of the leaked LockBit 3.0 builder.

Warlock ransomware, attributed to the China-based threat actor Storm-2603, has rapidly escalated its operations since its public debut in June 2025, claiming at least 16 successful attacks in its first month, with nearly half targeting government entities. The group has been observed exploiting the "ToolShell" SharePoint exploit chain (CVE-2025-49706, CVE-2025-49704, CVE-2025-53770, and CVE-2025-53771) to compromise over 400 SharePoint servers across 148 organizations.

### Actionable Threat Data
---

Initial Access & Privilege Escalation: Warlock exploits unpatched Microsoft SharePoint servers, specifically leveraging vulnerabilities like CVE-2025-49706, CVE-2025-49704, CVE-2025-53770, and CVE-2025-53771. They establish higher privileges by creating new Group Policy Objects (GPOs) and manipulating the built-in "guest" account to add it to the local "administrators" group.

Defense Evasion: The threat actor deploys a binary (e.g., vmtools.exe identified as Trojan.Win64.KILLLAV.I) to enumerate and terminate security-related processes listed in a log.txt file. This binary drops and installs a malicious driver (e.g., googleApiUtil64.sys) as a service to facilitate process termination.

Discovery & Credential Access: Warlock uses native Windows utilities like nltest for domain trust discovery (nltest /domain_trusts), and wmic to query installed applications (wmic product get name,identifyingnumber). They also employ Mimikatz for credential dumping and dump Windows registry hives (SAM and SECURITY) to extract password hashes.

Lateral Movement & Persistence: The attackers utilize Server Message Block (SMB) for copying payloads and tools across machines (e.g., copy C:\ProgramData\Mozilla\debug.exe \\<REDACTED>\c$\users\public\). They also enable RDP access by modifying registry values HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fdenytsconnections to 0 and disabling Network Level Authentication (NLA) by setting HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\userauthentication to 0.

Command and Control & Exfiltration: Warlock establishes stealthy C2 channels using protocol tunneling with a renamed Cloudflare binary (e.g., hpmews03.exe or macfee_agent.exe). Data exfiltration is performed using RClone, often disguised as legitimate tools (e.g., TrendSecurity.exe), to copy specific file types to cloud storage.

### Warlock Ransomware TTPs
---
```sql
-- Name: Warlock Ransomware Activity
-- Description: This rule detects a combination of Tactics, Techniques, and Procedures (TTPs) associated with Warlock ransomware campaigns.
-- It looks for evidence of discovery, credential access, defense evasion, lateral movement, and exfiltration by correlating multiple weak signals on a single host.
-- Author: RW
-- Date: 2025-08-21
-- References: https://www.trendmicro.com/en_us/research/25/h/warlock-ransomware.html
-- False Positive Sensitivity: Medium. This is a correlation rule that combines multiple weak signals.
-- Individual components, such as copying files to C$ or modifying RDP settings, might be legitimate administrative behavior.
-- The rule's strength comes from detecting multiple distinct TTPs on the same host in a short period. Consider tuning by adding known administrative accounts or tools to an exclusion list.

event_platform:'Win' + (
  /* Initial Access & Privilege Escalation */
  (ParentBaseFileName:'w3wp.exe' + ParentCommandLine:'*SharePoint*' + (CommandLine:'*net user guest /active:yes*' , CommandLine:'*net localgroup administrators guest /add*' , CommandLine:'*New-GPO*')) ,
  /* Discovery */
  (CommandLine:'*nltest /domain_trusts*' , CommandLine:'*wmic product get name,identifyingnumber*' , CommandLine:'*net group "domain admins"*' , CommandLine:'*net group "domain computers"*' , CommandLine:'*net group "domain controllers"*' , CommandLine:'*quser*') ,
  /* Credential Access */
  (ImageFileName:'mimikatz.exe' , CommandLine:'*reg*save*hklm\\sam*' , CommandLine:'*reg*save*hklm\\security*') ,
  /* Defense Evasion - Kill AV */
  (ParentBaseFileName:'vmtools.exe' + (CommandLine:'*taskkill*' , CommandLine:'*net stop*')) ,
  /* Defense Evasion - Malicious Driver */
  TargetFileName:'googleApiUtil64.sys' ,
  /* Command and Control */
  CommandLine:'*tunnel*run*--token*' ,
  /* Lateral Movement */
  CommandLine:'*copy*\\c$\\users\\public*' ,
  /* Persistence & Defense Evasion - RDP Modification */
  (RegistryPath:'*\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections' + RegistryValueData:'0' , RegistryPath:'*\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication' + RegistryValueData:'0') ,
  /* Exfiltration */
  (ParentBaseFileName:('rclone.exe' , 'TrendSecurity.exe') + CommandLine:'*copy*--protondrive-username*--protondrive-password*')
)
```