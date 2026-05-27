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

SELECT EndpointName AS host, UserName AS user, MIN(EventTime) AS first_activity, MAX(EventTime) AS last_activity, COUNT(DISTINCT Tactic) AS distinct_tactics, GROUP_CONCAT(DISTINCT Tactic) AS tactics_observed, GROUP_CONCAT(DISTINCT Signature) AS evidence
FROM (
  /* Initial Access & Privilege Escalation */
  SELECT EndpointName, UserName, EventTime, 'Initial Access & Privilege Escalation' AS Tactic, SrcProcCmdLine AS Signature
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND SrcProcParentName = 'w3wp.exe' AND SrcProcParentCmdLine LIKE '%SharePoint%' AND (SrcProcCmdLine LIKE '%net user guest /active:yes%' OR SrcProcCmdLine LIKE '%net localgroup administrators guest /add%' OR SrcProcCmdLine LIKE '%New-GPO%')
  UNION
  /* Discovery */
  SELECT EndpointName, UserName, EventTime, 'Discovery' AS Tactic, SrcProcCmdLine AS Signature
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND (SrcProcCmdLine LIKE '%nltest /domain_trusts%' OR SrcProcCmdLine LIKE '%wmic product get name,identifyingnumber%' OR SrcProcCmdLine LIKE '%net group "domain admins"%' OR SrcProcCmdLine LIKE '%net group "domain computers"%' OR SrcProcCmdLine LIKE '%net group "domain controllers"%' OR SrcProcCmdLine LIKE '%quser%')
  UNION
  /* Credential Access */
  SELECT EndpointName, UserName, EventTime, 'Credential Access' AS Tactic, COALESCE(SrcProcName, SrcProcCmdLine) AS Signature
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND (SrcProcName = 'mimikatz.exe' OR SrcProcCmdLine LIKE '%reg%save%hklm\\sam%' OR SrcProcCmdLine LIKE '%reg%save%hklm\\security%')
  UNION
  /* Defense Evasion - Kill AV */
  SELECT EndpointName, UserName, EventTime, 'Defense Evasion' AS Tactic, CONCAT('vmtools.exe killing processes: ', SrcProcCmdLine) AS Signature
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND SrcProcParentName = 'vmtools.exe' AND (SrcProcCmdLine LIKE '%taskkill%' OR SrcProcCmdLine LIKE '%net stop%')
  UNION
  /* Defense Evasion - Malicious Driver */
  SELECT EndpointName, UserName, EventTime, 'Defense Evasion' AS Tactic, CONCAT('Malicious driver created: ', TgtFilePath) AS Signature
  FROM deep_visibility
  WHERE EventType = 'File Creation' AND TgtFileName = 'googleApiUtil64.sys'
  UNION
  /* Command and Control */
  SELECT EndpointName, UserName, EventTime, 'Command and Control' AS Tactic, SrcProcCmdLine AS Signature
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND SrcProcCmdLine LIKE '%tunnel%run%--token%'
  UNION
  /* Lateral Movement */
  SELECT EndpointName, UserName, EventTime, 'Lateral Movement' AS Tactic, SrcProcCmdLine AS Signature
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND SrcProcCmdLine LIKE '%copy%\\c$\\users\\public%'
  UNION
  /* Persistence & Defense Evasion - RDP Modification */
  SELECT EndpointName, UserName, EventTime, 'Persistence & Defense Evasion' AS Tactic, CONCAT('RDP setting modified: ', RegistryPath) AS Signature
  FROM deep_visibility
  WHERE EventType = 'Registry Value Set' AND ((RegistryPath LIKE '%\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections' AND RegistryValue = '0') OR (RegistryPath LIKE '%\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication' AND RegistryValue = '0'))
  UNION
  /* Exfiltration */
  SELECT EndpointName, UserName, EventTime, 'Exfiltration' AS Tactic, SrcProcCmdLine AS Signature
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND SrcProcParentName IN ('rclone.exe', 'TrendSecurity.exe') AND SrcProcCmdLine LIKE '%copy%--protondrive-username%--protondrive-password%'
) AS ttps
GROUP BY host, user
HAVING distinct_tactics >= 2
ORDER BY distinct_tactics DESC
LIMIT 1000
```