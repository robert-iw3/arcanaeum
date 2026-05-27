### Scattered Spider Threat Report
---

Scattered Spider is a financially motivated cybercriminal group known for its aggressive social engineering tactics, including MFA fatigue and vishing, to gain initial access and deploy ransomware. The group has recently broadened its targeting to include the aviation sector, alongside its established focus on enterprises, retail, and insurance industries.

Scattered Spider has evolved its tactics in 2025, notably by using MFA-bypassing Attacker-in-the-Middle (AiTM) phishing pages and shifting their initial access strategy to sometimes target on-premises infrastructure before moving to the cloud. This evolution is significant as it demonstrates the group's adaptability in evading traditional security controls and exploiting blind spots in enterprise security visibility.

### Actionable Threat Data
---

Monitor for phishing domains mimicking legitimate corporate login portals, often using patterns like victimname-sso.com, victimname-servicedesk.com, or victimname-okta.com.

Detect and prevent the use of remote access tools such as Fleetdeck.io, Level.io, Ngrok, Pulseway, ScreenConnect, Splashtop, Tactical RMM, Tailscale, and TeamViewer, which Scattered Spider uses for persistent intrusion.

Implement robust detection for social engineering attempts, particularly vishing and MFA fatigue attacks, where attackers impersonate IT or help desk
personnel to gain credentials or bypass MFA.

Look for indicators of credential dumping using tools like Mimikatz, or the presence of infostealers such as WarZone RAT, Raccoon Stealer, and Vidar Stealer.

Monitor for the deployment of ransomware, specifically BlackCat/ALPHV or DragonForce, and suspicious activity related to VMware ESXi environments.

### Phishing Domain Patterns
---
```sql
-- Date: 2025-07-22
--
-- References:
-- - https://blog.checkpoint.com/research/exposing-scattered-spider-new-indicators-highlight-growing-threat-to-enterprises-and-aviation/
--
-- Description:
-- This detection looks for DNS queries to domains that match known phishing patterns used by the threat group Scattered Spider.
-- The group often registers domains that mimic legitimate corporate services by appending keywords like "-sso", "-servicedesk", or "-okta" to a target's name.
--
-- Data Source:
-- This rule is designed for CIM-compliant DNS data (Network_Resolution data model).
--
-- False Positive Sensitivity: Medium
-- This detection may generate false positives if legitimate third-party services used by your organization follow a similar naming convention.
-- To improve fidelity, it is highly recommended to implement the tuning suggestions included as comments in the search logic.
--
-- MITRE ATT&CK Framework:
-- - Tactic: TA0001 - Initial Access
-- - Technique: T1566.001 - Spearphishing Attachment
--
(`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where nodename=DNS (DNS.query LIKE "%-sso.com" OR DNS.query LIKE "%-servicedesk.com" OR DNS.query LIKE "%-okta.com") by DNS.query, DNS.src | `drop_dm_object_name("DNS")` | rename DNS.query as query, DNS.src as src)
| `ctime(firstTime)`
| `ctime(lastTime)`

-- key part of the logic: Extract the potential target name from the domain for easier analysis.
| rex field=query "(?<potential_target>.*)-(sso|servicedesk|okta)\.com"

-- tuning: Exclude known legitimate domains. Create and populate a lookup file named `legitimate_phishing_pattern_domains.csv` with a 'query' column containing domains to exclude.
| search NOT [| inputlookup legitimate_phishing_pattern_domains.csv | fields query]

-- tuning: To significantly reduce false positives, filter for domains where the `potential_target` field matches your organization's name, abbreviations, or brand names.
-- Example: | search potential_target IN ("mycompany", "my-company", "my_org")

-- Final output formatting.
| stats values(firstTime) as firstTime, values(lastTime) as lastTime, values(count) as event_count by src, query, potential_target
| table firstTime, lastTime, src, query, potential_target, event_count
| `scatttered_spider_phishing_domain_patterns_filter`
```

### Remote Access Tool Usage
---
```sql
-- Date: 2025-07-22
--
-- References:
-- - https://blog.checkpoint.com/research/exposing-scattered-spider-new-indicators-highlight-growing-threat-to-enterprises-and-aviation/
--
-- Description:
-- This detection identifies DNS queries for domains associated with remote access software known to be leveraged by the threat group Scattered Spider for command and control and persistence. The tools include Fleetdeck, Level.io, Ngrok, Pulseway, ScreenConnect (ConnectWise Control), Splashtop, Tactical RMM, Tailscale, and TeamViewer.
--
-- Data Source:
-- This rule is designed for CIM-compliant DNS data (Network_Resolution data model).
--
-- False Positive Sensitivity: Medium
-- This detection may generate false positives, as the remote access tools detected can be used for legitimate administrative purposes. It is highly recommended to tune this detection by excluding assets and users that are authorized to use these tools.
--
-- MITRE ATT&CK Framework:
-- - Tactic: TA0011 - Command and Control
-- - Technique: T1219 - Remote Access Software
--
`tstats` summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where nodename=DNS AND (DNS.query IN ("*.fleetdeck.io", "*.level.io", "*.ngrok.io", "*.ngrok.com", "*.pulseway.com", "*.screenconnect.com", "*.connectwise.com", "*.splashtop.com", "*.tacticalrmm.com", "*.tailscale.com", "*.teamviewer.com")) by DNS.query, DNS.src, user
| `drop_dm_object_name("DNS")`
| rename query as dest_domain, src as src_ip

-- key part of the logic: The WHERE clause filters for DNS queries matching domains of tools used by Scattered Spider.

-- Convert timestamps for readability.
| `ctime(firstTime)`
| `ctime(lastTime)`

-- tuning: Exclude known legitimate sources or domains. Create and populate a lookup file named `authorized_rat_usage.csv` with columns like 'src_ip' or 'dest_domain' to filter out legitimate activity.
| search NOT [| inputlookup authorized_rat_usage.csv | fields src_ip dest_domain]

-- Final output formatting.
| table firstTime, lastTime, src_ip, user, dest_domain, count
| `scattered_spider_remote_access_tool_usage_filter`
```

### MFA Fatigue Attempt
---
```sql
-- Date: 2025-07-22
--
-- References:
-- - https://blog.checkpoint.com/research/exposing-scattered-spider-new-indicators-highlight-growing-threat-to-enterprises-and-aviation/
--
-- Description:
-- This detection identifies a high volume of authentication attempts for a single user in a short period. This pattern is indicative of a Multi-Factor Authentication (MFA) fatigue or "push bombing" attack, a technique used by groups like Scattered Spider to overwhelm a user with push notifications in hopes of an accidental approval. Vishing (voice phishing) is often used in conjunction with this technique to coerce the user into accepting the prompt.
--
-- Data Source:
-- This rule is designed for CIM-compliant Authentication data. Ensure your MFA logs (Okta, Azure, Duo, etc.) are mapped to the Authentication data model. For better performance and accuracy, you can add a filter to the `tstats` command to only look at MFA-related applications, e.g., `where All_Authentication.app IN ("okta_mfa", "azure_mfa")`.
--
-- False Positive Sensitivity: Medium
-- This detection may trigger on users who are legitimately having trouble logging in or on misconfigured applications that generate repeated authentication requests. Tuning the `mfa_attempts` threshold and adding filters for specific applications is recommended.
--
-- MITRE ATT&CK Framework:
-- - Tactic: TA0006 - Credential Access
-- - Technique: T1621 - Multi-Factor Authentication Request Generation
-- - Tactic: TA0001 - Initial Access
-- - Technique: T1566.004 - Spearphishing Voice
--
`tstats` summariesonly=true count, values(All_Authentication.action) as actions, values(All_Authentication.src) as src_ips, values(All_Authentication.app) as apps, min(_time) as firstTime, max(_time) as lastTime from datamodel=Authentication where nodename=All_Authentication by _time span=10m, All_Authentication.user
| `drop_dm_object_name("All_Authentication")`

-- key part of the logic: Filter for users with a high number of attempts. This threshold (e.g., >20) is a starting point and should be tuned for your environment.
| where count > 20

-- Convert timestamps for readability.
| `ctime(firstTime)`
| `ctime(lastTime)`

-- Final output formatting.
| rename count as mfa_attempts
| table firstTime, lastTime, user, mfa_attempts, actions, src_ips, apps
| `scattered_spider_mfa_fatigue_attempt_filter`
```

### Credential Dumping/Infostealers
---
```sql
-- Date: 2025-07-22
--
-- References:
-- - https://blog.checkpoint.com/research/exposing-scattered-spider-new-indicators-highlight-growing-threat-to-enterprises-and-aviation/
--
-- Description:
-- This rule detects the execution of tools and commands associated with credential dumping and information stealing, as used by the threat group Scattered Spider. It specifically looks for process names and command-line arguments related to Mimikatz, WarZone RAT, Raccoon Stealer, and Vidar Stealer.
--
-- Data Source:
-- This rule is designed for CIM-compliant process execution data (Endpoint.Processes data model). This data can be populated by EDR solutions, Sysmon (Event ID 1), or Windows Event ID 4688 (with command-line logging enabled).
--
-- False Positive Sensitivity: Medium
-- While the Mimikatz command-line arguments are high-fidelity indicators of malicious activity, the process names for infostealers can be changed by attackers. Additionally, legitimate penetration testing or security tools may trigger this alert. Tuning by excluding authorized systems or users may be required.
--
-- MITRE ATT&CK Framework:
-- - Tactic: TA0006 - Credential Access
-- - Technique: T1003 - OS Credential Dumping
-- - Technique: T1555 - Credentials from Password Stores
--

`tstats` summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where
  (
    -- key part of the logic: Detects high-fidelity Mimikatz command-line arguments.
    Processes.process IN ("*sekurlsa::*", "*lsadump::*", "*privilege::debug*", "*logonpasswords*") OR

    -- key part of the logic: Detects process names for Mimikatz and common infostealers. Note that attackers frequently rename these tools.
    Processes.process_name IN ("mimikatz.exe", "WarZone.exe", "Raccoon.exe", "Vidar.exe")
  )
by Processes.dest, Processes.user
| `drop_dm_object_name("Processes")`

-- Convert timestamps for readability.
| `ctime(firstTime)`
| `ctime(lastTime)`

-- Final output formatting.
| rename dest as host, user as user, process as command_line, parent_process as parent_command_line
| table firstTime, lastTime, host, user, command_line, parent_command_line, count
| `scattered_spider_credential_dumping_and_infostealer_activity_filter`
```

### BlackCat/ALPHV Ransomware Deployment Indicators
---
```sql
-- Date: 2025-07-22
--
-- References:
-- - https://blog.checkpoint.com/research/exposing-scattered-spider-new-indicators-highlight-growing-threat-to-enterprises-and-aviation/
--
-- Description:
-- This rule detects behaviors and command-line patterns associated with the deployment of BlackCat/ALPHV ransomware, a tool known to be used by the Scattered Spider threat group. The detection focuses on pre-execution activities like deleting volume shadow copies and disabling system recovery, which are common ransomware precursors. It also includes a high-fidelity indicator specific to BlackCat/ALPHV execution.
--
-- Data Source:
-- This rule is designed for CIM-compliant process execution data (Endpoint.Processes data model). This data can be populated by EDR solutions, Sysmon (Event ID 1), or Windows Event ID 4688 (with command-line logging enabled).
--
-- False Positive Sensitivity: Medium
-- While the `--access-token` flag is a high-fidelity indicator of BlackCat, other commands like `vssadmin` or `bcdedit` can be used by legitimate administrators or backup software. It is recommended to tune this detection by excluding authorized administrator accounts or systems where such activity is expected.
--
-- MITRE ATT&CK Framework:
-- - Tactic: TA0040 - Impact
-- - Technique: T1490 - Inhibit System Recovery
-- - Technique: T1486 - Data Encrypted for Impact
--

`tstats` summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where
  (
    -- key part of the logic: High-fidelity indicator for BlackCat/ALPHV ransomware execution.
    Processes.process = "* --access-token *" OR

    -- key part of the logic: Detects attempts to delete volume shadow copies to prevent system restore.
    (Processes.process_name = "vssadmin.exe" AND Processes.process = "*delete*shadows*") OR
    (Processes.process_name IN ("powershell.exe", "pwsh.exe") AND Processes.process IN ("*Get-WmiObject*Win32_Shadowcopy*Delete*", "*gwmi*Win32_Shadowcopy*Delete*", "*Get-CimInstance*Win32_Shadowcopy*Remove-CimInstance*")) OR

    -- key part of the logic: Detects attempts to disable Windows recovery features.
    (Processes.process_name = "bcdedit.exe" AND Processes.process IN ("*recoveryenabled no*", "*bootstatuspolicy ignoreallfailures*"))
  )
by Processes.dest, Processes.user
| `drop_dm_object_name("Processes")`

-- Convert timestamps for readability.
| `ctime(firstTime)`
| `ctime(lastTime)`

-- Final output formatting.
| rename dest as host, user as user, process as command_line, parent_process as parent_command_line
| table firstTime, lastTime, host, user, command_line, parent_command_line, count
| `blackcat_alphv_ransomware_deployment_indicators_filter`
```