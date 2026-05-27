### Active Directory Compromise via Chained Misconfigurations
---

This report details a multi-stage attack leveraging common Active Directory misconfigurations to escalate privileges from zero credentials to Enterprise Admin. The attack chain exploits disabled SMB signing, LLMNR/NBT-NS and IPv6 DNS poisoning, NTLM relay to LDAP, and a high Machine Account Quota to achieve full domain compromise.

Recent intelligence indicates that the exploitation of Machine Account Quota (MAQ) has evolved beyond traditional Resource-Based Constrained Delegation (RBCD) attacks, now frequently combining machine account creation with techniques like Shadow Credentials and certificate-based authentication attacks. Additionally, NTLM relay attacks, while a long-standing threat, are still highly prevalent and are increasingly combined with authentication coercion techniques to force victims to authenticate, making them even more effective.

### Actionable Threat Data
---

Monitor for the creation of new computer accounts by non-administrative users, especially if the `ms-DS-MachineAccountQuota` attribute is greater than zero. This can be a precursor to privilege escalation via `RBCD` or other techniques.

Detect NTLM relay attempts by monitoring for NTLM authentication sessions where the client and server IP addresses are the same, or where an unexpected server is receiving NTLM authentication requests.

Look for suspicious LDAP modifications, specifically attempts to grant "`Replication-Get-Changes-All`" privileges to non-Domain Controller accounts or to add accounts to highly privileged groups like "Enterprise Admins".

Identify `LLMNR/NBT-NS` and `IPv6 DNS` poisoning by monitoring for unsolicited or spoofed responses to name resolution queries (`UDP 5355`, `UDP 137`, and `IPv6 DNS` traffic) from unexpected sources.

Detect the use of Impacket's `secretsdump.py` by monitoring for remote registry access (e.g., `svchost.exe` loading `regsvc.dll`) and the creation of temporary files in the Windows `Temp` or `System32` directories, as well as network traffic patterns consistent with `DCSync` replication from non-Domain Controllers.

Monitor for `evil-winrm` activity by looking for WinRM connections (ports `5985/5986`) from unusual source IPs or to sensitive targets, and by enabling PowerShell module logging to capture evil-winrm's interactive PowerShell sessions.

### Suspicious Computer Account Creation by Non-Admin User
---
```sql
`wineventlog_security`
// Filter for Event Code 4741: A computer account was created. This event is generated on Domain Controllers.
EventCode=4741
// Exclude computer accounts (ending in $) creating other accounts, which can be legitimate.
| where NOT like(SubjectUserName, "%$")
// Use a lookup to identify known administrative or delegated users.
// This lookup file (identity_admin_users.csv) must be created and maintained by the user.
// It should contain a list of all users and service accounts authorized to create computer accounts.
// The lookup should have a field named 'user' containing the usernames.
| lookup identity_admin_users.csv user as SubjectUserName OUTPUT user as is_admin
// Filter for events where the creating user is NOT found in the admin lookup.
| where isnull(is_admin)
// Aggregate results and format for readability.
| stats count by _time, host, SubjectUserName, TargetUserName
| rename SubjectUserName as creating_user, TargetUserName as new_computer_account, host as domain_controller
| fields _time, domain_controller, creating_user, new_computer_account, count
```

### NTLM Relay Attempt
---
```sql
`wineventlog_security`
// Filter for successful network logons (Logon Type 3) using the NTLM protocol.
EventCode=4624 LogonType=3 AuthenticationPackageName="NTLM"
// Exclude common noise from loopback addresses.
| where NOT IpAddress IN ("127.0.0.1", "::1")
// Normalize hostnames by taking the part before the first dot and converting to lowercase for comparison.
| eval dest_host=lower(mvindex(split(host,"."), 0))
| eval src_workstation=lower(mvindex(split(WorkstationName,"."), 0))
// Core detection logic: identify when the source workstation and destination host are the same.
| where dest_host == src_workstation AND dest_host!="" AND dest_host!="-"
// Potential for False Positives: Certain applications or scheduled tasks might exhibit this behavior.
// If legitimate activity is found, add specific exclusions for the user or host.
// Example: | where NOT (dest_host="appserver1" AND AccountName="svc_account")
// Aggregate results and format for readability.
| stats earliest(_time) as first_seen latest(_time) as last_seen count by dest_host, IpAddress, AccountName, SubjectUserName
| rename dest_host as host, IpAddress as source_ip, AccountName as target_user, SubjectUserName as source_user
| fields first_seen, last_seen, host, source_ip, source_user, target_user, count
```

### LDAP ACL Modification for DCSync or Privileged Group
---
```sql
`wineventlog_security`
// Filter for Directory Service Changes (5136) or additions to high-value security groups (4728, 4732, 4756)
(EventCode=5136 ObjectClass="domainDNS" AttributeLDAPDisplayName="nTSecurityDescriptor" AttributeValue IN ("*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*", "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*", "*9923a32a-3607-11d2-b9be-0000f87a36b2*"))
OR
(EventCode IN (4728, 4732, 4756) TargetUserName IN ("Enterprise Admins", "Domain Admins", "Administrators", "Schema Admins"))
// Exclude changes made by known administrative accounts or domain controllers to reduce false positives.
// This list may need to be customized. A lookup file is recommended for more robust filtering.
| where NOT (SubjectUserName IN ("*DWM-1", "*UMFD-1") OR match(SubjectUserName, "(?i)MSOL_.*"))
// Create a human-readable reason for the alert.
| eval reason=case(
    EventCode=5136, "DCSync Replication Rights Granted to Domain Object",
    EventCode IN (4728, 4732, 4756), "Account Added to Privileged Group"
    )
// Normalize the target of the action. For group additions, the target is the member added. For ACL changes, its the object being modified.
| eval target_principal=case(
    EventCode=5136, ObjectName,
    EventCode IN (4728, 4732, 4756), MemberName
    )
| eval privileged_group=if(EventCode IN (4728, 4732, 4756), TargetUserName, "N/A")
// Aggregate and format the results.
| stats count values(reason) as reasons by _time, host, SubjectUserName, target_principal, privileged_group
| rename host as domain_controller, SubjectUserName as actor
| fields _time, domain_controller, actor, target_principal, privileged_group, reasons, count
```

### LLMNR, NBT-NS, or IPv6 DNS Poisoning
---
```sql
// This search requires the Network_Traffic and Network_Resolution data models to be populated.
// It also requires a user-created lookup file `authorized_dns_servers.csv` for the DNS poisoning detection.
[| tstats summariesonly=true allow_old_summaries=true count from datamodel=Network_Traffic where All_Traffic.transport="udp" AND All_Traffic.dest_port IN (137, 5355) by All_Traffic.src, All_Traffic.dest
    | stats dc(All_Traffic.dest) as victim_count by All_Traffic.src
    // A single host responding to many clients is suspicious. The threshold may need tuning for your environment.
    | where victim_count > 10
    | eval reason="LLMNR/NBT-NS Poisoning Detected"
    | rename All_Traffic.src as poisoner
    | fields reason, poisoner, victim_count]
| append [
    // This part of the search identifies DNS servers that are not on an approved list.
    // The lookup file `authorized_dns_servers.csv` should contain a field `server_ip` with the IP addresses of your legitimate DNS servers.
    | tstats summariesonly=true allow_old_summaries=true count from datamodel=Network_Resolution where (DNS.qtype="AAAA" OR DNS.qtype="ANY") by DNS.dest, DNS.src
    | rename DNS.dest as dns_server
    | lookup authorized_dns_servers.csv server_ip as dns_server OUTPUT server_ip as is_authorized
    | where isnull(is_authorized) AND dns_server!="0.0.0.0"
    | stats dc(DNS.src) as victim_count by dns_server
    | where victim_count > 1
    | eval reason="Potential Rogue DNS Server Detected"
    | rename dns_server as poisoner
    | fields reason, poisoner, victim_count
]
// Consolidate alerts by the suspected poisoning host.
| stats values(reason) as attack_types, sum(victim_count) as distinct_victims_observed by poisoner
```

### Impacket secretsdump.py (DCSync Attack)
---
```sql
`wineventlog_security`
// Filter for Event ID 4662: An operation was performed on an object. This event must be enabled via audit policy on Domain Controllers.
EventCode=4662
// Filter for the specific access rights GUIDs associated with DCSync.
// 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes
// 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes-All
// 9923a32a-3607-11d2-b9be-0000f87a36b2 = DS-Replication-Get-Changes-In-Filtered-Set
| where match(Properties, /(?i)(1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|9923a32a-3607-11d2-b9be-0000f87a36b2)/)
// Use a lookup to identify known domain controllers. This file must be created and maintained by the user.
// The lookup file `domain_controllers.csv` should contain a field `ip` with all DC IP addresses.
| lookup domain_controllers.csv ip as IpAddress OUTPUT ip as is_dc
// The core detection logic: alert when the source of the replication request is NOT a domain controller.
| where isnull(is_dc)
// Filter out common false positives.
// This may need tuning. For example, Azure AD Connect or other identity management solutions may perform these actions.
// Example: | where NOT (SubjectUserName="MSOL_AD_SYNC" AND IpAddress="10.1.1.5")
| where NOT (SubjectUserName IN ("*DWM-1", "*UMFD-1") OR like(SubjectUserName, "%$"))
// Aggregate results to reduce alert volume and provide a summary.
| stats earliest(_time) as first_seen latest(_time) as last_seen count by host, SubjectUserName, IpAddress, ObjectName
| rename host as domain_controller, SubjectUserName as actor_account, IpAddress as source_ip, ObjectName as object_accessed
| fields first_seen, last_seen, domain_controller, source_ip, actor_account, object_accessed, count
```

### Evil-WinRM Remote PowerShell Session
---
```sql
`wineventlog_powershell`
// Filter for PowerShell Script Block Logging events.
EventCode=4104
// Evil-WinRM creates a custom prompt function that includes its name by default.
// This is a high-fidelity indicator of the tools use.
| where like(ScriptBlockText, "%function prompt%") AND like(ScriptBlockText, "%Evil-WinRM%")
// Exclude activity from analysts or tools searching for indicators of Evil-WinRM.
| where NOT (like(ScriptBlockText, "%grep%") OR like(ScriptBlockText, "%select-string%"))
// Aggregate results to provide a summary of the activity.
| stats count earliest(_time) as first_seen latest(_time) as last_seen by host, user, ScriptBlockText
| rename host as victim_host, user as actor_user, ScriptBlockText as evidence
| fields first_seen, last_seen, victim_host, actor_user, evidence, count
```
