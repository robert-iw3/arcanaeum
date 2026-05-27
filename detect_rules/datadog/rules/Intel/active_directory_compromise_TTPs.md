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
source:securityeventlog
| where EventID=4741 AND SubjectUserName!~".*\\$"
| lookup identity_admin_users.csv user=SubjectUserName OUTPUT user as is_admin
| where is_admin IS NULL
| stats count by timestamp, host, SubjectUserName, TargetUserName
| rename SubjectUserName=creating_user, TargetUserName=new_computer_account, host=domain_controller
| fields timestamp, domain_controller, creating_user, new_computer_account, count
```

### NTLM Relay Attempt
---
```sql
source:securityeventlog
| where EventID=4624 AND LogonType=3 AND AuthenticationPackageName="NTLM" AND IpAddress NOT IN ("127.0.0.1", "::1")
| eval dest_host=lower(split(host, ".")[0]), src_workstation=lower(split(WorkstationName, ".")[0])
| where dest_host=src_workstation AND dest_host!="" AND dest_host!="-"
| stats min(timestamp)=first_seen max(timestamp)=last_seen count by dest_host, IpAddress, AccountName, SubjectUserName
| rename dest_host=host, IpAddress=source_ip, AccountName=target_user, SubjectUserName=source_user
| fields first_seen, last_seen, host, source_ip, source_user, target_user, count
```

### LDAP ACL Modification for DCSync or Privileged Group
---
```sql
source:securityeventlog
| where (EventID=5136 AND ObjectClass="domainDNS" AND AttributeLDAPDisplayName="nTSecurityDescriptor" AND AttributeValue IN ("*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*", "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*", "*9923a32a-3607-11d2-b9be-0000f87a36b2*"))
  OR (EventID IN (4728, 4732, 4756) AND TargetUserName IN ("Enterprise Admins", "Domain Admins", "Administrators", "Schema Admins"))
| where SubjectUserName NOT IN ("*DWM-1", "*UMFD-1") AND SubjectUserName!~"(?i)MSOL_.*"
| eval reason=case(EventID=5136, "DCSync Replication Rights Granted to Domain Object", EventID IN (4728, 4732, 4756), "Account Added to Privileged Group")
| eval target_principal=case(EventID=5136, ObjectName, EventID IN (4728, 4732, 4756), MemberName)
| eval privileged_group=if(EventID IN (4728, 4732, 4756), TargetUserName, "N/A")
| stats count values(reason)=reasons by timestamp, host, SubjectUserName, target_principal, privileged_group
| rename host=domain_controller, SubjectUserName=actor
| fields timestamp, domain_controller, actor, target_principal, privileged_group, reasons, count
```

### LLMNR, NBT-NS, or IPv6 DNS Poisoning
---
```sql
(
  source:networktraffic
  | where transport="udp" AND dest_port IN (137, 5355)
  | stats dc(dest)=victim_count by src
  | where victim_count > 10
  | eval reason="LLMNR/NBT-NS Poisoning Detected"
  | rename src=poisoner
  | fields reason, poisoner, victim_count
) OR (
  source:networkresolution
  | where qtype IN ("AAAA", "ANY")
  | rename dest=dns_server
  | lookup authorized_dns_servers.csv server_ip=dns_server OUTPUT server_ip=is_authorized
  | where is_authorized IS NULL AND dns_server!="0.0.0.0"
  | stats dc(src)=victim_count by dns_server
  | where victim_count > 1
  | eval reason="Potential Rogue DNS Server Detected"
  | rename dns_server=poisoner
  | fields reason, poisoner, victim_count
)
| stats values(reason)=attack_types sum(victim_count)=distinct_victims_observed by poisoner
```

### Impacket secretsdump.py (DCSync Attack)
---
```sql
source:securityeventlog
| where EventID=4662 AND Properties=~"(?i)(1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|9923a32a-3607-11d2-b9be-0000f87a36b2)"
| lookup domain_controllers.csv ip=IpAddress OUTPUT ip=is_dc
| where is_dc IS NULL
| where SubjectUserName NOT IN ("*DWM-1", "*UMFD-1") AND SubjectUserName!~".*\\$"
| stats min(timestamp)=first_seen max(timestamp)=last_seen count by host, SubjectUserName, IpAddress, ObjectName
| rename host=domain_controller, SubjectUserName=actor_account, IpAddress=source_ip, ObjectName=object_accessed
| fields first_seen, last_seen, domain_controller, source_ip, actor_account, object_accessed, count
```

### Evil-WinRM Remote PowerShell Session
---
```sql
source:powershell
| where EventID=4104 AND ScriptBlockText=~".*function prompt.*" AND ScriptBlockText=~".*Evil-WinRM.*"
| where ScriptBlockText!~".*(grep|select-string).*"
| stats count min(timestamp)=first_seen max(timestamp)=last_seen by host, user, ScriptBlockText
| rename host=victim_host, user=actor_user, ScriptBlockText=evidence
| fields first_seen, last_seen, victim_host, actor_user, evidence, count
```