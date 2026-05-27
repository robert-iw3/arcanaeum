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
from winlogbeat-* // replace with ECS data source
| where winlog.channel = "Security" and winlog.event_id = "4741"
  and NOT winlog.event_data.SubjectUserName RLIKE ".*\\$$"
  and winlog.event_data.SubjectUserName NOT IN (
    SELECT user from admin_users where is_admin = true
  )
| stats
    count = COUNT(*)
  BY @timestamp, host.name, winlog.event_data.SubjectUserName, winlog.event_data.TargetUserName
| keep @timestamp, host.name, winlog.event_data.SubjectUserName, winlog.event_data.TargetUserName, count
| rename @timestamp AS _time, host.name AS domain_controller, winlog.event_data.SubjectUserName AS creating_user, winlog.event_data.TargetUserName AS new_computer_account
| sort _time ASC
```

### NTLM Relay Attempt
---
```sql
from winlogbeat-* // replace with ECS data source
| where winlog.channel = "Security"
  and winlog.event_id = "4624"
  and winlog.event_data.LogonType = "3"
  and winlog.event_data.AuthenticationPackageName = "NTLM"
  and source.ip NOT IN ("127.0.0.1", "::1")
| eval
    dest_host = LOWER(SPLIT(host.name, ".")[0]),
    src_workstation = LOWER(SPLIT(winlog.event_data.WorkstationName, ".")[0])
| where dest_host = src_workstation
  and dest_host IS NOT NULL
  and dest_host != ""
  and dest_host != "-"
| stats
    count = COUNT(*),
    first_seen = MIN(@timestamp),
    last_seen = MAX(@timestamp)
  BY dest_host, source.ip, winlog.event_data.TargetUserName, winlog.event_data.SubjectUserName
| keep first_seen, last_seen, dest_host, source.ip, winlog.event_data.SubjectUserName, winlog.event_data.TargetUserName, count
| eval
    first_seen = TO_STRING(first_seen, "yyyy-MM-dd HH:mm:ss"),
    last_seen = TO_STRING(last_seen, "yyyy-MM-dd HH:mm:ss")
| rename
    dest_host AS host,
    source.ip AS source_ip,
    winlog.event_data.TargetUserName AS target_user,
    winlog.event_data.SubjectUserName AS source_user
| sort first_seen ASC
```

### LDAP ACL Modification for DCSync or Privileged Group
---
```sql
from winlogbeat-*
| where winlog.channel = "Security"
  and (
    (winlog.event_id = "5136"
      and winlog.event_data.ObjectClass = "domainDNS"
      and winlog.event_data.AttributeLDAPDisplayName = "nTSecurityDescriptor"
      and winlog.event_data.Attributevalue RLIKE ".*(1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|9923a32a-3607-11d2-b9be-0000f87a36b2).*")
    OR
    (winlog.event_id IN ("4728", "4732", "4756")
      and winlog.event_data.TargetUserName IN ("Enterprise Admins", "Domain Admins", "Administrators", "Schema Admins"))
  )
  and NOT (
    winlog.event_data.SubjectUserName IN ("DWM-1", "UMFD-1")
    OR winlog.event_data.SubjectUserName RLIKE "(?i)MSOL_.*"
  )
| eval
    reason = CASE(
      winlog.event_id = "5136", "DCSync Replication Rights Granted to Domain Object",
      winlog.event_id IN ("4728", "4732", "4756"), "Account Added to Privileged Group",
      "Unknown"
    ),
    target_principal = CASE(
      winlog.event_id = "5136", winlog.event_data.ObjectName,
      winlog.event_id IN ("4728", "4732", "4756"), winlog.event_data.MemberName,
      NULL
    ),
    privileged_group = CASE(
      winlog.event_id IN ("4728", "4732", "4756"), winlog.event_data.TargetUserName,
      "N/A"
    )
| stats
    count = COUNT(*),
    reasons = GROUP_CONCAT(reason)
  BY @timestamp, host.name, winlog.event_data.SubjectUserName, target_principal, privileged_group
| keep @timestamp, host.name, winlog.event_data.SubjectUserName, target_principal, privileged_group, reasons, count
| rename
    @timestamp AS _time,
    host.name AS domain_controller,
    winlog.event_data.SubjectUserName AS actor
| sort _time ASC
```

### LLMNR, NBT-NS, or IPv6 DNS Poisoning
---
```sql
// Part 1: LLMNR/NBT-NS Poisoning Detection
from logs-packetbeat-* // replace with data source
| where network.transport = "udp"
  and destination.port IN (137, 5355)
| stats victim_count = COUNT(DISTINCT destination.ip) BY source.ip
| where victim_count > 10
| eval reason = "LLMNR/NBT-NS Poisoning Detected"
| keep reason, source.ip AS poisoner, victim_count
| UNION (
  // Part 2: Rogue DNS Server Detection
  from logs-packetbeat-*
  | where dns.question.type IN ("AAAA", "ANY")
    and destination.ip != "0.0.0.0"
    and destination.ip NOT IN (
      SELECT server_ip from authorized_dns_servers where is_authorized = true
    )
  | stats victim_count = COUNT(DISTINCT source.ip) BY destination.ip
  | where victim_count > 1
  | eval reason = "Potential Rogue DNS Server Detected"
  | keep reason, destination.ip AS poisoner, victim_count
)
// Consolidate results by poisoner
| stats
    attack_types = GROUP_CONCAT(reason),
    distinct_victims_observed = SUM(victim_count)
  BY poisoner
| sort distinct_victims_observed DESC
```

### Impacket secretsdump.py (DCSync Attack)
---
```sql
from winlogbeat-* // replace with data source
| where winlog.channel = "Security"
  and winlog.event_id = "4662"
  and winlog.event_data.Properties RLIKE "(?i).*(1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|9923a32a-3607-11d2-b9be-0000f87a36b2).*"
  and source.ip NOT IN (
    SELECT ip from domain_controllers where is_dc = true
  )
  and NOT (
    winlog.event_data.SubjectUserName IN ("DWM-1", "UMFD-1")
    OR winlog.event_data.SubjectUserName RLIKE ".*\\$$"
  )
| stats
    count = COUNT(*),
    first_seen = MIN(@timestamp),
    last_seen = MAX(@timestamp)
  BY host.name, winlog.event_data.SubjectUserName, source.ip, winlog.event_data.ObjectName
| keep first_seen, last_seen, host.name, source.ip, winlog.event_data.SubjectUserName, winlog.event_data.ObjectName, count
| eval
    first_seen = TO_STRING(first_seen, "yyyy-MM-dd HH:mm:ss"),
    last_seen = TO_STRING(last_seen, "yyyy-MM-dd HH:mm:ss")
| rename
    host.name AS domain_controller,
    winlog.event_data.SubjectUserName AS actor_account,
    source.ip AS source_ip,
    winlog.event_data.ObjectName AS object_accessed
| sort first_seen ASC
```

### Evil-WinRM Remote PowerShell Session
---
```sql
from winlogbeat-* // replace
| where winlog.channel = "Microsoft-Windows-PowerShell/Operational"
  and winlog.event_id = "4104"
  and winlog.event_data.ScriptBlockText RLIKE ".*function\\s+prompt.*"
  and winlog.event_data.ScriptBlockText RLIKE ".*Evil-WinRM.*"
  and NOT (
    winlog.event_data.ScriptBlockText RLIKE ".*grep.*"
    OR winlog.event_data.ScriptBlockText RLIKE ".*select-string.*"
  )
| stats
    count = COUNT(*),
    first_seen = MIN(@timestamp),
    last_seen = MAX(@timestamp)
  BY host.name, user.name, winlog.event_data.ScriptBlockText
| keep first_seen, last_seen, host.name, user.name, winlog.event_data.ScriptBlockText, count
| eval
    first_seen = TO_STRING(first_seen, "yyyy-MM-dd HH:mm:ss"),
    last_seen = TO_STRING(last_seen, "yyyy-MM-dd HH:mm:ss")
| rename
    host.name AS victim_host,
    user.name AS actor_user,
    winlog.event_data.ScriptBlockText AS evidence
| sort first_seen ASC
```
