### BadSuccessor: A New Active Directory Privilege Escalation Vulnerability
---

BadSuccessor is a critical privilege escalation vulnerability in Windows Server 2025 that abuses Delegated Managed Service Accounts (dMSAs) to allow an attacker to impersonate any user in Active Directory, including Domain Admins. This attack is possible due to the Kerberos Key Distribution Center's (KDC) blind trust of the `msDS-ManagedAccountPrecededByLink` attribute on dMSAs, enabling attackers to effectively take over an entire Active Directory forest.

Recent research highlights that the BadSuccessor vulnerability can also be leveraged for persistent access through a "Golden dMSA" attack, allowing for KDS root key material extraction and cross-domain lateral movement, which significantly broadens the scope and impact of this vulnerability beyond initial privilege escalation.

References:

https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory#badsuccessor

https://specterops.io/blog/2025/05/27/understanding-mitigating-badsuccessor/

https://www.covertswarm.com/post/bad-successor-technical-deep-dive

### Actionable Threat Data
---

Monitor for the creation of new `msDS-DelegatedManagedServiceAccount` objects (Event ID `5137`), especially by non-administrative users or in unusual Organizational Units (OUs).

Detect modifications to the `msDS-ManagedAccountPrecededByLink` attribute (Event ID `5136`) on dMSA objects, as this attribute is central to the BadSuccessor attack.

Look for instances where the `msDS-DelegatedMSAState attribute is set to '2'` on a dMSA object, indicating a simulated account migration.

Audit for the creation of new `KDS Root Keys` (Key Distribution Service Root Keys) in Active Directory, which are necessary for dMSA functionality and thus the BadSuccessor attack.

Identify `Kerberos TGT` requests for dMSAs that include the `KERB-DMSA-KEY-PACKAGE` structure (Event ID `2946` in the Directory Service log), as this indicates the dMSA is being used to impersonate another account.

### dMSA Object Creation
---
```sql
FROM * // or the index/data-stream for "logs-windows.security-*"
| WHERE event.code = "5137" AND winlog.event_data.ObjectClass = "msDS-DelegatedManagedServiceAccount"
| WHERE NOT (user.name ILIKE "*admin*" OR user.name ILIKE "svc_*" OR user.name ILIKE "*_svc" OR user.name ILIKE "*$")
| STATS count = COUNT(*), created_object_dn = ARRAY_AGG(winlog.event_data.ObjectDN)
  BY @timestamp, host.name, user.name
| KEEP @timestamp, host.name, user.name, created_object_dn, count
| RENAME host.name AS dvc, user.name AS user
```

### dMSA Attribute Modification
---
```sql
FROM *
| WHERE event.code = "5136" AND winlog.event_data.ObjectClass = "msDS-DelegatedManagedServiceAccount" AND winlog.event_data.AttributeLDAPDisplayName = "msDS-ManagedAccountPrecededByLink"
| WHERE NOT (user.name ILIKE "*admin*" OR user.name ILIKE "svc_*" OR user.name ILIKE "*_svc" OR user.name ILIKE "*$")
| STATS count = COUNT(*), modified_object_dn = ARRAY_AGG(winlog.event_data.ObjectDN), superseded_account_dn = ARRAY_AGG(winlog.event_data.AttributeValue)
  BY @timestamp, host.name, user.name
| KEEP @timestamp, host.name, user.name, modified_object_dn, superseded_account_dn, count
| RENAME host.name AS dvc, user.name AS user
```

### dMSA State Change
---
```sql
FROM *
| WHERE event.code = "5136" AND winlog.event_data.ObjectClass = "msDS-DelegatedManagedServiceAccount" AND winlog.event_data.AttributeLDAPDisplayName = "msDS-DelegatedMSAState" AND winlog.event_data.AttributeValue = "2"
| WHERE NOT (user.name ILIKE "*admin*" OR user.name ILIKE "svc_*" OR user.name ILIKE "*_svc" OR user.name ILIKE "*$")
| STATS count = COUNT(*), modified_object_dn = ARRAY_AGG(winlog.event_data.ObjectDN)
  BY @timestamp, host.name, user.name
| KEEP @timestamp, host.name, user.name, modified_object_dn, count
| RENAME host.name AS dvc, user.name AS user
```

### KDS Root Key Creation
---
```sql
FROM *
| WHERE event.code = "5137" AND winlog.event_data.ObjectClass = "msKds-ProvRootKey"
| STATS count = COUNT(*), kds_root_key_dn = ARRAY_AGG(winlog.event_data.ObjectDN)
  BY @timestamp, host.name, user.name
| KEEP @timestamp, host.name, user.name, kds_root_key_dn, count
| RENAME host.name AS dvc, user.name AS user
```

### Identify Kerberos TGT requests
---
```sql
FROM *
| WHERE event.code = "2946" AND user.name LIKE "*$" AND winlog.event_data.Message LIKE "*KERB-DMSA-KEY-PACKAGE*"
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY user.name, source.ip, host.name
| KEEP firstTime, lastTime, user.name, source.ip, host.name, count
| RENAME user.name AS Account_Name, source.ip AS Client_Address, host.name AS ComputerName
```