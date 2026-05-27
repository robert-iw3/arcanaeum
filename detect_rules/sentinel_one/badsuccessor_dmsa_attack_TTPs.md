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
SELECT
  eventTime,
  AgentName AS dvc,
  User AS user,
  ARRAY_AGG(rawEventData) AS created_object_dn,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  eventType = 'SecurityEvent'
  AND rawEventData LIKE '%5137%'
  AND rawEventData LIKE '%msDS-DelegatedManagedServiceAccount%'
  AND NOT (User LIKE '%admin%' OR User LIKE 'svc_%' OR User LIKE '%_svc' OR User LIKE '%$')
GROUP BY
  eventTime,
  AgentName,
  User
```

### dMSA Attribute Modification
---
```sql
SELECT
  eventTime,
  AgentName AS dvc,
  User AS user,
  ARRAY_AGG(rawEventData) AS modified_object_dn,
  ARRAY_AGG(rawEventData) AS superseded_account_dn,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  eventType = 'SecurityEvent'
  AND rawEventData LIKE '%5136%'
  AND rawEventData LIKE '%msDS-DelegatedManagedServiceAccount%'
  AND rawEventData LIKE '%msDS-ManagedAccountPrecededByLink%'
  AND NOT (User LIKE '%admin%' OR User LIKE 'svc_%' OR User LIKE '%_svc' OR User LIKE '%$')
GROUP BY
  eventTime,
  AgentName,
  User
```

### dMSA State Change
---
```sql
SELECT
  eventTime,
  AgentName AS dvc,
  User AS user,
  ARRAY_AGG(rawEventData) AS modified_object_dn,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  eventType = 'SecurityEvent'
  AND rawEventData LIKE '%5136%'
  AND rawEventData LIKE '%msDS-DelegatedManagedServiceAccount%'
  AND rawEventData LIKE '%msDS-DelegatedMSAState%'
  AND rawEventData LIKE '%2%'
  AND NOT (User LIKE '%admin%' OR User LIKE 'svc_%' OR User LIKE '%_svc' OR User LIKE '%$')
GROUP BY
  eventTime,
  AgentName,
  User
```

### KDS Root Key Creation
---
```sql
SELECT
  eventTime,
  AgentName AS dvc,
  User AS user,
  ARRAY_AGG(rawEventData) AS kds_root_key_dn,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  eventType = 'SecurityEvent'
  AND rawEventData LIKE '%5137%'
  AND rawEventData LIKE '%msKds-ProvRootKey%'
GROUP BY
  eventTime,
  AgentName,
  User
```

### Identify Kerberos TGT requests
---
```sql
SELECT
  MIN(eventTime) AS firstTime,
  MAX(eventTime) AS lastTime,
  User AS Account_Name,
  srcIp AS Client_Address,
  AgentName AS ComputerName,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  eventType = 'DirectoryServiceEvent'
  AND rawEventData LIKE '%2946%'
  AND User LIKE '%$'
  AND rawEventData LIKE '%KERB-DMSA-KEY-PACKAGE%'
GROUP BY
  User,
  srcIp,
  AgentName
```