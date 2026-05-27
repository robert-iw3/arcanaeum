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
`wineventlog_security` EventCode=5137 ObjectClass="msDS-DelegatedManagedServiceAccount"
| comment = "This search looks for the creation of Delegated Managed Service Account (dMSA) objects, which is the initial step in the BadSuccessor attack chain. The rule focuses on creation by non-administrative accounts to reduce noise."

| comment = "Filter out common administrative, service, and system accounts to reduce false positives. This list is a starting point and should be tuned for your specific environment by adding known administrator accounts or service account naming conventions."
| where NOT (like(SubjectUserName, "%admin%") OR like(SubjectUserName, "svc_%") OR like(SubjectUserName, "%_svc") OR like(SubjectUserName, "%$"))

| comment = "Group the results to provide a clear summary of the activity, showing who created the object, on which host, and the object's distinguished name."
| stats count values(ObjectDN) as created_object_dn by _time, dest, SubjectUserName

| comment = "Rename fields for better readability and CIM compliance."
| rename dest as dvc, SubjectUserName as user

| `security_content_summaries`
```

### dMSA Attribute Modification
---
```sql
`wineventlog_security` EventCode=5136 ObjectClass="msDS-DelegatedManagedServiceAccount" AttributeLDAPDisplayName="msDS-ManagedAccountPrecededByLink"
| comment = "This search looks for modifications to the msDS-ManagedAccountPrecededByLink attribute on a dMSA object. This is a key step in the BadSuccessor attack, where an attacker links the dMSA to a high-privilege account they wish to impersonate."

| comment = "Filter out common administrative, service, and system accounts to reduce false positives. This list is a starting point and should be tuned for your specific environment."
| where NOT (like(SubjectUserName, "%admin%") OR like(SubjectUserName, "svc_%") OR like(SubjectUserName, "%_svc") OR like(SubjectUserName, "%$"))

| comment = "Group the results to show who modified the object, what the object was, and which account it is now linked to."
| stats count values(ObjectDN) as modified_object_dn values(AttributeValue) as superseded_account_dn by _time, dest, SubjectUserName

| comment = "Rename fields for better readability and CIM compliance."
| rename dest as dvc, SubjectUserName as user

| `security_content_summaries`
```

### dMSA State Change
---
```sql
`wineventlog_security` EventCode=5136 ObjectClass="msDS-DelegatedManagedServiceAccount" AttributeLDAPDisplayName="msDS-DelegatedMSAState" AttributeValue="2"
| comment = "This search detects when the msDS-DelegatedMSAState attribute of a dMSA object is set to '2', which enables the account migration process. This is a key step in the BadSuccessor attack."

| comment = "Filter out common administrative, service, and system accounts to reduce false positives. This list is a starting point and should be tuned for your specific environment."
| where NOT (like(SubjectUserName, "%admin%") OR like(SubjectUserName, "svc_%") OR like(SubjectUserName, "%_svc") OR like(SubjectUserName, "%$"))

| comment = "Group the results to show who modified the object and what the object was."
| stats count values(ObjectDN) as modified_object_dn by _time, dest, SubjectUserName

| comment = "Rename fields for better readability and CIM compliance."
| rename dest as dvc, SubjectUserName as user

| `security_content_summaries`
```

### KDS Root Key Creation
---
```sql
`wineventlog_security` EventCode=5137 ObjectClass="msKds-ProvRootKey"
| comment = "This search detects the creation of a new KDS Root Key. This is a prerequisite for dMSA functionality and the BadSuccessor attack. KDS Root Key creation is a rare administrative event and any unexpected creation should be investigated."

| comment = "Group the results to show who created the key and on which domain controller."
| stats count values(ObjectDN) as kds_root_key_dn by _time, dest, SubjectUserName

| comment = "Rename fields for better readability and CIM compliance."
| rename dest as dvc, SubjectUserName as user

| `security_content_summaries`
```

### Identify Kerberos TGT requests
---
```sql
source="WinEventLog:Directory Service" EventCode=2946
| eval is_dMSA = if(match(Account_Name, "\$$"), 1, 0)
| where is_dMSA = 1
| eval has_dMSA_package = if(searchmatch("KERB-DMSA-KEY-PACKAGE"), 1, 0)
| where has_dMSA_package = 1
| stats count min(_time) as firstTime max(_time) as lastTime by Account_Name, Client_Address, ComputerName
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, Account_Name, Client_Address, ComputerName, count
```