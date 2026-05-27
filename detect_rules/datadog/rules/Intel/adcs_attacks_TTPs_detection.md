### Active Directory Certificate Services (AD CS) Attack Techniques and Detections
---

This report details various attack techniques targeting Active Directory Certificate Services (AD CS), ranging from misconfigured certificate templates to advanced persistence methods. It highlights how attackers exploit common AD CS misconfigurations for privilege escalation and persistence within Windows environments, emphasizing the critical need for robust detection and mitigation strategies.

Recent intelligence indicates the emergence of new AD CS attack vectors, specifically ESC15 (EKUwu) and ESC16, which exploit previously unaddressed vulnerabilities in certificate template application policies and global CA security extension enforcement, respectively. These novel techniques pose significant threats by enabling attackers to bypass traditional security controls and achieve persistent, high-privileged access.

### Actionable Threat Data
---

Monitor for certificate requests (Event ID `4886`) where the `Requester` and the `Subject` (UPN or SAN) do not match, especially for templates with `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` enabled, indicating potential `ESC1` or `ESC6` exploitation.

Detect modifications to certificate template properties (Event ID `5136` on Domain Controllers) that enable `ENROLLEE_SUPPLIES_SUBJECT` or alter `msPKI-Certificate-Name-Flag`, which could signify an `ESC4` attack.

Look for changes to the `msDS-KeyCredentialLink` attribute (Event ID `5136` on Domain Controllers) on user or computer objects, as this indicates the addition of shadow credentials (`ESC14`) for persistence.

Identify NTLM relay attempts targeting AD CS HTTP or RPC endpoints (Event ID `4776` for NTLM authentication attempts, combined with network traffic analysis for connections to `/certsrv/` or `DCOM` interfaces), which are indicative of `ESC8` or `ESC11` attacks.

Audit for changes to the CA's `EditFlags` registry key, specifically the removal of `szOID_NTDS_CA_SECURITY_EXT` (`OID: 1.3.6.1.4.1.311.25.2`) or the presence of `EDITF_ATTRIBUTESUBJECTALTNAME2` (`0x40000`), which are critical indicators of `ESC16` and `ESC6` vulnerabilities, respectively.

### ESC1/ESC6: Mismatched Cert Request
---
```sql
source:securityeventlog
| where EventID=4886 AND CertificateAttributes=~".*san:.*"
| rex field=CertificateAttributes "san:.*?upn=(?<san_upn>[^&\s]+)"
| where san_upn IS NOT NULL
| eval requester_principal=lower(replace(RequesterName, "^.*\\\\", "")), requester_principal=mvindex(split(requester_principal, "@"), 0), san_principal=lower(mvindex(split(san_upn, "@"), 0))
| where requester_principal!=san_principal
| fields timestamp, host, RequesterName, san_upn, CertificateTemplate, requester_principal, san_principal
```

### ESC4: Template Property Modification
---
```sql
source:securityeventlog
| where EventID=5136 AND ObjectClass="pKICertificateTemplate" AND AttributeLDAPDisplayName="msPKI-Certificate-Name-Flag" AND AttributeValue="1"
| fields timestamp, host, SubjectUserName, ObjectDN, AttributeLDAPDisplayName, AttributeValue
```

### ESC14: Shadow Credential Addition
---
```sql
source:securityeventlog
| where EventID=5136 AND AttributeLDAPDisplayName="msDS-KeyCredentialLink" AND (ObjectClass="user" OR ObjectClass="computer")
| fields timestamp, host, SubjectUserName, ObjectDN, ObjectClass, OperationType
```

### ESC8/ESC11: NTLM Relay to AD CS
---
```sql
source:securityeventlog
| where EventID=4776 AND Status="0x0" AND AccountName=~".*\\$"
| lookup adcs_servers.csv host=SourceWorkstation OUTPUT is_adcs_server
| where is_adcs_server="true"
| eval adcs_machine_account=upper(SourceWorkstation) + "$"
| where upper(AccountName)!=adcs_machine_account
| stats count by timestamp, host, AccountName, SourceWorkstation, IpAddress
```

### ESC16/ESC6: CA EditFlags Modification
---
```sql
source:sysmon
| where EventID=13 AND TargetObject=~".*\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\CertSvc\\\\Configuration\\\\.*\\\\PolicyModules\\\\CertificateAuthority_MicrosoftDefault\.Policy\\\\EditFlags"
| rex field=TargetObject "Configuration\\\\(?<ca_name>[^\\\\]+)\\\\PolicyModules"
| fields timestamp, host, user, process_name, ca_name, TargetObject, Details
```