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
from winlogbeat-*
| where winlog.channel = "Security"
  and winlog.event_id = "4886"
  and winlog.event_data.CertificateAttributes RLIKE ".*san:.*"
| eval
    san_upn = REGEXP(winlog.event_data.CertificateAttributes, "san:.*?upn=([^&\\s]+)", 1),
    requester_principal = LOWER(REPLACE(winlog.event_data.RequesterName, "^.*\\\\", "")),
    requester_principal = SPLIT(requester_principal, "@")[0],
    san_principal = LOWER(SPLIT(san_upn, "@")[0])
| where san_upn IS NOT NULL
  and requester_principal != san_principal
| keep
    @timestamp,
    host.name,
    winlog.event_data.RequesterName,
    san_upn,
    winlog.event_data.CertificateTemplate,
    requester_principal,
    san_principal
| rename
    @timestamp AS _time,
    host.name AS host,
    winlog.event_data.RequesterName AS RequesterName,
    winlog.event_data.CertificateTemplate AS CertificateTemplate
| sort _time ASC
```

### ESC4: Template Property Modification
---
```sql
from winlogbeat-*
| where winlog.channel = "Security"
  and winlog.event_id = "5136"
  and winlog.event_data.ObjectClass = "pKICertificateTemplate"
  and winlog.event_data.AttributeLDAPDisplayName = "msPKI-Certificate-Name-Flag"
  and winlog.event_data.Attributevalue = "1"
| keep
    @timestamp,
    host.name,
    winlog.event_data.SubjectUserName,
    winlog.event_data.ObjectName,
    winlog.event_data.AttributeLDAPDisplayName,
    winlog.event_data.Attributevalue
| rename
    @timestamp AS _time,
    host.name AS host,
    winlog.event_data.SubjectUserName AS Subject_User_Name,
    winlog.event_data.ObjectName AS Object_DN,
    winlog.event_data.AttributeLDAPDisplayName AS Attribute_LDAP_Display_Name,
    winlog.event_data.Attributevalue AS Attribute_Value
| sort _time ASC
```

### ESC14: Shadow Credential Addition
---
```sql
from winlogbeat-*
| where winlog.channel = "Security"
  and winlog.event_id = "5136"
  and winlog.event_data.AttributeLDAPDisplayName = "msDS-KeyCredentialLink"
  and winlog.event_data.ObjectClass IN ("user", "computer")
| keep
    @timestamp,
    host.name,
    winlog.event_data.SubjectUserName,
    winlog.event_data.ObjectName,
    winlog.event_data.ObjectClass,
    winlog.event_data.OperationType
| rename
    @timestamp AS _time,
    host.name AS host,
    winlog.event_data.SubjectUserName AS Subject_User_Name,
    winlog.event_data.ObjectName AS Object_DN,
    winlog.event_data.ObjectClass AS Object_Class,
    winlog.event_data.OperationType AS Operation_Type
| sort _time ASC
```

### ESC8/ESC11: NTLM Relay to AD CS
---
```sql
from winlogbeat-*
| where winlog.channel = "Security"
  and winlog.event_id = "4776"
  and winlog.event_data.Status = "0x0"
  and winlog.event_data.AccountName RLIKE ".*\\$$"
  and source.ip IN (SELECT ip from adcs_servers where is_adcs_server = true)
| eval
    adcs_machine_account = UPPER(winlog.event_data.SourceWorkstation) + "$"
| where UPPER(winlog.event_data.AccountName) != adcs_machine_account
| STATS
    count = COUNT(*)
  BY @timestamp, host.name, winlog.event_data.AccountName, winlog.event_data.SourceWorkstation, source.ip
| keep
    @timestamp,
    host.name,
    winlog.event_data.AccountName,
    winlog.event_data.SourceWorkstation,
    source.ip,
    count
| rename
    @timestamp AS _time,
    host.name AS host,
    winlog.event_data.AccountName AS Account_Name,
    winlog.event_data.SourceWorkstation AS Source_Workstation,
    source.ip AS Ip_Address
| sort _time ASC
```

### ESC16/ESC6: CA EditFlags Modification
---
```sql
from logs-endpoint.events-*
| where event.module = "sysmon"
  and event.code = "13"
  and winlog.event_data.TargetObject RLIKE ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\CertSvc\\\\Configuration\\\\.*\\\\PolicyModules\\\\CertificateAuthority_MicrosoftDefault\\.Policy\\\\EditFlags"
| eval
    ca_name = REGEXP(winlog.event_data.TargetObject, "Configuration\\\\([^\\\\]+)\\\\PolicyModules", 1)
| keep
    @timestamp,
    host.name,
    user.name,
    process.name,
    ca_name,
    winlog.event_data.TargetObject,
    winlog.event_data.Details
| rename
    @timestamp AS _time,
    host.name AS host,
    user.name AS user,
    process.name AS process_name,
    winlog.event_data.TargetObject AS TargetObject,
    winlog.event_data.Details AS Details
| sort _time ASC
```