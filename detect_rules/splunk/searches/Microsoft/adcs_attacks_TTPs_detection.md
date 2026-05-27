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
`wineventlog_security` EventCode=4886 "The certificate has been issued" CertificateAttributes="*san:*"
| comment="This SPL query detects potential AD CS abuse (ESC1/ESC6) by identifying certificate issuances where the requester's identity does not match the identity specified in the Subject Alternative Name (SAN)."

| comment="Extract the User Principal Name (UPN) from the Subject Alternative Name (SAN) in the CertificateAttributes field."
| rex field=CertificateAttributes "san:.*?upn=(?<san_upn>[^&\s]+)"

| comment="Filter for events where a SAN UPN was successfully extracted, as this is required for the attack."
| where isnotnull(san_upn)

| comment="Normalize the RequesterName and the SAN UPN to their core user/principal names for comparison. This handles formats like 'DOMAIN\\user', 'user@domain.com', and machine accounts 'HOST$'."
| eval requester_principal = lower(replace(RequesterName, "^.*\\\\", ""))
| eval requester_principal = mvindex(split(requester_principal, "@"), 0)
| eval san_principal = lower(mvindex(split(san_upn, "@"), 0))

| comment="Compare the normalized requester and SAN principals. A mismatch is a strong indicator of malicious activity, such as a low-privileged user requesting a certificate for a high-privileged one."
| where requester_principal != san_principal

| comment="FP Tuning: Legitimate services or administrative tasks might perform this action. Consider excluding known requesters or specific certificate templates. Example: | search NOT (RequesterName IN ('service_account$@domain.local') AND CertificateTemplate='KnownGoodTemplate')"

| comment="Format the output for analysis, showing the time, host, the original requester and SAN, the template used, and the extracted principals for easy verification."
| table _time, host, RequesterName, san_upn, CertificateTemplate, requester_principal, san_principal
| `ad_cs_mismatched_certificate_requester_and_subject_(esc1_esc6)_filter`
```

### ESC4: Template Property Modification
---
```sql
`wineventlog_security` EventCode=5136 Object_Class="pKICertificateTemplate" Attribute_LDAP_Display_Name="msPKI-Certificate-Name-Flag" Attribute_Value="1"
| comment="This SPL query detects the modification of a certificate template to allow the requester to supply the subject name (ESC4), a common privilege escalation technique."

| comment="FP Tuning: Legitimate administrative changes to templates will trigger this alert. Consider filtering by user (Subject_User_Name) or during approved change windows."

| comment="Format the output for analysis, showing who made the change, when, and to which template."
| table _time, host, Subject_User_Name, Object_DN, Attribute_LDAP_Display_Name, Attribute_Value
| `esc4_template_property_modification_filter`
```

### ESC14: Shadow Credential Addition
---
```sql
`wineventlog_security` EventCode=5136 Attribute_LDAP_Display_Name="msDS-KeyCredentialLink" (Object_Class="user" OR Object_Class="computer")
| comment="This query detects the modification of the 'msDS-KeyCredentialLink' attribute on a user or computer object, which is the technique for creating 'Shadow Credentials' (ESC14) for persistence."

| comment="FP Tuning: Legitimate provisioning of Windows Hello for Business (WHfB) or FIDO2 keys will generate these events. Consider filtering by the user making the change (Subject_User_Name) or the target object (Object_DN) if they are related to legitimate administrative activity."

| comment="Format the output for analysis, showing who made the change, to what object, and when."
| table _time, host, Subject_User_Name, Object_DN, Object_Class, Operation_Type
| `ad_cs_shadow_credential_addition_filter`
```

### ESC8/ESC11: NTLM Relay to AD CS
---
```sql
`wineventlog_security` EventCode=4776 Status="0x0" Account_Name LIKE "%$"
| comment="This query detects potential NTLM relay attacks against AD CS (ESC8/ESC11) by identifying when a machine account successfully authenticates via NTLM to a known AD CS server. This is highly suspicious as machine-to-server communication in an AD environment should typically use Kerberos."
| comment="The 'Source_Workstation' field in event 4776 indicates the server that requested the credential validation from the domain controller. In a relay attack, this is the AD CS server being targeted."

| comment="Use a lookup or macro to identify your AD CS servers. Create a lookup file 'adcs_servers.csv' with a 'host' column listing your AD CS server hostnames, or replace the line below with a hardcoded search like '| search Source_Workstation IN (adcs-srv1, adcs-srv2)'."
| lookup adcs_servers.csv host AS Source_Workstation OUTPUT is_adcs_server
| where is_adcs_server="true"

| comment="Exclude authentications where the machine account belongs to the AD CS server itself, which could be legitimate activity."
| eval adcs_machine_account = upper(Source_Workstation) + "$"
| where upper(Account_Name) != adcs_machine_account

| comment="FP Tuning: If you have legitimate services that use NTLM from specific machine accounts to AD CS servers, they should be excluded here. Example: | search NOT (Account_Name=\"LEGIT_MACHINE$\")"

| comment="Aggregate results to show which accounts are authenticating to which AD CS servers from which client IPs."
| stats count by _time, host, Account_Name, Source_Workstation, Ip_Address
| `esc8_esc11_ntlm_relay_to_ad_cs_filter`
```

### ESC16/ESC6: CA EditFlags Modification
---
```sql
`sysmon` EventCode=13 TargetObject="*\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\*\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy\\EditFlags"
| comment="This query detects modifications to a Certificate Authority's 'EditFlags' registry value, which can indicate critical misconfigurations related to ESC6 or ESC16."

| comment="Extract the CA name from the registry path for context."
| rex field=TargetObject "Configuration\\\\(?<ca_name>[^\\\\]+)\\\\PolicyModules"

| comment="FP Tuning: Legitimate changes by PKI administrators will trigger this alert. Correlate with change management records or filter for unauthorized users/processes."
| comment="Analyst Note: Investigate the new value in the 'Details' field. A value including the 0x40000 bit (EDITF_ATTRIBUTESUBJECTALTNAME2) indicates an ESC6 vulnerability. The absence of the 0x10000 bit (EDITF_ENABLEDEFAULTSMIME) may indicate an ESC16 vulnerability."
| comment="Also monitor for changes to the 'DisableExtensionList' registry key in the same path, as removing the SID extension OID is another vector for ESC16."

| comment="Format the output for analysis."
| table _time, host, user, process_name, ca_name, TargetObject, Details
| `esc16_esc6_ca_editflags_modification_filter`
```