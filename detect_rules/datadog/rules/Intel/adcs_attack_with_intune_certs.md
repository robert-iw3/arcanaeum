### Extending AD CS Attack Surface to the Cloud with Intune Certificates
---

This report details how attackers can leverage misconfigurations in Microsoft Intune's integration with Active Directory Certificate Services (AD CS) to escalate privileges from an Intune administrator or even a regular user to a Domain Administrator. The attack exploits the ability to request certificates with arbitrary subjects, enabling impersonation of highly privileged accounts within the on-premises Active Directory.

The article highlights novel attack paths by demonstrating how Intune administrators can directly request certificates for domain controllers via PKCS, and how regular users can achieve the same via SCEP by spoofing device properties, even with strong certificate mapping enforced. This significantly extends the known AD CS attack surface to hybrid cloud environments.

### Actionable Threat Data
---

Monitor for the creation or modification of Intune certificate profiles that include highly privileged accounts (e.g., Domain Controllers, Domain Admins) in the Subject Alternative Name (SAN) fields, especially those using `URL=tag:microsoft.com,2022-09-14:sid:<value>` for strong mapping.

Detect attempts to enroll certificates with `SANs` containing `SIDs` of sensitive Active Directory objects (e.g., Domain Controllers, Enterprise Admins) from the Intune Certificate Connector or NDES server.

Look for unusual or rapid changes to device names or other spoofable device properties (e.g., IMEI, SerialNumber) on endpoints that are in scope for Intune SCEP certificate profiles, particularly if followed by certificate enrollment attempts.

Monitor for the issuance of new certificates from AD CS that have both client authentication EKU and SANs corresponding to Domain Controllers or other highly privileged accounts, especially if the issuing source is the Intune Certificate Connector or NDES.

Implement detection for Kerberos Ticket Granting Ticket (TGT) requests for Domain Controllers or other privileged accounts where the authentication is performed using a certificate, especially if the certificate's issuance is anomalous.

### Suspicious Intune Certificate Profile Modification for PrivEsc
---
```sql
source:change
| where action="success" AND (command="Patch deviceConfiguration" OR command="Add deviceConfiguration")
| stats count min(timestamp)=firstTime max(timestamp)=lastTime by user, dest, command, fields
| rex field=fields "tag:microsoft\.com,2022-09-14:sid:(?<sid>S-1-5-21-[0-9-]+-(500|512|516|518|519))"
| where sid IS NOT NULL
```

### Sensitive Certificate Enrollment via Intune Connector
---
```sql
source:certificates
| where action="issued"
| search ndes_or_intune_connector_servers
| rex field=Subject_Alternative_Name "tag:microsoft\.com,2022-09-14:sid:(?<privileged_sid>S-1-5-21-\d{1,15}-\d{1,15}-\d{1,15}-(500|512|516|518|519))"
| where privileged_sid IS NOT NULL AND Template_Name NOT IN ("User", "ClientAuth")
| eval timestamp=if(timestamp IS NULL, now(), timestamp)
| stats count min(timestamp)=firstTime max(timestamp)=lastTime values(Subject)=subject values(Template_Name)=template_name values(Issuer)=issuer by dest, Requester_Name, privileged_sid
```

### Intune Device Spoofing followed by Certificate Enrollment
---
```sql
source:ms_intune_audit
| where ActivityType="Device" AND OperationName="Patch device"
| mvexpand Properties
| where Properties.DisplayName="Device Name"
| rename Properties.NewValue=new_device_name, Actor.Upn=user
| eval device_name_norm=lower(replace(trim(new_device_name, "\""), "\..*", "")), change_time=timestamp
| join type=inner device_name_norm [
  source:certificates
  | where action="issued"
  | search ndes_or_intune_connector_servers
  | rex field=Subject_Alternative_Name "DNS Name=(?<san_device_name>[^,;]+)"
  | where san_device_name IS NOT NULL
  | eval device_name_norm=lower(replace(san_device_name, "\..*", ""))
  | fields timestamp=issue_time, device_name_norm, Requester_Name, Subject, Subject_Alternative_Name, dest
]
| where issue_time > change_time AND (issue_time - change_time) <= 3600
| rename device_name_norm=device_name, change_time=firstTime, issue_time=lastTime
```

### Anomalous Certificate Issuance for Privileged Account via Intune
---
```sql
source:certificates
| where action="issued" AND Extended_Key_Usage=".*1\.3\.6\.1\.5\.5\.7\.3\.2.*"
| search ndes_or_intune_connector_servers
| rex field=Subject_Alternative_Name "DNS Name=(?<san_dns_name>[^,;]+)"
| where san_dns_name IS NOT NULL
| lookup privileged_assets_lookup asset=san_dns_name OUTPUT is_privileged
| where is_privileged="true"
| stats count min(timestamp)=firstTime max(timestamp)=lastTime values(Subject)=subject by dest, Requester_Name, san_dns_name
```

### Kerberos TGT Request with Certificate for Privileged Account
---
```sql
source:authentication
| where signature_id="4768" AND app IN ("PA-PK-AS-REQ", "15", "16")
| lookup privileged_assets_lookup asset=user OUTPUT is_privileged
| where is_privileged="true"
| stats count min(timestamp)=firstTime max(timestamp)=lastTime by user, src, dvc, app
```