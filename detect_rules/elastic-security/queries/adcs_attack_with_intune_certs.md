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
FROM *
| WHERE event.outcome == "success"
  AND (event.action == "Patch deviceConfiguration" OR event.action == "Add deviceConfiguration")
| DISSECT event.message "%{?}tag:microsoft.com,2022-09-14:sid:%{sid}" | WHERE sid LIKE "S-1-5-21-*-500" OR sid LIKE "S-1-5-21-*-512" OR sid LIKE "S-1-5-21-*-516" OR sid LIKE "S-1-5-21-*-518" OR sid LIKE "S-1-5-21-*-519"
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY user.name, host.name, event.action, event.message
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### Sensitive Certificate Enrollment via Intune Connector
---
```sql
FROM *
| WHERE event.action == "issued"
  AND user.name IN (<server1$>, <server2$>) // Replace with NDES/Intune connector server names
| DISSECT certificate.subject.alternative_name "%{?}tag:microsoft.com,2022-09-14:sid:%{privileged_sid}"
| WHERE privileged_sid RLIKE "S-1-5-21-\\d{1,15}-\\d{1,15}-\\d{1,15}-(500|512|516|518|519)"
  AND certificate.template NOT IN ("User", "ClientAuth")
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp),
    subject = VALUES(certificate.subject.common_name),
    template_name = VALUES(certificate.template),
    issuer = VALUES(certificate.issuer.common_name)
  BY host.name, user.name, privileged_sid
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"),
    lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### Intune Device Spoofing followed by Certificate Enrollment
---
```sql
FROM *
| WHERE event.category == "configuration" AND event.action == "Patch device" AND properties.display_name == "Device Name"
| EVAL user = actor.upn, new_device_name = properties.new_value, device_name_norm = LOWER(REGEXP_REPLACE(TRIM(new_device_name, "\""), "\\..*", "")), change_time = @timestamp
| KEEP change_time, device_name_norm, user
| JOIN (
  FROM certificates
  | WHERE event.action == "issued" AND user.name IN (<server1$>, <server2$>) // Replace with NDES/Intune connector server names
  | DISSECT certificate.subject.alternative_name "DNS Name=%{san_device_name}[^,;]*"
  | WHERE san_device_name IS NOT NULL
  | EVAL device_name_norm = LOWER(REGEXP_REPLACE(san_device_name, "\\..*", ""))
  | STATS issue_time = MIN(@timestamp), requester_name = VALUES(user.name), subject = VALUES(certificate.subject.common_name), subject_alternative_name = VALUES(certificate.subject.alternative_name), dest = VALUES(host.name) BY device_name_norm
) ON device_name_norm
| WHERE issue_time > change_time AND (issue_time - change_time) <= 3600
| EVAL device_name = device_name_norm, firstTime = change_time, lastTime = issue_time
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
| KEEP firstTime, lastTime, device_name, user, requester_name, subject, subject_alternative_name, dest
```

### Anomalous Certificate Issuance for Privileged Account via Intune
---
```sql
FROM *
| WHERE event.action == "issued"
  AND certificate.extended_key_usage LIKE "*1.3.6.1.5.5.7.3.2*"
  AND user.name IN (<server1$>, <server2$>) // Replace with NDES/Intune connector server names
| DISSECT certificate.subject.alternative_name "DNS Name=%{san_dns_name}[^,;]*"
| WHERE san_dns_name IS NOT NULL
| LOOKUP privileged_assets_lookup ON san_dns_name OUTPUT is_privileged
| WHERE is_privileged == "true"
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), subject = VALUES(certificate.subject.common_name)
  BY host.name, user.name, san_dns_name
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```

### Kerberos TGT Request with Certificate for Privileged Account
---
```sql
FROM *
| WHERE event.module == "security" AND event.id == "4768"
  AND process.name IN ("PA-PK-AS-REQ", "15", "16")
| LOOKUP privileged_assets_lookup ON user.name OUTPUT is_privileged
| WHERE is_privileged == "true"
| STATS count = COUNT(*), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp)
  BY user.name, source.ip, host.name, process.name
| EVAL firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss"), lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss")
```