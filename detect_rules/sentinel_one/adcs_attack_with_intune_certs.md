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
SELECT
  MIN(eventTime) AS firstTime,
  MAX(eventTime) AS lastTime,
  User,
  AgentName,
  rawEventData AS command,
  rawEventData AS eventFields,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  EventType = 'ConfigurationChange'
  AND eventResult = 'Success'
  AND rawEventData LIKE '%Patch deviceConfiguration%'
  OR rawEventData LIKE '%Add deviceConfiguration%'
  AND rawEventData REGEXP 'tag:microsoft\.com,2022-09-14:sid:S-1-5-21-[0-9-]+-(500|512|516|518|519)'
GROUP BY
  User,
  AgentName,
  rawEventData
```

### Sensitive Certificate Enrollment via Intune Connector
---
```sql
-- Note: Replace <server1$>, <server2$> with the actual NDES or Intune connector server names as defined in your environment.
SELECT
  MIN(eventTime) AS firstTime,
  MAX(eventTime) AS lastTime,
  AgentName,
  User AS requesterName,
  rawEventData AS privileged_sid,
  COUNT(*) AS count,
  ARRAY_AGG(rawEventData) AS subject,
  ARRAY_AGG(rawEventData) AS template_name,
  ARRAY_AGG(rawEventData) AS issuer
FROM deepvisibility
WHERE
  EventType = 'CertificateIssued'
  AND User IN ('server1$', 'server2$')
  AND rawEventData REGEXP '.*tag:microsoft\.com,2022-09-14:sid:S-1-5-21-[0-9]{1,15}-[0-9]{1,15}-[0-9]{1,15}-(500|512|516|518|519)'
  AND rawEventData NOT LIKE '%User%'
  AND rawEventData NOT LIKE '%ClientAuth%'
GROUP BY
  AgentName,
  User,
  rawEventData
```

### Intune Device Spoofing followed by Certificate Enrollment
---
```sql
SELECT
  MIN(eventTime) AS firstTime,
  MAX(eventTime) AS lastTime,
  AgentName AS device_name,
  User AS user,
  ARRAY_AGG(rawEventData) AS requester_name,
  ARRAY_AGG(rawEventData) AS subject,
  ARRAY_AGG(rawEventData) AS subject_alternative_name,
  ARRAY_AGG(AgentName) AS dest,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  (
    (EventType = 'ConfigurationChange'
     AND rawEventData LIKE '%Patch device%'
     AND rawEventData LIKE '%Device Name%')
    OR
    (EventType = 'CertificateIssued'
     AND User IN ('server1$', 'server2$')
     AND rawEventData REGEXP 'DNS Name=[^,;]+')
  )
GROUP BY
  AgentName,
  User
HAVING
  COUNT(DISTINCT EventType) = 2
  AND MAX(eventTime) - MIN(eventTime) <= 3600000
```

### Anomalous Certificate Issuance for Privileged Account via Intune
---
```sql
-- Note: Replace <server1$>, <server2$> with the actual NDES or Intune connector server names as defined in your environment.
SELECT
  MIN(eventTime) AS firstTime,
  MAX(eventTime) AS lastTime,
  AgentName,
  User AS requesterName,
  rawEventData AS san_dns_name,
  COUNT(*) AS count,
  ARRAY_AGG(rawEventData) AS subject
FROM deepvisibility
WHERE
  EventType = 'CertificateIssued'
  AND rawEventData LIKE '%1.3.6.1.5.5.7.3.2%'
  AND User IN ('server1$', 'server2$')
  AND rawEventData REGEXP 'DNS Name=[^,;]+'
GROUP BY
  AgentName,
  User,
  rawEventData
```

### Kerberos TGT Request with Certificate for Privileged Account
---
```sql
SELECT
  MIN(eventTime) AS firstTime,
  MAX(eventTime) AS lastTime,
  User,
  srcIp,
  AgentName,
  ProcessName AS app,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  EventType = 'Authentication'
  AND rawEventData LIKE '%4768%'
  AND ProcessName IN ('PA-PK-AS-REQ', '15', '16')
GROUP BY
  User,
  srcIp,
  AgentName,
  ProcessName
```