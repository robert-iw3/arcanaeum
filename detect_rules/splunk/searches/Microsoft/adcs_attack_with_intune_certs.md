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
```c
rule Intune_ADCS_PrivEsc_CertProfile_Modification {
  meta:
    author = "RW"
    description = "Detects suspicious modifications or additions to Intune device configurations related to certificate profiles, specifically targeting well-known high-privilege SIDs. This may indicate attempts at ADCS privilege escalation via Intune Certificate Connector."
    severity = "CRITICAL"

  events:
    $e.metadata.event_type = "CONFIGURATION_CHANGE" // UDM event type for configuration changes
    $e.metadata.event_type = "ENTITY_UPDATE" // Alternate UDM event type for changes

    // Capture the action (success) and command (Patch/Add deviceConfiguration)
    $e.metadata.action = "SUCCESS"
    $e.metadata.action = "CREATE"
    $e.metadata.action = "MODIFY"

    $e.metadata.product_event_type = "Patch deviceConfiguration"
    $e.metadata.product_event_type = "Add deviceConfiguration"

    // Extract the SID from the 'fields' or 'metadata.product_specific_id' field.
    // The Splunk regex searches for a specific SID pattern.
    $e.metadata.product_specific_id = /S-1-5-21-[0-9-]+-(500|512|516|518|519)/ // Extract SID pattern

  outcome:
    $first_seen = $e.metadata.event_timestamp.epoch_seconds
    $last_seen = $e.metadata.event_timestamp.epoch_seconds
    $user = $e.principal.user.userid // The user performing the action
    $destination = $e.target.hostname // The target device or configuration where the change occurred
    $command = $e.metadata.product_event_type // The command executed
    $sid = $e.metadata.product_specific_id // The extracted SID

  condition:
    $e
}
```

### Sensitive Certificate Enrollment via Intune Connector
---
```c
rule Intune_Cert_Request_Privileged_SID {
  meta:
    author = "RW"
    description = "Detects suspicious certificate requests from Intune Certificate Connector or NDES servers containing privileged SIDs in the Subject Alternative Name, excluding known benign templates. This may indicate ADCS privilege escalation attempts."
    severity = "CRITICAL"

  events:
    $e.metadata.event_type = "CERTIFICATE_REQUEST" // UDM event type for certificate requests or related actions.
    $e.metadata.action = "ISSUE" // Filter for issued certificates.

    // Filter for requests originating from known Intune Certificate Connector or NDES servers.
    // This requires a Chronicle Reference List named "ndes_intune_connector_ips"
    // containing the IP addresses of your legitimate NDES/Intune Connector servers.
    $e.principal.ip in %ndes_intune_connector_ips

    // Extract privileged SIDs from Subject Alternative Name (SAN).
    // The Splunk regex is adapted for YARA-L, using principal.x509_certificate.san.other_name
    // or a similar UDM field that captures SAN extension values.
    // Search results suggest SAN content is often in URI format: "tag:microsoft.com,2022-09-14:sid:<SID>".
    $e.principal.x509_certificate.san.other_name = /tag:microsoft\.com,2022-09-14:sid:S-1-5-21-\d{1,15}-\d{1,15}-\d{1,15}-(500|512|516|518|519)/ nocase

    // Exclude common legitimate certificate templates if known (e.g., "User", "ClientAuth").
    // Depending on your UDM mapping, the template name might be in a different field, e.g.,
    // $e.principal.x509_certificate.template_name or related.
    not $e.principal.x509_certificate.template_name in ("User", "ClientAuth")

  outcome:
    $first_seen = $e.metadata.event_timestamp.epoch_seconds
    $last_seen = $e.metadata.event_timestamp.epoch_seconds
    $destination = $e.target.hostname // The host (likely CA server) that issued the certificate.
    $requester_name = $e.principal.user.userid // The user or service account requesting the certificate.
    $privileged_sid = $e.principal.x509_certificate.san.other_name // The extracted privileged SID.
    $subject = $e.principal.x509_certificate.subject // The subject of the certificate.
    $template_name = $e.principal.x509_certificate.template_name // The certificate template name.
    $issuer = $e.principal.x509_certificate.issuer // The certificate issuer.
    $count = 1

  condition:
    $e
}
```

### Intune Device Spoofing followed by Certificate Enrollment
---
```c
rule Intune_Device_Name_Spoofing_and_Cert_Enrollment {
  meta:
    author = "RW"
    description = "Detects potential Intune device spoofing by correlating Intune device name changes with subsequent certificate issuance from NDES/Intune Connector servers within a short time window (1 hour)."
    severity = "CRITICAL"

  events:
    // Event 1: Intune Device Name Change (ms_intune_audit log)
    $intune_change.metadata.event_type = "CONFIGURATION_CHANGE" // Example UDM type, might be specific to Intune logs
    $intune_change.metadata.vendor_name = "Microsoft"
    $intune_change.metadata.product_name = "Intune"
    $intune_change.metadata.product_event_type = "Patch device" // Or a more specific field mapping for OperationName
    $intune_change.metadata.action = "MODIFY" // "Patch" is a modification
    $intune_change.principal.resource.type = "Device" // "ActivityType"=Device
    $intune_change.target.resource.name = "Device Name" // Properties.DisplayName == "Device Name"
    $intune_change.target.resource.new_value = $new_device_name // Properties.NewValue as new_device_name

    // Normalize the device name: lower case and remove domain suffix
    $device_name_norm_intune = lower(re.replace($new_device_name, `\..*`, ""))

    // Event 2: Certificate Issuance from NDES/Intune Connector (Certificates datamodel)
    $cert_issue.metadata.event_type = "CERTIFICATE_REQUEST" // Or similar, covering certificate issuance
    $cert_issue.metadata.action = "ISSUE" // Certificates.action=issued

    // Filter for requests from NDES/Intune Connector servers using a Reference List
    $cert_issue.principal.ip in %ndes_intune_connector_servers_ips // get_ndes_or_intune_connector_servers

    // Extract the device name from the certificate's SAN (Subject Alternative Name)
    // Example: DNS Name=<san_device_name>
    $cert_issue.principal.x509_certificate.san.other_name = /DNS Name=(?<san_device_name>[^,;]+)/ nocase

    // Normalize the device name from SAN
    $device_name_norm_san = lower(re.replace($san_device_name, `\..*`, ""))

    // Conditions for correlation
    $device_name_norm_intune = $device_name_norm_san // Join condition on normalized device name
    $cert_issue.metadata.event_timestamp.epoch_seconds > $intune_change.metadata.event_timestamp.epoch_seconds // issue_time > change_time

  match:
    $device_name_norm_intune over 1h after $intune_change // (issue_time - change_time) <= 3600

  outcome:
    $firstTime = $intune_change.metadata.event_timestamp.epoch_seconds
    $lastTime = $cert_issue.metadata.event_timestamp.epoch_seconds
    $device_name = $device_name_norm_intune
    $intune_change_user = $intune_change.principal.user.userid // Actor.Upn
    $cert_requester = $cert_issue.principal.user.userid // Certificates.Requester_Name
    $cert_subject = $cert_issue.principal.x509_certificate.subject
    $cert_san = $cert_issue.principal.x509_certificate.san.other_name
    $certificate_server = $cert_issue.target.hostname // Certificates.dest
    $cert_issue_time = $cert_issue.metadata.event_timestamp.epoch_seconds
    $intune_change_time = $intune_change.metadata.event_timestamp.epoch_seconds

  condition:
    $intune_change and $cert_issue
}
```

### Anomalous Certificate Issuance for Privileged Account via Intune
---
```c
rule Anomalous_Cert_Issuance_Privileged_Asset_via_Intune {
  meta:
    author = "RW"
    description = "Detects anomalous certificate issuance for privileged assets via Intune Certificate Connector or NDES, focusing on certificates with Client Authentication EKU."
    severity = "CRITICAL"

  events:
    $e.metadata.event_type = "CERTIFICATE_REQUEST" // UDM event type for certificate requests or related actions
    $e.metadata.action = "ISSUE" // Filter for issued certificates.
    $e.principal.x509_certificate.extended_key_usage = "1.3.6.1.5.5.7.3.2" // Client Authentication EKU.

    // Filter for requests originating from known Intune Certificate Connector or NDES servers.
    // This requires a Chronicle Reference List named "ndes_intune_connector_ips"
    // containing the IP addresses of your legitimate NDES/Intune Connector servers.
    $e.principal.ip in %ndes_intune_connector_ips

    // Extract the DNS name from the Subject Alternative Name (SAN).
    // The Splunk regex is adapted for YARA-L.
    $e.principal.x509_certificate.san.other_name = /DNS Name=(?<san_dns_name>[^,;]+)/ nocase

    // Correlate the SAN DNS name with a list of known privileged assets.
    // This requires a Chronicle Reference List named "privileged_assets_hostnames"
    // containing the hostnames of your privileged assets (e.g., Domain Controllers).
    $san_dns_name in %privileged_assets_hostnames

  outcome:
    $firstTime = $e.metadata.event_timestamp.epoch_seconds // UDM field for event timestamp.
    $lastTime = $e.metadata.event_timestamp.epoch_seconds // For single event, first and last are the same.
    $destination = $e.target.hostname // The host (likely CA server) that issued the certificate.
    $requester_name = $e.principal.user.userid // The user or service account requesting the certificate.
    $san_dns_name = $san_dns_name // The extracted DNS name from SAN.
    $subject = $e.principal.x509_certificate.subject // The subject of the certificate.
    $count = 1 // In a YARA-L rule, count typically refers to individual matching events.

  condition:
    $e
}
```

### Kerberos TGT Request with Certificate for Privileged Account
---
```c
rule Kerberos_TGT_Request_PKINIT_Privileged_Account {
  meta:
    author = "RW"
    description = "Detects Kerberos TGT requests using certificates (PKINIT) for privileged accounts, indicating potential abuse of certificate-based authentication for privilege escalation."
    severity = "HIGH"

  events:
    $e.metadata.event_type = "KERBEROS_TICKET_REQUEST" // UDM event type for Kerberos TGT requests.
    $e.metadata.event_code = 4768 // Windows Security Event ID for TGT requested.

    // Filter for Kerberos pre-authentication using a certificate (PKINIT).
    $e.extensions.auth.pre_authentication_type in ("PA_PK_AS_REQ", "15", "16") // UDM field for pre-authentication type.

    // Correlate the user account with a list of known privileged accounts.
    // This requires a Chronicle Reference List named "privileged_accounts"
    // containing the user IDs (including computer accounts ending with $) of your privileged accounts.
    $e.principal.user.userid in %privileged_accounts

  outcome:
    $firstTime = $e.metadata.event_timestamp.epoch_seconds // UDM field for event timestamp.
    $lastTime = $e.metadata.event_timestamp.epoch_seconds // For a single event, first and last are the same.
    $user = $e.principal.user.userid // UDM field for the user requesting the TGT.
    $source_address = $e.principal.ip // UDM field for the source IP of the request.
    $device = $e.principal.hostname // UDM field for the device associated with the request (e.g., Domain Controller).
    $pre_auth_type = $e.extensions.auth.pre_authentication_type // Pre-authentication type.

  condition:
    $e
}
```