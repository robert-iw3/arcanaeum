### Microsoft Entra ID OAuth Phishing and Detections
---

This report details the evolving threat of OAuth phishing targeting Microsoft Entra ID (formerly Azure AD), where attackers exploit legitimate OAuth workflows to gain unauthorized access to Microsoft 365 services. The primary goal of these attacks is to obtain tokens that allow impersonation, privilege escalation, and data exfiltration, often bypassing traditional security controls.


Recent intelligence indicates that threat actors, specifically UTA0352 and UTA0355, are increasingly using social engineering tactics via messaging apps like Signal and WhatsApp to deliver OAuth phishing links, and are leveraging compromised government accounts to establish initial credibility. Additionally, there's a growing focus on device code phishing, where attackers exploit the OAuth device authentication flow to trick users into authenticating an application through a fake device, receiving fresh access and refresh tokens.

### Actionable Threat Data
---

Monitor for successful sign-ins to Microsoft Graph (resource ID 00000003-0000-0000-c000-000000000000) or resource display name "Microsoft Graph" where the app_id is aebc6443-996d-45c2-90f0-388ff96faa56 (Visual Studio Code) and user_type is "Member", especially if authentication_processing_details contains "Oauth".

Detect instances where a single session_id is reused across two or more distinct IP addresses within a short time window (e.g., 5 minutes) for Microsoft Entra ID sign-in logs and Microsoft Graph activity, indicating potential session hijacking or token abuse.

Identify suspicious concurrent sign-ins where a user authenticates from two or more distinct IPs within a short timeframe (e.g., 1 hour) using either the device code flow without MFA or the Visual Studio Code client (app_id: aebc6443-996d-45c2-90f0-388ff96faa56).

Look for OAuth authorization code flows where the app_id is 29d9ed98-a469-4536-ade2-f981bc1d605e (Microsoft Authentication Broker) and the resource_id is 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9 (Device Registration Service), particularly when a single session_id is reused across multiple IPs and at least one request originates from a browser.

Monitor for successful sign-in events where a refresh token (incoming_token_type: "refreshToken") issued to the Microsoft Authentication Broker (app_id: 29d9ed98-a469-4536-ade2-f981bc1d605e) targets the Device Registration Service (resource_id: 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9) with the adrs_access OAuth scope.

Detect a sequence of Microsoft Entra ID audit log events indicating device registration activity, specifically "Add device", "Add registered users to device", and "Add registered owner to device" operations, all sharing the same correlation_id and occurring within a one-minute window, especially if the modified_properties for the device OS version is 10.0.19041.928.

Identify when a Microsoft Entra ID user first authenticates using a refresh token issued to the Microsoft Authentication Broker, followed shortly by the use of a Primary Refresh Token (PRT) from the same device, excluding activity tied to the Device Registration Service in the second step.

Alert on unusual PRT usage where a user principal authenticates from a newly observed device_id (not seen within the last 7 days) and the token_protection_status_details.sign_in_session_status is "unbound".

### OAuth Phishing via VSCode Client
---
```sql
`# Name: Entra ID OAuth Phishing via Visual Studio Code Client`
`# Description: Detects successful non-interactive sign-ins to Microsoft Graph using the Visual Studio Code application ID. This pattern is associated with OAuth phishing campaigns where attackers abuse the trust in first-party Microsoft applications to acquire tokens and access user data.`
`# Date: 2025-07-23`
`# References: https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection?linkId=834541216`

`# The sourcetype and index should be adjusted to match your environment's Azure AD sign-in log configuration.`
(index=* sourcetype="azure:signin" OR sourcetype="ms:aad:signin")
category=NonInteractiveUserSignInLogs

`# Filter for successful sign-ins by member accounts (not guests or service principals).`
| where status.errorCode=0 AND userType="Member"

`# Specify the target resource as Microsoft Graph.`
| where resourceDisplayName="Microsoft Graph" OR resourceId="00000003-0000-0000-c000-000000000000"

`# Specify the client application as Visual Studio Code using its well-known App ID.`
| where appId="aebc6443-996d-45c2-90f0-388ff96faa56"

`# Summarize the activity for alerting.`
| stats count by _time, user, userPrincipalName, appId, appDisplayName, resourceDisplayName, ipAddress, location
| rename userPrincipalName as victim_user, ipAddress as src_ip

`# FP Tuning: This activity can be legitimate for developers using VSCode extensions that interact with Microsoft Graph. To reduce false positives, consider the following:`
`# - Correlate the source IP with known corporate IP ranges or VPNs. Alert on activity from unexpected locations.`
`# - Baseline legitimate VSCode usage within your organization. Alert on users who do not typically use this application.`
`# - Correlate with user agent strings if available to identify non-standard clients.`
```

### Suspicious Session Reuse
---
```sql
# Name: Entra ID Session Reuse from Multiple IPs
# Description: Detects when a single Entra ID session is used from multiple IP addresses for both sign-in and Microsoft Graph activity within a 5-minute window. This behavior can indicate session hijacking or token abuse, where an attacker replays a stolen session token from a different location.
# Date: 2025-07-23
# References: https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection?linkId=834541216
# MITRE TTPs: T1190, T1566.002

# Specify sourcetypes for Entra ID sign-ins and O365/Graph activity. Adjust as needed for your environment.
(index=* (sourcetype="ms:aad:signin" OR sourcetype="azure:signin" OR sourcetype="ms:o365:management:activity"))

# Normalize key fields for correlation across different log sources.
| eval session_id=coalesce(properties.correlationId, CorrelationId), src_ip=coalesce(ipAddress, ClientIP), user=coalesce(userPrincipalName, UserId)
| eval event_type=if(sourcetype IN ("ms:aad:signin", "azure:signin"), "signin", "graph_activity")
| where isnotnull(session_id) AND isnotnull(src_ip) AND isnotnull(user)

# Group events by session ID within a 5-minute window.
| bin _time span=5m
| stats dc(src_ip) as distinct_ip_count, values(src_ip) as src_ips, dc(event_type) as distinct_event_type_count, values(event_type) as event_types, earliest(_time) as firstTime, latest(_time) as lastTime by _time, session_id, user

# Alert when a session has activity from >1 IP and includes both sign-in and graph events.
| where distinct_ip_count > 1 AND distinct_event_type_count > 1

# FP Tuning: Legitimate scenarios, like a user switching networks (e.g., wired to wireless, VPN on/off), can trigger this.
# - Filter out known corporate or VPN IP ranges.
# - Filter out known Microsoft IP ranges/ASNs to reduce noise from backend services.
#   e.g., | lookup ms_asn_ip_ranges.csv ip as src_ip OUTPUTNEW is_ms_ip | where isnull(is_ms_ip)
# - Adjust the 5-minute time window based on your environment's baseline activity.

# Format the results for alerting.
| rename user as victim_user, session_id as entra_session_id
| convert ctime(firstTime) ctime(lastTime)
| table firstTime, lastTime, victim_user, entra_session_id, distinct_ip_count, src_ips, event_types
```

### Concurrent Sign-ins with Suspicious Properties
---
```sql
# Name: Entra ID Concurrent Sign-ins with Suspicious Properties
# Description: Detects when a user authenticates from two or more distinct IP addresses within a 1-hour window, where at least one sign-in involves the Visual Studio Code client or the device code flow. This pattern can indicate token replay, session hijacking, or adversary-in-the-middle (AitM) attacks.
# Date: 2025-07-23
# References: https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection?linkId=834541216
# MITRE TTPs: T1190, T1566.002

# Target successful Entra ID sign-in logs. Adjust sourcetype/index as needed.
(index=* sourcetype="ms:aad:signin" OR sourcetype="azure:signin")
status.errorCode=0

# Group events into 1-hour windows for correlation.
| bin _time span=1h

# Aggregate sign-ins by user, counting distinct IPs and flagging suspicious properties.
| stats dc(ipAddress) as distinct_ip_count,
        values(ipAddress) as src_ips,
        list(eval(if(appId=="aebc6443-996d-45c2-90f0-388ff96faa56", "VS Code Client", null()))) as suspicious_apps,
        list(eval(if(authenticationDetails{}.authenticationMethod == "Device code", "Device Code Flow", null()))) as suspicious_auth_methods
        by _time, userPrincipalName

# Alert when a user has >1 IP AND at least one of the suspicious properties is present.
| where distinct_ip_count > 1 AND (isnotnull(suspicious_apps) OR isnotnull(suspicious_auth_methods))

# FP Tuning: Legitimate use of VPNs, mobile devices, or developer tools can cause FPs.
# - Filter out known corporate/VPN IP ranges.
# - The intel specifies "device code flow without MFA". To improve fidelity, you can add a filter to check for the absence of MFA, e.g., by inspecting `mfaDetail` or `authenticationProcessingDetails` fields.
# - Baseline users who frequently exhibit this behavior (e.g., developers).

# Format results for alerting.
| rename userPrincipalName as victim_user
| eval suspicious_properties = mvcombine(suspicious_apps, suspicious_auth_methods)
| table _time, victim_user, distinct_ip_count, src_ips, suspicious_properties
```

### OAuth Phishing via Auth Broker to DRS
---
```sql
# Name: OAuth Phishing via Microsoft Authentication Broker to DRS
# Description: Detects when a single Entra ID session involving the Microsoft Authentication Broker and Device Registration Service is used from multiple IP addresses, with at least one request coming from a browser. This pattern is indicative of an adversary using a phished authorization code to begin the device registration process for persistence.
# Date: 2025-07-23
# References: https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection?linkId=834541216
# MITRE TTPs: T1566.002, T1098

# Target successful Entra ID sign-in logs. Adjust sourcetype/index as needed.
(index=* sourcetype="ms:aad:signin" OR sourcetype="azure:signin")
status.errorCode=0

# Filter for the specific application (Microsoft Authentication Broker) and resource (Device Registration Service).
| where appId="29d9ed98-a469-4536-ade2-f981bc1d605e" AND resourceId="01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9"

# Identify requests originating from a web browser based on the User-Agent string.
| eval is_browser=if(match(userAgent, "(?i)Mozilla|Chrome|Safari|Edge|Firefox"), 1, 0)

# Group events by session (correlationId) within a 30-minute window to correlate activity.
| bin _time span=30m
| stats dc(ipAddress) as distinct_ip_count,
        values(ipAddress) as src_ips,
        sum(is_browser) as browser_request_count,
        count as event_count,
        values(userAgent) as user_agents
        by _time, correlationId, userPrincipalName

# Alert when a single session is used from more than one IP and includes at least one browser request.
| where distinct_ip_count > 1 AND browser_request_count > 0

# FP Tuning: A user quickly switching networks (e.g., from Wi-Fi to a mobile hotspot) could trigger this alert.
# - Consider filtering out known corporate/VPN IP ranges to reduce noise.
# - This activity should be extremely rare in most environments, so any alert warrants investigation.

# Format results for alerting.
| rename userPrincipalName as victim_user, correlationId as session_id
| table _time, victim_user, session_id, distinct_ip_count, src_ips, browser_request_count, user_agents
```

### Suspicious ADRS Token Request
---
```sql
# Name: Suspicious ADRS Token Request
# Description: Identifies Microsoft Entra ID sign-in events where a refresh token issued to the Microsoft Authentication Broker (MAB) client is used to access the Device Registration Service (DRS) with the 'adrs_access' scope. This pattern is a strong indicator of an adversary leveraging a stolen refresh token to register a malicious device for persistence, a technique commonly used with tools like ROADtx after an initial OAuth phishing attack.
# Date: 2025-07-23
# References: https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection?linkId=834541216
# MITRE TTPs: T1566.002, T1098

# Target successful Entra ID sign-in logs. Adjust sourcetype/index as needed.
(index=* sourcetype="ms:aad:signin" OR sourcetype="azure:signin")
status.errorCode=0

# Filter for member accounts using a refresh token for authentication.
| where userType="Member" AND incomingTokenType="refreshToken"

# Filter for the specific client (Microsoft Authentication Broker) and resource (Device Registration Service).
| where appId="29d9ed98-a469-4536-ade2-f981bc1d605e" AND resourceId="01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9"

# Ensure the OAuth scope contains 'adrs_access', indicating a request to the Azure Device Registration Service.
# The field name for authentication details can vary. Using a case-insensitive match for robustness.
| where match(authenticationProcessingDetails, "(?i)adrs_access")

# FP Tuning: This activity is highly anomalous and should have a very low false positive rate.
# Any alert warrants immediate investigation into potential device registration abuse.
# Ensure the field names (e.g., incomingTokenType, authenticationProcessingDetails) match your specific Splunk add-on for Azure.

# Format results for alerting.
| table _time, userPrincipalName, ipAddress, location, appId, appDisplayName, resourceDisplayName, incomingTokenType, authenticationProcessingDetails
| rename userPrincipalName as victim_user, ipAddress as src_ip
```

### Unusual Device Registration
---
```sql
# Name: Unusual Device Registration in Entra ID
# Description: Detects a rapid sequence of Entra ID audit events ("Add device", "Add registered users", "Add registered owner") sharing the same correlation ID. This pattern, especially when involving a specific Windows OS version ("10.0.19041.928"), is a strong indicator of malicious device registration using tools like ROADtx for persistence.
# Date: 2025-07-23
# References: https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection?linkId=834541216
# MITRE TTPs: T1098, T1566.002

# Target Entra ID audit logs. Adjust sourcetype/index as needed.
(index=* sourcetype="ms:aad:audit" OR sourcetype="azure:audit")
category=Device

# Group related events by correlation ID that occur within a 1-minute window.
| transaction correlationId maxspan=1m

# Filter for transactions that contain the full device registration sequence.
| where like(operationName, "%Add device%")
  AND like(operationName, "%Add registered users to device%")
  AND like(operationName, "%Add registered owner to device%")

# Specifically check for the hardcoded OS version used by tools like ROADtx. This is a high-fidelity indicator.
| where like(properties.targetResources{}.modifiedProperties{}.newValue, "%10.0.19041.928%")

# FP Tuning: Legitimate, scripted device provisioning could potentially trigger this rule, though the specific OS version is highly suspicious.
# To reduce potential FPs, consider filtering out events initiated by known, legitimate service principals used for device management.
# e.g., | where 'initiatedBy.user.userPrincipalName' != "provisioning_service_account@domain.com"

# Format results for alerting.
| eval actor_user = 'initiatedBy.user.userPrincipalName'
| eval target_device = mvindex('properties.targetResources{}.displayName', 0)
| eval operations = mvjoin(mvdedup(operationName), ", ")
| table _time, actor_user, correlationId, target_device, operations
| rename correlationId as correlation_id
```

### RT to PRT Transition
---
```sql
# Name: Entra ID Refresh Token to PRT Transition
# Description: Detects a sequence of authentications where a refresh token is used by the Microsoft Authentication Broker, followed shortly by the use of a Primary Refresh Token (PRT) from the same user and device. This pattern is a strong indicator of an adversary registering a device after a phishing attack and then using the resulting PRT for persistent access to other resources.
# Date: 2025-07-23
# References: https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection?linkId=834541216
# MITRE TTPs: T1098, T1566.002

# Target successful Entra ID sign-in logs. Adjust sourcetype/index as needed.
(index=* sourcetype="ms:aad:signin" OR sourcetype="azure:signin")
status.errorCode=0 userType="Member"

# Correlate events by user and device ID that occur within a 1-day window.
# Note: Field names like deviceDetail.deviceId and tokenProtectionStatus.signInSessionStatus may vary based on your Splunk Add-on for Microsoft Cloud Services version.
| transaction userPrincipalName, deviceDetail.deviceId maxspan=1d
  # The sequence must start with a refresh token auth via the Microsoft Authentication Broker.
  # The "unbound" session status is a key indicator of token replay.
  startswith=(
    incomingTokenType="refreshToken" AND
    appId="29d9ed98-a469-4536-ade2-f981bc1d605e" AND
    deviceDetail.trustType="Azure AD joined" AND
    tokenProtectionStatus.signInSessionStatus="unbound"
  )
  # The sequence must be followed by a PRT auth to a resource other than the Device Registration Service.
  # This indicates the PRT is being used for post-compromise activity, not just registration.
  endswith=(
    incomingTokenType="primaryRefreshToken" AND
    resourceDisplayName!="Device Registration Service"
  )

# FP Tuning: This is a high-fidelity detection pattern. False positives are unlikely but could theoretically occur in complex, scripted device enrollment or recovery scenarios. Any alert should be investigated as a potential compromise.

# Format the results for alerting.
| eval transaction_duration_sec = duration
| eval transaction_start_time = strftime(_time, "%Y-%m-%d %H:%M:%S")
| eval transaction_end_time = strftime(_time + duration, "%Y-%m-%d %H:%M:%S")
| table transaction_start_time, transaction_end_time, transaction_duration_sec, userPrincipalName, deviceDetail.deviceId, eventcount
| rename userPrincipalName as victim_user, deviceDetail.deviceId as device_id, eventcount as events_in_sequence
```

### Unusual PRT Usage
---
```sql
# Name: Entra ID Unusual PRT Usage from Newly Observed Device
# Description: Detects when a user authenticates using a Primary Refresh Token (PRT) from a device they have not used in the last 7 days, and the session status is "unbound". This combination is a high-fidelity indicator of token replay or device spoofing, potentially following a device registration attack (e.g., using ROADtx).
# Date: 2025-07-23
# References: https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection?linkId=834541216
# MITRE TTPs: T1098, T1566.002

# This detection requires a lookup file named 'user_device_baseline.csv' that contains a baseline of user and device activity.
# A separate saved search should run periodically (e.g., daily) to populate and maintain this lookup.
# Example lookup update search:
# `(index=* sourcetype="ms:aad:signin" OR sourcetype="azure:signin") status.errorCode=0 isnotnull(deviceDetail.deviceId) deviceDetail.deviceId!=""`
# `| fields _time, userPrincipalName, deviceDetail.deviceId`
# `| inputlookup append=t user_device_baseline.csv`
# `| stats max(_time) as last_seen by userPrincipalName, deviceDetail.deviceId`
# `| outputlookup user_device_baseline.csv`

# Target successful Entra ID sign-in logs. Adjust sourcetype/index as needed.
(index=* sourcetype="ms:aad:signin" OR sourcetype="azure:signin")
status.errorCode=0 userType="Member"

# Filter for the specific indicators of compromise.
# - incomingTokenType is "primaryRefreshToken" to focus on PRT usage.
# - tokenProtectionStatus.signInSessionStatus is "unbound", a key indicator of token replay.
# - A device ID must be present.
| where incomingTokenType="primaryRefreshToken"
  AND tokenProtectionStatus.signInSessionStatus="unbound"
  AND isnotnull(deviceDetail.deviceId) AND deviceDetail.deviceId!=""

# Use the lookup to get the last time this user-device pair was seen.
| lookup user_device_baseline.csv userPrincipalName, deviceDetail.deviceId OUTPUT last_seen

# Alert if the device has never been seen before (isnull) or was last seen more than 7 days ago (604800 seconds).
| where isnull(last_seen) OR (_time - last_seen > 604800)

# FP Tuning: Legitimate new device provisioning or a user returning from a long vacation could trigger this.
# However, the combination with an "unbound" PRT session is highly suspicious.
# To improve fidelity, you could correlate this alert with recent device enrollment events in Entra ID audit logs for the same user.

# Format the results for alerting.
| eval last_seen_time = if(isnull(last_seen), "Never", strftime(last_seen, "%Y-%m-%d %H:%M:%S"))
| table _time, userPrincipalName, deviceDetail.deviceId, ipAddress, location, last_seen_time, tokenProtectionStatus.signInSessionStatus
| rename userPrincipalName as victim_user, deviceDetail.deviceId as device_id, ipAddress as src_ip
```
