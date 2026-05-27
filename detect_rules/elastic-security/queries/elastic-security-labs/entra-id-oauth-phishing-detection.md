<p align="center">
  <img src="https://www.elastic.co/security-labs/grid.svg" />
</p>

### Signal 1 - Microsoft Entra ID OAuth Phishing as Microsoft Authentication Broker

```sql
[ FROM logs-azure.signinlogs-* ]
        |
        |  ← Pulls all Microsoft Entra ID sign-in logs
        ↓
[ WHERE app_id == MAB AND resource_id == DRS ]
        |
        |  ← Filters to OAuth auth code requests targeting
        |     Microsoft Authentication Broker + Device Reg Service
        ↓
[ EVAL session_id + is_browser ]
        |
        |  ← Extracts session ID and flags browser-based activity
        ↓
[ STATS BY 30-minute window, user, session_id ]
        |
        |  ← Groups logins within same session and time window,
        |     then aggregates:
        |       - user/session/token identifiers
        |       - distinct IPs and geo info
        |       - user agent, browser presence
        |       - app/resource/client info
        ↓
[ WHERE ip_count ≥ 2 AND session_id_count == 1 ]
        |
        |  ← Identifies reuse of a single session ID
        |     across ≥ 2 different IP addresses
        ↓
[ AND has_browser ≥ 1 AND auth_count ≥ 2 ]
        |
        |  ← Requires at least one browser-based request
        |     and at least two total sign-in events
        ↓
[ Output = Suspicious OAuth Flow with Auth Broker for DRS ]
```

### Signal 2 - Suspicious ADRS Token Request by Microsoft Auth Broker

```sql
event.dataset: "azure.signinlogs" and azure.signinlogs.properties.app_id : "29d9ed98-a469-4536-ade2-f981bc1d605e" and azure.signinlogs.properties.resource_id : "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9" and azure.signinlogs.properties.authentication_processing_details.`Oauth Scope Info`: *adrs_access* and azure.signinlogs.properties.incoming_token_type: "refreshToken" and azure.signinlogs.properties.user_type: "Member"
```

### Signal 3 - Unusual Device Registration in Entra ID

```sql
sequence by azure.correlation_id with maxspan=1m
[any where event.dataset == "azure.auditlogs" and azure.auditlogs.identity == "Device Registration Service" and azure.auditlogs.operation_name == "Add device" and azure.auditlogs.properties.additional_details.value like "Microsoft.OData.Client/*" and (
  azure.auditlogs.properties.target_resources.`0`.modified_properties.`1`.display_name == "CloudAccountEnabled" and
azure.auditlogs.properties.target_resources.`0`.modified_properties.`1`.new_value: "[true]") and azure.auditlogs.properties.target_resources.`0`.modified_properties.`3`.new_value like "*10.0.19041.928*"]
[any where event.dataset == "azure.auditlogs" and azure.auditlogs.operation_name == "Add registered users to device" and azure.auditlogs.properties.target_resources.`0`.modified_properties.`2`.new_value like "*urn:ms-drs:enterpriseregistration.windows.net*"]
```

### Signal 3 - Entra ID RT to PRT Transition from Same User and Device

```sql
sequence by azure.signinlogs.properties.user_id, azure.signinlogs.properties.device_detail.device_id with maxspan=1d
  [authentication where
    event.dataset == "azure.signinlogs" and
    azure.signinlogs.category == "NonInteractiveUserSignInLogs" and
    azure.signinlogs.properties.app_id == "29d9ed98-a469-4536-ade2-f981bc1d605e" and
    azure.signinlogs.properties.incoming_token_type == "refreshToken" and
    azure.signinlogs.properties.device_detail.trust_type == "Azure AD joined" and
    azure.signinlogs.properties.device_detail.device_id != null and
    azure.signinlogs.properties.token_protection_status_details.sign_in_session_status == "unbound" and
    azure.signinlogs.properties.user_type == "Member" and
    azure.signinlogs.result_signature == "SUCCESS"
  ]
  [authentication where
    event.dataset == "azure.signinlogs" and
    azure.signinlogs.properties.incoming_token_type == "primaryRefreshToken" and
    azure.signinlogs.properties.resource_display_name != "Device Registration Service" and
    azure.signinlogs.result_signature == "SUCCESS"
  ]
```

### Signal 4 - Unusual PRT Usage and Registered Device for User Principal

```sql
event.dataset: "azure.signinlogs" and
    event.category: "authentication" and
    azure.signinlogs.properties.user_type: "Member" and
    azure.signinlogs.properties.token_protection_status_details.sign_in_session_status: "unbound" and
    not azure.signinlogs.properties.device_detail.device_id: "" and
    azure.signinlogs.properties.user_principal_name: *
```