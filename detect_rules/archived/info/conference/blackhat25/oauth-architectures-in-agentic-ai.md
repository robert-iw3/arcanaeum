### Back to the Future: Hacking & Securing Connection-based OAuth Architectures in Agentic AI & Integration Platforms
---

This report summarizes the re-emergence of classic web security vulnerabilities within modern OAuth-as-a-Service (OaaS) architectures, particularly those used in Agentic AI and integration platforms. These vulnerabilities, including Session Fixation, Open Redirect, and Confused Deputy attacks, can lead to account takeovers and unauthorized access to user data.

The most significant new finding is the "remanifestation" of classic web attacks within the context of OaaS and Agentic AI platforms, which were previously thought to be addressed by OAuth standards. This is noteworthy because the proprietary and often non-standard implementations of OaaS introduce new attack surfaces, making these well-known vulnerabilities relevant again.

### Actionable Threat Data
---

Session Fixation (Cross-user): Attackers can initiate an OAuth flow, fixate the authorization session to a victim's browser by sharing a crafted OAuth URL, and then gain access to the victim's OAuth token, leading to account takeover. This can be detected by monitoring for discrepancies between the user who initiates an OAuth flow and the user who completes it.

Open Redirect (Cross-user): Attackers can leverage a vulnerable post-redirect URL in an OAuth flow to redirect a victim to an attacker-controlled location after successful authentication, potentially leading to credential leakage or further social engineering. Detections should focus on validating redirect URIs against a strict allowlist and ensuring that user-controllable post-redirect URLs are not exposed to the frontend.

Client ID Confusion (Cross-agent): In OaaS environments where client IDs are shared across multiple agents, an attacker can trick a user into consenting to a pre-built tool for one agent, inadvertently granting access to an attacker-controlled agent. This can be identified by ensuring that client IDs are unique per agent, or by implementing "Bring Your Own Client ID" (BYO) mechanisms.

Cross-agent COAT (Cross-app/tool OAuth Account Takeover): Attackers can infiltrate a malicious tool or agent to register other malicious tools by design, leading to account takeovers by leaking authorization codes or tokens. Detections should focus on differentiating between agents and tools, and enforcing globally unique redirect URIs for each tool within an agent.

Improper Fixes Leading to New Vulnerabilities: Attempts to fix Session Fixation using a "Post-Redirect pattern" can inadvertently introduce new Open Redirect vulnerabilities if not implemented carefully. Monitoring for unexpected redirects or unusual callback URLs after an OAuth flow can help identify such issues.

### OAuth Session Fixation Attempt
---

Author: RW

Date: 2025-08-14

Description:

Detects potential OAuth session fixation attacks by identifying when the user who initiates an OAuth flow is different from the user who completes it.

This attack occurs when an attacker tricks a victim into completing an OAuth authorization flow that the attacker started.

False Positive Sensitivity: Medium. Legitimate scenarios, such as an admin acting on behalf of a user or complex delegated application permissions, may trigger this alert.

Triage Steps:

    1. Verify if the initiating and completing users are expected to be different for the application in question.

    2. Examine the application to understand its OAuth flow.

    3. Investigate the activity of both the initiating and completing users around the time of the alert.

    4. Check if the initiating user sent a link to the completing user via email, chat, or another medium.

### Splunk
---
```sql
-- STEP 1: Define search criteria for OAuth events. Adapt the index, sourcetype, and event identifiers for your environment.
| search (index=* sourcetype=*) -- Specify your OAuth log sources here
    (event_name="OAuthFlowStart" OR event_name IN ("OAuthCallback", "TokenExchange")) -- Update with your event identifiers for initiation and completion

-- STEP 2: Standardize field names and identify flow steps. Replace placeholders with your actual field names.
| eval user_id = coalesce(user, username, user_name),
       state_param = coalesce(state, session_state, details.state),
       app_name = coalesce(app, application, app_id),
       src_ip = coalesce(src, src_ip, client_ip)
| eval flow_step = if(match(event_name, "OAuthFlowStart"), "initiation", "completion")
| where isnotnull(state_param) AND isnotnull(user_id)

-- STEP 3: Correlate initiation and completion events using the 'state' parameter over a 30-minute window.
| stats
    earliest(_time) as initiation_time,
    latest(_time) as completion_time,
    earliest(eval(if(flow_step=="initiation", user_id, null))) as initiating_user,
    latest(eval(if(flow_step=="completion", user_id, null))) as completing_user,
    earliest(eval(if(flow_step=="initiation", src_ip, null))) as initiating_ip,
    latest(eval(if(flow_step=="completion", src_ip, null))) as completing_ip
    by state_param, app_name

-- STEP 4: Apply detection logic - alert when initiating and completing users do not match.
| where isnotnull(initiating_user) AND isnotnull(completing_user) AND initiating_user != completing_user
| where (completion_time - initiation_time) > 0 AND (completion_time - initiation_time) <= 1800

-- Optional FP Tuning: Uncomment the following line to also check for different source IPs. This may increase FPs for users on dynamic networks but can be a strong signal.
-- | where initiating_ip != completing_ip

-- STEP 5: Format results for readability.
| convert ctime(*_time)
| table initiation_time, completion_time, app_name, initiating_user, initiating_ip, completing_user, completing_ip, state_param
| rename
    app_name as "Application",
    initiating_user as "Initiating User",
    initiating_ip as "Initiating IP",
    initiation_time as "Initiation Time",
    completion_time as "Detection Time",
    completing_user as "Completing User",
    completing_ip as "Completing IP",
    state_param as "State Parameter"
```

### Crowdstrike
---
```sql
event_platform=Win event_simpleName IN ("OAuthFlowStart","OAuthCallback","TokenExchange")
| eval user_id=coalesce(UserName,UserId,User_name), state_param=coalesce(State,SessionState,Details.State), app_name=coalesce(App,Application,AppId), src_ip=coalesce(SourceIp,ClientIp,SrcIp), flow_step=if(EventName=="OAuthFlowStart","initiation","completion")
| where state_param IS NOT NULL AND user_id IS NOT NULL
| group by StateParameter, AppName
| aggregate initiation_time=min(if(flow_step=="initiation",ContextTimeStamp,null)), completion_time=max(if(flow_step=="completion",ContextTimeStamp,null)), initiating_user=min(if(flow_step=="initiation",user_id,null)), completing_user=max(if(flow_step=="completion",user_id,null)), initiating_ip=min(if(flow_step=="initiation",src_ip,null)), completing_ip=max(if(flow_step=="completion",src_ip,null))
| where initiating_user IS NOT NULL AND completing_user IS NOT NULL AND initiating_user != completing_user AND (completion_time - initiation_time) > 0 AND (completion_time - initiation_time) <= 1800000
| project initiation_time, completion_time, app_name as Application, initiating_user as Initiating_User, initiating_ip as Initiating_IP, completing_user as Completing_User, completing_ip as Completing_IP, state_param as State_Parameter
```

### Datadog
---
```sql
(event_name:OAuthFlowStart OR event_name:(OAuthCallback OR TokenExchange)) AND @timestamp
:* AND user:* AND state:*
| eval user_id=coalesce(user,username,user_name), state_param=coalesce(state,session_state,details.state), app_name=coalesce(app,application,app_id), src_ip=coalesce(src,src_ip,client_ip), flow_step=if(event_name="OAuthFlowStart","initiation","completion")
| select min(if(flow_step="initiation",timestamp,null)) as initiation_time, max(if(flow_step="completion",timestamp,null)) as completion_time, min(if(flow_step="initiation",user_id,null)) as initiating_user, max(if(flow_step="completion",user_id,null)) as completing_user, min(if(flow_step="initiation",src_ip,null)) as initiating_ip, max(if(flow_step="completion",src_ip,null)) as completing_ip by state_param, app_name
| where initiating_user IS NOT NULL AND completing_user IS NOT NULL AND initiating_user != completing_user AND (completion_time - initiation_time) > 0 AND (completion_time - initiation_time) <= 1800
| select initiation_time, completion_time, app_name as Application, initiating_user as Initiating_User, initiating_ip as Initiating_IP, completing_user as Completing_User, completing_ip as Completing_IP, state_param as State_Parameter
```

### Elastic
---
```sql
FROM *
| WHERE event.action IN ("OAuthFlowStart", "OAuthCallback", "TokenExchange")
  AND user.id IS NOT NULL AND state IS NOT NULL
| EVAL user_id = COALESCE(user.id, user.name, user.full_name),
      state_param = COALESCE(state, session_state, details.state),
      app_name = COALESCE(application.name, application.id, app),
      src_ip = COALESCE(source.ip, client.ip, src_ip),
      flow_step = CASE(event.action == "OAuthFlowStart", "initiation", "completion")
| STATS
    initiation_time = MIN(CASE(flow_step == "initiation", @timestamp
, NULL)),
    completion_time = MAX(CASE(flow_step == "completion", @timestamp
, NULL)),
    initiating_user = MIN(CASE(flow_step == "initiation", user_id, NULL)),
    completing_user = MAX(CASE(flow_step == "completion", user_id, NULL)),
    initiating_ip = MIN(CASE(flow_step == "initiation", src_ip, NULL)),
    completing_ip = MAX(CASE(flow_step == "completion", src_ip, NULL))
    BY state_param, app_name
| WHERE initiating_user IS NOT NULL AND completing_user IS NOT NULL
  AND initiating_user != completing_user
  AND (completion_time - initiation_time) > 0
  AND (completion_time - initiation_time) <= 1800 * 1000
| KEEP initiation_time, completion_time, app_name AS Application, initiating_user AS Initiating_User, initiating_ip AS Initiating_IP, completing_user AS Completing_User, completing_ip AS Completing_IP, state_param AS State_Parameter
```

### Sentinel One
---
```sql
SELECT MIN(EventTime) AS Initiation_Time, MAX(EventTime) AS Detection_Time, MIN(CASE WHEN EventName IN ('OAuthFlowStart') THEN UserName END) AS Initiating_User, MAX(CASE WHEN EventName IN ('OAuthCallback', 'TokenExchange') THEN UserName END) AS Completing_User, MIN(CASE WHEN EventName IN ('OAuthFlowStart') THEN SrcIP END) AS Initiating_IP, MAX(CASE WHEN EventName IN ('OAuthCallback', 'TokenExchange') THEN SrcIP END) AS Completing_IP, State AS State_Parameter, Application AS Application
FROM events
WHERE EventName IN ('OAuthFlowStart', 'OAuthCallback', 'TokenExchange')
  AND UserName IS NOT NULL AND State IS NOT NULL
GROUP BY State, Application
HAVING Initiating_User IS NOT NULL AND Completing_User IS NOT NULL
  AND Initiating_User != Completing_User
  AND (Detection_Time - Initiation_Time) > 0
  AND (Detection_Time - Initiation_Time) <= 1800000
```

### OAuth Open Redirect
---
Author: RW

Date: 2025-08-14

Description:

Detects potential OAuth open redirect vulnerabilities by identifying when a redirect_uri in an authorization request does not match a pre-approved allowlist for the given application.

False Positive Sensitivity: Medium. This detection is highly dependent on a well-maintained allowlist of redirect URIs. A new or changed but legitimate URI will trigger an alert until the allowlist is updated.

Triage Steps:

    1. Examine the 'DetectedRedirectUri' and the 'Application'.

    2. Determine if the URI is a legitimate endpoint for that application's authentication flow. Consult with the application owner if necessary.

    3. If the URI is legitimate, add it to the 'RedirectUriAllowlist' to prevent future false positives.

    4. If the URI is suspicious or malicious, investigate the user's activity around the time of the alert for signs of phishing or compromise. Block the malicious URI.

### Splunk
---
```sql
-- STEP 1: Define search criteria for OAuth authorization events. Adapt the index, sourcetype, and event filters for your environment.
| search (index=* sourcetype=*) -- Specify your OAuth log sources here, e.g., index=okta or sourcetype=azure:signinlogs
    (eventtype="oauth_authorization" OR "Authorize app") -- Update with your event identifiers for OAuth authorization requests

-- STEP 2: Extract and rename key fields. Replace placeholders with your actual field names.
| rename client_id as ApplicationId, redirect_uri as DetectedRedirectUri, user as User, src_ip as IPAddress, app_name as Application
| where isnotnull(ApplicationId) AND isnotnull(DetectedRedirectUri)

-- STEP 3: Use a lookup to check if the combination of ApplicationId and DetectedRedirectUri is on the allowlist.
-- The lookup file 'oauth_redirect_uri_allowlist.csv' must contain 'ApplicationId' and 'AllowedRedirectUri' columns.
| lookup oauth_redirect_uri_allowlist.csv ApplicationId as ApplicationId, DetectedRedirectUri as AllowedRedirectUri OUTPUT AllowedRedirectUri as MatchedUri

-- STEP 4: Filter for events where the redirect URI was NOT found in the allowlist for the given application.
| where isnull(MatchedUri)

-- STEP 5: Format the results for alerting and investigation.
| table _time, User, IPAddress, Application, ApplicationId, DetectedRedirectUri
| rename _time as "DetectionTime", IPAddress as "Source IP Address"
```

### Crowdstrike
---
```sql
event_platform=Win event_simpleName IN ("oauth_authorization","AuthorizeApp") ClientId IS NOT NULL RedirectUri IS NOT NULL
| lookup oauth_redirect_uri_allowlist.csv ClientId as ApplicationId, RedirectUri as AllowedRedirectUri OUTPUT AllowedRedirectUri as MatchedUri
| where MatchedUri IS NULL
| project ContextTimeStamp as DetectionTime, UserName as User, SourceIp as Source_IP_Address, AppName as Application, ClientId as ApplicationId, RedirectUri as DetectedRedirectUri
```

### Datadog
---
```sql
(eventtype:oauth_authorization OR "Authorize app") AND client_id:* AND redirect_uri:*
| eval ApplicationId=client_id, DetectedRedirectUri=redirect_uri, User=user, Source_IP_Address=src_ip, Application=app_name
| lookup oauth_redirect_uri_allowlist.csv ApplicationId, DetectedRedirectUri as AllowedRedirectUri OUTPUT AllowedRedirectUri as MatchedUri
| where MatchedUri IS NULL
| select timestamp as DetectionTime, User, Source_IP_Address, Application, ApplicationId, DetectedRedirectUri
```

### Elastic
---
```sql
FROM *
| WHERE event.type IN ("oauth_authorization", "Authorize app")
  AND client.id IS NOT NULL AND http.response.redirect.uri IS NOT NULL
| EVAL ApplicationId = client.id, DetectedRedirectUri = http.response.redirect.uri, User = user.name, Source_IP_Address = source.ip, Application = application.name
| LOOKUP oauth_redirect_uri_allowlist.csv ON ApplicationId = ApplicationId, DetectedRedirectUri = AllowedRedirectUri OUTPUT AllowedRedirectUri AS MatchedUri
| WHERE MatchedUri IS NULL
| KEEP @timestamp
 AS DetectionTime, User, Source_IP_Address, Application, ApplicationId, DetectedRedirectUri
```

### Sentinel One
---
```sql
SELECT EventTime AS DetectionTime, UserName AS User, SrcIP AS Source_IP_Address, Application AS Application, ClientId AS ApplicationId, RedirectUri AS DetectedRedirectUri
FROM events
WHERE EventName IN ('oauth_authorization', 'AuthorizeApp')
  AND ClientId IS NOT NULL AND RedirectUri IS NOT NULL
  AND RedirectUri NOT IN (SELECT AllowedRedirectUri FROM oauth_redirect_uri_allowlist WHERE ApplicationId = ClientId)
```

### OAuth Client ID Confusion
---
Author: RW

Date: 2025-08-14

Description:

Detects when a single OAuth client_id is used by multiple distinct applications or agents. This is a key indicator of a potential Client ID Confusion vulnerability in OAuth-as-a-Service (OaaS) platforms, where an attacker's application could leverage a user's consent granted to a different, legitimate application that shares the same client_id.

False Positive Sensitivity: Medium. Some platforms may legitimately use a shared client_id for a suite of trusted applications from the same vendor. An allowlist should be maintained for such cases.

Triage Steps:

    1. Examine the 'SharedApplicationId' and the list of applications in 'ApplicationSet'.

    2. Verify if all applications in the set are from the same trusted vendor and are expected to share a client_id.

    3. If any application in the set is unknown, untrusted, or from a different developer than the others, it's a strong indicator of a vulnerability.

    4. Consult the platform's documentation to see if unique client_ids can be enforced per application/agent (e.g., "Bring Your Own Client ID").

    5. If the shared client_id is deemed legitimate, add it to the 'SharedClientIdAllowlist' to suppress future alerts.

### Splunk
---
```sql
-- STEP 1: Define search criteria for OAuth authorization events. Adapt the index, sourcetype, and event filters for your environment.
| tstats `summariesonly` count from datamodel=Authentication where (Authentication.action=success) by _time, Authentication.app, Authentication.src_user, Authentication.dest
| `drop_dm_object_name("Authentication")`

-- STEP 2: Extract and rename key fields. The 'dest' field is assumed to hold the client_id/ApplicationId. Adjust field names as necessary for your data source.
| rename app as Application, dest as ClientId, src_user as User
| where isnotnull(ClientId) AND isnotnull(Application)

-- STEP 3: Summarize by ClientId to find which ones are used by multiple applications over the last 14 days.
| bin _time span=14d
| stats
    dc(Application) as DistinctAppCount,
    values(Application) as ApplicationSet,
    values(User) as AffectedUsers
    by ClientId

-- STEP 4: Filter for ClientIds used by more than one distinct application.
| where DistinctAppCount > 1

-- STEP 5: Exclude known and allowlisted shared client IDs to reduce false positives. The lookup file should contain a single column named 'ClientId'.
| lookup oauth_shared_client_id_allowlist.csv ClientId OUTPUT ClientId as AllowlistedId
| where isnull(AllowlistedId)

-- STEP 6: Format the results for alerting and investigation.
| rename
    ClientId as "SharedClientId",
    DistinctAppCount as "Distinct Application Count",
    ApplicationSet as "Application Set",
    AffectedUsers as "Affected Users"
| fields "SharedClientId", "Distinct Application Count", "Application Set", "Affected Users"
```

### Crowdstrike
---
```sql
event_platform=Win event_simpleName=AuthenticationEvent Action=success ClientId IS NOT NULL AppName IS NOT NULL
| bin ContextTimeStamp span=1209600000
| group by ClientId
| aggregate DistinctAppCount=count_distinct(AppName), ApplicationSet=values(AppName), AffectedUsers=values(UserName)
| where DistinctAppCount > 1
| lookup oauth_shared_client_id_allowlist.csv ClientId OUTPUT ClientId as AllowlistedId
| where AllowlistedId IS NULL
| project ClientId as SharedClientId, DistinctAppCount as Distinct_Application_Count, ApplicationSet as Application_Set, AffectedUsers as Affected_Users
```

### Datadog
---
```sql
action:success AND app:* AND client_id:*
| eval Application=app, ClientId=dest, User=src_user
| bin timestamp span=14d
| select count_distinct(Application) as Distinct_Application_Count, values(Application) as Application_Set, values(User) as Affected_Users by ClientId
| where Distinct_Application_Count > 1
| lookup oauth_shared_client_id_allowlist.csv ClientId OUTPUT ClientId as AllowlistedId
| where AllowlistedId IS NULL
| select ClientId as SharedClientId, Distinct_Application_Count, Application_Set, Affected_Users
```

### Elastic
---
```sql
FROM *
| WHERE event.outcome = "success"
  AND client.id IS NOT NULL AND application.name IS NOT NULL
| EVAL Application = application.name, ClientId = client.id, User = user.name
| EVAL time_bin = DATE_TRUNC(14 days, @timestamp
)
| STATS
    DistinctAppCount = COUNT_DISTINCT(Application),
    ApplicationSet = VALUES(Application),
    AffectedUsers = VALUES(User)
    BY ClientId
| WHERE DistinctAppCount > 1
| LOOKUP oauth_shared_client_id_allowlist.csv ON ClientId = ClientId OUTPUT ClientId AS AllowlistedId
| WHERE AllowlistedId IS NULL
| KEEP ClientId AS SharedClientId, DistinctAppCount AS Distinct_Application_Count, ApplicationSet AS Application_Set, AffectedUsers AS Affected_Users
```

### Sentinel One
---
```sql
SELECT ClientId AS SharedClientId, COUNT(DISTINCT Application) AS Distinct_Application_Count, GROUP_CONCAT(DISTINCT Application) AS Application_Set, GROUP_CONCAT(DISTINCT UserName) AS Affected_Users
FROM events
WHERE EventName = 'AuthenticationEvent' AND EventOutcome = 'success'
  AND ClientId IS NOT NULL AND Application IS NOT NULL
GROUP BY ClientId, FLOOR(UNIX_TIMESTAMP(EventTime)/(142460*60))
HAVING Distinct_Application_Count > 1
AND ClientId NOT IN (SELECT ClientId FROM oauth_shared_client_id_allowlist)
```

### Suspicious OAuth Endpoint Configuration for Cross-Agent COAT
---
Author: RW

Date: 2025-08-14

Description:

Detects when an OAuth-enabled application or agent is configured with authorization or token endpoints pointing to a potentially malicious or non-standard domain. This is a preparatory step for a Cross-agent COAT (Cross-app/tool OAuth Account Takeover) attack, where an attacker sets up a malicious agent to intercept OAuth authorization codes.

False Positive Sensitivity: Medium. New legitimate integrations or custom-developed agents using new domains will trigger this alert. A robust allowlist of trusted domains is crucial for tuning.

Triage Steps:

    1. Examine the 'User', 'Application', and the 'SuspiciousUrl'.

    2. Determine if the domain of the URL is a legitimate Identity Provider (IdP) or a trusted partner integration for your organization.

    3. Investigate the user's activity. Is this user expected to be configuring OAuth applications?

    4. If the domain is legitimate, add it to the 'TrustedOAuthDomains' allowlist to prevent future alerts.

    5. If the domain is malicious, it indicates an attempt to set up a rogue agent. Investigate the application for other suspicious configurations, review all recent activity by the user, and consider disabling the application.

### Splunk
---
```sql
-- STEP 1: Define search criteria for OAuth application configuration events. Adapt the index, sourcetype, and event identifiers for your environment.
| search (index=* sourcetype=*) -- Specify your OAuth audit log sources here
    (event_name="update_oauth_app" OR (object="oauth_app" action="updated")) -- Update with your event identifiers for app configuration changes

-- STEP 2: Extract OAuth endpoint URLs. This is highly dependent on your log schema. Use spath for JSON or rex for unstructured data.
| spath output=auth_url path=details.authorization_url
| spath output=token_url path=details.token_url
-- | rex \"authorization_url\\\":\\\"(?<auth_url>[^\\\"]+)\"
-- | rex \"token_url\\\":\\\"(?<token_url>[^\\\"]+)\"

-- STEP 3: Normalize URLs into a single field and expand them for individual processing.
| eval suspicious_url = mvappend(auth_url, token_url)
| mvexpand suspicious_url
| where isnotnull(suspicious_url)

-- STEP 4: Extract the domain from the URL.
| rex field=suspicious_url "https?:\/\/(?<domain>[^\/:]+)"

-- STEP 5: Use a lookup to check if the domain is in the trusted list. The lookup file 'trusted_oauth_domains.csv' should contain a 'domain' column with all legitimate IdP and partner domains.
| lookup trusted_oauth_domains.csv domain OUTPUT domain as trusted_domain

-- STEP 6: Filter for events where the configured domain was NOT found in the trusted list.
| where isnull(trusted_domain) AND isnotnull(domain)

-- STEP 7: Format the results for alerting and investigation.
| rename user as "User", src_ip as "Source IP", app as "Application", action as "Action", suspicious_url as "Suspicious URL", domain as "Suspicious Domain"
| table _time, User, "Source IP", Application, Action, "Suspicious URL", "Suspicious Domain"
```

### Crowdstrike
---
```sql
event_platform=Win event_simpleName IN ("update_oauth_app") OR (Object="oauth_app" AND Action="updated") AuthorizationUrl IS NOT NULL OR TokenUrl IS NOT NULL
| eval suspicious_url=mvappend(AuthorizationUrl, TokenUrl)
| mvexpand suspicious_url
| where suspicious_url IS NOT NULL
| eval domain=extract_regex(suspicious_url, "https?://([^/:]+)")
| lookup trusted_oauth_domains.csv domain OUTPUT domain as trusted_domain
| where trusted_domain IS NULL AND domain IS NOT NULL
| project ContextTimeStamp as _time, UserName as User, SourceIp as Source_IP, AppName as Application, Action, suspicious_url as Suspicious_URL, domain as Suspicious_Domain
```

### Datadog
---
```sql
(event_name:update_oauth_app OR (object:oauth_app AND action:updated)) AND (details.authorization_url:* OR details.token_url:*)
| eval auth_url=details.authorization_url, token_url=details.token_url, suspicious_url=mvappend(auth_url, token_url)
| mvexpand suspicious_url
| where suspicious_url IS NOT NULL
| eval domain=extract(suspicious_url, "https?://([^/:]+)")
| lookup trusted_oauth_domains.csv domain OUTPUT domain as trusted_domain
| where trusted_domain IS NULL AND domain IS NOT NULL
| select timestamp as _time, user as User, src_ip as Source_IP, app as Application, action as Action, suspicious_url as Suspicious_URL, domain as Suspicious_Domain
```

### Elastic
---
```sql
FROM *
| WHERE event.action IN ("update_oauth_app") OR (event.target = "oauth_app" AND event.action = "updated")
  AND (details.authorization_url IS NOT NULL OR details.token_url IS NOT NULL)
| EVAL suspicious_url = MV_APPEND(details.authorization_url, details.token_url)
| MV_EXPAND suspicious_url
| WHERE suspicious_url IS NOT NULL
| EVAL domain = REGEXP_EXTRACT(suspicious_url, "https?://([^/:]+)")
| LOOKUP trusted_oauth_domains.csv ON domain = domain OUTPUT domain AS trusted_domain
| WHERE trusted_domain IS NULL AND domain IS NOT NULL
| KEEP @timestamp
 AS _time, user.name AS User, source.ip AS Source_IP, application.name AS Application, event.action AS Action, suspicious_url AS Suspicious_URL, domain AS Suspicious_Domain
```

### Sentinel One
---
```sql
SELECT EventTime AS _time, UserName AS User, SrcIP AS Source_IP, Application AS Application, EventName AS Action, COALESCE(AuthorizationUrl, TokenUrl) AS Suspicious_URL, REGEXP_EXTRACT(COALESCE(AuthorizationUrl, TokenUrl), 'https?://([^/:]+)') AS Suspicious_Domain
FROM events
WHERE (EventName = 'update_oauth_app' OR (Object = 'oauth_app' AND Action = 'updated'))
  AND (AuthorizationUrl IS NOT NULL OR TokenUrl IS NOT NULL)
  AND REGEXP_EXTRACT(COALESCE(AuthorizationUrl, TokenUrl), 'https?://([^/:]+)') NOT IN (SELECT domain FROM trusted_oauth_domains)
  AND REGEXP_EXTRACT(COALESCE(AuthorizationUrl, TokenUrl), 'https?://([^/:]+)') IS NOT NULL
```

### Potential Open Redirect via Unvalidated Post-Redirect Parameter
---
Author: RW

Date: 2025-08-14

Description:

Detects a potential open redirect attack where a 'post-redirect' parameter in an OAuth authorization request points to a domain not on the allowlist for that application. This pattern can arise from improperly implemented session fixation defenses.

False Positive Sensitivity: Medium. A new, legitimate post-authentication destination for an application will trigger this alert until the allowlist is updated.

Triage Steps:

    1. Examine the 'Application', 'User', and the 'PostRedirectUrl'.

    2. Determine if the domain of the 'PostRedirectUrl' is a legitimate and expected destination for users after authenticating with this application.

    3. If the domain is legitimate, add it to the 'PostRedirectDomainAllowlist' for the corresponding 'ApplicationId' to prevent future alerts.

    4. If the domain is suspicious, it indicates a potential open redirect attempt. Investigate the user's activity for signs of phishing and consider blocking the malicious domain.

### Splunk
---
```sql
-- STEP 1: Define search criteria for OAuth authorization events. Adapt the index, sourcetype, and event filters for your environment.
| search (index=* sourcetype=*) -- Specify your OAuth log sources here, e.g., index=waf or sourcetype=azure:signinlogs
    (uri_path="/oauth/authorize" OR event_name="Authorize app") -- Update with your event identifiers for OAuth authorization requests

-- STEP 2: Extract the Application ID and the post-redirect URL. The parameter name can vary (e.g., post_redirect_url, next, target). Adapt the regex as needed.
| rex field=uri "(?i)(client_id|appid)=(?<ApplicationId>[^&]+)"
| rex field=uri "(?i)(post_redirect_url|post-redirect|next|target|final_destination)=(?<PostRedirectUrl>[^&]+)"
| where isnotnull(ApplicationId) AND isnotnull(PostRedirectUrl)

-- STEP 3: Decode the post-redirect URL if it's URL-encoded and extract the domain.
| urldecode PostRedirectUrl
| rex field=PostRedirectUrl "https?:\/\/(?<PostRedirectDomain>[^\/:]+)"
| where isnotnull(PostRedirectDomain)

-- STEP 4: Use a lookup to check if the domain is allowlisted for the specific application.
-- The lookup file 'oauth_post_redirect_domain_allowlist.csv' must contain 'ApplicationId' and 'AllowedDomain' columns.
| lookup oauth_post_redirect_domain_allowlist.csv ApplicationId OUTPUT AllowedDomain

-- STEP 5: Filter for events where the post-redirect domain was NOT found in the allowlist for that application.
| where isnull(AllowedDomain)

-- STEP 6: Format the results for alerting and investigation.
| table _time, user, src_ip, ApplicationId, PostRedirectUrl, PostRedirectDomain
| rename _time as "DetectionTime", user as "User", src_ip as "Source IP", ApplicationId as "Application ID", PostRedirectUrl as "Post-Redirect URL", PostRedirectDomain as "Post-Redirect Domain"
```

### Crowdstrike
---
```sql
event_platform=Win (UriPath="/oauth/authorize" OR event_simpleName="AuthorizeApp") ClientId IS NOT NULL PostRedirectUrl IS NOT NULL
| eval ApplicationId=extract_regex(Uri, "(?i)(client_id|appid)=([^&]+)", 2), PostRedirectUrl=extract_regex(Uri, "(?i)(post_redirect_url|post-redirect|next|target|final_destination)=([^&]+)", 2)
| where ApplicationId IS NOT NULL AND PostRedirectUrl IS NOT NULL
| eval PostRedirectUrl=urldecode(PostRedirectUrl), PostRedirectDomain=extract_regex(PostRedirectUrl, "https?://([^/:]+)")
| where PostRedirectDomain IS NOT NULL
| lookup oauth_post_redirect_domain_allowlist.csv ApplicationId OUTPUT AllowedDomain
| where AllowedDomain IS NULL
| project ContextTimeStamp as DetectionTime, UserName as User, SourceIp as Source_IP, ApplicationId as Application_ID, PostRedirectUrl as Post_Redirect_URL, PostRedirectDomain as Post_Redirect_Domain
```

### Datadog
---
```sql
(uri_path:/oauth/authorize OR event_name:"Authorize app") AND client_id:* AND (post_redirect_url:* OR next:* OR target:* OR final_destination:*)
| eval ApplicationId=extract(uri, "(?i)(client_id|appid)=([^&]+)", 2), PostRedirectUrl=extract(uri, "(?i)(post_redirect_url|post-redirect|next|target|final_destination)=([^&]+)", 2)
| where ApplicationId IS NOT NULL AND PostRedirectUrl IS NOT NULL
| eval PostRedirectUrl=urldecode(PostRedirectUrl), PostRedirectDomain=extract(PostRedirectUrl, "https?://([^/:]+)")
| where PostRedirectDomain IS NOT NULL
| lookup oauth_post_redirect_domain_allowlist.csv ApplicationId OUTPUT AllowedDomain
| where AllowedDomain IS NULL
| select timestamp as DetectionTime, user as User, src_ip as Source_IP, ApplicationId as Application_ID, PostRedirectUrl as Post_Redirect_URL, PostRedirectDomain as Post_Redirect_Domain
```

### Elastic
---
```sql
FROM *
| WHERE http.request.path = "/oauth/authorize" OR event.action = "Authorize app"
  AND client.id IS NOT NULL AND (http.request.redirect_url IS NOT NULL OR http.request.next_url IS NOT NULL OR http.request.target IS NOT NULL)
| EVAL ApplicationId = REGEXP_EXTRACT(http.request.uri, "(?i)(client_id|appid)=([^&]+)", 2),
      PostRedirectUrl = REGEXP_EXTRACT(http.request.uri, "(?i)(post_redirect_url|post-redirect|next|target|final_destination)=([^&]+)", 2)
| WHERE ApplicationId IS NOT NULL AND PostRedirectUrl IS NOT NULL
| EVAL PostRedirectUrl = URLDECODE(PostRedirectUrl),
      PostRedirectDomain = REGEXP_EXTRACT(PostRedirectUrl, "https?://([^/:]+)")
| WHERE PostRedirectDomain IS NOT NULL
| LOOKUP oauth_post_redirect_domain_allowlist.csv ON ApplicationId = ApplicationId OUTPUT AllowedDomain
| WHERE AllowedDomain IS NULL
| KEEP @timestamp
 AS DetectionTime, user.name AS User, source.ip AS Source_IP, ApplicationId AS Application_ID, PostRedirectUrl AS Post_Redirect_URL, PostRedirectDomain AS Post_Redirect_Domain
```

### Sentinel One
---
```sql
SELECT EventTime AS DetectionTime, UserName AS User, SrcIP AS Source_IP, REGEXP_EXTRACT(Uri, '(?i)(client_id|appid)=([^&]+)', 2) AS Application_ID, REGEXP_EXTRACT(Uri, '(?i)(post_redirect_url|post-redirect|next|target|final_destination)=([^&]+)', 2) AS Post_Redirect_URL, REGEXP_EXTRACT(URLDECODE(REGEXP_EXTRACT(Uri, '(?i)(post_redirect_url|post-redirect|next|target|final_destination)=([^&]+)', 2)), 'https?://([^/:]+)') AS Post_Redirect_Domain
FROM events
WHERE (UriPath = '/oauth/authorize' OR EventName = 'AuthorizeApp')
  AND REGEXP_EXTRACT(Uri, '(?i)(client_id|appid)=([^&]+)', 2) IS NOT NULL
  AND REGEXP_EXTRACT(Uri, '(?i)(post_redirect_url|post-redirect|next|target|final_destination)=([^&]+)', 2) IS NOT NULL
  AND REGEXP_EXTRACT(URLDECODE(REGEXP_EXTRACT(Uri, '(?i)(post_redirect_url|post-redirect|next|target|final_destination)=([^&]+)', 2)), 'https?://([^/:]+)') IS NOT NULL
  AND REGEXP_EXTRACT(URLDECODE(REGEXP_EXTRACT(Uri, '(?i)(post_redirect_url|post-redirect|next|target|final_destination)=([^&]+)', 2)), 'https?://([^/:]+)') NOT IN (SELECT AllowedDomain FROM oauth_post_redirect_domain_allowlist WHERE ApplicationId = REGEXP_EXTRACT(Uri, '(?i)(client_id|appid)=([^&]+)', 2))
```