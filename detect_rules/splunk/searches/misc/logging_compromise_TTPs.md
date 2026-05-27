### Hunting for Secrets in Plain Sight: Leveraging Internal Logging and Monitoring Services
---

This report details how adversaries can exploit misconfigured internal logging and monitoring platforms (like Kibana, Datadog, and Sumo Logic) to discover sensitive credentials and escalate privileges, ultimately leading to domain compromise. The core threat lies in the inadvertent logging of secrets by legitimate users, which attackers can then leverage for "living off the land" attacks with a low detection footprint.

Recent intelligence highlights a continued trend of threat actors leveraging legitimate credentials and "living off the land" techniques, making the exploitation of inadvertently logged secrets a persistent and evolving threat. Notably, the use of "shadow credentials" and DCSync attacks for privilege escalation remains a significant concern, with recent reports detailing their continued use in sophisticated attack chains.

### Actionable Threat Data

Monitor for unauthenticated access attempts to logging and monitoring platforms (e.g., Kibana, Datadog, Sumo Logic) from internal or external networks.

Implement robust log scrubbing and secret scanning solutions to prevent sensitive information (e.g., API keys, plaintext credentials, access tokens) from being stored in logs.

Detect suspicious search queries within logging platforms that indicate attempts to find credentials or sensitive data (e.g., "password", "secret", "api_key", "token", "connection string").

Monitor for the creation or modification of service accounts and their associated permissions, especially those with "Replicating Directory Changes" or "GenericAll" rights, which can be abused for DCSync attacks.

Alert on anomalous Kerberos authentication ticket (TGT) requests, particularly those with non-blank "Certificate Information" attributes, which could indicate a "shadow credentials" attack.

### Unauthenticated Access to Logging Platforms
---
```sql
`comment("Define regex patterns for logging platform hostnames and URLs. Tune these to match your environment.")`
`define_macro(platform_host_regex, `"(?i)(kibana|elastic|logs|logging|monitoring|observ|datadog|ddog|sumo|splunk|spl|graylog|wazuh)"`)`
`define_macro(platform_url_regex, `"(?i)\/((app|s|p)\/(kibana|discover|dashboards?)|logs|apm|metrics|explorer|dashboards)"`)`

`define_macro(unauthenticated_user_patterns,`
    `user="-"` OR \
    `user=""` OR \
    `user="anonymous"` OR \
    `isnull(user)`
`)`

`comment("Primary detection logic using the CIM Web datamodel for efficiency.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.status=200 by Web.url, Web.src, Web.dest, Web.user
| `drop_dm_object_name("Web")`

`comment("Uncomment the following section and comment out the tstats search above if you do not use the Web datamodel.")`
`comment("
(index=* sourcetype IN (pan:traffic, zscaler:nss:web, stream:http)) status=200
| fields _time, url, src, dest, user
")`

`comment("Filter for requests to hosts or URLs matching common logging platform naming conventions.")`
| where match(dest, `platform_host_regex`) OR match(url, `platform_url_regex`)

`comment("Filter out common noise like static content and health checks. This may need tuning.")`
| where NOT match(url, "(?i)\.(css|js|png|gif|jpg|ico|svg|woff)$|/api/status|/status$")

`comment("Core logic: Identify requests where the user field indicates unauthenticated access.")`
| where `unauthenticated_user_patterns`

`comment("Group results to create a single alert per source and destination.")`
| stats earliest(firstTime) as firstTime, latest(lastTime) as lastTime, sum(count) as event_count, values(url) as accessed_urls by src, dest, user
| rename src as src_ip, dest as dest_host

`comment("Provide a clear title and description for the alert.")`
| eval rule_title="Unauthenticated Access to Logging Platform Detected", rule_description="Successful unauthenticated access was detected from " + src_ip + " to the logging platform at " + dest_host + ". The user was identified as '" + user + "'. Accessed URLs include: " + mvjoin(accessed_urls, ", ")
| table firstTime, lastTime, src_ip, dest_host, user, event_count, accessed_urls, rule_title, rule_description
```

### Sensitive Data Discovered in Logs
---
```sql
`comment("Define keywords and regex patterns for sensitive data. Tune these for your environment.")`
`define_macro(secret_keywords, `"password" OR "passwd" OR "pwd" OR "credential" OR "secret" OR "api_key" OR "apikey" OR "api-key" OR "client_secret" OR "access_key" OR "accesskey" OR "access-token" OR "accesstoken" OR "auth_token" OR "authtoken" OR "bearer" OR "authorization" OR "connectionstring" OR "connection_string" OR "jdbc:"`)`
`define_macro(secret_regex, `match(_raw, "(?i)ghp_[0-9a-zA-Z]{36}|AKIA[0-9A-Z]{16}|xox[pboa]-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}")`)`

`comment("IMPORTANT: Scope this search to relevant indexes (e.g., index=apps) to improve performance.")`
(index=*)
| where `secret_keywords` OR `secret_regex`

`comment("Optional: Filter out common non-sensitive events. Uncomment and tune as needed.")`
`comment("| where NOT match(_raw, \"(?i)invalid|failed|expired|revoked|session\")")`

`comment("Group similar findings to reduce alert volume.")`
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime, values(_raw) as sample_events by host, sourcetype, source
| rename source as log_source

`comment("Format the output for alerting.")`
| eval rule_title="Sensitive Data Discovered in Logs", rule_description="Potential secrets or credentials were found in logs from host: " + host + " and sourcetype: " + sourcetype + ". Review the sample events to determine if sensitive data was exposed."
| table firstTime, lastTime, host, sourcetype, log_source, count, sample_events, rule_title, rule_description
```

### Suspicious Log Queries for Sensitive Data
---
```sql
`comment("Define a regex of keywords used to find secrets. Tune based on your environment's data.")`
`define_macro(suspicious_query_pattern, `"(?i)password|passwd|pwd|credential|secret|api_key|apikey|api-key|client_secret|access_key|accesskey|access-token|accesstoken|auth_token|authtoken|bearer|authorization|connectionstring|connection_string|jdbc:|ghp_[0-9a-zA-Z]{36}|AKIA[0-9A-Z]{16}|xox[pboa]"` )`

`comment("IMPORTANT: Whitelist your security team members and service accounts to avoid false positives.")`
`define_macro(security_team_users, `user IN ("sec_analyst_1", "threat_hunter_2", "soc_service_account")` )`

`comment("Search the audit logs of your logging platform for search activity.")`
`comment("This example uses Splunk's _audit index. Adapt the index and fields for other platforms.")`
index=_audit action=search info=granted
| rename search as query

`comment("Filter out searches performed by whitelisted security team members and system accounts.")`
| where NOT (`security_team_users` OR user="splunk-system-user")

`comment("Filter out scheduled searches, which are often legitimate and repetitive.")`
| where NOT search_id LIKE "scheduler_%"

`comment("Apply the core detection logic to find suspicious keywords in the search query.")`
| where match(query, `suspicious_query_pattern`)

`comment("Group similar events to reduce alert volume.")`
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime, values(query) as suspicious_queries by user, clientip
| rename clientip as src_ip

`comment("Format the output for alerting.")`
| eval rule_title="Suspicious Query for Sensitive Data Detected", rule_description="User '" + user + "' from IP " + src_ip + " searched for sensitive data patterns. This may be an attempt to find exposed credentials in logs. Review the suspicious queries."
| table firstTime, lastTime, user, src_ip, count, suspicious_queries, rule_title, rule_description
```

### High-Privilege Active Directory Permission Granted
---
```sql
`comment("Search for Directory Service object modifications, which log changes to AD permissions.")`
sourcetype="WinEventLog:Directory-Service-Changes" EventCode=5136 AttributeLDAPDisplayName=nTSecurityDescriptor

`comment("Filter for ACE strings that grant DCSync or GenericAll permissions. The GUIDs correspond to 'Replicating Directory Changes'.")`
| where (like(AttributeValue, "%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%") OR like(AttributeValue, "%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%") OR like(AttributeValue, "%(A;;GA;;;%"))

`comment("Extract the SID of the account that was granted the permission from the ACE string.")`
| rex field=AttributeValue ";;(?<granted_sid>S-1-5-[^)]+)"

`comment("Identify the specific permission granted for better alert context.")`
| eval granted_permission=case(
    like(AttributeValue, "%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%"), "Replicating Directory Changes",
    like(AttributeValue, "%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%"), "Replicating Directory Changes All",
    like(AttributeValue, "%(A;;GA;;;%"), "GenericAll",
    1=1, "Unknown High-Privilege"
)

`comment("Enrich the SID with a username. This requires a populated asset and identity framework (e.g., from the Splunk App for Windows Infrastructure).")`
| lookup identity_lookup_expanded objectSid as granted_sid OUTPUT identity as granted_user
| lookup identity_lookup_expanded objectSid as SubjectSID OUTPUT identity as SubjectUser

`comment("Aggregate results to reduce alert volume.")`
| stats count, values(granted_permission) as permissions, earliest(_time) as firstTime, latest(_time) as lastTime by dest, SubjectUser, granted_user, granted_sid, ObjectDN
| rename dest as dvc

`comment("Format the output for alerting.")`
| eval rule_title="High-Privilege AD Permission Granted", rule_description=SubjectUser + " granted '" + granted_user + "' the following permission(s): " + mvjoin(permissions, ", ") + " on the object '" + ObjectDN + "'. This is a critical permission that can be abused for privilege escalation."
| table firstTime, lastTime, dvc, SubjectUser, granted_user, permissions, ObjectDN, rule_title, rule_description
```

### Potential Shadow Credentials Attack
---
```sql
`comment("Filter for Kerberos TGT requests (EventCode 4768) from Domain Controllers.")`
sourcetype="WinEventLog:Security" EventCode=4768

`comment("Filter for events where certificate information is present, indicating PKINIT authentication.")`
| where Certificate_Issuer_Name!="" AND Certificate_Issuer_Name!="-" AND isnotnull(Certificate_Issuer_Name)

`comment("MEDIUM SENSITIVITY: Filter out machine account authentications, which commonly use certificates. Remove this line for higher sensitivity to detect attacks targeting computer accounts.")`
| where NOT like(Account_Name, "%$")

`comment("MEDIUM SENSITIVITY: Consider creating a lookup of legitimate certificate users (e.g., smart card, WHfB users) and filtering them out to reduce noise.")`
`comment("| lookup legitimate_cert_users_lookup user as Account_Name OUTPUT is_legit | where isnull(is_legit)")`

`comment("Aggregate events to create a single alert per user, source, and certificate.")`
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime by dest, Account_Name, Client_Address, Certificate_Issuer_Name, Certificate_Serial_Number
| rename dest as dvc, Account_Name as user, Client_Address as src_ip

`comment("Format the output for alerting.")`
| eval rule_title="Potential Shadow Credentials Attack Detected", rule_description="A Kerberos TGT was requested for user '" + user + "' using a certificate issued by '" + Certificate_Issuer_Name + "'. This activity originated from " + src_ip + ". This could be a Shadow Credentials attack where an attacker uses a forged certificate to impersonate the user."
| table firstTime, lastTime, dvc, user, src_ip, Certificate_Issuer_Name, Certificate_Serial_Number, count, rule_title, rule_description
```