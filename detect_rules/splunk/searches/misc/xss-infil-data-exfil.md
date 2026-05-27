### XSS to Account Takeover and Data Exfiltration Report
---

This report details how a reflected Cross-Site Scripting (XSS) vulnerability can be escalated to achieve full account takeover and sensitive data exfiltration. The attack chain leverages XSS to perform session riding, bypassing HttpOnly cookie protections and anti-CSRF tokens by dynamically fetching and manipulating legitimate application forms.

Recent intelligence indicates that XSS vulnerabilities, particularly persistent (stored) XSS, continue to be a significant threat, often leading to account takeover and data breaches, with new CVEs being reported in 2024 and 2025. Attackers are increasingly chaining XSS with other vulnerabilities like CSRF bypasses and misconfigured OAuth flows to achieve greater impact and bypass modern security controls.

### Actionable Threat Data
---

Monitor for web requests containing script tags or common XSS payloads in URL parameters or HTTP request bodies, especially in unexpected or unlinked endpoints.

Detect unusual outbound HTTP/DNS requests from client-side JavaScript to external domains (e.g., Burp Collaborator, oastify.com, or attacker-controlled servers) which may indicate data exfiltration attempts.

Look for rapid, automated sequences of web requests from a single user session that involve fetching a page, extracting form data (including CSRF tokens or VIEWSTATE), modifying specific fields (like email addresses), and resubmitting the form.

Identify instances where JavaScript dynamically creates and appends new script elements to the DOM, particularly if the src attribute points to an external, untrusted domain.

Alert on successful email address changes or password reset requests for user accounts that originate from suspicious or previously unseen IP addresses or user agents, especially if not accompanied by multi-factor authentication.

### Potential XSS Payload in URL or Request Body
---
```sql
-- This query assumes a CIM-compliant datamodel or a macro `weblogs` that includes web proxy, web server, or WAF logs.
-- Example sourcetypes: sourcetype=iis, sourcetype=apache:access, sourcetype=stream:http, sourcetype=pan:traffic, sourcetype=aws:waf
`weblogs`
-- Combine URL and request body fields and decode them to find encoded payloads.
| eval combined_request_data = coalesce(url, uri, "") + " " + coalesce(form_data, http_request_body, "")
| eval decoded_request = urldecode(combined_request_data)
-- Search for common XSS keywords and patterns. The list is not exhaustive.
| where (
    like(decoded_request, "%<script%") OR
    like(decoded_request, "%script>%") OR
    like(decoded_request, "%javascript:%") OR
    like(decoded_request, "%onload=%") OR
    like(decoded_request, "%onerror=%") OR
    like(decoded_request, "%onmouseover=%") OR
    like(decoded_request, "%onclick=%") OR
    like(decoded_request, "%alert(%") OR
    like(decoded_request, "%prompt(%") OR
    like(decoded_request, "%confirm(%") OR
    like(decoded_request, "%eval(%") OR
    like(decoded_request, "%String.fromCharCode(%") OR
    like(decoded_request, "%btoa(%") OR
    like(decoded_request, "%document.cookie%") OR
    like(decoded_request, "%document.write(%") OR
    like(decoded_request, "%\"<>%") OR
    like(decoded_request, "%src=x%") OR
    like(decoded_request, "%addEventListener(%")
)
-- Identify which keyword triggered the detection for easier analysis.
| eval matched_payload = case(
    like(decoded_request, "%<script%"), "<script",
    like(decoded_request, "%script>%"), "script>",
    like(decoded_request, "%javascript:%"), "javascript:",
    like(decoded_request, "%onload=%"), "onload=",
    like(decoded_request, "%onerror=%"), "onerror=",
    like(decoded_request, "%onmouseover=%"), "onmouseover=",
    like(decoded_request, "%onclick=%"), "onclick=",
    like(decoded_request, "%alert(%"), "alert(",
    like(decoded_request, "%prompt(%"), "prompt(",
    like(decoded_request, "%confirm(%"), "confirm(",
    like(decoded_request, "%eval(%"), "eval(",
    like(decoded_request, "%String.fromCharCode(%"), "String.fromCharCode(",
    like(decoded_request, "%btoa(%"), "btoa(",
    like(decoded_request, "%document.cookie%"), "document.cookie",
    like(decoded_request, "%document.write(%"), "document.write(",
    like(decoded_request, "%\"<>%"), "\"><",
    like(decoded_request, "%src=x%"), "src=x",
    like(decoded_request, "%addEventListener(%"), "addEventListener("
)
-- Aggregate results to provide a summary of suspicious activity.
| stats count, values(matched_payload) as matched_payloads, values(url) as urls by src, dest, user_agent
| rename src as src_ip, dest as dest_ip, user_agent as http_user_agent
-- Placeholder for filtering known false positives, such as vulnerability scanners or specific applications.
-- | where NOT (match(http_user_agent, "(?i)nessus|qualys|acunetix") OR src_ip IN ("10.0.0.1", "192.168.1.1"))
```

### Potential Data Exfiltration via Client-Side Request
---
```sql
-- This query is best run against CIM-compliant web proxy, WAF, or web server logs.
-- For performance, it uses tstats. If you do not have the Web datamodel populated, replace the tstats command with ` `weblogs` | rename http_user_agent as user_agent `
| tstats `summariesonly` count from datamodel=Web where (nodename=Web.Proxy OR nodename=Web.Web) by _time, Web.src, Web.dest, Web.http_user_agent, Web.url, Web.referer
| `drop_dm_object_name("Web")`

-- Extract hostnames from the referer and destination URL.
| rex field=referer "^https?://(?<referer_host>[^/:]+)"
| rex field=url "^https?://(?<dest_host>[^/:]+)"
| where isnotnull(referer_host) AND isnotnull(dest_host)

-- Key logic: Filter for requests where the referer is an internal domain and the destination is external.
-- You MUST customize the following line with your organization's domains.
| where match(referer_host, "(?i)your_company_domain\.com$|your_other_app\.io$") AND NOT match(dest_host, "(?i)your_company_domain\.com$|your_other_app\.io$")

-- Placeholder for allowlisting known good external services to reduce false positives.
-- | where NOT match(dest_host, "(?i)google-analytics\.com$|salesforce\.com$|some_other_partner\.com$")

-- Identify suspicious exfiltration patterns based on the destination or URL structure.
| eval exfil_reason = case(
    match(dest_host, "(?i)\.oastify\.com$|\.burpcollaborator\.net$|\.interact\.sh$|\.requestbin\.net$"), "Known Interaction/Exfil Domain",
    rex(url, "(?i)[\?&](data|payload|html|content|b64|dom)=([A-Za-z0-9+\/_\-]{100,})"), "Long Encoded Data in URL Parameter",
    len(url) > 1024, "Unusually Long URL"
)
| where isnotnull(exfil_reason)

-- Aggregate and format the results for analysis.
| stats count, values(url) as exfil_urls, values(exfil_reason) as reasons by _time, src, dest, user_agent, referer_host, dest_host
| rename src as src_ip, dest as dest_ip, user_agent as http_user_agent
```

### Potential Automated Form Resubmission for Account Takeover
---
```sql
-- This query is best run against CIM-compliant web proxy, WAF, or web server logs.
-- For performance, it uses tstats. If you do not have the Web datamodel populated, replace the tstats command with ` `weblogs` `.
| tstats `summariesonly` values(Web.http_method) as http_method, values(Web.status) as status from datamodel=Web where (nodename=Web.Proxy OR nodename=Web.Web) by _time, Web.src, Web.user, Web.url
| `drop_dm_object_name("Web")`

-- Key Logic: Filter for sensitive account management pages that an attacker would target.
-- You MUST customize this list with your application's actual endpoints for profile changes, email updates, etc.
| where match(url, "(?i)/Account|/profile|/settings|/user/update|/change_password|/reset_email")

-- Filter for successful GET (fetch) and POST (submit) requests. A POST may result in a 200 (OK) or 302 (Redirect).
| where (http_method="GET" AND status=200) OR (http_method="POST" AND status IN (200, 302))

-- Group events into a single transaction if they come from the same source, for the same user and URL, within 1 minute.
-- The transaction must start with a GET and end with a POST, which mimics the "fetch and submit" attack pattern.
| transaction src, user, url startswith=(http_method="GET") endswith=(http_method="POST") maxspan=1m

-- A valid automated attack sequence will have at least two events (the GET and the POST).
| where eventcount >= 2

-- The core detection logic: A script can fetch and resubmit a form in seconds. A human cannot.
-- Adjust this threshold based on your application's complexity and expected user behavior.
| where duration < 5

-- Format the output for analysis.
| table _time, src, user, url, duration, eventcount
| rename src as src_ip, user as user_name, url as target_url, duration as time_between_get_and_post_sec, eventcount as steps_in_sequence
```

### Dynamic Loading of External JavaScript
---
```sql
-- This query is best run against CIM-compliant web proxy logs.
-- For performance, it uses tstats. If you do not have the Web datamodel populated, replace the tstats command with ` `weblogs` `.
| tstats `summariesonly` count from datamodel=Web where (nodename=Web.Proxy OR nodename=Web.Web) by _time, Web.src, Web.dest, Web.http_user_agent, Web.url, Web.referer
| `drop_dm_object_name("Web")`

-- Key Logic: Filter for requests to download JavaScript files.
| where match(url, "(?i)\.js$")

-- Extract the hostname from the referer and destination URL to determine origin and destination.
| rex field=referer "^https?://(?<referer_host>[^/:]+)"
| rex field=url "^https?://(?<dest_host>[^/:]+)"
| where isnotnull(referer_host) AND isnotnull(dest_host)

-- Filter for requests where the referer is an internal domain and the destination is external.
-- You MUST customize the following line with your organization's domains.
| where match(referer_host, "(?i)your_company_domain\.com$|your_other_app\.io$") AND NOT match(dest_host, "(?i)your_company_domain\.com$|your_other_app\.io$")

-- False Positive Tuning: Maintain an allowlist of known-good external domains that are authorized to serve scripts to your application.
-- This is critical to reducing noise from legitimate third-party services.
| where NOT match(dest_host, "(?i)google-analytics\.com$|googletagmanager\.com$|cdn\.jsdelivr\.net$|code\.jquery\.com$|some_ad_network\.com$|your_support_widget\.io$")

-- Aggregate results to show which internal pages are loading which external scripts.
| stats count, values(url) as external_script_urls by _time, src, referer, dest_host, http_user_agent
| rename src as src_ip, referer as source_page_url, dest_host as external_script_host
```

### Suspicious Email or Password Change from New Source
---
```sql
-- This detection requires a baseline of known user and source IP combinations.
-- Create and regularly update a lookup file named `user_source_baseline.csv` with a scheduled search like this:
-- `| tstats `summariesonly` earliest(_time) as firstTime, latest(_time) as lastTime from datamodel=Authentication where Authentication.action=success by Authentication.user, Authentication.src | outputlookup user_source_baseline.csv`

-- Step 1: Identify successful email or password change events from your application or web server logs.
-- You MUST customize this search to match the logs for your specific application.
`weblogs` OR `applogs`
| where (
    (match(message, "(?i)email address (updated|changed)") AND match(message, "(?i)success")) OR
    (match(message, "(?i)password (changed|reset)") AND match(message, "(?i)success")) OR
    (match(url, "(?i)/Account.aspx|/api/user/profile|/settings/security") AND http_method="POST" AND (status=200 OR status=302))
)

-- Step 2: Extract relevant fields. Field names (user, src) may need to be adjusted for your data.
| rename user as user, src as src_ip, http_user_agent as user_agent

-- Step 3: Use the baseline lookup to check if this user/IP combination has been seen before.
| lookup user_source_baseline.csv user AS user, src_ip AS src_ip OUTPUT user as found_user

-- Step 4: The core detection logic. Alert if the user/IP pair was NOT found in the baseline.
| where isnull(found_user)

-- (Optional) Further reduce false positives by checking if MFA was used for the session.
-- This requires logs that correlate MFA status with user sessions and may require a subsearch.
-- | search NOT [| search `mfa_logs` mfa_status=success | fields mfa_user]

-- Step 5: Aggregate and format the results for alerting.
| stats count, earliest(_time) as first_seen, latest(_time) as last_seen, values(url) as urls, values(message) as messages by user, src_ip, user_agent
| `ctime(first_seen)`
| `ctime(last_seen)`
| rename user as suspicious_user, src_ip as new_source_ip, user_agent as source_user_agent
```