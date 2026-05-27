### Hunting Laundry Bear: Infrastructure Analysis and Detection Opportunities
---

Laundry Bear, also tracked as Void Blizzard, is a Russian state-sponsored APT group active since at least April 2024, primarily focused on cyber espionage against NATO countries and Ukraine. The group leverages sophisticated spear-phishing campaigns, often employing typosquatted domains and stolen credentials or session cookies for initial access, to exfiltrate sensitive data from targeted organizations.

Recent intelligence indicates Laundry Bear has evolved its initial access techniques to include targeted spear phishing for credential theft, utilizing adversary-in-the-middle (AitM) techniques with tools like Evilginx. Additionally, the group is increasingly abusing legitimate cloud services like Mailgun and Cloudflare for their infrastructure, and using privacy-preserving domain registration services, making their activities harder to trace.

### Actionable Threat Data
---

Monitor for email traffic originating from newly registered domains (especially those registered within the last 180 days) that are lookalikes of legitimate, well-known organizations or services, particularly those using privacy-preserving registration services like `onionmail.org` or `aficors.com`.

Detect attempts to access or exfiltrate data from cloud services (e.g., Exchange Online, SharePoint) using stolen credentials or session cookies, especially if originating from unusual IP addresses or locations.

Look for network connections to domains and IP addresses identified as Laundry Bear infrastructure, including `micsrosoftonline[.]com`, `ebsumrnit[.]eu`, `enticator-secure[.]com`, `walshhgroup[.]com`, `maidservant[.]shop`, and the associated IP addresses (e.g., `104.36.83[.]170`, `34.204.123[.]157`, `54.144.139[.]77`).

Identify and flag HTTP/HTTPS requests that redirect to known malicious PDF files or other suspicious executables, particularly those hosted on non-standard ports or newly observed domains.

Implement detection rules for the use of `Evilginx` or similar `AitM` phishing frameworks, which often involve specific HTML response bodies or JavaScript redirects designed to capture credentials and session tokens.

### Detects DNS queries for Laundry Bear (Void Blizzard) APT group's phishing domains
---
```sql
`comment("

Author: RW

This query detects DNS queries for domains associated with the Laundry Bear (Void Blizzard) APT group's phishing campaigns,
as identified in the referenced threat intelligence

This query is written for CIM-compliant data and is best served by an accelerated Network_Resolution data model

For performance in production environments, consider creating a lookup file with the listed domains and using that instead of the long 'where' clause.

")`

`cim_Network_Resolution`
`comment("The 'where' clause checks if the DNS query matches a known malicious domain or any of its subdomains.")`
| where
    (
        like(DNS.query, "%.aoc-gov.us") OR DNS.query="aoc-gov.us" OR
        like(DNS.query, "%.app-v4-mybos.com") OR DNS.query="app-v4-mybos.com" OR
        like(DNS.query, "%.avsgroup.au") OR DNS.query="avsgroup.au" OR
        like(DNS.query, "%.bidscale.net") OR DNS.query="bidscale.net" OR
        like(DNS.query, "%.defraudatubanco.com") OR DNS.query="defraudatubanco.com" OR
        like(DNS.query, "%.deloittesharepoint.com") OR DNS.query="deloittesharepoint.com" OR
        like(DNS.query, "%.ebsum.eu") OR DNS.query="ebsum.eu" OR
        like(DNS.query, "%.ebsumlts.eu") OR DNS.query="ebsumlts.eu" OR
        like(DNS.query, "%.ebsummlt.eu") OR DNS.query="ebsummlt.eu" OR
        like(DNS.query, "%.ebsummt.eu") OR DNS.query="ebsummt.eu" OR
        like(DNS.query, "%.ebsumrnit.eu") OR DNS.query="ebsumrnit.eu" OR
        like(DNS.query, "%.ebsurnmit.eu") OR DNS.query="ebsurnmit.eu" OR
        like(DNS.query, "%.enticator-secure.com") OR DNS.query="enticator-secure.com" OR
        like(DNS.query, "%.it-sharepoint.com") OR DNS.query="it-sharepoint.com" OR
        like(DNS.query, "%.m-365-app.com") OR DNS.query="m-365-app.com" OR
        like(DNS.query, "%.mail-forgot.com") OR DNS.query="mail-forgot.com" OR
        like(DNS.query, "%.maidservant.shop") OR DNS.query="maidservant.shop" OR
        like(DNS.query, "%.max-linear.com") OR DNS.query="max-linear.com" OR
        like(DNS.query, "%.microffice.org") OR DNS.query="microffice.org" OR
        like(DNS.query, "%.micsrosoftonline.com") OR DNS.query="micsrosoftonline.com" OR
        like(DNS.query, "%.miscrsosoft.com") OR DNS.query="miscrsosoft.com" OR
        like(DNS.query, "%.myspringbank.com") OR DNS.query="myspringbank.com" OR
        like(DNS.query, "%.ourbelovedsainscore.space") OR DNS.query="ourbelovedsainscore.space" OR
        like(DNS.query, "%.portal-microsoftonline.com") OR DNS.query="portal-microsoftonline.com" OR
        like(DNS.query, "%.propescom.com") OR DNS.query="propescom.com" OR
        like(DNS.query, "%.redronesolutions.cloud") OR DNS.query="redronesolutions.cloud" OR
        like(DNS.query, "%.refundes.net") OR DNS.query="refundes.net" OR
        like(DNS.query, "%.remerelli.com") OR DNS.query="remerelli.com" OR
        like(DNS.query, "%.spidergov.org") OR DNS.query="spidergov.org" OR
        like(DNS.query, "%.teamsupportonline.top") OR DNS.query="teamsupportonline.top" OR
        like(DNS.query, "%.weblogmail.live") OR DNS.query="weblogmail.live" OR
        like(DNS.query, "%.x9a7lm02kqaccountprotectionaccountsecuritynoreply.com") OR DNS.query="x9a7lm02kqaccountprotectionaccountsecuritynoreply.com"
    )
`comment("Group the results to show the source of the query, the queried domain, and provide a count.")`
| stats count min(_time) as firstTime max(_time) as lastTime by DNS.src, dest, DNS.query
| `ctime(firstTime)`
| `ctime(lastTime)`
| rename DNS.src as src_ip, dest as dns_server, DNS.query as suspicious_domain
| fields firstTime, lastTime, src_ip, dns_server, suspicious_domain, count
```

### Detects Evilginx-like Phishing Frameworks (Laundry Bear) via Specific HTML Redirects
---
```sql
`comment("

Author: RW

This query detects specific HTML response bodies indicative of Adversary-in-the-Middle (AitM) phishing frameworks like Evilginx,
used by the Laundry Bear (Void Blizzard) APT group. This query is designed for the Splunk Common Information Model (CIM) and
requires proxy logs, specifically the Web data model. The http_response_body field must be populated for this detection to function.

")`

| from datamodel=Web.Web
`comment("The where clause searches for the exact HTML content of two known redirect pages used by the threat actor. This provides a high-fidelity match to the phishing kit's artifacts.")`
| where
    (
        http_response_body="<html><head><meta name='referrer' content='no-referrer'><script>top.location.href='https://outlook.live.com';</script></head><body></body></html>"
        OR http_response_body="<html><head><meta name='referrer' content='no-referrer'><script>top.location.href='https://login.live.com';</script></head><body></body></html>"
    )
`comment("Group the results by key fields to identify unique sources, destinations, and users involved in the activity.")`
| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(url) as urls
    by src, dest, user, http_user_agent, http_response_body
`comment("Convert epoch timestamps to a human-readable format.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
`comment("Rename fields for better readability in the final alert output.")`
| rename
    src as src_ip,
    dest as dest_host,
    http_user_agent as user_agent,
    http_response_body as malicious_html_response
`comment("FP Note: These HTML bodies are highly specific to known phishing kits. However, it is possible that other threat actors or red teams use the same redirect code, which could lead to potential false positives.")`
```

### Detects Network Traffic to Laundry Bear (Void Blizzard) APT Group Infrastructure
---
```sql
`comment("

This query detects network traffic to IP addresses known to be part of the Laundry Bear (Void Blizzard) APT group's infrastructure. This query is designed for the Splunk Common Information Model (CIM) and is best served by an accelerated Network_Traffic data model.

")`

| from datamodel=Network_Traffic.All_Traffic
`comment("Filter for traffic where the destination IP matches one of the known malicious IPs. For better performance, consider using a lookup file for the IOCs.")`
| where dest_ip IN("34.204.123.157", "54.144.139.77", "104.36.83.170")
`comment("Group the results to show the source, destination, and count of connections, providing context for the investigation.")`
| stats count min(_time) as firstTime max(_time) as lastTime values(app) as app by src, dest, dest_port, user
`comment("Convert epoch timestamps to a human-readable format.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
`comment("Rename fields for better readability in the final alert output.")`
| rename src as source_ip, dest as destination_ip, dest_port as destination_port
`comment("FP Note: These IP addresses are highly specific to the threat actor's infrastructure. False positives may occur if these IPs are reallocated to legitimate services or sinkholed by security researchers in the future. Review the traffic patterns and application protocol for context.")`
| fields firstTime, lastTime, source_ip, destination_ip, destination_port, user, app, count
```

### Laundry Bear APT Group DNS Request Detection
---
```sql
| from datamodel=Network_Resolution.DNS
`comment("The tld(query, 2) function extracts the effective second-level domain (e.g., 'evil.com' from 'www.evil.com' or 'sub.evil.com'). This provides a more accurate and efficient match than a simple wildcard search.")`
| eval domain_lookup = tld(query, 2)

`comment("Filter for events where the extracted domain matches a known malicious domain from the inline list. Note: While convenient, using a lookup file is generally more performant and scalable for managing a large number of indicators.")`
| where domain_lookup IN (
    "micsrosoftonline.com",
    "ebsumrnit.eu",
    "enticator-secure.com",
    "walshhgroup.com",
    "maidservant.shop",
    "it-sharepoint.com",
    "ebsum.eu",
    "ebsumlts.eu",
    "ebsurnmit.eu",
    "ebsummlt.eu",
    "ebsummt.eu",
    "redronesolutions.cloud",
    "ourbelovedsainscore.space",
    "weblogmail.live",
    "microffice.org",
    "spidergov.org",
    "portal-microsoftonline.com",
    "remerelli.com",
    "myspringbank.com",
    "propescom.com",
    "defraudatubanco.com",
    "m-365-app.com",
    "max-linear.com",
    "app-v4-mybos.com",
    "miscrsosoft.com",
    "deloittesharepoint.com",
    "mail-forgot.com",
    "x9a7lm02kqaccountprotectionaccountsecuritynoreply.com",
    "teamsupportonline.top",
    "aoc-gov.us",
    "bidscale.net",
    "refundes.net",
    "avsgroup.au"
)

`comment("Aggregate the results to create a concise alert, showing which internal systems are communicating with the threat actor's infrastructure.")`
| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(query) as queries_made
    values(answer) as resolved_ips
    by src, user, domain_lookup

`comment("Convert epoch timestamps to a human-readable format for easier analysis.")`
| `ctime(firstTime)`
| `ctime(lastTime)`

`comment("Rename fields for clarity in the final alert output, making it easier for analysts to understand.")`
| rename
    src as source_ip,
    user as source_user,
    domain_lookup as matched_domain

`comment("FP Note: False positives are unlikely as the domains are specific to this threat actor. However, if a domain expires and is re-registered for benign purposes, or if it is sinkholed by a security vendor, you may see legitimate traffic from security tools or sandboxes. The 'source_ip' and 'source_user' fields can help differentiate this activity.")`
| fields firstTime, lastTime, source_ip, source_user, matched_domain, queries_made, resolved_ips, count
```

### Suspicious File Download on Non-Standard Web Ports
---
```sql
`comment("

Author: RW

This query detects the download of potentially malicious file types (e.g., PDF, executables) over non-standard web ports.
This behavior is unusual and has been associated with APT activity, such as Laundry Bear/Void Blizzard.

")`
`comment("This query is designed for the Splunk Common Information Model (CIM) and requires proxy logs mapped to the Web data model.")`
| from datamodel=Web.Web
`comment("Filter for events that are not on standard web ports.")`
| where
    NOT (dest_port IN (80, 443, 8080, 8443))
    `comment("Filter for specific file extensions commonly used in malicious downloads. The regex is case-insensitive.")`
    AND match(url, "(?i)\.(pdf|exe|dll|scr|msi|vbs|ps1)$")
`comment("Aggregate the results to create a concise alert, summarizing the activity.")`
| stats
    count
    values(action) as actions
    values(http_user_agent) as user_agents
    min(_time) as firstTime
    max(_time) as lastTime
    by src, dest, dest_port, url, user
`comment("Convert epoch timestamps to a human-readable format for easier analysis.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
`comment("Rename fields for clarity in the final alert output.")`
| rename
    src as source_ip,
    dest as destination_ip,
    dest_port as destination_port,
    url as requested_url,
    user as source_user
`comment("FP Note: This detection may trigger on legitimate applications that use custom ports for updates. If you identify benign traffic, consider excluding the specific destination_ip or destination_port in the 'where' clause to reduce noise.")`
| fields
    firstTime,
    lastTime,
    source_ip,
    source_user,
    destination_ip,
    destination_port,
    requested_url,
    actions,
    user_agents,
    count
```