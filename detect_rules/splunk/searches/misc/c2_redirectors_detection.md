### C2 Redirectors: Advanced Infrastructure for Modern Red Team Operations
---

This report summarizes the use of C2 redirectors as a critical component of modern red team operations, detailing various types of redirectors (HTTP/HTTPS, DNS, SMTP, Socat) and advanced evasion techniques. The primary goal of C2 redirectors is to obscure the actual C2 server, making it significantly harder for blue teams to detect and block command and control traffic.

Recent advancements in C2 redirector techniques emphasize sophisticated traffic shaping and timing to mimic legitimate user behavior, alongside dynamic IP rotation and robust TLS certificate management, making detection more challenging than traditional static C2 infrastructure. The article also highlights the increasing difficulty of domain fronting due to CDN policy changes, pushing red teams towards more nuanced protocol encapsulation and DGA strategies.

### Actionable Threat Data
---

Unusual User-Agent Strings:

Monitor for `User-Agent strings` that do not conform to standard browser or operating system patterns, especially those observed in `Nginx or Apache access logs` from C2 redirectors.

Suspicious HTTP/HTTPS Traffic Patterns:

Look for HTTP/HTTPS requests with unusual `Content-Type` headers (e.g., `application/octet-stream` for non-file downloads), or Host headers that do not align with the SNI in TLS handshakes, indicative of domain fronting attempts.

Anomalous DNS Queries:

Detect DNS queries for highly random or algorithmically generated subdomains (DGA patterns) or an unusually high volume of DNS TXT record queries, which could indicate DNS tunneling for C2 communication or data exfiltration.

Non-Standard Protocol Usage on Common Ports:

Identify non-HTTP/HTTPS traffic on ports 80/443, or unexpected protocols on other common ports (e.g., SMTP traffic on non-standard ports, or ICMP tunneling), as this may indicate Socat or custom protocol encapsulation.

Rapid IP Address Changes for a Given Domain:

Monitor for frequent and rapid changes in the IP address resolution for a specific domain, especially if the domain is associated with suspicious activity, which could indicate automated IP rotation strategies used by threat actors.

### C2 Redirector with Unusual User-Agent
---
```sql
(sourcetype=nginx*access OR sourcetype=apache_access OR sourcetype=iis) http_user_agent!="-" http_user_agent!=""
# FP Mitigation: Filter out common legitimate User-Agents. This list should be customized for your environment to reduce noise from legitimate but less common applications or scripts.
| search NOT ( http_user_agent IN ("Mozilla/*", "Opera/*", "curl/*", "Wget/*", "Python-urllib/*", "Go-http-client/*", "Java/*") OR http_user_agent LIKE "%bot%" OR http_user_agent LIKE "%spider%" OR http_user_agent LIKE "%crawler%" OR http_user_agent LIKE "%scanner%" )
# Count the occurrences of each User-Agent to identify rare ones.
| stats count by http_user_agent, src, dest
| eventstats sum(count) as ua_total_count by http_user_agent
# The threshold (ua_total_count < 10) can be adjusted. A lower value is more sensitive but may increase FPs. A higher value may miss stealthier activity.
| where ua_total_count < 10
# Group the results for alerting, showing the rare User-Agent and associated IPs.
| stats values(src) as src_ips, values(dest) as dest_ips, sum(count) as event_count by http_user_agent, ua_total_count
| rename http_user_agent as "Unusual_User_Agent", ua_total_count as "Total_Count_In_Timeframe", src_ips as "Source_IPs", dest_ips as "Destination_IPs", event_count as "Connection_Count"
```

### Suspicious HTTP/HTTPS Traffic for C2
---
```sql
# Base search for Zeek SSL and HTTP logs. This logic requires both data sources.
(sourcetype=zeek:ssl OR sourcetype=zeek:http)
# Correlate SSL and HTTP events by their unique ID (uid).
| stats values(sourcetype) as sourcetypes, values(host) as http_host, values(server_name) as sni, values(method) as http_method, values(uri) as uri, values(orig_filenames) as filenames, values(resp_mime_types) as content_type by uid, id.orig_h, id.resp_h, id.resp_p
# --- Detection Logic ---
| where ( \
    # Pattern 1: Detects suspicious content-types like application/octet-stream, often used to exfiltrate binary data over HTTP.
    # We filter out common file extensions and transfers with explicit filenames to reduce FPs.
    (mvfind(content_type, "application/octet-stream") AND NOT (match(uri, "\.(exe|zip|rar|dll|msi|iso|pkg|dmg)$") OR isnotnull(filenames))) \
    OR \
    # Pattern 2: Detects domain fronting where the inner HTTP Host header does not match the outer TLS SNI.
    # The check `NOT like(http_host, "%." + sni)` allows for subdomains (e.g., host=a.b.com, sni=b.com), reducing FPs.
    (mvcount(sourcetypes) > 1 AND isnotnull(http_host) AND isnotnull(sni) AND http_host!=sni AND NOT like(http_host, "%." + sni)) \
)
# --- False Positive Tuning ---
# The following search filters out common CDN providers that legitimately use domain fronting.
# This list should be customized for your environment by adding known legitimate domains or creating a lookup.
| search NOT (sni IN ("*.google.com", "*.akamaiedge.net", "*.amazonaws.com", "*.azureedge.net", "*.cloudflare.net", "*.fastly.net", "*.cloudfront.net") OR http_host IN ("*.google.com", "*.akamaiedge.net", "*.amazonaws.com", "*.azureedge.net", "*.cloudflare.net", "*.fastly.net", "*.cloudfront.net"))
# --- Final Output ---
| rename id.orig_h as src, id.resp_h as dest, id.resp_p as dest_port, http_host as http_host_header, sni as tls_sni
| table _time, src, dest, dest_port, http_host_header, tls_sni, content_type, uri, http_method
```

### Anomalous DNS Queries for C2
---
```sql
# This search requires DNS query logs. Adjust the index and sourcetype for your environment.
(index=* sourcetype=stream:dns) OR (tag=dns) query!="localhost"
# --- Feature Engineering ---
# Calculate query length and the ratio of numeric characters, common DGA indicators.
| eval query_len = len(query)
| eval numeric_chars = replace(query, "[^0-9]", "")
| eval numeric_ratio = len(numeric_chars) / query_len

# --- Detection Logic & Aggregation ---
# Group by source and the queried domain to spot suspicious patterns from a single client.
| stats count, dc(query) as distinct_queries, values(query) as sample_queries, values(query_type) as query_types, avg(query_len) as avg_query_len, max(numeric_ratio) as max_numeric_ratio, count(eval(query_type="TXT")) as txt_query_count by src, domain

# --- Thresholding and Filtering ---
# Apply thresholds to identify anomalous behavior. These may need tuning for your environment.
| where ( \
    /* Pattern 1: DGA-like behavior. Looks for a high number of unique, long, and random-looking queries from one source to a single domain. */ \
    (distinct_queries > 15 AND avg_query_len > 20 AND max_numeric_ratio > 0.2) \
    OR \
    /* Pattern 2: DNS Tunneling via TXT records. Looks for a high volume of TXT queries from one source to a single domain. */ \
    (txt_query_count > 10 AND distinct_queries > 5) \
)

# --- False Positive Tuning ---
# Exclude common cloud services or other legitimate services that may exhibit similar patterns.
# This list should be customized. Consider using a lookup for better performance.
| search NOT (domain IN ("*.amazonaws.com", "*.google.com", "*.microsoft.com", "*.icloud.com", "*.akamai.net"))

# --- Final Output ---
| rename src as src_ip, domain as target_domain, count as total_queries, distinct_queries as distinct_query_count, txt_query_count as total_txt_queries
| table _time, src_ip, target_domain, total_queries, distinct_query_count, total_txt_queries, avg_query_len, max_numeric_ratio, sample_queries
```

### Non-Standard Protocol Usage for C2
---
```sql
# Datasources: Network traffic logs (e.g., Zeek, Palo Alto, firewalls) mapped to the CIM.

# This search uses the `append` command to combine results from two different detection methods.
# --- Part 1: Protocol-Port Mismatch Detection ---
(tag=network tag=communicate)
# Filter for either standard services on non-standard ports OR non-standard services on web ports.
| where ((app="dns" AND dest_port!=53) OR (app="smtp" AND dest_port NOT IN (25, 465, 587))) OR (dest_port IN (80, 443) AND NOT app IN ("http", "ssl", "https", "quic", "http-proxy", "unknown", "bittorrent"))
# Add a reason for why the event is suspicious.
| eval reason = case(dest_port IN (80, 443), "Non-Standard Protocol on Web Port", app="dns", "DNS on Non-Standard Port", app="smtp", "SMTP on Non-Standard Port", 1=1, "Unknown Anomaly")
| eval signature = app
# Select fields for the final table.
| table _time, src, dest, dest_port, transport, signature, reason

# --- Part 2: ICMP Tunneling Detection ---
| append [
    search (tag=network tag=communicate) transport="icmp"
    # Aggregate ICMP traffic between hosts to find high-volume communication.
    | stats sum(bytes) as total_bytes, dc(icmp_type) as distinct_icmp_types, count as pkt_count by _time, src, dest, transport
    # Thresholds for ICMP tunneling. Normal pings are small and infrequent.
    # Tune these values based on your environments baseline.
    | where pkt_count > 100 AND total_bytes > 20480
    | eval reason = "Potential ICMP Tunneling"
    | eval signature = "High Volume ICMP (" + tostring(total_bytes) + " bytes, " + tostring(pkt_count) + " packets)"
    # Select fields for the final table.
    | table _time, src, dest, transport, signature, reason
]

# --- False Positive Tuning ---
# Exclude known network scanners, monitoring tools, or other legitimate sources of unusual traffic.
# Consider creating a lookup file of approved applications and ports for better performance and management.
| search NOT (src IN ("10.0.0.0/8", "127.0.0.1") OR dest IN ("224.0.0.0/4", "255.255.255.255"))

# --- Final Output ---
| fillnull value="N/A" dest_port
| rename src as source_ip, dest as destination_ip, dest_port as destination_port
| table _time, source_ip, destination_ip, destination_port, transport, signature, reason
```

### Rapid IP Address Changes for a Domain
---
```sql
# Datasources: DNS logs mapped to the CIM Network_Resolution data model.

# Use tstats for performance to search DNS data over the last 24 hours.
# This requires the Network_Resolution data model to be populated.
| tstats `summariesonly` allow_old_summaries=true values(DNS.answers) as answers from datamodel=Network_Resolution where nodename="DNS" AND DNS.qtype IN ("A", "AAAA") by _time, DNS.query span=1h
| `drop_dm_object_name("DNS")`

# Aggregate results over the full time range for each domain.
| mvexpand answers
# Filter out non-IP answers and private IPs, focusing on external infrastructure.
| where isnotnull(answers) AND NOT (match(answers, "^10\.") OR match(answers, "^172\.(1[6-9]|2[0-9]|3[0-1])\.") OR match(answers, "^192\.168\.") OR match(answers, "^127\.0\.0\.1"))
| stats dc(answers) as distinct_ip_count, values(answers) as resolved_ips by query

# Set the threshold for the number of distinct IPs.
# This value may need to be tuned. A lower value increases sensitivity but may also increase FPs from legitimate services.
| where distinct_ip_count > 3

# --- False Positive Tuning ---
# Exclude domains associated with major CDNs and cloud providers that legitimately use IP rotation.
# For production environments, this should be converted to a lookup for better management and performance.
| search NOT (query IN ("*.google.com", "*.googleapis.com", "*.microsoft.com", "*.windowsupdate.com", "*.apple.com", "*.icloud.com", "*.amazonaws.com", "*.cloudfront.net", "*.akamaitechnologies.com", "*.akamai.net", "*.cloudflare.com", "*.fastly.net", "*.office365.com"))

# --- Final Output ---
| rename query as domain
| table domain, distinct_ip_count, resolved_ips
```