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
source:(nginx* apache_access iis) http.user_agent:*-* -http.user_agent:(Mozilla/* Opera/* curl/* Wget/* Python-urllib/* Go-http-client/* Java/* *bot* *spider* *crawler* *scanner*)
| groupby http.user_agent, src.ip, dest.ip count as event_count
| filter total_count < 10
| groupby http.user_agent values(src.ip) as Source_IPs, values(dest.ip) as Destination_IPs, sum(event_count) as Connection_Count, total_count as Total_Count_In_Timeframe
```

### Suspicious HTTP/HTTPS Traffic for C2
---
```sql
source:(zeek:ssl zeek:http) -(tls.sni:(*.google.com *.akamaiedge.net *.amazonaws.com *.azureedge.net *.cloudflare.net *.fastly.net *.cloudfront.net) OR http.host:(*.google.com *.akamaiedge.net *.amazonaws.com *.azureedge.net *.cloudflare.net *.fastly.net *.cloudfront.net)) (content_type:application/octet-stream -(uri:*\.(exe|zip|rar|dll|msi|iso|pkg|dmg)$ OR filenames:*-*) OR (sourcetype:zeek:ssl sourcetype:zeek:http http.host:*-* tls.sni:*-* http.host!=tls.sni -http.host:*.*tls.sni))
| groupby uid, src.ip, dest.ip, dest.port values(sourcetype) as sourcetypes, values(http.host) as http_host_header, values(tls.sni) as tls_sni, values(http.method) as http_method, values(uri) as uri, values(content_type) as content_type
```

### Anomalous DNS Queries for C2
---
```sql
source:(stream:dns) OR tag:dns -query:localhost
| eval query_len=len(query), numeric_chars=replace(query, "[^0-9]", ""), numeric_ratio=len(numeric_chars)/query_len
| groupby src.ip, domain count as total_queries, dc(query) as distinct_query_count, values(query) as sample_queries, values(query_type) as query_types, avg(query_len) as avg_query_len, max(numeric_ratio) as max_numeric_ratio, count(query_type:TXT) as total_txt_queries
| filter ((distinct_query_count > 15 avg_query_len > 20 max_numeric_ratio > 0.2) OR (total_txt_queries > 10 distinct_query_count > 5)) -domain:(*.amazonaws.com *.google.com *.microsoft.com *.icloud.com *.akamai.net)
| table _time, src.ip, domain, total_queries, distinct_query_count, total_txt_queries, avg_query_len, max_numeric_ratio, sample_queries
```

### Non-Standard Protocol Usage for C2
---
```sql
(source:network tag:network tag:communicate (((app:dns -dest.port:53) OR (app:smtp -dest.port:(25 465 587)) OR (dest.port:(80 443) -app:(http ssl https quic http-proxy unknown bittorrent))) OR (transport:icmp
| groupby _time, src.ip, dest.ip, transport sum(bytes) as total_bytes, dc(icmp_type) as distinct_icmp_types, count as pkt_count
| filter pkt_count > 100 total_bytes > 20480)) -src.ip:(10.0.0.0/8 127.0.0.1) -dest.ip:(224.0.0.0/4 255.255.255.255)
| eval reason=case(dest.port:(80 443), "Non-Standard Protocol on Web Port", app:dns, "DNS on Non-Standard Port", app:smtp, "SMTP on Non-Standard Port", transport:icmp, "Potential ICMP Tunneling", true, "Unknown Anomaly"), signature=if(transport:icmp, "High Volume ICMP (" + total_bytes + " bytes, " + pkt_count + " packets)", app)
| table _time, src.ip as source_ip, dest.ip as destination_ip, dest.port as destination_port, transport, signature, reason
```

### Rapid IP Address Changes for a Domain
---
```sql
source:network_resolution qtype:(A AAAA) -answers:(10.* 172.1[6-9].* 172.2[0-9].* 172.3[0-1].* 192.168.* 127.0.0.1) -query:(*.google.com *.googleapis.com *.microsoft.com *.windowsupdate.com *.apple.com *.icloud.com *.amazonaws.com *.cloudfront.net *.akamaitechnologies.com *.akamai.net *.cloudflare.com *.fastly.net *.office365.com)
| groupby query values(answers) as resolved_ips, dc(answers) as distinct_ip_count
| filter distinct_ip_count > 3
| table query as domain, distinct_ip_count, resolved_ips
```