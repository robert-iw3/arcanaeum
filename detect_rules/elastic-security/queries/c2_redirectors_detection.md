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
from logs-nginx*, logs-apache*, logs-iis*
| where http.request.user_agent IS NOT NULL
  and http.request.user_agent != "-"
  and NOT (
    http.request.user_agent rlike ".*(Mozilla/|Opera/|curl/|Wget/|Python-urllib/|Go-http-client/|Java/).*"
    OR http.request.user_agent rlike ".*(bot|spider|crawler|scanner).*"
  )
| stats
    count = COUNT(*)
  BY http.request.user_agent, source.ip, destination.ip
| stats
    ua_total_count = SUM(count)
  BY http.request.user_agent
| where ua_total_count < 10
| stats
    Source_IPs = GROUP_CONCAT(source.ip),
    Destination_IPs = GROUP_CONCAT(destination.ip),
    Connection_Count = SUM(count)
  BY http.request.user_agent, ua_total_count
| keep
    http.request.user_agent,
    ua_total_count,
    Source_IPs,
    Destination_IPs,
    Connection_Count
| rename
    http.request.user_agent AS Unusual_User_Agent,
    ua_total_count AS Total_Count_In_Timeframe
| sort Total_Count_In_Timeframe ASC
```

### Suspicious HTTP/HTTPS Traffic for C2
---
```sql
from zeek-* | where zeek.session_id IS NOT NULL
  // Filter for Zeek SSL or HTTP events (assuming event.category or similar distinguishes them)
  and (event.category IN ("zeek_ssl", "zeek_http"))
  // Correlate events by session_id, source.address, destination.address, destination.port
  | stats
      sourcetypes = COLLECT(event.category),
      http_host = COLLECT(url.domain),
      sni = COLLECT(tls.server_name),
      http_method = COLLECT(http.request.method),
      uri = COLLECT(url.path),
      filenames = COLLECT(http.response.body.filenames),
      content_type = COLLECT(http.response.mime_type)
    BY zeek.session_id, source.address, destination.address, destination.port
  // Detection Logic
  | where (
      // Pattern 1: Suspicious content-type (application/octet-stream) without common file extensions or filenames
      ("application/octet-stream" IN content_type
       and NOT (uri MATCHES ".*\\.(exe|zip|rar|dll|msi|iso|pkg|dmg)$" OR filenames IS NOT NULL))
      OR
      // Pattern 2: Domain fronting (HTTP Host != SNI, excluding subdomains)
      (LENGTH(sourcetypes) > 1
       and http_host IS NOT NULL
       and sni IS NOT NULL
       and http_host != sni
       and NOT http_host like CONCAT("%.", sni))
  )
  // False Positive Filtering: Exclude common CDN domains
  | where NOT (
      sni like "*.google.com"
      OR sni like "*.akamaiedge.net"
      OR sni like "*.amazonaws.com"
      OR sni like "*.azureedge.net"
      OR sni like "*.cloudflare.net"
      OR sni like "*.fastly.net"
      OR sni like "*.cloudfront.net"
      OR http_host like "*.google.com"
      OR http_host like "*.akamaiedge.net"
      OR http_host like "*.amazonaws.com"
      OR http_host like "*.azureedge.net"
      OR http_host like "*.cloudflare.net"
      OR http_host like "*.fastly.net"
      OR http_host like "*.cloudfront.net"
  )
  // rename and select fields for output
  | eval
      src = source.address,
      dest = destination.address,
      dest_port = destination.port,
      http_host_header = http_host,
      tls_sni = sni
  | keep @timestamp, src, dest, dest_port, http_host_header, tls_sni, content_type, uri, http_method
  // sort by timestamp for consistency
  | sort @timestamp desc
```

### Anomalous DNS Queries for C2
---
```sql
from *
| where (event.dataset = "stream.dns" OR tags = "dns") and dns.question.name != "localhost"
| eval
    query_len = LENGTH(dns.question.name),
    numeric_chars = REGEXP_REPLACE(dns.question.name, "[^0-9]", ""),
    numeric_ratio = LENGTH(numeric_chars) / query_len
| stats
    total_queries = COUNT(),
    distinct_query_count = COUNT_DISTINCT(dns.question.name),
    sample_queries = COLLECT(dns.question.name),
    query_types = COLLECT(dns.question.type),
    avg_query_len = AVG(query_len),
    max_numeric_ratio = MAX(numeric_ratio),
    total_txt_queries = COUNT(case(dns.question.type = "TXT", 1, NULL))
  BY source.ip, dns.question.registered_domain
| where
    (distinct_query_count > 15 and avg_query_len > 20 and max_numeric_ratio > 0.2)
    OR
    (total_txt_queries > 10 and distinct_query_count > 5)
| where NOT (
    dns.question.registered_domain like ".amazonaws.com"
    OR dns.question.registered_domain like ".google.com"
    OR dns.question.registered_domain like ".microsoft.com"
    OR dns.question.registered_domain like ".icloud.com"
    OR dns.question.registered_domain like ".akamai.net"
)
| eval
    src_ip = source.ip,
    target_domain = dns.question.registered_domain
| keep
    @timestamp,
    src_ip,
    target_domain,
    total_queries,
    distinct_query_count,
    total_txt_queries,
    avg_query_len,
    max_numeric_ratio,
    sample_queries
| sort @timestamp desc
```

### Non-Standard Protocol Usage for C2
---
```sql
// Part 1: Protocol-Port Mismatch Detection
from network_traffic
| where tags IN ("network", "communicate")
| where (
    (network.application == "dns" AND destination.port != 53)
    OR (network.application == "smtp" AND destination.port NOT IN (25, 465, 587))
    OR (destination.port IN (80, 443) AND network.application NOT IN ("http", "ssl", "https", "quic", "http-proxy", "unknown", "bittorrent"))
)
| eval reason = CASE(
    destination.port IN (80, 443), "Non-Standard Protocol on Web Port",
    network.application == "dns", "DNS on Non-Standard Port",
    network.application == "smtp", "SMTP on Non-Standard Port",
    true, "Unknown Anomaly"
)
| eval signature = network.application
| keep @timestamp, source.ip, destination.ip, destination.port, network.transport, signature, reason

// Part 2: ICMP Tunneling Detection
| union (
    from network_traffic
    | where tags IN ("network", "communicate") AND network.transport == "icmp"
    | stats total_bytes = SUM(network.bytes), distinct_icmp_types = COUNT_DISTINCT(network.icmp.type), pkt_count = COUNT(*)
      BY @timestamp, source.ip, destination.ip, network.transport
    | where pkt_count > 100 AND total_bytes > 20480
    | eval reason = "Potential ICMP Tunneling"
    | eval signature = "High Volume ICMP (" + TO_STRING(total_bytes) + " bytes, " + TO_STRING(pkt_count) + " packets)"
    | keep @timestamp, source.ip, destination.ip, network.transport, signature, reason
)

// False Positive Tuning
| where source.ip NOT IN ("10.0.0.0/8", "127.0.0.1")
  AND destination.ip NOT IN ("224.0.0.0/4", "255.255.255.255")

// Final Output
| eval destination.port = COALESCE(destination.port, "N/A")
| rename @timestamp AS _time, source.ip AS source_ip, destination.ip AS destination_ip,
         destination.port AS destination_port, network.transport AS transport
| keep _time, source_ip, destination_ip, destination_port, transport, signature, reason
```

### Rapid IP Address Changes for a Domain
---
```sql
from network_resolution
| where @timestamp >= NOW() - 1 DAY
  AND event.dataset == "dns"
  AND dns.question.type IN ("A", "AAAA")
| stats distinct_ip_count = COUNT_DISTINCT(dns.answers.address), resolved_ips = COLLECT(dns.answers.address)
  BY dns.question.name
| where distinct_ip_count > 3
  AND dns.answers.address IS NOT NULL
  AND NOT (
    dns.answers.address like "10.%"
    OR dns.answers.address like "172.1[6-9].%"
    OR dns.answers.address like "172.2[0-9].%"
    OR dns.answers.address like "172.3[0-1].%"
    OR dns.answers.address like "192.168.%"
    OR dns.answers.address == "127.0.0.1"
  )
  AND NOT (
    dns.question.name like "%.google.com"
    OR dns.question.name like "%.googleapis.com"
    OR dns.question.name like "%.microsoft.com"
    OR dns.question.name like "%.windowsupdate.com"
    OR dns.question.name like "%.apple.com"
    OR dns.question.name like "%.icloud.com"
    OR dns.question.name like "%.amazonaws.com"
    OR dns.question.name like "%.cloudfront.net"
    OR dns.question.name like "%.akamaitechnologies.com"
    OR dns.question.name like "%.akamai.net"
    OR dns.question.name like "%.cloudflare.com"
    OR dns.question.name like "%.fastly.net"
    OR dns.question.name like "%.office365.com"
  )
| rename dns.question.name AS domain
| keep domain, distinct_ip_count, resolved_ips
```