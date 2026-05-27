### Detecting Data Exfiltration with Network Traffic Analysis
---

Data exfiltration is the unauthorized transfer of sensitive data from an organization's network to an external location, posing significant financial, regulatory, and reputational risks. Network Traffic Analysis (NTA) is a crucial defense mechanism that continuously monitors, collects, and analyzes network activities to detect anomalous patterns and prevent data theft.

Recent intelligence highlights a growing trend of threat actors leveraging legitimate cloud services for data exfiltration, with ransomware groups increasingly using platforms like Azure Storage Explorer and Amazon S3 buckets to move stolen data. This evolution necessitates enhanced monitoring of cloud environments and integration of cloud security posture management (CSPM) solutions.

### Actionable Threat Data

Unusual Data Spikes and Volume Anomalies:

Monitor for sudden, significant increases in outbound network traffic, especially during off-hours or from unexpected internal hosts. This can indicate large-scale data transfers.

```sql
index=* sourcetype=network_traffic direction=outbound
| timechart span=1h sum(bytes) as total_bytes
| streamstats window=5 avg(total_bytes) as avg_bytes, stdev(total_bytes) as stdev_bytes
| eval lower_bound=(avg_bytes - (2 * stdev_bytes)), upper_bound=(avg_bytes + (2 * stdev_bytes))
| where total_bytes < lower_bound OR total_bytes > upper_bound
```

Connections to Suspicious or Blacklisted External IPs:

Alert on connections to unknown, newly observed, or blacklisted external IP addresses, which could signify communication with C2 servers or data exfiltration endpoints.

```sql
index=* sourcetype=network_traffic direction=outbound
| lookup threat_intel_blacklist ip as dest_ip OUTPUT threat_status
| where threat_status="blacklisted"
```

DNS Tunneling Detection:

Identify unusually large or frequent DNS queries, or DNS requests to suspicious domains, as these can indicate data being exfiltrated through DNS tunneling.

```sql
index=* sourcetype=dns
| stats count by query, src_ip
| where count > 100 OR len(query) > 150
| table _time, src_ip, query, count
```

Unauthorized Cloud Storage Uploads:

Detect and flag unauthorized file transfers to personal or unapproved cloud storage services (e.g., Google Drive, Dropbox, Amazon S3, Azure Blob Storage) from internal systems.

```sql
index=* sourcetype=web_proxy (dest_url="*drive.google.com*" OR dest_url="*dropbox.com*" OR dest_url="*s3.amazonaws.com*" OR dest_url="*blob.core.windows.net*")
| stats sum(bytes_out) as total_bytes_uploaded by user, dest_url
| where total_bytes_uploaded > 100000000
```

Use of Uncommon Ports and Protocols:

Monitor for the use of non-standard ports or less-monitored protocols (e.g., UDP over TCP) for outbound connections, as attackers may use these to evade detection.

```sql
index=* sourcetype=network_traffic direction=outbound
| stats count by dest_port, transport
| where count > 1000 AND NOT (dest_port IN (80, 443, 21, 22, 23, 25, 110, 143, 3389))
```

### Unusual Outbound Traffic Spike
---
```sql
`#
Unusual Outbound Traffic Spike

This detection identifies a significant spike in outbound data volume from an internal source system.
It establishes a dynamic baseline of normal traffic volume for each host by calculating a moving average
and standard deviation over a 24-hour window. An alert is triggered when the traffic volume in a
given hour exceeds this baseline by a configurable number of standard deviations, which can be an
indicator of bulk data exfiltration.

False Positive Sensitivity: Medium

Tactic: Exfiltration (TA0010)

Technique: Exfiltration Over C2 Channel (T1041)
#`

`comment("This search leverages the Network_Traffic data model. Ensure your network data (firewall, proxy, netflow) is CIM-compliant.")`
tstats `summariesonly` sum(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic where All_Traffic.direction=outbound by _time, All_Traffic.src span=1h
| `drop_dm_object_name("All_Traffic")`

`comment("Calculate a moving average and standard deviation over the last 24 hours for each source IP to establish a dynamic baseline.")`
| streamstats time_window=24h avg(bytes_out) as avg_bytes_out stdev(bytes_out) as stdev_bytes_out by src

`comment("A spike is defined as traffic volume exceeding the average by a certain number of standard deviations. The multiplier (e.g., 3) can be tuned to adjust sensitivity. A higher value reduces false positives.")`
| eval stdev_multiplier = 3
| eval threshold = avg_bytes_out + (stdev_multiplier * stdev_bytes_out)

`comment("Filter for traffic spikes that are statistically significant and exceed a minimum volume (e.g., 100MB) to reduce noise from minor fluctuations.")`
| where bytes_out > threshold AND bytes_out > 100000000

`comment("FP Tuning: To reduce false positives, exclude known sources of high-volume outbound traffic, such as backup servers or systems that regularly sync with cloud services.")`
`comment("| where NOT match(src, \"<ip_or_cidr_of_known_high_traffic_source>\")")`

`comment("FP Tuning: Consider focusing on spikes occurring outside of typical business hours (e.g., 8 AM to 6 PM).")`
`comment("| eval hour=strftime(_time, \"%H\") | where hour < 8 OR hour > 18")`

`comment("Format the results for readability and alerting.")`
| eval "GB Sent" = round(bytes_out/1073741824, 2)
| eval "Avg GB Sent (24h)" = round(avg_bytes_out/1073741824, 2)
| eval "Alert Threshold (GB)" = round(threshold/1073741824, 2)
| table _time, src, "GB Sent", "Avg GB Sent (24h)", "Alert Threshold (GB)"
| rename src as source_system
```

### Connections to Blacklisted IPs
---
```sql
`#
Connections to Blacklisted IP Addresses

This rule detects outbound network connections to IP addresses that are present on a threat intelligence blacklist. Such connections can indicate communication with command-and-control (C2) servers, malware distribution points, or data exfiltration endpoints.

False Positive Sensitivity: Medium

Tactic: Command and Control (TA0011), Exfiltration (TA0010)

Technique: Application Layer Protocol (T1071)
#`

`comment("This search leverages the Network_Traffic data model. Ensure your network data (firewall, proxy, netflow) is CIM-compliant.")`
tstats `summariesonly` values(All_Traffic.action) as action, values(All_Traffic.dest_port) as dest_port, values(All_Traffic.user) as user, sum(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic where All_Traffic.direction=outbound by _time, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name("All_Traffic")`

`comment("Lookup destination IPs against a threat intelligence feed. Replace 'ip_threat_intel_lookup' with your specific lookup file/definition and 'threat_key' with the relevant output field(s).")`
| lookup ip_threat_intel_lookup dest as ip OUTPUT threat_key as threat_match

`comment("Filter for events where the destination IP was found in the threat intelligence list.")`
| where isnotnull(threat_match)

`comment("FP Tuning: Your threat intelligence feed may contain false positives. Consider creating an allow list of known good IPs or specific threat categories to exclude if they are generating noise.")`
`comment("| search NOT dest IN (<ip1_to_exclude>, <ip2_to_exclude>)")`

`comment("Format the results for readability and alerting.")`
| rename src as source_ip, dest as destination_ip
| table _time, source_ip, destination_ip, dest_port, user, bytes_out, action, threat_match
```

### DNS Tunneling Activity
---
```sql
`#
DNS Tunneling Activity

This detection identifies potential DNS tunneling activity by analyzing DNS query patterns. It flags source systems that generate a high volume of unusually long DNS queries within a short time frame. This behavior is a strong indicator of data being exfiltrated covertly over the DNS protocol, bypassing traditional firewall rules.

False Positive Sensitivity: Medium

Tactic: Command and Control (TA0011), Exfiltration (TA0010)

Technique: Application Layer Protocol: DNS (T1071.004)
#`

`comment("This search leverages the Network_Resolution data model. Ensure your DNS data is CIM-compliant.")`
tstats `summariesonly` count from datamodel=Network_Resolution by _time, All_Resolution.src, All_Resolution.query
| `drop_dm_object_name("All_Resolution")`

`comment("Calculate the length of each DNS query.")`
| eval query_length = len(query)

`comment("Aggregate DNS activity over a 10-minute window for each source IP.")`
| bin _time span=10m
| stats count, dc(query) as distinct_queries, avg(query_length) as avg_query_length, max(query_length) as max_query_length, values(query) as sample_queries by _time, src

`comment("FP Tuning: The thresholds for max query length (>100) and query count (>50) are key tuning parameters. Adjust these based on your environment's baseline. Some legitimate services, like CDNs, can use long domain names.")`
| where max_query_length > 100 AND count > 50

`comment("FP Tuning: To reduce noise, consider excluding known internal DNS resolvers if the logs reflect their IP as the source. The focus should be on the original client IP.")`
`comment("| search NOT src IN (<resolver1_ip>, <resolver2_ip>)")`

`comment("FP Tuning: Exclude known legitimate domains that may generate long queries. Populate a lookup file with domains to ignore.")`
`comment("| lookup local_legitimate_domains_lookup.csv domain as query OUTPUT is_legit | where isnull(is_legit)")`

`comment("Format the results for readability and alerting.")`
| rename src as source_ip
| table _time, source_ip, count, distinct_queries, avg_query_length, max_query_length, sample_queries
```

### Unauthorized Cloud Uploads
---
```sql
`#
Unauthorized Cloud Storage Uploads

This detection identifies large data uploads to common public cloud storage services within a one-hour window. This activity can be an indicator of data exfiltration, where an attacker or malicious insider uses legitimate web services to transfer sensitive data out of the network, bypassing other security controls.

False Positive Sensitivity: Medium

Tactic: Exfiltration (TA0010)

Technique: Exfiltration Over Web Service (T1567), Exfiltration to Cloud Storage (T1567.002)
#`

`comment("This search leverages the Web data model. Ensure your web proxy or firewall data is CIM-compliant.")`
tstats `summariesonly` sum(Web.bytes_out) as total_bytes_out, values(Web.url) as sample_urls from datamodel=Web where (Web.url IN ("*drive.google.com*", "*dropbox.com*", "*box.com*", "*mega.nz*", "*s3.amazonaws.com*", "*blob.core.windows.net*")) AND Web.action=allowed by _time, Web.src, Web.user span=1h
| `drop_dm_object_name("Web")`

`comment("FP Tuning: The threshold for total bytes uploaded (100MB) is a key tuning parameter. Adjust based on your organization's policies and baseline activity.")`
| where total_bytes_out > 100000000

`comment("FP Tuning: To reduce noise, exclude users or departments that are authorized to perform large uploads to these services.")`
`comment("| search NOT user IN (<authorized_user1>, <authorized_user2>)")`

`comment("FP Tuning: If your organization uses a sanctioned cloud provider (e.g., Box), consider removing it from the tstats filter to focus only on unsanctioned services.")`

`comment("Format the results for readability and alerting.")`
| eval "Total MB Uploaded" = round(total_bytes_out / 1048576, 2)
| rename src as source_ip, user as user_id
| table _time, source_ip, user_id, "Total MB Uploaded", sample_urls
```

### Uncommon Port/Protocol Use
---
```sql
`#
Outbound Traffic on Uncommon Port

This detection identifies outbound network traffic to destination ports that are not commonly associated with standard internet services (e.g., HTTP/S, DNS, SMTP). Attackers often use non-standard ports for command-and-control (C2) communication or data exfiltration to evade simple, port-based firewall rules and security monitoring.

False Positive Sensitivity: Medium

Tactic: Command and Control (TA0011), Exfiltration (TA0010)

Technique: Non-Standard Port (T1571)
#`

`comment("This search leverages the Network_Traffic data model. Ensure your network data (firewall, proxy, netflow) is CIM-compliant.")`
tstats `summariesonly` count, sum(All_Traffic.bytes_out) as total_bytes_out from datamodel=Network_Traffic where All_Traffic.direction=outbound AND NOT (All_Traffic.dest_port IN (21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3389, 5222, 5223, 8080, 8443)) by _time, All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.transport span=1h
| `drop_dm_object_name("All_Traffic")`

`comment("Filter for a notable amount of activity to reduce noise from ephemeral connections or network scanners. Adjust thresholds based on your environment's baseline.")`
| where count > 10 AND total_bytes_out > 10240

`comment("FP Tuning: Some legitimate applications (e.g., games, P2P clients, specific business apps) use non-standard ports. Add ports used by sanctioned applications to the exclusion list in the tstats command.")`
`comment("FP Tuning: If certain internal systems are known to communicate over custom ports, exclude their source IPs to reduce false positives.")`
`comment("| search NOT src IN (<known_source_ip_1>, <known_source_ip_2>)")`

`comment("Format the results for readability and alerting.")`
| rename src as source_ip, dest as destination_ip, dest_port as destination_port, transport as protocol
| eval "Total KB Out" = round(total_bytes_out/1024, 2)
| table _time, source_ip, destination_ip, destination_port, protocol, count, "Total KB Out"
```