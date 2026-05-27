### DanaBot C2 Anomalies
---
```sql
`cim_Network_Traffic`

`# Focus on connections with small response sizes, which could be C2 beacons plus leaked data.`
`# The DanaBleed vulnerability adds up to 1792 bytes of variable data to the C2 response.`
| where isnotnull(bytes_in) AND bytes_in > 1 AND bytes_in < 4096

`# Filter out common broadcast/multicast noise.`
| where NOT (cidrmatch("224.0.0.0/4", dest_ip) OR cidrmatch("ff00::/8", dest_ip))

`# Aggregate by destination to identify potential C2 servers.`
| stats count, dc(src_ip) as distinct_sources, values(src_ip) as src_ips, avg(bytes_in) as avg_response_size, stdev(bytes_in) as stdev_response_size by dest_ip, dest_port, action

`# A high standard deviation in response size can indicate variable padding, a key feature of the DanaBleed C2 anomaly.`
`# A high number of distinct sources connecting to the same destination is also suspicious.`
| where distinct_sources > 5 AND stdev_response_size > 100 AND action="allowed"

`# False Positive Tuning:`
`# The thresholds for distinct_sources (e.g., > 5) and stdev_response_size (e.g., > 100) may need adjustment for your environment.`
`# Consider excluding traffic to known benign services (e.g., CDNs, public DNS, update servers) by using a lookup of allowed destinations.`
`# For example: | search NOT [| inputlookup known_good_ips.csv | fields dest_ip]`

`# Format the output for analysis.`
| rename dest_ip as "Suspected_C2_Server", dest_port as "C2_Port", distinct_sources as "Infected_Host_Count", avg_response_size as "Avg_Response_Bytes", stdev_response_size as "StDev_Response_Bytes"
| table Suspected_C2_Server, C2_Port, Infected_Host_Count, Avg_Response_Bytes, StDev_Response_Bytes, src_ips
| sort - Infected_Host_Count
```

### DanaBot Custom C2 Protocol
---
```sql
`# name: "danabot_custom_c2_protocol"`
`# description: |-`
`# Detects network traffic to known DanaBot command and control (C2) servers. DanaBot uses a custom binary protocol for C2 communications, which may be sent`
`# over common ports like 443. Connections to these specific IP addresses are a strong indicator of a DanaBot infection.`
`# date: "2025-07-24"`
`# version: "1"`
`# references:`
`#  - "https://www.zscaler.com/blogs/security-research/operation-endgame-2-0-danabusted"`
`# tags:`
`#  - "mitre_attack:T1071"`
`#  - "malware_family:DanaBot"`
`#  - "pyramid_of_pain:Network Artifacts"`
`#  - "security_domain:network"`
`#  - "detection_source:network_traffic"`

`comment("This search identifies traffic to known DanaBot C2 servers using the Network_Traffic data model.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest_ip IN ("149.28.241.120", "91.243.50.68", "77.239.101.139", "77.239.99.248", "77.91.76.17", "149.28.127.237") by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.user, All_Traffic.dest
`comment("Rename fields for CIM compliance and add human-readable timestamps.")`
| rename "All_Traffic.*" as *
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
`comment("This logic can produce false positives if the C2 IP addresses are reallocated. Analysts should verify the age of the IOCs and the nature of the traffic (e.g., confirm it is not legitimate TLS traffic if on port 443).")`
| eval name="DanaBot C2 Communication", description="Network traffic detected to a known DanaBot C2 server: " + dest_ip + " from source " + src_ip + "."
| fields name, description, firstTime, lastTime, src_ip, dest_ip, dest_port, user, dest, count
```