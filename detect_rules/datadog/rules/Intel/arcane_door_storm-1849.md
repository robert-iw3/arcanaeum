### ArcaneDoor Campaign Summary
---

The ArcaneDoor campaign, attributed to the state-sponsored actor UAT4356 (aka STORM-1849), is an espionage-focused operation targeting perimeter network devices, specifically Cisco Adaptive Security Appliances (ASA) and Firepower Threat Defense (FTD) devices. The actor utilizes sophisticated custom malware, "Line Dancer" and "Line Runner," to achieve persistence, conduct reconnaissance, exfiltrate data, and evade forensic analysis.

Recent intelligence confirms that the ArcaneDoor campaign, active since at least July 2023, involves the exploitation of two zero-day vulnerabilities (CVE-2024-20353 and CVE-2024-20359) in Cisco ASA and FTD devices to deploy custom malware. While the initial access vector remains unknown, the campaign highlights a continued focus by state-sponsored actors on compromising critical network infrastructure for espionage, with some analysis suggesting potential links to China.

### Actionable Threat Data
---

Monitor for unexpected `reboots` or `unscheduled configuration changes` on Cisco ASA and FTD devices, as these can indicate compromise by the ArcaneDoor campaign.

Look for network connections from Cisco ASA devices to the identified actor-controlled infrastructure `IP addresses`.

Inspect Cisco ASA device memory for the presence of more than one executable memory region when running `show memory region | include lina`, especially if a `0x1000` byte region is present, which could indicate the "`Line Dancer`" in-memory implant.

Regularly check `disk0:` on Cisco ASA devices for unusual `.zip` files, particularly after applying patches for CVE-2024-20359, as this may indicate the presence of the "`Line Runner`" persistence mechanism.

Implement network traffic analysis to detect HTTP `POST` requests to Cisco ASA devices that bypass traditional authentication, which could signify "Line Dancer" activity.

### ArcaneDoor C2 IPs
---
```sql
source:network dest.ip:(192.36.57.181 185.167.60.85 185.227.111.17 176.31.18.153 172.105.90.154 185.244.210.120 45.86.163.224 172.105.94.93 213.156.138.77 89.44.198.189 45.77.52.253 103.114.200.230 212.193.2.48 51.15.145.37 89.44.198.196 131.196.252.148 213.156.138.78 121.227.168.69 213.156.138.68 194.4.49.6 185.244.210.65 216.238.75.155 5.183.95.95 45.63.119.131 45.76.118.87 45.77.54.14 45.86.163.244 45.128.134.189 89.44.198.16 96.44.159.46 103.20.222.218 103.27.132.69 103.51.140.101 103.119.3.230 103.125.218.198 104.156.232.22 107.148.19.88 107.172.16.208 107.173.140.111 121.37.174.139 139.162.135.12 149.28.166.244 152.70.83.47 154.22.235.13 154.22.235.17 154.39.142.47 172.233.245.241 185.123.101.250 192.210.137.35 194.32.78.183 205.234.232.196 207.148.74.250 216.155.157.136 216.238.66.251 216.238.71.49 216.238.72.201 216.238.74.95 216.238.81.149 216.238.85.220 216.238.86.24)
| groupby src.ip, dest.ip, user, dest.port, action
```

### Line Dancer Memory Artifacts
---
```sql
source:cisco sourcetype:(cisco:asa cisco:ftd) /asa/bin/lina r-xp
| parse mem_start="[a-f0-9]+-[a-f0-9]+" as mem_start, mem_end="[a-f0-9]+-[a-f0-9]+" as mem_end
| eval region_size=tonumber(mem_end, 16) - tonumber(mem_start, 16)
| groupby host count(executable_region_count), values(region_size)
| filter executable_region_count > 1
```

### Line Runner Persistence
---
```sql
source:cisco client_bundle .zip -filename:client_bundle.zip
| parse filename="client_bundle*.zip" as filename
| groupby host values(filename) as suspicious_files
```

### Suspicious HTTP POST to ASA
---
```sql
source:web http.method:POST form_data:*host-scan-reply*
| parse host_scan_reply_payload="host-scan-reply=[^&]+" as host_scan_reply_payload
| eval payload_len=len(host_scan_reply_payload)
| filter payload_len > 500 (user:NULL OR user:-)
| groupby src.ip, dest.ip, user count, values(payload_len) as payload_lengths, values(url) as urls
```

### ASA Configuration Tampering
---
```sql
source:cisco sourcetype:(cisco:asa cisco:ftd) (%ASA-6-110002 OR (%ASA-5-111008 ("no logging enable" OR "write memory")))
| parse user="Executed by \S+" as user
| eval reason=case(like(_raw, "%ASA-6-110002"), "Device Reboot/Startup Detected", like(_raw, "%no logging enable%"), "Syslog Logging Disabled", like(_raw, "%write memory%"), "Configuration Saved to Memory")
| groupby _time, host, user count, values(reason) as reasons
```
