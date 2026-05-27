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
(|tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest_ip IN ("192.36.57.181", "185.167.60.85", "185.227.111.17", "176.31.18.153", "172.105.90.154", "185.244.210.120", "45.86.163.224", "172.105.94.93", "213.156.138.77", "89.44.198.189", "45.77.52.253", "103.114.200.230", "212.193.2.48", "51.15.145.37", "89.44.198.196", "131.196.252.148", "213.156.138.78", "121.227.168.69", "213.156.138.68", "194.4.49.6", "185.244.210.65", "216.238.75.155", "5.183.95.95", "45.63.119.131", "45.76.118.87", "45.77.54.14", "45.86.163.244", "45.128.134.189", "89.44.198.16", "96.44.159.46", "103.20.222.218", "103.27.132.69", "103.51.140.101", "103.119.3.230", "103.125.218.198", "104.156.232.22", "107.148.19.88", "107.172.16.208", "107.173.140.111", "121.37.174.139", "139.162.135.12", "149.28.166.244", "152.70.83.47", "154.22.235.13", "154.22.235.17", "154.39.142.47", "172.233.245.241", "185.123.101.250", "192.210.137.35", "194.32.78.183", "205.234.232.196", "207.148.74.250", "216.155.157.136", "216.238.66.251", "216.238.71.49", "216.238.72.201", "216.238.74.95", "216.238.81.149", "216.238.85.220", "216.238.86.24") by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.user, All_Traffic.dest_port, All_Traffic.action
| `drop_dm_object_name("All_Traffic")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| `comment("This search looks for network traffic to IP addresses associated with the ArcaneDoor campaign. For better performance, consider using a lookup file for the IOCs.")`
| `comment("Some of these IPs are multi-tenant (e.g., public VPNs) and may generate false positives. To reduce noise, consider filtering for traffic originating only from critical perimeter devices like Cisco ASAs (e.g., append '| search src_ip IN (<list_of_your_ASA_ips>)').")`)
```

### Line Dancer Memory Artifacts
---
```sql
`cisco`
| comment("This search requires logs from Cisco ASA/FTD devices containing the output of the 'show memory region' command. Ensure this data is being collected, for example via a scripted input.")
| search sourcetype IN (cisco:asa, cisco:ftd) AND "/asa/bin/lina" AND "r-xp"
| comment("Filter for events from the 'show memory region' command for the 'lina' process, specifically looking for executable memory regions (r-xp).")
| rex field=_raw "(?<mem_start>[a-f0-9]+)-(?<mem_end>[a-f0-9]+)\s+r-xp"
| comment("Extract the start and end memory addresses for each executable region.")
| eval region_size = tonumber(mem_end, 16) - tonumber(mem_start, 16)
| comment("Calculate the size of the memory region in bytes. The Line Dancer implant often creates a new region of exactly 4096 bytes (0x1000).")
| stats count as executable_region_count, values(region_size) as region_sizes by host, _time
| comment("Count the number of executable regions and list their sizes for each host.")
| where executable_region_count > 1
| comment("A healthy Cisco ASA device should only have one executable (r-xp) memory region for the 'lina' process. More than one is a strong indicator of compromise by an in-memory implant like Line Dancer.")
| rename host as dvc
```

### Line Runner Persistence
---
```sql
`cisco`
| comment("This search requires logs from Cisco ASA/FTD devices containing the output of commands like 'dir disk0:'. This may require a custom scripted input.")
| search "client_bundle" AND ".zip"
| comment("Focus on logs containing client bundle zip files, which are central to the Line Runner persistence technique.")
| rex field=_raw "(?<filename>client_bundle[\w_-]*\.zip)"
| comment("Extract the specific filename matching the pattern used by the malware.")
| where filename != "client_bundle.zip"
| comment("The Line Runner persistence mechanism often re-creates the bundle with a new name (e.g., client_bundle_install.zip). This logic filters for these suspicious variants. Legitimate custom bundle names could cause false positives; any findings should be investigated.")
| stats values(filename) as suspicious_files by host
| rename host as dvc
```

### Suspicious HTTP POST to ASA
---
```sql
`web`
| comment("This search requires Cisco ASA webvpn logs or web proxy logs capturing traffic to the ASA. The 'web' macro should be configured for these sources.")
| search http_method=POST AND form_data="*host-scan-reply*"
| comment("Focus on POST requests containing the 'host-scan-reply' field, which is abused by the Line Dancer implant.")
| rex field=form_data "host-scan-reply=(?<host_scan_reply_payload>[^&]+)"
| comment("Extract the payload from the 'host-scan-reply' field.")
| eval payload_len=len(host_scan_reply_payload)
| comment("Calculate the length of the payload. Malicious payloads are typically large, containing shellcode.")
| where payload_len > 500 AND (isnull(user) OR user="-")
| comment("The key indicator is the presence of a large host-scan-reply payload in a request that is NOT authenticated. Legitimate uses of this field typically occur within an established user session. This may need tuning based on how unauthenticated users are represented in your logs.")
| stats count, values(payload_len) as payload_lengths, values(url) as urls by src, dest, user
| rename src as src_ip, dest as dest_ip
```

### ASA Configuration Tampering
---
```sql
`cisco`
| comment("This search requires Cisco ASA/FTD logs that capture system and configuration events. Ensure sourcetypes are mapped correctly.")
| search sourcetype IN (cisco:asa, cisco:ftd) AND (
    `comment("Cisco message ID for device startup/reboot")`
    %ASA-6-110002
    OR
    `comment("Cisco message ID for executed commands, looking for syslog disable or config save")`
    (%ASA-5-111008 AND ("no logging enable" OR "write memory"))
)
| comment("Filter for key indicators of tampering: unexpected reboots, disabling logging, or saving configuration changes. The ArcaneDoor actor performed these actions to hide activity.")
| rex "Executed by (?<user>\S+)"
| eval reason=case(
    like(_raw, "%ASA-6-110002"), "Device Reboot/Startup Detected",
    like(_raw, "%no logging enable%"), "Syslog Logging Disabled",
    like(_raw, "%write memory%"), "Configuration Saved to Memory"
    )
| comment("Categorize the activity. The analyst should verify if this activity corresponds to a scheduled maintenance window or change request, as these actions can be legitimate.")
| stats count, values(reason) as reasons by _time, host, user
| rename host as dvc
```
