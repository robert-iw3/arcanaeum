### The Covert Operator's Playbook: Infiltration of Global Telecom Networks
---

The CL-STA-0969 activity cluster, assessed with high confidence to be a nation-state adversary, has been actively targeting global telecommunications networks, particularly in Southwest Asia, between February and November 2024. This threat actor, overlapping with groups like Liminal Panda, UNC3886, UNC2891, and UNC1945, demonstrates a deep understanding of telecom protocols and infrastructure, employing custom tools and sophisticated defense evasion techniques to maintain persistent and stealthy access.

Recent intelligence confirms Liminal Panda's continued focus on telecommunications, leveraging compromised servers to infiltrate additional providers across various geographic regions and utilizing GSM protocols for C2 communications and data exfiltration. This highlights an evolving threat where initial compromises are used as jumping-off points for wider network infiltration, emphasizing the need for enhanced inter-provider security measures.

### Actionable Threat Data and Quick Searches
---

SSH Brute Force and Account Compromise: The threat actor gains initial access primarily through SSH brute-force attacks, utilizing well-tuned account dictionaries that include built-in telecommunications equipment accounts.

Detection Opportunity: Monitor for a high volume of failed SSH login attempts from a single source IP address or against multiple accounts within a short timeframe. Look for successful SSH logins immediately following multiple failed attempts.

```sql
index=* "Failed password for invalid user" OR "Failed password for *" // replace with linux logs index/data-stream
| stats count by src_ip, user
| where count > 5 (adjust threshold as needed)
```

Custom Backdoors and C2 over Telecom Protocols: The adversary deploys custom backdoors like AuthDoor, GTPDoor, ChronosRAT, and NoDepDNS, which abuse common protocols (SSH, ICMP, DNS, GTP) for persistent access and covert C2. GTPDoor, for instance, communicates C2 traffic over GTP-C signaling messages on UDP port 2123. NoDepDNS uses DNS tunneling, encoding commands in DNS question fields and receiving XOR-encoded bash commands in IP addresses within DNS responses.

Detection Opportunity: Monitor network traffic for unusual activity on telecom-specific ports (e.g., UDP 2123 for GTP-C) and for anomalous DNS queries (e.g., unusually long domain names, high entropy in domain names, or frequent queries to rare/unpopular domains).

```sql
index=* (dest_port=2123 AND proto=udp) OR (dns_query_length > 52 OR dns_query_entropy > 4.5) // network logs/data-stream
| stats count by src_ip, dest_ip, dest_port, dns_query
| where count > 10 (adjust thresholds as needed)
```

Privilege Escalation via Known Vulnerabilities: The threat actor exploits known vulnerabilities such as CVE-2016-5195 (DirtyCoW), CVE-2021-4034 (PwnKit), and CVE-2021-3156 (Baron Samedit) to escalate privileges to root.

Detection Opportunity: Monitor for the execution of known exploit tools (e.g., exploit_userspec.py for CVE-2021-3156) or for suspicious process behavior indicative of privilege escalation (e.g., unexpected changes in user IDs or group IDs, or execution of commands with elevated privileges by non-privileged users).

```sql
index=* (process_name="pkexec" AND command_line="*--help*") OR (process_name="sudo" AND command_line="*exploit_userspec.py*")
```

Defense Evasion Techniques: The group employs various defense evasion techniques, including tunneling traffic over DNS, routing traffic through compromised mobile operators, clearing authentication logs, disguising process names (e.g., mimicking kernel threads like [kpqd] or [watchdog/1], or using httpd -D or dbus- prefixes), timestomping executables, and disabling SELinux.

Detection Opportunity: Monitor for modifications to log files (/var/log/wtmp, /var/log/auth.log, ~/.bash_history), unusual process names (especially those with brackets or mimicking common system services but running from unusual paths), and changes to SELinux enforcement mode.

```sql
index=your_linux_logs (file_path="/var/log/wtmp" OR file_path="/var/log/auth.log" OR file_path="*/.bash_history") AND (action="modified" OR action="deleted") OR (process_name="[kpqd]" OR process_name="[watchdog/1]" OR process_name="httpd -D*" OR process_name="dbus-*") AND NOT (process_path="/usr/sbin/httpd" OR process_path="/usr/bin/dbus-daemon") OR (file_path="/etc/selinux/config" AND action="modified") OR (command_line="*setenforce 0*")
```

Use of Publicly Available Tools: The threat actor utilizes publicly available tools such as Microsocks proxy, Fast Reverse Proxy (FRP), FScan, Responder, and ProxyChains for various purposes including network scanning, proxying, and lateral movement.

Detection Opportunity: Monitor for the execution of these tools, especially from unusual directories or with suspicious command-line arguments. For FScan, look for network scanning activity on ports 22, 80, 135, 139, and 443. For ProxyChains, monitor for its execution to tunnel network traffic.

```sql
index=your_linux_logs (process_name="microsocks" OR process_name="frp" OR process_name="fscan" OR process_name="responder" OR process_name="proxychains*") OR (dest_port IN (22,80,135,139,443) AND action="network_scan")
```

More detailed searches:

### SSH Brute Force
---
```sql
(sourcetype=linux_secure OR sourcetype=sshd OR tag=authentication)
`comment("Filter for SSH authentication events")`
| eval status=case(
    searchmatch("(?i)(failed|invalid|failure)"), "failure",
    searchmatch("(?i)(accepted|opened)"), "success"
  )
`comment("Categorize authentication events as 'success' or 'failure'")`
| where status IN ("failure", "success")
`comment("Group events into 30-minute windows to correlate related activity")`
| bucket _time span=30m
`comment("Calculate statistics for each source IP within the time window")`
| stats
    values(user) as users,
    dc(user) as distinct_user_count,
    count(eval(status="failure")) as failed_logins,
    count(eval(status="success")) as successful_logins
    by _time, src_ip, dest
`comment("The core detection logic: find a source IP with at least one successful login and a high number of failed logins. The failed_logins threshold is a key tuning parameter.")`
| where successful_logins > 0 AND failed_logins > 10
`comment("This detection may generate false positives from misconfigured automated systems, password managers, or vulnerability scanners. Consider tuning the 'failed_logins' threshold or filtering known/trusted source IPs.")`
| rename dest as potential_target
```

### GTPDoor C2
---
```sql
| tstats `summariesonly` count from datamodel=Network_Traffic where All_Traffic.dest_port=2123 AND All_Traffic.transport="udp" by _time, All_Traffic.src_ip, All_Traffic.dest_ip span=5m
`comment("Summarize network traffic to UDP port 2123 (GTP-C), the port used by GTPDoor for C2.")`
| `drop_dm_object_name("All_Traffic")`
| stats count as total_events, dc(src_ip) as distinct_sources, values(src_ip) as src_ips by dest_ip
`comment("Aggregate data per destination host to identify potential implants.")`
| where total_events > 50 AND distinct_sources < 5
`comment("Flag destinations with sustained traffic from a few sources, indicative of C2. Thresholds may need tuning. In networks without legitimate GTP traffic, any event is suspicious.")`
```

### NoDepDNS C2
---
```sql
`comment("This detection identifies potential NoDepDNS C2 activity by analyzing DNS query characteristics.")`
| tstats `summariesonly` values(All_DNS.answer) as answer, count from datamodel=Network_Resolution where nodename = All_DNS by _time, All_DNS.query, All_DNS.src
| `drop_dm_object_name("All_DNS")`
| `comment("Summarize DNS queries, keeping the source, query, and answers.")`
| eval answer_count = mvcount(answer)
| `comment("Count the number of IP addresses in the DNS response, a key indicator for NoDepDNS.")`
| eval query_length = len(query)
| `comment("Calculate the length of the DNS query string.")`
| where (query LIKE "%.nodep" AND answer_count > 1) OR (query_length > 80 AND answer_count > 4)
| `comment("Detects either the specific '.nodep' domain used by the malware or generic DNS tunneling behavior (long queries with multiple A-records).")`
| `comment("False positives may occur from CDNs or load-balanced services. Consider tuning thresholds or allowlisting known domains if noise is high.")`
| stats
    min(_time) as firstTime,
    max(_time) as lastTime,
    values(query) as queries,
    sum(count) as query_count
    by src
| `comment("Aggregate results by source IP to identify systems exhibiting this behavior.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
```

### Privilege Escalation Exploits
---
```sql
`comment("This detection identifies privilege escalation attempts related to specific CVEs mentioned in the CL-STA-0969 campaign.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where
    (Processes.process_name IN ("python","python*") AND Processes.process="*exploit_userspec.py*") OR
    (Processes.process_name="pkexec" AND (Processes.process="pkexec" OR Processes.process="/usr/bin/pkexec"))
    by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
| rename dest as host
| `comment("Identify exploit attempts for CVE-2021-3156 (Baron Samedit) and CVE-2021-4034 (PwnKit).")`
| eval threat_name=case(
    process_name="pkexec", "PwnKit Exploit Attempt (CVE-2021-4034)",
    process_name LIKE "python%", "Baron Samedit Exploit Attempt (CVE-2021-3156)"
  )
| append [
    `comment("Identify post-exploitation artifact (user creation) from CVE-2016-5195 (DirtyCow).")`
    (index=* sourcetype=linux_secure OR sourcetype=linux:audit) ("useradd" OR "new user" OR "user has been created") AND "firefart"
    | stats count min(_time) as firstTime max(_time) as lastTime by host, user
    | eval threat_name="DirtyCow Post-Exploitation Artifact (CVE-2016-5195)", process="useradd firefart", process_name="useradd"
]
| `comment("FP Note: The PwnKit detection (pkexec with no arguments) may trigger on legitimate but unusual admin activity. The Baron Samedit and DirtyCow indicators are high-fidelity. Monitor and tune as needed.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, threat_name, process_name, process, count
```

### Log Tampering
---
```sql
`comment("This detection identifies log tampering and defense evasion techniques based on CL-STA-0969 TTPs.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="touch" AND Processes.process="*-r *") OR (Processes.process="*HISTFILE=/dev/null*") OR (Processes.process="*utmpdump*|*sed*") by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
| rename dest as host
| `comment("Identify process-based tampering: timestomping, history disabling, and log sanitization.")`
| eval threat_name=case(
    process_name="touch", "Timestomping with Touch",
    process LIKE "*HISTFILE=/dev/null*", "Bash History Disabling Attempt",
    process LIKE "*utmpdump*|*sed*", "WTMP Log Sanitization Attempt"
  )
| append [
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.action IN ("deleted", "modified")) AND (Filesystem.file_path IN ("/var/log/wtmp", "/var/log/auth.log", "/var/log/btmp") OR Filesystem.file_path LIKE "%/.bash_history") by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.action
    | `drop_dm_object_name("Filesystem")`
    | rename dest as host, file_path as process
    | `comment("Identify direct file modification or deletion of critical log files.")`
    | eval threat_name="Sensitive Log File Tampering (" + action + ")", process_name="File System Event"
]
| `comment("FP Note: Timestomping (`touch -r`) can be used legitimately in software build scripts. Disabling bash history may be a user preference. Direct modification of system logs is highly suspicious but could be caused by misconfigured log rotation tools. Investigate the user and context of the activity.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, threat_name, process_name, process, count
```

### Process Name Masquerading
---
```sql
`comment("This detection identifies process name masquerading techniques used by CL-STA-0969.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (
    `comment("Detects processes masquerading as kernel threads by checking for bracketed names with a file path on disk.")`
    (Processes.process_name LIKE "[%]" AND Processes.process_name LIKE "%]" AND Processes.process_path!="") OR
    `comment("Detects httpd processes running from non-standard paths.")`
    (Processes.process_name="httpd" AND Processes.process LIKE "%-D%" AND NOT Processes.process_path IN ("/usr/sbin/", "/usr/local/apache2/bin/")) OR
    `comment("Detects dbus-prefixed processes running from non-standard paths.")`
    (Processes.process_name LIKE "dbus-%" AND NOT Processes.process_path="/usr/bin/")
  )
  by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.process_path
| `drop_dm_object_name("Processes")`
| rename dest as host
| `comment("Categorize the type of masquerading technique observed.")`
| eval technique=case(
    process_name LIKE "[%]" AND process_name LIKE "%]", "Kernel Thread Masquerading",
    process_name="httpd", "Apache httpd Masquerading",
    process_name LIKE "dbus-%", "D-Bus Process Masquerading"
  )
| `comment("FP Note: Legitimate custom applications or scripts may use non-standard paths or naming conventions that trigger this rule. Review the process path and binary. The list of legitimate paths for httpd and dbus may need to be tuned for your environment.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, technique, process_name, process, process_path, count
```

### SELinux Disablement
---
```sql
`comment("This detection identifies attempts to disable SELinux, a common defense evasion technique.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="setenforce" AND (Processes.process="* 0" OR Processes.process="* Permissive"))
  by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
| rename dest as host
| eval technique="SELinux Disabled via Command"
| append [
    `comment("Looks for modifications to the SELinux configuration file.")`
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
      from datamodel=Endpoint.Filesystem
      where (Filesystem.file_path="/etc/selinux/config" AND Filesystem.action="modified")
      by Filesystem.dest, Filesystem.user, Filesystem.file_path
    | `drop_dm_object_name("Filesystem")`
    | rename dest as host, file_path as process
    | eval process_name="File Modification", technique="SELinux Disabled via Config File"
]
| `comment("FP Note: System administrators may legitimately disable SELinux for troubleshooting or maintenance. Verify the user and the reason for the change.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, technique, process_name, process, count
```

### FScan Usage
---
```sql
`comment("This detection identifies the execution of FScan, a common reconnaissance tool, or network scanning behavior consistent with its use as seen in the CL-STA-0969 campaign.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name IN ("fscan", "fscan.exe", "catlog"))
  by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
| rename dest as host
| eval technique="FScan Execution Detected", detail=process
| `comment("FP Note: A legitimate tool could be named 'fscan'. Verify the binary's hash and origin if possible. The name 'catlog' is based on a specific sample from the report.")`
| append [
    `comment("This part detects network scanning activity on ports commonly targeted by FScan.")`
    | tstats `summariesonly` dc(All_Traffic.dest_ip) as scanned_hosts
      from datamodel=Network_Traffic
      where All_Traffic.action="allowed" AND All_Traffic.dest_port IN (22, 80, 135, 139, 443)
      by _time span=10m, All_Traffic.src_ip, All_Traffic.dest_port
    | `drop_dm_object_name("All_Traffic")`
    | where scanned_hosts > 20 `comment("A single source connecting to over 20 distinct hosts on a specific port in 10 minutes is considered a scan. This threshold is a key tuning parameter.")`
    | stats min(_time) as firstTime, max(_time) as lastTime, values(dest_port) as scanned_ports, sum(scanned_hosts) as total_scanned_hosts by src_ip
    | rename src_ip as host
    | eval technique="Network Scan on FScan Ports", detail="Scanned " + total_scanned_hosts + " hosts on ports: " + mvjoin(scanned_ports, ", "), user="N/A", process_name="Network Traffic", process="Port Scan"
    | `comment("FP Note: Legitimate vulnerability scanners, asset management tools, or network monitoring solutions can generate this behavior. Consider allowlisting known scanner IPs to reduce noise.")`
]
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, technique, process_name, process, detail, count
```

### ProxyChains Usage
---
```sql
`comment("This detection identifies the execution of ProxyChains, a tool used to redirect network connections through proxy servers, often to conceal the origin of network traffic as seen in the CL-STA-0969 campaign.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name = "proxychains" OR Processes.process_name = "proxychains4")
  by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
| rename dest as host
| `comment("FP Note: ProxyChains can be used legitimately by network administrators or developers. Investigate the user and the full command line to determine if the activity is authorized. Usage combined with tools like 'sshpass' or 'scp' for lateral movement is highly suspicious.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, process_name, process, count
```

### AuthDoor Hash
---
```sql
`comment("This detection identifies the presence of the AuthDoor backdoor by its known SHA256 hash. AuthDoor is a PAM backdoor used by CL-STA-0969 for persistent access.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.hash IN ("540f60702ee5019cd2b39b38b07e17da69bde1f9ed3b4543ff26e9da7ba6e0be", "cd754125657f1d52c08f9274fda57600e12929847eee3f7bea2e60ca5ba7711d")
  by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.hash
| `drop_dm_object_name("Processes")`
| rename dest as host
| `comment("FP Note: This is a high-fidelity detection based on a specific hash. A match is a strong indicator of compromise. No false positives are expected.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, process_name, process, hash, count
```

### GTPDoor Hash
---
```sql
`comment("This detection identifies the presence of the GTPDoor backdoor by its known SHA256 hash. GTPDoor is a backdoor used by CL-STA-0969 for C2 over GTP-C.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.hash = "827f41fc1a6f8a4c8a8575b3e2349aeaba0dfc2c9390ef1cceeef1bb85c34161"
  by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.hash
| `drop_dm_object_name("Processes")`
| rename dest as host
| `comment("FP Note: This is a high-fidelity detection based on a specific hash. A match is a strong indicator of compromise. No false positives are expected.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, process_name, process, hash, count
```

### ChronosRAT Hash
---
```sql
`comment("This detection identifies the presence of the ChronosRAT backdoor by its known SHA256 hash. ChronosRAT is a backdoor used by CL-STA-0969.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.hash = "432125ca41a2c5957013c8bff09c4037ad18addccab872d46230dd662a2b8123"
  by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.hash
| `drop_dm_object_name("Processes")`
| rename dest as host
| `comment("FP Note: This is a high-fidelity detection based on a specific hash. A match is a strong indicator of compromise. No false positives are expected.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, process_name, process, hash, count
```

### NoDepDNS Hash
---
```sql
`comment("This detection identifies the presence of the NoDepDNS backdoor by its known SHA256 hash. NoDepDNS is a backdoor used by CL-STA-0969 that leverages DNS for C2.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.hash = "aa661e149f0a6a9a61cadcca47a83893a9e6a5cdb41c3b075175da28e641a80f"
  by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.hash
| `drop_dm_object_name("Processes")`
| rename dest as host
| `comment("FP Note: This is a high-fidelity detection based on a specific hash. A match is a strong indicator of compromise. No false positives are expected.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, process_name, process, hash, count
```

### PwnKit Exploit Hash
---
```sql
`comment("This detection identifies the PwnKit exploit tool by its known SHA256 hash. PwnKit is used to exploit CVE-2021-4034 for privilege escalation.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.hash = "44e83f84a5d5219e2f7c3cf1e4f02489cae81361227f46946abe4b8d8245b879"
  by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.hash
| `drop_dm_object_name("Processes")`
| rename dest as host
| `comment("FP Note: This is a high-fidelity detection based on a specific hash. A match is a strong indicator of compromise. No false positives are expected.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, process_name, process, hash, count
```

### CVE-2021-3156 Exploit Hash
---
```sql
`comment("This detection identifies the execution of a known exploit script for CVE-2021-3156 (sudo heap-based buffer overflow) by its SHA256 hash.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.hash = "b1e473dd70732ba34b7e985422bfd44f3883379569d89bee523f4263c7070fd9"
  by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.hash
| `drop_dm_object_name("Processes")`
| rename dest as host
| `comment("FP Note: This is a high-fidelity detection based on a specific hash. A match is a strong indicator of compromise. No false positives are expected.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, process_name, process, hash, count
```

### FScan Hash
---
```sql
`comment("This detection identifies the execution of the FScan tool by its known SHA256 hash, as used by the CL-STA-0969 threat actor.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.hash = "705a035e54ce328227341ff9d55de15f4e16d387829cba26dc948170dac1c70f"
  by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.hash
| `drop_dm_object_name("Processes")`
| rename dest as host
| `comment("FP Note: This is a high-fidelity detection based on a specific hash. A match is a strong indicator of compromise. No false positives are expected.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, process_name, process, hash, count
```

### Responder Hash
---
```sql
`comment("This detection identifies the execution of the Responder tool by its known SHA256 hash, as used by the CL-STA-0969 threat actor.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.hash = "efa04c33b289e97a84ec6ab1f1b161f900ed3b4521a9a69fb6986bd9991ecfc6"
  by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.hash
| `drop_dm_object_name("Processes")`
| rename dest as host
| `comment("FP Note: This is a high-fidelity detection based on a specific hash. A match is a strong indicator of compromise. No false positives are expected.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, process_name, process, hash, count
```

### Microsocks Proxy Hash
---
```sql
`comment("This detection identifies the execution of the Microsocks proxy tool by its known SHA256 hash, as used by the CL-STA-0969 threat actor.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.hash = "3c42194d6c18a480d9a7f3f7550f011c69ff276707e2bae5e6143f7943343f74"
  by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.hash
| `drop_dm_object_name("Processes")`
| rename dest as host
| `comment("FP Note: This is a high-fidelity detection based on a specific hash. A match is a strong indicator of compromise. No false positives are expected.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, process_name, process, hash, count
```

### Fast Reverse Proxy Hash
---
```sql
`comment("This detection identifies the execution of the Fast Reverse Proxy (FRP) tool by its known SHA256 hash, as used by the CL-STA-0969 threat actor.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.hash = "e3b06f860b8584d69a713127f7d3a4ee5f545ad72e41ec71f9e8692c3525efa0"
  by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.hash
| `drop_dm_object_name("Processes")`
| rename dest as host
| `comment("FP Note: This is a high-fidelity detection based on a specific hash. However, FRP can be used for legitimate purposes. Correlate with other suspicious activity to confirm malicious intent.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, process_name, process, hash, count
```

### Cordscan Hashes
---
```sql
`comment("This detection identifies the presence of the Cordscan tool by its known SHA256 hashes. Cordscan is a custom network scanning utility used by CL-STA-0969.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.hash IN ("bacbe2a793d8ddca0a195b67def527e66d280a13a8d4df90b507546b76e87d29", "1852473ca6a0b5d945e989fb65fa481452c108b718f0f6fd7e8202e9d183e707")
  by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.hash
| `drop_dm_object_name("Processes")`
| rename dest as host
| `comment("FP Note: This is a high-fidelity detection based on specific hashes. A match is a strong indicator of compromise. No false positives are expected.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, process_name, process, hash, count
```

### EchoBackdoor Hashes
---
```sql
`comment("This detection identifies the presence of the EchoBackdoor and its related scripts by their known SHA256 hashes. EchoBackdoor is a passive ICMP-based backdoor used by CL-STA-0969.")`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.hash IN ("188861d7f0861103886543eff63a96c314c8262dbf52c6e0cf9372cf1e889d52", "4985de6574ff34009b6c72504af602a21c152ec104b022d6be94e2fec607eb43", "0bb3b4d8b72fec995c56a8a0baf55f2a07d2b361ee127c2b9deced24f67426fd")
  by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.hash
| `drop_dm_object_name("Processes")`
| rename dest as host
| `comment("FP Note: This is a high-fidelity detection based on specific hashes. A match is a strong indicator of compromise. No false positives are expected.")`
| `ctime(firstTime)`
| `ctime(lastTime)`
| table firstTime, lastTime, host, user, process_name, process, hash, count
```