### The Covert Operator's Playbook: Infiltration of Global Telecom Networks
---

The CL-STA-0969 activity cluster, assessed with high confidence to be a nation-state adversary, has been actively targeting global telecommunications networks, particularly in Southwest Asia, between February and November 2024. This threat actor, overlapping with groups like Liminal Panda, UNC3886, UNC2891, and UNC1945, demonstrates a deep understanding of telecom protocols and infrastructure, employing custom tools and sophisticated defense evasion techniques to maintain persistent and stealthy access.

Recent intelligence confirms Liminal Panda's continued focus on telecommunications, leveraging compromised servers to infiltrate additional providers across various geographic regions and utilizing GSM protocols for C2 communications and data exfiltration. This highlights an evolving threat where initial compromises are used as jumping-off points for wider network infiltration, emphasizing the need for enhanced inter-provider security measures.

### Actionable Threat Data
---

SSH Brute Force and Account Compromise: The threat actor gains initial access primarily through SSH brute-force attacks, utilizing well-tuned account dictionaries that include built-in telecommunications equipment accounts.

Detection Opportunity: Monitor for a high volume of failed SSH login attempts from a single source IP address or against multiple accounts within a short timeframe. Look for successful SSH logins immediately following multiple failed attempts.

Custom Backdoors and C2 over Telecom Protocols: The adversary deploys custom backdoors like AuthDoor, GTPDoor, ChronosRAT, and NoDepDNS, which abuse common protocols (SSH, ICMP, DNS, GTP) for persistent access and covert C2. GTPDoor, for instance, communicates C2 traffic over GTP-C signaling messages on UDP port 2123. NoDepDNS uses DNS tunneling, encoding commands in DNS question fields and receiving XOR-encoded bash commands in IP addresses within DNS responses.

Detection Opportunity: Monitor network traffic for unusual activity on telecom-specific ports (e.g., UDP 2123 for GTP-C) and for anomalous DNS queries (e.g., unusually long domain names, high entropy in domain names, or frequent queries to rare/unpopular domains).

Privilege Escalation via Known Vulnerabilities: The threat actor exploits known vulnerabilities such as CVE-2016-5195 (DirtyCoW), CVE-2021-4034 (PwnKit), and CVE-2021-3156 (Baron Samedit) to escalate privileges to root.

Detection Opportunity: Monitor for the execution of known exploit tools (e.g., exploit_userspec.py for CVE-2021-3156) or for suspicious process behavior indicative of privilege escalation (e.g., unexpected changes in user IDs or group IDs, or execution of commands with elevated privileges by non-privileged users).

Defense Evasion Techniques: The group employs various defense evasion techniques, including tunneling traffic over DNS, routing traffic through compromised mobile operators, clearing authentication logs, disguising process names (e.g., mimicking kernel threads like [kpqd] or [watchdog/1], or using httpd -D or dbus- prefixes), timestomping executables, and disabling SELinux.

Detection Opportunity: Monitor for modifications to log files (/var/log/wtmp, /var/log/auth.log, ~/.bash_history), unusual process names (especially those with brackets or mimicking common system services but running from unusual paths), and changes to SELinux enforcement mode.

Use of Publicly Available Tools: The threat actor utilizes publicly available tools such as Microsocks proxy, Fast Reverse Proxy (FRP), FScan, Responder, and ProxyChains for various purposes including network scanning, proxying, and lateral movement.

Detection Opportunity: Monitor for the execution of these tools, especially from unusual directories or with suspicious command-line arguments. For FScan, look for network scanning activity on ports 22, 80, 135, 139, and 443. For ProxyChains, monitor for its execution to tunnel network traffic.

### SSH Brute Force
---
```sql
FROM * // replace with your index/data-stream
| WHERE
  @timestamp IS NOT NULL
  AND (event.dataset IN ("linux.secure", "sshd") OR event.category == "authentication")
  AND event.outcome IN ("success", "failure")
| EVAL
  status = CASE(
    event.outcome == "success" OR event.action LIKE "%accepted%" OR event.action LIKE "%opened%", "success",
    event.outcome == "failure" OR event.action LIKE "%failed%" OR event.action LIKE "%invalid%", "failure",
    NULL
  )
| WHERE status IN ("success", "failure")
| STATS
  users = ARRAY_DISTINCT(VALUES(user.name)),
  distinct_user_count = COUNT_DISTINCT(user.name),
  failed_logins = COUNT(CASE(status == "failure", 1, NULL)),
  successful_logins = COUNT(CASE(status == "success", 1, NULL))
  BY
  BUCKET(@timestamp, 30 minutes) AS _time,
  source.ip,
  destination.ip AS potential_target
| WHERE successful_logins > 0 AND failed_logins > 10
| SORT _time DESC
```

### GTPDoor C2
---
```sql
FROM *
| WHERE
  @timestamp IS NOT NULL
  AND destination.port == 2123
  AND network.transport == "udp"
| STATS
  total_events = COUNT(*),
  distinct_sources = COUNT_DISTINCT(source.ip),
  src_ips = ARRAY_DISTINCT(VALUES(source.ip))
  BY
  BUCKET(@timestamp, 5 minutes) AS _time,
  destination.ip
| WHERE total_events > 50 AND distinct_sources < 5
| SORT _time DESC
```

### NoDepDNS C2
---
```sql
FROM *
| WHERE
  @timestamp IS NOT NULL
  AND event.category == "dns"
| EVAL
  answer_count = ARRAY_LENGTH(dns.resolved_ip),
  query_length = LENGTH(dns.question.name)
| WHERE
  (dns.question.name LIKE "%.nodep" AND answer_count > 1)
  OR (query_length > 80 AND answer_count > 4)
| STATS
  firstTime = MIN(@timestamp),
  lastTime = MAX(@timestamp),
  queries = ARRAY_DISTINCT(VALUES(dns.question.name)),
  query_count = SUM(event.count)
  BY source.ip AS src
| EVAL
  firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss'Z'"),
  lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss'Z'")
| SORT firstTime DESC
```

### Privilege Escalation Exploits
---
```sql
FROM *
| WHERE
  @timestamp IS NOT NULL
  AND (
    (process.name IN ("python", "python2", "python3") AND process.command_line LIKE "%exploit_userspec.py%")
    OR
    (process.name == "pkexec" AND (process.command_line == "pkexec" OR process.command_line LIKE "%/usr/bin/pkexec%"))
    OR
    (event.dataset IN ("linux.secure", "linux.audit") AND event.action LIKE "%useradd%" OR event.action LIKE "%new user%" OR event.action LIKE "%user has been created%" AND event.action LIKE "%firefart%")
  )
| EVAL
  threat_name = CASE(
    process.name == "pkexec", "PwnKit Exploit Attempt (CVE-2021-4034)",
    process.name LIKE "python%", "Baron Samedit Exploit Attempt (CVE-2021-3156)",
    event.action LIKE "%useradd%" OR event.action LIKE "%new user%" OR event.action LIKE "%user has been created%", "DirtyCow Post-Exploitation Artifact (CVE-2016-5195)",
    NULL
  ),
  process_name = COALESCE(process.name, "useradd"),
  process = CASE(
    event.action LIKE "%useradd%" OR event.action LIKE "%new user%" OR event.action LIKE "%user has been created%", "useradd firefart",
    process.command_line
  )
| STATS
  firstTime = MIN(@timestamp),
  lastTime = MAX(@timestamp),
  count = COUNT(*)
  BY host.name AS host, user.name AS user, threat_name, process_name, process
| EVAL
  firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss'Z'"),
  lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss'Z'")
| KEEP firstTime, lastTime, host, user, threat_name, process_name, process, count
| SORT firstTime DESC
```

### Log Tampering
---
```sql
FROM *
| WHERE
  @timestamp IS NOT NULL
  AND (
    (process.name == "touch" AND process.command_line LIKE "%-r %")
    OR (process.command_line LIKE "%HISTFILE=/dev/null%")
    OR (process.command_line LIKE "%utmpdump%|%sed%")
    OR (
      event.category == "file"
      AND event.action IN ("deleted", "modified")
      AND file.path IN ("/var/log/wtmp", "/var/log/auth.log", "/var/log/btmp", "%/.bash_history")
    )
  )
| EVAL
  threat_name = CASE(
    process.name == "touch", "Timestomping with Touch",
    process.command_line LIKE "%HISTFILE=/dev/null%", "Bash History Disabling Attempt",
    process.command_line LIKE "%utmpdump%|%sed%", "WTMP Log Sanitization Attempt",
    event.category == "file", "Sensitive Log File Tampering (" + event.action + ")",
    NULL
  ),
  process_name = COALESCE(process.name, "File System Event"),
  process = COALESCE(process.command_line, file.path)
| STATS
  firstTime = MIN(@timestamp),
  lastTime = MAX(@timestamp),
  count = COUNT(*)
  BY
  host.name AS host,
  user.name AS user,
  threat_name,
  process_name,
  process
| EVAL
  firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss'Z'"),
  lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss'Z'")
| KEEP
  firstTime, lastTime, host, user, threat_name, process_name, process, count
| SORT firstTime DESC
```

### Process Name Masquerading
---
```sql
FROM *
| WHERE
  @timestamp IS NOT NULL
  AND event.category == "process"
  AND (
    (process.name LIKE "[%]" AND process.name LIKE "%]" AND process.executable != "")
    OR (process.name == "httpd" AND process.command_line LIKE "%-D%"
        AND process.executable NOT IN ("/usr/sbin/*", "/usr/local/apache2/bin/*"))
    OR (process.name LIKE "dbus-%" AND process.executable != "/usr/bin/*")
  )
| EVAL
  technique = CASE(
    process.name LIKE "[%]" AND process.name LIKE "%]", "Kernel Thread Masquerading",
    process.name == "httpd", "Apache httpd Masquerading",
    process.name LIKE "dbus-%", "D-Bus Process Masquerading",
    NULL
  )
| STATS
  firstTime = MIN(@timestamp),
  lastTime = MAX(@timestamp),
  count = COUNT(*)
  BY
  host.name AS host,
  user.name AS user,
  technique,
  process.name AS process_name,
  process.command_line AS process,
  process.executable AS process_path
| EVAL
  firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss'Z'"),
  lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss'Z'")
| KEEP
  firstTime, lastTime, host, user, technique, process_name, process, process_path, count
| SORT firstTime DESC
```

### SELinux Disablement
---
```sql
FROM *
| WHERE
  @timestamp IS NOT NULL
  AND (
    (process.name == "setenforce" AND (process.command_line LIKE "% 0%" OR process.command_line LIKE "%Permissive%"))
    OR (event.category == "file" AND event.action == "modified" AND file.path == "/etc/selinux/config")
  )
| EVAL
  technique = CASE(
    process.name == "setenforce", "SELinux Disabled via Command",
    file.path == "/etc/selinux/config", "SELinux Disabled via Config File",
    NULL
  ),
  process_name = COALESCE(process.name, "File Modification"),
  process = COALESCE(process.command_line, file.path)
| STATS
  firstTime = MIN(@timestamp),
  lastTime = MAX(@timestamp),
  count = COUNT(*)
  BY
  host.name AS host,
  user.name AS user,
  technique,
  process_name,
  process
| EVAL
  firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss'Z'"),
  lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss'Z'")
| KEEP
  firstTime, lastTime, host, user, technique, process_name, process, count
| SORT firstTime DESC
```

### FScan Usage
---
```sql
FROM *
| WHERE
  @timestamp IS NOT NULL
  AND (
    (event.category == "process"
     AND process.name IN ("fscan", "fscan.exe", "catlog"))
    OR (event.category == "network"
        AND network.direction == "outbound"
        AND event.action == "allowed"
        AND destination.port IN (22, 80, 135, 139, 443))
  )
| EVAL
  technique = CASE(
    process.name IN ("fscan", "fscan.exe", "catlog"), "FScan Execution Detected",
    event.category == "network", "Network Scan on FScan Ports",
    NULL
  ),
  process_name = COALESCE(process.name, "Network Traffic"),
  process = COALESCE(process.command_line, "Port Scan"),
  detail = CASE(
    process.name IN ("fscan", "fscan.exe", "catlog"), process.command_line,
    event.category == "network", "Scanned " + TO_STRING(COUNT_DISTINCT(destination.ip)) + " hosts on ports: " + ARRAY_JOIN(ARRAY_DISTINCT(VALUES(destination.port)), ", "),
    NULL
  ),
  user = COALESCE(user.name, "N/A")
| STATS
  firstTime = MIN(@timestamp),
  lastTime = MAX(@timestamp),
  count = COUNT(*),
  scanned_hosts = COUNT_DISTINCT(destination.ip) WHEN event.category == "network",
  scanned_ports = ARRAY_DISTINCT(VALUES(destination.port)) WHEN event.category == "network"
  BY
  host.name AS host,
  user,
  technique,
  process_name,
  process,
  detail
| WHERE
  (technique == "FScan Execution Detected")
  OR (technique == "Network Scan on FScan Ports" AND scanned_hosts > 20)
| EVAL
  firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss'Z'"),
  lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss'Z'"),
  detail = CASE(
    technique == "Network Scan on FScan Ports",
    "Scanned " + TO_STRING(scanned_hosts) + " hosts on ports: " + ARRAY_JOIN(scanned_ports, ", "),
    detail
  )
| KEEP
  firstTime, lastTime, host, user, technique, process_name, process, detail, count
| SORT firstTime DESC
```

### ProxyChains Usage
---
```sql
FROM *
| WHERE
  @timestamp IS NOT NULL
  AND event.category == "process"
  AND process.name == "proxychains" OR process.name == "proxychains4"
| STATS
  firstTime = MIN(@timestamp),
  lastTime = MAX(@timestamp),
  count = COUNT(*)
  BY
  host.name AS host,
  user.name AS user,
  process.name AS process_name,
  process.command_line AS process
| EVAL
  firstTime = TO_STRING(firstTime, "yyyy-MM-dd'T'HH:mm:ss'Z'"),
  lastTime = TO_STRING(lastTime, "yyyy-MM-dd'T'HH:mm:ss'Z'")
| KEEP
  firstTime, lastTime, host, user, process_name, process, count
| SORT firstTime DESC
```