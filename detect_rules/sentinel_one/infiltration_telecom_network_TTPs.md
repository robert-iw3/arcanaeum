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
SELECT
  FLOOR(createdAt, "30m") AS _time,
  srcIp AS src_ip,
  dstIp AS potential_target,
  ARRAY_AGG(DISTINCT User) AS users,
  COUNT(DISTINCT User) AS distinct_user_count,
  SUM(CASE WHEN eventType LIKE "%failed%" OR eventType LIKE "%invalid%" THEN 1 ELSE 0 END) AS failed_logins,
  SUM(CASE WHEN eventType LIKE "%accepted%" OR eventType LIKE "%opened%" THEN 1 ELSE 0 END) AS successful_logins
FROM deepvisibility
WHERE
  eventType IN ("ssh_authentication", "linux_secure")
  AND (
    eventType LIKE "%failed%" OR eventType LIKE "%invalid%" OR
    eventType LIKE "%accepted%" OR eventType LIKE "%opened%"
  )
GROUP BY
  FLOOR(createdAt, "30m"),
  srcIp,
  dstIp
HAVING
  successful_logins > 0 AND failed_logins > 10
```

### GTPDoor C2
---
```sql
SELECT
  FLOOR(createdAt, "5m") AS _time,
  dstIp AS dest_ip,
  COUNT(*) AS total_events,
  COUNT(DISTINCT srcIp) AS distinct_sources,
  ARRAY_AGG(DISTINCT srcIp) AS src_ips
FROM deepvisibility
WHERE
  dstPort = 2123
  AND protocol = "udp"
GROUP BY
  FLOOR(createdAt, "5m"),
  dstIp
HAVING
  total_events > 50 AND distinct_sources < 5
```

### NoDepDNS C2
---
```sql
SELECT
  MIN(createdAt) AS firstTime,
  MAX(createdAt) AS lastTime,
  ARRAY_AGG(DISTINCT dnsQuery) AS queries,
  SUM(eventCount) AS query_count,
  srcIp AS src
FROM deepvisibility
WHERE
  eventType = "dns"
  AND (
    (dnsQuery LIKE "%.nodep" AND ARRAY_LENGTH(dnsAnswers) > 1)
    OR (LENGTH(dnsQuery) > 80 AND ARRAY_LENGTH(dnsAnswers) > 4)
  )
GROUP BY srcIp
```

### Privilege Escalation Exploits
---
```sql
SELECT
  MIN(createdAt) AS firstTime,
  MAX(createdAt) AS lastTime,
  AgentName AS host,
  User AS user,
  CASE
    WHEN ProcessName = "pkexec" THEN "PwnKit Exploit Attempt (CVE-2021-4034)"
    WHEN ProcessName LIKE "python%" THEN "Baron Samedit Exploit Attempt (CVE-2021-3156)"
    WHEN eventType LIKE "%useradd%" OR eventType LIKE "%new user%" OR eventType LIKE "%user has been created%" THEN "DirtyCow Post-Exploitation Artifact (CVE-2016-5195)"
  END AS threat_name,
  COALESCE(ProcessName, "useradd") AS process_name,
  CASE
    WHEN eventType LIKE "%useradd%" OR eventType LIKE "%new user%" OR eventType LIKE "%user has been created%" THEN "useradd firefart"
    ELSE ProcessCmd
  END AS process,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  (
    (ProcessName IN ("python", "python2", "python3") AND ProcessCmd LIKE "%exploit_userspec.py%")
    OR
    (ProcessName = "pkexec" AND (ProcessCmd = "pkexec" OR ProcessCmd LIKE "%/usr/bin/pkexec%"))
    OR
    (eventType IN ("linux_secure", "linux_audit") AND (eventType LIKE "%useradd%" OR eventType LIKE "%new user%" OR eventType LIKE "%user has been created%") AND eventType LIKE "%firefart%")
  )
GROUP BY
  AgentName,
  User,
  CASE
    WHEN ProcessName = "pkexec" THEN "PwnKit Exploit Attempt (CVE-2021-4034)"
    WHEN ProcessName LIKE "python%" THEN "Baron Samedit Exploit Attempt (CVE-2021-3156)"
    WHEN eventType LIKE "%useradd%" OR eventType LIKE "%new user%" OR eventType LIKE "%user has been created%" THEN "DirtyCow Post-Exploitation Artifact (CVE-2016-5195)"
  END,
  COALESCE(ProcessName, "useradd"),
  CASE
    WHEN eventType LIKE "%useradd%" OR eventType LIKE "%new user%" OR eventType LIKE "%user has been created%" THEN "useradd firefart"
    ELSE ProcessCmd
  END
```

### Log Tampering
---
```sql
SELECT
  MIN(createdAt) AS firstTime,
  MAX(createdAt) AS lastTime,
  AgentName AS host,
  User AS user,
  CASE
    WHEN ProcessName = "touch" THEN "Timestomping with Touch"
    WHEN ProcessCmd LIKE "%HISTFILE=/dev/null%" THEN "Bash History Disabling Attempt"
    WHEN ProcessCmd LIKE "%utmpdump%|%sed%" THEN "WTMP Log Sanitization Attempt"
    WHEN eventType IN ("file_deleted", "file_modified") THEN "Sensitive Log File Tampering (" + eventType + ")"
  END AS threat_name,
  COALESCE(ProcessName, "File System Event") AS process_name,
  COALESCE(ProcessCmd, filePath) AS process,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  (
    (ProcessName = "touch" AND ProcessCmd LIKE "%-r %")
    OR (ProcessCmd LIKE "%HISTFILE=/dev/null%")
    OR (ProcessCmd LIKE "%utmpdump%|%sed%")
    OR (
      eventType IN ("file_deleted", "file_modified")
      AND filePath IN ("/var/log/wtmp", "/var/log/auth.log", "/var/log/btmp")
      OR filePath LIKE "%/.bash_history"
    )
  )
GROUP BY
  AgentName,
  User,
  CASE
    WHEN ProcessName = "touch" THEN "Timestomping with Touch"
    WHEN ProcessCmd LIKE "%HISTFILE=/dev/null%" THEN "Bash History Disabling Attempt"
    WHEN ProcessCmd LIKE "%utmpdump%|%sed%" THEN "WTMP Log Sanitization Attempt"
    WHEN eventType IN ("file_deleted", "file_modified") THEN "Sensitive Log File Tampering (" + eventType + ")"
  END,
  COALESCE(ProcessName, "File System Event"),
  COALESCE(ProcessCmd, filePath)
```

### Process Name Masquerading
---
```sql
SELECT
  MIN(createdAt) AS firstTime,
  MAX(createdAt) AS lastTime,
  AgentName AS host,
  User AS user,
  CASE
    WHEN ProcessName LIKE "[%]" AND ProcessName LIKE "%]" THEN "Kernel Thread Masquerading"
    WHEN ProcessName = "httpd" THEN "Apache httpd Masquerading"
    WHEN ProcessName LIKE "dbus-%" THEN "D-Bus Process Masquerading"
  END AS technique,
  ProcessName AS process_name,
  ProcessCmd AS process,
  ProcessPath AS process_path,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  (
    (ProcessName LIKE "[%]" AND ProcessName LIKE "%]" AND ProcessPath != "")
    OR (ProcessName = "httpd" AND ProcessCmd LIKE "%-D%"
        AND ProcessPath NOT LIKE "/usr/sbin/%" AND ProcessPath NOT LIKE "/usr/local/apache2/bin/%")
    OR (ProcessName LIKE "dbus-%" AND ProcessPath NOT LIKE "/usr/bin/%")
  )
GROUP BY
  AgentName,
  User,
  CASE
    WHEN ProcessName LIKE "[%]" AND ProcessName LIKE "%]" THEN "Kernel Thread Masquerading"
    WHEN ProcessName = "httpd" THEN "Apache httpd Masquerading"
    WHEN ProcessName LIKE "dbus-%" THEN "D-Bus Process Masquerading"
  END,
  ProcessName,
  ProcessCmd,
  ProcessPath
```

### SELinux Disablement
---
```sql
SELECT
  MIN(createdAt) AS firstTime,
  MAX(createdAt) AS lastTime,
  AgentName AS host,
  User AS user,
  CASE
    WHEN ProcessName = "setenforce" THEN "SELinux Disabled via Command"
    WHEN filePath = "/etc/selinux/config" THEN "SELinux Disabled via Config File"
  END AS technique,
  COALESCE(ProcessName, "File Modification") AS process_name,
  COALESCE(ProcessCmd, filePath) AS process,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  (
    (ProcessName = "setenforce" AND (ProcessCmd LIKE "% 0%" OR ProcessCmd LIKE "%Permissive%"))
    OR (eventType = "file_modified" AND filePath = "/etc/selinux/config")
  )
GROUP BY
  AgentName,
  User,
  CASE
    WHEN ProcessName = "setenforce" THEN "SELinux Disabled via Command"
    WHEN filePath = "/etc/selinux/config" THEN "SELinux Disabled via Config File"
  END,
  COALESCE(ProcessName, "File Modification"),
  COALESCE(ProcessCmd, filePath)
```

### FScan Usage
---
```sql
SELECT
  MIN(createdAt) AS firstTime,
  MAX(createdAt) AS lastTime,
  AgentName AS host,
  COALESCE(User, "N/A") AS user,
  CASE
    WHEN ProcessName IN ("fscan", "fscan.exe", "catlog") THEN "FScan Execution Detected"
    WHEN eventType = "network" THEN "Network Scan on FScan Ports"
  END AS technique,
  COALESCE(ProcessName, "Network Traffic") AS process_name,
  COALESCE(ProcessCmd, "Port Scan") AS process,
  CASE
    WHEN ProcessName IN ("fscan", "fscan.exe", "catlog") THEN ProcessCmd
    WHEN eventType = "network" THEN "Scanned " + CAST(COUNT(DISTINCT dstIp) AS STRING) + " hosts on ports: " + ARRAY_JOIN(ARRAY_AGG(DISTINCT dstPort), ", ")
  END AS detail,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  (
    (ProcessName IN ("fscan", "fscan.exe", "catlog"))
    OR (
      eventType = "network"
      AND networkAction = "allowed"
      AND dstPort IN (22, 80, 135, 139, 443)
    )
  )
GROUP BY
  AgentName,
  COALESCE(User, "N/A"),
  CASE
    WHEN ProcessName IN ("fscan", "fscan.exe", "catlog") THEN "FScan Execution Detected"
    WHEN eventType = "network" THEN "Network Scan on FScan Ports"
  END,
  COALESCE(ProcessName, "Network Traffic"),
  COALESCE(ProcessCmd, "Port Scan"),
  CASE
    WHEN ProcessName IN ("fscan", "fscan.exe", "catlog") THEN ProcessCmd
    WHEN eventType = "network" THEN "Scanned " + CAST(COUNT(DISTINCT dstIp) AS STRING) + " hosts on ports: " + ARRAY_JOIN(ARRAY_AGG(DISTINCT dstPort), ", ")
  END
HAVING
  (technique = "FScan Execution Detected")
  OR (technique = "Network Scan on FScan Ports" AND COUNT(DISTINCT dstIp) > 20)
```

### ProxyChains Usage
---
```sql
SELECT
  MIN(createdAt) AS firstTime,
  MAX(createdAt) AS lastTime,
  AgentName AS host,
  User AS user,
  ProcessName AS process_name,
  ProcessCmd AS process,
  COUNT(*) AS count
FROM deepvisibility
WHERE
  (ProcessName IN ("proxychains", "proxychains4")) THEN "Proxychains Execution Detected"
GROUP BY
  AgentName,
  User,
  ProcessName,
  ProcessCmd
```