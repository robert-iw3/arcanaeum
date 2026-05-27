### Linux Persistence Strategies
---

This report details common Linux persistence techniques used by adversaries to maintain access to compromised systems, ranging from basic shell modifications to more robust system-level changes. It provides actionable threat data for detection engineers to create high-fidelity detection rules.

Recent intelligence highlights the continued abuse of established Linux persistence mechanisms, with a focus on blending in with legitimate system activities and leveraging common utilities like systemd timers and cron jobs for stealth and reliability. Adversaries are also observed patching exploited vulnerabilities post-compromise to secure their exclusive foothold and obscure initial access techniques.

### Actionable Threat Data
---

Suspicious Process Execution with nohup and Reverse Shells: Monitor for nohup commands combined with bash -c and network redirection to /dev/tcp or /dev/udp, indicating an attempt to establish a persistent reverse shell that survives terminal closure. This aligns with MITRE ATT&CK T1059.004 (Command and Scripting Interpreter: Unix Shell) and T1546.004 (Event Triggered Execution: Unix Shell Configuration Modification).

Modification of User Shell Configuration Files: Detect modifications to user-specific shell configuration files such as ~/.bashrc, ~/.bash_profile, or ~/.profile that include commands for reverse shells or other malicious payloads. This is a common technique for persistence that triggers upon user login or new shell sessions.

Creation or Modification of systemd Service Units: Look for new or altered .service files in /etc/systemd/system/, ~/.config/systemd/user/, or other systemd unit paths, especially those with ExecStart commands initiating reverse shells or suspicious binaries, and Restart=always directives. This maps to MITRE ATT&CK T1543.002 (Create or Modify System Process: Systemd Service).

New or Modified cron Jobs: Monitor for the creation or modification of cron job entries in /etc/crontab, /etc/cron.d/, /var/spool/cron/crontabs/, or user-specific crontab files that execute suspicious commands or scripts at regular intervals. This corresponds to MITRE ATT&CK T1053.003 (Scheduled Task/Job: Cron).

Unexpected Outbound Network Connections: Identify unusual outbound connections from processes or users that typically do not initiate external communication, especially on common reverse shell ports (e.g., 4444, 8080, 80, 443, 53) or to suspicious external IP addresses. This can indicate an active reverse shell or C2 communication.

### Nohup Reverse Shell
---
```sql
-- Name: Linux Nohup Reverse Shell Persistence
-- Author: RW
-- Date: 2025-08-20

-- MITRE ATT&CK:
-- - T1059.004: Command and Scripting Interpreter: Unix Shell
-- - T1546.004: Event Triggered Execution: Unix Shell Configuration Modification

-- Description:
-- This detection rule identifies a Linux persistence technique where 'nohup' is used to execute a reverse shell.
-- The use of 'nohup' ensures the process continues running even if the originating terminal session is closed.
-- The command pattern includes 'bash -c' to execute a script string and '/dev/tcp/' or '/dev/udp/' for network redirection,
-- which are common components of a shell-based reverse shell.

-- Data Source:
-- This rule requires process execution data from Linux endpoints, mapped to ECS fields (e.g., from Elastic Defend or Sysmon for Linux).
-- Optimized for efficiency by using targeted index patterns and avoiding unnecessary wildcards in LIKE clauses where possible.
-- For high-fidelity detection, focus on exact matches for process.name and pattern matching on command_line to reduce false positives.

-- False Positives:
-- While this pattern is highly suspicious, some legitimate administrative or custom scripts might use 'nohup' with network-aware bash commands.
-- These instances are expected to be rare. If false positives occur, consider adding filters based on user.name, host.name, or specific command_line patterns
-- known to be benign in your environment. A placeholder for such filtering is included below.

FROM logs-endpoint.events.process-*  -- Target process events index for optimization; adjust based on your setup (e.g., logs-* for broader scope)
| WHERE process.name == "nohup" AND process.command_line LIKE "%bash -c%" AND (process.command_line LIKE "%/dev/tcp/%" OR process.command_line LIKE "%/dev/udp/%")
| STATS count = COUNT(), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp) BY host.name, user.name, process.parent.name, process.name, process.command_line
| EVAL firstTime = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", firstTime), lastTime = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", lastTime)
-- (Optional) Filter out known false positives. Uncomment and modify as needed.
-- | WHERE NOT (user.name == "known_admin_user" AND process.command_line LIKE "%known_script.sh%")
| KEEP firstTime, lastTime, host.name, user.name, process.parent.name, process.name, process.command_line, count
| SORT firstTime DESC
| LIMIT 1000  -- Limit results for performance; adjust based on environment scale
```

### Shell Config Modification
---
```sql
-- Name: Linux Shell Config Modification for Persistence
-- Author: RW
-- Date: 2025-08-20

-- MITRE ATT&CK:
-- - T1546.004: Event Triggered Execution: Unix Shell Configuration Modification

-- Description:
-- Detects attempts to add persistence by writing or appending suspicious commands to common Linux shell configuration files
-- like .bashrc, .profile, or .bash_profile. Adversaries modify these files to execute malicious code, such as a reverse shell,
-- every time a new shell session is started by the user.

-- Data Source:
-- This rule requires process execution data from Linux endpoints, mapped to ECS fields (e.g., from Elastic Defend or Sysmon for Linux).
-- Optimized by combining conditions into efficient LIKE patterns and targeting specific indices to reduce query overhead.

-- False Positives:
-- False positives are unlikely but could occur if administrators use scripts to legitimately modify shell configuration files with commands that resemble reverse shells.
-- If false positives occur, consider excluding known administrative scripts or specific user accounts.

FROM logs-endpoint.events.process-*
| WHERE (process.command_line LIKE "% > %" OR process.command_line LIKE "% >> %")
  AND (process.command_line LIKE "%.bashrc%" OR process.command_line LIKE "%.profile%" OR process.command_line LIKE "%.bash_profile%")
  AND (process.command_line LIKE "%nc %" OR process.command_line LIKE "%netcat%" OR process.command_line LIKE "%/dev/tcp/%" OR process.command_line LIKE "%/dev/udp/%" OR process.command_line LIKE "%bash -i%" OR process.command_line LIKE "%python%import socket%" OR process.command_line LIKE "%perl%use Socket%")
| STATS count = COUNT(), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp) BY host.name, user.name, process.parent.name, process.name, process.command_line
| EVAL firstTime = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", firstTime), lastTime = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", lastTime)
-- (Optional) Filter out known false positives.
-- | WHERE NOT (user.name == "known_admin" AND process.command_line LIKE "%legit_script.sh%")
| KEEP firstTime, lastTime, host.name, user.name, process.parent.name, process.name, process.command_line, count
| SORT firstTime DESC
| LIMIT 1000
```

### Systemd Service Persistence
---
```sql
-- Name: Linux Systemd Service Persistence
-- Author: RW
-- Date: 2025-08-20

-- MITRE ATT&CK:
-- - T1543.002: Create or Modify System Process: Systemd Service

-- Description:
-- Detects the creation of a suspicious systemd service file, a common Linux persistence technique.
-- This rule looks for command-line activity where a process writes content containing both persistence parameters (like 'Restart=always')
-- and reverse shell indicators (like '/dev/tcp/') into a .service file in a standard systemd path.

-- Data Source:
-- This rule requires process execution data from Linux endpoints, mapped to ECS fields.
-- Optimized with precise LIKE patterns to avoid scanning unnecessary data.

-- False Positives:
-- False positives are possible if legitimate administrative scripts create service files using command-line redirection and happen to contain keywords that overlap with this rule's logic.
-- However, the combination of a persistence directive and a reverse shell indicator in the same command is highly suspicious.
-- If false positives occur, consider excluding known administrative scripts or specific user accounts.

FROM logs-endpoint.events.process-*
| WHERE (process.command_line LIKE "% > %" OR process.command_line LIKE "% >> %" OR process.name == "tee")
  AND (process.command_line LIKE "%/etc/systemd/system/%.service%" OR process.command_line LIKE "%/.config/systemd/user/%.service%")
  AND (process.command_line LIKE "%Restart=always%" OR process.command_line LIKE "%Restart=on-failure%")
  AND (process.command_line LIKE "%/dev/tcp/%" OR process.command_line LIKE "%/dev/udp/%" OR process.command_line LIKE "%nc %" OR process.command_line LIKE "%netcat %" OR process.command_line LIKE "%bash -i%")
| STATS count = COUNT(), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp) BY host.name, user.name, process.parent.name, process.name, process.command_line
| EVAL firstTime = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", firstTime), lastTime = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", lastTime)
-- (Optional) Filter out known false positives.
-- | WHERE NOT (user.name == "known_admin" AND process.command_line LIKE "%legit_service_installer.sh%")
| KEEP firstTime, lastTime, host.name, user.name, process.parent.name, process.name, process.command_line, count
| SORT firstTime DESC
| LIMIT 1000
```

### Cron Job Persistence
---
```sql
-- Name: Linux Cron Job Persistence for Reverse Shell
-- Author: RW
-- Date: 2025-08-20

-- MITRE ATT&CK:
-- - T1053.003: Scheduled Task/Job: Cron

-- Description:
-- Detects the creation or modification of a cron job intended to establish persistence with a reverse shell.
-- This rule identifies command-line activity that either uses the 'crontab' utility or writes directly to cron-related
-- files, while also containing common reverse shell patterns.

-- Data Source:
-- This rule requires process execution data from Linux endpoints, mapped to ECS fields.
-- Optimized by grouping conditions logically to enable query planner efficiencies.

-- False Positives:
-- False positives are unlikely, as the combination of cron modification and reverse shell syntax in a single command is highly indicative of malicious intent.
-- However, some non-standard administrative scripts could trigger this detection. If false positives occur, consider excluding known scripts or users.

FROM logs-endpoint.events.process-*
| WHERE (process.name == "crontab" OR ((process.command_line LIKE "% > %" OR process.command_line LIKE "% >> %") AND (process.command_line LIKE "%/etc/cron%" OR process.command_line LIKE "%/var/spool/cron%")))
  AND (process.command_line LIKE "%/dev/tcp/%" OR process.command_line LIKE "%/dev/udp/%" OR process.command_line LIKE "%nc %" OR process.command_line LIKE "%netcat %" OR process.command_line LIKE "%bash -i%")
| STATS count = COUNT(), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp) BY host.name, user.name, process.parent.name, process.name, process.command_line
| EVAL firstTime = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", firstTime), lastTime = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", lastTime)
-- (Optional) Filter out known false positives.
-- | WHERE NOT (user.name == "known_admin" AND process.command_line LIKE "%legit_cron_script.sh%")
| KEEP firstTime, lastTime, host.name, user.name, process.parent.name, process.name, process.command_line, count
| SORT firstTime DESC
| LIMIT 1000
```

### Unexpected Outbound Connection
---
```sql
-- Name: Unexpected Outbound Connection from Shell or Scripting Process
-- Author: RW
-- Date: 2025-08-20

-- MITRE ATT&CK:
-- - T1071: Application Layer Protocol
-- - T1571: Non-Standard Port

-- Description:
-- Detects outbound network connections from common shell interpreters and scripting engines.
-- Adversaries frequently use these processes to establish reverse shells or communicate with Command and Control (C2) infrastructure.
-- This rule flags connections on ports commonly used for C2, including standard web ports (80, 443) that can be used for masquerading.

-- Data Source:
-- This rule requires network traffic data with process context, mapped to ECS fields (e.g., from Elastic Defend).
-- Optimized for detection quality by using IN operators for exact matches on ports and process names, reducing false positives from broad scans.

-- False Positives:
-- This detection may trigger on legitimate administrative scripts, software installers, or package managers (e.g., pip, gem) that use scripting engines to fetch resources over HTTP/S.
-- Tuning is essential. Consider excluding known-good source/destination pairs, trusted scripts, or specific user accounts that perform such actions regularly.

FROM logs-endpoint.events.network-*
| WHERE network.direction == "outbound" AND destination.port IN (4444, 8080, 53, 80, 443)
  AND (
    process.name IN ("bash", "sh", "zsh", "ksh", "csh", "perl", "php", "ruby", "pwsh", "nc", "netcat", "ncat")
    OR process.name LIKE "python%"
  )
| STATS count = COUNT(), firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), process_name = VALUES(process.name) BY destination.ip, source.ip, user.name, destination.port
| EVAL firstTime = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", firstTime), lastTime = DATE_FORMAT("yyyy-MM-dd'T'HH:mm:ss.SSSZ", lastTime)
-- (Optional) Filter out known false positives.
-- | WHERE NOT (user.name == "known_admin" AND destination.ip == "known_destination_ip")
| KEEP firstTime, lastTime, source.ip, user.name, process_name, destination.ip, destination.port, count
| SORT firstTime DESC
| LIMIT 1000
```