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
-- This rule requires process execution data from Linux endpoints, mapped to the Splunk Common Information Model (CIM), Endpoint.Processes data model.
-- This can be sourced from tools like Sysmon for Linux, auditd, or various EDR agents.

-- False Positives:
-- While this pattern is highly suspicious, some legitimate administrative or custom scripts might use 'nohup' with network-aware bash commands.
-- These instances are expected to be rare. If false positives occur, consider adding filters based on user, host, or specific command-line arguments
-- known to be benign in your environment. A placeholder for such filtering is included below.

-- Search for process execution events using the CIM Endpoint.Processes data model for efficiency.
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
-- The core detection logic looks for the specific combination of nohup, bash, and network redirection.
where Processes.process_name=nohup AND Processes.process="*bash -c*" AND (Processes.process="*/dev/tcp/*" OR Processes.process="*/dev/udp/*")
by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process

-- Rename fields for better readability in the final output.
| rename "Processes.*" as *

-- Convert epoch timestamps to a human-readable format.
| convert ctime(firstTime) ctime(lastTime)

-- (Optional) Filter out known false positives. Uncomment and modify the line below as needed.
-- | where NOT (user="known_admin_user" AND process="*known_script.sh*")

-- Structure the final output table with relevant fields for investigation.
| table firstTime, lastTime, dest, user, parent_process, process_name, process, count
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
-- This rule requires process execution data from Linux endpoints, mapped to the Splunk Common Information Model (CIM), Endpoint.Processes data model.
-- This can be sourced from tools like Sysmon for Linux, auditd, or various EDR agents.

-- False Positives:
-- False positives are unlikely but could occur if administrators use scripts to legitimately modify shell configuration files with commands that resemble reverse shells.
-- If false positives occur, consider excluding known administrative scripts or specific user accounts.

-- Search for process execution events using the CIM Endpoint.Processes data model.
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
-- Filter for command-lines that write or append to common shell configuration files.
where (Processes.process="* > *" OR Processes.process="* >> *")
  AND (Processes.process="*.bashrc*" OR Processes.process="*.profile*" OR Processes.process="*.bash_profile*")
  -- Look for keywords commonly associated with reverse shells being written to the file.
  AND (Processes.process="*nc *" OR Processes.process="*netcat*" OR Processes.process="*/dev/tcp/*" OR Processes.process="*/dev/udp/*" OR Processes.process="*bash -i*" OR Processes.process="*python*import socket*" OR Processes.process="*perl*use Socket*")
by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process

-- Rename fields for better readability.
| rename "Processes.*" as *

-- Convert epoch timestamps to a human-readable format.
| convert ctime(firstTime) ctime(lastTime)

-- (Optional) Filter out known false positives.
-- | where NOT (user="known_admin" AND process="*legit_script.sh*")

-- Structure the final output table.
| table firstTime, lastTime, dest, user, parent_process, process_name, process, count
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
-- This rule requires process execution data from Linux endpoints, mapped to the Splunk Common Information Model (CIM), Endpoint.Processes data model.
-- This can be sourced from tools like Sysmon for Linux, auditd, or various EDR agents.

-- False Positives:
-- False positives are possible if legitimate administrative scripts create service files using command-line redirection and happen to contain keywords that overlap with this rule's logic.
-- However, the combination of a persistence directive and a reverse shell indicator in the same command is highly suspicious.
-- If false positives occur, consider excluding known administrative scripts or specific user accounts.

-- Search for process execution events using the CIM Endpoint.Processes data model.
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
-- Filter for processes writing to a .service file in common systemd directories.
where (Processes.process LIKE "% > %" OR Processes.process LIKE "% >> %" OR Processes.process_name="tee")
  AND (Processes.process LIKE "%/etc/systemd/system/%.service%" OR Processes.process LIKE "%/.config/systemd/user/%.service%")
  -- Look for persistence directives like 'Restart=always' being written in the command.
  AND (Processes.process LIKE "%Restart=always%" OR Processes.process LIKE "%Restart=on-failure%")
  -- Concurrently look for common reverse shell patterns being written.
  AND (Processes.process LIKE "%/dev/tcp/%" OR Processes.process LIKE "%/dev/udp/%" OR Processes.process LIKE "%nc %" OR Processes.process LIKE "%netcat %" OR Processes.process LIKE "%bash -i%")
by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process

-- Rename fields for better readability.
| rename "Processes.*" as *

-- Convert epoch timestamps to a human-readable format.
| convert ctime(firstTime) ctime(lastTime)

-- (Optional) Filter out known false positives.
-- | where NOT (user="known_admin" AND process="*legit_service_installer.sh*")

-- Structure the final output table.
| table firstTime, lastTime, dest, user, parent_process, process_name, process, count
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
-- This rule requires process execution data from Linux endpoints, mapped to the Splunk Common Information Model (CIM), Endpoint.Processes data model.
-- This can be sourced from tools like Sysmon for Linux, auditd, or various EDR agents.

-- False Positives:
-- False positives are unlikely, as the combination of cron modification and reverse shell syntax in a single command is highly indicative of malicious intent.
-- However, some non-standard administrative scripts could trigger this detection. If false positives occur, consider excluding known scripts or users.

-- Search for process execution events using the CIM Endpoint.Processes data model.
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
-- Filter for commands that modify cron jobs and contain reverse shell indicators.
where
  -- Detect modification via the crontab utility or direct file writes to cron directories.
  (Processes.process_name="crontab" OR ((Processes.process LIKE "% > %" OR Processes.process LIKE "% >> %") AND (Processes.process LIKE "%/etc/cron%" OR Processes.process LIKE "%/var/spool/cron%")))
  -- Look for common reverse shell patterns within the same command.
  AND (Processes.process LIKE "%/dev/tcp/%" OR Processes.process LIKE "%/dev/udp/%" OR Processes.process LIKE "%nc %" OR Processes.process LIKE "%netcat %" OR Processes.process LIKE "%bash -i%")
by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process

-- Rename fields for better readability.
| rename "Processes.*" as *

-- Convert epoch timestamps to a human-readable format.
| convert ctime(firstTime) ctime(lastTime)

-- (Optional) Filter out known false positives.
-- | where NOT (user="known_admin" AND process="*legit_cron_script.sh*")

-- Structure the final output table.
| table firstTime, lastTime, dest, user, parent_process, process_name, process, count
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
-- This rule requires network traffic data with process context, mapped to the Splunk Common Information Model (CIM), Network_Traffic data model.
-- This is typically sourced from an EDR agent that logs network connections made by processes.

-- False Positives:
-- This detection may trigger on legitimate administrative scripts, software installers, or package managers (e.g., pip, gem) that use scripting engines to fetch resources over HTTP/S.
-- Tuning is essential. Consider excluding known-good source/destination pairs, trusted scripts, or specific user accounts that perform such actions regularly.

-- Search for network traffic events using the CIM Network_Traffic data model.
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.process_name) as process_name from datamodel=Network_Traffic
-- Filter for outbound connections on ports commonly associated with reverse shells or C2.
where All_Traffic.direction="outbound" AND All_Traffic.dest_port IN (4444, 8080, 53, 80, 443)
  -- Filter for connections originating from common shell interpreters or scripting engines.
  AND (
    All_Traffic.process_name IN ("bash", "sh", "zsh", "ksh", "csh", "perl", "php", "ruby", "pwsh", "nc", "netcat", "ncat")
    OR All_Traffic.process_name LIKE "python%"
  )
by All_Traffic.dest All_Traffic.src All_Traffic.user All_Traffic.dest_port

-- Rename fields for better readability.
| rename "All_Traffic.*" as *

-- Convert epoch timestamps to a human-readable format.
| convert ctime(firstTime) ctime(lastTime)

-- (Optional) Filter out known false positives.
-- | where NOT (user="known_admin" AND dest="known_destination_ip")

-- Structure the final output table.
| table firstTime, lastTime, src, user, process_name, dest, dest_port, count
```