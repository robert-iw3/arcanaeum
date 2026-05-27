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
-- This rule requires process execution logs from Linux endpoints ingested into Datadog (e.g., via Datadog Agent with process collection enabled).
-- For optimization, use faceted searches on indexed attributes like @process.name and @process.cmdline to minimize query time and improve detection quality.
-- In the Logs Explorer, group by facets and measure aggregations as described.

-- False Positives:
-- While this pattern is highly suspicious, some legitimate administrative or custom scripts might use 'nohup' with network-aware bash commands.
-- These instances are expected to be rare. If false positives occur, consider adding exclusions based on @usr.name, @host.name, or specific @process.cmdline patterns
-- known to be benign in your environment. A placeholder for such filtering is included below.

-- Log Search Query (use in Datadog Logs Explorer):
source:linux @process.name:nohup @process.cmdline:"*bash -c*" (@process.cmdline:"*/dev/tcp/*" OR @process.cmdline:"*/dev/udp/*")
-- (Optional) Filter out known false positives. Append to query:
-- -@usr.name:known_admin_user -@process.cmdline:"*known_script.sh*"

-- In Logs Explorer:
-- - Group by: @host.name, @usr.name, @process.parent_name, @process.name, @process.cmdline
-- - Measure: count() as count, min(@timestamp) as firstTime, max(@timestamp) as lastTime
-- For human-readable timestamps, use Datadog's formatting options in the UI.
-- Optimize by setting time windows and using indexed facets to reduce scanned data volume.
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
-- This rule requires process execution logs from Linux endpoints ingested into Datadog.
-- Use faceted searches for efficiency.

-- False Positives:
-- False positives are unlikely but could occur if administrators use scripts to legitimately modify shell configuration files with commands that resemble reverse shells.
-- If false positives occur, consider excluding known administrative scripts or specific user accounts.

-- Log Search Query:
source:linux (@process.cmdline:"* > *" OR @process.cmdline:"* >> *") (@process.cmdline:"*.bashrc*" OR @process.cmdline:"*.profile*" OR @process.cmdline:"*.bash_profile*") (@process.cmdline:"*nc *" OR @process.cmdline:"*netcat*" OR @process.cmdline:"*/dev/tcp/*" OR @process.cmdline:"*/dev/udp/*" OR @process.cmdline:"*bash -i*" OR @process.cmdline:"*python*import socket*" OR @process.cmdline:"*perl*use Socket*")
-- (Optional) Filter out known false positives:
-- -@usr.name:known_admin -@process.cmdline:"*legit_script.sh*"

-- In Logs Explorer:
-- - Group by: @host.name, @usr.name, @process.parent_name, @process.name, @process.cmdline
-- - Measure: count() as count, min(@timestamp) as firstTime, max(@timestamp) as lastTime
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
-- This rule requires process execution logs from Linux endpoints ingested into Datadog.

-- False Positives:
-- False positives are possible if legitimate administrative scripts create service files using command-line redirection and happen to contain keywords that overlap with this rule's logic.
-- However, the combination of a persistence directive and a reverse shell indicator in the same command is highly suspicious.
-- If false positives occur, consider excluding known administrative scripts or specific user accounts.

-- Log Search Query:
source:linux (@process.cmdline:"* > *" OR @process.cmdline:"* >> *" OR @process.name:tee) (@process.cmdline:"*/etc/systemd/system/*.service*" OR @process.cmdline:"*/.config/systemd/user/*.service*") (@process.cmdline:"*Restart=always*" OR @process.cmdline:"*Restart=on-failure*") (@process.cmdline:"*/dev/tcp/*" OR @process.cmdline:"*/dev/udp/*" OR @process.cmdline:"*nc *" OR @process.cmdline:"*netcat *" OR @process.cmdline:"*bash -i*")
-- (Optional) Filter out known false positives:
-- -@usr.name:known_admin -@process.cmdline:"*legit_service_installer.sh*"

-- In Logs Explorer:
-- - Group by: @host.name, @usr.name, @process.parent_name, @process.name, @process.cmdline
-- - Measure: count() as count, min(@timestamp) as firstTime, max(@timestamp) as lastTime
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
-- This rule requires process execution logs from Linux endpoints ingested into Datadog.

-- False Positives:
-- False positives are unlikely, as the combination of cron modification and reverse shell syntax in a single command is highly indicative of malicious intent.
-- However, some non-standard administrative scripts could trigger this detection. If false positives occur, consider excluding known scripts or users.

-- Log Search Query:
source:linux (@process.name:crontab OR ((@process.cmdline:"* > *" OR @process.cmdline:"* >> *") AND (@process.cmdline:"*/etc/cron*" OR @process.cmdline:"*/var/spool/cron*"))) (@process.cmdline:"*/dev/tcp/*" OR @process.cmdline:"*/dev/udp/*" OR @process.cmdline:"*nc *" OR @process.cmdline:"*netcat *" OR @process.cmdline:"*bash -i*")
-- (Optional) Filter out known false positives:
-- -@usr.name:known_admin -@process.cmdline:"*legit_cron_script.sh*"

-- In Logs Explorer:
-- - Group by: @host.name, @usr.name, @process.parent_name, @process.name, @process.cmdline
-- - Measure: count() as count, min(@timestamp) as firstTime, max(@timestamp) as lastTime
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
-- This rule requires network traffic logs with process context ingested into Datadog (e.g., via Network Monitoring or EDR integrations).

-- False Positives:
-- This detection may trigger on legitimate administrative scripts, software installers, or package managers (e.g., pip, gem) that use scripting engines to fetch resources over HTTP/S.
-- Tuning is essential. Consider excluding known-good source/destination pairs, trusted scripts, or specific user accounts that perform such actions regularly.

-- Log Search Query:
source:linux @network.direction:outbound @network.destination.port:(4444 OR 8080 OR 53 OR 80 OR 443) (@process.name:(bash OR sh OR zsh OR ksh OR csh OR perl OR php OR ruby OR pwsh OR nc OR netcat OR ncat) OR @process.name:python*)
-- (Optional) Filter out known false positives:
-- -@usr.name:known_admin -@network.destination.ip:known_destination_ip

-- In Logs Explorer:
-- - Group by: @network.destination.ip, @network.source.ip, @usr.name, @network.destination.port
-- - Measure: count() as count, min(@timestamp) as firstTime, max(@timestamp) as lastTime, values(@process.name) as process_name
```