### Fire Ant: Hypervisor-Level Espionage Campaign
---

The "Fire Ant" campaign is a sophisticated cyber-espionage operation primarily targeting VMware ESXi and vCenter environments, as well as network appliances, to achieve hypervisor-level persistence and evade detection. This threat actor, strongly linked to UNC3886, leverages advanced techniques to maintain access and move laterally within compromised infrastructure, even adapting to eradication efforts.

Recent intelligence indicates UNC3886, the group associated with Fire Ant, continues to evolve its TTPs by deploying custom backdoors on Juniper Networks' Junos OS routers and actively exploiting zero-day vulnerabilities in Fortinet, VMware, and Juniper systems, demonstrating a persistent focus on targeting network and virtualization infrastructure that often lacks traditional security monitoring.

### Actionable Threat Data
---

Monitor for unexpected crashes of the `vmdird` process on vCenter servers, which may indicate exploitation of CVE-2023-34048.

Alert on the installation of unsigned vSphere Installation Bundles (VIBs) on ESXi hosts, especially those deployed with the `--force` flag, as this is a known persistence mechanism for the `VIRTUALPITA` malware family.

Detect the creation or modification of `/etc/rc.local.d/local.sh` on ESXi hosts to execute unauthorized Python scripts (e.g., `autobackup.bin`), which can establish HTTP-based backdoors.

Look for the termination of the `vmsyslogd` process on ESXi hosts, as this indicates an attempt to disable logging and obscure malicious activity.

Identify process creation events in guest virtual machines where `cmd.exe` or `powershell.exe` are spawned with `vmtoolsd.exe` as the parent process, particularly when accompanied by encoded commands, suggesting host-to-guest command injection via CVE-2023-20867.

Monitor for direct execution of the `/bin/vmx` binary with the `-x` argument on ESXi hosts, which can indicate the deployment of rogue virtual machines outside of vCenter's visibility.

Detect the presence and execution of the V2Ray framework (e.g., `update.exe`) on guest virtual machines, especially when configured to listen on unusual ports like TCP `58899`, as this is used for encrypted tunneling and C2 communication.

Look for the deployment of the `Medusa rootkit` on Linux pivot hosts, which can be identified by its dynamic linker hijacking via `LD_PRELOAD` and its credential logging capabilities (e.g., `remote.txt`).

Monitor for the use of `netsh portproxy` commands on Windows servers and workstations to enable unauthorized port forwarding, bypassing network ACLs.

Identify F5 load balancer compromises through the exploitation of `CVE-2022-1388`, specifically looking for the deployment of webshells to `/usr/local/www/xui/common/css/css.php`.

### vmdird Process Crash
---
```sql
`comment("
-- name: VMware vCenter vmdird Process Crash
-- author: Rob Weber
-- date: 2025-07-25
-- description: >
--   Detects the unexpected crash of the vmdird process on a VMware vCenter server.
--   This is indicated by "vmdird dumping core" messages in vCenter logs (e.g., vMonCoreDumper.log).
--   This behavior may be an indicator of exploitation of CVE-2023-34048, a vulnerability used by threat actors like Fire Ant to gain initial access.
-- references:
--   - https://www.sygnia.co/blog/fire-ant-a-deep-dive-into-hypervisor-level-espionage/
-- mitre_attack:
--   - technique: T1190
--     tactic: Initial Access
-- false_positives: >
--   Legitimate software bugs or resource exhaustion could also cause the vmdird process to crash.
--   Investigate the context of the crash. A single event may be an anomaly, whereas repeated crashes or correlation with other suspicious activity targeting the vCenter server increases the likelihood of malicious activity.
-- data_source:
--   - VMware vCenter logs
")`

`vmware` "vmdird dumping core"
| comment: "This search looks for log entries indicating the vmdird process on a VMware vCenter server is crashing and dumping a core file. This specific event was observed during the Fire Ant campaign as a precursor to exploitation of CVE-2023-34048."
| rex field=_raw "Pid\s*:\s*(?<process_id>\d+)"
| comment: "Extract the Process ID for additional context."
| stats count by _time, host, process_id, _raw
| comment: "Aggregate the results to show unique crash events."
| rename host as vcenter_server, _raw as log_message
| comment: "Rename fields for better readability in the results."
| fields _time, vcenter_server, process_id, log_message, count
```

### Unsigned VIB Installation
---
```sql
`comment("
-- name: VMware ESXi Unsigned VIB Installation
-- author: Rob Weber
-- date: 2025-07-25
-- description: >
--   Detects the installation of a vSphere Installation Bundle (VIB) using the "--force" flag on an ESXi host.
--   This bypasses signature validation and is a technique used by threat actors like Fire Ant to install malicious VIBs (like VIRTUALPITA) for persistence.
-- references:
--   - https://www.sygnia.co/blog/fire-ant-a-deep-dive-into-hypervisor-level-espionage/
-- mitre_attack:
--   - technique: T1543.003
--     tactic: Persistence
-- false_positives: >
--   System administrators may use the "--force" flag in rare troubleshooting or specific software deployment scenarios.
--   Investigate the context of the installation, the user performing the action, and the nature of the VIB being installed.
-- data_source:
--   - VMware ESXi logs (e.g., shell.log, syslog)
")`

`vmware` "esxcli software vib install" "--force"
| comment: "Search for the command to install a VIB on an ESXi host, specifically including the '--force' flag which bypasses signature checks."
| rex "esxcli\s+software\s+vib\s+install\s+.*?\s+(-v|--viburl)\s+(?<vib_path>\S+)"
| comment: "Extract the path or URL of the VIB being installed for analysis."
| stats count by _time, host, user, vib_path, _raw
| comment: "Aggregate results to identify unique forced VIB installations."
| rename host as esxi_host, _raw as log_message
| comment: "Rename fields for clarity."
| fields _time, esxi_host, user, vib_path, log_message, count
```

### Modified local.sh on ESXi
---
```sql
`comment("
-- name: ESXi local.sh Modified for Persistence
-- author: Rob Weber
-- date: 2025-07-25
-- description: >
--   Detects modification of the /etc/rc.local.d/local.sh script on a VMware ESXi host.
--   Threat actors like Fire Ant modify this file to add commands that execute backdoors, such as Python scripts, for persistence across reboots.
-- references:
--   - https://www.sygnia.co/blog/fire-ant-a-deep-dive-into-hypervisor-level-espionage/
-- mitre_attack:
--   - technique: T1547.006
--     tactic: Persistence
-- false_positives: >
--   Legitimate system administrators may modify this file for valid configuration purposes.
--   However, such modifications should be rare and correspond to planned maintenance.
--   Investigate the user performing the modification and the content being added to the file.
--   The presence of keywords like "python", ".bin", or paths like "/bootbank/" in the command increases suspicion.
-- data_source:
--   - Endpoint.Processes (Sysmon, EDR, etc.)
--   - VMware ESXi logs (e.g., shell.log)
")`

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*/etc/rc.local.d/local.sh*") AND Processes.process_name IN ("vi", "vim", "nano", "pico", "sed", "echo", "cat") by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "This search uses the CIM to find commands (like echo, sed, vi) that are commonly used to modify files, where the target is the ESXi startup script 'local.sh'."
| comment: "To reduce potential false positives from legitimate administrative activity, consider filtering for commands that also contain suspicious keywords like 'python', '.bin', or '/bootbank/', e.g., 'AND Processes.process IN (\"*python*\", \"*.bin*\")'."
| rename dest as esxi_host
```

### vmsyslogd Process Termination
---
```sql
`comment("
-- name: VMware ESXi vmsyslogd Process Terminated
-- author: Rob Weber
-- date: 2025-07-25
-- description: >
--   Detects the termination of the 'vmsyslogd' process on a VMware ESXi host.
--   Threat actors like Fire Ant (UNC3886) may terminate this service to disable local and remote logging,
--   thereby evading detection and hindering forensic investigations.
-- references:
--   - https://www.sygnia.co/blog/fire-ant-a-deep-dive-into-hypervisor-level-espionage/
-- mitre_attack:
--   - technique: T1562.002
--     tactic: Defense Evasion
-- false_positives: >
--   This activity is highly suspicious. Legitimate administrators should not typically need to manually kill the syslog daemon.
--   It might occur during a failed system update or a complex troubleshooting scenario, but such instances should be rare and verifiable.
-- data_source:
--   - Endpoint.Processes (Sysmon, EDR, etc.)
--   - VMware ESXi logs (e.g., shell.log)
")`

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("kill", "pkill", "killall")) AND (Processes.process="*vmsyslogd*") by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "This search uses the CIM to find commands like 'kill' or 'pkill' being used to terminate the 'vmsyslogd' process on an ESXi host."
| comment: "This is a strong indicator of defense evasion, as seen in the Fire Ant campaign. A complementary detection strategy is to monitor for a sudden cessation of logs from an ESXi host."
| rename dest as esxi_host
```

### vmtoolsd.exe Parent Process
---
```sql
`comment("
-- name: VMware Guest Command Execution via vmtoolsd
-- author: Rob Weber
-- date: 2025-07-25
-- description: >
--   Detects process creation events in guest virtual machines where cmd.exe or powershell.exe are spawned by the VMware Tools service process, vmtoolsd.exe.
--   This behavior is highly indicative of host-to-guest command injection, often using tools like PowerCLI's Invoke-VMScript.
--   Threat actors like Fire Ant (UNC3886) have exploited CVE-2023-20867 to perform this action without guest credentials, enabling them to tamper with security tools or deploy malware from the hypervisor.
-- references:
--   - https://www.sygnia.co/blog/fire-ant-a-deep-dive-into-hypervisor-level-espionage/
-- mitre_attack:
--   - technique: T1219
--     tactic: Execution
-- false_positives: >
--   While uncommon, legitimate administrative scripts may use Invoke-VMScript for automation or management tasks.
--   Investigate the command line executed and the context of the activity.
--   Consider tuning the rule to exclude known administrative actions or to focus on suspicious command-line arguments (e.g., encoded commands).
-- data_source:
--   - Endpoint.Processes (Sysmon, EDR, etc.)
")`

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="vmtoolsd.exe") AND (Processes.process_name IN ("cmd.exe", "powershell.exe")) by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "This search identifies command shells (cmd.exe, powershell.exe) being spawned by the VMware Tools service (vmtoolsd.exe)."
| comment: "This is a strong indicator of host-to-guest command injection, a technique used by the Fire Ant actor."
| rename dest as guest_vm
```

### Rogue VM Execution
---
```sql
`comment("
-- name: Rogue VMware VM Execution via vmx -x
-- author: Rob Weber
-- date: 2025-07-25
-- description: >
--   Detects the direct execution of the '/bin/vmx' binary with the '-x' argument on a VMware ESXi host.
--   This command launches a virtual machine directly from its .vmx configuration file, bypassing vCenter registration and management.
--   This technique was used by the Fire Ant threat actor (UNC3886) to deploy rogue virtual machines that are hidden from standard administrative interfaces.
-- references:
--   - https://www.sygnia.co/blog/fire-ant-a-deep-dive-into-hypervisor-level-espionage/
-- mitre_attack:
--   - technique: T1578.002
--     tactic: Defense Evasion
-- false_positives: >
--   This method of launching a VM is highly unusual in production environments and is a strong indicator of malicious activity.
--   Legitimate use cases are rare and typically confined to specific troubleshooting or development scenarios.
-- data_source:
--   - Endpoint.Processes (Sysmon, EDR, etc.)
--   - VMware ESXi logs (e.g., shell.log)
")`

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*/bin/vmx -x*") by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "This search looks for the direct execution of the vmx binary with the '-x' flag, which launches a VM outside of vCenter's control."
| comment: "This is a specific TTP used by the Fire Ant actor to run rogue, hidden virtual machines on a compromised ESXi host."
| rename dest as esxi_host
```

### V2Ray Framework Execution
---
```sql
`comment("
-- name: V2Ray Framework Execution for C2
-- author: Rob Weber
-- date: 2025-07-25
-- description: >
--   Detects a process listening on TCP port 58899. This port was used by the Fire Ant threat actor (UNC3886) for command and control (C2) communication using the V2Ray framework.
--   The actor deployed V2Ray as a binary named 'update.exe' onto guest virtual machines to establish an encrypted tunnel.
-- references:
--   - https://www.sygnia.co/blog/fire-ant-a-deep-dive-into-hypervisor-level-espionage/
-- mitre_attack:
--   - technique: T1572
--     tactic: Command and Control
-- false_positives: >
--   This port is not commonly used. A false positive may occur if legitimate, custom software in the environment is configured to listen on this port.
--   Investigate the process name and its purpose. The actor was observed using 'update.exe', but other names are possible.
-- data_source:
--   - Endpoint.Network_Traffic (Sysmon Event ID 3, EDR, etc.)
")`

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Network_Traffic where (Network_Traffic.action="listen" AND Network_Traffic.dest_port=58899) by Network_Traffic.dest, Network_Traffic.user, Network_Traffic.process_name, Network_Traffic.dest_port
| `drop_dm_object_name(Network_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "This search looks for processes listening on TCP port 58899, which was used by the Fire Ant actor for V2Ray C2 tunneling."
| comment: "While the actor used 'update.exe', this rule focuses on the network artifact to detect the C2 channel even if the tool is renamed."
| rename dest as guest_vm, process_name as listening_process
```

### Medusa Rootkit Deployment
---
```sql
`comment("
-- name: Medusa Rootkit Deployment via LD_PRELOAD
-- author: Rob Weber
-- date: 2025-07-25
-- description: >
--   Detects the use of the LD_PRELOAD environment variable to hijack the dynamic linker on Linux systems.
--   This technique is used by the Medusa rootkit, deployed by the Fire Ant threat actor (UNC3886), to load a malicious shared object into a process for persistence and credential theft.
--   The rootkit specifically uses this to hook SSH and log credentials to a file named 'remote.txt'.
-- references:
--   - https://www.sygnia.co/blog/fire-ant-a-deep-dive-into-hypervisor-level-espionage/
--   - https://github.com/ldpreload/Medusa/tree/main
-- mitre_attack:
--   - technique: T1574.006
--     tactic: Persistence
--   - technique: T1574.006
--     tactic: Privilege Escalation
--   - technique: T1574.006
--     tactic: Defense Evasion
-- false_positives: >
--   Legitimate software, particularly for performance monitoring (e.g., jemalloc), debugging, or system profiling, may use LD_PRELOAD.
--   Investigate the shared object (.so) file being loaded and the context of the execution.
--   Suspicious paths for the .so file include /tmp, /var/tmp, or user home directories.
--   Consider adding known legitimate .so files or processes to an exclusion list.
-- data_source:
--   - Endpoint.Processes (Sysmon for Linux, auditd, EDR, etc.)
")`

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*LD_PRELOAD=*") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "This search identifies any process execution where the LD_PRELOAD environment variable is set on the command line."
| comment: "This is the core technique used by the Medusa rootkit. Review the loaded .so file and the process for legitimacy."
| comment: "To reduce potential false positives, you could filter for specific processes being hijacked (e.g., ssh, sshd) or suspicious .so paths (e.g., /tmp/*), like: `| where match(process, \"(ssh|sshd)\") AND match(process, \"/tmp/\")`"
| rename dest as host
```

### Netsh Portproxy Abuse
---
```sql
`comment("
-- name: Netsh Portproxy Rule Modification
-- author: Rob Weber
-- date: 2025-07-25
-- description: >
--   Detects the use of the 'netsh' command-line utility to configure port proxying (port forwarding).
--   Threat actors, such as Fire Ant (UNC3886), leverage this native Windows feature to pivot within a network,
--   bypass access control lists (ACLs), and tunnel traffic to otherwise restricted systems.
-- references:
--   - https://www.sygnia.co/blog/fire-ant-a-deep-dive-into-hypervisor-level-espionage/
-- mitre_attack:
--   - technique: T1572
--     tactic: Command and Control
-- false_positives: >
--   Legitimate use of netsh portproxy is rare in most environments but may be used by administrators or certain applications for specific networking tasks.
--   Investigate the user, host, and the specific rule being added to determine if the activity is authorized.
-- data_source:
--   - Endpoint.Processes (Sysmon, EDR, Windows Security Event ID 4688)
")`

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="netsh.exe" AND Processes.process="*portproxy*") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "This search identifies the execution of netsh.exe with 'portproxy' in the command line, indicating a port forwarding rule is being viewed, added, or modified."
| comment: "To reduce noise from administrators checking configurations, consider focusing on commands that create or change rules, e.g., `| where match(process, \"(?i)(add|set)\")`"
| rename dest as host
```

### F5 Load Balancer Compromise
---
```sql
`comment("
-- name: F5 Load Balancer Webshell Deployment
-- author: Rob Weber
-- date: 2025-07-25
-- description: >
--   Detects the creation of a specific webshell file on an F5 BIG-IP load balancer.
--   Threat actors like Fire Ant (UNC3886) have been observed exploiting CVE-2022-1388 to execute commands
--   and deploy a webshell to '/usr/local/www/xui/common/css/css.php' for persistence and further access.
-- references:
--   - https://www.sygnia.co/blog/fire-ant-a-deep-dive-into-hypervisor-level-espionage/
-- mitre_attack:
--   - technique: T1190
--     tactic: Initial Access
--   - technique: T1505.003
--     tactic: Persistence
-- false_positives: >
--   This activity is highly suspicious. False positives are unlikely as legitimate processes should not be writing a PHP file to a CSS directory on an F5 device.
--   However, a compromised administrative account could be used to perform this action manually.
-- data_source:
--   - Endpoint.Processes (auditd, EDR, etc.)
")`

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*>/usr/local/www/xui/common/css/css.php*") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| comment: "This search looks for any process command that writes to the specific webshell path '/usr/local/www/xui/common/css/css.php' used by the Fire Ant actor."
| comment: "This is a high-fidelity indicator of compromise on an F5 BIG-IP device, often resulting from the exploitation of CVE-2022-1388."
| rename dest as f5_host
```