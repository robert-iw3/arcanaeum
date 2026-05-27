### Chinese State-Sponsored Cyber Espionage Targets Taiwan's Semiconductor Sector
---

Chinese state-sponsored threat actors have intensified spear-phishing campaigns against Taiwan's semiconductor industry and related financial analysts, employing custom backdoors and commodity tools like Cobalt Strike. These campaigns, attributed to groups like UNK_FistBump, UNK_DropPitch, and UNK_SparkyCarp, aim to collect intelligence aligned with China's strategic goal of semiconductor self-sufficiency.

Beyond the reported campaigns, recent intelligence indicates a broader trend of Chinese state-sponsored actors, including Salt Typhoon, leveraging known vulnerabilities in network appliances (Cisco IOS XE, Palo Alto PAN-OS) for initial access and persistence, expanding their targeting to critical infrastructure and government entities. The increased use of SoftEther VPN by multiple Chinese hacking groups for stealthy C2 communications and the continued evolution of cross-platform malware like Spark RAT highlight a persistent and adaptable threat landscape.

### Actionable Threat Data
---

Initial Access & Execution:

Monitor for spear-phishing emails with employment themes containing LNK files masquerading as PDFs, or emails with embedded links to PDF documents that download ZIP files containing malicious DLL payloads (DLL side-loading). (T1566.001, T1204.002, T1574.001)

Look for execution of `rundll32.exe` or other legitimate binaries loading suspicious DLLs, particularly those named `libcef.dll` or `pbvm90.dll`. (T1218.011)

Detect attempts to exploit known vulnerabilities in internet-facing devices, specifically Cisco IOS XE (`CVE-2023-20198`, `CVE-2023-20273`) and Palo Alto Networks PAN-OS (`CVE-2024-3400`). (T1190)

Monitor for the use of SoftEther VPN client executables on endpoints or servers where they are not explicitly authorized, especially if communicating over HTTPS to blend with legitimate traffic. (T1572)

Look for HTTP Basic Authentication attempts to suspected `SparkRAT` C2 server panels, often on default port `8000`, and WebSocket protocol usage for C2 communications. (T1071.001)

Defense Evasion & Persistence:

Detect the presence and execution of custom backdoors like `Voldemort` (hard-coded C2 IP) and `HealthKick` (FakeTLS protocol with magic bytes `0x17` `0x03` `0x03` and `XOR` encoding). (T1059.003, T1027)

Look for the deployment of Intel Endpoint Management Assistant (EMA) for remote control via suspicious C2 domains. (T1219)

NOTE: You must be ingesting endpoint data that tracks process activity from your hosts to populate the Endpoint data model in the Common Information Model (CIM).

### Spear-Phishing with LNK/DLL
---
```sql
-- description: Detects a potential DLL side-loading attack where a legitimate system executable is launched from a common user download or temporary directory.

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (
-- key logic: find legitimate system processes that are often abused for side-loading
  Processes.process_name IN ("calc.exe","consent.exe","control.exe","dism.exe","MpCmdRun.exe","mspaint.exe","OneDrive.exe","RuntimeBroker.exe","SystemSettings.exe","Teams.exe","vlc.exe","WerFault.exe","wusa.exe")
) AND (
-- key logic: check if they are running from user-writable or temporary locations, common for downloaded malware
  Processes.process_path IN ("*\\Users\\*\\Downloads\\*","*\\AppData\\Local\\Temp\\*","*\\Users\\Public\\*","C:\\ProgramData\\*")
)
by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process_path, Processes.process
-- rename fields for clarity
| `drop_dm_object_name("Processes")`
-- format time for readability
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- provide a placeholder for custom filtering to reduce false positives
| `spear_phishing_with_lnk_leading_to_dll_side_loading_filter`
```

### Exploitation of Network Appliances
---
```sql
-- description: Detects potential exploitation attempts against known vulnerabilities in Cisco IOS XE (CVE-2023-20198, CVE-2023-20273) and Palo Alto Networks PAN-OS (CVE-2024-3400). These TTPs have been associated with Chinese state-sponsored actors for initial access.
-- how_to_implement: You must be ingesting web server, proxy, or firewall logs and populating the Web data model in the Common Information Model (CIM). The `http_header` field is required for the Palo Alto CVE detection.

from datamodel=Web.Web
| `drop_dm_object_name("Web")`
-- key logic: identify web requests matching signatures for specific CVEs
| where (
-- Cisco IOS XE exploit attempts (CVE-2023-20198, CVE-2023-20273)
  (http_method="POST" AND (url="*/webui/logoutconfirm.html?logon_hash=1" OR url="*/webui/wsma/config"))
-- Palo Alto PAN-OS exploit attempt (CVE-2024-3400)
  OR (url="*/ssl-vpn/hipreport.esp" AND like(http_header, "%`%"))
)
-- aggregate results by source and destination
| stats count values(url) as urls values(http_method) as http_methods min(_time) as firstTime max(_time) as lastTime by src, dest, user, http_user_agent
-- format time for readability
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- provide a placeholder for custom filtering to reduce false positives
| `potential_exploitation_of_network_appliances_filter`
```

### SoftEther VPN Client Execution for C2 Tunneling
---
```sql
-- description: Detects the execution of SoftEther VPN client executables (vpnclient.exe, vpncmd.exe). Chinese state-sponsored threat actors have been observed using SoftEther VPN to create encrypted tunnels for command and control (C2) communications, often over common ports like 443 (HTTPS) to blend in with legitimate traffic. Detecting the execution of this software on systems where it is not authorized can indicate malicious activity.

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where
-- key logic: search for SoftEther VPN client and command-line tool process names
  Processes.process_name IN ("vpnclient.exe", "vpnclient_x64.exe", "vpncmd.exe", "vpncmd_x64.exe")
-- aggregate results by host, user, and process details
by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
-- format time for readability
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- provide a placeholder for custom filtering to reduce false positives
| `softether_vpn_client_execution_for_c2_tunneling_filter`
```

### Suspicious Parent Process Spawning Command Shell
---
```sql
-- description: Detects a command shell (`cmd.exe`, `powershell.exe`) being spawned by a parent process that is running from a suspicious, user-writable location (e.g., Downloads, AppData\Local\Temp). This pattern is indicative of a backdoor, like HealthKick or Voldemort, executing commands after being dropped via a phishing attack.

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("cmd.exe", "powershell.exe") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.parent_process_path, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
-- key logic: filter for parent processes running from suspicious, user-writable, or temporary locations.
| where (like(parent_process_path, "%\\Downloads\\%") OR like(parent_process_path, "%\\AppData\\Local\\Temp\\%") OR like(parent_process_path, "%\\Users\\Public\\%") OR like(parent_process_path, "C:\\ProgramData\\%"))
-- format time for readability
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- provide a placeholder for custom filtering
| `suspicious_parent_process_spawning_command_shell_filter`
```

### Intel EMA Agent Execution for Remote Access
---
```sql
-- description: Detects the execution of the Intel Endpoint Management Assistant (EMA) agent. While EMA is a legitimate remote administration tool, it has been observed being deployed by Chinese state-sponsored actors for malicious remote control, communicating with C2 domains like `ema.moctw[.]info`. This detection should be treated as a policy violation and tuned to alert only on systems where this software is not expected.

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where
-- key logic: search for the Intel EMA agent process name
  Processes.process_name = "Intel(R) EMA Agent.exe"
-- aggregate results by host, user, and process details
by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
-- format time for readability
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
-- provide a placeholder for custom filtering to reduce false positives
| `intel_ema_agent_execution_for_remote_access_filter`
```