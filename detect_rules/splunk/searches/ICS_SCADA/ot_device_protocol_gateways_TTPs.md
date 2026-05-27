### Detecting OT Devices Across Protocol Gateways
---

This report summarizes the challenges and methods for detecting Operational Technology (OT) devices across various industrial protocols, highlighting the increasing convergence of IT and OT networks. It emphasizes the need for robust discovery and monitoring to secure these critical environments against evolving threats.

Recent intelligence indicates a significant increase in internet-exposed OT devices and a rise in sophisticated attacks targeting the IT/OT convergence points, including the exploitation of vulnerabilities in common OT protocols like Modbus and DNP3, and the use of new malware specifically designed for OT environments. Notably, a critical Erlang/OTP SSH vulnerability (CVE-2025-32433) is being actively exploited, disproportionately affecting OT networks and demonstrating how IT-centric vulnerabilities can bridge into operational threats.

### Actionable Threat Data
---

Monitor for unusual Modbus TCP/IP (port 502) or DNP3 (port 20000) traffic patterns, especially connections originating from or destined for external networks, as these protocols often lack strong authentication and encryption, making them vulnerable to unauthorized access and data tampering.

Implement network segmentation to isolate OT networks from IT networks and the internet, and monitor for any unauthorized communication attempts across these boundaries (e.g., IT assets attempting to connect directly to PLCs or other OT devices).

Detect attempts to enumerate or "banner sniff" OT devices using protocols like Modbus and DNP3, as this reconnaissance activity often precedes targeted attacks. Look for repeated connection attempts to common OT ports from unusual sources.

Monitor for the exploitation of known vulnerabilities in industrial control systems and their associated protocols, such as the Erlang/OTP SSH vulnerability (CVE-2025-32433) which has been observed to affect OT networks. Look for SSH connections on non-standard ports (e.g., TCP 2222) or unexpected command execution.

Establish baselines for normal communication patterns and device identities within your OT environment and alert on deviations, such as new or unrecognized devices appearing on the network, changes in device configurations, or unexpected protocol usage.

### Search
---
```sql
-- Name: External Communication to OT Protocols (Modbus/DNP3)
-- Description: Detects network traffic to or from external IP addresses on ports commonly used for OT protocols like Modbus (502) and DNP3 (20000). This could indicate misconfigured devices, unauthorized remote access, or reconnaissance against industrial control systems.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK:
-- - T1071.004: Application Layer Protocol: File Transfer Protocols
-- - T1090: Proxy
-- - T1572: Protocol Tunneling
-- False Positive Sensitivity: Medium
-- - Legitimate remote administration, cloud-based SCADA monitoring services, or connections from business partners may use these protocols over the internet.
-- - To reduce false positives, add the IP addresses of any authorized external systems to the 'ot_ip_allowlist' macro.
-- References:
-- - https://www.veridify.com/dnp3-security-risks/
-- - https://www.veridify.com/modbus-security-issues-and-how-to-mitigate-cyber-risks/

-- Splunk Query
`comment("This macro should contain a list of legitimate external IP addresses that are allowed to communicate with the OT network. Example: (1.2.3.4, 2.3.4.5)")`
`create_macro(ot_ip_allowlist, "1.2.3.4, 8.8.8.8")`

| tstats summariesonly=true allow_old_summaries=true count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Network_Traffic where (All_Traffic.dest_port IN (502, 20000)) by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port
| rename "All_Traffic.*" as *

`comment("Identify if source and destination IPs are internal (private RFC1918 addresses)")`
| eval is_src_private=if(cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("172.16.0.0/12", src_ip) OR cidrmatch("192.168.0.0/16", src_ip), 1, 0)
| eval is_dest_private=if(cidrmatch("10.0.0.0/8", dest_ip) OR cidrmatch("172.16.0.0/12", dest_ip) OR cidrmatch("192.168.0.0/16", dest_ip), 1, 0)

`comment("Filter for traffic crossing the internal/external boundary. Excludes internal-to-internal and external-to-external traffic.")`
| where is_src_private != is_dest_private

`comment("Exclude known-good external IPs to reduce false positives")`
| where NOT (src_ip IN (`ot_ip_allowlist`) OR dest_ip IN (`ot_ip_allowlist`))

`comment("Identify the protocol based on the destination port")`
| eval protocol=case(dest_port==502, "Modbus", dest_port==20000, "DNP3", "Other")

`comment("Convert timestamps to human-readable format")`
| convert ctime(firstTime) ctime(lastTime)

`comment("Structure the output fields for the alert")`
| table firstTime, lastTime, src_ip, dest_ip, dest_port, protocol, count
| `external_communication_to_ot_protocols__modbus_dnp3__filter`
```
---
```sql
-- Name: Unauthorized IT to OT Network Communication
-- Description: Detects network traffic originating from the IT network and connecting to devices on the OT network over common industrial protocol ports. This can indicate a breach of network segmentation policies, unauthorized access attempts, or lateral movement from IT to OT environments.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK:
-- - T1090: Proxy
-- - T1572: Protocol Tunneling
-- False Positive Sensitivity: Medium
-- - This rule's effectiveness is highly dependent on the accurate definition of IT and OT network segments in the macros below.
-- - Legitimate systems like data historians or engineering workstations may need to communicate across these boundaries. Add any such authorized connections to the 'authorized_it_ot_connections' macro or, for better performance, use a lookup file.
-- References:
-- - https://www.cisa.gov/uscert/ics/publications/recommended-practice-improving-industrial-control-system-cybersecurity-network

-- --- CONFIGURATION MACROS ---
-- These macros must be created in your Splunk instance for the search to function correctly.

`comment("Define the IP address ranges for your IT network. Example: (cidrmatch(\"10.0.0.0/8\", $ip_field$) OR cidrmatch(\"172.16.0.0/12\", $ip_field$) OR cidrmatch(\"192.168.0.0/16\", $ip_field$))")`
`create_macro(it_subnets(ip_field), "(cidrmatch(\"10.0.0.0/8\", $ip_field$) OR cidrmatch(\"172.16.0.0/12\", $ip_field$) OR cidrmatch(\"192.168.0.0/16\", $ip_field$))")`

`comment("Define the IP address ranges for your OT/ICS network. Example: (cidrmatch(\"100.64.0.0/10\", $ip_field$))")`
`create_macro(ot_subnets(ip_field), "(cidrmatch(\"100.64.0.0/10\", $ip_field$))")`

`comment("Define common OT ports to monitor. Example: 502, 20000, 44818, 2222")`
`create_macro(ot_ports, "502, 20000, 44818, 2222")`

`comment("Define authorized connections from IT to OT to reduce false positives. Format: \"SourceIT_IP:DestinationOT_IP:DestinationPort\". Example: \"10.1.1.100:100.64.10.50:502\", \"10.1.2.200:100.64.20.75:44818\"")`
`create_macro(authorized_it_ot_connections, "\"10.1.1.100:100.64.10.50:502\", \"10.1.2.200:100.64.20.75:44818\"")`

-- --- DETECTION LOGIC ---

| tstats summariesonly=true allow_old_summaries=true count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest_port IN (`ot_ports`) by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port
| rename "All_Traffic.*" as *

`comment("Filter for traffic originating from defined IT subnets and destined for defined OT subnets.")`
| where `it_subnets("src_ip")` AND `ot_subnets("dest_ip")`

`comment("Create a unique key for the connection tuple to filter against the allowlist.")`
| eval connection_key = src_ip.":".dest_ip.":".dest_port

`comment("Exclude authorized connections defined in the macro.")`
| where NOT connection_key IN (`authorized_it_ot_connections`)

`comment("Add protocol context based on the destination port.")`
| eval protocol = case(dest_port==502, "Modbus", dest_port==20000, "DNP3", dest_port==44818, "EtherNet/IP (TCP)", dest_port==2222, "EtherNet/IP (UDP)", 1=1, "Other")

`comment("Convert epoch timestamps to human-readable format.")`
| convert ctime(firstTime) ctime(lastTime)

`comment("Structure the output fields for the alert.")`
| table firstTime, lastTime, src_ip, dest_ip, dest_port, protocol, count
| rename src_ip as SourceIT_IP, dest_ip as DestinationOT_IP, dest_port as DestinationPort, count as ConnectionCount

| `unauthorized_it_to_ot_network_communication_filter`
```
---
```sql
-- Name: OT Protocol Scanning (Banner Sniffing)
-- Description: Detects potential reconnaissance activity where a single source IP address attempts to connect to multiple distinct devices on common Operational Technology (OT) ports. This behavior is indicative of an adversary performing "banner sniffing" or enumeration to gather information about OT assets, which often precedes a targeted attack. This rule identifies scanning from both internal and external sources.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK:
-- - T1595: Active Scanning
-- - T1590: Gather Victim Network Information
-- False Positive Sensitivity: Medium
-- - Legitimate systems such as vulnerability scanners, network management tools, or data historians may exhibit this behavior.
-- - To reduce false positives, add the IP addresses of any authorized scanning systems to the 'scanner_ip_allowlist' macro.
-- - The 'device_scan_threshold' macro may need to be adjusted based on your environment's baseline activity.

-- --- CONFIGURATION MACROS ---
-- These macros must be created in your Splunk instance for the search to function correctly.

`comment("Define the OT ports to monitor for scanning activity. Example: 502, 20000, 44818, 2222")`
`create_macro(ot_ports, "502, 20000, 44818, 2222")`

`comment("Define the threshold for the number of distinct devices scanned by a single source to trigger an alert. Example: 3")`
`create_macro(device_scan_threshold, "3")`

`comment("Define an allowlist for legitimate scanners or management systems. Example: \"192.168.1.100\", \"10.10.0.50\"")`
`create_macro(scanner_ip_allowlist, "\"192.168.1.100\", \"10.10.0.50\"")`

-- --- DETECTION LOGIC ---

| tstats summariesonly=true allow_old_summaries=true count from datamodel=Network_Traffic where All_Traffic.dest_port IN (`ot_ports`) by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port, _time
| rename "All_Traffic.*" as *

`comment("Exclude authorized scanners to reduce false positives.")`
| where NOT src_ip IN (`scanner_ip_allowlist`)

`comment("Summarize connection attempts by the source IP address.")`
| stats min(_time) as StartTime, max(_time) as EndTime, dc(dest_ip) as DistinctOTDevicesScanned, values(dest_ip) as ScannedOT_IPs, values(dest_port) as ScannedPorts, sum(count) as TotalConnections by src_ip

`comment("Filter for sources that have scanned more devices than the defined threshold.")`
| where DistinctOTDevicesScanned > `device_scan_threshold`

`comment("Add context about the location of the scanning source.")`
| eval ScannerLocation=if(cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("172.16.0.0/12", src_ip) OR cidrmatch("192.168.0.0/16", src_ip), "Internal", "External")

`comment("Format the output for readability.")`
| convert ctime(StartTime) ctime(EndTime)
| rename src_ip as ScannerIP
| table StartTime, EndTime, ScannerIP, ScannerLocation, DistinctOTDevicesScanned, TotalConnections, ScannedOT_IPs, ScannedPorts
| `ot_protocol_scanning__banner_sniffing__filter`
```
---
```sql
-- Name: Erlang/OTP SSH Vulnerability Exploitation (CVE-2025-32433)
-- Description: Detects potential exploitation of a fictional Erlang/OTP SSH vulnerability (CVE-2025-32433). The rule identifies two key patterns associated with this threat: 1) Erlang-related processes accepting inbound connections on non-standard SSH ports (e.g., 2222), which is a primary indicator of the exploit attempt, especially in OT networks. 2) Erlang-related processes spawning command shells, indicating successful post-exploitation and remote code execution.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK:
-- - T1190: Exploit Public-Facing Application
-- - T1021: Remote Services
-- - T1059: Command and Scripting Interpreter
-- False Positive Sensitivity: Medium
-- - Some legitimate applications built on Erlang/OTP may use SSH on non-standard ports for administrative purposes.
-- - Spawning a shell from an Erlang process is highly suspicious but could occur in bespoke management scripts.
-- - To reduce false positives, populate the 'ot_subnets' macro with your specific OT network ranges and review any findings for legitimacy.
-- References:
-- - https://unit42.paloaltonetworks.com/erlang-otp-cve-2025-32433/
-- - https://gbhackers.com/erlang-otp-ssh-rce-vulnerability-actively-exploited/

-- --- CONFIGURATION MACROS ---
-- These macros must be created in your Splunk instance for the search to function correctly.

`comment("Define non-standard SSH ports. Port 2222 is specifically mentioned in intelligence. Example: 2222")`
`create_macro(non_standard_ssh_ports, "2222")`

`comment("Define known Erlang/OTP process names. Example: \"beam.smp\", \"beam\", \"erl\", \"erlexec\"")`
`create_macro(erlang_processes, "\"beam.smp\", \"beam\", \"erl\", \"erlexec\"")`

`comment("Define common command shell processes. Example: \"bash\", \"sh\", \"zsh\", \"csh\", \"ksh\", \"cmd.exe\", \"powershell.exe\"")`
`create_macro(shell_processes, "\"bash\", \"sh\", \"zsh\", \"csh\", \"ksh\", \"cmd.exe\", \"powershell.exe\"")`

`comment("Define OT network ranges to focus the detection. Example: (cidrmatch(\"10.100.0.0/16\", $ip_field$) OR cidrmatch(\"192.168.50.0/24\", $ip_field$))")`
`create_macro(ot_subnets(ip_field), "(cidrmatch(\"10.100.0.0/16\", $ip_field$) OR cidrmatch(\"192.168.50.0/24\", $ip_field$))")`

-- --- DETECTION LOGIC ---

`comment("Tactic 1: Detect Erlang process accepting connections on a non-standard SSH port")`
| tstats summariesonly=true allow_old_summaries=true count from datamodel=Endpoint.Ports where (Ports.dest_port IN (`non_standard_ssh_ports`)) AND (Ports.process_name IN (`erlang_processes`)) by Ports.dest, Ports.process_name, Ports.dest_port, Ports.src, _time
| rename "Ports.dest" as host, "Ports.process_name" as process_name, "Ports.dest_port" as local_port, "Ports.src" as remote_ip
| `drop_dm_object_name("Ports")`
| where `ot_subnets(host)`
| eval activity="Non-Standard SSH Port Connection to Erlang Process", parent_process_name="N/A", command_line="N/A"
| table _time, activity, host, process_name, parent_process_name, command_line, local_port, remote_ip

| append [
    `comment("Tactic 2: Detect Erlang process spawning a command shell")`
    | tstats summariesonly=true allow_old_summaries=true values(Processes.process) as command_line from datamodel=Endpoint.Processes where (Processes.process_name IN (`shell_processes`)) AND (Processes.parent_process_name IN (`erlang_processes`)) by Processes.dest, Processes.process_name, Processes.parent_process_name, _time
    | rename "Processes.dest" as host, "Processes.process_name" as process_name, "Processes.parent_process_name" as parent_process_name
    | `drop_dm_object_name("Processes")`
    | where `ot_subnets(host)`
    | eval activity="Shell Spawned by Erlang Process", local_port="N/A", remote_ip="N/A"
    | table _time, activity, host, process_name, parent_process_name, command_line, local_port, remote_ip
]

| convert ctime(_time)
| `erlang_otp_ssh_vulnerability_exploitation__cve_2025_32433__filter`
```
---
```sql
-- Name: OT Network Baseline Deviations
-- Description: Detects new devices or new communication patterns within the Operational Technology (OT) network by comparing recent activity against a historical baseline. This can indicate newly connected (and potentially unauthorized) devices, or existing devices being used in an anomalous way, which could be a precursor to or part of a malicious attack.
-- Author: RW
-- Date: 2025-08-17
-- MITRE ATT&CK:
-- - T1592: Gather Victim Host Information
-- - T1595: Active Scanning
-- - T1083: File and Directory Discovery
-- False Positive Sensitivity: Medium
-- - This rule will trigger when new devices are legitimately added to the OT network or when device configurations are intentionally changed. These events should be reviewed and acknowledged.
-- - The effectiveness of this rule depends heavily on the accuracy of the 'ot_subnets' definition and the stability of the network. The time window macros may need tuning for your environment.
-- - NOTE: This query uses multiple subsearches for baselining which can be resource-intensive. For production environments, it is highly recommended to replace the subsearches with pre-populated lookups that are updated on a scheduled basis (e.g., daily).

-- --- CONFIGURATION MACROS ---
-- These macros must be created in your Splunk instance for the search to function correctly.

`comment("Define the time window for the historical baseline. Default is 14 days ago up to 1 day ago.")`
`create_macro(ot_baseline_period, "earliest=-14d@d latest=-1d@d")`

`comment("Define the time window for recent activity. Default is the last 24 hours.")`
`create_macro(ot_recent_period, "earliest=-1d@d latest=now")`

`comment("Define the IP address ranges for your OT/ICS network. Example: (cidrmatch(\"10.100.0.0/16\", $ip_field$) OR cidrmatch(\"192.168.50.0/24\", $ip_field$))")`
`create_macro(ot_subnets(ip_field), "(cidrmatch(\"10.100.0.0/16\", $ip_field$) OR cidrmatch(\"192.168.50.0/24\", $ip_field$))")`

-- --- DETECTION LOGIC ---

`comment("Tactic 1: Find entirely new devices that have appeared in the OT network.")`
| tstats summariesonly=true allow_old_summaries=true min(_time) as StartTime, max(_time) as EndTime, values(All_Traffic.dest_port) as Port, values(All_Traffic.src_ip) as ConnectedRemoteIPs from datamodel=Network_Traffic where `ot_recent_period` AND `ot_subnets(All_Traffic.dest_ip)` by All_Traffic.dest, All_Traffic.dest_ip
| rename "All_Traffic.*" as *
| search NOT [
    | tstats summariesonly=true allow_old_summaries=true dc(All_Traffic.dest_ip) from datamodel=Network_Traffic where `ot_baseline_period` AND `ot_subnets(All_Traffic.dest_ip)` by All_Traffic.dest_ip
    | rename All_Traffic.dest_ip as dest_ip
    | fields dest_ip
    | format
]
| eval DeviationType = "New OT Device Detected"
| eval Details = "New device appeared on the OT network. Ports used: " . mvjoin(Port, ", ")
| rename dest as DeviceName, dest_ip as OT_DeviceIP
| convert ctime(StartTime) ctime(EndTime)
| table StartTime, EndTime, DeviationType, DeviceName, OT_DeviceIP, Details, ConnectedRemoteIPs, Port

| append [
    `comment("Tactic 2: Find existing devices that are communicating on new, previously unseen ports.")`
    | tstats summariesonly=true allow_old_summaries=true min(_time) as StartTime, max(_time) as EndTime, values(All_Traffic.src_ip) as ConnectedRemoteIPs from datamodel=Network_Traffic where `ot_recent_period` AND `ot_subnets(All_Traffic.dest_ip)` by All_Traffic.dest, All_Traffic.dest_ip, All_Traffic.dest_port
    | rename "All_Traffic.*" as *
    | eval device_port_key = dest_ip . ":" . dest_port
    `comment("Filter out device-port combinations that existed in the baseline.")`
    | search NOT [
        | tstats summariesonly=true allow_old_summaries=true count from datamodel=Network_Traffic where `ot_baseline_period` AND `ot_subnets(All_Traffic.dest_ip)` by All_Traffic.dest_ip, All_Traffic.dest_port
        | eval device_port_key = All_Traffic.dest_ip . ":" . All_Traffic.dest_port
        | fields device_port_key
        | format
    ]
    `comment("Only consider devices that were already in the baseline (new devices are handled by Tactic 1).")`
    | search [
        | tstats summariesonly=true allow_old_summaries=true dc(All_Traffic.dest_ip) from datamodel=Network_Traffic where `ot_baseline_period` AND `ot_subnets(All_Traffic.dest_ip)` by All_Traffic.dest_ip
        | rename All_Traffic.dest_ip as dest_ip
        | fields dest_ip
        | format
    ]
    | eval DeviationType = "New OT Communication Pattern Detected"
    | eval Details = "Existing device communicated on a new port: " . dest_port . ". Connected from/to remote IPs: " . mvjoin(ConnectedRemoteIPs, ", ")
    | rename dest as DeviceName, dest_ip as OT_DeviceIP, dest_port as Port
    | convert ctime(StartTime) ctime(EndTime)
    | table StartTime, EndTime, DeviationType, DeviceName, OT_DeviceIP, Details, ConnectedRemoteIPs, Port
]
| `ot_network_baseline_deviations_filter`
```