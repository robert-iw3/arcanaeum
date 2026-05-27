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
-- References:
-- - https://www.veridify.com/dnp3-security-risks/
-- - https://www.veridify.com/modbus-security-issues-and-how-to-mitigate-cyber-risks/

-- Rule: Uses NetworkConnectTCPv4 and NetworkAcceptTCPv4 to detect traffic on OT ports crossing internal/external boundaries. Excludes allowlisted IPs and filters for OT assets.
event_platform=Win event_simpleName IN ("NetworkConnectTCPv4", "NetworkAcceptTCPv4") dest_port IN (502, 20000) (
    (LocalAddressIP4:/^(10.|192.168.|172.(1[6-9]|2[0-9]|3[0-1]).)/ AND !RemoteAddressIP4:/^(10.|192.168.|172.(1[6-9]|2[0-9]|3[0-1]).)/) OR
    (!LocalAddressIP4:/^(10.|192.168.|172.(1[6-9]|2[0-9]|3[0-1]).)/ AND RemoteAddressIP4:/^(10.|192.168.|172.(1[6-9]|2[0-9]|3[0-1]).)/)
) !LocalAddressIP4 IN ("1.2.3.4", "8.8.8.8") !RemoteAddressIP4 IN ("1.2.3.4", "8.8.8.8") +ComputerName:/(PLC|RTU|GRID)/i
| stats min(@timestamp) as firstTime max(@timestamp) as lastTime sum(count) as count by LocalAddressIP4 RemoteAddressIP4 dest_port
| eval protocol=case(dest_port==502, "Modbus", dest_port==20000, "DNP3", true, "Other")
| rename LocalAddressIP4 as src_ip RemoteAddressIP4 as dest_ip dest_port as DestinationPort count as ConnectionCount
| table firstTime lastTime src_ip dest_ip DestinationPort protocol ConnectionCount
-- Potential False Positives: Legitimate remote admin or cloud-based SCADA services. Maintain allowlist for authorized IPs (e.g., !LocalAddressIP4 IN ("1.2.3.4")). Filter for OT assets (e.g., +ComputerName:/(PLC|RTU)/i).
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
-- References:
-- - https://www.cisa.gov/uscert/ics/publications/recommended-practice-improving-industrial-control-system-cybersecurity-network

-- Rule: Uses NetworkConnectTCPv4 to detect IT-to-OT traffic on OT ports, excluding authorized connections. Filters for OT assets and maps ports to protocols.
event_platform=Win event_simpleName=NetworkConnectTCPv4 dest_port IN (502, 20000, 44818, 2222) SourceAddressIP4:/^(10.|172.(1[6-9]|2[0-9]|3[0-1]).|192.168.)/ RemoteAddressIP4:/^100.64./ !concat(SourceAddressIP4, ":", RemoteAddressIP4, ":", dest_port) IN ("10.1.1.100:100.64.10.50:502", "10.1.2.200:100.64.20.75:44818") +ComputerName:/(PLC|RTU|GRID)/i
| stats min(@timestamp) as firstTime max(@timestamp) as lastTime sum(count) as ConnectionCount by SourceAddressIP4 RemoteAddressIP4 dest_port
| eval protocol=case(dest_port==502, "Modbus", dest_port==20000, "DNP3", dest_port==44818, "EtherNet/IP (TCP)", dest_port==2222, "EtherNet/IP (UDP)", true, "Other")
| rename SourceAddressIP4 as SourceIT_IP RemoteAddressIP4 as DestinationOT_IP dest_port as DestinationPort
| table firstTime lastTime SourceIT_IP DestinationOT_IP DestinationPort protocol ConnectionCount
-- Potential False Positives: Legitimate systems like data historians or engineering workstations. Maintain allowlist for authorized connections (e.g., !concat(SourceAddressIP4, ":", RemoteAddressIP4, ":", dest_port) IN (...)). Filter for OT assets (e.g., +ComputerName:/(PLC|RTU)/i).
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

-- Rule: Uses NetworkConnectTCPv4 to detect sources scanning multiple OT devices on OT ports. Excludes allowlisted scanners and applies threshold for distinct devices.
event_platform=Win event_simpleName=NetworkConnectTCPv4 dest_port IN (502, 20000, 44818, 2222) !SourceAddressIP4 IN ("192.168.1.100", "10.10.0.50") +ComputerName:/(PLC|RTU|GRID)/i
| stats min(@timestamp) as StartTime max(@timestamp) as EndTime dc(RemoteAddressIP4) as DistinctOTDevicesScanned values(RemoteAddressIP4) as ScannedOT_IPs values(dest_port) as ScannedPorts sum(count) as TotalConnections by SourceAddressIP4
| where DistinctOTDevicesScanned > 3
| eval ScannerLocation=if(SourceAddressIP4:/^(10.|192.168.|172.(1[6-9]|2[0-9]|3[0-1]).)/, "Internal", "External")
| rename SourceAddressIP4 as ScannerIP
| table StartTime EndTime ScannerIP ScannerLocation DistinctOTDevicesScanned TotalConnections ScannedOT_IPs ScannedPorts
-- Potential False Positives: Legitimate vulnerability scanners or network management tools. Tune threshold (e.g., DistinctOTDevicesScanned > 3) and maintain scanner allowlist (e.g., !SourceAddressIP4 IN (...)). Filter for OT assets (e.g., +ComputerName:/(PLC|RTU)/i).
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
-- References:
-- - https://unit42.paloaltonetworks.com/erlang-otp-cve-2025-32433/
-- - https://gbhackers.com/erlang-otp-ssh-rce-vulnerability-actively-exploited/

-- Rule: Uses NetworkAcceptTCPv4 for non-standard SSH connections and ProcessRollup2 for shell spawning by Erlang processes. Filters for OT subnets and devices.
(
    (event_platform=Win event_simpleName=NetworkAcceptTCPv4 dest_port IN (2222) ImageFileName IN ("beam.smp", "beam", "erl", "erlexec") RemoteAddressIP4:/^(10.100.|192.168.50.)/ +ComputerName:/(PLC|RTU|GRID)/i
    | eval activity="Non-Standard SSH Port Connection to Erlang Process" parent_process_name="N/A" command_line="N/A" local_port=dest_port remote_ip=RemoteAddressIP4)
| append [
        event_platform=Win event_simpleName=ProcessRollup2 ImageFileName IN ("bash", "sh", "zsh", "csh", "ksh", "cmd.exe", "powershell.exe") ParentBaseFileName IN ("beam.smp", "beam", "erl", "erlexec") RemoteAddressIP4:/^(10.100.|192.168.50.)/ +ComputerName:/(PLC|RTU|GRID)/i
        | eval activity="Shell Spawned by Erlang Process" local_port="N/A" remote_ip="N/A" command_line=CommandLine
    ]
)
| stats min(@timestamp) as _time values(activity) as activity values(ImageFileName) as process_name values(parent_process_name) as parent_process_name values(command_line) as command_line values(local_port) as local_port values(remote_ip) as remote_ip by ComputerName
| rename ComputerName as host
| table _time activity host process_name parent_process_name command_line local_port remote_ip
-- Potential False Positives: Legitimate Erlang/OTP apps using non-standard SSH ports or bespoke scripts spawning shells. Verify findings and maintain OT subnet definitions (e.g., RemoteAddressIP4:/^(10.100.|192.168.50.)/). Filter for OT devices (e.g., +ComputerName:/(PLC|RTU)/i).
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

-- Rule: Uses NetworkConnectTCPv4 to detect new devices or new port usage in OT subnets. Compares recent activity (last 24h) against a 14-day baseline. Filters for OT devices.
(
    -- Tactic 1: New OT Devices
    (event_platform=Win event_simpleName=NetworkConnectTCPv4 RemoteAddressIP4:/^(10.100.|192.168.50.)/ +ComputerName:/(PLC|RTU|GRID)/i @timestamp >now()-1d
    | stats min(@timestamp) as StartTime max(@timestamp) as EndTime values(dest_port) as Port values(SourceAddressIP4) as ConnectedRemoteIPs by ComputerName RemoteAddressIP4
    | where !RemoteAddressIP4 IN (subquery[event_platform=Win event_simpleName=NetworkConnectTCPv4 RemoteAddressIP4:/^(10.100.|192.168.50.)/ @timestamp >now()-14d AND @timestamp <now()-1d
    | stats values(RemoteAddressIP4) by RemoteAddressIP4])
    | eval DeviationType="New OT Device Detected" Details="New device appeared on the OT network. Ports used: " + mvjoin(Port, ", ")
    | rename ComputerName as DeviceName RemoteAddressIP4 as OT_DeviceIP)
| append [
        -- Tactic 2: New Port Usage on Existing Devices
        event_platform=Win event_simpleName=NetworkConnectTCPv4 RemoteAddressIP4:/^(10.100.|192.168.50.)/ +ComputerName:/(PLC|RTU|GRID)/i @timestamp >now()-1d
        | stats min(@timestamp) as StartTime max(@timestamp) as EndTime values(SourceAddressIP4) as ConnectedRemoteIPs by ComputerName RemoteAddressIP4 dest_port
        | where concat(RemoteAddressIP4, ":", dest_port) NOT IN (subquery[event_platform=Win event_simpleName=NetworkConnectTCPv4 RemoteAddressIP4:/^(10.100.|192.168.50.)/ @timestamp >now()-14d AND @timestamp <now()-1d
        | stats values(concat(RemoteAddressIP4, ":", dest_port)) by RemoteAddressIP4]) AND RemoteAddressIP4 IN (subquery[event_platform=Win event_simpleName=NetworkConnectTCPv4 RemoteAddressIP4:/^(10.100.|192.168.50.)/ @timestamp >now()-14d AND @timestamp <now()-1d
        | stats values(RemoteAddressIP4) by RemoteAddressIP4])
        | eval DeviationType="New OT Communication Pattern Detected" Details="Existing device communicated on a new port: " + dest_port + ". Connected from/to remote IPs: " + mvjoin(ConnectedRemoteIPs, ", ")
        | rename ComputerName as DeviceName RemoteAddressIP4 as OT_DeviceIP dest_port as Port
    ]
)
| table StartTime EndTime DeviationType DeviceName OT_DeviceIP Details ConnectedRemoteIPs Port
-- Potential False Positives: Legitimate new devices or configuration changes. Correlate with change management records. Tune baseline periods (e.g., @timestamp >now()-14d) and OT subnet definitions (e.g., RemoteAddressIP4:/^(10.100.|192.168.50.)/). Filter for OT devices (e.g., +ComputerName:/(PLC|RTU)/i).
```