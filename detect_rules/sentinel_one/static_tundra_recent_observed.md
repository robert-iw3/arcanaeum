### Static Tundra Threat Report
---

Static Tundra, a Russian state-sponsored cyber espionage group linked to the FSB's Center 16, has been actively exploiting a seven-year-old vulnerability (CVE-2018-0171) in unpatched and end-of-life Cisco network devices. The group specializes in long-term intelligence gathering, focusing on telecommunications, higher education, and manufacturing sectors globally, with a notable increase in activity against Ukrainian entities since the start of the Russia-Ukraine war.

Recent intelligence confirms Static Tundra's continued aggressive exploitation of CVE-2018-0171, with the FBI observing the collection of configuration files from thousands of U.S. critical infrastructure devices in the past year, indicating an ongoing and widespread campaign. Additionally, the group is actively modifying TACACS+ configurations to hinder remote logging and altering Access Control Lists (ACLs) to permit access from their controlled IP addresses, showcasing evolving defense evasion tactics.

### Actionable Threat Data
---

Monitor for inbound TFTP connections to network devices, especially those attempting to retrieve startup-config or running-config files, as this is a key exfiltration method for Static Tundra.

Look for unusual or unauthorized modifications to TACACS+ configurations or ACLs on network devices, which could indicate defense evasion and persistence efforts by the threat actor.

Detect attempts to enable the local TFTP server on Cisco devices via command-line logs, specifically the command tftp-server nvram:startup-config, which Static Tundra uses to facilitate configuration exfiltration.

Identify network traffic patterns indicative of Generic Routing Encapsulation (GRE) tunnels being established from network devices to external, potentially malicious, IP addresses, as this is used for data collection and exfiltration.

Search for the presence of the SYNful Knock implant on Cisco IOS devices by leveraging available scanning tools and monitoring for "magic packets" (specifically crafted TCP SYN packets) that trigger remote access.

### Consolidated Analysis Search
---
```sql
----------------------------------------------------------------------------------
-- Name:         Static Tundra Group Activity
-- Author:       RW
-- Date:         2025-08-22

-- Description:  This detection looks for a combination of Tactics, Techniques, and
--               Procedures (TTPs) associated with the Russian state-sponsored
--               group Static Tundra. This includes network communications to
--               known C2 IPs, network device configuration changes, and data
--               exfiltration techniques.

-- References:   - https://blog.talosintelligence.com/static-tundra/

-- False Positive Sensitivity: Medium

-- Tactic:       Initial Access, Persistence, Defense Evasion, Collection, Exfiltration

-- Technique:    T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts),
--               T1098.002 (Create Account: Local Account), T1562.007 (Disable or
--               Modify Cloud Firewall), T1020 (Automated Exfiltration), T1048 (Exfiltration
--               Over Alternative Protocol)
----------------------------------------------------------------------------------

SELECT EventTime AS _time, COALESCE(NetworkSrcIP, 'N/A') AS src, COALESCE(NetworkDestIP, EndpointName) AS dest, UserName AS user,
  GROUP_CONCAT(DISTINCT detection_technique) AS detection_techniques, GROUP_CONCAT(DISTINCT command) AS commands,
  'Potential Static Tundra activity detected. Techniques observed: ' || GROUP_CONCAT(DISTINCT detection_technique) || '. Source: ' || src || ', Destination: ' || dest || ', User: ' || user AS message
FROM (
  /* IOC Search: Known Static Tundra C2 IPs */
  SELECT EventTime, NetworkSrcIP, NetworkDestIP, UserName, 'Static Tundra C2 IP Detected' AS detection_technique, 'N/A' AS command
  FROM deep_visibility
  WHERE EventType = 'Network Connect' AND (NetworkSrcIP IN ('185.141.24.222', '185.82.202.34', '185.141.24.28', '185.82.200.181') OR NetworkDestIP IN ('185.141.24.222', '185.82.202.34', '185.141.24.28', '185.82.200.181'))
  UNION
  /* Network TTPs: Inbound TFTP or GRE */
  SELECT EventTime, NetworkSrcIP, NetworkDestIP, UserName,
    CASE
      WHEN NetworkDestPort = '69' THEN 'Potential Inbound TFTP for Config Exfil'
      WHEN NetworkProtocol = 'GRE' THEN 'GRE Tunnel Established for Traffic Collection'
    END AS detection_technique, 'N/A' AS command
  FROM deep_visibility
  WHERE EventType = 'Network Connect' AND ((NetworkProtocol = 'UDP' AND NetworkDestPort = '69') OR NetworkProtocol = 'GRE')
  UNION
  /* Command Line TTPs: Specific Cisco commands */
  SELECT EventTime, NULL AS NetworkSrcIP, EndpointName AS NetworkDestIP, UserName,
    CASE
      WHEN SrcProcCmdLine LIKE '%tftp-server nvram:startup-config%' THEN 'Local TFTP Server Enabled for Config Exfil'
      WHEN SrcProcCmdLine LIKE '%redirect tftp://%' THEN 'Config Exfil via TFTP Redirect'
      WHEN SrcProcCmdLine LIKE '%copy running-config ftp://%' THEN 'Config Exfil via FTP'
      WHEN SrcProcCmdLine LIKE '%access-list %' THEN 'ACL Modification Detected'
      WHEN SrcProcCmdLine LIKE '%tacacs-server %' THEN 'TACACS+ Config Modification Detected'
    END AS detection_technique, SrcProcCmdLine AS command
  FROM deep_visibility
  WHERE EventType = 'Process Start' AND (
    SrcProcCmdLine LIKE '%tftp-server nvram:startup-config%' OR
    SrcProcCmdLine LIKE '%redirect tftp://%' OR
    SrcProcCmdLine LIKE '%copy running-config ftp://%' OR
    SrcProcCmdLine LIKE '%access-list %' OR
    SrcProcCmdLine LIKE '%tacacs-server %'
  )
) AS ttps
GROUP BY _time, src, dest, user
ORDER BY _time DESC
LIMIT 1000
```