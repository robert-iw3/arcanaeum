### Salt Typhoon and UNC4841 Threat Intelligence Report
---

Salt Typhoon and UNC4841 are sophisticated, state-sponsored Chinese APT groups primarily engaged in cyber espionage, targeting telecommunications, government, and critical infrastructure globally. They are known for exploiting vulnerabilities to gain long-term, stealthy access and exfiltrate sensitive data.

Recent findings indicate a significant infrastructure overlap and potential coordination between Salt Typhoon and UNC4841, suggesting a more unified Chinese state-sponsored cyber operation. This collaboration enhances their ability to maintain persistence and adapt to defensive measures, as evidenced by UNC4841's rapid malware modifications post-patching.

### Actionable Threat Data
---

Exploitation of Public-Facing Applications (T1190):

Both Salt Typhoon and UNC4841 exploit vulnerabilities in internet-facing software and appliances for initial access. Notably, UNC4841 exploited CVE-2023-2868 in Barracuda Email Security Gateway (ESG) appliances. Salt Typhoon has also exploited CVE-2018-0171 in Cisco IOS and IOS XE software, and vulnerabilities in Sophos Firewall, Ivanti VPN, Fortinet FortiClient EMS, and Microsoft Exchange Server.

Command and Control (T1071):

The groups utilize newly identified domains for C2 communications, often registered with fake WHOIS information (e.g., gibberish ProtonMail addresses, non-existent US addresses, and generic English names). These domains frequently use specific name servers such as *.1domainregistry[.]com, *.orderbox-dns[.]com, *.monovm[.]com, and *.naracauva[.]com[.]ru.

Persistence (T1547):

Salt Typhoon maintains persistence through custom malware like Demodex rootkit, Snappybee, Ghostspider backdoors, and Masol RAT. UNC4841 deploys malware families such as SKIPJACK, DEPTHCHARGE (aka SUBMARINE), FOXTROT, and FOXGLOVE to maintain access, even modifying them in response to remediation efforts.

Credential Access (T1003):

Salt Typhoon has been observed dumping network device configurations to acquire credentials and using tools like Trill Client to harvest administrative credentials from browser caches.

Lateral Movement (T1021):

Salt Typhoon uses harvested valid account credentials to access remote systems and spread malware. They also modify device configurations to create and use Generic Routing Encapsulation (GRE) tunnels and alter loopback addresses for SSH connections to bypass ACLs. UNC4841 performs internal reconnaissance and lateral movement using open-source tools like fscan.

Defense Evasion (T1070):

Salt Typhoon clears logs, including .bash_history, auth.log, lastlog, wtmp, and btmp. UNC4841's malware, such as FOXTROT, uses a lightweight XOR cipher with a dynamically rotated key for configuration files and network traffic payloads.

### Exploitation of Public-Facing Applications
---
```sql
-- Detects network connections to Salt Typhoon/UNC4841 C2 domains from public-facing assets (T1190).
-- Data requirement: network_events, dns_events with NetworkDest, DnsQuery.
-- FP Tuning: Filter SrcHost against public-facing assets list (external enrichment).
SELECT COUNT(*) AS event_count, MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime, NetworkDest, SrcHost, User
FROM network_events
WHERE NetworkDest IN ("aar.gandhibludtric.com", "aria-hidden.com", "asparticrooftop.com", "caret-right.com", "chatscreend.com", "chekoodver.com", "cloudprocenter.com", "clubworkmistake.com", "col-lg.com", "colourtinctem.com", "componfrom.com", "dateupdata.com", "e-forwardviewupdata.com", "fessionalwork.com", "fjtest-block.com", "fitbookcatwer.com", "followkoon.com", "gandhibludtric.com", "gesturefavour.com", "getdbecausehub.com", "goldenunder.com", "hateupopred.com", "imap.dateupdata.com", "incisivelyfut.com", "infraredsen.com", "junsamyoung.com", "lookpumrron.com", "materialplies.com", "morrowadded.com", "newhkdaily.com", "onlineeylity.com", "pulseathermakf.com", "qatarpenble.com", "redbludfootvr.com", "requiredvalue.com", "ressicepro.com", "shalaordereport.com", "siderheycook.com", "sinceretehope.com", "solveblemten.com", "togetheroffway.com", "toodblackrun.com", "troublendsef.com", "unfeelmoonvd.com", "verfiedoccurr.com", "waystrkeprosh.com", "xdmgwctese.com") OR DnsQuery IN ("aar.gandhibludtric.com", "aria-hidden.com", "asparticrooftop.com", "caret-right.com", "chatscreend.com", "chekoodver.com", "cloudprocenter.com", "clubworkmistake.com", "col-lg.com", "colourtinctem.com", "componfrom.com", "dateupdata.com", "e-forwardviewupdata.com", "fessionalwork.com", "fjtest-block.com", "fitbookcatwer.com", "followkoon.com", "gandhibludtric.com", "gesturefavour.com", "getdbecausehub.com", "goldenunder.com", "hateupopred.com", "imap.dateupdata.com", "incisivelyfut.com", "infraredsen.com", "junsamyoung.com", "lookpumrron.com", "materialplies.com", "morrowadded.com", "newhkdaily.com", "onlineeylity.com", "pulseathermakf.com", "qatarpenble.com", "redbludfootvr.com", "requiredvalue.com", "ressicepro.com", "shalaordereport.com", "siderheycook.com", "sinceretehope.com", "solveblemten.com", "togetheroffway.com", "toodblackrun.com", "troublendsef.com", "unfeelmoonvd.com", "verfiedoccurr.com", "waystrkeprosh.com", "xdmgwctese.com")
AND SrcHost IN (SELECT asset FROM public_facing_assets)  -- External enrichment
GROUP BY SrcHost, NetworkDest, User
```

### C2 Communications with Fake WHOIS
---
```sql
-- Detects DNS queries for domains with Salt Typhoon/UNC4841 name servers and ProtonMail registrants.
-- Data requirement: dns_events with enriched NsServer, RegistrantEmail.
-- FP Tuning: Review RegistrantEmail for gibberish patterns.
SELECT MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime, VALUES(SrcHost) AS src_hosts, VALUES(RegistrantEmail) AS registrant_email, VALUES(NsServer) AS name_servers
FROM dns_events
WHERE NsServer LIKE '%1domainregistry.com' OR '%orderbox-dns.com' OR '%monovm.com' OR '%naracauva.com.ru' AND RegistrantEmail LIKE '%@protonmail.com'
GROUP BY DnsQuery AS dest_domain
```

### Credential Dumping and Harvesting
---
```sql
-- Detects non-browser processes accessing browser credential files (T1003).
-- Data requirement: process_events with SrcProcCmdLine, SrcProcImagePath.
-- FP Tuning: Exclude legitimate password managers/backup tools in SrcProcImagePath.
SELECT COUNT(*) AS count, MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime, SrcProcCmdLine AS process_command_line
FROM process_events
WHERE SrcProcCmdLine LIKE '%Login Data%' OR '%Web Data%' OR '%Cookies%' OR '%key4.db%' OR '%logins.json%'
AND SrcProcImagePath NOT IN ('chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe', 'vivaldi.exe')
AND SrcProcCmdLine LIKE '%AppData%Local%Google%' OR '%AppData%Roaming%Google%' OR '%AppData%Local%Microsoft%' OR '%AppData%Roaming%Microsoft%' OR '%AppData%Local%BraveSoftware%' OR '%AppData%Roaming%Mozilla%' OR '%AppData%Opera Software%'
AND (SrcProcCmdLine LIKE '%Login Data%' OR '%Web Data%' OR '%Cookies%' OR '%key4.db%' OR '%logins.json%')
GROUP BY DstHost, User, ParentProcImagePath, SrcProcImagePath
```

### Lateral Movement via GRE Tunnels/SSH
---
```sql
-- Detects network device configuration changes for GRE tunnels or SSH loopback (T1021).
-- Data requirement: process_events from network devices (e.g., cisco:ios).
-- FP Tuning: Correlate with authorized admin activity or lookup of known admins.
SELECT COUNT(*) AS count, MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime, VALUES(SrcProcCmdLine) AS command
FROM process_events
WHERE SrcProcCmdLine LIKE '%interface tunnel%' OR '%ip ssh source-interface loopback%' OR '%set system services ssh source-address%' OR '%set interfaces gre%'
GROUP BY DstHost, User
```

### Log Clearing for Defense Evasion
---
```sql
-- Detects attempts to clear Linux log files (T1070).
-- Data requirement: process_events with SrcProcImagePath, SrcProcCmdLine.
-- FP Tuning: Exclude authorized log rotation scripts (e.g., logrotate.sh).
SELECT COUNT(*) AS count, MIN(EventTime) AS firstTime, MAX(EventTime) AS lastTime, VALUES(SrcProcCmdLine) AS process_command
FROM process_events
WHERE (
  (SrcProcImagePath IN ('shred', 'truncate', 'rm') AND SrcProcCmdLine LIKE '%.bash_history%' OR '%auth.log%' OR '%lastlog%' OR '%wtmp%' OR '%btmp%') OR
  (SrcProcCmdLine LIKE '%cat /dev/null%' OR '%echo%' OR '%printf %' AND SrcProcCmdLine LIKE '%> %.bash_history%' OR '%> %auth.log%' OR '%> %lastlog%' OR '%> %wtmp%' OR '%> %btmp%') OR
  (SrcProcImagePath IN ('bash', 'sh', 'zsh', 'ksh') AND SrcProcCmdLine LIKE '%> %.bash_history%' OR '%> %auth.log%' OR '%> %lastlog%' OR '%> %wtmp%' OR '%> %btmp%') OR
  (SrcProcImagePath = 'history' AND SrcProcCmdLine LIKE '% -c')
)
GROUP BY DstHost, User, SrcProcImagePath
```