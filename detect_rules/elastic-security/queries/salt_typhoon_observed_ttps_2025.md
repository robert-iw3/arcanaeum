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
-- Data requirement: Indices network-*, dns-* with ECS fields.
-- FP Tuning: Filter source.ip against public-facing assets list (external enrichment).
FROM network-*,dns-*
| WHERE destination.domain IN ("aar.gandhibludtric.com", "aria-hidden.com", "asparticrooftop.com", "caret-right.com", "chatscreend.com", "chekoodver.com", "cloudprocenter.com", "clubworkmistake.com", "col-lg.com", "colourtinctem.com", "componfrom.com", "dateupdata.com", "e-forwardviewupdata.com", "fessionalwork.com", "fjtest-block.com", "fitbookcatwer.com", "followkoon.com", "gandhibludtric.com", "gesturefavour.com", "getdbecausehub.com", "goldenunder.com", "hateupopred.com", "imap.dateupdata.com", "incisivelyfut.com", "infraredsen.com", "junsamyoung.com", "lookpumrron.com", "materialplies.com", "morrowadded.com", "newhkdaily.com", "onlineeylity.com", "pulseathermakf.com", "qatarpenble.com", "redbludfootvr.com", "requiredvalue.com", "ressicepro.com", "shalaordereport.com", "siderheycook.com", "sinceretehope.com", "solveblemten.com", "togetheroffway.com", "toodblackrun.com", "troublendsef.com", "unfeelmoonvd.com", "verfiedoccurr.com", "waystrkeprosh.com", "xdmgwctese.com") OR dns.question.name IN ("aar.gandhibludtric.com", "aria-hidden.com", "asparticrooftop.com", "caret-right.com", "chatscreend.com", "chekoodver.com", "cloudprocenter.com", "clubworkmistake.com", "col-lg.com", "colourtinctem.com", "componfrom.com", "dateupdata.com", "e-forwardviewupdata.com", "fessionalwork.com", "fjtest-block.com", "fitbookcatwer.com", "followkoon.com", "gandhibludtric.com", "gesturefavour.com", "getdbecausehub.com", "goldenunder.com", "hateupopred.com", "imap.dateupdata.com", "incisivelyfut.com", "infraredsen.com", "junsamyoung.com", "lookpumrron.com", "materialplies.com", "morrowadded.com", "newhkdaily.com", "onlineeylity.com", "pulseathermakf.com", "qatarpenble.com", "redbludfootvr.com", "requiredvalue.com", "ressicepro.com", "shalaordereport.com", "siderheycook.com", "sinceretehope.com", "solveblemten.com", "togetheroffway.com", "toodblackrun.com", "troublendsef.com", "unfeelmoonvd.com", "verfiedoccurr.com", "waystrkeprosh.com", "xdmgwctese.com")
| WHERE source.ip IN (SELECT ip FROM public_facing_assets)  -- External enrichment needed
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), event_count = COUNT(*), app = VALUES(http.request.referrer), user = VALUES(user.name), action = VALUES(event.action) BY source.ip, destination.domain
| KEEP firstTime, lastTime, source.ip AS src_host, destination.domain AS dest_host, app, user, action, event_count
| SORT firstTime DESC
| LIMIT 10000
```

### C2 Communications with Fake WHOIS
---
```sql
-- Detects DNS queries for domains with Salt Typhoon/UNC4841 name servers and ProtonMail registrants.
-- Data requirement: Index dns-* with enriched ns_server, registrant_email.
-- FP Tuning: Review registrant_email for gibberish patterns.
FROM dns-*
| EVAL ns_server = COALESCE(ns_server, "external")  -- Assume enriched
| WHERE ns_server RLIKE "(?i)(\\.1domainregistry\\.com|\\.orderbox-dns\\.com|\\.monovm\\.com|\\.naracauva\\.com\\.ru)$" AND registrant_email LIKE "%@protonmail.com"
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), src_hosts = VALUES(source.ip), registrant_email = VALUES(registrant_email), name_servers = VALUES(ns_server) BY dns.question.name AS dest_domain
| KEEP firstTime, lastTime, src_hosts, dest_domain AS suspicious_domain, registrant_email, name_servers
| SORT firstTime DESC
| LIMIT 10000
```

### Credential Dumping and Harvesting
---
```sql
-- Detects non-browser processes accessing browser credential files (T1003).
-- Data requirement: Index endpoint-* with ECS fields.
-- FP Tuning: Exclude legitimate password managers/backup tools in process.name.
FROM endpoint-*
| WHERE process.command_line LIKE "%Login Data%" OR "%Web Data%" OR "%Cookies%" OR "%key4.db%" OR "%logins.json%" AND process.name NOT IN ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe")
| WHERE process.command_line RLIKE "(?i)AppData\\\\(Local|Roaming)\\\\(Google|Microsoft|BraveSoftware|Mozilla|Opera Software)" AND (process.command_line RLIKE "(?i)(Login Data|Web Data|Cookies|key4.db|logins.json)")
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), count = COUNT(*) BY host.name, user.name, parent.process.executable, process.name
| KEEP firstTime, lastTime, host.name AS dest_host, user.name AS user, parent.process.executable AS parent_process, process.name AS process_name, process.command_line, count
| SORT firstTime DESC
| LIMIT 10000
```

### Lateral Movement via GRE Tunnels/SSH
---
```sql
-- Detects network device configuration changes for GRE tunnels or SSH loopback (T1021).
-- Data requirement: Index network-* or syslog-* with ECS message field.
-- FP Tuning: Correlate with authorized admin activity or lookup of known admins.
FROM network-*,syslog-*
| WHERE message RLIKE "(?i)(interface\s+tunnel\d+|ip\s+ssh\s+source-interface\s+loopback\d+|set\s+system\s+services\s+ssh\s+source-address|set\s+interfaces\s+gre)"
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), command = VALUES(message), count = COUNT(*) BY host.name, user.name
| KEEP firstTime, lastTime, host.name AS dest_device, user.name AS user_executing_change, command, count
| SORT firstTime DESC
| LIMIT 10000
```

### Log Clearing for Defense Evasion
---
```sql
-- Detects attempts to clear Linux log files (T1070).
-- Data requirement: Index endpoint-* with ECS fields.
-- FP Tuning: Exclude authorized log rotation scripts (e.g., logrotate.sh).
FROM endpoint-*
| WHERE ((process.name IN ("shred", "truncate", "rm") AND process.command_line RLIKE "(?i)(\\.bash_history|auth\\.log|lastlog|wtmp|btmp)") OR (process.command_line RLIKE "(?i)(cat /dev/null|echo|printf '')" AND process.command_line RLIKE "(?i)>\\s*.*(\\.bash_history|auth\\.log|lastlog|wtmp|btmp)") OR (process.name IN ("bash", "sh", "zsh", "ksh") AND process.command_line RLIKE "(?i)^\\s*>\\s*.*(\\.bash_history|auth\\.log|lastlog|wtmp|btmp)") OR (process.name == "history" AND process.command_line LIKE "% -c"))
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), process_command = VALUES(process.command_line), count = COUNT(*) BY host.name, user.name, process.name
| KEEP firstTime, lastTime, host.name AS dest_host, user.name AS user, parent.process.executable AS parent_process_name, process.name AS process_name, process_command, count
| SORT firstTime DESC
| LIMIT 10000
```