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
-- Data requirement: Sources network, dns with dest_host, dns.query fields.
-- FP Tuning: Filter @src_host against public-facing assets list via external processor.
source:(network OR dns) AND (@dest_host:("aar.gandhibludtric.com" OR "aria-hidden.com" OR "asparticrooftop.com" OR "caret-right.com" OR "chatscreend.com" OR "chekoodver.com" OR "cloudprocenter.com" OR "clubworkmistake.com" OR "col-lg.com" OR "colourtinctem.com" OR "componfrom.com" OR "dateupdata.com" OR "e-forwardviewupdata.com" OR "fessionalwork.com" OR "fjtest-block.com" OR "fitbookcatwer.com" OR "followkoon.com" OR "gandhibludtric.com" OR "gesturefavour.com" OR "getdbecausehub.com" OR "goldenunder.com" OR "hateupopred.com" OR "imap.dateupdata.com" OR "incisivelyfut.com" OR "infraredsen.com" OR "junsamyoung.com" OR "lookpumrron.com" OR "materialplies.com" OR "morrowadded.com" OR "newhkdaily.com" OR "onlineeylity.com" OR "pulseathermakf.com" OR "qatarpenble.com" OR "redbludfootvr.com" OR "requiredvalue.com" OR "ressicepro.com" OR "shalaordereport.com" OR "siderheycook.com" OR "sinceretehope.com" OR "solveblemten.com" OR "togetheroffway.com" OR "toodblackrun.com" OR "troublendsef.com" OR "unfeelmoonvd.com" OR "verfiedoccurr.com" OR "waystrkeprosh.com" OR "xdmgwctese.com") OR @dns.query:("aar.gandhibludtric.com" OR "aria-hidden.com" OR "asparticrooftop.com" OR "caret-right.com" OR "chatscreend.com" OR "chekoodver.com" OR "cloudprocenter.com" OR "clubworkmistake.com" OR "col-lg.com" OR "colourtinctem.com" OR "componfrom.com" OR "dateupdata.com" OR "e-forwardviewupdata.com" OR "fessionalwork.com" OR "fjtest-block.com" OR "fitbookcatwer.com" OR "followkoon.com" OR "gandhibludtric.com" OR "gesturefavour.com" OR "getdbecausehub.com" OR "goldenunder.com" OR "hateupopred.com" OR "imap.dateupdata.com" OR "incisivelyfut.com" OR "infraredsen.com" OR "junsamyoung.com" OR "lookpumrron.com" OR "materialplies.com" OR "morrowadded.com" OR "newhkdaily.com" OR "onlineeylity.com" OR "pulseathermakf.com" OR "qatarpenble.com" OR "redbludfootvr.com" OR "requiredvalue.com" OR "ressicepro.com" OR "shalaordereport.com" OR "siderheycook.com" OR "sinceretehope.com" OR "solveblemten.com" OR "togetheroffway.com" OR "toodblackrun.com" OR "troublendsef.com" OR "unfeelmoonvd.com" OR "verfiedoccurr.com" OR "waystrkeprosh.com" OR "xdmgwctese.com")) AND @src_host:*public-facing*
-- In Log Explorer, facet by @src_host, @dest_host, @user, @app, @action; aggregate min/max @timestamp, sum(count).
```

### C2 Communications with Fake WHOIS
---
```sql
-- Detects DNS queries for domains with Salt Typhoon/UNC4841 name servers and ProtonMail registrants.
-- Data requirement: Source dns with enriched @ns_server, @registrant_email.
-- FP Tuning: Enrich via processors for PDNS/WHOIS; review @registrant_email for gibberish.
source:dns AND @ns_server:/(1domainregistry\.com|orderbox-dns\.com|monovm\.com|naracauva\.com\.ru)$/i AND @registrant_email:*@protonmail.com
-- In Log Explorer, facet by @dest_domain; aggregate values(@src_hosts, @registrant_email, @ns_server), min/max @timestamp.
```

### Credential Dumping and Harvesting
---
```sql
-- Detects non-browser processes accessing browser credential files (T1003).
-- Data requirement: Source endpoint with @process.command_line, @process.name.
-- FP Tuning: Exclude legitimate password managers/backup tools in @process.name.
source:endpoint AND (@process.command_line:*Login Data* OR *Web Data* OR *Cookies* OR *key4.db* OR *logins.json*) AND @process.name:!("chrome.exe" OR "msedge.exe" OR "firefox.exe" OR "brave.exe" OR "opera.exe" OR "vivaldi.exe") AND @process.command_line:/AppData\\\(Local|Roaming\)\\\(Google|Microsoft|BraveSoftware|Mozilla|Opera Software)/i AND (@process.command_line:/(Login Data|Web Data|Cookies|key4\.db|logins\.json)/i)
-- In Log Explorer, facet by @dest_host, @user, @parent_process.name, @process.name; aggregate count, min/max @timestamp.
```

### Lateral Movement via GRE Tunnels/SSH
---
```sql
-- Detects network device configuration changes for GRE tunnels or SSH loopback (T1021).
-- Data requirement: Sources cisco, juniper, pan with @message field.
-- FP Tuning: Correlate with authorized admin activity or lookup of known admins.
source:(cisco OR juniper OR pan) AND @message:/(interface\s+tunnel\d+|ip\s+ssh\s+source-interface\s+loopback\d+|set\s+system\s+services\s+ssh\s+source-address|set\s+interfaces\s+gre)/i
-- In Log Explorer, facet by @host, @user; aggregate min/max @timestamp, values(@message).
```

### Log Clearing for Defense Evasion
---
```sql
-- Detects attempts to clear Linux log files (T1070).
-- Data requirement: Source endpoint with @process.name, @process.command_line.
-- FP Tuning: Exclude authorized log rotation scripts (e.g., logrotate.sh).
source:endpoint AND [(@process.name:("shred" OR "truncate" OR "rm") AND @process.command_line:/(\.bash_history|auth\.log|lastlog|wtmp|btmp)/i) OR (@process.command_line:/(cat \/dev\/null|echo|printf '')/i AND @process.command_line:/>\s*.*(\.bash_history|auth\.log|lastlog|wtmp|btmp)/i) OR (@process.name:("bash" OR "sh" OR "zsh" OR "ksh") AND @process.command_line:/^\s*>\s*.*(\.bash_history|auth\.log|lastlog|wtmp|btmp)/i) OR (@process.name:"history" AND @process.command_line:* -c)]
-- In Log Explorer, facet by @dest_host, @user, @process.name; aggregate count, min/max @timestamp.
```