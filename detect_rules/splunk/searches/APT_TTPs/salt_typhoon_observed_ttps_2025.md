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
-- This detection rule identifies network connections from public-facing assets to known Salt Typhoon/UNC4841 C2 domains, indicating a potential compromise following the exploitation of a public-facing application (T1190).
-- Data source requirement: This rule requires network traffic (proxy, firewall) and/or DNS logs, mapped to the Splunk Common Information Model (CIM). Ensure the 'Network_Traffic' and 'DNS' data models are populated.

| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (dest IN ("aar.gandhibludtric.com", "aria-hidden.com", "asparticrooftop.com", "caret-right.com", "chatscreend.com", "chekoodver.com", "cloudprocenter.com", "clubworkmistake.com", "col-lg.com", "colourtinctem.com", "componfrom.com", "dateupdata.com", "e-forwardviewupdata.com", "fessionalwork.com", "fjtest-block.com", "fitbookcatwer.com", "followkoon.com", "gandhibludtric.com", "gesturefavour.com", "getdbecausehub.com", "goldenunder.com", "hateupopred.com", "imap.dateupdata.com", "incisivelyfut.com", "infraredsen.com", "junsamyoung.com", "lookpumrron.com", "materialplies.com", "morrowadded.com", "newhkdaily.com", "onlineeylity.com", "pulseathermakf.com", "qatarpenble.com", "redbludfootvr.com", "requiredvalue.com", "ressicepro.com", "shalaordereport.com", "siderheycook.com", "sinceretehope.com", "solveblemten.com", "togetheroffway.com", "toodblackrun.com", "troublendsef.com", "unfeelmoonvd.com", "verfiedoccurr.com", "waystrkeprosh.com", "xdmgwctese.com")) by All_Traffic.dest, All_Traffic.src, All_Traffic.user, All_Traffic.app, All_Traffic.action
| `drop_dm_object_name("All_Traffic")`
| append [
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=DNS where (DNS.query IN ("aar.gandhibludtric.com", "aria-hidden.com", "asparticrooftop.com", "caret-right.com", "chatscreend.com", "chekoodver.com", "cloudprocenter.com", "clubworkmistake.com", "col-lg.com", "colourtinctem.com", "componfrom.com", "dateupdata.com", "e-forwardviewupdata.com", "fessionalwork.com", "fjtest-block.com", "fitbookcatwer.com", "followkoon.com", "gandhibludtric.com", "gesturefavour.com", "getdbecausehub.com", "goldenunder.com", "hateupopred.com", "imap.dateupdata.com", "incisivelyfut.com", "infraredsen.com", "junsamyoung.com", "lookpumrron.com", "materialplies.com", "morrowadded.com", "newhkdaily.com", "onlineeylity.com", "pulseathermakf.com", "qatarpenble.com", "redbludfootvr.com", "requiredvalue.com", "ressicepro.com", "shalaordereport.com", "siderheycook.com", "sinceretehope.com", "solveblemten.com", "togetheroffway.com", "toodblackrun.com", "troublendsef.com", "unfeelmoonvd.com", "verfiedoccurr.com", "waystrkeprosh.com", "xdmgwctese.com")) by DNS.query as dest, DNS.src
    | `drop_dm_object_name("DNS")`
]
-- The tstats commands efficiently search for any communication to the hardcoded list of C2 domains.

| stats min(firstTime) as firstTime max(lastTime) as lastTime sum(count) as event_count values(app) as app values(user) as user values(action) as action by src, dest
-- Aggregate results to get a summary of the communication.

-- FP Tuning: This is the key filtering step. Create a lookup file named 'public_facing_assets.csv' with a single column 'asset' containing the IP addresses or hostnames of your public-facing servers (e.g., Exchange, Barracuda, VPNs, Firewalls). This focuses the alert on potentially compromised servers.
| lookup public_facing_assets.csv asset as src OUTPUT asset
| where isnotnull(asset)

| rename src as src_host, dest as dest_host
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| fields firstTime, lastTime, src_host, dest_host, app, user, action, event_count
```

### C2 Communications with Fake WHOIS
---
```sql
-- This detection rule identifies DNS queries for domains that match registration patterns (TTPs) associated with the Salt Typhoon and UNC4841 APT groups. This rule is designed to find *new* C2 infrastructure, not just known-bad domains.
-- IMPORTANT: This rule has significant data prerequisites. It requires two custom lookups populated with external data: 1) A passive DNS lookup to identify name servers for a domain. 2) A WHOIS lookup to identify the registrant's email address.

| tstats `summariesonly` min(_time) as firstTime, max(_time) as lastTime, values(DNS.src) as src_hosts from datamodel=DNS by DNS.query
| `drop_dm_object_name("DNS")`
| rename DNS.query as dest_domain

-- FP Tuning: Enrich DNS queries with name server information. The lookup file 'pdns_nameservers.csv' should contain fields 'dest_domain' and 'ns_server'. This data must be sourced from a passive DNS provider.
| lookup pdns_nameservers.csv dest_domain OUTPUT ns_server
| where isnotnull(ns_server)
| mvexpand ns_server

-- Filter for domains using name servers matching patterns used by the threat actors.
| where match(ns_server, "(?i)(\.1domainregistry\.com|\.orderbox-dns\.com|\.monovm\.com|\.naracauva\.com\.ru)$")

-- FP Tuning: Enrich the remaining domains with WHOIS data. The lookup file 'whois_enrichment.csv' should contain fields 'dest_domain' and 'registrant_email'. This data must be sourced from a WHOIS provider.
| lookup whois_enrichment.csv dest_domain OUTPUT registrant_email
| where isnotnull(registrant_email)

-- Filter for domains registered with a ProtonMail address, a key part of the actor's TTP.
| where like(registrant_email, "%@protonmail.com")

-- The combination of these specific name servers and a ProtonMail registrant is a strong signal. Further manual review of the registrant_email for 'gibberish' patterns can increase confidence.
| stats values(src_hosts) as src_hosts, values(registrant_email) as registrant_email, values(ns_server) as name_servers, min(firstTime) as firstTime, max(lastTime) as lastTime by dest_domain
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rename dest_domain as suspicious_domain
| fields firstTime, lastTime, src_hosts, suspicious_domain, registrant_email, name_servers
```

### Persistence with Custom Malware
---
```sql
-- This rule detects network activity associated with known Salt Typhoon and UNC4841 malware families (e.g., Demodex, Snappybee, SKIPJACK, FOXTROT). Activity to these hardcoded C2 domains is a strong indicator of malware presence and successful persistence on a host.
-- Data source requirement: This rule requires network traffic (proxy, firewall) and/or DNS logs, mapped to the Splunk Common Information Model (CIM).

| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (All_Traffic.dest IN ("aar.gandhibludtric.com", "aria-hidden.com", "asparticrooftop.com", "caret-right.com", "chatscreend.com", "chekoodver.com", "cloudprocenter.com", "clubworkmistake.com", "col-lg.com", "colourtinctem.com", "componfrom.com", "dateupdata.com", "e-forwardviewupdata.com", "fessionalwork.com", "fjtest-block.com", "fitbookcatwer.com", "followkoon.com", "gandhibludtric.com", "gesturefavour.com", "getdbecausehub.com", "goldenunder.com", "hateupopred.com", "imap.dateupdata.com", "incisivelyfut.com", "infraredsen.com", "junsamyoung.com", "lookpumrron.com", "materialplies.com", "morrowadded.com", "newhkdaily.com", "onlineeylity.com", "pulseathermakf.com", "qatarpenble.com", "redbludfootvr.com", "requiredvalue.com", "ressicepro.com", "shalaordereport.com", "siderheycook.com", "sinceretehope.com", "solveblemten.com", "togetheroffway.com", "toodblackrun.com", "troublendsef.com", "unfeelmoonvd.com", "verfiedoccurr.com", "waystrkeprosh.com", "xdmgwctese.com")) by All_Traffic.dest, All_Traffic.src, All_Traffic.user
| `drop_dm_object_name("All_Traffic")`
| append [
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=DNS where (DNS.query IN ("aar.gandhibludtric.com", "aria-hidden.com", "asparticrooftop.com", "caret-right.com", "chatscreend.com", "chekoodver.com", "cloudprocenter.com", "clubworkmistake.com", "col-lg.com", "colourtinctem.com", "componfrom.com", "dateupdata.com", "e-forwardviewupdata.com", "fessionalwork.com", "fjtest-block.com", "fitbookcatwer.com", "followkoon.com", "gandhibludtric.com", "gesturefavour.com", "getdbecausehub.com", "goldenunder.com", "hateupopred.com", "imap.dateupdata.com", "incisivelyfut.com", "infraredsen.com", "junsamyoung.com", "lookpumrron.com", "materialplies.com", "morrowadded.com", "newhkdaily.com", "onlineeylity.com", "pulseathermakf.com", "qatarpenble.com", "redbludfootvr.com", "requiredvalue.com", "ressicepro.com", "shalaordereport.com", "siderheycook.com", "sinceretehope.com", "solveblemten.com", "togetheroffway.com", "toodblackrun.com", "troublendsef.com", "unfeelmoonvd.com", "verfiedoccurr.com", "waystrkeprosh.com", "xdmgwctese.com")) by DNS.query as dest, DNS.src
    | `drop_dm_object_name("DNS")`
]
-- The tstats commands efficiently search for any communication to the hardcoded list of C2 domains across network and DNS data.

| stats min(firstTime) as firstTime, max(lastTime) as lastTime, sum(count) as event_count, values(user) as user by src, dest
-- Aggregate results to provide a summary of the communication from a source host to a malicious destination.

-- FP Tuning: These domains are high-fidelity indicators. However, a domain could expire and be re-registered for benign use, leading to FPs. Review the age and registration status of any alerting domain if suspicious.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rename src as src_host, dest as malicious_domain
| fields firstTime, lastTime, src_host, malicious_domain, user, event_count
```

### Credential Dumping and Harvesting
---
```sql
-- This rule detects attempts to harvest credentials from web browsers, a TTP associated with Salt Typhoon (T1003). The group has been observed using tools like 'Trill Client' for this purpose. This detection looks for non-browser processes accessing common browser credential database files via the command line.
-- Data source requirement: This rule requires endpoint process execution logs (e.g., Sysmon Event ID 1, Windows Security 4688) mapped to the Splunk Common Information Model (CIM) 'Processes' node.

| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where (Processes.process="*Login Data*" OR Processes.process="*Web Data*" OR Processes.process="*Cookies*" OR Processes.process="*key4.db*" OR Processes.process="*logins.json*") AND (Processes.process_name!="chrome.exe" AND Processes.process_name!="msedge.exe" AND Processes.process_name!="firefox.exe" AND Processes.process_name!="brave.exe" AND Processes.process_name!="opera.exe" AND Processes.process_name!="vivaldi.exe") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name
| `drop_dm_object_name("Processes")`

-- Filter results to ensure the command line specifically targets user profile paths where credential files are stored.
| where (
    match(cmdline, "(?i)AppData\\\\(Local|Roaming)\\\\(Google|Microsoft|BraveSoftware|Mozilla|Opera Software)")
    AND
    (match(cmdline, "(?i)Login Data") OR match(cmdline, "(?i)Web Data") OR match(cmdline, "(?i)Cookies") OR match(cmdline, "(?i)key4.db") OR match(cmdline, "(?i)logins.json"))
)

-- FP Tuning: Legitimate applications like password managers or backup software might access these files. Add their process names to the exclusion list in the initial tstats command to reduce noise.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rename dest as dest_host, parent_process_name as parent_process, process_name as process_name, cmdline as process_command_line
| fields firstTime, lastTime, dest_host, user, parent_process, process_name, process_command_line, count

-- Note on detecting network device configuration dumping: This activity requires logs from network devices (e.g., Cisco IOS syslog) or TACACS+ servers. A separate detection could be built using a query like: `sourcetype=cisco:ios OR sourcetype=tacacsplus | where (command=\"show running-config\" OR command=\"copy running-config*\") | ...` This is highly dependent on specific data sources and is not included in this rule.
```

### Lateral Movement via GRE Tunnels/SSH
---
```sql
-- This rule detects network device configuration changes associated with Salt Typhoon's lateral movement TTPs (T1021). Specifically, it looks for the creation of GRE tunnels or the modification of the SSH source interface to a loopback, which can be used to bypass network access controls.
-- Data source requirement: This rule requires command-line execution logs from network devices (e.g., Cisco IOS, Juniper Junos, Arista) sent via syslog or collected via TACACS+. Adapt the 'sourcetype' or base search to match your environment's data.

(`sourcetype=cisco:ios` OR `sourcetype=juniper:junos` OR `sourcetype=pan:config`)
-- Filter for logs from common network devices. Change this to match your specific network device log sources.

| where (
    (match(_raw, "(?i)interface\s+tunnel\d+")) OR
    (match(_raw, "(?i)ip\s+ssh\s+source-interface\s+loopback\d+")) OR
    (match(_raw, "(?i)set\s+system\s+services\s+ssh\s+source-address")) OR
    (match(_raw, "(?i)set\s+interfaces\s+gre"))
  )
-- The 'where' clause searches for specific commands used to create a GRE tunnel or set the SSH source interface to a loopback across different vendor syntaxes.

| stats count min(_time) as firstTime max(_time) as lastTime values(_raw) as command by host, user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

-- FP Tuning: These configuration changes can be legitimate administrative actions, especially in complex network environments. Alerts should be correlated with other suspicious activity or reviewed by a network administrator to verify if the change was authorized and expected. Consider creating a lookup of authorized network administrators to filter out known-good activity.
| rename host as dest_device, user as user_executing_change
| fields firstTime, lastTime, dest_device, user_executing_change, command, count
```

### Log Clearing for Defense Evasion
---
```sql
-- This rule detects attempts to clear or tamper with common Linux log files, a defense evasion technique (T1070) used by actors like Salt Typhoon.
-- Data source requirement: This rule requires endpoint process execution logs (e.g., Sysmon for Linux, Auditd) mapped to the Splunk Common Information Model (CIM) 'Processes' node.

| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes
  by Processes.dest, Processes.user, Processes.process_name
-- The 'where' clause identifies several common methods of log clearing.
| where
    -- Detects tools like shred, truncate, or rm used on sensitive log files.
    (
        (process_name IN ("shred", "truncate", "rm"))
        AND
        (match(process, "(?i)\b(\.bash_history|auth\.log|lastlog|wtmp|btmp)\b"))
    )
    OR
    -- Detects overwriting files by redirecting null or empty output.
    (
        (match(process, "(?i)(cat /dev/null|echo|printf '')"))
        AND
        (match(process, "(?i)>\s*.*\b(\.bash_history|auth\.log|lastlog|wtmp|btmp)\b"))
    )
    OR
    -- Detects shell redirection to truncate a file directly (e.g., '> /var/log/wtmp').
    (
        (process_name IN ("bash", "sh", "zsh", "ksh"))
        AND
        (match(process, "(?i)^\s*>\s*.*\b(\.bash_history|auth\.log|lastlog|wtmp|btmp)\b"))
    )
    OR
    -- Detects clearing the command history using the built-in 'history' command.
    (
        (process_name="history" AND match(process, "(?i)\s-c"))
    )

| `drop_dm_object_name("Processes")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

-- FP Tuning: Legitimate administrative scripts may perform log rotation or clearing. Review the parent_process and user context. If a specific script or user is authorized, consider adding it as an exclusion to the 'where' clause (e.g., 'AND parent_process!=\"logrotate.sh\"').
| rename dest as dest_host, process_name as process_name, process as process_command, parent_process as parent_process_name
| fields firstTime, lastTime, dest_host, user, parent_process_name, process_name, process_command, count
```