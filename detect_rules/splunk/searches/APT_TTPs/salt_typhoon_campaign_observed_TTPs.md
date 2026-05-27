### Salt Typhoon: China's State-Corporate Advanced Persistent Threat
---

Salt Typhoon is a Chinese state-sponsored APT group, aligned with the Ministry of State Security (MSS), that specializes in long-term espionage operations targeting global telecommunications infrastructure. The group leverages a hybrid model of direct MSS oversight and pseudo-private contractors to exploit network edge devices, establish deep persistence, and exfiltrate sensitive communications data.

Recent intelligence highlights Salt Typhoon's continued exploitation of known vulnerabilities in network devices, including Cisco, Ivanti, and Palo Alto products, to gain initial access and maintain persistence. The group has also been observed using a new custom malware called "JumbledPath" to create remote connection chains between compromised Cisco devices and their command and control infrastructure.
A
### Actionable Threat Data
---

Monitor for exploitation attempts against public-facing applications, particularly vulnerabilities in routers, firewalls, and VPN gateways (e.g., Cisco IOS XE Web UI (CVE-2023-20198), Ivanti Connect Secure (CVE-2023-35082, CVE-2024-21887), Palo Alto PAN-OS GlobalProtect (CVE-2024-3400 series), and Cisco Smart Install (CVE-2018-0171)).

Detect the creation of new Linux-level users or modifications to /etc/shadow and /etc/passwd on network devices, as Salt Typhoon has been observed using these techniques for persistence.

Look for unusual SSH connections originating from modified loopback interface addresses on compromised switches, which Salt Typhoon uses to bypass Access Control Lists (ACLs).

Identify and alert on the use of ProtonMail accounts in WHOIS registration data for newly registered domains, especially those mimicking legitimate technology or telecom services, or using fabricated U.S. personas like "Shawn Francis," "Monica Burch," or "Larry Smith."

Monitor for DNS queries resolving to known Salt Typhoon name server hosts and IP clusters, such as irdns.mars.orderbox-dns.com, ns4.1domainregistry.com, ns1.value-domain.com, earth.monovm.com, mars.monovm.com, and IPs 162.251.82.125, 162.251.82.252, 172.64.53.3.

Detect the presence of custom router implants and backdoored updates, as well as the exfiltration of configuration files from network devices over FTP and TFTP.

Monitor for the use of specific malware families like Demodex (custom rootkit), SigRouter, GhostSpider, SnappyBee, Masol RAT, and China Chopper web shells.

Implement detections for PowerShell downgrade attacks to bypass Windows Antimalware Scan Interface (AMSI) logging.

Monitor for the use of public cloud and communication services (e.g., GitHub, Gmail, AnonFiles, File.io) for command and control (C2) and data exfiltration.

### Combined Search Logic Detecting Actionable Threat Data
---
```sql
-- This rule is a composite of multiple detection strategies for the Salt Typhoon APT group. In a production environment, it is highly recommended to split these into separate, focused rules for each data source and detection method for better performance, manageability, and tuning.

-- Detection Method 1: IOC Matching for known Domains and IPs
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (nodename=All_Traffic) (dest_ip IN ("162.251.82.125", "162.251.82.252", "172.64.53.3") OR dest_name IN ("irdns.mars.orderbox-dns.com", "ns4.1domainregistry.com", "ns1.value-domain.com", "earth.monovm.com", "mars.monovm.com", "aria-hidden.com", "asparticrooftop.com", "availabilitydesired.us", "caret-right.com", "chekoodver.com", "clubworkmistake.com", "col-lg.com", "dateupdata.com", "e-forwardviewupdata.com", "fessionalwork.com", "fitbookcatwer.com", "fjtest-block.com", "gandhibludtric.com", "gesturefavour.com", "getdbecausehub.com", "hateupopred.com", "incisivelyfut.com", "lookpumrron.com", "materialplies.com", "onlineeylity.com", "redbludfootvr.com", "requiredvalue.com", "ressicepro.com", "shalaordereport.com", "siderheycook.com", "sinceretehope.com", "solveblemten.com", "togetheroffway.com", "toodblackrun.com", "troublendsef.com", "verfiedoccurr.com", "waystrkeprosh.com", "xdmgwctese.com")) by src_ip dest_ip dest_name
| `drop_dm_object_name("All_Traffic")`
| eval threat_reason="Known Salt Typhoon C2/Infrastructure", detection_method="IOC Match"

-- Append results from other detection methods
| append [
    -- Detection Method 2: Exploitation of Network Edge Devices via vulnerability signatures. Requires IDS/IPS/Firewall Threat logs.
    search (index=* sourcetype=pan:threat OR sourcetype=cisco:asa OR sourcetype=suricata OR sourcetype=zeek:*) AND (signature IN ("*CVE-2023-20198*", "*CVE-2023-35082*", "*CVE-2024-21887*", "*CVE-2024-3400*", "*CVE-2018-0171*") OR threat_name IN ("*CVE-2023-20198*", "*CVE-2023-35082*", "*CVE-2024-21887*", "*CVE-2024-3400*", "*CVE-2018-0171*"))
    | eval threat_reason="Potential Exploitation of Vulnerability linked to Salt Typhoon", detection_method="CVE Exploit Attempt"
    | stats values(signature) as signature by _time, src_ip, dest_ip, threat_reason, detection_method
]
| append [
    -- Detection Method 3: Linux User Creation/Modification for Persistence. Requires Linux auditd or FIM logs.
    search (index=os sourcetype=linux_audit) type=USER_MGMT
    | eval threat_reason="Suspicious user management activity on Linux host", detection_method="Persistence"
    | stats count by _time, host, user, auid, exe, threat_reason, detection_method
    | rename host as dest_ip, user as threat_object
]
| append [
    -- Detection Method 4: DNS Queries for domains registered with ProtonMail. Requires a lookup of known IOCs populated from a threat intel feed. This is a conceptual example.
    search (index=dns OR index=network) (sourcetype=stream:dns OR sourcetype=coredns)
    | `lookup salt_typhoon_domains_whois.csv domain as query OUTPUT registrant_email`
    | where match(registrant_email, "protonmail.com")
    | eval threat_reason="DNS query for domain registered with ProtonMail (Salt Typhoon TTP)", detection_method="WHOIS TTP"
    | stats values(query) as query by _time, src, dest, threat_reason, detection_method
    | rename src as src_ip, dest as dest_ip
]
| append [
    -- Detection Method 5: Exfiltration of configuration files over unencrypted protocols. This may be noisy and require tuning to filter out legitimate administrative activity.
    search (index=netops) (sourcetype=zeek:ftp:log OR sourcetype=zeek:tftp:log) AND (command="STOR" OR command="PUT") AND (arg LIKE "%.conf" OR arg LIKE "%.cfg" OR arg LIKE "%config%")
    | eval ts=coalesce(ts, _time) | eval _time=ts
    | eval threat_reason="Potential exfiltration of configuration file via FTP/TFTP", detection_method="Exfiltration"
    | stats count by _time, id.orig_h, id.resp_h, command, arg, threat_reason, detection_method
    | rename id.orig_h as src_ip, id.resp_h as dest_ip
]
| append [
    -- Detection Method 6: Salt Typhoon Malware Families detected. Requires EDR/AV logs.
    search (index=endpoint) (sourcetype=crowdstrike:falcon OR sourcetype=symantec:ep:*) AND (threat_name IN ("*Demodex*", "*SigRouter*", "*GhostSpider*", "*SnappyBee*", "*Masol RAT*", "*China Chopper*") OR signature IN ("*Demodex*", "*SigRouter*", "*GhostSpider*", "*SnappyBee*", "*Masol RAT*", "*China Chopper*"))
    | eval threat_reason="Malware associated with Salt Typhoon detected", detection_method="Malware Detection"
    | stats values(threat_name) as threat_name by _time, dest, user, threat_reason, detection_method
    | rename dest as dest_ip
]
| append [
    -- Detection Method 7: PowerShell Downgrade Attacks. Requires PowerShell script block logging (EventCode 4104).
    search (index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104) AND (Message LIKE "%[System.Management.Automation.AMSIUtils]%" OR Message LIKE "%Set-MpPreference -DisableRealtimeMonitoring%" OR (Message LIKE "%-Version 2%" AND (Message LIKE "%-enc%" OR Message LIKE "%-command%")))
    | eval threat_reason="PowerShell downgrade attack detected (Salt Typhoon TTP)", detection_method="Defense Evasion"
    | stats count by _time, host, user, Message, threat_reason, detection_method
    | rename host as dest_ip
]
| append [
    -- Detection Method 8: C2/Exfil via Public Cloud/Communication Services. This is a broad search and may generate false positives. Tune by baselining normal traffic and focusing on sensitive systems.
    search (index=proxy) dest_host IN ("github.com", "gmail.com", "anonfiles.com", "file.io") AND (http_method="POST" OR bytes_out > 1000000)
    | eval threat_reason="Potential C2 or exfiltration to public service (Salt Typhoon TTP)", detection_method="C2/Exfil"
    | stats values(dest_host) as dest_host, sum(bytes_out) as total_bytes_out by _time, src_ip, dest_ip, user, threat_reason, detection_method
]

-- Final aggregation and formatting of results from all detection methods
| fillnull value="N/A"
| stats earliest(_time) as firstTime, latest(_time) as lastTime, values(threat_reason) as threat_reasons, values(detection_method) as detection_methods, count by src_ip, dest_ip, user, dest_name
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```