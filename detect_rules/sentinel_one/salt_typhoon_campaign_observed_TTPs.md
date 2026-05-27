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

-- S1QL Base Filters (Run as Subqueries and Union in PowerQuery):

-- Method 1: IOC Matching
destination_ip IN ("162.251.82.125", "162.251.82.252", "172.64.53.3", "45.79.14.194") OR destination_name IN ("irdns.mars.orderbox-dns.com", "ns4.1domainregistry.com", "ns1.value-domain.com", "earth.monovm.com", "mars.monovm.com", "aria-hidden.com", "asparticrooftop.com", "availabilitydesired.us", "caret-right.com", "chekoodver.com", "clubworkmistake.com", "col-lg.com", "dateupdata.com", "e-forwardviewupdata.com", "fessionalwork.com", "fitbookcatwer.com", "fjtest-block.com", "gandhibludtric.com", "gesturefavour.com", "getdbecausehub.com", "hateupopred.com", "incisivelyfut.com", "lookpumrron.com", "materialplies.com", "onlineeylity.com", "redbludfootvr.com", "requiredvalue.com", "ressicepro.com", "shalaordereport.com", "siderheycook.com", "sinceretehope.com", "solveblemten.com", "togetheroffway.com", "toodblackrun.com", "troublendsef.com", "verfiedoccurr.com", "waystrkeprosh.com", "xdmgwctese.com")

-- Method 2: CVE Exploits
signature RegExp "(?i)(CVE-2023-20198|CVE-2023-35082|CVE-2024-21887|CVE-2024-3400|CVE-2018-0171)"

-- Method 3: Linux User Mods
event_type = "USER_MGMT"

-- Method 4: ProtonMail Domains
registrant_email Contains "protonmail.com"

-- Method 5: Config Exfil
(command = "STOR" OR command = "PUT") AND message RegExp "(?i)(\\.conf|\\.cfg|config)"

-- Method 6: Malware
threat_name RegExp "(?i)(Demodex|SigRouter|GhostSpider|SnappyBee|Masol RAT|China Chopper)"

-- Method 7: PowerShell Downgrade
event_code = 4104 AND message RegExp "(?i)(System.Management.Automation.AMSIUtils|Set-MpPreference -DisableRealtimeMonitoring|-Version 2.*(-enc|-command))"

-- Method 8: C2/Exfil
destination_name IN ("github.com", "gmail.com", "anonfiles.com", "file.io") AND (http_method = "POST" OR bytes_out > 1000000)

-- PowerQuery for Union and Aggregation:

| union
    [filter for Method 1 | let threat_reason = "Known Salt Typhoon C2/Infrastructure", detection_method = "IOC Match"],
    [filter for Method 2 | let threat_reason = "Potential Exploitation of Vulnerability linked to Salt Typhoon", detection_method = "CVE Exploit Attempt"],
    [filter for Method 3 | let threat_reason = "Suspicious user management activity on Linux host", detection_method = "Persistence"],
    [filter for Method 4 | let threat_reason = "DNS query for domain registered with ProtonMail (Salt Typhoon TTP)", detection_method = "WHOIS TTP"],
    [filter for Method 5 | let threat_reason = "Potential exfiltration of configuration file via FTP/TFTP", detection_method = "Exfiltration"],
    [filter for Method 6 | let threat_reason = "Malware associated with Salt Typhoon detected", detection_method = "Malware Detection"],
    [filter for Method 7 | let threat_reason = "PowerShell downgrade attack detected (Salt Typhoon TTP)", detection_method = "Defense Evasion"],
    [filter for Method 8 | let threat_reason = "Potential C2 or exfiltration to public service (Salt Typhoon TTP)", detection_method = "C2/Exfil"]
| where isnotnull(threat_reason)
| group firstTime = min(EventTime), lastTime = max(EventTime), threat_reasons = array_concat(threat_reason), detection_methods = array_concat(detection_method), count = count() by source_ip, destination_ip, user, destination_name
| columns firstTime, lastTime, threat_reasons, detection_methods, count, source_ip, destination_ip, user, destination_name
| sort -count

-- Note: Parse fields (e.g., user from message) with parse user from message with regex "user=(?<user>[^ ]+)". Time range: last 30d.
```