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

FROM logs-* -- Event Data Log Index or Data Stream
| WHERE
  -- Method 1: IOC Matching
  (event.dataset == "network_traffic" AND (destination.ip IN ("162.251.82.125", "162.251.82.252", "172.64.53.3", "45.79.14.194") OR destination.domain IN ("irdns.mars.orderbox-dns.com", "ns4.1domainregistry.com", "ns1.value-domain.com", "earth.monovm.com", "mars.monovm.com", "aria-hidden.com", "asparticrooftop.com", "availabilitydesired.us", "caret-right.com", "chekoodver.com", "clubworkmistake.com", "col-lg.com", "dateupdata.com", "e-forwardviewupdata.com", "fessionalwork.com", "fitbookcatwer.com", "fjtest-block.com", "gandhibludtric.com", "gesturefavour.com", "getdbecausehub.com", "hateupopred.com", "incisivelyfut.com", "lookpumrron.com", "materialplies.com", "onlineeylity.com", "redbludfootvr.com", "requiredvalue.com", "ressicepro.com", "shalaordereport.com", "siderheycook.com", "sinceretehope.com", "solveblemten.com", "togetheroffway.com", "toodblackrun.com", "troublendsef.com", "verfiedoccurr.com", "waystrkeprosh.com", "xdmgwctese.com")))
  OR
  -- Method 2: CVE Exploits
  (event.dataset IN ("pan_threat", "cisco_asa", "suricata", "zeek") AND REGEXP(signature, "(?i)(CVE-2023-20198|CVE-2023-35082|CVE-2024-21887|CVE-2024-3400|CVE-2018-0171)"))
  OR
  -- Method 3: Linux User Mods
  (event.dataset == "linux_audit" AND event.type == "user_mgmt")
  OR
  -- Method 4: ProtonMail Domains (assumes JOIN to threat_intel index for registrant_email)
  (event.dataset IN ("dns", "network") AND (SELECT registrant_email FROM threat_intel WHERE domain == query) LIKE "%protonmail.com")
  OR
  -- Method 5: Config Exfil
  (event.dataset IN ("zeek_ftp", "zeek_tftp") AND command IN ("STOR", "PUT") AND REGEXP(arg, "(?i)(\\.conf|\\.cfg|config)"))
  OR
  -- Method 6: Malware
  (event.dataset IN ("crowdstrike", "symantec_ep") AND REGEXP(threat_name, "(?i)(Demodex|SigRouter|GhostSpider|SnappyBee|Masol RAT|China Chopper)"))
  OR
  -- Method 7: PowerShell Downgrade
  (event.dataset == "wineventlog" AND event.code == 4104 AND REGEXP(message, "(?i)(System.Management.Automation.AMSIUtils|Set-MpPreference -DisableRealtimeMonitoring|-Version 2.*(-enc|-command))"))
  OR
  -- Method 8: C2/Exfil
  (event.dataset == "proxy" AND destination.domain IN ("github.com", "gmail.com", "anonfiles.com", "file.io") AND (http.request.method == "POST" OR network.bytes_out > 1000000))
| EVAL threat_reason = CASE(
    destination.ip IN ("162.251.82.125", "162.251.82.252", "172.64.53.3", "45.79.14.194") OR destination.domain IN ("irdns.mars.orderbox-dns.com", ...), "Known Salt Typhoon C2/Infrastructure",
    REGEXP(signature, "(?i)(CVE-2023-20198|...)"), "Potential Exploitation of Vulnerability linked to Salt Typhoon",
    event.type == "user_mgmt", "Suspicious user management activity on Linux host",
    (SELECT registrant_email ...) LIKE "%protonmail.com", "DNS query for domain registered with ProtonMail (Salt Typhoon TTP)",
    REGEXP(arg, "(?i)(\\.conf|...)"), "Potential exfiltration of configuration file via FTP/TFTP",
    REGEXP(threat_name, "(?i)(Demodex|...)"), "Malware associated with Salt Typhoon detected",
    REGEXP(message, "(?i)(System.Management.Automation.AMSIUtils|...)"), "PowerShell downgrade attack detected (Salt Typhoon TTP)",
    destination.domain IN ("github.com", ...), "Potential C2 or exfiltration to public service (Salt Typhoon TTP)",
    "N/A"
  ),
  detection_method = CASE(
    destination.ip IN ("162.251.82.125", ...), "IOC Match",
    REGEXP(signature, "(?i)(CVE-2023-20198|...)"), "CVE Exploit Attempt",
    event.type == "user_mgmt", "Persistence",
    (SELECT registrant_email ...) LIKE "%protonmail.com", "WHOIS TTP",
    REGEXP(arg, "(?i)(\\.conf|...)"), "Exfiltration",
    REGEXP(threat_name, "(?i)(Demodex|...)"), "Malware Detection",
    REGEXP(message, "(?i)(System.Management.Automation.AMSIUtils|...)"), "Defense Evasion",
    destination.domain IN ("github.com", ...), "C2/Exfil",
    "N/A"
  )
| WHERE threat_reason != "N/A"
| STATS firstTime = MIN(@timestamp), lastTime = MAX(@timestamp), threat_reasons = MV_CONCAT(threat_reason), detection_methods = MV_CONCAT(detection_method), count = COUNT(*) BY source.ip, destination.ip, user.name, destination.domain
| RENAME source.ip AS src_ip, destination.ip AS dest_ip, user.name AS user, destination.domain AS dest_name
| SORT -count

-- Note: For Method 4, replace (SELECT ...) with actual JOIN syntax if using enriched indices. Use time range: last 30d for historical.
```