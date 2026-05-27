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

-- Method 1: IOC Matching (Network Traffic)
source:network AND (@destination.ip:("162.251.82.125" "162.251.82.252" "172.64.53.3" "45.79.14.194") OR @destination.name:("irdns.mars.orderbox-dns.com" "ns4.1domainregistry.com" "ns1.value-domain.com" "earth.monovm.com" "mars.monovm.com" "aria-hidden.com" "asparticrooftop.com" "availabilitydesired.us" "caret-right.com" "chekoodver.com" "clubworkmistake.com" "col-lg.com" "dateupdata.com" "e-forwardviewupdata.com" "fessionalwork.com" "fitbookcatwer.com" "fjtest-block.com" "gandhibludtric.com" "gesturefavour.com" "getdbecausehub.com" "hateupopred.com" "incisivelyfut.com" "lookpumrron.com" "materialplies.com" "onlineeylity.com" "redbludfootvr.com" "requiredvalue.com" "ressicepro.com" "shalaordereport.com" "siderheycook.com" "sinceretehope.com" "solveblemten.com" "togetheroffway.com" "toodblackrun.com" "troublendsef.com" "verfiedoccurr.com" "waystrkeprosh.com" "xdmgwctese.com"))
| @threat_reason:"Known Salt Typhoon C2/Infrastructure" @detection_method:"IOC Match"

-- Method 2: CVE Exploits (Threat Logs)
source:(pan_threat OR cisco_asa OR suricata OR zeek) AND (@signature ~ /CVE-2023-20198|CVE-2023-35082|CVE-2024-21887|CVE-2024-3400|CVE-2018-0171/)
| @threat_reason:"Potential Exploitation of Vulnerability linked to Salt Typhoon" @detection_method:"CVE Exploit Attempt"

-- Method 3: Linux User Mods (Audit Logs)
source:linux_audit AND @event.type:"user_mgmt"
| @threat_reason:"Suspicious user management activity on Linux host" @detection_method:"Persistence"

-- Method 4: ProtonMail Domains (DNS Logs; assumes @registrant_email facet from pipeline)
source:(dns OR network) AND @registrant_email ~ /protonmail\.com/
| @threat_reason:"DNS query for domain registered with ProtonMail (Salt Typhoon TTP)" @detection_method:"WHOIS TTP"

-- Method 5: Config Exfil (NetOps Logs)
source:(zeek_ftp OR zeek_tftp) AND (@command:("STOR" "PUT") AND (@arg ~ /.*\.conf|.*\.cfg|.*config.*/))
| @threat_reason:"Potential exfiltration of configuration file via FTP/TFTP" @detection_method:"Exfiltration"

-- Method 6: Malware (Endpoint Logs)
source:(crowdstrike OR symantec_ep) AND (@threat_name ~ /Demodex|SigRouter|GhostSpider|SnappyBee|Masol RAT|China Chopper/)
| @threat_reason:"Malware associated with Salt Typhoon detected" @detection_method:"Malware Detection"

-- Method 7: PowerShell Downgrade (WinEvent Logs)
source:win_event AND @event.code:4104 AND (@message ~ /[System.Management.Automation.AMSIUtils]|Set-MpPreference -DisableRealtimeMonitoring|(-Version 2.*(-enc|-command))/)
| @threat_reason:"PowerShell downgrade attack detected (Salt Typhoon TTP)" @detection_method:"Defense Evasion"

-- Method 8: C2/Exfil via Public Services (Proxy Logs)
source:proxy AND @destination.host:("github.com" "gmail.com" "anonfiles.com" "file.io") AND (@http_method:"POST" OR @bytes_out > 1000000)
| @threat_reason:"Potential C2 or exfiltration to public service (Salt Typhoon TTP)" @detection_method:"C2/Exfil"
```