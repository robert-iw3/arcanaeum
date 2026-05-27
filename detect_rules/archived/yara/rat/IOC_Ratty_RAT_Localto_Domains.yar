rule IOC_Ratty_RAT_Localto_Domains
{
    meta:
        description = "Detects files containing hardcoded Command and Control (C2) domains associated with a Ratty RAT campaign. These domains, using the 'localto.net' service, were observed being used for malicious tunneling."
        author = "Rob Weber"
        date = "2025-07-24"
        version = 1
        reference = "https://www.fortinet.com/blog/threat-research/multilayered-email-attack-how-a-pdf-invoice-and-geofencing-led-to-rat-malware"
        tags = "CRIME, RAT, JAVA, RATTY, C2, IOC, FILE"
        mitre_attack = "T1071"
        malware_family = "Ratty"
        malware_type = "RAT"

    strings:
        // Specific C2 domains observed in the Ratty RAT campaign
        $domain1 = "jw8ndw9ev.localto.net" ascii wide
        $domain2 = "l5ugb6qxh.localto.net" ascii wide

    condition:
        // This rule triggers if any of the specified C2 domains are found within a file.
        // These domains are highly specific, making false positives unlikely.
        1 of ($*)
}
