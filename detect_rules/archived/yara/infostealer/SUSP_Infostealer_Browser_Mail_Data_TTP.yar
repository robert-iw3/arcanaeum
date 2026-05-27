import "pe"

rule SUSP_Infostealer_Browser_Mail_Data_TTP
{
    meta:
        description = "Detects infostealer malware, such as DarkCloud, that attempts to access and exfiltrate sensitive data from browser profiles and mail client data files."
        author = "Rob Weber"
        date = "2025-07-24"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/darkcloud-stealer-and-obfuscated-autoit-scripting/"
        tags = "CRIME, INFOSTEALER, DARKCLOUD, TTP, FILE"
        mitre_attack = "T1555, T1539, T1552, T1528"
        malware_family = "DarkCloud"
        malware_type = "Infostealer"

    strings:
        // High-confidence signature string for DarkCloud Stealer
        $sig_darkcloud = "DARKCLOUD" ascii

        // Common credential/data files for Gecko-based browsers (e.g., Firefox)
        $gecko1 = "logins.json" ascii wide
        $gecko2 = "key4.db" ascii wide
        $gecko3 = "signons.sqlite" ascii wide

        // Common credential/data files for Chromium-based browsers (e.g., Chrome, Edge)
        $chrome1 = "Login Data" ascii wide
        $chrome2 = "Web Data" ascii wide
        $chrome3 = "Local State" ascii wide // Contains encryption key for credentials

        // Strings from SQL queries used to steal credit card data from browser databases
        $sql1 = "card_number_encrypted" ascii wide
        $sql2 = "name_on_card" ascii wide

    condition:
        // Must be a PE file under 10MB to scope the rule.
        pe.is_pe and filesize < 10MB and
        (
            // High-confidence match for the specific malware family.
            $sig_darkcloud
            or
            // Broader TTP-based detection for infostealer activity.
            // This may flag other infostealers or legitimate backup tools, so multiple indicators are required.
            (
                2 of ($gecko*) or
                3 of ($chrome*) or
                (1 of ($gecko*) and 2 of ($chrome*)) or
                (1 of ($chrome*) and 2 of ($sql*))
            )
        )
}
