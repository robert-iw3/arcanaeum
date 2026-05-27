import "pe"

rule MAL_Win_TerraStealerV2_Infostealer {
    meta:
        description = "Detects TerraStealerV2 malware which targets browser credentials by copying the 'Login Data' database to a temporary location and querying it."
        author = "Rob Weber"
        date = "2025-07-24"
        version = 1
        reference = "https://blog.polyswarm.io/venom-spider-using-new-terrastealerv2-and-terralogger-malware"
        hash = "14d9d56bc4c17a971a9d69b41a4663ab7eb2ca5b52d860f9613823101f072c31"
        hash = "1ed9368d5ac629fa2e7e81516e4520f02eb970d010d3087e902cd4f2e35b1752"
        hash = "313203cb71acd29e6cc542bf57f0e90ce9e9456e2483a20418c8f17b7afe0b57"
        tags = "CRIME, INFOSTEALER, VENOM_SPIDER, TERRASTEALER, FILE"
        mitre_attack = "T1555.003, T1083"
        malware_family = "TerraStealerV2"
        malware_type = "Infostealer"

    strings:
        // Specific path where the Chrome Login Data database is copied.
        $path_1 = "C:\\ProgramData\\Temp\\LoginData" wide

        // Strings related to Chrome's credential database.
        $db_1 = "Login Data" wide
        $sql_1 = "SELECT origin_url, username_value, password_value FROM logins" wide

        // Strings related to Telegram API for data exfiltration.
        $api_1 = "api.telegram.org/bot" wide
        $api_2 = "/sendMessage" wide
        $api_3 = "/sendDocument" wide

    condition:
        // The rule targets PE files under 5MB.
        pe.is_pe and filesize < 5MB and
        (
            // Primary condition: The specific temporary path is a strong indicator.
            $path_1 and
            // To reduce potential false positives, we require at least one other related artifact.
            (1 of ($db_*, $sql_*) or 1 of ($api_*))
        )
}
