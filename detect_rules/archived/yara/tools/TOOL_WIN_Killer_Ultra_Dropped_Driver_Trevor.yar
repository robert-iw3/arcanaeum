import "pe"
import "hash"

rule TOOL_WIN_Killer_Ultra_Dropped_Driver_Trevor
{
    meta:
        description = "Detects the 'trevor' driver file (amsdk.sys), which is dropped by the Killer Ultra malware. This tool leverages the vulnerable Zemana AntiLogger driver to terminate security processes as part of a defense evasion strategy."
        author = "Rob Weber"
        date = "2025-07-27"
        version = 1
        hash = "ACDDC320EA03B29F091D1FD8C1F20A771DA19671D60B0F5B51CCA18DC9585D58"
        tags = "FILE, DRIVER, DEFENSE_EVASION, KILLER_ULTRA"
        mitre_attack = "T1562.001"
        malware_family = "Killer Ultra"
        malware_type = "Defense Evasion"

    strings:
        // These strings are characteristic of the vulnerable Zemana driver (amsdk.sys)
        $s1 = "Zemana Anti-Malware SDK Driver" wide
        $s2 = "amsdk.sys" nocase
        $s3 = "Copyright (C) 2017 Zemana Ltd." wide

    condition:
        // The file must be a PE driver
        pe.is_pe and pe.is_driver() and
        (
            // Primary condition matches the specific hash of the 'trevor' driver
            hash.sha256(0, filesize) == "acddc320ea03b29f091d1fd8c1f20a771da19671d60b0f5b51cca18dc9585d58" or

            // Secondary condition provides broader detection for variants of the same driver
            all of them
        )
}
