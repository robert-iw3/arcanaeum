import "hash"

rule MAL_FScan_Hash
{
    meta:
        description = "Detects a specific sample of FScan based on its SHA256 hash. FScan is an open-source network scanning tool and was leveraged by the CL-STA-0969 threat actor."
        author = "RW"
        date = "2025-07-31"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/"
        hash = "705a035e54ce328227341ff9d55de15f4e16d387829cba26dc948170dac1c70f"
        tags = "FILE, SCANNER, APT, CL-STA-0969, LIMINAL_PANDA"
        mitre_attack = "T1046"
        malware_family = "FScan"
        malware_type = "Scanner"

    condition:
        // This rule matches a known SHA256 hash for an FScan sample.
        // FP Note: While the hash is specific, FScan is a publicly available tool used by red teams and threat actors. Correlate with other suspicious activity.
        hash.sha256(0, filesize) == "705a035e54ce328227341ff9d55de15f4e16d387829cba26dc948170dac1c70f"
}
