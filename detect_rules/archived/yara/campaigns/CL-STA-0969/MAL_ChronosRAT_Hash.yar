import "hash"

rule MAL_ChronosRAT_Hash
{
    meta:
        description = "Detects a specific sample of the ChronosRAT backdoor based on its SHA256 hash. ChronosRAT is a modular backdoor used by the CL-STA-0969 threat actor."
        author = "RW"
        date = "2025-07-31"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/"
        hash = "432125ca41a2c5957013c8bff09c4037ad18addccab872d46230dd662a2b8123"
        tags = "FILE, BACKDOOR, RAT, APT, CL-STA-0969, LIMINAL_PANDA"
        mitre_attack = "T1219"
        malware_family = "ChronosRAT"
        malware_type = "Backdoor"

    condition:
        // This rule matches a known SHA256 hash for the ChronosRAT backdoor.
        hash.sha256(0, filesize) == "432125ca41a2c5957013c8bff09c4037ad18addccab872d46230dd662a2b8123"
}
