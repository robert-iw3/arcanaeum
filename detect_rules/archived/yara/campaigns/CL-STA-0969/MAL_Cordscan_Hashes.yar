import "hash"

rule MAL_Cordscan_Hashes
{
    meta:
        description = "Detects Cordscan, a custom network scanning and packet capture utility used by the CL-STA-0969 threat actor, based on known SHA256 hashes."
        author = "RW"
        date = "2025-07-31"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/"
        hash = "bacbe2a793d8ddca0a195b67def527e66d280a13a8d4df90b507546b76e87d29"
        hash = "1852473ca6a0b5d945e989fb65fa481452c108b718f0f6fd7e8202e9d183e707"
        tags = "FILE, SCANNER, APT, CL-STA-0969, LIMINAL_PANDA"
        mitre_attack = "T1046, T1040"
        malware_family = "Cordscan"
        malware_type = "Scanner"

    condition:
        // This rule matches known SHA256 hashes for the Cordscan utility.
        hash.sha256(0, filesize) == "bacbe2a793d8ddca0a195b67def527e66d280a13a8d4df90b507546b76e87d29" or
        hash.sha256(0, filesize) == "1852473ca6a0b5d945e989fb65fa481452c108b718f0f6fd7e8202e9d183e707"
}
