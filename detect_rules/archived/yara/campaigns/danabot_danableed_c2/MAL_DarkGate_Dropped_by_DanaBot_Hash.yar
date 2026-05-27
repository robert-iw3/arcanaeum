import "hash"

rule MAL_DarkGate_Dropped_by_DanaBot_Hash
{
    meta:
        description = "Detects a specific DarkGate sample (dropped by DanaBot) identified by its SHA256 hash."
        date = "2025-07-24"
        version = "1"
        reference = "https://www.zscaler.com/blogs/security-research/operation-endgame-2-0-danabusted"
        hash = "e2c228d0bf460f25b39dd60f871f59ea5ef671b8a2f4879d09abae7a9d4d49fb"
        tags = "CRIME, RAT, DARKGATE, DANABOT, FILE"
        mitre_attack = "T1105"
        malware_family = "DarkGate"
        malware_type = "RAT"

    condition:
        // Condition checks if the file's SHA256 hash matches the known DarkGate sample.
        hash.sha256(0, filesize) == "e2c228d0bf460f25b39dd60f871f59ea5ef671b8a2f4879d09abae7a9d4d49fb"
}
