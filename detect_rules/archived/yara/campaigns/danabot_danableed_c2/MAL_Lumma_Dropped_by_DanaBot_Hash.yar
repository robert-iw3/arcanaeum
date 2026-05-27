import "hash"

rule MAL_Lumma_Dropped_by_DanaBot_Hash
{
    meta:
        description = "Detects a specific Lumma (version 4) sample, known to be dropped by DanaBot, identified by its SHA256 hash."
        date = "2025-07-24"
        version = "1"
        reference = "https://www.zscaler.com/blogs/security-research/operation-endgame-2-0-danabusted"
        hash = "75ff0334d46f9b7737e95ac1edcc79d956417b056154c23fad8480ec0829b079"
        tags = "CRIME, INFOSTEALER, LUMMA, DANABOT, FILE"
        mitre_attack = "T1105"
        malware_family = "Lumma"
        malware_type = "Infostealer"

    condition:
        // Condition checks if the file's SHA256 hash matches the known Lumma sample.
        hash.sha256(0, filesize) == "75ff0334d46f9b7737e95ac1edcc79d956417b056154c23fad8480ec0829b079"
}
