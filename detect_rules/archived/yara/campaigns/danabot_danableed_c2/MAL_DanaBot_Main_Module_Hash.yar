import "hash"

rule MAL_DanaBot_Main_Module_Hash
{
    meta:
        description = "Detects a specific DanaBot main module sample identified by its SHA256 hash."
        date = "2025-07-24"
        version = "1"
        reference = "https://www.zscaler.com/blogs/security-research/operation-endgame-2-0-danabusted"
        hash = "2f8e0fc38eaf08a69653f40867dcd4cc951a10cd92b8168898b9aa45ba18a5c8"
        tags = "CRIME, BANKER, LOADER, DANABOT, FILE"
        mitre_attack = "T1105"
        malware_family = "DanaBot"
        malware_type = "Banker"

    condition:
        // Condition checks if the file's SHA256 hash matches the known DanaBot sample 1.
        hash.sha256(0, filesize) == "2f8e0fc38eaf08a69653f40867dcd4cc951a10cd92b8168898b9aa45ba18a5c8"
        // Condition checks if the file's SHA256 hash matches the known DanaBot sample 2.
        hash.sha256(0, filesize) == "871862d1117fd7d2df907406a3ce08555196800b0ef9901dd4c46f82b728263d"
}
