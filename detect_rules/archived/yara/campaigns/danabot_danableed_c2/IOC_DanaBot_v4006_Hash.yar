rule IOC_DanaBot_v4006_Hash
{
    meta:
        description = "Detects a specific version of the DanaBot malware (v4006) by its SHA256 hash."
        date = "2025-07-24"
        version = 1
        reference = "https://www.zscaler.com/blogs/security-research/danableed-danabot-c2-server-memory-leak-bug"
        hash = "ae5eaeb93764bf4ac7abafeb7082a14682c10a15d825d3b76128f63e0aa6ceb9"
        tags = "CRIME, BANKER, INFOSTEALER, DANABOT, FILE"
        mitre_attack = "T1105, T1204.002"
        malware_family = "DanaBot"
        malware_type = "Banker"

    condition:
        // Match based on the specific SHA256 hash of the malware sample.
        sha256 == "ae5eaeb93764bf4ac7abafeb7082a14682c10a15d825d3b76128f63e0aa6ceb9"
}
