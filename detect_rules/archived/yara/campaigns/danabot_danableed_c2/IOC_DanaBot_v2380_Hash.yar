rule IOC_DanaBot_v2380_Hash
{
    meta:
        description = "Detects a specific version of the DanaBot malware (v2380) by its SHA256 hash. This version is associated with the 'DanaBleed' C2 server memory leak vulnerability."
        date = "2025-07-24"
        version = 1
        reference = "https://www.zscaler.com/blogs/security-research/danableed-danabot-c2-server-memory-leak-bug"
        // This hash is for the main component of DanaBot v2380
        hash = "3ce09a0cc03dcf3016c21979b10bc3bfc61a7ba3f582e2838a78f0ccd3556555"
        tags = "CRIME, BANKER, INFOSTEALER, DANABOT, FILE"
        mitre_attack = "T1105, T1204.002"
        malware_family = "DanaBot"
        malware_type = "Banker"

    condition:
        // Match based on the specific SHA256 hash of the malware sample.
        // This provides a high-fidelity detection with a very low chance of false positives.
        sha256 == "3ce09a0cc03dcf3016c21979b10bc3bfc61a7ba3f582e2838a78f0ccd3556555"
}
