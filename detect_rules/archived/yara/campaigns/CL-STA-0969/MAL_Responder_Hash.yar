import "hash"

rule MAL_Responder_Hash
{
    meta:
        description = "Detects a specific sample of the Responder tool based on its SHA256 hash. Responder is an open-source tool for network reconnaissance and credential capture, and was leveraged by the CL-STA-0969 threat actor."
        author = "RW"
        date = "2025-07-31"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/"
        hash = "efa04c33b289e97a84ec6ab1f1b161f900ed3b4521a9a69fb6986bd9991ecfc6"
        tags = "FILE, RECON, CREDENTIAL_ACCESS, APT, CL-STA-0969, LIMINAL_PANDA"
        mitre_attack = "T1557"
        malware_family = "Responder"
        malware_type = "Credential Harvester"

    condition:
        // This rule matches a known SHA256 hash for a Responder sample.
        // FP Note: While the hash is specific, Responder is a legitimate open-source tool used in penetration testing. Correlate with other suspicious activity.
        hash.sha256(0, filesize) == "efa04c33b289e97a84ec6ab1f1b161f900ed3b4521a9a69fb6986bd9991ecfc6"
}
