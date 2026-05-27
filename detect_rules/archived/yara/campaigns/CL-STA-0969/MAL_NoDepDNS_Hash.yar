import "hash"

rule MAL_NoDepDNS_Hash
{
    meta:
        description = "Detects a specific sample of the NoDepDNS backdoor based on its SHA256 hash. NoDepDNS is a Golang-based backdoor used by the CL-STA-0969 threat actor for C2 via DNS tunneling."
        author = "RW"
        date = "2025-07-31"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/"
        hash = "aa661e149f0a6a9a61cadcca47a83893a9e6a6cdb41c3b075175da28e641a80f"
        tags = "FILE, BACKDOOR, APT, CL-STA-0969, LIMINAL_PANDA, GOLANG"
        mitre_attack = "T1071.004"
        malware_family = "NoDepDNS"
        malware_type = "Backdoor"

    condition:
        // This rule matches a known SHA256 hash for the NoDepDNS backdoor.
        hash.sha256(0, filesize) == "aa661e149f0a6a9a61cadcca47a83893a9e6a6cdb41c3b075175da28e641a80f"
}
