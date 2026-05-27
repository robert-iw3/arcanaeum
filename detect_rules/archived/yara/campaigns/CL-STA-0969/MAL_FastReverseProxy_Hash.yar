import "hash"

rule MAL_FastReverseProxy_Hash
{
    meta:
        description = "Detects a specific sample of Fast Reverse Proxy (FRP) based on its SHA256 hash. FRP is a tool used to expose local servers and was leveraged by the CL-STA-0969 threat actor."
        author = ""RW
        date = "2025-07-31"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/"
        hash = "e3b06f860b8584d69a713127f7d3a4ee5f545ad72e41ec71f9e8692c3525efa0"
        tags = "FILE, PROXY, APT, CL-STA-0969, LIMINAL_PANDA"
        mitre_attack = "T1090"
        malware_family = "Fast Reverse Proxy"
        malware_type = "Proxy"

    condition:
        // This rule matches a known SHA256 hash for a Fast Reverse Proxy sample.
        // FP Note: While the hash is specific, FRP can be used for legitimate purposes. Correlate with other suspicious activity.
        hash.sha256(0, filesize) == "e3b06f860b8584d69a713127f7d3a4ee5f545ad72e41ec71f9e8692c3525efa0"
}
