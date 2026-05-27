import "hash"

rule MAL_MicrosocksProxy_Hash
{
    meta:
        description = "Detects a specific sample of Microsocks proxy based on its SHA256 hash. Microsocks is a tool used for pivoting and tunneling network activity and was leveraged by the CL-STA-0969 threat actor."
        author = "RW"
        date = "2025-07-31"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/"
        hash = "3c42194d6c18a480d9a7f3f7550f011c69ff276707e2bae5e6143f7943343f74"
        tags = "FILE, PROXY, APT, CL-STA-0969, LIMINAL_PANDA"
        mitre_attack = "T1090"
        malware_family = "Microsocks"
        malware_type = "Proxy"

    condition:
        // This rule matches a known SHA256 hash for a Microsocks proxy sample.
        // FP Note: While the hash is specific, Microsocks is a legitimate open-source tool. Correlate with other suspicious activity.
        hash.sha256(0, filesize) == "3c42194d6c18a480d9a7f3f7550f011c69ff276707e2bae5e6143f7943343f74"
}
