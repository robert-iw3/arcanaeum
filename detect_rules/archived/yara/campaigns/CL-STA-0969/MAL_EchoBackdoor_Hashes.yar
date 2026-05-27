import "hash"

rule MAL_EchoBackdoor_Hashes
{
    meta:
        description = "Detects EchoBackdoor and its related scripts based on known SHA256 hashes. This malware is a passive ICMP backdoor used by the CL-STA-0969 threat actor."
        author = "RW"
        date = "2025-07-31"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/"
        hash = "188861d7f0861103886543eff63a96c314c8262dbf52c6e0cf9372cf1e889d52"
        hash = "4985de6574ff34009b6c72504af602a21c152ec104b022d6be94e2fec607eb43"
        hash = "0bb3b4d8b72fec995c56a8a0baf55f2a07d2b361ee127c2b9deced24f67426fd"
        tags = "FILE, BACKDOOR, APT, CL-STA-0969, LIMINAL_PANDA"
        mitre_attack = "T1095"
        malware_family = "EchoBackdoor"
        malware_type = "Backdoor"

    condition:
        // This rule matches known SHA256 hashes for EchoBackdoor and its associated scripts.
        hash.sha256(0, filesize) == "188861d7f0861103886543eff63a96c314c8262dbf52c6e0cf9372cf1e889d52" or
        hash.sha256(0, filesize) == "4985de6574ff34009b6c72504af602a21c152ec104b022d6be94e2fec607eb43" or
        hash.sha256(0, filesize) == "0bb3b4d8b72fec995c56a8a0baf55f2a07d2b361ee127c2b9deced24f67426fd"
}
