import "hash"

rule IOC_Ratty_RAT_Hashes
{
    meta:
        description = "Detects known samples of the Ratty Remote Access Trojan (RAT) based on their file hashes. These samples were identified as part of a multi-layered email campaign."
        author = "Rob Weber"
        date = "2025-07-24"
        version = 1
        reference = "https://www.fortinet.com/blog/threat-research/multilayered-email-attack-how-a-pdf-invoice-and-geofencing-led-to-rat-malware"
        hash = "a1c2861a68b2a4d62b6fbfc7534f498cefe5f92f720466d24ae1b66ebc9f5731"
        hash = "d20d14792c91107f53318ff7df83b9cd98acd3c394959a74e72278682822b600"
        hash = "9184ff2cdd05fcaf111db23123479c845b2ece2fedccc2524b2de592f9980876"
        hash = "5f897fec78e2fd812eb3bc451222e64480a9d5bc97b746cc0468698a63470880"
        hash = "6153c80b17cb990caad1d80cac72c867d4ecfa1a84b7ab286b7373cd4168794e"
        hash = "469b8911fd1ae2ded8532a50e9e66b8d54820c18ccdba49d7a38850d6af54475"
        hash = "af8b6ac45918bc87d2a164fae888dab6e623327cba7c2409e4d0ef1dde8d1793"
        tags = "CRIME, RAT, JAVA, RATTY, HASH, FILE"
        mitre_attack = "T1105"
        malware_family = "Ratty"
        malware_type = "RAT"

    condition:
        // This rule triggers if the file's SHA256 hash matches any of the known malicious samples.
        hash.sha256(0, filesize) == "a1c2861a68b2a4d62b6fbfc7534f498cefe5f92f720466d24ae1b66ebc9f5731" or
        hash.sha256(0, filesize) == "d20d14792c91107f53318ff7df83b9cd98acd3c394959a74e72278682822b600" or
        hash.sha256(0, filesize) == "9184ff2cdd05fcaf111db23123479c845b2ece2fedccc2524b2de592f9980876" or
        hash.sha256(0, filesize) == "5f897fec78e2fd812eb3bc451222e64480a9d5bc97b746cc0468698a63470880" or
        hash.sha256(0, filesize) == "6153c80b17cb990caad1d80cac72c867d4ecfa1a84b7ab286b7373cd4168794e" or
        hash.sha256(0, filesize) == "469b8911fd1ae2ded8532a50e9e66b8d54820c18ccdba49d7a38850d6af54475" or
        hash.sha256(0, filesize) == "af8b6ac45918bc87d2a164fae888dab6e623327cba7c2409e4d0ef1dde8d1793"
}
