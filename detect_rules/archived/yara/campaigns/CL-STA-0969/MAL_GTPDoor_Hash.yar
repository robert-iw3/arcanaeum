import "hash"

rule MAL_GTPDoor_Hash
{
    meta:
        description = "Detects a specific sample of the GTPDoor backdoor based on its SHA256 hash. GTPDoor is a Linux-based implant that communicates C2 traffic over GTP-C signaling messages and was used by the CL-STA-0969 threat actor."
        author = "RW"
        date = "2025-07-31"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/"
        hash = "827f41fc1a6f8a4c8a8575b3e2349aeaba0dfc2c9390ef1cceeef1bb85c34161"
        tags = "FILE, BACKDOOR, APT, CL-STA-0969, LIMINAL_PANDA, TELECOM"
        mitre_attack = "T1095"
        malware_family = "GTPDoor"
        malware_type = "Backdoor"

    condition:
        // This rule matches a known SHA256 hash for the GTPDoor backdoor.
        hash.sha256(0, filesize) == "827f41fc1a6f8a4c8a8575b3e2349aeaba0dfc2c9390ef1cceeef1bb85c34161"
}
