import "hash"

rule MAL_AuthDoor_Hashes
{
    meta:
        description = "Detects the AuthDoor backdoor based on known SHA256 hashes. AuthDoor is a PAM backdoor used by the CL-STA-0969 threat actor for persistence."
        author = "RW"
        date = "2025-07-31"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/"
        hash = "540f60702ee5019cd2b39b38b07e17da69bde1f9ed3b4543ff26e9da7ba6e0be"
        hash = "cd754125657f1d52c08f9274fda57600e12929847eee3f7bea2e60ca5ba7711d"
        tags = "FILE, BACKDOOR, APT, CL-STA-0969, LIMINAL_PANDA, AUTHDOOR"
        mitre_attack = "T1556"
        malware_family = "AuthDoor"
        malware_type = "Backdoor"

    condition:
        // This rule matches known SHA256 hashes for the AuthDoor PAM backdoor.
        hash.sha256(0, filesize) == "540f60702ee5019cd2b39b38b07e17da69bde1f9ed3b4543ff26e9da7ba6e0be" or
        hash.sha256(0, filesize) == "cd754125657f1d52c08f9274fda57600e12929847eee3f7bea2e60ca5ba7711d"
}
