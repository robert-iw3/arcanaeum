import "pe"

rule TTP_Sensitive_File_Access_Skynet
{
    meta:
        description = "Detects files containing strings related to accessing sensitive user files, such as SSH keys and host files. This behavior is characteristic of the Skynet malware, which gathers this data for credential access and lateral movement."
        date = "2025-07-24"
        version = 1
        reference = "https://research.checkpoint.com/2025/ai-evasion-prompt-injection/"
        hash = "6cdf54a6854179bf46ad7bc98d0a0c0a6d82c804698d1a52f6aa70ffa5207b02"
        tags = "TTP, INFOSTEALER, CREDENTIAL_ACCESS, SKYNET, FILE"
        mitre_attack = "T1005, T1552.004"
        malware_family = "Skynet"

    strings:
        // Strings representing paths to sensitive files, as seen in Skynet malware.
        // The use of forward slashes in Windows paths can be an indicator.
        $path_1 = ".ssh/known_hosts" wide ascii
        $path_2 = ".ssh/id_rsa" wide ascii
        $path_3 = "C:/Windows/System32/Drivers/etc/hosts" wide ascii
        $path_4 = "/etc/hosts" wide ascii

    condition:
        // Must be a PE file
        pe.is_pe
        and
        (
            // Condition requires at least two of the sensitive file path strings.
            // This increases confidence and reduces potential FPs from legitimate tools
            // (e.g., SSH clients, system utilities) that might reference one of these paths.
            2 of ($path_*)
        )
}
