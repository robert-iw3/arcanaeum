rule BEHAVIOR_PS_Evasion_ScreenResolutionMD5
{
    meta:
        description = "Detects PowerShell scripts attempting to evade analysis environments by checking the MD5 hash of the screen resolution. This technique is notably used by the COLDRIVER group as part of the LOSTKEYS malware deployment."
        date = "2025-07-24"
        version = 1
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/coldriver-steal-documents-western-targets-ngos"
        tags = "TTP, PowerShell, Evasion, COLDRIVER, LOSTKEYS"
        mitre_attack = "T1497.001"
        malware_family = "LOSTKEYS"
        malware_type = "Evasion"

    strings:
        // Strings to identify screen resolution discovery in PowerShell
        $res_1 = "PrimaryScreen.Bounds" ascii wide nocase
        $res_2 = "Win32_VideoController" ascii wide nocase
        $res_3 = "CIM_VideoControllerResolution" ascii wide nocase

        // Strings to identify MD5 hashing operations in PowerShell
        $md5_1 = "MD5CryptoServiceProvider" ascii wide nocase
        $md5_2 = "ComputeHash" ascii wide nocase

        // String conversion to bytes, often precedes hashing a string value
        $enc_1 = ".GetBytes(" ascii wide nocase

    condition:
        // Detects scripts that combine screen resolution discovery with MD5 hashing.
        // This combination is a strong indicator of sandbox evasion.
        // NOTE: While possible, it is uncommon for legitimate administrative scripts to
        // perform MD5 hashing on screen resolution values.
        filesize < 500KB and
        (1 of ($res_*)) and (1 of ($md5_*)) and $enc_1
}
