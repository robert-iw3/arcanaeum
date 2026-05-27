import "hash"

rule BEHAVIOR_VBS_Infostealer_LOSTKEYS_Pattern
{
    meta:
        description = "Detects VBScript-based infostealers that exhibit behaviors similar to the COLDRIVER group's LOSTKEYS malware. This rule identifies scripts that perform system and process discovery and prepare data for exfiltration."
        date = "2025-07-24"
        version = 1
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/coldriver-steal-documents-western-targets-ngos"
        tags = "TTP, VBS, Infostealer, COLDRIVER, LOSTKEYS"
        mitre_attack = "T1005, T1082, T1057"
        malware_family = "LOSTKEYS"
        malware_type = "Infostealer"

    strings:
        // System information discovery commands and functions (T1082)
        $sysinfo_1 = "systeminfo" ascii nocase
        $sysinfo_2 = "ipconfig /all" ascii nocase
        $sysinfo_3 = ".ExpandEnvironmentStrings(\"%COMPUTERNAME%\")" ascii nocase
        $sysinfo_4 = ".GetDrive(\"C:\\\").SerialNumber" ascii nocase
        $sysinfo_5 = "net view" ascii nocase

        // Process discovery command (T1057)
        $procinfo_1 = "tasklist" ascii nocase

        // Data encoding and preparation for exfiltration (T1005)
        $exfil_1 = "base64encode" ascii nocase
        $exfil_2 = "ReqStr = Chain(ReqStr," ascii nocase // Custom function for obfuscating beacon data

        // Unique substitution cipher logic from LOSTKEYS
        $obfu_1 = "my_str = replace(my_str,a1,\"!\" )" ascii nocase
        $obfu_2 = "my_str = replace(my_str,b1 ,a1 )" ascii nocase
        $obfu_3 = "my_str = replace(my_str,\"!\" ,b1 )" ascii nocase

    condition:
        // This rule detects either the highly specific substitution cipher from LOSTKEYS
        // or a combination of info-gathering and data-staging behaviors.
        // The behavioral part requires multiple indicators to reduce potential false positives from legitimate admin scripts.
        filesize < 250KB and
        (
            all of ($obfu_*) or
            (2 of ($sysinfo_*) and $procinfo_1 and 1 of ($exfil_*))
        )
}
