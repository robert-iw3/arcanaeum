import "macho"

rule MACOS_Sploitlight_Importer_CVE_2025_31199
{
    meta:
        description = "Detects malicious Spotlight Importer (.mdimporter) binaries consistent with the 'Sploitlight' TCC bypass technique (CVE-2025-31199). The rule identifies Mach-O files that export the required 'GetMetadataForFile' function and contain code patterns for reading a file and exfiltrating its contents via logging."
        author = "RW"
        date = "2025-08-02"
        version = 1
        tags = "MACOS, TCC_BYPASS, SPLOITLIGHT, FILE, CVE_2025_31199"
        mitre_attack = "T1553.001, T1547.014, T1005"
        malware_family = "Sploitlight"
        malware_type = "TCC Bypass"

    strings:
        // Specific strings from the Microsoft proof-of-concept code
        $poc_log1 = "POC: FILE @ %s: size: %lu" ascii
        $poc_log2 = "POC: file @ leak at offset %lu: %s" ascii

        // Generic Objective-C methods used for the exfiltration technique
        $exfil_open = "fileHandleForReadingAtPath:" ascii wide
        $exfil_read = "readDataOfLength:" ascii wide
        $exfil_log = "NSLog" ascii wide

    condition:
        // Must be a Mach-O file (the executable within the .mdimporter bundle)
        macho.is_macho

        // A legitimate Spotlight Importer must export this function
        and macho.exports("GetMetadataForFile")

        // Detection logic:
        // Either find specific strings from the public PoC,
        // or find a combination of generic methods used for file reading and logging,
        // which indicates the exfiltration technique.
        // NOTE: Legitimate importers may read files, but the combination with extensive logging is suspicious.
        and (
            1 of ($poc_*) or
            (all of ($exfil*))
        )
}
