import "pe"

rule TOOL_WIN_Vulnerable_Driver_EDRSandblast
{
    meta:
        description = "Detects vulnerable drivers (GDRV.sys, RTCore64.sys, DBUtil_2_3.sys) commonly exploited by tools like EDRSandblast in 'Bring Your Own Vulnerable Driver' (BYOVD) attacks to disable security solutions."
        author = "Rob Weber"
        date = "2025-07-27"
        version = 1
        // Hashes for specific known vulnerable versions mentioned in the reference
        hash = "31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427" // GDRV.sys
        hash = "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd" // RTCore64.sys
        hash = "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5" // DBUtil_2_3.sys
        tags = "FILE, DRIVER, BYOVD, LOLDRIVER, EDRSANDBLAST"
        mitre_attack = "T1562.001"
        malware_family = "EDRSandblast"
        malware_type = "Defense Evasion"

    strings:
        // Filenames as strings for broader detection if PE info is stripped
        $fname1 = "gdrv.sys" nocase
        $fname2 = "RTCore64.sys" nocase
        $fname3 = "DBUtil_2_3.sys" nocase

        // Company names from PE version info to add context and reduce FPs
        $cname1 = "GIGABYTE" wide
        $cname2 = "Micro-Star" wide // For MSI Afterburner's RTCore64.sys
        $cname3 = "Dell Inc." wide

    condition:
        // The file must be a PE file and identified as a driver
        pe.is_pe and pe.is_driver() and
        (
            // Match on specific combinations of filename and company name
            ($fname1 and $cname1) or
            ($fname2 and $cname2) or
            ($fname3 and $cname3) or

            // Fallback to PE version info which is more reliable than loose strings.
            // This provides a good balance for medium false positive sensitivity.
            pe.version_info["OriginalFilename"] contains "gdrv.sys" or
            pe.version_info["OriginalFilename"] contains "RTCore64.sys" or
            pe.version_info["OriginalFilename"] contains "DBUtil_2_3.sys"
        )
}
