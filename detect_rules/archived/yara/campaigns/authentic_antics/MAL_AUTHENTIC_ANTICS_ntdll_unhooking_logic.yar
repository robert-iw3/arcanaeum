import "pe"

rule MAL_AUTHENTIC_ANTICS_ntdll_unhooking_logic
{
    meta:
        description = "Detects the AUTHENTIC ANTICS dropper by identifying the specific code logic it uses to unhook registry-related API functions within ntdll.dll. This is done to evade monitoring by security tools."
        author = "Rob Weber"
        date = "2025-07-25"
        version = 1
        reference = "NCSC Malware Analysis Report: AUTHENTIC ANTICS"
        malware_family = "AUTHENTIC ANTICS"
        malware_type = "Dropper"
        mitre_attack = "T1562.001"
        tags = "FILE, DROPPER, LOADER, AUTHENTIC_ANTICS, NCSC"

    strings:
        // Specific byte sequence for the ntdll.dll function unhooking calculation logic, as seen in the NCSC report.
        $unhook_logic = { 48 8B D0 49 2B D4 8B D2 49 03 D6 48 8B 00 48 3B 02 }

    condition:
        // Check for PE file header and that the file is a 64-bit DLL.
        uint16(0) == 0x5A4D and pe.is_64bit() and pe.is_dll() and
        // The report indicates the dropper is around 1.5MB. This helps scope the rule.
        filesize > 1MB and filesize < 2MB and
        // The primary condition is the presence of the unique unhooking code.
        $unhook_logic
}
