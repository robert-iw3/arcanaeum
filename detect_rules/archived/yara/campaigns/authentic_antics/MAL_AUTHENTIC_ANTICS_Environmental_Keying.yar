import "pe"

rule MAL_AUTHENTIC_ANTICS_Environmental_Keying
{
    meta:
        description = "Detects the AUTHENTIC ANTICS loader by identifying strings related to its environmental keying technique. The malware derives a decryption key from the victim's MachineGuid and Volume Serial Number to decrypt its stealer payload. This rule looks for the specific obfuscated string 'MachineGuid' as described in the NCSC report."
        author = "Rob Weber"
        date = "2025-07-25"
        version = "1"
        reference = "NCSC Malware Analysis Report: AUTHENTIC ANTICS"
        malware_family = "AUTHENTIC ANTICS"
        malware_type = "Loader"
        mitre_attack = "T1480.001"
        tags = "FILE, LOADER, DROPPER, AUTHENTIC_ANTICS, NCSC"

    strings:
        // Specific byte sequence for the string "MachineGuid" obfuscated via subtraction with 0x54, as detailed in the NCSC report.
        $obf_machineguid = { a1 b5 b7 bc bd c2 b9 9b c9 bd b8 }

        // Supporting strings related to the environmental keying logic.
        $s1 = "Cryptography" wide ascii // Part of the registry path for MachineGuid: HKLM\Software\Microsoft\Cryptography
        $s2 = "GetVolumeInformationW" wide ascii // Windows API used to retrieve the volume serial number.
        $s3 = "c:\\" wide ascii // The malware specifically targets the C: drive for the volume serial number.

    condition:
        // The dropper is a 64-bit PE DLL file.
        uint16(0) == 0x5A4D and pe.is_64bit() and pe.is_dll() and
        // Report indicates samples are around 1.5MB. This helps scope the rule.
        filesize > 1MB and filesize < 2MB and
        // Require the unique obfuscated string and at least one other supporting artifact to increase confidence.
        $obf_machineguid and 1 of ($s*)
}
