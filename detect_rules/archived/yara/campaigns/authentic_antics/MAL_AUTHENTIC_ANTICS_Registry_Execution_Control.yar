import "pe"

rule MAL_AUTHENTIC_ANTICS_Registry_Execution_Control
{
    meta:
        description = "Detects the AUTHENTIC ANTICS malware by identifying strings related to its registry-based execution frequency control. The malware reads and writes to the 'Counter' value within 'HKCU\\Software\\Microsoft\\Office\\16.0\\Outlook\\Logging' to ensure it only runs periodically."
        author = "Rob Weber"
        date = "2025-07-25"
        version = "1"
        reference = "NCSC Malware Analysis Report: AUTHENTIC ANTICS"
        malware_family = "AUTHENTIC ANTICS"
        malware_type = "Stealer"
        mitre_attack = "T1112"
        tags = "FILE, STEALER, LOADER, AUTHENTIC_ANTICS, NCSC"

    strings:
        // Registry path used for storing execution timer and stolen tokens.
        $reg_path = "Software\\Microsoft\\Office\\16.0\\Outlook\\Logging" wide ascii

        // Registry value name for the execution timer. The NCSC report states this is not a legitimate value.
        $reg_val_counter = "Counter" wide ascii

        // Registry value name used to store a stolen OAuth refresh token.
        $reg_val_locale = "Locale" wide ascii

    condition:
        // Check for a 64-bit PE file, likely a DLL as per the report.
        uint16(0) == 0x5A4D and pe.is_64bit() and pe.is_dll() and

        // The malware components are described as being under 2MB.
        filesize < 2MB and

        // Require the specific registry path and at least one of the unique value names.
        $reg_path and ( $reg_val_counter or $reg_val_locale )
}
