import "zip"

rule SUSP_Large_Encrypted_Zip_With_NSIS_Installer {
    meta:
        description = "Detects unusually large (e.g., >800MB) password-protected ZIP archives containing a Nullsoft Scriptable Install System (NSIS) installer. This technique is used by malware families like Lumma and Vidar to bypass security scanners with file size limitations."
        date = "2025-07-24"
        version = 1
        reference = "https://www.zscaler.com/blogs/security-research/black-hat-seo-poisoning-search-engine-results-ai-distribute-malware"
        tags = "CRIME, INFOSTEALER, LOADER, LUMMA, VIDAR, ZIP, NSIS, FILE"
        mitre_attack = "T1566.001, T1189"
        malware_family = "Lumma, Vidar"
        malware_type = "Loader"

    strings:
        // Private string to identify a ZIP archive header.
        $_zip_header = { 50 4B 03 04 }

        // Public string for the NSIS installer signature.
        $nsis_sig = "NullsoftInst" ascii

    condition:
        // 1. Check for ZIP file signature.
        $_zip_header at 0
        // 2. Filter for unusually large files (>800MB) to match the evasion technique.
        and filesize > 800MB
        // 3. Verify that the archive is password-protected using the zip module.
        and zip.encrypted
        // 4. Check for the presence of an NSIS installer signature within the archive.
        and $nsis_sig
}
