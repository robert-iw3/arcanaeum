rule SUSP_LNK_LargeFile_RoKRAT_InitialAccess
{
    meta:
        description = "Detects unusually large LNK (shortcut) files. This technique is used by threat actors like APT37 to embed malicious payloads, such as RoKRAT malware, within the LNK file itself."
        author = "RW"
        date = "2025-08-05"
        version = 1
        reference = "https://www.genians.co.kr/en/blog/threat_intelligence/rokrat_shellcode_steganographic"
        tags = "APT, ROKRAT, APT37, LNK, FILE"
        mitre_attack = "T1204.001, T1566.001"
        malware_family = "RoKRAT"

    strings:
        // LNK file header: 0x4C (L)
        $_lnk_header = { 4C 00 00 00 }

        // LNK file CLSID: 00021401-0000-0000-C000-000000000046
        $lnk_clsid = { 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

    condition:
        // Check for LNK file signature at the start of the file
        $_lnk_header at 0 and
        // Check for the presence of the LNK CLSID
        $lnk_clsid and
        // Detect if the file size is abnormally large for a shortcut file.
        // The threshold is set to 10MB, as legitimate LNK files are typically only a few kilobytes.
        // This may need tuning based on environment, but is a strong indicator of embedded content.
        filesize > 10MB
}
