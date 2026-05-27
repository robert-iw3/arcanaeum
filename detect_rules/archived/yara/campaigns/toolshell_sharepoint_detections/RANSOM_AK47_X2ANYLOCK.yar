import "pe"

rule RANSOM_AK47_X2ANYLOCK {
    meta:
        description = "Detects AK47/X2ANYLOCK ransomware based on unique PDB paths and embedded ransom note artifacts."
        author = "RW"
        date = "2025-08-06"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/ak47-activity-linked-to-sharepoint-vulnerabilities/"
        hash = "4147a1c7084357463b35071eab6f4525a94476b40336ebbf8a4e54eb9b51917f"
        hash = "79bef5da8af21f97e8d4e609389c28e0646ef81a6944e329330c716e19f33c73"
        hash = "55a246576af6f6212c26ef78be5dd8f83e78dd45aea97bb505d8cee1aeef6f17"
        tags = "CRIME, RANSOMWARE, AK47, X2ANYLOCK, FILE"
        mitre_attack = "T1486"
        malware_family = "AK47/X2ANYLOCK"
        malware_type = "Ransomware"

    strings:
        // Specific PDB paths found in AK47 ransomware samples
        $pdb1 = "C:\\Users\\Administrator\\Desktop\\work\\tools\\ai\\ak47\\cpp\\encrypt\\encrypt\\x64\\Release\\encrypt.pdb" ascii
        $pdb2 = "C:\\Users\\Administrator\\Desktop\\work\\tools\\ai\\ak47\\writenull\\x64\\Release\\writenull.pdb" ascii

        // Ransom note artifacts
        $note_name1 = "How to decrypt my data.txt" wide
        $note_name2 = "How to decrypt my data.log" wide
        $note_ext = ".x2anylock" wide
        $note_tox = "3DCE1C43491FC92EA7010322040B254FDD2731001C2DDC2B9E819F0C946BDC3CD251FA3B694A" ascii nocase

        // File path checked by the ransomware for its anti-analysis timestamp check
        $file_check = "C:\\Windows\\System32\\perfc009.dat" wide

    condition:
        // Must be a PE file under 5MB
        pe.is_pe and filesize < 5MB and
        (
            // High-confidence match on unique PDB paths
            1 of ($pdb*) or
            // Combination of ransom note artifacts for broader detection
            (1 of ($note_name*) and $note_ext and $note_tox and $file_check)
        )
}
