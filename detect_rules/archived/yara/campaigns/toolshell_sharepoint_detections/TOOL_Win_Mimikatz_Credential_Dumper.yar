import "pe"

rule TOOL_Win_Mimikatz_Credential_Dumper {
    meta:
        description = "Detects Mimikatz, a credential dumping tool, often used in post-exploitation activities. This rule identifies the tool based on unique strings found in its binaries."
        author = "Rob Weber"
        date = "2025-07-24"
        version = 1
        reference = "https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/"
        tags = "TOOL, MIMIKATZ, CREDENTIAL_DUMPING, FILE"
        mitre_attack = "T1003.001"
        malware_family = "Mimikatz"
        malware_type = "Credential Dumper"

    strings:
        // Core identifiers for Mimikatz, including author and project names.
        $id1 = "mimikatz" wide ascii nocase
        $id2 = "gentilkiwi" wide ascii
        $id3 = "Benjamin DELPY" wide ascii

        // Common command and module names used within Mimikatz.
        $cmd1 = "sekurlsa::logonpasswords" wide ascii
        $cmd2 = "lsadump::sam" wide ascii
        $cmd3 = "privilege::debug" wide ascii
        $cmd4 = "kerberos::list" wide ascii
        $cmd5 = "dpapi::masterkey" wide ascii
        $cmd6 = "ERROR kuhl_m_" wide ascii // Common error format

    condition:
        // This rule detects the file at rest. Mimikatz is often reflectively loaded into memory,
        // which requires memory scanning or behavioral detection by an EDR.
        pe.is_pe
        and filesize < 10MB
        and (1 of ($id*)) and (2 of ($cmd*))
}
