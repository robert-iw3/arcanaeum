import "pe"

rule MAL_DanaBot_TOR_C2_Domain
{
    meta:
        description = "Detects DanaBot malware samples containing a hardcoded TOR C2 domain. This .onion address was identified as a command-and-control server for the DanaBot main module."
        author = "Rob Weber"
        date = "2025-07-24"
        version = "1"
        reference = "https://www.zscaler.com/blogs/security-research/operation-endgame-2-0-danabusted"
        tags = "CRIME, BANKER, LOADER, DANABOT, FILE"
        mitre_attack = "T1071.001"
        malware_family = "DanaBot"
        malware_type = "Banker"

    strings:
        // Hardcoded TOR C2 domain for DanaBot main module
        $c2_onion = "y3wg3owz34ybihfulzr4blznkb6g6zf2eeuffhqrdvwdp43xszjknwad.onion" ascii wide

    condition:
        // Check for PE file and reasonable size to scope the search
        pe.is_pe and filesize < 10MB and

        // The presence of this unique .onion address is a strong indicator of DanaBot
        $c2_onion
}
