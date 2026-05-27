import "pe"

rule MAL_DanaBot_Naming_Artifacts
{
    meta:
        description = "Detects DanaBot malware by identifying unique strings used in its dynamic artifact naming algorithm. This algorithm generates filenames and other artifacts based on the host's hardware GUID."
        author = "Rob Weber"
        date = "2025-07-24"
        version = 1
        reference = "https://www.zscaler.com/blogs/security-research/operation-endgame-2-0-danabusted"
        hash = "2f8e0fc38eaf08a69653f40867dcd4cc951a10cd92b8168898b9aa45ba18a5c8"
        hash = "871862d1117fd7d2df907406a3ce08555196800b0ef9901dd4c46f82b728263d"
        tags = "CRIME, BANKER, LOADER, DANABOT, FILE"
        mitre_attack = "T1036.005"
        malware_family = "DanaBot"
        malware_type = "Banker"

    strings:
        // Unique charsets hardcoded in the malware for its artifact naming function
        $naming_charset1 = "wrtpsdfhlzcvbnm" ascii
        $naming_charset2 = "qeyuioaqeyuioaqe" ascii

        // This string is from the DanaBot client application, but may appear in bot samples
        // It is not used in the condition to avoid potential false negatives, but can be useful for manual analysis
        $_client_string = "Hi it's okay you're in the system" wide nocase

    condition:
        // Must be a PE file under 5MB
        pe.is_pe and filesize < 5MB and

        // Both charsets must be present as they are part of the same naming function
        // The combination of these two strings is highly specific to DanaBot
        all of ($naming_*)
}
