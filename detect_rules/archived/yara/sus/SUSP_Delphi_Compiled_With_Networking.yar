import "pe"

rule SUSP_Delphi_Compiled_With_Networking
{
    meta:
        description = "Detects executable files compiled with Delphi that also contain networking-related strings. This pattern is common in various malware families, including DanaBot, which use Delphi for development."
        author = "Rob Weber"
        date = "2025-07-24"
        version = 1
        reference = "https://www.zscaler.com/blogs/security-research/danableed-danabot-c2-server-memory-leak-bug"
        tags = "FILE, TOOLS, DELPHI, DANABOT"
        mitre_attack = "T1105"
        malware_family = "DanaBot"
        malware_type = "Tool"

    strings:
        // High-confidence markers for Delphi-compiled files
        $marker1 = "Borland-Delphi" ascii
        $marker2 = "DVCLAL" wide // Common resource name

        // Common Delphi Visual Component Library (VCL) class names
        $vcl1 = "TMemoryStream" ascii wide
        $vcl2 = "TForm" ascii wide
        $vcl3 = "TApplication" ascii wide
        $vcl4 = "SysUtils" ascii wide
        $vcl5 = "Classes" ascii wide

        // Networking-related strings, including Delphi's Indy library and standard WinSock functions
        $net1 = "TIdHTTP" ascii wide
        $net2 = "TClientSocket" ascii wide
        $net3 = "gethostbyname" ascii
        $net4 = "WSAStartup" ascii

    condition:
        // Must be a PE file under 5MB to scope the rule
        pe.is_pe and filesize < 5MB and
        // Require either a strong Delphi marker or a cluster of VCL strings
        ( (1 of ($marker*)) or (3 of ($vcl*)) ) and
        // Also require at least one networking-related string to align with the threat pattern
        // Note: This may flag legitimate Delphi applications that use networking.
        (1 of ($net*))
}
