rule WEBSHELL_ASPX_SharePoint_Spinstall_MachineKey_Stealer {
    meta:
        description = "Detects the 'spinstall.aspx' web shell used by threat actors to steal SharePoint MachineKey data following exploitation of vulnerabilities like CVE-2025-53770."
        author = "Rob Weber"
        date = "2025-07-24"
        version = 1
        reference = "https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/"
        hash = "92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514"
        tags = "WEBSHELL, SHAREPOINT, STORM-2603, FILE"
        mitre_attack = "T1505.003"
        malware_family = "Storm-2603"
        malware_type = "Web Shell"

    strings:
        // ASPX page directive, common at the start of the file.
        $aspx_directive = "<%@ Page Language=" nocase

        // Strings related to accessing the MachineKey configuration section.
        $s1 = "MachineKeySection" ascii
        $s2 = "GetSection(\"system.web/machineKey\")" ascii

        // Strings for the specific keys being stolen.
        $s3 = "DecryptionKey" ascii
        $s4 = "ValidationKey" ascii

        // String to output the stolen data.
        $s5 = "Response.Write" ascii

    condition:
        // This rule targets small text-based files consistent with web shells.
        // It looks for ASPX files that contain functionality to read and display MachineKey data.
        // This could potentially flag legitimate administrative scripts, but the combination of strings is specific to the described threat.
        filesize < 20KB
        and $aspx_directive at 0
        and ( $s2 or ($s1 and $s3 and $s4) )
        and $s5
}
