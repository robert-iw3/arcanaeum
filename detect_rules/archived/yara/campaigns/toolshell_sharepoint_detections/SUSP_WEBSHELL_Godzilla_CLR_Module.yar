import "pe"

rule SUSP_WEBSHELL_Godzilla_CLR_Module
{
    meta:
        description = "Detects Godzilla webshell .NET extension modules. These modules are loaded into the IIS worker process (w3wp.exe) to provide additional functionality like remote code execution, file listing, and system information gathering. This activity is often seen after the exploitation of SharePoint vulnerabilities like CVE-2025-53770 and CVE-2025-53771."
        author = "Rob Weber"
        date = "2025-07-25"
        version = 1
        reference = "https://kerberpoasting.medium.com/sharepoint-of-no-return-analysing-the-godzilla-webshell-cve-2025-53770-cve-2025-53771-a4e8e6a74bd1"
        tags = "WEBSHELL, BACKDOOR, GODZILLA, FILE"
        mitre_attack = "T1547.008, T1055"
        malware_family = "Godzilla"
        malware_type = "Webshell"

    strings:
        // Module names, may be present as filename or within the assembly.
        $mod_name_1 = "LoadLibrary" wide
        $mod_name_2 = "RemoteExec" wide
        $mod_name_3 = "FileList" wide
        $mod_name_4 = "ProcessList" wide
        $mod_name_5 = "Information" wide

        // Specific class name from the LoadLibrary module
        $specific_1 = "LoadLibrary.Class1" wide

        // Base64 encoded strings for POST field names used as arguments
        $specific_2 = "X19TQ1JPTExQT1NJVElPTg==" ascii // base64 for "__SCROLLPOSITION" used by RemoteExec
        $specific_3 = "X19TQ1JPTExQQVRI" ascii // base64 for "__SCROLLPATH" used by FileList

    condition:
        // Rule targets .NET assemblies, which are PE files.
        pe.is_pe
        and filesize < 1MB
        // Detects files containing any of the specific module names or unique artifacts.
        // Some module names like 'Information' or 'ProcessList' could be generic.
        // If false positives occur, consider requiring more specific strings ($specific_*)
        // or multiple module name strings (e.g., 2 of ($mod_name_*)).
        and (
            1 of ($mod_name_*) or
            1 of ($specific_*)
        )
}
