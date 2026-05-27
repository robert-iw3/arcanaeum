rule SUSP_ASPX_Webshell_UpdateChecker {
    meta:
        description = "Detects the UpdateChecker ASPX web shell, a highly obfuscated C# web shell used by an Iranian state-sponsored threat group in attacks against Middle East critical national infrastructure. The rule identifies the shell by its unique obfuscation patterns, such as Unicode-escaped identifiers, and specific JSON keys used in its command-and-control structure."
        date = "2025-07-28"
        version = 1
        hash = "a841c8179ac48bdc2ebf1e646d4f552d9cd02fc79207fdc2fc783889049f32bc"
        tags = "FILE, WEBSHELL, APT, IRAN, CNI"
        mitre_attack = "T1505.003, T1190"
        malware_family = "UpdateChecker"
        malware_type = "Webshell"

    strings:
        // -- Structural and Content-Type Indicators --
        $header_cs = "<%@ Page Language=\"C#\" %>" nocase ascii
        $content_type = "application/octet-stream" wide ascii

        // -- Obfuscation Artifacts --
        // Detects sequences of Unicode-escaped characters used for variable/class names
        // e.g., \u005c\u0049\u004f\u0031\u0031\u0049\u004f\u0031\u0031
        $obfu_unicode = /\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}/ ascii

        // -- C2 JSON Keys and Module Names --
        // These keys are mandatory in the C2 JSON structure
        $json_key1 = "ProtocolVersion" wide ascii
        $json_key2 = "ModuleName" wide ascii
        $json_key3 = "RequestName" wide ascii

        // Specific module names used by the web shell
        $module1 = "CommandShell" wide ascii
        $module2 = "FileManager" wide ascii
        $module3 = "GetBasicServerApplicationInfo" wide ascii

    condition:
        // -- Rule Logic --
        // Check for ASPX file header and reasonable file size
        uint16(0) == 0x253c and filesize < 500KB and

        // Require the C# page directive
        $header_cs and

        // Match one of two high-confidence patterns:
        (
            // Pattern 1: Obfuscation pattern plus key C2 strings
            ( $obfu_unicode and $content_type and 2 of ($json_key*) ) or

            // Pattern 2: All core JSON keys and at least one specific module name
            ( all of ($json_key*) and 1 of ($module*) )
        )
}
