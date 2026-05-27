import "pe"

rule SUSP_PowerShell_Memory_Injection_Loader_CobaltStrike {
    meta:
        description = "Detects PowerShell scripts indicative of in-memory payload execution, commonly used by Cobalt Strike loaders. The rule looks for a combination of Base64 decoding, memory allocation functions (VirtualAlloc), and shellcode execution via delegates (.Invoke)."
        author = "RW"
        date = "2025-08-06"
        version = 1
        hash = "41116eaf116e0aa23a281d271f8b6056b0004de809e0ca9b639a5eaf4766d355"
        tags = "TTP, POWERSHELL, LOADER, COBALT_STRIKE, FILE"
        mitre_attack = "T1059.001, T1055, T1106"
        malware_family = "Cobalt Strike"
        malware_type = "Loader"

    strings:
        // -- Obfuscation/Decoding indicators
        $obfu_1 = "FromBase64String" ascii wide
        $obfu_2 = "-EncodedCommand" ascii wide nocase
        $obfu_3 = "bxor" ascii wide nocase // XOR operation for deobfuscation

        // -- Core memory injection API and method calls
        $api_1 = "VirtualAlloc" ascii wide
        $api_2 = "GetProcAddress" ascii wide
        $api_3 = "Marshal.Copy" ascii wide // Used to copy shellcode into the allocated buffer
        $api_4 = "VirtualProtect" ascii wide
        $api_5 = "WriteProcessMemory" ascii wide
        $api_6 = "CreateRemoteThread" ascii wide

        // -- Execution via .NET delegate
        $exec_1 = ".Invoke" ascii wide

    condition:
        // This rule targets scripts, not PE files, so we focus on string combinations.
        // The logic requires key components of the attack chain: decoding, memory allocation, and execution.
        // This combination is highly suspicious but could potentially flag complex administrative scripts.
        filesize < 500KB
        and (
            // Detects PowerShell scripts (.ps1)
            1 of ($obfu_*) and
            all of ($api_1, $api_3, $exec_1) and
            1 of ($api_2, $api_4, $api_5, $api_6)
        ) or (
            // Detects PE files (.exe, .dll) with embedded Cobalt Strike strings
            pe.is_pe and
            2 of ($api_1, $api_4, $api_5, $api_6) and
            $obfu_2
        )
}
