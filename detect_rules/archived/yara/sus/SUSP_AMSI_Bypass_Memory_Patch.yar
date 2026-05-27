import "pe"

rule SUSP_AMSI_Bypass_Memory_Patch
{
    meta:
        description = "Detects files containing code snippets commonly used for in-memory patching of the AmsiScanBuffer function to bypass AMSI. This technique is often used by malware and offensive security tools."
        author = "RW"
        date = "2025-07-30"
        version = 1
        reference = "https://www.crowdstrike.com/en-us/blog/crowdstrike-investigates-threat-of-patchless-amsi-bypass-attacks/"
        tags = "TTP, DEFENSE_EVASION, AMSI, BYPASS, FILE"
        mitre_attack = "T1562.001"
        malware_type = "Bypass"

    strings:
        // References to the AMSI library and the target function
        $s_amsi_dll = "amsi.dll" nocase ascii wide
        $s_amsi_func = "AmsiScanBuffer" ascii wide

        // Functions used to change memory permissions to allow patching
        $s_mem_perm1 = "VirtualProtect" ascii wide
        $s_mem_perm2 = "NtProtectVirtualMemory" ascii wide

        // Common byte sequences for patching AmsiScanBuffer to force a return
        // mov eax, 0x80070057 (E_INVALIDARG); ret
        $hex_patch_invalid_arg = { B8 57 00 07 80 C3 }
        // xor eax, eax; ret (return 0 / S_OK)
        $hex_patch_ret_0_xor = { 33 C0 C3 }
        // mov eax, 0; ret (return 0 / S_OK)
        $hex_patch_ret_0_mov = { B8 00 00 00 00 C3 }

    condition:
        // Rule targets PE files under 2MB to scope the search
        pe.is_pe and filesize < 2MB
        // Must reference either the amsi dll or the specific function
        and ( $s_amsi_dll or $s_amsi_func )
        // Must reference a function to change memory permissions
        and ( $s_mem_perm1 or $s_mem_perm2 )
        // Must contain a known patch sequence. This is the strongest indicator.
        // This combination may flag some legitimate offensive security tools or red-team scripts.
        and ( 1 of ($hex_patch*) )
}
