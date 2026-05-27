import "pe"

rule SUSP_Injector_ProcessHollowing_Indicators_v1
{
    meta:
        description = "Detects files containing code artifacts consistent with the Process Hollowing technique (T1055.012). This rule identifies PE files that import or contain strings of Windows APIs used to create a suspended process, unmap its memory, and inject new code."
        author = "RW"
        date = "2025-08-07"
        version = 1
        tags = "FILE, INJECTOR, EVASION, PROCESS_HOLLOWING"
        mitre_attack = "T1055.012"
        malware_type = "Injector"

    strings:
        // Key APIs for process hollowing
        $api_unmap = "NtUnmapViewOfSection" ascii wide
        $api_alloc = "VirtualAllocEx" ascii wide
        $api_write = "WriteProcessMemory" ascii wide
        $api_resume = "ResumeThread" ascii wide
        $api_context = "GetThreadContext" ascii wide
        $api_create = "CreateProcess" ascii wide // Catches CreateProcessA and CreateProcessW

        // Flag used when creating the target process in a suspended state
        $flag_suspended = "CREATE_SUSPENDED" ascii wide

    condition:
        // Rule targets Windows PE files under 5MB
        pe.is_pe
        and filesize < 5MB
        // The presence of NtUnmapViewOfSection is a strong indicator of hollowing
        and $api_unmap
        // Requiring the CREATE_SUSPENDED flag and at least two other hollowing APIs increases confidence.
        // Note: Some legitimate software packers or protectors may use these functions, which could cause FPs.
        and ($flag_suspended or $api_create)
        and 2 of ($api_alloc, $api_write, $api_resume, $api_context)
}
