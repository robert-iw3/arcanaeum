import "pe"

rule TTP_Injector_EntryPoint_API
{
    meta:
        description = "Detects PE files that import a combination of Windows APIs commonly used for entry point process injection. This technique involves creating a suspended process, querying its entry point, overwriting it with shellcode, and then resuming the process."
        author = "RW"
        date = "2025-08-02"
        version = 1
        tags = "FILE, INJECTOR, WINDOWS"
        mitre_attack = "T1055"
        malware_type = "Injector"

    strings:
        // APIs for creating and resuming the target process
        $api_create = "CreateProcess" ascii wide
        $api_resume = "ResumeThread" ascii wide

        // APIs for writing shellcode into the target process
        $api_write_1 = "WriteProcessMemory" ascii wide
        $api_write_2 = "NtWriteVirtualMemory" ascii wide

        // APIs for finding the entry point address
        $api_query_1 = "NtQueryInformationThread" ascii wide
        $api_query_2 = "NtQueryInformationProcess" ascii wide

    condition:
        // Check for a valid PE file, typically a tool/utility so under 2MB.
        pe.is_pe and filesize < 2MB and

        // The logic detects the combination of APIs needed for this specific injection technique.
        // FP Note: Debuggers, security tools, or process management utilities may also use this combination.
        $api_create and
        $api_resume and
        1 of ($api_write_*) and
        1 of ($api_query_*)
}
