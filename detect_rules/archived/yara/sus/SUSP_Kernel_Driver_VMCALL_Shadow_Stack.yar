import "pe"

rule SUSP_Kernel_Driver_VMCALL_Shadow_Stack : KERNEL DRIVER SHADOW_STACK FILE
{
    meta:
        description = "Detects kernel drivers or other 64-bit executables containing specific vmcall hypercalls (0xC and 0x11). These hypercalls are used to interact with the Windows secure kernel for shadow stack management. Malicious drivers may use these hypercalls in an attempt to manipulate or bypass Kernel Shadow Stack protections."
        author = "RW"
        date = "2025-08-04"
        version = 1
        reference = "https://github.com/synacktiv/windows_kernel_shadow_stack"
        tags = "EXPLOIT, KERNEL, DRIVER, SHADOW_STACK, VMCALL, FILE"
        mitre_attack = "T1562.001"
        malware_type = "Exploit"

    strings:
        // mov rcx, 0x11; vmcall - Used for nt!VslAllocateKernelShadowStack
        $vmcall_11 = { 48 C7 C1 11 00 00 00 0F 01 C1 }

        // mov rcx, 0xc; vmcall - Used for securekernel!ShvlpProtectPages
        $vmcall_0c = { 48 C7 C1 0C 00 00 00 0F 01 C1 }

    condition:
        // Check for a 64-bit PE file, likely a kernel driver
        uint16(0) == 0x5A4D and
        pe.is_64bit() and
        pe.subsystem == pe.IMAGE_SUBSYSTEM_NATIVE and
        filesize < 5MB and

        // Detect either of the suspicious hypercall sequences
        1 of ($vmcall_*)
}
