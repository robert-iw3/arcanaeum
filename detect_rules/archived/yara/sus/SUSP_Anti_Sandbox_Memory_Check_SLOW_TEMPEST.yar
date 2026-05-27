import "pe"

rule SUSP_Anti_Sandbox_Memory_Check_SLOW_TEMPEST
{
    meta:
        description = "Detects files performing an anti-sandbox check by querying total physical memory using GlobalMemoryStatusEx and comparing it against a high threshold (e.g., 6GB), a technique observed in SLOW#TEMPEST malware."
        date = "2025-07-24"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/slow-tempest-malware-obfuscation/"
        tags = "CRIME, SLOW_TEMPEST, ANTI-SANDBOX, FILE, T1497.001"
        mitre_attack = "T1497.001"
        malware_family = "SLOW#TEMPEST"
        malware_type = "Evasion"

    strings:
        // Looks for the instruction to move the 6GB value (0x180000000) into a 64-bit general-purpose register.
        // This value is used as the threshold for the memory check.
        // Opcode: 48 B[8-F] -> MOV r64, imm64
        // Value: 00 00 00 80 01 00 00 00 -> 6,442,450,944 (6GB) in little-endian
        $mov_6gb = /48 B[8-F] 00 00 00 80 01 00 00 00/

    condition:
        // Target 64-bit PE files, as the technique uses 64-bit registers and values.
        pe.is_pe and pe.is_64bit()
        // Check for the import of the specific Windows API used for the memory check.
        and pe.imports("kernel32.dll", "GlobalMemoryStatusEx")
        // The presence of the hardcoded 6GB value being loaded into a register is a strong indicator.
        // This combination is highly suspicious of an anti-analysis evasion technique.
        and $mov_6gb
}
