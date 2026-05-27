import "pe"

rule TTP_Heavens_Gate_Evasion_Technique
{
    meta:
        description = "Detects the Heaven's Gate technique, which allows a 32-bit process to execute 64-bit code. This is achieved via a 'far jump' instruction (jmp far 33:<address>) that switches the CPU from x86 to x64 mode. This evasion technique is used by malware like Lumma Stealer to bypass security products and call native 64-bit APIs."
        author = "RW"
        date = "2025-07-28"
        version = "1"
        malware_family = "Lumma"
        malware_type = "Infostealer"
        mitre_attack = "T1027.006"
        tags = "CRIME, INFOSTEALER, LUMMA, HEAVENS_GATE, EVASION, FILE"

    strings:
        // Detects the 'jmp far' instruction used to switch from 32-bit to 64-bit mode.
        // Opcode EA: JMPF p_imm16:imm16/32
        // [4]: 4-byte address offset
        // 33 00: The 16-bit segment selector 0x33 for the 64-bit code segment.
        $heavens_gate_jmp = { EA [4] 33 00 }

    condition:
        // Must be a 32-bit PE file. Heaven's Gate is used by 32-bit processes to execute 64-bit code.
        pe.is_pe and pe.machine == pe.MACHINE_I386 and
        // File size check to scope the rule and avoid very large files.
        filesize < 5MB and
        // The presence of the specific far jump instruction.
        // This technique is highly suspicious but could potentially be used by legitimate software like DRM or anti-cheat.
        // The check for a 32-bit PE file helps increase confidence.
        $heavens_gate_jmp
}
