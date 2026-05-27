import "pe"

rule TTP_Lumma_Stealer_ChaCha20_Decryption
{
    meta:
        description = "Detects the ChaCha20 decryption routine used by malware like Lumma Stealer. This rule identifies the characteristic sequence of ADD, XOR, and ROL (rotate left) instructions that form the ChaCha20 quarter-rounds, which are used to decrypt strings and C2 domains."
        author = "RW"
        date = "2025-07-28"
        version = "1"
        malware_family = "Lumma"
        malware_type = "Infostealer"
        mitre_attack = "T1027"
        tags = "CRIME, INFOSTEALER, LUMMA, CHACHA20, DECRYPTION, FILE"

    strings:
        // Detects the core operations of ChaCha20 quarter-rounds (ADD, XOR, ROL) with the specific rotate values.
        // Pattern: ADD r32, r32; XOR r32, r32; ROL r32, imm8
        // { 01 ?? } = ADD r/m32, r32
        // { 31 ?? } = XOR r/m32, r32
        // { C1 C? imm8 } = ROL r/m32, imm8
        $chacha_qr_16 = { 01 ?? 31 ?? C1 C? 10 } // ROL by 16
        $chacha_qr_12 = { 01 ?? 31 ?? C1 C? 0C } // ROL by 12
        $chacha_qr_08 = { 01 ?? 31 ?? C1 C? 08 } // ROL by 8
        $chacha_qr_07 = { 01 ?? 31 ?? C1 C? 07 } // ROL by 7

    condition:
        // Target 32-bit executables, as seen in the Lumma Stealer sample.
        pe.is_pe and pe.machine == pe.MACHINE_I386 and
        filesize < 5MB and
        // A full ChaCha20 implementation will use all four quarter-round variations.
        // Requiring all of them provides high confidence. For broader detection, this could be lowered
        // to `3 of them`, but may increase potential false positives from other cryptographic implementations.
        all of ($chacha_qr_*)
}
