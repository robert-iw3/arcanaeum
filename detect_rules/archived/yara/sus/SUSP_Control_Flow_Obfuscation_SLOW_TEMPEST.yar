import "pe"

rule SUSP_Control_Flow_Obfuscation_SLOW_TEMPEST
{
    meta:
        description = "Detects files potentially using control flow graph (CFG) obfuscation techniques similar to those used by SLOW#TEMPEST malware. This rule looks for a high frequency of dynamic jumps and calls to general-purpose registers, which are characteristic of this evasion method."
        date = "2025-07-24"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/slow-tempest-malware-obfuscation/"
        tags = "CRIME, SLOW_TEMPEST, OBFUSCATION, FILE, T1027.004"
        mitre_attack = "T1027.004"
        malware_family = "SLOW#TEMPEST"
        malware_type = "Obfuscation"

    strings:
        // Opcodes for dynamic jumps and calls via general-purpose registers (RAX, RCX, RDX, RBX).
        // A high frequency of these can indicate control flow obfuscation as described in the reference.
        $dyn_jmp = /FF E[0-3]/ // JMP RAX/RCX/RDX/RBX
        $dyn_call = /FF D[0-3]/ // CALL RAX/RCX/RDX/RBX

    condition:
        // Rule targets PE files, as the malware described is a DLL.
        pe.is_pe
        and filesize < 10MB
        // The core logic detects a high number of dynamic jumps or calls.
        // The threshold is based on the analysis that the malware's main function had 10+ dynamic jumps.
        // This may need tuning as it could flag legitimate, complex applications (e.g., with many switch statements or virtual calls).
        and ( #dyn_jmp > 8 or #dyn_call > 8 )
}
