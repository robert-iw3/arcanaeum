import "pe"

rule TOOL_Win_AVNeutralizer_AuKill_Drivers
{
    meta:
        description = "Detects driver files associated with the AVNeutralizer (also known as AuKill) tool. This tool uses ProcLaunchMon.sys or a renamed Process Explorer driver (PED.sys) to terminate security products and evade defenses."
        author = "Rob Weber"
        date = "2025-07-27"
        version = 1
        tags = "FILE, DRIVER, DEFENSE_EVASION, AVNEUTRALIZER, AUKILL"
        mitre_attack = "T1562.001"
        malware_family = "AVNeutralizer"
        malware_type = "Defense Evasion"

    strings:
        // Strings for ProcLaunchMon.sys used by AVNeutralizer
        $f1 = "ProcLaunchMon.sys" nocase
        $d1 = "\\\\.\\com_microsoft_idna_ProcLaunchMon" wide

        // Strings for PED.sys, which is a renamed Process Explorer driver
        $f2 = "PED.sys" nocase
        $d2 = "\\\\.\\PROCEXP152" wide

        // Characteristic strings from the legitimate Process Explorer driver to identify it even when renamed
        $pe1 = "Process Explorer" wide
        $pe2 = "Mark Russinovich" wide
        $pe3 = "www.sysinternals.com" ascii

    condition:
        // The file must be a PE driver
        uint16(0) == 0x5a4d and pe.is_driver() and
        (
            // Detects the ProcLaunchMon driver
            ($f1 and $d1)
            or
            // Detects the Process Explorer driver when named PED.sys or using the specific device handle.
            // This helps reduce false positives, as Process Explorer is a legitimate tool.
            // The combination of identifying the driver's origin and its malicious filename/handle is a strong indicator.
            (2 of ($pe*)) and ($f2 or $d2)
        )
}
