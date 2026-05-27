import "pe"

rule TOOL_Win_EDRSilencer
{
    meta:
        description = "Detects EDRSilencer, a tool used to disable or tamper with EDR security solutions by manipulating Windows Filtering Platform (WFP) filters. It looks for specific strings related to its functionality and command-line usage."
        author = "Rob Weber"
        date = "2025-07-27"
        version = 1
        hash = "721af117726af1385c08cc6f49a801f3cf3f057d9fd26fcec2749455567888e7"
        tags = "FILE, DEFENSE_EVASION, EDRSILENCER"
        mitre_attack = "T1562.001"
        malware_family = "EDRSilencer"
        malware_type = "Defense Evasion"

    strings:
        // PDB path is a high-confidence indicator
        $pdb = "EDRSilencer.pdb" nocase

        // Unique command-line arguments used by the tool
        $cmd1 = "blockedr" ascii wide
        $cmd2 = "unblockall" ascii wide

        // Output messages related to WFP filter manipulation
        $msg1 = "All filters have been removed." wide
        $msg2 = "Filter with ID" wide
        $msg3 = "has been added." wide
        $msg4 = "has been removed." wide

        // Generic command-line arguments, used to increase confidence
        $generic_cmd1 = "block" ascii wide
        $generic_cmd2 = "unblock" ascii wide

    condition:
        // Rule requires a PE file under 1MB
        uint16(0) == 0x5a4d and filesize < 1MB and
        (
            // High-confidence match on the PDB string
            $pdb or
            // Combination of unique commands and output messages
            (all of ($cmd*) and 2 of ($msg*)) or
            // Combination of generic commands and more specific messages
            (all of ($generic_cmd*) and all of ($msg*))
        )
}
