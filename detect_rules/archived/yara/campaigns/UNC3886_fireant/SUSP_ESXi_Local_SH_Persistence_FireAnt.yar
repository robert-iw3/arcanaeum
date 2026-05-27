rule SUSP_ESXi_Local_SH_Persistence_FireAnt
{
    meta:
        description = "Detects modifications to the ESXi startup script '/etc/rc.local.d/local.sh' consistent with persistence techniques used by the Fire Ant threat actor (UNC3886). The rule looks for the execution of suspicious scripts, particularly Python scripts located in the '/bootbank/' directory, which is a known TTP for this actor."
        author = "Rob Weber"
        date = "2025-07-25"
        version = 1
        reference = "https://www.sygnia.co/blog/fire-ant-a-deep-dive-into-hypervisor-level-espionage/"
        tags = "FILE, PERSISTENCE, APT, FIRE_ANT, UNC3886, VMWARE, ESXI, SHELL"
        mitre_attack = "T1547.006"
        malware_family = "Fire Ant"

    strings:
        // -- Private strings to identify the target file --
        // Standard shebang for the local.sh script
        $_shebang = "#!/bin/sh" ascii
        // Standard warning header in the local.sh script
        $_warning = "Note: modify at your own risk!" ascii

        // -- Public detection strings based on Fire Ant TTPs --
        // Command used to execute the backdoor
        $s_python = "python" ascii nocase
        // Suspicious path for custom scripts on ESXi, used by the actor
        $s_bootbank = "/bootbank/" ascii
        // The actor used .bin to masquerade the python script
        $s_bin_ext = ".bin" ascii
        // Command to run the process in a new session, detaching it from the terminal
        $s_setsid = "setsid" ascii

    condition:
        // 1. Check if the file is likely local.sh by looking for the shebang or standard VMware warning at the beginning.
        // 2. Ensure the file size is small, which is typical for startup scripts.
        // 3. Detect the core TTP: executing a python script from the /bootbank directory.
        //    The presence of ".bin" or "setsid" increases confidence but is not required, to keep the rule from being too brittle.
        (
            $_shebang at 0 or $_warning at 0
        )
        and filesize < 15KB
        and $s_python
        and $s_bootbank
        and (1 of ($s_bin_ext, $s_setsid))
}
