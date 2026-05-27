import "elf"

rule TOOL_Linux_Medusa_Rootkit_FireAnt
{
    meta:
        description = "Detects the Medusa rootkit, a tool used by the Fire Ant threat actor (UNC3886) for persistence on Linux hosts. The rootkit uses LD_PRELOAD to hijack functions, hide its presence, and log SSH credentials to a file named 'remote.txt'."
        author = "Rob Weber"
        date = "2025-07-25"
        version = 1
        reference = "https://www.sygnia.co/blog/fire-ant-a-deep-dive-into-hypervisor-level-espionage/, https://github.com/ldpreload/Medusa/tree/main"
        tags = "FILE, ROOTKIT, LINUX, APT, FIRE_ANT, UNC3886, MEDUSA"
        mitre_attack = "T1014, T1574.006"
        malware_family = "Medusa"
        malware_type = "Rootkit"

    strings:
        // -- Key indicators from the Medusa source code --
        // The hardcoded name of the file where credentials are logged.
        $s1 = "remote.txt" ascii
        // The format string used to log stolen SSH passwords.
        $s2 = "Password for %s@%s: %s\\n" ascii
        // A magic string used to unhide files/processes.
        $s3 = "medusa_gid" ascii
        // Functions hooked by the rootkit to intercept credentials.
        $s4 = "pam_get_item" ascii
        $s5 = "pam_get_user" ascii

    condition:
        // The rule targets ELF shared objects (.so files), which is the format for LD_PRELOAD rootkits.
        uint32(0) == 0x464c457f and elf.type == elf.ET_DYN
        // Check for a reasonable file size for this type of tool.
        and filesize < 100KB
        // Require the most specific strings for high confidence.
        and $s1 and $s2
        // Require at least one of the other characteristic strings to confirm.
        and 1 of ($s3, $s4, $s5)
}
