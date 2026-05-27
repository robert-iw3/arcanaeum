import "elf"

rule EXPL_Linux_CVE_2025_37752_Pipe_Manipulation
{
    meta:
        description = "Detects potential exploit binaries for CVE-2025-37752 that use pipe file descriptor manipulation for privilege escalation. The rule looks for strings related to creating named pipes (mkfifo), manipulating file descriptors via /proc, and other artifacts associated with the page-UAF technique described in the exploit."
        author = "RW"
        date = "2025-07-31"
        version = 1
        tags = "EXPLOIT, LINUX, KERNEL, PRIVILEGE_ESCALATION, CVE_2025_37752, FILE"
        mitre_attack = "T1068, T1574.002"
        malware_family = "CVE-2025-37752 Exploit"
        malware_type = "Exploit"

    strings:
        // Vulnerability context: SFQ and TBF qdiscs are required for the bug trigger.
        $vuln_1 = "sfq" ascii
        $vuln_2 = "tbf" ascii

        // Exploit primitive: Creating named pipes is the first step of the UAF setup.
        $pipe_setup = "mkfifo" ascii

        // Exploit techniques for pipe object manipulation and UAF reclamation.
        $pipe_trick_1 = "/proc/self/fd/" ascii
        $pipe_trick_2 = "signalfd" ascii
        $pipe_trick_3 = "FIONREAD" ascii

    condition:
        // Target Linux executables under 2MB.
        elf.is_elf and filesize < 2MB and

        // Must contain strings for both vulnerable qdiscs.
        all of ($vuln_*) and

        // Must contain the string for setting up named pipes.
        $pipe_setup and

        // Must contain at least one string related to the specific pipe manipulation techniques.
        // This combination is highly specific to the exploit described for CVE-2025-37752.
        1 of ($pipe_trick_*)
}
