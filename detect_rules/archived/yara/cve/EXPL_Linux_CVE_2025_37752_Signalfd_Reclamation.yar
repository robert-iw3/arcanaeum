import "elf"

rule EXPL_Linux_CVE_2025_37752_Signalfd_Reclamation
{
    meta:
        description = "Detects potential exploit binaries for CVE-2025-37752 that use signalfd file reclamation for privilege escalation. This technique involves spraying signalfd file objects to reclaim a freed kernel page, enabling an arbitrary read/write primitive to overwrite process credentials."
        author = "RW"
        date = "2025-07-31"
        version = 1
        tags = "EXPLOIT, LINUX, KERNEL, PRIVILEGE_ESCALATION, CVE_2025_37752, FILE"
        mitre_attack = "T1068, T1574.002"
        malware_family = "CVE-2025-37752 Exploit"
        malware_type = "Exploit"

    strings:
        // Vulnerability context: The exploit targets an interaction between sfq and tbf qdiscs.
        $vuln_1 = "sfq" ascii
        $vuln_2 = "tbf" ascii

        // Exploit setup: The exploit uses named pipes and /proc file descriptor manipulation.
        $pipe_1 = "mkfifo" ascii
        $pipe_2 = "/proc/self/fd/" ascii

        // Reclamation/Exploitation: Specific artifacts related to the page-UAF and credential overwrite.
        $reclaim_1 = "signalfd" ascii  // Used to reclaim the freed page.
        $reclaim_2 = "FIONREAD" ascii  // Used in a side-channel to find the corrupted pipe.
        $reclaim_3 = "private_data" ascii // May appear in exploit code referencing the file struct field.
        $reclaim_4 = "f_cred" ascii // May appear in exploit code referencing the credentials struct field.

    condition:
        // Target Linux executables under 2MB.
        elf.is_elf and filesize < 2MB and

        // The combination of vulnerability context, pipe manipulation, and reclamation techniques
        // is highly specific to this exploit and minimizes false positives. While individual strings
        // may appear in legitimate tools, their co-occurrence is a strong indicator of malicious intent.
        all of ($vuln_*) and
        all of ($pipe_*) and
        1 of ($reclaim_*)
}
