import "elf"

rule EXPL_Linux_CVE_2025_37752_SFQ_Qdisc_OOB_Write
{
    meta:
        description = "Detects potential exploit binaries for CVE-2025-37752, a Linux kernel vulnerability in the SFQ network packet scheduler. The rule identifies files containing strings related to the specific exploit technique, which involves manipulating SFQ and TBF qdiscs, using named pipes for memory corruption, and signalfd for page reclamation."
        author = "RW"
        date = "2025-07-31"
        version = 1
        tags = "EXPLOIT, LINUX, KERNEL, PRIVILEGE_ESCALATION, CVE_2025_37752, FILE"
        mitre_attack = "T1068, T1499.001"
        malware_family = "CVE-2025-37752 Exploit"
        malware_type = "Exploit"

    strings:
        // Core components of the vulnerability: SFQ and TBF qdiscs
        $qdisc1 = "sfq" ascii
        $qdisc2 = "tbf" ascii

        // Exploit primitives involving named pipes and signalfd
        $prim1 = "mkfifo" ascii
        $prim2 = "signalfd" ascii

        // Specific TBF netlink attributes used for stabilization
        $tbf_attr1 = "TCA_TBF_RATE64" ascii
        $tbf_attr2 = "TCA_TBF_PARMS" ascii

        // Side-channel/exploit logic artifacts mentioned in the report
        $logic1 = "FIONREAD" ascii
        $logic2 = "SIGPIPE" ascii

    condition:
        // Target ELF files under 5MB
        elf.is_elf and filesize < 5MB and
        // Requires strings for both vulnerable qdiscs
        all of ($qdisc*) and
        // Requires strings for the core exploit primitives (pipe UAF and reclamation)
        all of ($prim*) and
        // Requires at least one specific TBF attribute used for stabilization
        1 of ($tbf_attr*) and
        // Requires at least one artifact related to the detailed exploit logic to increase confidence
        // This may cause false negatives if exploit variants don't use these, but reduces false positives.
        1 of ($logic*)
}
