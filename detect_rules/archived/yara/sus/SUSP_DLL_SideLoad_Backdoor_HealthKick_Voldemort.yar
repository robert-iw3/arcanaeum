import "pe"

rule SUSP_DLL_SideLoad_Backdoor_HealthKick_Voldemort : FILE DLL SIDELOADING APT
{
    meta:
        description = "Detects characteristics of a malicious DLL intended for side-loading, consistent with backdoors like HealthKick and Voldemort. These were used by Chinese state-sponsored actors in campaigns targeting Taiwan's semiconductor sector. The rule looks for small DLLs with a low number of exports that also contain strings related to command execution and networking, indicative of a backdoor or reverse shell."
        date = "2025-07-27"
        version = 1
        tags = "FILE, DLL, SIDELOADING, APT, HEALTHKICK, VOLDEMORT"
        mitre_attack = "T1574.001, T1566.001, T1204.002"
        malware_family = "HealthKick, Voldemort"
        malware_type = "Backdoor"

    strings:
        // Command execution strings, as described for the HealthKick backdoor
        $cmd_exec1 = "cmd.exe" wide nocase
        $cmd_exec2 = "CreatePipe" ascii
        $cmd_exec3 = "CreateProcessA" ascii

        // Networking strings for C2 communication / reverse shell
        $net1 = "WSAStartup" ascii
        $net2 = "socket" ascii
        $net3 = "connect" ascii
        $net4 = "send" ascii
        $net5 = "recv" ascii

    condition:
        // Must be a valid PE file and specifically a DLL
        uint16(0) == 0x5A4D and pe.is_dll()
        and
        // Malicious side-loaded DLLs are often small
        filesize < 500KB
        and
        // Heuristic for side-loading: DLLs often have very few exports
        pe.number_of_exports > 0 and pe.number_of_exports < 10
        and
        // Contains functionality to execute commands
        ( $cmd_exec1 and ($cmd_exec2 or $cmd_exec3) )
        and
        // Contains basic networking capabilities for C2
        // This combination is common in simple backdoors and reverse shells
        3 of ($net*)
}
