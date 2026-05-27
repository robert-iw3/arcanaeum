import "pe"

rule KimJongRAT_PE_Variant : MALWARE STEALER BACKDOOR KIMJONGRAT PE LOADER ORCHESTRATOR FILE
{
    meta:
        description = "Detects components of the KimJongRAT PE variant, including the orchestrator (NetworkService.dll), loader (sys.dll/baby.dll), and stealer (dwm.dll), based on unique strings, PDB paths, and network communication artifacts."
        date = "2025-06-26"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/kimjongrat-stealer-variant-powershell/"
        hash = "85be5cc01f0e0127a26dceba76571a94335d00d490e5391ccef72e115c3301b3" // Example hash for Orchestrator (NetworkService.dll)
        tags = "MALWARE, STEALER, BACKDOOR, KIMJONGRAT, PE, LOADER, ORCHESTRATOR, FILE"
        mitre_attack = "T1027, T1071.001, T1082, T1083, T1056.001, T1056.002, T1555.003, T1555.004, T1555.005, T1036.004, T1036.005, T1497.001"
        malware_family = "KimJongRAT"
        malware_type = "Stealer, Backdoor, Loader"

    strings:
        // Orchestrator (NetworkService.dll) related indicators
        $s1 = "\\research\\Spyware\\Advanced\\Covaware" ascii wide // Highly unique PDB path
        $s2 = "----------sdfaffi3457839sfhjkaskl" ascii wide // Unique HTTP POST boundary
        $s3 = "fool" ascii wide // Exported function name
        $s4 = "NetworkService.dll" ascii wide // Internal name

        // Loader (sys.dll / baby.dll) related indicators
        $s5 = "co_sys_co" ascii wide // Mutex name
        //$s6 = "s" ascii wide // Exported function name (common, needs strong context)
        $s7 = "baby.dll" ascii wide // Internal name

        // Stealer (dwm.dll) related indicators
        $s8 = "init_engine" ascii wide // Exported function name
        $s9 = "main_engine" ascii wide // Exported function name
        $s10 = "stop_engine" ascii wide // Exported function name
        $s11 = "dwm.dll" ascii wide // Internal name
        $s12 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide // MetaMask ID
        $s13 = "egjidjbpglichdcondbcbdnbeeppgdph" ascii wide // Trust Wallet ID
        $s14 = "ibnejdfjmmkpcnlpebklmnkoeoihofec" ascii wide // TronLink ID
        $s15 = "aholpfdialjgjfhomihkjbmgjidlcdno" ascii wide // Exodus Web3 Wallet ID
        $s16 = "fhbohimaelbohpjbbldcngcnapndodjp" ascii wide // BEW lite ID
        $s17 = "mcohilncbfahbmgdjkbpemcciiolgcge" ascii wide // OKX Wallet ID
        $s18 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide // Phantom ID
        $s19 = "bhhhlbepdkbapadjdnnojkbgioiodbic" ascii wide // Solflare Wallet ID

    condition:
        pe.is_pe and filesize < 10MB and (
            // Orchestrator specific conditions: PDB path or internal name AND HTTP boundary or exported function
            ( ($s1 or $s4) and ($s2 or $s3) ) or
            // Loader specific conditions: Mutex name or internal name AND exported function
            ($s5 or $s7) or
            // Stealer specific conditions: Internal name or 2 of its exported functions AND 3 of the crypto wallet IDs
            ( ($s11 or 2 of ($s8, $s9, $s10)) and (3 of ($s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19)) )
        )
}