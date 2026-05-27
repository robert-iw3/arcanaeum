import "pe"

rule SUSP_AMSI_Bypass_VEH2
{
    meta:
        description = "Detects files containing code artifacts consistent with the VEH2 AMSI bypass technique. This method uses two Vectored Exception Handlers (VEH) to set a hardware breakpoint on AmsiScanBuffer and then handle the resulting exception to bypass the scan, avoiding calls to NtSetContextThread."
        author = "RW"
        date = "2025-07-30"
        version = 1
        reference = "https://www.crowdstrike.com/en-us/blog/crowdstrike-investigates-threat-of-patchless-amsi-bypass-attacks/"
        tags = "TTP, DEFENSE_EVASION, AMSI, BYPASS, VEH2, FILE"
        mitre_attack = "T1562.001, T1055"
        malware_type = "Bypass"

    strings:
        // Key API call to register a Vectored Exception Handler
        $api_veh = "AddVectoredExceptionHandler" ascii wide

        // API call to trigger the first exception (EXCEPTION_BREAKPOINT)
        $api_dbg = "DebugBreak" ascii wide

        // Target AMSI function and library for the bypass
        $s_amsi_func = "AmsiScanBuffer" ascii
        $s_amsi_dll = "amsi.dll" nocase ascii wide

        // Hex values for the specific exceptions handled by the two VEHs
        $hex_exc_breakpoint = { 03 00 00 80 } // EXCEPTION_BREAKPOINT (0x80000003)
        $hex_exc_singlestep = { 04 00 00 80 } // EXCEPTION_SINGLE_STEP (0x80000004)

    condition:
        // Rule targets PE files under 2MB to scope the search
        pe.is_pe and filesize < 2MB and
        // Must contain the API to set up the exception handlers
        $api_veh and
        // Must contain the API to trigger the initial breakpoint exception
        $api_dbg and
        // Must reference the target AMSI function or DLL
        ( $s_amsi_func or $s_amsi_dll ) and
        // Must contain the constants for both specific exceptions used in the technique.
        // This combination is a strong indicator of the VEH2 bypass logic.
        // Potential for FPs in advanced debuggers or security research tools, but unlikely in common software.
        all of ($hex_exc_*)
}
