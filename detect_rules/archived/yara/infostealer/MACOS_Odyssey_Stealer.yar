import "macho"

rule MACOS_Odyssey_Stealer
{
    meta:
        description = "Detects Odyssey Infostealer, a macOS malware known for stealing sensitive data and establishing persistence. This rule identifies specific strings related to its C2 communication, data theft, and persistence mechanisms."
        date = "2025-07-16"
        version = 1
        reference = "https://www.jamf.com/blog/signed-and-stealing-uncovering-new-insights-on-odyssey-infostealer/"
        hash = "dec750b9d596b14aeab1ed6f6d6d370022443ceceb127e7d2468b903c2d9477a"
        hash = "82b73222629ce27531f57bae6800831a169dff71849e1d7e790d9bd9eb6e9ee7"
        hash = "86d351e18a549d16d687f87ee516eefa811549fe697c137b188d5858229c7f73"
        hash = "d40652486f6d0a0cb01a1d77ebc2d1569f4beb22b60de2206ec5db41e4efb2fd"
        tags = "CRIME, INFOSTEALER, BACKDOOR, ODYSSEY, MACOS, FILE"
        mitre_attack = "T1059.002, T1543.004, T1005, T1041, T1090.002"
        malware_family = "Odyssey Stealer"
        malware_type = "Infostealer"

    strings:
        // -- Private strings for file type check --
        $_macho_magic_64 = { CF FA ED FE }
        $_applescript_shebang = "#!/usr/bin/osascript"

        // -- C2 Communication & Asset Paths --
        // These strings are found in the AppleScript payloads and define C2 API endpoints.
        $c2_path_1 = "/api/v1/bot/actions/" ascii
        $c2_path_2 = "/api/v1/bot/joinsystem/" ascii
        $c2_path_3 = "/otherassets/ledger.zip" ascii
        $c2_path_4 = "/otherassets/socks" ascii

        // -- Hidden files created in the user's home directory --
        $file_1 = "/.pwd" ascii
        $file_2 = "/.chost" ascii
        $file_3 = "/.username" ascii
        $file_4 = "/.botid" ascii
        $file_5 = "/.uninstalled" ascii

        // -- Specific AppleScript commands and dialogs --
        $as_1 = "Required Application Helper. Please enter device password to continue." wide
        $as_2 = "dscl . authonly " ascii // Note the trailing space
        $as_3 = "system_profiler SPHardwareDataType" ascii

        // -- Backdoor commands received from C2 --
        $cmd_1 = "enablesocks5" ascii
        $cmd_2 = "doshell" ascii

    condition:
        // The rule targets either Mach-O binaries or AppleScript files under 5MB.
        (
            ($_macho_magic_64 at 0) or
            ($_applescript_shebang at 0)
        ) and filesize < 5MB and
        (
            // Condition 1: Detects the main data theft script
            (2 of ($c2_path_*)) and (2 of ($file_*)) and (1 of ($as_*))
            or
            // Condition 2: Detects the backdoor script
            (1 of ($cmd_*)) and $file_4
        )
}