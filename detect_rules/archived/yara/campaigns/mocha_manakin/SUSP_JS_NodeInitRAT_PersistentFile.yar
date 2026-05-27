rule SUSP_JS_NodeInitRAT_PersistentFile_Jul24
{
    meta:
        description = "Detects the persistent JavaScript file for NodeInitRAT, often saved with a .log extension in the AppData\\Roaming directory. This rule identifies the file based on characteristic strings related to persistence, C2, and reconnaissance."
        author = "Rob Weber"
        date = "2025-07-24"
        version = 1
        reference = "https://redcanary.com/blog/threat-intelligence/mocha-manakin-nodejs-backdoor/"
        tags = "CRIME, BACKDOOR, MOCHA_MANAKIN, NODEINITRAT, FILE"
        mitre_attack = "T1059.007, T1547.001, T1082"
        malware_family = "NodeInitRAT"

    strings:
        // Persistence-related strings from the RAT's code
        $p1 = "'ChromeUpdater'" ascii
        $p2 = "'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'" ascii
        $p3 = "'reg\\x20add'" ascii // "reg add"

        // C2-related strings
        $c1 = "'/init1234'" ascii
        $c2 = "'trycloudflare.com'" ascii

        // Reconnaissance and execution strings
        $r1 = "'child_process'" ascii
        $r2 = "'nltest'" ascii
        $r3 = "'setspn.exe'" ascii
        $r4 = "'net user %USERNAME% /domain'" ascii
        $r5 = "'sysinfo'" ascii
        $r6 = "'tasklist /svc'" ascii
        $r7 = "'rundll32.exe'" ascii

    condition:
        // This rule targets the script file containing the RAT.
        // It may trigger on developer or pentesting tools that contain similar command strings.
        filesize < 500KB and
        1 of ($p*) and
        1 of ($c*) and
        3 of ($r*)
}
