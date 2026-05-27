rule SUSP_JS_NodeInitRAT_MochaManakin
{
    meta:
        description = "Detects obfuscated JavaScript files characteristic of NodeInitRAT, used by the Mocha Manakin threat actor. The rule identifies specific strings related to the RAT's functionality, such as persistence, reconnaissance, and C2 communication, which are often passed as a command-line argument to node.exe."
        author = "Rob Weber"
        date = "2025-07-24"
        version = 1
        reference = "https://redcanary.com/blog/threat-intelligence/mocha-manakin-nodejs-backdoor/"
        tags = "CRIME, BACKDOOR, MOCHA_MANAKIN, NODEINITRAT, FILE"
        mitre_attack = "T1059.007, T1547.001, T1082"
        malware_family = "NodeInitRAT"

    strings:
        // Persistence-related strings
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
        // This rule targets the script file containing the RAT, not the running process.
        // It may trigger on developer or pentesting tools that contain similar command strings.
        filesize < 500KB and
        1 of ($p*) and
        1 of ($c*) and
        3 of ($r*)
}
