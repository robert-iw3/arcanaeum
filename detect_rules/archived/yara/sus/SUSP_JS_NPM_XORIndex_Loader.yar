import "pe"

rule SUSP_JS_NPM_XORIndex_Loader
{
    meta:
        description = "Detects suspicious JavaScript files characteristic of the XORIndex loader, often distributed via malicious npm packages using 'postinstall' scripts. This activity is associated with the North Korean 'Contagious Interview' campaign."
        date = "2025-07-24"
        version = "1"
        reference = "https://www.bleepingcomputer.com/news/security/north-korean-xorindex-malware-hidden-in-67-malicious-npm-packages/"
        tags = "APT, LOADER, NPM, JAVASCRIPT, FILE, CONTAGIOUS_INTERVIEW, XORINDEX"
        mitre_attack = "T1129, T1059.007, T1071.001"
        malware_family = "XORIndex"
        malware_type = "Loader"

    strings:
        // Suspicious script execution hooks often found in package.json, but can appear in JS files that parse it.
        $hook_post = "postinstall" ascii
        $hook_pre = "preinstall" ascii

        // Host information gathering functions used for victim profiling.
        $info1 = "os.hostname()" ascii
        $info2 = "os.userInfo()" ascii
        $info3 = "os.networkInterfaces()" ascii
        $info4 = "os.platform()" ascii
        $info5 = "process.env" ascii

        // Network communication for C2, including specific infrastructure noted in reporting.
        $net1 = ".request(" ascii // Catches http.request and https.request
        $net2 = "fetch(" ascii
        $net3 = ".vercel.app" ascii // C2 infrastructure used by this actor. Could be FP prone on its own.

        // Suspicious execution methods for running payloads.
        $exec1 = "eval(" ascii
        $exec2 = "child_process" ascii
        $exec3 = "execSync" ascii

        // XOR decoding routine artifact, characteristic of XORIndex.
        $xor_loop = ".charCodeAt(i) ^" ascii

    condition:
        // Target files are typically small JavaScript or JSON files.
        filesize < 500KB and
        (
            // Pattern 1: Strongest signal - XOR decoding with networking and info gathering.
            $xor_loop and 1 of ($info*) and 1 of ($net*)
        or
            // Pattern 2: Suspicious execution combined with info gathering and C2 communication.
            // The use of eval/child_process with these other elements is a high-confidence indicator.
            (1 of ($exec*)) and (2 of ($info*)) and (1 of ($net*))
        or
            // Pattern 3: A script run on installation that gathers significant info and phones home.
            // This may have a higher chance of FPs on packages with telemetry, but the combination is suspicious.
            (1 of ($hook*)) and (3 of ($info*)) and (1 of ($net*))
        )
}
