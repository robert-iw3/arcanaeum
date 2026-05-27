rule XWorm_PE {
    meta:
        sha256 = "18dc423099be030506353e6b26762f2c789f22e79991192f4fae3e290afacc07"
        description = "YARA rule that detects XWorm malware based on common indicators like PowerShell usage and embedded Mozilla-style User-Agent strings."
        reference = "[https://cofense.com/blog/the-rise-of-xworm-rat-what-cybersecurity-teams-need-to-know-now]"
strings:
        $powershell_1 = {70 00 6F 00 77 00 65 00 72 00 73 00 68 00 65 00 6C 00 6C 00 2E 00 65 00 78 00 65 00}
        $powershell_2 = {45 00 78 00 65 00 63 00 75 00 74 00 69 00 6F 00 6E 00 50 00 6F 00 6C 00 69 00 63 00 79 00}


        $UserAgent_1 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0" ascii wide
        $UserAgent_2 = "Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1" ascii wide
        $UserAgent_3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36" ascii wide

        $batchScript_1 = "@echo off" ascii wide
        $batchScript_2 = "timeout 3 > NUL" ascii wide
        $batchScript_3 = "DEL \"" ascii wide
        $batchScript_4 = "\" /f /q" ascii wide




    condition:
        uint16(0) == 0x5A4D and 2 of ($UserAgent_*) and all of ($powershell_*) and all of ($batchScript_*)
}