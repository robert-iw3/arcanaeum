
import "pe"

rule APT_CurlyCOMrades_CurlCat_v1
{
    meta:
        description = "Detects CurlCat, a custom tool used by the Curly COMrades group. This tool functions similarly to netcat, using libcurl to transfer data over HTTPS to a C2 server. It employs a custom Base64 substitution cipher for encoding/decoding traffic."
        author = "RW"
        date = "2025-08-15"
        version = 1
        reference = "https://businessinsights.bitdefender.com/curly-comrades-new-threat-actor-targeting-geopolitical-hotbeds"
        hash = "b55e8e1d84d03ffe885e63a53a9acc7d"
        hash = "dd253f7403644cfa09d8e42a7120180d"
        tags = "APT, CURLY_COMRADES, CURLCAT, FILE"
        mitre_attack = "T1090, T1071.001"
        malware_family = "CurlCat"
        malware_type = "Proxy Tool"

    strings:
        // Unique 128-character string used to build a custom Base64 substitution map
        $s1 = "H2IWw5/AOhBJ6zQmxreqlVFYgfckCEnbABCDEFGHIJKLMNOPQRSTUVWXYZabcdefKDPL8t0N9T3UMRo1XajZ7Gp+ydvSisu4ghijklmnopqrstuvwxyz0123456789+/" ascii

        // Hardcoded HTTP headers found in the tool
        $s2 = "Content-type: application/octet-stream" ascii wide
        $s3 = "Cookie: PHPSESSID=" ascii wide
        $s4 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" ascii

        // Functions used for I/O redirection
        $f1 = "PeekNamedPipe" ascii
        $f2 = "WriteFile" ascii
        $f3 = "ReadFile" ascii

    condition:
        // Must be a PE file under 2MB
        pe.is_pe and filesize < 2MB
        // The custom substitution map is the primary high-confidence indicator
        and $s1
        // Require at least two other supporting strings to reduce potential FPs
        and 2 of ($s*)
}
