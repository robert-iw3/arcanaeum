rule MAL_Ratty_RAT_JAR
{
    meta:
        description = "Detects the Ratty Remote Access Trojan (RAT) JAR file. This malware was observed in a multi-layered email campaign involving social engineering, geo-fencing, and the abuse of legitimate services like Dropbox and Ngrok."
        author = "Rob Weber"
        date = "2025-07-24"
        version = 1
        reference = "https://www.fortinet.com/blog/threat-research/multilayered-email-attack-how-a-pdf-invoice-and-geofencing-led-to-rat-malware"
        hash = "a1c2861a68b2a4d62b6fbfc7534f498cefe5f92f720466d24ae1b66ebc9f5731"
        tags = "CRIME, RAT, JAVA, RATTY, FILE"
        mitre_attack = "T1219, T1059, T1056.001, T1113, T1105"
        malware_family = "Ratty"
        malware_type = "RAT"

    strings:
        // Private string for ZIP/JAR file header check
        $_header_zip = { 50 4B 03 04 }

        // Specific package and class paths for Ratty RAT
        $pkg1 = "me/security/ratty/Ratty.class" ascii
        $pkg2 = "me/security/ratty/Main.class" ascii
        $pkg3 = "me/security/ratty/crypto" ascii

        // Other artifacts found in Ratty RAT stubs
        $str1 = "RATTY-STUB" ascii
        $str2 = "enable-keylogger" ascii
        $str3 = "enable-passwords" ascii

    condition:
        // File must be a JAR (ZIP format) and within a reasonable size
        $_header_zip at 0 and filesize < 15MB and
        // Require at least two of the specific Ratty artifacts for detection.
        // Since Ratty is open-source, legitimate tools could potentially reuse code,
        // but a combination of these strings is a strong indicator of Ratty RAT.
        2 of ($*)
}
