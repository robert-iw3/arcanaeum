rule Dropping_Elephant_RAT {
    meta:
        description = "Rule for detecting Dropping Elephant RAT"
        last_modified = "2025-07-16"
        version = "1.0"
        sha256 = "8b6acc087e403b913254dd7d99f09136dc54fa45cf3029a8566151120d34d1c2"
    strings:
        $a1 = "%s=33up$!!$%s$!!$%s" ascii wide
        $a2 = "%s=uep$@$%s$@$%s" ascii wide
        $a3 = "%s=%s$!!$%s" ascii wide
        $a4 = "%s=%s$!!$%s$!!$%s" ascii wide
        $a5 = "%s=%s!$$$!%s" ascii wide
        $a6 = "%s=%s!@!%s!@!%lu" ascii wide
        $a7 = "%s=%s!$$$!%s!$$$!%s" ascii wide
        $a8 = "%s=error@$$@%s@$$@%s" ascii wide
        $a9 = "%s=%s$!!$%s$!!$%s$!!$%s$!!$%s$!!$%s$!!$" ascii wide
    condition:
        (uint16(0) == 0x5A4D) and (filesize < 1MB) and (all of ($a*))
}