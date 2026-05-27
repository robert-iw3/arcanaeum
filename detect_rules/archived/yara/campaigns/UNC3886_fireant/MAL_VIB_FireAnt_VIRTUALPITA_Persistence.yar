rule MAL_VIB_FireAnt_VIRTUALPITA_Persistence {
    meta:
        description = "Detects malicious VMware vSphere Installation Bundles (VIBs) used by threat actors like Fire Ant (UNC3886). This rule identifies VIB descriptor XML files that are configured for persistence, such as by dropping files into startup directories like '/etc/rc.local.d/' and setting a 'partner' acceptance level to facilitate forced installation."
        author = "Rob Weber"
        date = "2025-07-25"
        version = 1
        reference = "https://www.sygnia.co/blog/fire-ant-a-deep-dive-into-hypervisor-level-espionage/"
        tags = "FILE, MALWARE, PERSISTENCE, APT, FIRE_ANT, UNC3886, VMWARE, ESXI, VIRTUALPITA"
        mitre_attack = "T1543.003"
        malware_family = "VIRTUALPITA"
        malware_type = "Backdoor"

    strings:
        // -- Private Strings --
        // This rule targets the XML descriptor file within a VIB package.
        $_xml_header = "<?xml" ascii

        // -- Public Detection Strings --
        // Threat actor sets acceptance level to 'partner' to bypass signature validation with --force flag.
        $s_level = "<acceptance-level>partner</acceptance-level>" ascii

        // Persistence is achieved by dropping files into the rc.local.d directory for execution at startup.
        $s_persist = "/etc/rc.local.d/" ascii

        // Malicious VIBs are often marked as non-removable to hinder cleanup efforts.
        $s_no_remove = "<live-remove-allowed>false</live-remove-allowed>" ascii

    condition:
        // Check if the file is a small XML, likely a VIB descriptor.
        $_xml_header at 0
        and filesize < 20KB
        // Condition requires the 'partner' acceptance level, a key part of the TTP.
        and $s_level
        // To reduce false positives, it must also contain a known persistence method or be marked as non-removable.
        and (
            $s_persist or $s_no_remove
        )
}
