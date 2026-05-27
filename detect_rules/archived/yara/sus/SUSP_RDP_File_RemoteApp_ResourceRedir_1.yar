rule SUSP_RDP_File_RemoteApp_ResourceRedir_1 : RDP PHISHING ESPIONAGE FILE UNC5837
{
    meta:
        description = "Detects RDP configuration files (.rdp) that enable malicious RemoteApp features and extensive resource redirection, commonly abused in 'Rogue RDP' campaigns for espionage and data exfiltration."
        date = "2025-07-03"
        version = 1
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/windows-rogue-remote-desktop-protocol"
        tags = "RDP, PHISHING, ESPIONAGE, FILE, UNC5837"
        mitre_attack = "T1566.001, T1021.001, T1074.001"
        malware_family = "UNC5837"

    strings:
        $rdp_param1 = "remoteapplicationmode:i:1" wide
        $rdp_param2 = "drivestoredirect:s:" wide
        $rdp_param3 = "remoteapplicationprogram:s:" wide
        $rdp_param4 = "remoteapplicationname:s:" wide
        $rdp_param5 = "redirectclipboard:i:1" wide

    condition:
        filesize < 20KB and (3 of ($rdp_param*))
}