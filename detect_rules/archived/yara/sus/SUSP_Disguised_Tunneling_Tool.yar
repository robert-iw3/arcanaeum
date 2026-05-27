import "pe"

rule SUSP_Disguised_Tunneling_Tool
{
    meta:
        description = "Detects tunneling or reverse proxy tools, such as LCX or FRP, which have been observed disguised with non-executable file extensions like .jpg or .txt to evade detection. This activity was highlighted in a Trend Micro report on web shell and VPN threats."
        author = "Rob Weber"
        date = "2025-07-27"
        version = 1
        reference = "https://www.trendmicro.com/en_us/research/24/j/understanding-the-initial-stages-of-web-shell-and-vpn-threats-an.html"
        tags = "CRIME, TUNNEL, PROXY, DEFENSE_EVASION, FILE"
        mitre_attack = "T1572, T1036.003, T1041"
        malware_type = "Tunnel"

    strings:
        // LCX (HTran) specific strings - a common port forwarding/tunneling tool
        $lcx_1 = "[Usage]: lcx -<listen|tran|slave>" ascii wide
        $lcx_2 = "Can't connect to %s:%d" ascii wide
        $lcx_3 = "Listen port %d error!" ascii wide

        // FRP (Fast Reverse Proxy) specific strings
        $frp_1 = "login to frps success" ascii wide
        $frp_2 = "start proxy success" ascii wide
        $frp_3 = "frpc.ini" ascii wide nocase

    condition:
        // This rule detects the tool's content. The file extension (.jpg, .txt) should be correlated by the analyst.
        // Condition: Must be a PE file under 2MB and contain at least two characteristic strings of either LCX or FRP.
        pe.is_pe
        and filesize < 2MB
        and (
            2 of ($lcx_*) or
            2 of ($frp_*)
        )
}
