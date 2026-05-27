import "pe"

rule TOOL_Win_Proxy_Tunneling_T1572
{
    meta:
        description = "Detects common open-source proxy and tunneling tools like plink, ngrok, glider, and ReverseSocks5. These are often dual-use tools but are leveraged by threat actors for protocol tunneling (T1572) to bypass network segmentation, exfiltrate data, or establish C2 channels. Detection of the tool binary should be correlated with process execution and network logs to determine malicious intent."
        author = "Rob Weber"
        date = "2025-07-28"
        version = 1
        tags = "FILE, TOOL, PROXY, TUNNEL, NGROK, PLINK, GLIDER"
        mitre_attack = "T1572"
        malware_type = "Tool"

    strings:
        // -- Plink (PuTTY Link) --
        // Plink is a command-line connection utility from the PuTTY suite.
        $plink_1 = "plink: The PuTTY command-line connection tool" ascii wide
        $plink_2 = "This is Plink, a command-line connection utility" ascii wide
        $plink_3 = "FATAL ERROR: No session specified" ascii wide
        $plink_4 = "Unable to open connection:" ascii wide

        // -- Ngrok --
        // Ngrok is a popular tool for creating secure tunnels to localhost.
        $ngrok_1 = "ngrok - secure introspectable tunnels to localhost" ascii wide
        $ngrok_2 = "When using ngrok, you agree to the ngrok Terms of Service" ascii wide
        $ngrok_3 = "ngrok.com/tos" ascii wide
        $ngrok_4 = "tunnel.ngrok.com" ascii wide

        // -- Glider --
        // Glider is a forward proxy with multiple protocol support.
        $glider_1 = "glider is a forward proxy with multiple protocols support" ascii wide
        $glider_2 = "github.com/nadoo/glider" ascii wide

        // -- ReverseSocks5 --
        // ReverseSocks5 is a tool that creates a reverse SOCKS5 proxy.
        $reversesocks5_1 = "Connecting to reverse SOCKS5 server" ascii wide
        $reversesocks5_2 = "failed to dial reverse SOCKS5 server" ascii wide

    condition:
        // These tools are typically Windows PE files.
        pe.is_pe and filesize < 50MB and
        (
            // Require at least 2 strings to confirm Plink, reducing FPs.
            2 of ($plink_*) or
            // Require at least 2 strings to confirm Ngrok.
            2 of ($ngrok_*) or
            // Require both strings for Glider due to their specificity.
            all of ($glider_*) or
            // A single string is sufficient for ReverseSocks5 if specific enough.
            1 of ($reversesocks5_*)
        )
}
