rule SUSP_PS_Download_Cradle_MochaManakin
{
    meta:
        description = "Detects PowerShell download cradles that use Invoke-RestMethod (or irm) and Invoke-Expression (or iex) to download and execute content from a hardcoded IP address. This technique is used by adversaries like Mocha Manakin."
        author = "Rob Weber"
        date = "2025-07-24"
        version = 1
        reference = "https://redcanary.com/blog/threat-intelligence/mocha-manakin-nodejs-backdoor/"
        tags = "CRIME, LOADER, MOCHA_MANAKIN, FILE"
        mitre_attack = "T1059.001, T1105"
        malware_family = "Mocha Manakin"

    strings:
        // Detects Invoke-RestMethod or its alias 'irm'
        $cmd_irm = /\b(Invoke-RestMethod|irm)\b/ nocase

        // Detects Invoke-Expression or its alias 'iex'
        $cmd_iex = /\b(Invoke-Expression|iex)\b/ nocase

        // Detects an IPv4 address.
        // This is a key component, as legitimate tools often use FQDNs.
        $re_ipv4 = /\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/

    condition:
        // This rule may generate false positives on legitimate administrative scripts
        // (e.g., Chocolatey, Chef) that might use a similar pattern.
        // Consider adding exclusions for known-good scripts or sources.
        filesize < 500KB and all of them
}
