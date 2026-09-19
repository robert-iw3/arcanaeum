<#
.SYNOPSIS
    Opt-in: points system DNS at a malware-filtering resolver (Quad9 by default) with encrypted
    DNS, so connections to known phishing / malware / C2 domains fail at the network layer -
    before the browser or a LOLBin ever reaches them.

.DESCRIPTION
    Every other control here is host-based. A filtering resolver adds a network-layer net that
    catches things the host didn't anticipate and that works even after a click: the domain in
    the phishing link, the C2 callback, the malware-hosting CDN simply don't resolve. For a
    non-technical user this is high leverage - it blocks the destination without them having to
    make any decision.

    - Sets DNS on the active physical interfaces to the chosen filtering provider.
    - Adds DNS-over-HTTPS templates so the lookups are encrypted and can't be trivially
      poisoned/stripped on the LAN (pairs with NameResolutionGuard).

    Providers (Provider option): Quad9 (9.9.9.9 - malware-blocking, privacy-respecting; default),
    Cloudflare (1.1.1.2 - malware-blocking family resolver).

    OPT-IN because it's a real network change: captive-portal Wi-Fi (hotels/airports) and some
    ISP/enterprise networks misbehave with a pinned resolver, and it overrides DNS the user's
    router may hand out. Rollback resets the interfaces back to automatic (DHCP) DNS.

    Requires the DnsClient module cmdlets (present on Windows 11).
#>

$script:Providers = @{
    Quad9      = @{ V4 = @('9.9.9.9', '149.112.112.112'); DohTemplate = 'https://dns.quad9.net/dns-query' }
    Cloudflare = @{ V4 = @('1.1.1.2', '1.0.0.2');         DohTemplate = 'https://security.cloudflare-dns.com/dns-query' }
}

function Get-DnsFilterGuardTargetInterface {
    # Active, non-virtual/loopback IPv4 interfaces we should manage.
    Get-DnsClient -ErrorAction SilentlyContinue | ForEach-Object {
        $if = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
        if ($if -and $if.Status -eq 'Up' -and $if.Virtual -eq $false) { $_ }
    }
}

function Get-DnsFilterGuardStatus {
    $out = @()
    $ifaces = @(Get-DnsFilterGuardTargetInterface)
    if ($ifaces.Count -eq 0) { return @('No active physical network interfaces found.') }
    foreach ($i in $ifaces) {
        $servers = (Get-DnsClientServerAddress -InterfaceIndex $i.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
        $out += "$($i.InterfaceAlias): DNS = $(if ($servers) { $servers -join ', ' } else { 'automatic (DHCP)' })."
    }
    $out
}

function Invoke-DnsFilterGuardHardening {
    param(
        [switch]$Remediate,
        [ValidateSet('Quad9', 'Cloudflare')] [string]$Provider = 'Quad9'
    )
    $p = $script:Providers[$Provider]
    $ifaces = @(Get-DnsFilterGuardTargetInterface)
    if (-not $Remediate) {
        return @("(dry run) Would set DNS on $($ifaces.Count) active interface(s) to $Provider ($($p.V4 -join ', ')) and add its DNS-over-HTTPS template.")
    }
    $out = @()
    # Register the DoH template so Windows will use encrypted DNS for these server IPs. Best-effort:
    # netsh may be restricted by policy on some machines - if so, DNS filtering still applies, just
    # not encrypted, so we note it and continue rather than failing the whole module.
    try {
        foreach ($ip in $p.V4) {
            & netsh.exe dns add encryption server=$ip dohtemplate=$($p.DohTemplate) autoupgrade=yes udpfallback=no 2>&1 | Out-Null
        }
    } catch {
        $out += "Note: could not register DNS-over-HTTPS templates ($($_.Exception.Message)). Filtering DNS still applies, unencrypted."
    }
    foreach ($i in $ifaces) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $i.InterfaceIndex -ServerAddresses $p.V4 -ErrorAction Stop
            $out += "$($i.InterfaceAlias): DNS set to $Provider ($($p.V4 -join ', ')), encrypted where supported."
        } catch {
            $out += "$($i.InterfaceAlias): could not set DNS - $($_.Exception.Message)"
        }
    }
    $out += "If Wi-Fi captive portals (hotels/airports) stop working, roll back this module for that trip."
    $out
}

function Invoke-DnsFilterGuardRollback {
    param([switch]$Remediate)
    $ifaces = @(Get-DnsFilterGuardTargetInterface)
    if ($Remediate) {
        $out = @()
        foreach ($i in $ifaces) {
            try {
                Set-DnsClientServerAddress -InterfaceIndex $i.InterfaceIndex -ResetServerAddresses -ErrorAction Stop
                $out += "$($i.InterfaceAlias): DNS reset to automatic (DHCP)."
            } catch {
                $out += "$($i.InterfaceAlias): could not reset DNS - $($_.Exception.Message)"
            }
        }
        try {
            foreach ($prov in $script:Providers.Values) {
                foreach ($ip in $prov.V4) { & netsh.exe dns delete encryption server=$ip 2>&1 | Out-Null }
            }
        } catch { $out += "Note: could not remove DoH templates ($($_.Exception.Message))." }
        if ($out.Count -eq 0) { $out += 'No active interfaces to reset.' }
        $out
    } else {
        @("(dry run) Would reset DNS to automatic (DHCP) on $($ifaces.Count) interface(s) and remove the DoH templates.")
    }
}

Export-ModuleMember -Function Get-DnsFilterGuardStatus, Invoke-DnsFilterGuardHardening, Invoke-DnsFilterGuardRollback, Get-DnsFilterGuardTargetInterface
