<#
.SYNOPSIS
    Shuts down the broadcast name-resolution and proxy-discovery protocols that Responder-style
    tools poison to harvest credentials from a compromised network.

.DESCRIPTION
    After gaining any foothold on a LAN, the classic pivot is credential harvesting via
    name-resolution poisoning: a tool like Responder answers LLMNR/NetBIOS broadcasts and WPAD
    probes, and every mistyped hostname or auto-proxy lookup from this machine hands the
    attacker an NTLM challenge/response to crack or relay. None of this is malware Defender
    would surface - it's the machine voluntarily talking to a rogue responder.

    Three cuts, all registry, all reversible:
    - LLMNR off (EnableMulticast=0 policy): mistyped names no longer broadcast to the LAN.
      DNS is unaffected.
    - NetBIOS node type = P-node (NodeType=2): the machine stops using NetBIOS *broadcasts*
      for name resolution (WINS-only, which home networks don't have). Less invasive than
      disabling NetBIOS per adapter - existing name resolution via DNS/mDNS still works, so
      typical NAS/printer access by name is unaffected. Requires reboot.
    - WPAD auto-discovery off (WpadOverride=1): the machine stops probing the network for a
      proxy config an attacker can serve. Home networks do not use WPAD; corporate laptops
      that rely on a WPAD-published proxy should skip this module.

    Deliberately NOT touched (balance - see README): mDNS. It is the discovery protocol behind
    network printers, Chromecast/AirPlay-style casting, and smart-home devices; disabling it
    breaks exactly the things a normal household uses daily, for marginal gain once LLMNR and
    NetBIOS broadcasts are already off.
#>

$script:LlmnrKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
$script:NetbtKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
$script:WpadKey  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad'

function Get-NameResolutionGuardStatus {
    $out = @()
    $llmnr = (Get-ItemProperty -Path $script:LlmnrKey -Name 'EnableMulticast' -ErrorAction SilentlyContinue).EnableMulticast
    if ($llmnr -eq 0) {
        $out += 'LLMNR: disabled by policy.'
    } else {
        $out += 'LLMNR: ENABLED - mistyped hostnames broadcast to the LAN and can be poisoned (Responder).'
    }
    $nodeType = (Get-ItemProperty -Path $script:NetbtKey -Name 'NodeType' -ErrorAction SilentlyContinue).NodeType
    if ($nodeType -eq 2) {
        $out += 'NetBIOS node type: P-node (no broadcast name resolution).'
    } else {
        $out += "NetBIOS node type: $(if ($null -ne $nodeType) { $nodeType } else { 'default (broadcast-capable)' }) - NetBIOS broadcasts can be poisoned."
    }
    $wpad = (Get-ItemProperty -Path $script:WpadKey -Name 'WpadOverride' -ErrorAction SilentlyContinue).WpadOverride
    if ($wpad -eq 1) {
        $out += 'WPAD auto-discovery: disabled.'
    } else {
        $out += 'WPAD auto-discovery: ENABLED - a rogue device can publish a malicious auto-proxy for this machine.'
    }
    $out
}

function Invoke-NameResolutionGuardHardening {
    param([switch]$Remediate)
    $out = @()
    if ($Remediate) {
        if (-not (Test-Path $script:LlmnrKey)) { New-Item -Path $script:LlmnrKey -Force | Out-Null }
        Set-ItemProperty -Path $script:LlmnrKey -Name 'EnableMulticast' -Value 0 -Type DWord
        $out += 'Disabled LLMNR (EnableMulticast=0) - mistyped hostnames no longer broadcast to the LAN.'

        if (-not (Test-Path $script:NetbtKey)) { New-Item -Path $script:NetbtKey -Force | Out-Null }
        Set-ItemProperty -Path $script:NetbtKey -Name 'NodeType' -Value 2 -Type DWord
        $out += 'Set NetBIOS node type to P-node (NodeType=2) - no NetBIOS broadcast resolution. Effective after reboot.'

        if (-not (Test-Path $script:WpadKey)) { New-Item -Path $script:WpadKey -Force | Out-Null }
        Set-ItemProperty -Path $script:WpadKey -Name 'WpadOverride' -Value 1 -Type DWord
        $out += 'Disabled WPAD proxy auto-discovery (WpadOverride=1).'
    } else {
        $out += "(dry run) Would disable LLMNR ($script:LlmnrKey\EnableMulticast=0)."
        $out += "(dry run) Would set NetBIOS to P-node ($script:NetbtKey\NodeType=2, reboot required)."
        $out += "(dry run) Would disable WPAD auto-discovery ($script:WpadKey\WpadOverride=1)."
    }
    $out
}

function Invoke-NameResolutionGuardRollback {
    param([switch]$Remediate)
    $out = @()
    $values = @(
        @{ Path = $script:LlmnrKey; Name = 'EnableMulticast'; Label = 'LLMNR policy' },
        @{ Path = $script:NetbtKey; Name = 'NodeType';        Label = 'NetBIOS node type (reboot to apply)' },
        @{ Path = $script:WpadKey;  Name = 'WpadOverride';    Label = 'WPAD auto-discovery override' }
    )
    foreach ($v in $values) {
        if ($Remediate) {
            try {
                Remove-ItemProperty -Path $v.Path -Name $v.Name -Force -ErrorAction Stop
                $out += "Removed $($v.Label) ($($v.Name))."
            } catch {
                $out += "$($v.Label) not present: nothing to undo."
            }
        } else {
            $out += "(dry run) Would remove $($v.Path)\$($v.Name)."
        }
    }
    $out
}

Export-ModuleMember -Function Get-NameResolutionGuardStatus, Invoke-NameResolutionGuardHardening, Invoke-NameResolutionGuardRollback
