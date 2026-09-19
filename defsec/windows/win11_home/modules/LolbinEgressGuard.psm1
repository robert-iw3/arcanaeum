<#
.SYNOPSIS
    Windows Firewall outbound-block rules for the living-off-the-land binaries attackers use as
    download cradles and C2 callbacks - containment that still works when Defender is blind.

.DESCRIPTION
    Once an initial payload lands, the standard LOTL pattern is to use a signed, inbox Microsoft
    binary to fetch the next stage or beacon out: `mshta https://...`, `certutil -urlcache -f`,
    `bitsadmin /transfer`, `regsvr32 /i:https://... scrobj.dll`, WSH downloaders. Because the
    binary is Microsoft-signed and the technique is fileless, Defender frequently does NOT
    surface it, and user-mode ETW/AMSI patching can silence what detection there is.

    This module cuts the chain at a layer user-mode tampering cannot reach: Windows Filtering
    Platform rules (Windows Firewall) enforced in the kernel. Each listed binary gets an
    outbound-deny rule, so even a successfully launched cradle cannot reach the internet to pull
    a payload or call home. The binaries still run locally - nothing about offline/legitimate
    use changes, and none of them are network tools for a normal user:

        mshta.exe, wscript.exe, cscript.exe  - script/HTA engines (no legitimate egress)
        certutil.exe, certreq.exe            - certificate tools abused as HTTP downloaders
        bitsadmin.exe                        - deprecated BITS CLI (the BITS service itself,
                                               which Windows Update uses, is NOT affected)
        regsvr32.exe                         - the Squiblydoo remote-scriptlet vector

    Deliberately NOT blocked by default (balance - see README):
        powershell.exe / pwsh.exe - breaks winget source updates, Windows remediation scripts,
                                    and every admin's day. Pair with STIG script-block logging.
        curl.exe                  - a real tool for developers and support workflows. Pass
                                    -IncludeCurl on a direct module call to block it too.

    Rules are created in a dedicated group so rollback is a single group delete.
#>

$script:RuleGroup = 'Win11 Home Baseline - LOLBin Egress'

$script:DefaultBinaries = @(
    'mshta.exe', 'wscript.exe', 'cscript.exe',
    'certutil.exe', 'certreq.exe', 'bitsadmin.exe', 'regsvr32.exe'
)

function Get-LolbinEgressTarget {
    <#
    .SYNOPSIS
        Expands binary names to the full System32/SysWOW64 paths that exist on this machine.
    #>
    param(
        [string[]]$Binaries = $script:DefaultBinaries
    )
    $targets = @()
    foreach ($bin in $Binaries) {
        foreach ($dir in @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64")) {
            $path = Join-Path $dir $bin
            if (Test-Path -LiteralPath $path) {
                $targets += [pscustomobject]@{
                    Binary      = $bin
                    Path        = $path
                    DisplayName = "Block outbound - $bin ($(Split-Path $dir -Leaf))"
                }
            }
        }
    }
    $targets
}

function Get-LolbinEgressGuardStatus {
    $rules = @(Get-NetFirewallRule -Group $script:RuleGroup -ErrorAction SilentlyContinue)
    $targets = @(Get-LolbinEgressTarget)
    if ($rules.Count -eq 0) {
        @("No LOLBin egress rules present ($($targets.Count) download-cradle binaries currently have unrestricted outbound network access).")
    } else {
        @("$($rules.Count) outbound-block rule(s) active in group '$script:RuleGroup' (expected $($targets.Count)).")
    }
}

function Invoke-LolbinEgressGuardHardening {
    param(
        [switch]$Remediate,
        [switch]$IncludeCurl
    )
    $binaries = $script:DefaultBinaries
    if ($IncludeCurl) { $binaries = $binaries + 'curl.exe' }
    $targets = @(Get-LolbinEgressTarget -Binaries $binaries)

    if (-not $Remediate) {
        return @("(dry run) Would create $($targets.Count) outbound-block firewall rules (group '$script:RuleGroup') for: $(($targets | ForEach-Object { $_.Path }) -join ', ')")
    }

    $out = @()
    $existing = @(Get-NetFirewallRule -Group $script:RuleGroup -ErrorAction SilentlyContinue | ForEach-Object { $_.DisplayName })
    foreach ($t in $targets) {
        if ($t.DisplayName -in $existing) {
            $out += "Already present: $($t.DisplayName)"
            continue
        }
        New-NetFirewallRule -DisplayName $t.DisplayName -Group $script:RuleGroup `
            -Direction Outbound -Action Block -Program $t.Path -Profile Any -Enabled True | Out-Null
        $out += "Created: $($t.DisplayName) -> $($t.Path)"
    }
    $out += "LOLBin download cradles can no longer reach the network (kernel-level WFP block, unaffected by user-mode ETW/AMSI tampering)."
    $out
}

function Invoke-LolbinEgressGuardRollback {
    param([switch]$Remediate)
    if ($Remediate) {
        $rules = @(Get-NetFirewallRule -Group $script:RuleGroup -ErrorAction SilentlyContinue)
        if ($rules.Count -eq 0) {
            return @('No LOLBin egress rules found: nothing to undo.')
        }
        Remove-NetFirewallRule -Group $script:RuleGroup
        @("Removed $($rules.Count) outbound-block rule(s) in group '$script:RuleGroup'.")
    } else {
        $rules = @(Get-NetFirewallRule -Group $script:RuleGroup -ErrorAction SilentlyContinue)
        @("(dry run) Would remove $($rules.Count) firewall rule(s) in group '$script:RuleGroup'.")
    }
}

Export-ModuleMember -Function Get-LolbinEgressGuardStatus, Invoke-LolbinEgressGuardHardening, Invoke-LolbinEgressGuardRollback, Get-LolbinEgressTarget
