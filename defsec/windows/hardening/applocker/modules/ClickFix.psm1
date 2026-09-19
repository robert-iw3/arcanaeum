<#
.SYNOPSIS
    AppLocker baseline module targeting ClickFix-style scams.

.DESCRIPTION
    "ClickFix" is the umbrella name for the fake CAPTCHA / fake browser error / fake driver-update
    lure that tells a normal, non-technical user to press Win+R (or open a terminal) and paste a
    "fix" command. The pasted command is attacker-controlled and almost always chains into the
    Windows Script Host engines or mshta.exe to download and run the real payload, because those
    binaries are signed Microsoft system components that AppLocker's default allow rules (anything
    under %WINDIR%) let run without a second thought.

    AppLocker can't see *what was pasted* into Run/PowerShell (it only ever sees "powershell.exe
    started" or "wscript.exe started", not the malicious command line), so it can't catch the lure
    itself. What it CAN do is take away the most common next hop the lure relies on:

        - wscript.exe / cscript.exe (Windows Script Host) - runs the .vbs/.js dropped or
          downloaded by the pasted command.
        - mshta.exe - runs attacker HTA/JavaScript directly, a long-standing favorite for this
          exact "paste this to fix it" pattern.

    Denying these for Everyone removes a working payload path for the overwhelming majority of
    ClickFix variants seen in the wild, while almost never affecting a normal user's day-to-day
    work (legitimate consumer software essentially never depends on wscript/cscript/mshta).

    Disabling the Windows Script Host engine at the registry level is added as defense-in-depth:
    it stops the same .vbs/.js payload even on a box where AppLocker enforcement is off, not yet
    deployed, or misconfigured.

.NOTES
    Does NOT attempt to restrict powershell.exe itself - that's covered by the base policy's
    Script rule collection enforcement, which (once Enabled) puts unprivileged interactive
    PowerShell sessions into Constrained Language Mode, removing most of what a paste-and-run
    one-liner needs (Add-Type, COM objects, arbitrary .NET method calls). See Get-ClickFixStatus.
#>

function Get-ClickFixStatus {
    $results = @()

    $wshKey = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'
    $wshEnabled = $true
    if (Test-Path $wshKey) {
        $val = (Get-ItemProperty -Path $wshKey -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
        if ($null -ne $val) { $wshEnabled = [bool]$val }
    }
    $results += "Windows Script Host: $(if ($wshEnabled) { 'ENABLED (wscript/cscript can still run .vbs/.js)' } else { 'disabled' })"

    try {
        $exeCollection = (Get-AppLockerPolicy -Local).RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Exe' }
        $exeRules = @($exeCollection)
        $denyNames = @($exeRules | Where-Object { $_.Action -eq 'Deny' } | Select-Object -ExpandProperty Name)
        $covered = @('wscript.exe', 'cscript.exe', 'mshta.exe') | Where-Object {
            $bin = $_
            $denyNames | Where-Object { $_ -match [regex]::Escape($bin) }
        }
        $results += "AppLocker Exe deny rules present for: $(if ($covered) { $covered -join ', ' } else { '(none yet - run -Remediate)' })"
    } catch {
        $results += "AppLocker Exe rule collection not readable yet."
    }

    $results
}

function Get-ClickFixPolicyFragment {
    $binaries = @(
        @{ File = 'wscript.exe'; Label = 'Windows Script Host (wscript.exe)' },
        @{ File = 'cscript.exe'; Label = 'Windows Script Host (cscript.exe)' },
        @{ File = 'mshta.exe';   Label = 'HTML Application Host (mshta.exe)' }
    )
    $dirs = @('%SYSTEM32%', '%WINDIR%\SysWOW64')

    foreach ($bin in $binaries) {
        foreach ($dir in $dirs) {
            $path = "$dir\$($bin.File)"
            $id = [guid]::NewGuid().ToString()
            [PSCustomObject]@{
                CollectionType = 'Exe'
                Name           = "Deny $($bin.Label) at $dir (ClickFix scam mitigation)"
                Xml            = @"
<FilePathRule Id="$id" Name="Deny $($bin.Label) at $dir (ClickFix scam mitigation)" Description="Blocks the script-host engine commonly chained into by ClickFix-style fake CAPTCHA/fix-it social engineering scams. See modules/ClickFix.psm1." UserOrGroupSid="S-1-1-0" Action="Deny">
    <Conditions>
        <FilePathCondition Path="$path" />
    </Conditions>
</FilePathRule>
"@
            }
        }
    }
}

function Invoke-ClickFixHardening {
    param([switch]$Remediate)
    $results = @()

    $wshKey = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'
    if ($Remediate) {
        if (-not (Test-Path $wshKey)) { New-Item -Path $wshKey -Force | Out-Null }
        Set-ItemProperty -Path $wshKey -Name 'Enabled' -Value 0 -Type DWord
        $results += "Disabled Windows Script Host (HKLM\...\Windows Script Host\Settings\Enabled = 0)."
    } else {
        $results += "(dry run) Would disable Windows Script Host at $wshKey."
    }

    $results
}

function Invoke-ClickFixRollback {
    param([switch]$Remediate)
    $wshKey = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'
    if ($Remediate) {
        try {
            if (Test-Path $wshKey) {
                Remove-ItemProperty -Path $wshKey -Name 'Enabled' -Force -ErrorAction Stop
            }
            @('Re-enabled Windows Script Host (removed the Enabled=0 registry restriction).')
        } catch {
            Write-Warning "Failed to remove WSH restriction: $($_.Exception.Message). Requires an elevated PowerShell session."
            @("FAILED: $($_.Exception.Message)")
        }
    } else {
        @("(dry run) Would remove the Windows Script Host Enabled restriction at $wshKey.")
    }
}

Export-ModuleMember -Function Get-ClickFixStatus, Get-ClickFixPolicyFragment, Invoke-ClickFixHardening, Invoke-ClickFixRollback
