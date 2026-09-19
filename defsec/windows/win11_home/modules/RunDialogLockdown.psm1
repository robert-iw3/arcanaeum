<#
.SYNOPSIS
    Opt-in: removes the Win+R "Run" dialog - the classic ClickFix delivery path.

.DESCRIPTION
    Ported from the applocker baseline. The classic ClickFix delivery mechanism is "press
    Windows+R, paste this, press Enter." Removing the Run dialog closes that specific path
    outright.

    Opt-in (not default) because it's a real usability trade-off: it removes Run for everyone on
    the machine, including admins/power users, and there's no per-standard-user scoping without a
    domain GPO. Use it on normal-user machines where that's acceptable; skip it on machines an
    admin drives daily. Note the containment layer already blunts the ClickFix payload itself:
    even with Run available, ScriptHostGuard stops the pasted .vbs/.js and LolbinEgressGuard
    stops the pasted mshta/certutil cradle from reaching the network.
#>

$script:Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'

function Get-RunDialogLockdownStatus {
    $val = (Get-ItemProperty -Path $script:Key -Name 'NoRun' -ErrorAction SilentlyContinue).NoRun
    @("Win+R Run dialog: $(if ($val -eq 1) { 'disabled' } else { 'available (ClickFix paste path open)' })")
}

function Invoke-RunDialogLockdownHardening {
    param([switch]$Remediate)
    if ($Remediate) {
        if (-not (Test-Path $script:Key)) { New-Item -Path $script:Key -Force | Out-Null }
        Set-ItemProperty -Path $script:Key -Name 'NoRun' -Value 1 -Type DWord
        @("Disabled the Run dialog machine-wide ($script:Key\NoRun=1). Affects all users, including admins.")
    } else {
        @("(dry run) Would disable the Run dialog machine-wide at $script:Key\NoRun.")
    }
}

function Invoke-RunDialogLockdownRollback {
    param([switch]$Remediate)
    if ($Remediate) {
        try {
            Remove-ItemProperty -Path $script:Key -Name 'NoRun' -Force -ErrorAction Stop
            Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
            @('Restored Win+R Run dialog (removed NoRun; Explorer restarted to apply immediately).')
        } catch {
            @("NoRun not present: nothing to undo.")
        }
    } else {
        $val = (Get-ItemProperty -Path $script:Key -Name 'NoRun' -ErrorAction SilentlyContinue).NoRun
        @("(dry run) Would remove $script:Key\NoRun (currently $(if ($null -ne $val) { $val } else { 'not set' })) and restart Explorer.")
    }
}

Export-ModuleMember -Function Get-RunDialogLockdownStatus, Invoke-RunDialogLockdownHardening, Invoke-RunDialogLockdownRollback
