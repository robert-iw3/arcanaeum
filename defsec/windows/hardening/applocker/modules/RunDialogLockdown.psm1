<#
.SYNOPSIS
    Opt-in AppLocker baseline module: removes the Win+R "Run" dialog.

.DESCRIPTION
    The classic ClickFix delivery mechanism is "press Windows+R, paste this, press Enter."
    Removing the Run dialog (and the equivalent Start-menu "type a command" path) closes that
    specific delivery mechanism outright, independent of what AppLocker does once something
    executes.

    This is opt-in (not in the orchestrator's default module set) because it's a real usability
    trade-off: it also removes Run for legitimate admins/power users on the same machine, and
    there's no per-standard-user-only registry scoping without a domain GPO + security filtering.
    Use it on normal-user laptops where that trade-off is acceptable; skip it (default) on
    machines shared with admins, or where Run is genuinely needed.

    Wire it in explicitly: .\Invoke-AppLockerBaseline.ps1 -Remediate -Modules ClickFix,RunDialogLockdown
#>

function Get-RunDialogLockdownStatus {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $disabled = $false
    if (Test-Path $key) {
        $val = (Get-ItemProperty -Path $key -Name 'NoRun' -ErrorAction SilentlyContinue).NoRun
        if ($val -eq 1) { $disabled = $true }
    }
    @("Win+R Run dialog: $(if ($disabled) { 'disabled' } else { 'available (ClickFix delivery path open)' })")
}

function Invoke-RunDialogLockdownHardening {
    param([switch]$Remediate)
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    if ($Remediate) {
        if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
        Set-ItemProperty -Path $key -Name 'NoRun' -Value 1 -Type DWord
        @("Disabled the Run dialog machine-wide ($key\NoRun = 1). Affects all users on this machine, including admins.")
    } else {
        @("(dry run) Would disable the Run dialog machine-wide at $key\NoRun.")
    }
}

function Invoke-RunDialogLockdownRollback {
    param([switch]$Remediate)
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    if ($Remediate) {
        try {
            Remove-ItemProperty -Path $key -Name 'NoRun' -Force -ErrorAction Stop
            Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
            @('Restored Win+R Run dialog (removed NoRun; Explorer restarted to apply immediately).')
        } catch {
            Write-Warning "Failed to remove NoRun: $($_.Exception.Message). Requires an elevated PowerShell session."
            @("FAILED: $($_.Exception.Message)")
        }
    } else {
        $val = (Get-ItemProperty -Path $key -Name 'NoRun' -ErrorAction SilentlyContinue).NoRun
        @("(dry run) Would remove $key\NoRun (currently $(if ($null -ne $val) { $val } else { 'not set' })) and restart Explorer.")
    }
}

Export-ModuleMember -Function Get-RunDialogLockdownStatus, Invoke-RunDialogLockdownHardening, Invoke-RunDialogLockdownRollback
