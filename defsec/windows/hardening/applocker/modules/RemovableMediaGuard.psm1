<#
.SYNOPSIS
    Disables AutoRun/AutoPlay for all drive types - the "found a USB drive in the parking lot"
    attack vector.

.DESCRIPTION
    Modern Windows already disables true execute-on-insert AutoRun for non-optical removable
    media by default, but AutoPlay still prompts the user with an actionable dialog on insert,
    and any explicit attempt to run something straight off a removable drive still depends on
    AppLocker's normal default-deny once the Exe/Script collections are enforced rather than on
    anything specific to removable media (AppLocker has no "removable drive" path variable to
    write a targeted rule against). This module's registry setting is a small, no-collateral-
    damage backstop layered on top of that: it removes the AutoPlay prompt entirely so there is no
    "click here to open folder / run setup.exe" suggestion in the first place.
#>

function Get-RemovableMediaGuardStatus {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $val = (Get-ItemProperty -Path $key -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
    $disabled = ($val -eq 255)
    @("AutoRun/AutoPlay: $(if ($disabled) { 'disabled for all drive types' } else { "not fully disabled (NoDriveTypeAutoRun=$val)" })")
}

function Invoke-RemovableMediaGuardHardening {
    param([switch]$Remediate)
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    if ($Remediate) {
        if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
        Set-ItemProperty -Path $key -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord
        @("Disabled AutoRun/AutoPlay for all drive types (NoDriveTypeAutoRun = 255).")
    } else {
        @("(dry run) Would disable AutoRun/AutoPlay for all drive types at $key\NoDriveTypeAutoRun.")
    }
}

function Invoke-RemovableMediaGuardRollback {
    param([switch]$Remediate)
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    if ($Remediate) {
        try {
            Remove-ItemProperty -Path $key -Name 'NoDriveTypeAutoRun' -Force -ErrorAction Stop
            @('Restored AutoRun/AutoPlay defaults (removed NoDriveTypeAutoRun policy value).')
        } catch {
            Write-Warning "Failed to remove NoDriveTypeAutoRun: $($_.Exception.Message). Requires an elevated PowerShell session."
            @("FAILED: $($_.Exception.Message)")
        }
    } else {
        $val = (Get-ItemProperty -Path $key -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
        @("(dry run) Would remove $key\NoDriveTypeAutoRun (currently $(if ($null -ne $val) { $val } else { 'not set' })).")
    }
}

Export-ModuleMember -Function Get-RemovableMediaGuardStatus, Invoke-RemovableMediaGuardHardening, Invoke-RemovableMediaGuardRollback
