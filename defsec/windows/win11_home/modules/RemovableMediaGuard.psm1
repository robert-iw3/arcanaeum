<#
.SYNOPSIS
    Disables the AutoRun/AutoPlay prompt for all drive types - the "found a USB drive" run-on-
    insert vector - WITHOUT disabling removable storage itself.

.DESCRIPTION
    Ported from the applocker baseline (registry-only there too). This is the deliberate,
    balanced version of "USB hardening": it closes the AutoRun/AutoPlay *prompt* that offers to
    run setup.exe / open a folder the instant a drive is inserted, which is the actual attack
    surface. It does NOT block the drive - external hard drives, USB sticks, camera SD cards,
    and phones still mount and their files are fully accessible. A normal user's printer, backup
    drive, and photo transfer keep working; only the auto-execute prompt goes away.

    Matches STIG WN11-CC-000190 (NoDriveTypeAutoRun=255). Kept here so the Home baseline is
    self-contained even if the STIG layer isn't run.

    If you want to actually block execution *from* removable media (not just the prompt), that
    is what the Defender ASR "Block untrusted/unsigned processes from USB" rule does - and the
    Defender STIG already enables it on Home. This module is the always-safe complement.
#>

$script:Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'

function Get-RemovableMediaGuardStatus {
    $val = (Get-ItemProperty -Path $script:Key -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
    $disabled = ($val -eq 255)
    @("AutoRun/AutoPlay prompt: $(if ($disabled) { 'disabled for all drive types (storage still fully usable)' } else { "not fully disabled (NoDriveTypeAutoRun=$val)" })")
}

function Invoke-RemovableMediaGuardHardening {
    param([switch]$Remediate)
    if ($Remediate) {
        if (-not (Test-Path $script:Key)) { New-Item -Path $script:Key -Force | Out-Null }
        Set-ItemProperty -Path $script:Key -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord
        @('Disabled the AutoRun/AutoPlay prompt for all drive types (NoDriveTypeAutoRun=255). Drives still mount and files are still accessible - only the auto-execute prompt is removed.')
    } else {
        @("(dry run) Would disable the AutoRun/AutoPlay prompt for all drive types at $script:Key\NoDriveTypeAutoRun (storage remains usable).")
    }
}

function Invoke-RemovableMediaGuardRollback {
    param([switch]$Remediate)
    if ($Remediate) {
        try {
            Remove-ItemProperty -Path $script:Key -Name 'NoDriveTypeAutoRun' -Force -ErrorAction Stop
            @('Restored AutoRun/AutoPlay defaults (removed NoDriveTypeAutoRun policy value).')
        } catch {
            @("NoDriveTypeAutoRun not present: nothing to undo.")
        }
    } else {
        $val = (Get-ItemProperty -Path $script:Key -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
        @("(dry run) Would remove $script:Key\NoDriveTypeAutoRun (currently $(if ($null -ne $val) { $val } else { 'not set' })).")
    }
}

Export-ModuleMember -Function Get-RemovableMediaGuardStatus, Invoke-RemovableMediaGuardHardening, Invoke-RemovableMediaGuardRollback
