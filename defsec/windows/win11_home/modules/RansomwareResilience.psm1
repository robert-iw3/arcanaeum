<#
.SYNOPSIS
    Opt-in: turns on Defender Controlled Folder Access (blocks unauthorized processes from
    encrypting personal files) and ensures System Restore is on for a recovery path - last-line
    containment if execution does happen.

.DESCRIPTION
    If a payload detonates despite everything upstream, the damage a home user actually cares
    about is ransomware encrypting photos and documents. Two built-in features blunt that:

    - Controlled Folder Access: only trusted programs can write to Documents/Pictures/Desktop/etc.;
      an unknown process trying to mass-encrypt them is blocked. Set via Defender.
    - System Restore: enabled on the system drive so there's a rollback point.

    Options:
      Mode = Enabled | Audit (default Enabled). Audit only logs what WOULD be blocked - useful to
      shake out false positives before enforcing.

    OPT-IN because Controlled Folder Access has a real false-positive tail: legitimate apps (games
    saving to Documents, creative/backup tools) get blocked until you allow-list them in Windows
    Security, and a non-technical user won't know why a save failed. Consider Mode=Audit first,
    review Defender's "Controlled folder access" block events, allow-list the good apps, then
    switch to Enabled.

    Requires Microsoft Defender to be the active AV (Set-MpPreference). Status/hardening detect a
    missing Defender and say so.
#>

function Get-RansomwareResilienceStatus {
    $out = @()
    if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
        try {
            $cfa = (Get-MpPreference).EnableControlledFolderAccess
            $map = @{ 0 = 'Disabled'; 1 = 'Enabled (Block)'; 2 = 'Audit' }
            $out += "Controlled Folder Access (anti-ransomware): $(if ($map.ContainsKey([int]$cfa)) { $map[[int]$cfa] } else { $cfa })."
        } catch {
            $out += "Could not read Controlled Folder Access state: $($_.Exception.Message)"
        }
    } else {
        $out += 'Microsoft Defender cmdlets not present - Controlled Folder Access cannot be reported (third-party AV?).'
    }
    return $out
}

function Invoke-RansomwareResilienceHardening {
    param(
        [switch]$Remediate,
        [ValidateSet('Enabled', 'Audit')] [string]$Mode = 'Enabled'
    )
    if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) {
        return @('Microsoft Defender cmdlets not present - skipping Controlled Folder Access (requires Defender as the active AV).')
    }
    $cfaValue = if ($Mode -eq 'Audit') { 'AuditMode' } else { 'Enabled' }
    if (-not $Remediate) {
        return @(
            "(dry run) Would set Controlled Folder Access = $cfaValue (anti-ransomware).",
            '(dry run) Would ensure System Restore is enabled on the system drive.'
        )
    }
    $out = @()
    try {
        Set-MpPreference -EnableControlledFolderAccess $cfaValue -ErrorAction Stop
        $out += "Controlled Folder Access set to $Mode. If a legitimate app is blocked, allow it in Windows Security > Ransomware protection."
    } catch {
        $out += "Could not enable Controlled Folder Access: $($_.Exception.Message) (Defender active with Tamper Protection allowing changes?)"
    }
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction Stop
        # Allow restore points to be created more than once a day.
        $srKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        if (-not (Test-Path $srKey)) { New-Item -Path $srKey -Force -ErrorAction SilentlyContinue | Out-Null }
        Set-ItemProperty -Path $srKey -Name 'SystemRestorePointCreationFrequency' -Value 0 -Type DWord -ErrorAction SilentlyContinue
        $out += 'Enabled System Restore on the system drive (recovery path for ransomware/bad updates).'
    } catch {
        $out += "Could not enable System Restore: $($_.Exception.Message)"
    }
    $out
}

function Invoke-RansomwareResilienceRollback {
    param([switch]$Remediate)
    if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) {
        return @('Microsoft Defender cmdlets not present - nothing to undo.')
    }
    if ($Remediate) {
        try {
            Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction Stop
            @('Disabled Controlled Folder Access. (System Restore left enabled - it is a safety net, not a hardening change.)')
        } catch {
            @("Could not disable Controlled Folder Access: $($_.Exception.Message)")
        }
    } else {
        @('(dry run) Would disable Controlled Folder Access (System Restore left enabled).')
    }
}

Export-ModuleMember -Function Get-RansomwareResilienceStatus, Invoke-RansomwareResilienceHardening, Invoke-RansomwareResilienceRollback
