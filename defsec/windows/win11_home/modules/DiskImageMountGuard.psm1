<#
.SYNOPSIS
    Stops Windows from auto-mounting .iso/.img/.vhd/.vhdx on double-click - closing the
    disk-image container that smuggles payloads past Mark-of-the-Web / SmartScreen / Defender.

.DESCRIPTION
    The dominant phishing-delivery evasion of the last few years defeats exactly the protection
    PhishingAttachmentGuard relies on: the attacker ships the payload inside an .iso (or .img /
    .vhd / .vhdx). Windows 11 mounts these on double-click, and files *inside* a mounted image do
    NOT inherit the Mark-of-the-Web - so `Invoice.iso` -> double-click -> a clean-looking drive
    with `Invoice.exe` that runs with no "from the internet" warning at all. A non-technical user
    never sees a gate.

    This module neuters the double-click *mount* action by marking the shell "mount" verb on the
    relevant ProgIDs as ProgrammaticAccessOnly - which removes it from the double-click/right-click
    UI while leaving the programmatic path (PowerShell `Mount-DiskImage`, backup/VM tools that call
    the API) fully working. So a real user who genuinely needs to open an ISO still can from
    PowerShell, but a double-click on a malicious one does nothing.

    Balance: mounting an ISO by double-click is not a normal home-user action; the payload-in-a-
    container trick is. Near-zero collateral. Registry-only, reversible.

    ProgIDs: Windows.IsoFile (.iso, .img) and Windows.VhdFile (.vhd, .vhdx).
#>

$script:MountVerbKeys = @(
    'HKLM:\SOFTWARE\Classes\Windows.IsoFile\shell\mount',
    'HKLM:\SOFTWARE\Classes\Windows.VhdFile\shell\mount'
)

function Get-DiskImageMountGuardStatus {
    $out = @()
    foreach ($key in $script:MountVerbKeys) {
        $progId = ($key -split '\\')[4]
        if (-not (Test-Path $key)) {
            $out += "${progId}: no mount verb registered (nothing to gate)."
            continue
        }
        $pao = (Get-ItemProperty -Path $key -Name 'ProgrammaticAccessOnly' -ErrorAction SilentlyContinue).PSObject.Properties.Name -contains 'ProgrammaticAccessOnly'
        $out += "${progId}: double-click auto-mount $(if ($pao) { 'disabled (payload-in-container smuggling closed)' } else { 'ENABLED (an .iso/.vhd double-click auto-mounts, bypassing Mark-of-the-Web)' })."
    }
    $out
}

function Invoke-DiskImageMountGuardHardening {
    param([switch]$Remediate)
    $out = @()
    foreach ($key in $script:MountVerbKeys) {
        $progId = ($key -split '\\')[4]
        if ($Remediate) {
            try {
                if (-not (Test-Path $key)) {
                    $out += "${progId}: no mount verb present - skipped."
                    continue
                }
                # A present 'ProgrammaticAccessOnly' value (no data) hides the verb from the UI.
                Set-ItemProperty -Path $key -Name 'ProgrammaticAccessOnly' -Value '' -Type String -ErrorAction Stop
                $out += "${progId}: disabled double-click auto-mount (Mount-DiskImage still works programmatically)."
            } catch {
                $out += "SKIPPED ${progId}: $($_.Exception.Message)"
            }
        } else {
            $out += "(dry run) Would mark the mount verb ProgrammaticAccessOnly for $progId ($key)."
        }
    }
    $out
}

function Invoke-DiskImageMountGuardRollback {
    param([switch]$Remediate)
    $out = @()
    foreach ($key in $script:MountVerbKeys) {
        $progId = ($key -split '\\')[4]
        if ($Remediate) {
            if (Test-Path $key) {
                Remove-ItemProperty -Path $key -Name 'ProgrammaticAccessOnly' -Force -ErrorAction SilentlyContinue
                $out += "${progId}: restored double-click mount."
            } else {
                $out += "${progId}: no mount verb present - nothing to undo."
            }
        } else {
            $out += "(dry run) Would remove the ProgrammaticAccessOnly marker for $progId."
        }
    }
    $out
}

Export-ModuleMember -Function Get-DiskImageMountGuardStatus, Invoke-DiskImageMountGuardHardening, Invoke-DiskImageMountGuardRollback
