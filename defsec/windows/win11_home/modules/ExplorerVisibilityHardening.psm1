<#
.SYNOPSIS
    Forces Explorer to show known file extensions, defeating the `invoice.pdf.exe`
    double-extension disguise - for the current user and for newly created accounts.

.DESCRIPTION
    HideFileExt is a per-user Explorer preference read from HKCU; there is no machine-wide
    policy value for it. So this module covers two audiences separately:

    - Current user: HKCU\...\Explorer\Advanced\HideFileExt = 0.
    - New accounts: seeds the same value into the Default user profile hive
      (C:\Users\Default\NTUSER.DAT), which Windows copies into every newly created profile.
      This is done by loading that hive, writing the value, and unloading - not by writing to
      HKLM\...\Explorer\Advanced, which only stores the *definitions* of Explorer's advanced
      settings and is ignored as a live preference. (An earlier version wrote there and had no
      effect on new users; this is the corrected implementation.)

    Existing OTHER user profiles are not rewritten (their hives aren't loaded and doing so while
    they're logged in is unsafe); each shows extensions once this module - or the setting - is
    applied in their own session.
#>

$script:CurrentUserKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$script:DefaultHivePath = Join-Path $env:SystemDrive 'Users\Default\NTUSER.DAT'
$script:DefaultMountName = 'HomeBaseline_DefaultUser'

function Set-ExplorerDefaultProfileHideFileExt {
    <#
    .SYNOPSIS
        Loads the Default user profile hive, sets (or with -Remove, clears) HideFileExt=0 so new
        accounts inherit it, then unloads. Never throws - returns a status string. Factored out
        so the load/unload dance is testable in isolation.
    #>
    param(
        [switch]$Remediate,
        [switch]$Remove
    )
    $verb = if ($Remove) { 'remove HideFileExt=0 from' } else { 'seed HideFileExt=0 into' }
    if (-not $Remediate) {
        return "(dry run) Would $verb the Default user profile ($script:DefaultHivePath) so new accounts inherit it."
    }
    if (-not (Test-Path -LiteralPath $script:DefaultHivePath)) {
        return "Default profile hive not found at $script:DefaultHivePath - skipped new-account seeding."
    }
    $mountKey = "HKU\$script:DefaultMountName"
    $advanced = "Registry::HKEY_USERS\$script:DefaultMountName\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    $load = & reg.exe load $mountKey $script:DefaultHivePath 2>&1
    if ($LASTEXITCODE -ne 0) {
        return "Could not load the Default profile hive (already in use?): $load"
    }
    try {
        if ($Remove) {
            Remove-ItemProperty -Path $advanced -Name 'HideFileExt' -Force -ErrorAction SilentlyContinue
            return 'Removed the HideFileExt seed from the Default user profile.'
        } else {
            if (-not (Test-Path -LiteralPath $advanced)) { New-Item -Path $advanced -Force | Out-Null }
            Set-ItemProperty -Path $advanced -Name 'HideFileExt' -Value 0 -Type DWord
            return 'Seeded HideFileExt=0 into the Default user profile - new accounts will show file extensions.'
        }
    } catch {
        return "Failed while editing the Default profile hive: $($_.Exception.Message)"
    } finally {
        # Release the provider's handle to the hive so the unload can succeed.
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        & reg.exe unload $mountKey 2>&1 | Out-Null
    }
}

function Get-ExplorerVisibilityHardeningStatus {
    $val = (Get-ItemProperty -Path $script:CurrentUserKey -Name 'HideFileExt' -ErrorAction SilentlyContinue).HideFileExt
    if ($val -eq 0) {
        @('File extensions: shown for the current user (double-extension disguises are visible).')
    } else {
        @('File extensions: HIDDEN for the current user - invoice.pdf.exe displays as invoice.pdf.')
    }
}

function Invoke-ExplorerVisibilityHardeningHardening {
    param([switch]$Remediate)
    $out = @()
    if ($Remediate) {
        if (-not (Test-Path $script:CurrentUserKey)) { New-Item -Path $script:CurrentUserKey -Force | Out-Null }
        Set-ItemProperty -Path $script:CurrentUserKey -Name 'HideFileExt' -Value 0 -Type DWord
        $out += "Set HideFileExt=0 for the current user ($script:CurrentUserKey)."
        $out += Set-ExplorerDefaultProfileHideFileExt -Remediate
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
        $out += 'Explorer restarted to apply extension visibility.'
    } else {
        $out += "(dry run) Would set HideFileExt=0 for the current user ($script:CurrentUserKey)."
        $out += Set-ExplorerDefaultProfileHideFileExt
    }
    $out
}

function Invoke-ExplorerVisibilityHardeningRollback {
    param([switch]$Remediate)
    $out = @()
    if ($Remediate) {
        try {
            Remove-ItemProperty -Path $script:CurrentUserKey -Name 'HideFileExt' -Force -ErrorAction Stop
            $out += "Removed HideFileExt override for the current user ($script:CurrentUserKey)."
        } catch {
            $out += "HideFileExt not set for the current user: nothing to undo."
        }
        $out += Set-ExplorerDefaultProfileHideFileExt -Remediate -Remove
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
        $out += 'Explorer restarted.'
    } else {
        $out += "(dry run) Would remove the HideFileExt override for the current user ($script:CurrentUserKey)."
        $out += Set-ExplorerDefaultProfileHideFileExt -Remove
    }
    $out
}

Export-ModuleMember -Function Get-ExplorerVisibilityHardeningStatus, Invoke-ExplorerVisibilityHardeningHardening, Invoke-ExplorerVisibilityHardeningRollback, Set-ExplorerDefaultProfileHideFileExt
