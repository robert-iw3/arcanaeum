<#
.SYNOPSIS
    Forces "show known file extensions" so a file named invoice.pdf.exe shows its real .exe
    extension instead of displaying as invoice.pdf.

.DESCRIPTION
    The double-extension disguise (invoice.pdf.exe, photo.jpg.scr, resume.doc.vbs) is one of the
    oldest and still most common tricks used in scams targeting non-technical users, and it works
    purely because Windows hides known extensions by default. This is a one-line registry fix with
    essentially no downside.

    Applies to the current user's profile and to HKEY_USERS\.DEFAULT (so newly created local
    profiles inherit it). It does NOT retroactively reach other already-existing user profiles on
    a shared machine - re-run this module (or have each user run it) per profile if more than one
    standard-user account is in regular use on the same laptop.
#>

function Get-ExplorerVisibilityHardeningStatus {
    $val = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -ErrorAction SilentlyContinue).HideFileExt
    $shown = ($val -eq 0)
    @("File extensions for the current user: $(if ($shown) { 'shown' } else { 'hidden (double-extension disguise risk, e.g. invoice.pdf.exe)' })")
}

function Invoke-ExplorerVisibilityHardeningHardening {
    param([switch]$Remediate)
    $paths = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
        'Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    )
    $results = @()
    foreach ($path in $paths) {
        if ($Remediate) {
            if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
            Set-ItemProperty -Path $path -Name 'HideFileExt' -Value 0 -Type DWord
            $results += "Set HideFileExt = 0 at $path"
        } else {
            $results += "(dry run) Would set HideFileExt = 0 at $path"
        }
    }
    $results
}

function Invoke-ExplorerVisibilityHardeningRollback {
    param([switch]$Remediate)
    $paths = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
        'Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    )
    $results = @()
    foreach ($path in $paths) {
        if ($Remediate) {
            try {
                Remove-ItemProperty -Path $path -Name 'HideFileExt' -Force -ErrorAction Stop
                $results += "Removed HideFileExt override at $path."
            } catch {
                Write-Warning "Failed to remove HideFileExt at ${path}: $($_.Exception.Message)"
                $results += "FAILED at ${path}: $($_.Exception.Message)"
            }
        } else {
            $val = (Get-ItemProperty -Path $path -Name 'HideFileExt' -ErrorAction SilentlyContinue).HideFileExt
            $results += "(dry run) Would remove HideFileExt override at $path (currently $(if ($null -ne $val) { $val } else { 'not set' }))."
        }
    }
    if ($Remediate) {
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
        $results += 'Explorer restarted to apply the change immediately.'
    }
    $results
}

Export-ModuleMember -Function Get-ExplorerVisibilityHardeningStatus, Invoke-ExplorerVisibilityHardeningHardening, Invoke-ExplorerVisibilityHardeningRollback
