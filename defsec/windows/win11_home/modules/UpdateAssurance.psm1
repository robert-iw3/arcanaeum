<#
.SYNOPSIS
    Ensures Windows keeps patching itself automatically - so the machine isn't exploitable
    through known holes that need no user click at all.

.DESCRIPTION
    A non-technical user who turns off or endlessly defers updates leaves the OS and Office
    exploitable by n-day bugs an attacker can trigger from a web page or document with no
    interaction. This module pins automatic updating on:

    - NoAutoUpdate = 0, AUOptions = 4: download and install updates automatically on a schedule.
    - No long deferral of quality/feature updates (DeferQualityUpdates* / DeferFeatureUpdates* = 0).
    - Makes sure the Windows Update service (wuauserv) isn't left Disabled.

    Balance: essentially none for a home user - this is the behavior most people expect anyway;
    it just prevents updates being silently disabled. It does not force immediate reboots.
#>

$script:AuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$script:WuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'

function Get-UpdateAssuranceStatus {
    $out = @()
    $svc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($svc) { $out += "Windows Update service: $($svc.Status), StartType=$($svc.StartType)$(if ($svc.StartType -eq 'Disabled') { ' - DISABLED (updates will not install)' } else { '' })." }
    $au = (Get-ItemProperty -Path $script:AuKey -Name 'NoAutoUpdate' -ErrorAction SilentlyContinue).NoAutoUpdate
    if ($au -eq 1) {
        $out += 'Automatic updates: DISABLED by policy.'
    } else {
        $out += 'Automatic updates: enabled (not disabled by policy).'
    }
    $out
}

function Set-UpdateValue {
    param([string]$Path, [string]$Name, $Value)
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -ErrorAction Stop
        $null
    } catch { "SKIPPED ${Path}\${Name}: $($_.Exception.Message)" }
}

function Invoke-UpdateAssuranceHardening {
    param([switch]$Remediate)
    if (-not $Remediate) {
        return @(
            '(dry run) Would enable automatic updates (NoAutoUpdate=0, AUOptions=4) and clear update deferrals.',
            '(dry run) Would ensure the Windows Update service is not Disabled.'
        )
    }
    $out = @()
    $errs = @()
    $errs += Set-UpdateValue -Path $script:AuKey -Name 'NoAutoUpdate' -Value 0
    $errs += Set-UpdateValue -Path $script:AuKey -Name 'AUOptions' -Value 4
    $errs += Set-UpdateValue -Path $script:WuKey -Name 'DeferQualityUpdates' -Value 0
    $errs += Set-UpdateValue -Path $script:WuKey -Name 'DeferQualityUpdatesPeriodInDays' -Value 0
    $errs += Set-UpdateValue -Path $script:WuKey -Name 'DeferFeatureUpdates' -Value 0
    $out += 'Enabled automatic updates and cleared update deferrals.'

    $svc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($svc -and $svc.StartType -eq 'Disabled') {
        try {
            Set-Service -Name wuauserv -StartupType Manual -ErrorAction Stop
            $out += 'Re-enabled the Windows Update service (was Disabled -> Manual/trigger-start).'
        } catch {
            $out += "Could not re-enable the Windows Update service: $($_.Exception.Message)"
        }
    }
    $errs = @($errs | Where-Object { $_ })
    if ($errs) { $out += $errs }
    $out
}

function Invoke-UpdateAssuranceRollback {
    param([switch]$Remediate)
    if ($Remediate) {
        foreach ($n in 'NoAutoUpdate', 'AUOptions') { Remove-ItemProperty -Path $script:AuKey -Name $n -Force -ErrorAction SilentlyContinue }
        foreach ($n in 'DeferQualityUpdates', 'DeferQualityUpdatesPeriodInDays', 'DeferFeatureUpdates') { Remove-ItemProperty -Path $script:WuKey -Name $n -Force -ErrorAction SilentlyContinue }
        @('Removed the automatic-update policy overrides (Windows Update returns to Settings-app control).')
    } else {
        @('(dry run) Would remove the automatic-update policy overrides.')
    }
}

Export-ModuleMember -Function Get-UpdateAssuranceStatus, Invoke-UpdateAssuranceHardening, Invoke-UpdateAssuranceRollback
