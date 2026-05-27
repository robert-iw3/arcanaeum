<#
.SYNOPSIS
    DoD WinSvr 2025 MS STIG User v1r1

.DESCRIPTION
    This script checks and optionally remediates user-level settings for the DoD Windows Server
    2025 MS STIG User v1r1. It evaluates compliance based on registry values and provides a report.

.EXAMPLE
    # Check compliance only
    .\WindowsServer2025-DoD-STIG-User-V1R1.ps1

    # Check and remediate non-compliant settings
    .\WindowsServer2025-DoD-STIG-User-V1R1.ps1 -Remediate

.NOTES
    Author: Robert Weber
#>

param([switch]$Remediate)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { $null }
}

function Set-RegValue {
    param([string]$Path, [string]$Name, [object]$Value, [string]$Type = "DWord")
    if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

# =============================================================================
# STIG RULES ARRAY
# =============================================================================
$rules = @(
    [pscustomobject]@{VID="V-XXXXXX"; Title="Do not preserve zone information in file attachments"; CheckType="Registry"; Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"; Name="SaveZoneInformation"; Expected=2},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Always install with elevated privileges"; CheckType="Registry"; Path="HKCU:\Software\Policies\Microsoft\Windows\Installer"; Name="AlwaysInstallElevated"; Expected=0}
)

# =============================================================================
# MAIN EXECUTION
# =============================================================================
$report = @()

foreach ($rule in $rules) {
    $status = "Non-Compliant"
    $remediated = $false
    $current = Get-RegValue -Path $rule.Path -Name $rule.Name

    if ($current -eq $rule.Expected) {
        $status = "Compliant"
    }
    elseif ($Remediate) {
        Set-RegValue -Path $rule.Path -Name $rule.Name -Value $rule.Expected
        $remediated = $true
    }

    $report += [pscustomobject]@{
        VID        = $rule.VID
        Title      = $rule.Title
        Status     = $status
        Remediated = if ($Remediate -and $remediated) { "Yes" } else { "No" }
        Current    = if ($null -eq $current) { "Not Set" } else { $current }
    }
}

# =============================================================================
# OUTPUT
# =============================================================================
$report | Sort-Object VID | Format-Table -AutoSize

if ($Remediate) {
    Write-Host "`nRemediation complete for all DoD WinSvr 2025 MS STIG User v1r1 rules!" -ForegroundColor Green
} else {
    Write-Host "`nRun with -Remediate to fix Non-Compliant items." -ForegroundColor Cyan
}
Write-Host "DoD WinSvr 2025 MS STIG User v1r1 is finished." -ForegroundColor White