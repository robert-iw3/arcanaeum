<#
.SYNOPSIS
    DoD Internet Explorer 11 STIG User V2R6

.DESCRIPTION
    This script checks and optionally remediates user-specific settings for
    Internet Explorer 11 as per the DoD STIG User V2R6 guidelines.

.PARAMETER Remediate
    If specified, the script will attempt to remediate any non-compliant settings
    to meet the expected values defined in the STIG.

.EXAMPLE
    .\InternetExplorer11-STIG-User-V2R6.ps1
    This will check the current user settings against the STIG requirements and output a compliance report.

.EXAMPLE
    .\InternetExplorer11-STIG-User-V2R6.ps1 -Remediate
    This will check the current user settings, remediate any non-compliant settings, and output a compliance report indicating which settings were remediated.

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
    # === WinTrust State ===
    [pscustomobject]@{VID="IE11-TrustProviders"; Title="WinTrust Software Publishing State"; CheckType="Registry"; Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"; Name="State"; Expected=0x00023C00},

    # === Disable AutoComplete for forms ===
    [pscustomobject]@{VID="IE11-AutoCompleteForms"; Title="Disable AutoComplete for forms"; CheckType="Registry"; Path="HKCU:\Software\Policies\Microsoft\Internet Explorer\Main"; Name="AutoComplete"; Expected=0},

    # === Turn on auto-complete for user names and passwords on forms (Disabled) ===
    [pscustomobject]@{VID="IE11-AutoCompletePasswords"; Title="Turn on the auto-complete feature for user names and passwords on forms"; CheckType="Registry"; Path="HKCU:\Software\Policies\Microsoft\Internet Explorer\Main"; Name="FormSuggest"; Expected=0}
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
        $status = "Remediated"
    }

    $report += [pscustomobject]@{
        VID        = $rule.VID
        Title      = $rule.Title
        Status     = $status
        Remediated = if ($Remediate -and $remediated) { "Yes" } else { "No" }
    }
}

# =============================================================================
# OUTPUT REPORT
# =============================================================================
$report | Sort-Object VID | Format-Table -AutoSize

if ($Remediate) {
    Write-Host "`nAll DoD Internet Explorer 11 STIG User V2R6 User settings have been remediated!" -ForegroundColor Green
} else {
    Write-Host "`nRun the script with -Remediate to apply fixes." -ForegroundColor Cyan
}
Write-Host "Script complete - DoD Internet Explorer 11 STIG User V2R6 is finished." -ForegroundColor White