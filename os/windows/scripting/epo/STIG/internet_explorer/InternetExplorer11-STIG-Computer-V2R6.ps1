<#
.SYNOPSIS
    DoD Internet Explorer 11 STIG Computer V2R6

.DESCRIPTION
    This script checks and optionally remediates computer-specific settings for
    Internet Explorer 11 as per the DoD STIG Computer V2R6 guidelines.

.PARAMETER Remediate
    If specified, the script will attempt to remediate any non-compliant settings
    to meet the expected values defined in the STIG.

.EXAMPLE
    .\InternetExplorer11-STIG-Computer-V2R6.ps1
    This will check the current computer settings against the STIG requirements and output a compliance report.

.EXAMPLE
    .\InternetExplorer11-STIG-Computer-V2R6.ps1 -Remediate
    This will check the current computer settings, remediate any non-compliant settings, and output a compliance report indicating which settings were remediated.

.NOTES
    Author: Robert Weber
#>

param([switch]$Remediate)

# =============================================================================
# NATIVE HELPER FUNCTIONS (Computer = HKLM)
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
    # === Main IE11 Policies ===
    [pscustomobject]@{VID="IE11-Standalone"; Title="Disable Internet Explorer 11 as a standalone browser"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"; Name="DisableIE11AsStandalone"; Expected=1},
    [pscustomobject]@{VID="IE11-SmartScreenBypass"; Title="Prevent bypassing SmartScreen Filter warnings"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter"; Name="PreventOverride"; Expected=1},
    [pscustomobject]@{VID="IE11-SmartScreenFile"; Title="Prevent bypassing SmartScreen Filter warnings about files not commonly downloaded"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter"; Name="PreventOverrideForFiles"; Expected=1},
    [pscustomobject]@{VID="IE11-SmartScreenManage"; Title="Prevent managing SmartScreen Filter"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter"; Name="Enabled"; Expected=1},
    [pscustomobject]@{VID="IE11-ActiveXPerUser"; Title="Prevent per-user installation of ActiveX controls"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions"; Name="NoUserInstall"; Expected=1},

    # === Security Zones ===
    [pscustomobject]@{VID="IE11-ZoneAddSites"; Title="Security Zones: Do not allow users to add/delete sites"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"; Name="SecurityZones"; Expected=1},
    [pscustomobject]@{VID="IE11-ZoneChangePolicies"; Title="Security Zones: Do not allow users to change policies"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"; Name="SecurityOptions"; Expected=1},
    [pscustomobject]@{VID="IE11-ZoneMachineOnly"; Title="Security Zones: Use only machine settings"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"; Name="Security_HKLM_only"; Expected=1},

    # === Additional IE Settings ===
    [pscustomobject]@{VID="IE11-CrashDetection"; Title="Turn off Crash Detection"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions"; Name="NoCrashDetection"; Expected=1},
    [pscustomobject]@{VID="IE11-SecurityCheck"; Title="Turn off the Security Settings Check feature"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"; Name="NoSecurityCheck"; Expected=0},
    [pscustomobject]@{VID="IE11-DeleteHistoryOnExit"; Title="Allow deleting browsing history on exit"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\DeleteBrowsingHistory"; Name="ClearBrowsingHistoryOnExit"; Expected=0},
    [pscustomobject]@{VID="IE11-HistoryDays"; Title="Disable 'Configuring History'"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\ControlPanel"; Name="History"; Expected=40},
    [pscustomobject]@{VID="IE11-CertificateErrors"; Title="Prevent ignoring certificate errors"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"; Name="WarnOnBadCertRecving"; Expected=1},
    [pscustomobject]@{VID="IE11-InvalidSignature"; Title="Allow software to run or install even if the signature is invalid"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Download"; Name="RunInvalidSignatures"; Expected=0},
    [pscustomobject]@{VID="IE11-CertRevocation"; Title="Check for server certificate revocation"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"; Name="CheckCertRevocation"; Expected=1},
    [pscustomobject]@{VID="IE11-SignatureCheck"; Title="Check for signatures on downloaded programs"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Download"; Name="CheckSignatures"; Expected=1},

    # === Protected Mode / EPM ===
    [pscustomobject]@{VID="IE11-EPM-ActiveX"; Title="Do not allow ActiveX controls to run in Protected Mode when Enhanced Protected Mode is enabled"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"; Name="NoProtectedModeActiveX"; Expected=1},
    [pscustomobject]@{VID="IE11-TLS"; Title="Turn off encryption support"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"; Name="SecureProtocols"; Expected=0x00000A00},  # TLS 1.2 only
    [pscustomobject]@{VID="IE11-64BitTabs"; Title="Turn on 64-bit tab processes when running in Enhanced Protected Mode"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"; Name="64BitTabProcesses"; Expected=1},
    [pscustomobject]@{VID="IE11-EnhancedPM"; Title="Turn on Enhanced Protected Mode"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"; Name="Isolation"; Expected=1},

    # === Intranet / UNC ===
    [pscustomobject]@{VID="IE11-IntranetUNC"; Title="Intranet Sites: Include all network paths (UNCs)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"; Name="UNCAsIntranet"; Expected=0},

    # === Certificate Mismatch ===
    [pscustomobject]@{VID="IE11-CertMismatch"; Title="Turn on certificate address mismatch warning"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"; Name="WarnOnPostNotEncrypted"; Expected=1}
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
    Write-Host "`nAll DoD Internet Explorer 11 STIG Computer V2R6 settings have been remediated!" -ForegroundColor Green
} else {
    Write-Host "`nRun the script with -Remediate to apply fixes." -ForegroundColor Cyan
}
Write-Host "Script complete - DoD Internet Explorer 11 STIG Computer V2R6 is finished." -ForegroundColor White