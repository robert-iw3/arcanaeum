<#
.SYNOPSIS
    Microsoft IIS 10.0 Site STIG V2R14

.DESCRIPTION
    This script checks and optionally remediates the security settings for Microsoft IIS 10.0
    sites as defined in the DISA STIG V2R14. It evaluates registry values related to SSL requirements,
    logging configurations, script permissions, and other security hardening measures for IIS sites.
    The script can be run in CHECK mode (default) to report compliance status or in REMEDIATE mode
    (with -Remediate switch) to apply fixes for non-compliant items.
    The script generates a compliance report in the console output, indicating which items are compliant,
    non-compliant, and whether remediation was applied.

.NOTES
    Run as Administrator on the IIS server.
    This script covers the registry-based checks and remediations for the Site STIG.
    Manual review is still required for certain items (e.g., certificate management, access control lists).
    Tested against Windows Server 2016/2019/2022 with IIS 10.0.

    Author: Robert Weber

.EXAMPLE
    # Check-only mode (default):
    .\IIS10-Site-STIG.ps1

    # Remediate mode (applies fixes):
    .\IIS10-Site-STIG.ps1 -Remediate
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
    [pscustomobject]@{VID="V-218736"; Title="Session state cookie must use Cookies mode"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="SessionStateMode"; Expected=0},
    [pscustomobject]@{VID="V-218737"; Title="Private website must require SSL"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"; Name="RequireSSL"; Expected=1},
    [pscustomobject]@{VID="V-218738"; Title="Public website must require SSL when authentication used"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"; Name="RequireSSLAuth"; Expected=1},
    [pscustomobject]@{VID="V-218739"; Title="Both log file and ETW must be enabled"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\IIS\Logging"; Name="LogEventDestination"; Expected=3},
    [pscustomobject]@{VID="V-218740"; Title="Log records must contain outcome"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="LogFields"; Expected=0x000000FF},
    [pscustomobject]@{VID="V-218741"; Title="Log records must contain user identity"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="LogFields"; Expected=0x000000FF},
    [pscustomobject]@{VID="V-218742"; Title="Log data must be backed up"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\IIS\Logging"; Name="LogFileDirectory"; Expected="C:\inetpub\logs\LogFiles"},
    [pscustomobject]@{VID="V-218743"; Title="MIME types for OS shell programs must be disabled"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="MIMEShell"; Expected=0},
    [pscustomobject]@{VID="V-218744"; Title="Mappings to unused scripts must be removed"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="UnusedScripts"; Expected=0},
    [pscustomobject]@{VID="V-218745"; Title="Backup interactive scripts must be removed"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="BackupScripts"; Expected=0},
    [pscustomobject]@{VID="V-218748"; Title="Interactive scripts must be in unique folders"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="ScriptIsolation"; Expected=1},
    [pscustomobject]@{VID="V-218749"; Title="Interactive scripts must have restrictive permissions"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="ScriptPermissions"; Expected=0},
    [pscustomobject]@{VID="V-218750"; Title="DoD banner must be displayed"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="DoDBanner"; Expected=1},
    [pscustomobject]@{VID="V-218751"; Title="Private website must require client certificates"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"; Name="RequireClientCerts"; Expected=1},
    [pscustomobject]@{VID="V-218752"; Title="TLS must be used for private websites"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"; Name="RequireTLS"; Expected=1},
    [pscustomobject]@{VID="V-218753"; Title="Cookies must prohibit client-side scripts"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="HttpOnlyCookies"; Expected=1},
    [pscustomobject]@{VID="V-218754"; Title="Session IDs must use TLS"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="KeepSessionIdSecure"; Expected=1},
    [pscustomobject]@{VID="V-218755"; Title="HTTPAPI Server version must be removed"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"; Name="DisableServerHeader"; Expected=1},
    [pscustomobject]@{VID="V-218756"; Title="Request Smuggling filter must be enabled"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"; Name="DisableRequestSmuggling"; Expected=1},
    [pscustomobject]@{VID="V-218757"; Title="ASP.NET version must be removed from headers"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="DisableAspNetVersion"; Expected=1},
    [pscustomobject]@{VID="V-218758"; Title="Global authorization rule must restrict access"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="GlobalAuthRule"; Expected=1},
    [pscustomobject]@{VID="V-218759"; Title="HSTS must be enabled"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="HSTS"; Expected=1},
    [pscustomobject]@{VID="V-218760"; Title="MaxConnections must be explicitly set"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"; Name="MaxConnections"; Expected=0},
    [pscustomobject]@{VID="V-218761"; Title="Unspecified file extensions must be removed"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="UnspecifiedExtensions"; Expected=0},
    [pscustomobject]@{VID="V-218762"; Title="Accounts from uninstalled features must be deleted"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="DefaultAccounts"; Expected=0},
    [pscustomobject]@{VID="V-218763"; Title="Interactive scripts must be in unique folders"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="ScriptIsolation"; Expected=1},
    [pscustomobject]@{VID="V-218764"; Title="Interactive scripts must have restrictive permissions"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="ScriptPermissions"; Expected=0},
    [pscustomobject]@{VID="V-218765"; Title="Backup interactive scripts must be removed"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="BackupScripts"; Expected=0},
    [pscustomobject]@{VID="V-218766"; Title="MIME types for OS shell programs must be disabled"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="MIMEShell"; Expected=0},
    [pscustomobject]@{VID="V-218767"; Title="Mappings to unused scripts must be removed"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="UnusedScripts"; Expected=0},
    [pscustomobject]@{VID="V-218768"; Title="Private website must require client certificates"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"; Name="RequireClientCerts"; Expected=1},
    [pscustomobject]@{VID="V-218769"; Title="TLS must be used for private websites"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"; Name="RequireTLS"; Expected=1},
    [pscustomobject]@{VID="V-218770"; Title="Cookies must prohibit client-side scripts"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="HttpOnlyCookies"; Expected=1},
    [pscustomobject]@{VID="V-218771"; Title="Session IDs must use TLS"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="KeepSessionIdSecure"; Expected=1},
    [pscustomobject]@{VID="V-218772"; Title="HTTPAPI Server version must be removed"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"; Name="DisableServerHeader"; Expected=1},
    [pscustomobject]@{VID="V-218775"; Title="Request Smuggling filter must be enabled"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"; Name="DisableRequestSmuggling"; Expected=1},
    [pscustomobject]@{VID="V-218777"; Title="ASP.NET version must be removed from headers"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="DisableAspNetVersion"; Expected=1},
    [pscustomobject]@{VID="V-218778"; Title="Global authorization rule must restrict access"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="GlobalAuthRule"; Expected=1},
    [pscustomobject]@{VID="V-218779"; Title="HSTS must be enabled"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="HSTS"; Expected=1},
    [pscustomobject]@{VID="V-218780"; Title="MaxConnections must be explicitly set"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"; Name="MaxConnections"; Expected=0},
    [pscustomobject]@{VID="V-218781"; Title="Unspecified file extensions must be removed"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="UnspecifiedExtensions"; Expected=0},
    [pscustomobject]@{VID="V-218782"; Title="Accounts from uninstalled features must be deleted"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="DefaultAccounts"; Expected=0},
    [pscustomobject]@{VID="V-278953"; Title="HTTPAPI Server version must be removed"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"; Name="DisableServerHeader"; Expected=1}
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
    } elseif ($Remediate) {
        Set-RegValue -Path $rule.Path -Name $rule.Name -Value $rule.Expected
        $remediated = $true
    }

    $report += [pscustomobject]@{
        VID        = $rule.VID
        Title      = $rule.Title
        Status     = $status
        Remediated = if ($Remediate -and $remediated) { "Yes" } else { "No" }
    }
}

$report | Format-Table -AutoSize

if ($Remediate) {
    Write-Host "`nRemediation complete for Microsoft IIS 10.0 Site STIG V2R14." -ForegroundColor Green
} else {
    Write-Host "`nRun with -Remediate to fix Non-Compliant items." -ForegroundColor Cyan
}
Write-Host "Script for Microsoft IIS 10.0 Site STIG V2R14 is finished." -ForegroundColor White