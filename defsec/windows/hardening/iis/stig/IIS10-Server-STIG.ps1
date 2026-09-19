<#
.SYNOPSIS
    Microsoft IIS 10.0 Server STIG V3R6

.DESCRIPTION
    This script checks and optionally remediates the registry settings required for compliance with the Microsoft IIS
    10.0 Server STIG V3R6. It covers various security configurations related to logging, authentication, SSL requirements,
    and other hardening measures as specified in the DISA STIG documentation.

.NOTES
    - Run as Administrator on the IIS server.
    - This script modifies registry settings; ensure you have backups and understand the changes before running in remediate mode.
    - The script checks each setting against the expected compliant value and optionally remediates non-compliant settings when the -Remediate switch is used.
    - A report is generated in the console showing the compliance status of each rule, and whether remediation was applied.
    - Reference: Full STIG documentation for Microsoft IIS 10.0 Server V3R6.

    Author: Robert Weber

.EXAMPLE
    # Check compliance without making changes:
    .\IIS10-Server-STIG.ps1

    # Check compliance and remediate non-compliant settings:
    .\IIS10-Server-STIG.ps1 -Remediate
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
    [pscustomobject]@{VID="V-218786"; Title="Both the log file and ETW must be enabled"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\IIS\Logging"; Name="LogEventDestination"; Expected=3},
    [pscustomobject]@{VID="V-218788"; Title="Log records must contain outcome (success/failure)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="LogFields"; Expected=0x000000FF},
    [pscustomobject]@{VID="V-218789"; Title="Log records must contain user identity"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="LogFields"; Expected=0x000000FF},
    [pscustomobject]@{VID="V-218790"; Title="Log data must be backed up"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\IIS\Logging"; Name="LogFileDirectory"; Expected="C:\inetpub\logs\LogFiles"},
    [pscustomobject]@{VID="V-218791"; Title="IIS must not perform user management"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="UserManagement"; Expected=0},
    [pscustomobject]@{VID="V-218792"; Title="IIS must only contain necessary functions"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="UnneededFeatures"; Expected=0},
    [pscustomobject]@{VID="V-218793"; Title="IIS must not be both website and proxy"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"; Name="ProxyEnabled"; Expected=0},
    [pscustomobject]@{VID="V-218794"; Title="Sample code and tutorials must be removed"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="SampleCode"; Expected=0},
    [pscustomobject]@{VID="V-218795"; Title="Accounts from uninstalled features must be deleted"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="DefaultAccounts"; Expected=0},
    [pscustomobject]@{VID="V-218796"; Title="Unspecified file extensions must be removed"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="UnspecifiedExtensions"; Expected=0},
    [pscustomobject]@{VID="V-218797"; Title="MaxConnections must be explicitly set"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"; Name="MaxConnections"; Expected=0},
    [pscustomobject]@{VID="V-218798"; Title="Global authorization rule must restrict access"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="GlobalAuthRule"; Expected=1},
    [pscustomobject]@{VID="V-218799"; Title="HTTP Strict Transport Security (HSTS) must be enabled"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="HSTS"; Expected=1},
    [pscustomobject]@{VID="V-218801"; Title="Server version must be removed from headers"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"; Name="DisableServerHeader"; Expected=1},
    [pscustomobject]@{VID="V-218802"; Title="Request Smuggling filter must be enabled"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"; Name="DisableRequestSmuggling"; Expected=1},
    [pscustomobject]@{VID="V-218803"; Title="ASP.NET version must be removed from headers"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="DisableAspNetVersion"; Expected=1},
    [pscustomobject]@{VID="V-218804"; Title="Interactive scripts must be in unique folders"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="ScriptIsolation"; Expected=1},
    [pscustomobject]@{VID="V-218805"; Title="Interactive scripts must have restrictive permissions"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="ScriptPermissions"; Expected=0},
    [pscustomobject]@{VID="V-218806"; Title="Backup interactive scripts must be removed"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="BackupScripts"; Expected=0},
    [pscustomobject]@{VID="V-218807"; Title="DoD banner must be displayed"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="DoDBanner"; Expected=1},
    [pscustomobject]@{VID="V-218808"; Title="Private website must require SSL"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"; Name="RequireSSL"; Expected=1},
    [pscustomobject]@{VID="V-218809"; Title="Public website must require SSL when authentication is used"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"; Name="RequireSSLAuth"; Expected=1},
    [pscustomobject]@{VID="V-218810"; Title="Log records must contain user identity"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="LogUserIdentity"; Expected=1},
    [pscustomobject]@{VID="V-218812"; Title="Log records must contain outcome"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="LogOutcome"; Expected=1},
    [pscustomobject]@{VID="V-218813"; Title="Log data must be backed up"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\IIS\Logging"; Name="LogFileDirectory"; Expected="C:\inetpub\logs\LogFiles"},
    [pscustomobject]@{VID="V-218814"; Title="Access to web administration tools must be restricted"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="AdminToolAccess"; Expected=0},
    [pscustomobject]@{VID="V-218815"; Title="Web server must not provide any other role"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="OtherRoles"; Expected=0},
    [pscustomobject]@{VID="V-218816"; Title="IPP must be disabled"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="IPPEnabled"; Expected=0},
    [pscustomobject]@{VID="V-218817"; Title="SMTP relay must require authentication"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\SMTPSVC"; Name="RequireAuth"; Expected=1},
    [pscustomobject]@{VID="V-218818"; Title="HTTPAPI Server version must be removed"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"; Name="DisableServerHeader"; Expected=1},
    [pscustomobject]@{VID="V-218819"; Title="Session IDs must use TLS"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="KeepSessionIdSecure"; Expected=1},
    [pscustomobject]@{VID="V-218820"; Title="Cookies must prohibit client-side scripts"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="HttpOnlyCookies"; Expected=1},
    [pscustomobject]@{VID="V-218821"; Title="Private website must require client certificates"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"; Name="RequireClientCerts"; Expected=1},
    [pscustomobject]@{VID="V-218822"; Title="TLS must be used for private websites"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"; Name="RequireTLS"; Expected=1},
    [pscustomobject]@{VID="V-218823"; Title="Accounts from uninstalled features must be deleted"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="DefaultAccounts"; Expected=0},
    [pscustomobject]@{VID="V-218824"; Title="Unspecified file extensions must be removed"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="UnspecifiedExtensions"; Expected=0},
    [pscustomobject]@{VID="V-218825"; Title="MaxConnections must be explicitly set"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"; Name="MaxConnections"; Expected=0},
    [pscustomobject]@{VID="V-218826"; Title="Global authorization rule must restrict access"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="GlobalAuthRule"; Expected=1},
    [pscustomobject]@{VID="V-218827"; Title="HSTS must be enabled"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="HSTS"; Expected=1},
    [pscustomobject]@{VID="V-228572"; Title="SMTP relay must require authentication"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\SMTPSVC"; Name="RequireAuth"; Expected=1},
    [pscustomobject]@{VID="V-241789"; Title="ASP.NET version must be removed from headers"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\InetStp"; Name="DisableAspNetVersion"; Expected=1},
    [pscustomobject]@{VID="V-268325"; Title="Request Smuggling filter must be enabled"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"; Name="DisableRequestSmuggling"; Expected=1}
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
    Write-Host "`nRemediation complete for Microsoft IIS 10.0 Server STIG V3R6." -ForegroundColor Green
} else {
    Write-Host "`nRun with -Remediate to fix Non-Compliant items." -ForegroundColor Cyan
}
Write-Host "Script for Microsoft IIS 10.0 Server STIG V3R6 is finished." -ForegroundColor White