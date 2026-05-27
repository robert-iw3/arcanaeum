<#
.SYNOPSIS
    Fully automated Trellix ePO 5.10.0 installation in FIPS mode (split-server)
    On Windows Server 2022/2025. This script enables Windows FIPS mode, creates
    necessary firewall rules, and launches the ePO installer with FIPS settings.

.DESCRIPTION
    This script is designed to automate the installation of Trellix ePO 5.10
    in a split-server configuration with FIPS compliance. It enables Windows FIPS mode,
    creates firewall rules for ePO communication, and launches the ePO installer with
    the necessary parameters for FIPS mode. After running this script, you will need to
    complete the installation through the ePO setup wizard, providing the SQL server details.

.PARAMETER EPOInstallerPath
    The directory where the ePO setup.exe is located.
.PARAMETER SQLServerFQDN
    The fully qualified domain name of the remote SQL server hosting the ePO database.
.PARAMETER SQLInstanceName
    The name of the SQL instance (default is MSSQLSERVER for default instance).
.PARAMETER EpoDatabaseName
    The name of the ePO database to create/use on the SQL server.
.PARAMETER SQLAuthMode
    Authentication mode to use for SQL connection (Windows or SQL).
.PARAMETER SQLLogin
    SQL login name (if using SQL authentication).
.PARAMETER SQLPassword
    SQL login password (if using SQL authentication).
.PARAMETER EnableWindowsFIPS
    Whether to enable Windows FIPS mode (recommended for full compliance).
.PARAMETER CreateFirewallRules
    Whether to create Windows Firewall rules for ePO communication (ports 80, 443, 8443).

.EXAMPLE
    .\Install-EPO-FIPS-SplitServer.ps1 -EPOInstallerPath "C:\Temp\ePO_5.10.0" -SQLServerFQDN "sql01.contoso.local" \
    -SQLInstanceName "MSSQLSERVER" -EpoDatabaseName "ePO" -SQLAuthMode "Windows" -EnableWindowsFIPS $true -CreateFirewallRules $true

.NOTES
    Author: Robert Weber
#>

param (
    # ====================== EDIT THESE ONLY ======================
    [string]$EPOInstallerPath   = "C:\Temp\ePO_5.10.0",
    [string]$SQLServerFQDN      = "sql01.contoso.local",
    [string]$SQLInstanceName    = "MSSQLSERVER",
    [string]$EpoDatabaseName    = "ePO",
    [string]$SQLAuthMode        = "Windows",   # Windows or SQL
    [string]$SQLLogin           = "",
    [string]$SQLPassword        = "",
    [bool]$EnableWindowsFIPS    = $true,
    [bool]$CreateFirewallRules  = $true
    # ============================================================
)

$ErrorActionPreference = "Stop"
$LogFile = "$env:SYSTEMDRIVE\ePO-Install\ePO-Install.log"
New-Item -Path "$env:SYSTEMDRIVE\ePO-Install" -ItemType Directory -Force | Out-Null

function Write-Log { param([string]$Msg) "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $Msg" | Tee-Object -FilePath $LogFile -Append }

Write-Log "=== Starting Trellix ePO 5.10.0 FIPS Split-Server Installation ==="

# Pre-checks
if (-not (Test-Path "$EPOInstallerPath\setup.exe")) { throw "ePO setup.exe not found!" }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators")) { throw "Run as Administrator" }

# Enable Windows FIPS
if ($EnableWindowsFIPS) {
    Write-Log "Enabling Windows FIPS mode..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "FIPSAlgorithmPolicy" -Value 1 -Type DWord
}

# Comprehensive firewall rules
if ($CreateFirewallRules) {
    $ports = "80,443,8443,1433"
    New-NetFirewallRule -DisplayName "ePO FIPS - HTTP/HTTPS/ASSC/SQL" -Direction Inbound -Protocol TCP -LocalPort $ports -Action Allow | Out-Null
    Write-Log "Firewall rules created for ports $ports"
}

# Launch ePO installer with official FIPS flag
$SetupExe = Join-Path $EPOInstallerPath "setup.exe"
Write-Log "Launching ePO 5.10.0 Setup with FIPS mode enabled..."
Start-Process -FilePath $SetupExe -ArgumentList "ENABLEFIPSMODE=1" -Wait -NoNewWindow

Write-Log "ePO installer completed. Post-install verification steps:"

# Post-install instructions (copy-paste ready)
Write-Host "`n=== ePO FIPS Installation COMPLETE ===" -ForegroundColor Green
Write-Host "1. Log into https://<epo-server>:8443" -ForegroundColor Yellow
Write-Host "2. On Database Information page use:" -ForegroundColor Yellow
Write-Host "   SQL Server : $SQLServerFQDN" -ForegroundColor White
Write-Host "   Instance   : $SQLInstanceName" -ForegroundColor White
Write-Host "   Database   : $EpoDatabaseName" -ForegroundColor White
Write-Host "   Auth       : $SQLAuthMode" -ForegroundColor White
Write-Host "`n3. Verify FIPS: Open <ePO>\DB\server.ini → confirm FipsMode=1" -ForegroundColor Cyan
Write-Host "Log file: $LogFile" -ForegroundColor White