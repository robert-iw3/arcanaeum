<#
.SYNOPSIS
    IIS to SQL Hardening Script - SSPI + Certificate Encryption with Backup & Test
    Configures secure connection using Windows Auth (SSPI) and TLS encryption.
.DESCRIPTION
    This script hardens IIS-SQL connectivity (IIS and SQL must be on separate servers):
    - Creates backup of current IIS config
    - Sets app pool identity for SSPI
    - Validates user-provided cert for SQL encryption
    - Instructs user to run separate SQL config script on SQL server
    - Outputs recommended connection string for web.config
    - Tests connection
.PARAMETER IisServerName
    IIS server hostname (default: localhost).
.PARAMETER SqlServerName
    SQL server hostname.
.PARAMETER InstanceName
    SQL instance name (default: MSSQLSERVER).
.PARAMETER CertPath
    Path to certificate file (.pfx or .cer).
.PARAMETER CertPassword
    SecureString password for PFX import (if needed).
.PARAMETER AppPoolName
    IIS application pool name.
.PARAMETER SiteName
    IIS website name.
.PARAMETER ServiceAccount
    Domain\Username for app pool identity.
.PARAMETER ServiceAccountPassword
    SecureString password for service account.
.PARAMETER DatabaseName
    SQL database to grant access.
.PARAMETER BackupPath
    Directory for IIS config backup (default: current dir with timestamp).
.PARAMETER SqlConfigScriptPath
    Path to separate SQL config script (default: .\Configure-SQL-For-IIS.ps1).
.NOTES
    - Run as Administrator on IIS server
    - Cert must have Server Authentication EKU
    - Restart IIS after running
    - Run Configure-SQL-For-IIS.ps1 separately on SQL server machine
    - Author: Robert Weber
.EXAMPLE
    $certPass = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
    $svcPass = ConvertTo-SecureString "SvcP@ss" -AsPlainText -Force
    .\Harden-IIS-SQL-SSPI.ps1 -SqlServerName "sql01" -CertPath "C:\certs\sqlcert.pfx" -CertPassword $certPass `
        -AppPoolName "MyAppPool" -SiteName "MySite" -ServiceAccount "DOMAIN\SvcAcct" -ServiceAccountPassword $svcPass `
        -DatabaseName "MyDB"
#>

param(
    [string]$IisServerName = "localhost",
    [Parameter(Mandatory)][string]$SqlServerName,
    [string]$InstanceName = "MSSQLSERVER",
    [Parameter(Mandatory)][string]$CertPath,
    [SecureString]$CertPassword,
    [Parameter(Mandatory)][string]$AppPoolName,
    [Parameter(Mandatory)][string]$SiteName,
    [Parameter(Mandatory)][string]$ServiceAccount,
    [Parameter(Mandatory)][SecureString]$ServiceAccountPassword,
    [Parameter(Mandatory)][string]$DatabaseName,
    [string]$BackupPath = (Join-Path $PSScriptRoot "IIS_SQL_Backup_$(Get-Date -Format 'yyyyMMdd-HHmmss')"),
    [string]$SqlConfigScriptPath = (Join-Path $PSScriptRoot "Configure-SQL-For-IIS.ps1")
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [ConsoleColor]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

# ─── PRE-FLIGHT CHECKS ──────────────────────────────────────────────────────────
try {
    Write-Log "Performing pre-flight checks..." Cyan

    if (-not (Test-Path $CertPath)) { throw "Certificate file not found: $CertPath" }
    if (-not (Get-Module -ListAvailable WebAdministration)) { throw "WebAdministration module required - install IIS Management Tools" }
    if (-not (Get-Service W3SVC -ErrorAction SilentlyContinue)) { throw "IIS service (W3SVC) not found - ensure IIS is installed and running" }
    if (-not (Test-Path $SqlConfigScriptPath)) { throw "SQL config script not found: $SqlConfigScriptPath" }

    Write-Log "Pre-flight checks passed" Green
} catch {
    Write-Log "Pre-flight check failed: $($_.Exception.Message)" Red
    throw
}

# ─── BACKUP IIS CONFIG BEFORE CHANGES ───────────────────────────────────────────
Write-Log "Creating backup of current IIS configuration..." Cyan
try {
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null

    Import-Module WebAdministration -ErrorAction Stop

    # Backup app pool identity & settings
    $poolSettings = Get-ItemProperty "IIS:\AppPools\$AppPoolName" -Name processModel.* -ErrorAction Stop
    $poolSettings | Export-Clixml "$BackupPath\AppPool_$AppPoolName.xml" -ErrorAction Stop

    # Backup site authentication settings
    $siteAuth = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $SiteName `
        -Filter "system.webServer/security/authentication/*" -Name "enabled" -ErrorAction Stop
    $siteAuth | Export-Clixml "$BackupPath\SiteAuth_$SiteName.xml" -ErrorAction Stop

    Write-Log "IIS backup created at: $BackupPath" Green
} catch {
    Write-Log "Backup failed: $($_.Exception.Message)" Red
    throw
}

# ─── VALIDATE CERTIFICATE ───────────────────────────────────────────────────────
Write-Log "Validating certificate..." Cyan
try {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath, $CertPassword)

    if ($cert.NotAfter -lt (Get-Date)) { throw "Certificate expired" }
    if ($cert.NotBefore -gt (Get-Date)) { throw "Certificate not yet valid" }
    $serverAuthEku = $cert.EnhancedKeyUsageList | Where-Object { $_.Oid.Value -eq "1.3.6.1.5.5.7.3.1" }
    if (-not $serverAuthEku) { throw "Missing Server Authentication EKU" }
    if (-not $cert.Verify()) { throw "Certificate chain validation failed" }

    Write-Log "Certificate validated successfully" Green
} catch {
    Write-Log "Certificate validation failed: $($_.Exception.Message)" Red
    throw
}

# ─── CONFIGURE SQL SERVER (USER INSTRUCTION FOR SEPARATE SERVER) ─────────────────
Write-Log "SQL Server is on a separate machine ($SqlServerName)." Yellow
Write-Log "Please run the following on the SQL server:" Yellow
Write-Log ".\Configure-SQL-For-IIS.ps1 -CertPath <copy cert to SQL> -CertPassword <password> -ServiceAccount `"$ServiceAccount`" -DatabaseName `"$DatabaseName`"" Yellow

$confirmSql = Read-Host "Confirm SQL configuration is complete on $SqlServerName? (Y/N)"
if ($confirmSql -ne "Y") {
    throw "SQL configuration not confirmed - aborting"
}

Write-Log "SQL configuration confirmed" Green

# ─── SET IIS APP POOL IDENTITY ──────────────────────────────────────────────────
Write-Log "Setting IIS app pool identity..." Cyan
try {
    Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name processModel.identityType -Value 3  # SpecificUser
    Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name processModel.userName -Value $ServiceAccount
    Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name processModel.password -Value ($ServiceAccountPassword | ConvertFrom-SecureString -AsPlainText)

    # Verify
    $newIdentity = (Get-ItemProperty "IIS:\AppPools\$AppPoolName" -Name processModel.userName).Value
    if ($newIdentity -ne $ServiceAccount) { throw "App pool identity not set correctly" }
    Write-Log "App pool identity set to $ServiceAccount" Green
} catch {
    Write-Log "App pool config failed: $($_.Exception.Message)" Red
    throw
}

# ─── TEST SECURE CONNECTION ─────────────────────────────────────────────────────
Write-Log "Testing secure SQL connection..." Cyan
try {
    $testQuery = "SELECT 1 AS Test"
    Invoke-Sqlcmd -ServerInstance "$SqlServerName\$InstanceName" -Database $DatabaseName -Query $testQuery `
        -TrustServerCertificate:$false -EncryptConnection -ErrorAction Stop | Out-Null

    Write-Log "Connection test successful (as current user)" Green
} catch {
    Write-Log "Connection test failed: $($_.Exception.Message)" Red
    throw
}

# ─── OUTPUT CONNECTION STRING ───────────────────────────────────────────────────
Write-Log "Recommended connection string for web.config:" Yellow
Write-Log "Server=$SqlServerName\$InstanceName;Database=$DatabaseName;Integrated Security=SSPI;Encrypt=Yes;TrustServerCertificate=No;" Yellow
Write-Log "Update manually and restart IIS app pool." Yellow

Write-Log "Hardening complete! Restart IIS and test applications." Green