<#
.SYNOPSIS
    SQL Hardening Rollback Script
    Reverts SQL Server encryption and permissions changes.
.DESCRIPTION
    This script rolls back SQL hardening:
    - Drops imported certificate
    - Disables force encryption
    - Disables TLS 1.3 config
    - Drops least privilege permissions for service account
.PARAMETER SqlServerName
    SQL server hostname (default: localhost).
.PARAMETER InstanceName
    SQL instance name (default: MSSQLSERVER).
.PARAMETER ServiceAccount
    Domain\Username to revoke permissions.
.PARAMETER DatabaseName
    SQL database to revoke access.
.NOTES
    - Run as Administrator on SQL server
    - Restart SQL service after running
    - Author: Robert Weber
.EXAMPLE
    .\Rollback-SQL-Hardening.ps1 -ServiceAccount "DOMAIN\SvcAcct" -DatabaseName "MyDB"
#>

param(
    [string]$SqlServerName = "localhost",
    [string]$InstanceName = "MSSQLSERVER",
    [Parameter(Mandatory)][string]$ServiceAccount,
    [Parameter(Mandatory)][string]$DatabaseName
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [ConsoleColor]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

# Drop certificate
Write-Log "Dropping imported certificate..." Cyan
try {
    $dropCertQuery = "DROP CERTIFICATE IISHardenCert"
    Invoke-Sqlcmd -ServerInstance "$SqlServerName\$InstanceName" -Query $dropCertQuery -ErrorAction Stop
    Write-Log "Certificate dropped" Green
} catch {
    Write-Log "Certificate drop failed: $($_.Exception.Message)" Red
}

# Disable force encryption
Write-Log "Disabling force encryption..." Cyan
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib"
    if ($InstanceName -ne "MSSQLSERVER") { $regPath = $regPath -replace 'MSSQLServer', "MSSQL.$InstanceName\MSSQLServer" }

    Set-ItemProperty $regPath -Name "Certificate" -Value ""
    Set-ItemProperty $regPath -Name "ForceEncryption" -Value 0

    Write-Log "Force encryption disabled. Restart SQL service." Yellow
} catch {
    Write-Log "Encryption disable failed: $($_.Exception.Message)" Red
}

# Disable TLS 1.3 config
Write-Log "Disabling TLS 1.3 config..." Cyan
try {
    $tlsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server"
    Set-ItemProperty $tlsPath -Name "Enabled" -Value 0 -Type DWord
    Set-ItemProperty $tlsPath -Name "DisabledByDefault" -Value 1 -Type DWord

    Write-Log "TLS 1.3 disabled. Restart SQL service." Yellow
} catch {
    Write-Log "TLS 1.3 disable failed: $($_.Exception.Message)" Red
}

# Drop permissions
Write-Log "Dropping SQL permissions..." Cyan
try {
    $dropQuery = @"
USE [$DatabaseName];
DROP USER IF EXISTS [$ServiceAccount];
DROP LOGIN IF EXISTS [$ServiceAccount];
"@
    Invoke-Sqlcmd -ServerInstance "$SqlServerName\$InstanceName" -Query $dropQuery -ErrorAction Stop
    Write-Log "Permissions dropped" Green
} catch {
    Write-Log "Permissions drop failed: $($_.Exception.Message)" Red
}

Write-Log "SQL rollback complete!" Green