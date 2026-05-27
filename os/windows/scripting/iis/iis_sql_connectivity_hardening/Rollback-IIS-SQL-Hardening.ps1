<#
.SYNOPSIS
    Rollback IIS-SQL Hardening Changes
    Restores IIS app pool identity and optionally resets SQL encryption/permissions.
.DESCRIPTION
    Reverts IIS app pool to original identity from backup.
    Optionally resets SQL force encryption and drops permissions.
.PARAMETER BackupPath
    Path to the backup folder created by Harden-IIS-SQL-SSPI.ps1.
.PARAMETER ResetSqlEncryption
    Switch to reset SQL force encryption to off and remove cert.
.PARAMETER RemoveSqlPermissions
    Switch to drop user/login for service account.
.NOTES
    - Run as Administrator
    - Restart IIS/SQL after rollback
    - Author: Robert Weber
.EXAMPLE
    .\Rollback-IIS-SQL-Hardening.ps1 -BackupPath "IIS_SQL_Backup_20260119-0349xx" -ResetSqlEncryption -RemoveSqlPermissions
#>

param(
    [Parameter(Mandatory)][string]$BackupPath,
    [switch]$ResetSqlEncryption,
    [switch]$RemoveSqlPermissions
)

$ErrorActionPreference = "Stop"

$logFile = Join-Path $BackupPath "rollback_detailed.log"

function Write-Log {
    param([string]$Message, [ConsoleColor]$Color = "White")
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "$time $Message" | Out-File -FilePath $logFile -Append -Encoding utf8
    Write-Host $Message -ForegroundColor $Color
}

# ─── PRE-FLIGHT CHECKS ──────────────────────────────────────────────────────────
try {
    Write-Log "Performing pre-flight checks..." Cyan

    if (-not (Test-Path $BackupPath -PathType Container)) { throw "Backup path not found: $BackupPath" }

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Script must run as Administrator"
    }

    Import-Module WebAdministration -ErrorAction Stop

    Write-Log "Pre-flight checks passed" Green
} catch {
    Write-Log "Pre-flight check failed: $($_.Exception.Message)" Red
    throw
}

# ─── RESTORE IIS APP POOL IDENTITY ──────────────────────────────────────────────
Write-Log "Restoring IIS app pool identity..." Cyan
try {
    $poolXml = Join-Path $BackupPath "AppPool_$AppPoolName.xml"
    if (-not (Test-Path $poolXml)) { throw "App pool backup file not found: $poolXml" }

    $poolBackup = Import-Clixml $poolXml -ErrorAction Stop

    Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name processModel.identityType -Value $poolBackup.identityType -ErrorAction Stop
    Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name processModel.userName -Value $poolBackup.userName -ErrorAction Stop
    Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name processModel.password -Value $poolBackup.password -ErrorAction Stop

    # Verify
    $currentType = (Get-ItemProperty "IIS:\AppPools\$AppPoolName" -Name processModel.identityType).Value
    if ($currentType -ne $poolBackup.identityType) { throw "Identity type verification failed" }

    Write-Log "IIS app pool identity restored and verified" Green
} catch {
    Write-Log "IIS app pool rollback failed: $($_.Exception.Message)" Red
    throw
}

# ─── OPTIONAL SQL ROLLBACK: RESET ENCRYPTION ────────────────────────────────────
if ($ResetSqlEncryption) {
    Write-Log "Resetting SQL encryption..." Yellow
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib"
        if ($InstanceName -ne "MSSQLSERVER") { $regPath = $regPath -replace 'MSSQLServer', "MSSQL.$InstanceName\MSSQLServer" }

        Set-ItemProperty $regPath -Name "Certificate" -Value "" -ErrorAction Stop
        Set-ItemProperty $regPath -Name "ForceEncryption" -Value 0 -ErrorAction Stop

        # Verify
        $currentEncryption = (Get-ItemProperty $regPath -Name "ForceEncryption").ForceEncryption
        if ($currentEncryption -ne 0) { throw "ForceEncryption verification failed" }

        Write-Log "SQL encryption reset and verified. Restart SQL." Green
    } catch {
        Write-Log "SQL encryption reset failed: $($_.Exception.Message)" Red
    }
}

# ─── OPTIONAL SQL ROLLBACK: REMOVE PERMISSIONS ──────────────────────────────────
if ($RemoveSqlPermissions) {
    Write-Log "Removing SQL permissions..." Yellow
    try {
        $revokeQuery = @"
USE [$DatabaseName];
DROP USER IF EXISTS [$ServiceAccount];
DROP LOGIN IF EXISTS [$ServiceAccount];
"@

        Invoke-Sqlcmd -ServerInstance "$SqlServerName\$InstanceName" -Query $revokeQuery -ErrorAction Stop

        # Verify (check if login exists)
        $checkLogin = Invoke-Sqlcmd -ServerInstance "$SqlServerName\$InstanceName" -Query "SELECT name FROM sys.server_principals WHERE name = '$ServiceAccount'"
        if ($checkLogin) { throw "Login drop verification failed - still exists" }

        Write-Log "SQL permissions removed and verified" Green
    } catch {
        Write-Log "SQL permissions removal failed: $($_.Exception.Message)" Red
    }
}

Write-Log "Rollback complete. Restart IIS/SQL and test." Green