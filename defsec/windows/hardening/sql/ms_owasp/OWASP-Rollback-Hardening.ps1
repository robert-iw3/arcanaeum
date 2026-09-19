<#
.SYNOPSIS
    Rollback script for OWASP SQL Server security hardening

.DESCRIPTION
    Restores SQL Server configuration settings to their pre-hardening state
    using a backup file created by OWASP-Backup-SQLConfig.ps1.

    Currently supports rollback of:
    - xp_cmdshell
    - CLR enabled
    - Mixed mode / Windows Authentication only
    - sa account status
    - SQL Browser service status

    Important: Dropped sample databases and linked servers are NOT automatically restored

.PARAMETER ServerName
    Required. The hostname or IP address of the SQL Server machine.

.PARAMETER InstanceName
    Optional. Named instance (leave empty for default instance).

.PARAMETER BackupFile
    Required. Full path to the backup JSON file created by the OWASP backup script.

.EXAMPLE
    .\OWASP-Rollback-Hardening.ps1 -ServerName "sqlprod01" -InstanceName "PROD" `
        -BackupFile "C:\Backups\OWASP\CurrentConfigBackup_OWASP_20260118_092145.json"

.EXAMPLE
    .\OWASP-Rollback-Hardening.ps1 -ServerName "localhost" `
        -BackupFile ".\ConfigBackupOWASP\CurrentConfigBackup_OWASP_20260117_214530.json"

.NOTES
    Requires SQLServer PowerShell module
    Requires sysadmin privileges for most SQL changes
    Authentication mode change requires SQL Server service restart
    Dropped sample databases and linked servers are intentionally NOT restored
    SQL Browser service start/stop requires administrative permissions
    Author: Robert Weber
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$ServerName,
    [string]$InstanceName = "",
    [Parameter(Mandatory=$true)]
    [string]$BackupFile
)

$FullServer = if ($InstanceName) { "$ServerName\$InstanceName" } else { $ServerName }

Import-Module SQLServer -ErrorAction Stop

if (-not (Test-Path $BackupFile)) {
    Write-Error "Backup file not found: $BackupFile"
    exit 1
}

$Backup = Get-Content $BackupFile | ConvertFrom-Json

$LogFile = Join-Path (Split-Path $BackupFile) "RollbackLog_OWASP_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

function Write-Log { param([string]$Message) Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"; Write-Host $Message }

Write-Log "Starting OWASP hardening rollback using: $BackupFile"

function Invoke-SqlCommand {
    param ([string]$Command)
    try {
        Invoke-Sqlcmd -ServerInstance $FullServer -Query $Command -TrustServerCertificate | Out-Null
        return $true
    } catch {
        Write-Log "ERROR executing: $Command → $($_.Exception.Message)"
        return $false
    }
}

# xp_cmdshell
if ($null -ne $Backup.xp_cmdshell) {
    $cmd = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', $($Backup.xp_cmdshell); RECONFIGURE;"
    if (Invoke-SqlCommand $cmd) {
        Write-Log "Restored xp_cmdshell → $($Backup.xp_cmdshell)"
    }
}

# CLR enabled
if ($null -ne $Backup.clr_enabled) {
    $cmd = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'clr enabled', $($Backup.clr_enabled); RECONFIGURE;"
    if (Invoke-SqlCommand $cmd) {
        Write-Log "Restored clr enabled → $($Backup.clr_enabled)"
    }
}

# Mixed mode authentication
# Note: This requires SMO and server restart - we only set it if we can
if ($null -ne $Backup.mixed_mode_auth) {
    $desiredMode = if ($Backup.mixed_mode_auth) {
        [Microsoft.SqlServer.Management.Smo.ServerLoginMode]::Mixed
    } else {
        [Microsoft.SqlServer.Management.Smo.ServerLoginMode]::Integrated
    }

    try {
        $smo = New-Object Microsoft.SqlServer.Management.Smo.Server $FullServer
        if ($smo.Settings.LoginMode -ne $desiredMode) {
            $smo.Settings.LoginMode = $desiredMode
            $smo.Alter()
            Write-Log "Restored authentication mode → $(if($Backup.mixed_mode_auth){'Mixed'}else{'Windows only'}) (restart required)"
        } else {
            Write-Log "Authentication mode already at desired state"
        }
    } catch {
        Write-Log "Failed to restore authentication mode: $($_.Exception.Message)"
    }
}

# sa account
if ($Backup.sa_disabled -eq $false) {  # was enabled → enable it again
    $cmd = "ALTER LOGIN sa ENABLE;"
    if (Invoke-SqlCommand $cmd) {
        Write-Log "Re-enabled sa account"
    }
}

# Sample databases - we cannot reliably restore dropped databases
# → only warning
if (-not $Backup.sample_dbs_removed) {
    Write-Log "WARNING: Sample databases were present before hardening."
    Write-Log "Automatic restoration of dropped databases is not possible."
}

# Linked servers - very dangerous to restore automatically
# → warning only
if ($Backup.linked_servers -gt 0) {
    Write-Log "WARNING: $($Backup.linked_servers) linked server(s) were present before hardening."
    Write-Log "Automatic restoration of linked servers is not implemented for safety reasons."
}

# SQL Browser service
if ($Backup.sql_browser_disabled -eq $false) {  # was enabled
    try {
        $serviceName = "SQLBrowser"
        Set-Service -Name $serviceName -ComputerName $ServerName -StartupType Automatic -ErrorAction Stop
        Start-Service -Name $serviceName -ComputerName $ServerName -ErrorAction Stop
        Write-Log "Restored SQL Browser service → Running & Automatic"
    } catch {
        Write-Log "Failed to restore SQL Browser service: $($_.Exception.Message)"
    }
}

Write-Log "OWASP rollback completed."
Write-Log "Note: Some changes (authentication mode) require SQL Server restart."
Write-Host "`nRollback finished. Check log: $LogFile" -ForegroundColor Green