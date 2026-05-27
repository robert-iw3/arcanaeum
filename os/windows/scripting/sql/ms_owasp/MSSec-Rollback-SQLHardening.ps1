<#
.SYNOPSIS
    Rollback script for Microsoft SQL Server security hardening

.DESCRIPTION
    Restores SQL Server configuration settings to their pre-hardening state
    using a backup file created by Backup-SQLConfig-MS.ps1.

    Currently supports rollback of:
    - Force Protocol Encryption
    - OLE Automation Procedures
    - Remote Access
    - Contained Database Authentication
    - Extended Protection (registry)

    Important: TLS registry rollback is intentionally NOT automated for safety reasons.

.PARAMETER ServerName
    Required. The hostname or IP address of the SQL Server machine.

.PARAMETER InstanceName
    Optional. Named instance (leave empty for default MSSQLSERVER instance).

.PARAMETER BackupFile
    Required. Full path to the backup JSON file created by the backup script.

.EXAMPLE
    .\MSSec-Rollback-SQLHardening-MS.ps1 -ServerName "sqlprod01" -InstanceName "INST1" `
        -BackupFile "C:\Backups\ConfigBackupMS\CurrentConfigBackup_20260118_143022.json"

.EXAMPLE
    .\MSSec-Rollback-SQLHardening-MS.ps1 -ServerName "localhost" `
        -BackupFile ".\ConfigBackupMS\CurrentConfigBackup_20260117_221500.json"

.NOTES
    Requires SQLServer PowerShell module
    Requires sysadmin privileges for SQL configuration changes
    Requires administrative privileges for registry modifications
    Some restored settings (Force Encryption, Extended Protection) require SQL Server restart
    TLS settings are logged but NOT automatically restored
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
$LogFile = Join-Path (Split-Path $BackupFile) "RollbackLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

function Write-Log { param([string]$Message) Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"; Write-Host $Message }

Write-Log "Starting rollback using backup: $BackupFile"

function Invoke-SqlCommand {
    param ([string]$Command)
    try {
        Invoke-Sqlcmd -ServerInstance $FullServer -Query $Command -TrustServerCertificate | Out-Null
        return $true
    } catch {
        Write-Log "ERROR: $Command - $($_.Exception.Message)"
        return $false
    }
}

# Restore SQL configurations
if ($Backup.force_encryption -eq $false) {
    try {
        $smo = New-Object Microsoft.SqlServer.Management.Smo.Server $FullServer
        $smo.Settings.ForceProtocolEncryption = $false
        $smo.Alter()
        Write-Log "Restored Force Encryption → Disabled (restart required)"
    } catch {
        Write-Log "Failed to restore Force Encryption: $($_.Exception.Message)"
    }
}

if ($Backup.ole_automation_disabled -eq $false) {
    Invoke-SqlCommand "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;"
    Write-Log "Restored OLE Automation Procedures → Enabled"
}

if ($Backup.remote_access_disabled -eq $false) {
    Invoke-SqlCommand "EXEC sp_configure 'remote access', 1; RECONFIGURE;"
    Write-Log "Restored remote access → Enabled"
}

if ($Backup.contained_db_auth -eq $true) {
    Invoke-SqlCommand "EXEC sp_configure 'contained database authentication', 1; RECONFIGURE;"
    Write-Log "Restored contained database authentication → Enabled"
}

# Note: server_audit_enabled rollback is complex (would require disabling specific audits)
# → We skip automatic rollback here; review manually if needed

# Registry-based rollback (Extended Protection)
if ($Backup.extended_protection -and $Backup.extended_protection -ne "Not Configured") {
    $regPath = if ($InstanceName) {
        "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer.$InstanceName\MSSQLServer"
    } else { "HKLM:\SOFTWARE\Microsoft\MSSQLServer\MSSQLServer" }

    $valueMap = @{ "Off"=0; "Allowed"=1; "Required"=2 }
    $targetValue = $valueMap[$Backup.extended_protection]

    if ($null -ne $targetValue) {
        try {
            Set-ItemProperty -Path $regPath -Name "ExtendedProtection" -Value $targetValue -Type DWord -Force
            Write-Log "Restored Extended Protection → $($Backup.extended_protection) (restart required)"
        } catch {
            Write-Log "Failed to restore Extended Protection: $($_.Exception.Message)"
        }
    }
}

# TLS rollback is **very dangerous** → we only warn/log
if ($Backup.tls_version) {
    Write-Log "WARNING: TLS registry settings detected in backup."
    Write-Log "Automatic TLS rollback is NOT performed for safety reasons."
    Write-Log "Review backup file and restore Schannel registry keys manually if needed."
    Write-Log "Original TLS state:"
    $Backup.tls_version | ConvertTo-Json -Depth 3
}

Write-Log "Rollback completed. Review log file: $LogFile"
Write-Log "Some changes (Force Encryption, Extended Protection) require SQL Server restart."
Write-Host "`nRollback finished. Check log: $LogFile" -ForegroundColor Green