<#
.SYNOPSIS
    Backup current SQL Server security-relevant configuration (OWASP focus)

.DESCRIPTION
    Captures current state of key OWASP-recommended configuration settings
    before hardening. Creates a timestamped JSON backup file.

.PARAMETER ServerName
    Required. The hostname or IP address of the SQL Server machine.

.PARAMETER InstanceName
    Optional. Named instance (leave empty for default).

.PARAMETER BackupPath
    Directory where the configuration backup JSON will be saved.
    Defaults to .\ConfigBackupOWASP

.EXAMPLE
    .\OWASP-Backup-SQLConfig.ps1 -ServerName "sqlprod01" -InstanceName "INST1"

.NOTES
    Requires SQLServer module and appropriate permissions
    Author: Robert Weber
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$ServerName,
    [string]$InstanceName = "",
    [string]$BackupPath = ".\ConfigBackupOWASP"
)

$FullServer = if ($InstanceName) { "$ServerName\$InstanceName" } else { $ServerName }

Import-Module SQLServer -ErrorAction Stop

New-Item -ItemType Directory -Force -Path $BackupPath | Out-Null

$BackupFile = Join-Path $BackupPath "CurrentConfigBackup_OWASP_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$LogFile     = Join-Path $BackupPath "BackupLog_OWASP.txt"

function Write-Log { param([string]$Message) Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"; Write-Host $Message }

Write-Log "Starting OWASP configuration backup for $FullServer"

$BackupConfig = @{}

function Get-CurrentValue {
    param ([string]$ConfigName)
    switch ($ConfigName) {
        "xp_cmdshell" {
            $q = "SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'"
            $r = Invoke-Sqlcmd -ServerInstance $FullServer -Query $q -TrustServerCertificate
            return $r.value_in_use
        }
        "clr_enabled" {
            $q = "SELECT value_in_use FROM sys.configurations WHERE name = 'clr enabled'"
            $r = Invoke-Sqlcmd -ServerInstance $FullServer -Query $q -TrustServerCertificate
            return $r.value_in_use
        }
        "mixed_mode_auth" {
            $q = "SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS AuthMode"
            $r = Invoke-Sqlcmd -ServerInstance $FullServer -Query $q -TrustServerCertificate
            return $r.AuthMode -eq 0  # 0 = Mixed mode (true = mixed enabled)
        }
        "sa_disabled" {
            $q = "SELECT is_disabled FROM sys.sql_logins WHERE name = 'sa'"
            $r = Invoke-Sqlcmd -ServerInstance $FullServer -Query $q -TrustServerCertificate
            return $r.is_disabled -eq 0  # 0 = enabled
        }
        "sample_dbs_removed" {
            $q = "SELECT COUNT(*) AS Count FROM sys.databases WHERE name IN ('Northwind','AdventureWorks','AdventureWorksDW')"
            $r = Invoke-Sqlcmd -ServerInstance $FullServer -Query $q -TrustServerCertificate
            return $r.Count -eq 0
        }
        "linked_servers" {
            $q = "SELECT COUNT(*) AS Count FROM sys.servers WHERE is_linked = 1 AND server_id <> 0"
            $r = Invoke-Sqlcmd -ServerInstance $FullServer -Query $q -TrustServerCertificate
            return $r.Count
        }
        "sql_browser_disabled" {
            $service = Get-Service -Name "SQLBrowser" -ComputerName $ServerName -ErrorAction SilentlyContinue
            if ($service) {
                return ($service.Status -eq "Stopped") -and ($service.StartType -eq "Disabled")
            }
            return $false
        }
        default { "N/A" }
    }
}

$configsToBackup = @(
    "xp_cmdshell",
    "clr_enabled",
    "mixed_mode_auth",
    "sa_disabled",
    "sample_dbs_removed",
    "linked_servers",
    "sql_browser_disabled"
)

foreach ($cfg in $configsToBackup) {
    $value = Get-CurrentValue $cfg
    $BackupConfig[$cfg] = $value
    Write-Log "Backed up $cfg : $value"
}

# Save backup
$BackupConfig | ConvertTo-Json -Depth 5 | Out-File -FilePath $BackupFile -Encoding UTF8
Write-Log "OWASP configuration backup saved to: $BackupFile"

Write-Host "`nBackup file created: $BackupFile" -ForegroundColor Green
Write-Log "Backup completed successfully."