<#
.SYNOPSIS
    Backup current SQL Server security-relevant configuration (Microsoft focus)

.DESCRIPTION
    Captures current state of important security-related configuration settings
    before hardening. Creates a timestamped JSON backup file that can be used
    for documentation or rollback purposes.

.PARAMETER ServerName
    Required. The hostname or IP address of the SQL Server machine.

.PARAMETER InstanceName
    Optional. Named instance (leave empty for default).

.PARAMETER BackupPath
    Directory where the configuration backup JSON will be saved.
    Defaults to .\ConfigBackupMS

.EXAMPLE
    .\MSSec-Backup-SQLConfig.ps1 -ServerName "sqlprod01" -InstanceName "PROD"

.NOTES
    Requires SQLServer module and appropriate permissions
    Backs up a selected subset of security-relevant settings
    Author: Robert Weber
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$ServerName,
    [string]$InstanceName = "",
    [string]$BackupPath = ".\ConfigBackupMS"
)

$FullServer = if ($InstanceName) { "$ServerName\$InstanceName" } else { $ServerName }

Import-Module SQLServer -ErrorAction Stop

New-Item -ItemType Directory -Force -Path $BackupPath | Out-Null

$BackupFile = Join-Path $BackupPath "CurrentConfigBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$LogFile     = Join-Path $BackupPath "BackupLog.txt"

function Write-Log { param([string]$Message) Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"; Write-Host $Message }

Write-Log "Starting configuration backup for $FullServer"

$BackupConfig = @{}

# Helper to query current values (same as in hardening script)
function Get-CurrentValue {
    param ([string]$ConfigName)
    switch ($ConfigName) {
        "force_encryption" {
            $smo = New-Object Microsoft.SqlServer.Management.Smo.Server $FullServer
            return $smo.ConnectionContext.EncryptConnection
        }
        "ole_automation_disabled" {
            $q = "SELECT value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures'"
            $r = Invoke-Sqlcmd -ServerInstance $FullServer -Query $q -TrustServerCertificate
            return $r.value_in_use -eq 0
        }
        "remote_access_disabled" {
            $q = "SELECT value_in_use FROM sys.configurations WHERE name = 'remote access'"
            $r = Invoke-Sqlcmd -ServerInstance $FullServer -Query $q -TrustServerCertificate
            return $r.value_in_use -eq 0
        }
        "contained_db_auth" {
            $q = "SELECT value_in_use FROM sys.configurations WHERE name = 'contained database authentication'"
            $r = Invoke-Sqlcmd -ServerInstance $FullServer -Query $q -TrustServerCertificate
            return $r.value_in_use -eq 1
        }
        "server_audit_enabled" {
            $q = "SELECT COUNT(*) AS C FROM sys.server_audits WHERE is_state_enabled = 1"
            $r = Invoke-Sqlcmd -ServerInstance $FullServer -Query $q -TrustServerCertificate
            return $r.C -gt 0
        }
        "extended_protection" {
            $regPath = if ($InstanceName) {
                "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer.$InstanceName\MSSQLServer"
            } else { "HKLM:\SOFTWARE\Microsoft\MSSQLServer\MSSQLServer" }
            try {
                $val = (Get-ItemProperty -Path $regPath -Name "ExtendedProtection" -ErrorAction Stop).ExtendedProtection
                switch ($val) { 0 {"Off"} 1 {"Allowed"} 2 {"Required"} default {"Unknown"} }
            } catch { "Not Configured" }
        }
        "tls_version" {
            $keys = @(
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
            )
            $state = @{}
            foreach ($k in $keys) {
                $name = $k.Split('\')[-2]
                try { $state[$name] = (Get-ItemProperty -Path $k -Name "Enabled").Enabled -eq 1 } catch { $state[$name] = $null }
            }
            return $state
        }
        default { "N/A" }
    }
}

$configsToBackup = @(
    "force_encryption", "ole_automation_disabled", "remote_access_disabled",
    "contained_db_auth", "server_audit_enabled", "extended_protection", "tls_version"
)

foreach ($cfg in $configsToBackup) {
    $BackupConfig[$cfg] = Get-CurrentValue $cfg
    Write-Log "Backed up $cfg : $($BackupConfig[$cfg])"
}

# Save backup
$BackupConfig | ConvertTo-Json -Depth 5 | Out-File -FilePath $BackupFile -Encoding UTF8
Write-Log "Configuration backup saved to: $BackupFile"

Write-Log "Backup completed successfully."
Write-Host "`nBackup file created: $BackupFile" -ForegroundColor Green