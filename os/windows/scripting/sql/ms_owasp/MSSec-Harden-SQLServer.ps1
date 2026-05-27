<#
.SYNOPSIS
    SQL Server Hardening Script for Microsoft Security Best Practices
    Automatically performs configuration backup before applying changes.

.DESCRIPTION
    Applies Microsoft-recommended security configurations from the specified JSON file.
    Automatically runs the backup script before making any changes.
    Many advanced security features (TDE, gMSA, TLS registry, data classification)
    require manual implementation steps.

.PARAMETER ServerName
    Required. The hostname or IP address of the SQL Server machine.

.PARAMETER InstanceName
    Optional. Named instance (leave empty for default instance).

.PARAMETER ConfigPath
    Path to the hardening configuration JSON file.
    Defaults to .\MSSec-HardeningConfig.json

.PARAMETER BackupScriptPath
    Path to the backup script.
    Defaults to .\MSSec-Backup-SQLConfig.ps1

.PARAMETER BackupOutputDir
    Directory where configuration backups will be stored.
    Defaults to .\ConfigBackupMS

.PARAMETER SkipBackup
    Switch to skip automatic backup (strongly discouraged in production).

.EXAMPLE
    .\MSSec-Harden-SQLServer.ps1 -ServerName "sqlprod01" -InstanceName "INST1"

.EXAMPLE
    .\MSSec-Harden-SQLServer.ps1 -ServerName "localhost" -ConfigPath "C:\Configs\MSSec-HardeningConfig.json" -BackupOutputDir "C:\SQLBackups"

.NOTES
    Requires SQLServer PowerShell module and sysadmin + administrative privileges
    Some changes (Force Encryption, Extended Protection) require SQL Server restart
    Many security features (TDE, gMSA, TLS registry, data classification) require manual steps
    Author: Robert Weber
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$ServerName,

    [string]$InstanceName = "",

    [string]$ConfigPath = ".\MSSec-HardeningConfig.json",

    # Backup parameters
    [string]$BackupScriptPath = ".\MSSec-Backup-SQLConfig.ps1",
    [string]$BackupOutputDir  = ".\ConfigBackupMS",
    [switch]$SkipBackup = $false
)

# Construct full server\instance name
$FullServer = if ($InstanceName) { "$ServerName\$InstanceName" } else { $ServerName }

# Import required module
try {
    Import-Module SQLServer -ErrorAction Stop
} catch {
    Write-Error "SQLServer PowerShell module not found. Install it with: Install-Module -Name SqlServer"
    exit 1
}

# Prepare output directory for hardening results
$OutputPath = ".\HardenResultsMS"
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

# Output files
$LogFile   = Join-Path $OutputPath "HardenLogMS_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$ReportCsv = Join-Path $OutputPath "HardenReportMS_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

# Logging function
function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ConsoleColor]$Color = 'White'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logLine = "$timestamp - $Message"
    Add-Content -Path $LogFile -Value $logLine -Encoding UTF8
    Write-Host $logLine -ForegroundColor $Color
}

Write-Log "====================================================================" -Color Cyan
Write-Log "Starting Microsoft SQL Server Best Practices Hardening" -Color Cyan
Write-Log "Target server: $FullServer" -Color Cyan
Write-Log "Configuration file: $ConfigPath" -Color Cyan
Write-Log "Started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Color Cyan
Write-Log "====================================================================" -Color Cyan

# -------------------------------------------------------------------------
# PHASE 0: AUTOMATIC CONFIGURATION BACKUP (SAFETY FIRST)
# -------------------------------------------------------------------------
if (-not $SkipBackup) {
    Write-Log "Performing automatic configuration backup BEFORE any hardening..." -Color Yellow

    if (-not (Test-Path $BackupScriptPath -PathType Leaf)) {
        Write-Log "CRITICAL: Backup script not found at path: $BackupScriptPath" -Color Red
        Write-Log "Hardening process aborted for safety reasons." -Color Red
        Write-Error "Cannot continue without valid backup. Please specify correct -BackupScriptPath parameter."
        exit 1
    }

    try {
        $backupParams = @{
            ServerName   = $ServerName
            InstanceName = $InstanceName
            BackupPath   = $BackupOutputDir
        }

        Write-Log "Launching backup script: $BackupScriptPath" -Color Yellow
        Write-Log "Backup target directory: $BackupOutputDir" -Color Yellow

        # Execute backup script
        & $BackupScriptPath @backupParams 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                Write-Log "BACKUP ERROR : $_" -Color Red
            } else {
                Write-Log "BACKUP OUTPUT: $_" -Color DarkGray
            }
        }

        if ($LASTEXITCODE -ne 0) {
            Write-Log "Backup script returned exit code $LASTEXITCODE - assuming failure" -Color Red
            Write-Log "Hardening process aborted to prevent unrecoverable changes." -Color Red
            exit 1
        }

        Write-Log "Configuration backup completed successfully" -Color Green
        Write-Log "Backups should be located in: $BackupOutputDir" -Color Green
    }
    catch {
        Write-Log "Exception while running backup script: $($_.Exception.Message)" -Color Red
        Write-Log "Hardening aborted for safety reasons." -Color Red
        exit 1
    }
}
else {
    Write-Log "!!! BACKUP STEP SKIPPED VIA -SkipBackup PARAMETER !!!" -Color Magenta
    Write-Log "This is extremely dangerous in production environments!" -Color Magenta
    Start-Sleep -Seconds 5
}

# -------------------------------------------------------------------------
# PHASE 1: Load hardening configuration
# -------------------------------------------------------------------------
if (-not (Test-Path $ConfigPath -PathType Leaf)) {
    Write-Log "Hardening configuration file not found: $ConfigPath" -Color Red
    exit 1
}

try {
    $HardeningConfig = Get-Content $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    Write-Log "Successfully loaded hardening configuration from $ConfigPath" -Color Green
}
catch {
    Write-Log "Failed to parse hardening configuration JSON: $($_.Exception.Message)" -Color Red
    exit 1
}

# -------------------------------------------------------------------------
# PHASE 2: Prepare reporting
# -------------------------------------------------------------------------
$Report = @()

# Helper - execute SQL command (modification)
function Invoke-SqlCommand {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [switch]$IgnoreErrors
    )
    try {
        Invoke-Sqlcmd -ServerInstance $FullServer -Query $Command -TrustServerCertificate -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        if (-not $IgnoreErrors) {
            Write-Log "SQL Command failed: $Command" -Color Red
            Write-Log "Error: $($_.Exception.Message)" -Color Red
        }
        return $false
    }
}

# Helper - get current configuration value
function Get-ConfigValue {
    param ([string]$ConfigName)

    switch ($ConfigName) {
        "tde_enabled" {
            $query = @"
SELECT
    COUNT(CASE WHEN is_encrypted = 1 AND encryption_state IN (3,4) THEN 1 END) AS EncryptedDBs,
    COUNT(*) - COUNT(CASE WHEN is_encrypted = 1 AND encryption_state IN (3,4) THEN 1 END) AS NotEncryptedDBs
FROM sys.databases d
LEFT JOIN sys.dm_database_encryption_keys k ON d.database_id = k.database_id
WHERE d.database_id > 4
"@
            $r = Invoke-SqlQuery $query
            return ($r.EncryptedDBs -gt 0) -and ($r.NotEncryptedDBs -eq 0)
        }

        "force_encryption" {
            try {
                $smo = New-Object Microsoft.SqlServer.Management.Smo.Server $FullServer
                return $smo.Settings.ForceProtocolEncryption
            } catch { return $false }
        }

        "server_audit_enabled" {
            $r = Invoke-SqlQuery "SELECT COUNT(*) AS C FROM sys.server_audits WHERE is_state_enabled = 1"
            return $r.C -gt 0
        }

        "ole_automation_disabled" {
            $r = Invoke-SqlQuery "SELECT value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures'"
            return $r.value_in_use -eq 0
        }

        "remote_access_disabled" {
            $r = Invoke-SqlQuery "SELECT value_in_use FROM sys.configurations WHERE name = 'remote access'"
            return $r.value_in_use -eq 0
        }

        "contained_db_auth" {
            $r = Invoke-SqlQuery "SELECT value_in_use FROM sys.configurations WHERE name = 'contained database authentication'"
            return $r.value_in_use -eq 1
        }

        "gmsa_service_account" {
            $svcName = if ($InstanceName) { "MSSQL`$$InstanceName" } else { "MSSQLSERVER" }
            $svc = Get-Service -Name $svcName -ComputerName $ServerName -ErrorAction SilentlyContinue
            return $svc.StartName -like "*`$*"   # rough gMSA detection
        }

        "extended_protection" {
            $regPath = if ($InstanceName) {
                "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer.$InstanceName\MSSQLServer"
            } else {
                "HKLM:\SOFTWARE\Microsoft\MSSQLServer\MSSQLServer"
            }
            try {
                $val = (Get-ItemProperty -Path $regPath -Name "ExtendedProtection" -EA Stop).ExtendedProtection
                switch ($val) { 0 {"Off"} 1 {"Allowed"} 2 {"Required"} default {"Unknown"} }
            } catch { "Not Configured" }
        }

        "data_classification" {
            $r = Invoke-SqlQuery "SELECT COUNT(*) AS C FROM sys.sensitivity_labels"
            return $r.C -gt 0
        }

        "tls_version" {
            $keys = @(
                @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"; Expected=$false},
                @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"; Expected=$false},
                @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"; Expected=$true}
            )
            $compliant = $true
            foreach ($k in $keys) {
                try {
                    $v = (Get-ItemProperty -Path $k.Path -Name "Enabled" -EA Stop).Enabled -eq 1
                    if ($v -ne $k.Expected) { $compliant = $false }
                } catch {
                    $compliant = $false
                }
            }
            return if ($compliant) { "1.2 Compliant" } else { "Non-compliant" }
        }

        "backup_encrypted" {
            $r = Invoke-SqlQuery "SELECT TOP 1 is_encrypted FROM msdb.dbo.backupset ORDER BY backup_finish_date DESC"
            return $r.is_encrypted -eq 1
        }

        default { return "N/A" }
    }
}

# Helper - SQL query wrapper
function Invoke-SqlQuery {
    param ([string]$Query)
    try {
        return Invoke-Sqlcmd -ServerInstance $FullServer -Query $Query -TrustServerCertificate -ErrorAction Stop
    } catch {
        Write-Log "Query failed: $Query" -Color DarkRed
        Write-Log $_.Exception.Message -Color DarkRed
        return $null
    }
}

# -------------------------------------------------------------------------
# PHASE 3: Apply hardening recommendations
# -------------------------------------------------------------------------
Write-Log "Beginning configuration hardening..." -Color Yellow

foreach ($prop in $HardeningConfig.PSObject.Properties) {
    $configName   = $prop.Name
    $recommended  = $prop.Value
    $beforeValue  = Get-ConfigValue $configName
    $success      = $false
    $changeDetail = ""

    Write-Log "Processing: $configName (Recommended: $recommended)" -Color Cyan

    switch ($configName) {
        "tde_enabled" {
            $changeDetail = "TDE requires manual certificate creation and per-database encryption. Cannot be fully automated."
            $success = $false
        }

        "force_encryption" {
            if ($recommended -eq $true) {
                try {
                    $smo = New-Object Microsoft.SqlServer.Management.Smo.Server $FullServer
                    $smo.Settings.ForceProtocolEncryption = $true
                    $smo.Alter()
                    $changeDetail = "Force Protocol Encryption enabled. SQL Server restart required."
                    $success = $true
                } catch {
                    $changeDetail = "Failed: $($_.Exception.Message)"
                }
            }
        }

        "server_audit_enabled" {
            if ($recommended -eq $true) {
                $auditName = "Security_Baseline_Audit"
                $auditPath = "C:\SQLAudit\"
                $cmd = @"
IF NOT EXISTS (SELECT * FROM sys.server_audits WHERE name = '$auditName')
BEGIN
    CREATE SERVER AUDIT [$auditName]
    TO FILE (FILEPATH = '$auditPath', MAXSIZE = 50 MB, MAX_ROLLOVER_FILES = 10)
    WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);
END

ALTER SERVER AUDIT [$auditName] WITH (STATE = ON);
"@
                if (Invoke-SqlCommand $cmd) {
                    $changeDetail = "Basic server audit '$auditName' created/enabled"
                    $success = $true
                }
            }
        }

        "ole_automation_disabled" {
            if ($recommended -eq $true) {
                $cmd = @"
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 0;
RECONFIGURE;
"@
                $success = Invoke-SqlCommand $cmd
                $changeDetail = if ($success) { "Disabled" } else { "Failed to disable" }
            }
        }

        "remote_access_disabled" {
            if ($recommended -eq $true) {
                $cmd = "EXEC sp_configure 'remote access', 0; RECONFIGURE;"
                $success = Invoke-SqlCommand $cmd
                $changeDetail = if ($success) { "Disabled" } else { "Failed" }
            }
        }

        "contained_db_auth" {
            if ($recommended -eq $false) {
                $cmd = "EXEC sp_configure 'contained database authentication', 0; RECONFIGURE;"
                $success = Invoke-SqlCommand $cmd
                $changeDetail = if ($success) { "Disabled" } else { "Failed" }
            }
        }

        "gmsa_service_account" {
            if ($recommended -eq $true) {
                $changeDetail = "Group Managed Service Account configuration requires Active Directory and manual service account change."
                $success = $false
            }
        }

        "extended_protection" {
            if ($recommended -eq "Required") {
                $changeDetail = "Extended Protection must be set via registry (ExtendedProtection = 2) and SQL Server restarted. Manual step required."
                $success = $false
            }
        }

        "data_classification" {
            if ($recommended -eq $true) {
                $changeDetail = "Sensitivity labels must be applied manually via SSMS or T-SQL (ADD SENSITIVITY LABEL). Cannot be automated globally."
                $success = $false
            }
        }

        "tls_version" {
            if ($recommended -eq "1.2") {
                $changeDetail = @"
TLS 1.2+ enforcement requires:
• Disable TLS 1.0/1.1 in Windows Schannel registry
• Enable TLS 1.2
• Restart SQL Server
Manual configuration required.
"@
                $success = $false
            }
        }

        "backup_encrypted" {
            if ($recommended -eq $true) {
                $changeDetail = "Future backups should use WITH ENCRYPTION or be protected via TDE. Existing backups not affected. Manual process."
                $success = $false
            }
        }

        default {
            $changeDetail = "No action defined for this setting"
            $success = $false
        }
    }

    $afterValue = Get-ConfigValue $configName

    $Report += [PSCustomObject]@{
        ConfigurationItem = $configName
        RecommendedValue  = $recommended
        ValueBefore       = $beforeValue
        ValueAfter        = $afterValue
        Success           = $success
        Status            = if ($success) { "Success" } else { "Failed / Manual" }
        Details           = $changeDetail
        Timestamp         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }

    $color = if ($success) { "Green" } else { "Yellow" }
    Write-Log "[$($Report[-1].Status)] $configName → $changeDetail" -Color $color
}

# -------------------------------------------------------------------------
# PHASE 4: Final reporting
# -------------------------------------------------------------------------
$Report | Export-Csv -Path $ReportCsv -NoTypeInformation -Encoding UTF8
Write-Log "Hardening report saved to: $ReportCsv" -Color Green

Write-Log "====================================================================" -Color Cyan
Write-Log "Hardening process completed" -Color Cyan
Write-Log "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Color Cyan
Write-Log "Important: Review manual steps (TDE, TLS, Extended Protection, gMSA, data classification)" -Color Yellow
Write-Log "Some changes require SQL Server service restart" -Color Yellow
Write-Log "Backup location (should exist): $BackupOutputDir" -Color Green
Write-Log "====================================================================" -Color Cyan

Write-Host "`nHardening process finished." -ForegroundColor Green
Write-Host "Backup directory (if successful): $BackupOutputDir" -ForegroundColor Green
Write-Host "Detailed report: $ReportCsv" -ForegroundColor Green
Write-Host "Log file: $LogFile" -ForegroundColor Green