<#
.SYNOPSIS
    SQL Server Hardening Script based on OWASP Database Security Cheat Sheet

.DESCRIPTION
    Applies recommended security configurations based on OWASP guidelines
    using values from OWASP-HardeningConfig.json.

    IMPORTANT: This version automatically performs a configuration backup
    BEFORE applying any hardening changes using the companion backup script.

.PARAMETER ServerName
    Required. The hostname or IP address of the SQL Server machine.

.PARAMETER InstanceName
    Optional. The named instance (leave empty for default instance).

.PARAMETER ConfigPath
    Path to the hardening configuration JSON file.
    Defaults to .\OWASP-HardeningConfig.json

.PARAMETER OutputPath
    Directory for hardening results (report CSV and log).
    Defaults to .\HardenResultsOWASP

.PARAMETER BackupScriptPath
    Path to the OWASP backup script (Backup-SQLConfig-OWASP.ps1).
    Defaults to .\Backup-SQLConfig-OWASP.ps1

.PARAMETER BackupOutputDir
    Directory where configuration backups will be stored.
    Defaults to .\ConfigBackupOWASP

.PARAMETER SkipBackup
    Switch to skip the automatic backup step (strongly discouraged in production).

.EXAMPLE
    .\OWASP-Harden-SQLServer.ps1 -ServerName "sqlprod01" -InstanceName "PROD"

.EXAMPLE
    .\OWASP-Harden-SQLServer.ps1 -ServerName "localhost" `
        -ConfigPath "C:\Configs\owasp-prod.json" `
        -BackupOutputDir "C:\Backups\OWASP"

.EXAMPLE
    .\OWASP-Harden-SQLServer.ps1 -ServerName "sqltest01" -SkipBackup -Verbose

.NOTES
    Requires SQLServer PowerShell module and sysadmin privileges
    Authentication mode changes require SQL Server restart
    Service account changes are not automated (manual only)
    Dropping linked servers is intentionally skipped for safety
    Automatic backup is highly recommended before any hardening
    Author: Robert Weber
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$ServerName,

    [string]$InstanceName = "",

    [string]$ConfigPath = ".\OWASP-HardeningConfig.json",

    [string]$OutputPath = ".\HardenResultsOWASP",

    # === Backup parameters (new) ===
    [string]$BackupScriptPath = ".\OWASP-Backup-SQLConfig.ps1",
    [string]$BackupOutputDir  = ".\ConfigBackupOWASP",
    [switch]$SkipBackup = $false
)

# Construct full server instance name
$FullServer = if ($InstanceName) { "$ServerName\$InstanceName" } else { $ServerName }

# Import required module
try {
    Import-Module SQLServer -ErrorAction Stop
} catch {
    Write-Error "SQLServer PowerShell module not found. Install with: Install-Module SqlServer"
    exit 1
}

# Create output directory for hardening results
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

# Output files
$LogFile   = Join-Path $OutputPath "HardenLog_OWASP_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$ReportCsv = Join-Path $OutputPath "HardenReport_OWASP_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

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
Write-Log "Starting OWASP SQL Server Hardening" -Color Cyan
Write-Log "Target server: $FullServer" -Color Cyan
Write-Log "Configuration file: $ConfigPath" -Color Cyan

# -------------------------------------------------------------------------
# PHASE 0: AUTOMATIC BACKUP BEFORE ANY CHANGES
# -------------------------------------------------------------------------
if (-not $SkipBackup) {
    Write-Log "Performing automatic configuration backup BEFORE hardening..." -Color Yellow

    if (-not (Test-Path $BackupScriptPath -PathType Leaf)) {
        Write-Log "CRITICAL: Backup script not found: $BackupScriptPath" -Color Red
        Write-Log "Hardening process aborted for safety reasons." -Color Red
        Write-Error "Cannot continue without valid backup script."
        exit 1
    }

    try {
        $backupParams = @{
            ServerName   = $ServerName
            InstanceName = $InstanceName
            BackupPath   = $BackupOutputDir
        }

        Write-Log "Executing backup script: $BackupScriptPath" -Color Yellow

        & $BackupScriptPath @backupParams 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                Write-Log "BACKUP ERROR: $_" -Color Red
            } else {
                Write-Log "BACKUP: $_" -Color DarkGray
            }
        }

        if ($LASTEXITCODE -ne 0) {
            Write-Log "Backup script exited with code $LASTEXITCODE - assuming failure" -Color Red
            Write-Log "Hardening aborted to prevent unrecoverable changes." -Color Red
            exit 1
        }

        Write-Log "Configuration backup completed successfully" -Color Green
        Write-Log "Backup files should be in: $BackupOutputDir" -Color Green
    }
    catch {
        Write-Log "Backup execution failed: $($_.Exception.Message)" -Color Red
        Write-Log "Hardening process aborted." -Color Red
        exit 1
    }
}
else {
    Write-Log "!!! WARNING: Automatic backup was skipped via -SkipBackup !!!" -Color Magenta
    Write-Log "This is NOT recommended in production environments." -Color Magenta
    Start-Sleep -Seconds 4
}

# -------------------------------------------------------------------------
# PHASE 1: Load hardening configuration
# -------------------------------------------------------------------------
if (-not (Test-Path $ConfigPath)) {
    Write-Log "Error: Hardening configuration not found at $ConfigPath" -Color Red
    exit 1
}

try {
    $HardeningConfig = Get-Content $ConfigPath | ConvertFrom-Json
    Write-Log "Hardening configuration loaded successfully." -Color Green
} catch {
    Write-Log "Failed to parse JSON configuration: $($_.Exception.Message)" -Color Red
    exit 1
}

# -------------------------------------------------------------------------
# PHASE 2: Prepare reporting
# -------------------------------------------------------------------------
$Report = @()

# Function to run SQL command (modification)
function Invoke-SqlCommand {
    param ([string]$Command)
    try {
        Invoke-Sqlcmd -ServerInstance $FullServer -Query $Command -TrustServerCertificate | Out-Null
        return $true
    } catch {
        Write-Log "SQL Command failed: $Command" -Color Red
        Write-Log $_.Exception.Message -Color Red
        return $false
    }
}

# Function to get current value for reporting
function Get-ConfigValue {
    param ([string]$ConfigName)
    switch ($ConfigName) {
        "xp_cmdshell" {
            $query = "SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'"
            $result = Invoke-SqlQuery $query
            return $result.value_in_use
        }
        "clr_enabled" {
            $query = "SELECT value_in_use FROM sys.configurations WHERE name = 'clr enabled'"
            $result = Invoke-SqlQuery $query
            return $result.value_in_use
        }
        "mixed_mode_auth" {
            $query = "SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS AuthMode"
            $result = Invoke-SqlQuery $query
            return $result.AuthMode -eq 0  # true if mixed mode
        }
        "sa_disabled" {
            $query = "SELECT is_disabled FROM sys.sql_logins WHERE name = 'sa'"
            $result = Invoke-SqlQuery $query
            return $result.is_disabled -eq 1
        }
        "sample_dbs_removed" {
            $query = "SELECT COUNT(*) AS Count FROM sys.databases WHERE name IN ('Northwind', 'AdventureWorks', 'AdventureWorksDW')"
            $result = Invoke-SqlQuery $query
            return $result.Count -eq 0
        }
        "linked_servers" {
            $query = "SELECT COUNT(*) AS Count FROM sys.servers WHERE is_linked = 1 AND server_id <> 0"
            $result = Invoke-SqlQuery $query
            return $result.Count
        }
        "sql_browser_disabled" {
            $browserService = Get-Service -Name "SQLBrowser" -ComputerName $ServerName -ErrorAction SilentlyContinue
            $status = if ($browserService) { $browserService.Status } else { "Not Found" }
            $startup = if ($browserService) { $browserService.StartType } else { "Unknown" }
            return ($status -eq "Stopped") -and ($startup -eq "Disabled")
        }
        default { return "N/A" }
    }
}

# Helper Invoke-SqlQuery (non-modifying)
function Invoke-SqlQuery {
    param ([string]$Query)
    try {
        return Invoke-Sqlcmd -ServerInstance $FullServer -Query $Query -TrustServerCertificate
    } catch {
        Write-Log "Error querying: $Query - $_" -Color DarkRed
        return $null
    }
}

# -------------------------------------------------------------------------
# PHASE 3: Apply hardenings
# -------------------------------------------------------------------------
Write-Log "Beginning OWASP hardening application..." -Color Yellow

foreach ($prop in $HardeningConfig.PSObject.Properties) {
    $configName  = $prop.Name
    $recommended = $prop.Value
    $before      = Get-ConfigValue $configName
    $success     = $false
    $details     = ""

    switch ($configName) {
        "xp_cmdshell" {
            if ($recommended -eq 0) {
                $cmd = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;"
                $success = Invoke-SqlCommand $cmd
                $details = if ($success) { "Disabled" } else { "Failed to disable" }
            }
        }
        "clr_enabled" {
            if ($recommended -eq 0) {
                $cmd = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'clr enabled', 0; RECONFIGURE;"
                $success = Invoke-SqlCommand $cmd
                $details = if ($success) { "Disabled" } else { "Failed" }
            }
        }
        "mixed_mode_auth" {
            if (-not $recommended) {  # false = Windows only
                try {
                    $smoServer = New-Object Microsoft.SqlServer.Management.Smo.Server $FullServer
                    if ($smoServer.Settings.LoginMode -ne [Microsoft.SqlServer.Management.Smo.ServerLoginMode]::Integrated) {
                        $smoServer.Settings.LoginMode = [Microsoft.SqlServer.Management.Smo.ServerLoginMode]::Integrated
                        $smoServer.Alter()
                        $details = "Authentication changed to Windows only. Restart required."
                        $success = $true
                    } else {
                        $success = $true
                        $details = "Already in Windows-only mode"
                    }
                } catch {
                    $details = "Failed to change auth mode: $($_.Exception.Message)"
                }
            }
        }
        "sa_disabled" {
            if ($recommended) {
                $cmd = "ALTER LOGIN sa DISABLE;"
                $success = Invoke-SqlCommand $cmd
                $details = if ($success) { "sa account disabled" } else { "Failed" }
            }
        }
        "sample_dbs_removed" {
            if ($recommended) {
                $dbs = @('Northwind', 'AdventureWorks', 'AdventureWorksDW')
                $allSuccess = $true
                foreach ($db in $dbs) {
                    $checkCmd = "IF DB_ID('$db') IS NOT NULL DROP DATABASE [$db];"
                    if (-not (Invoke-SqlCommand $checkCmd)) {
                        $allSuccess = $false
                    }
                }
                $success = $allSuccess
                $details = if ($success) { "Sample databases removed" } else { "Some removals failed" }
            }
        }
        "linked_servers" {
            if ($recommended -eq 0) {
                $details = "Dropping linked servers skipped for safety. Manual review required."
                $success = $false
            }
        }
        "sql_browser_disabled" {
            if ($recommended) {
                try {
                    $browserService = Get-Service -Name "SQLBrowser" -ComputerName $ServerName -ErrorAction Stop
                    Stop-Service -Name "SQLBrowser" -ComputerName $ServerName -Force -ErrorAction Stop
                    Set-Service -Name "SQLBrowser" -ComputerName $ServerName -StartupType Disabled -ErrorAction Stop
                    $success = $true
                    $details = "SQL Browser stopped and disabled"
                } catch {
                    $details = "Failed to disable SQL Browser: $($_.Exception.Message)"
                }
            }
        }
        default {
            $details = "No action defined for this configuration item"
        }
    }

    $after = Get-ConfigValue $configName

    $Report += [PSCustomObject]@{
        Config      = $configName
        Recommended = $recommended
        Before      = $before
        After       = $after
        Status      = if ($success) { "Success" } else { "Failed / Skipped" }
        Details     = $details
    }

    $color = if ($success) { "Green" } else { "Yellow" }
    Write-Log "[$($Report[-1].Status)] $configName → $details" -Color $color
}

# -------------------------------------------------------------------------
# Final reporting
# -------------------------------------------------------------------------
$Report | Export-Csv -Path $ReportCsv -NoTypeInformation -Encoding UTF8
Write-Log "Hardening report saved to: $ReportCsv" -Color Green

# Optional: Generate example config (as in original)
$ExampleConfig = @{
    "xp_cmdshell"         = 0
    "clr_enabled"         = 0
    "mixed_mode_auth"     = $false
    "sa_disabled"         = $true
    "sample_dbs_removed"  = $true
    "linked_servers"      = 0
    "sql_browser_disabled"= $true
}
$ExamplePath = Join-Path $OutputPath "Example_OWASP-HardeningConfig.json"
$ExampleConfig | ConvertTo-Json -Depth 3 | Out-File $ExamplePath -Encoding UTF8
Write-Log "Example config template saved to: $ExamplePath" -Color Cyan

Write-Log "====================================================================" -Color Cyan
Write-Log "OWASP Hardening process completed" -Color Cyan
Write-Log "Backup directory (if successful): $BackupOutputDir" -Color Green
Write-Log "Review manual steps, restart requirements, and log file." -Color Yellow
Write-Log "====================================================================" -Color Cyan