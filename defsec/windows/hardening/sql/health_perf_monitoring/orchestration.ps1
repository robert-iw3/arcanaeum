<#
.SYNOPSIS
    SQL Health Monitoring Setup Script
.DESCRIPTION
    Orchestrates the setup of SQL Server health monitoring: Config validation (no creation), Agent job execution (from separate SQL file), health script test, error handling with rollback.
    Outputs: Prometheus .prom, plain text log appended with results.
    Loki: Assumes promtail-config.yml tails LogFile.
    Prometheus: .prom for node_exporter.
    Grafana: Import dashboard.json for metrics.
    Error handling: Try-catch, log to ErrorLog, rollback job on failure.
.PARAMETER ConfigPath
    Optional. Path to config.ini file.
    Defaults to .\config.ini
.EXAMPLE
    .\orchestration.ps1 -ConfigPath "C:\Custom\config.ini"
.EXAMPLE
    .\orchestration.ps1
.NOTES
    Requires SQLCMD and SQL Server Agent access.
    Run as admin with SQL perms; adaptable via config.ini (must exist and be valid).
    If config.ini is missing or invalid, script warns and dumps issues/template to console.
    Author: Robert Weber
#>

# Function to read and validate config.ini
function Get-Config {
    param (
        [string]$ConfigPath = "config.ini"
    )
    if (-not (Test-Path $ConfigPath)) {
        Write-Host "Error: config.ini missing at $ConfigPath."
        Write-Host "Create it with this template:"
        Write-Host @"
[SQL]
ServerName = localhost
Database = master
Authentication = -E
HealthScriptPath = C:\Scripts\sql_health_check.sql
JobScriptPath = C:\Scripts\create_agent_job.sql

[Paths]
PromFile = \Monitoring\sql_metrics.prom
LogFile = \Monitoring\health.log
DriveLetter = C
ErrorLog = C:\Monitoring\setup_errors.log

[Job]
JobName = SQL_Health_Monitor
ScheduleName = Hourly_Health_Check
OwnerLogin = sa

[LokiPrometheus]
# Integration notes only
"@
        exit
    }

    # Read and validate
    $config = @{}
    $lines = Get-Content $ConfigPath
    $section = ""
    $errors = @()
    $requiredKeys = @(
        "SQL.ServerName", "SQL.Database", "SQL.Authentication", "SQL.HealthScriptPath", "SQL.JobScriptPath",
        "Paths.PromFile", "Paths.LogFile", "Paths.DriveLetter", "Paths.ErrorLog",
        "Job.JobName", "Job.ScheduleName", "Job.OwnerLogin"
    )

    foreach ($line in $lines) {
        $line = $line.Trim()
        if ($line -eq "" -or $line.StartsWith("#")) { continue }  # Skip empty/comments
        if ($line -match "^\[(.+)\]$") { $section = $matches[1]; continue }
        if ($line -match "^(.+?)\s*=\s*(.+)$") {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            if ($value -eq "") { $errors += "Empty value for $section.$key" }
            $config["$section.$key"] = $value
        } else {
            $errors += "Malformed line: $line (missing '=' or invalid format)"
        }
    }

    # Check required keys
    foreach ($req in $requiredKeys) {
        if (-not $config.ContainsKey($req) -or $config[$req] -eq "") {
            $errors += "Missing or empty required key: $req"
        }
    }

    if ($errors.Count -gt 0) {
        Write-Host "Error: Invalid config.ini syntax/issues:"
        $errors | ForEach-Object { Write-Host "- $_" }
        exit
    }

    return $config
}

# Main orchestration
param (
    [string]$ConfigPath = "config.ini"
)

$config = Get-Config -ConfigPath $ConfigPath

# Prefix paths with drive
$config['Paths.PromFile'] = "$($config['Paths.DriveLetter']):$($config['Paths.PromFile'])"
$config['Paths.LogFile'] = "$($config['Paths.DriveLetter']):$($config['Paths.LogFile'])"
$config['Paths.ErrorLog'] = "$($config['Paths.DriveLetter']):$($config['Paths.ErrorLog'])"

# Ensure directories exist
$promDir = Split-Path $config['Paths.PromFile'] -Parent
$logDir = Split-Path $config['Paths.LogFile'] -Parent
if (-not (Test-Path $promDir)) { New-Item -Path $promDir -ItemType Directory -Force }
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force }

try {
    # Execute job creation from separate SQL file
    $sqlCmd = "sqlcmd -S $($config['SQL.ServerName']) -d $($config['SQL.Database']) $($config['SQL.Authentication']) -i `"$($config['SQL.JobScriptPath'])`""
    $jobOutput = Invoke-Expression $sqlCmd -ErrorAction Stop
    if ($jobOutput -match "Error") { throw "Job creation failed: $jobOutput" }

    # Test health script execution
    $healthCmd = "sqlcmd -S $($config['SQL.ServerName']) -d $($config['SQL.Database']) $($config['SQL.Authentication']) -i `"$($config['SQL.HealthScriptPath'])`" -t 300 > `"$($config['Paths.PromFile'])`" 2>&1; Get-Content `"$($config['Paths.PromFile'])`" | Add-Content `"$($config['Paths.LogFile'])`" -Force"
    Invoke-Expression $healthCmd -ErrorAction Stop

    Write-Host "Setup complete. Job '$($config['Job.JobName'])' created. Outputs: Prom $($config['Paths.PromFile']), Log $($config['Paths.LogFile'])."
} catch {
    Add-Content $config['Paths.ErrorLog'] "Critical error: $($_.Exception.Message)"
    # Rollback: Delete job if exists
    $rollbackCmd = "sqlcmd -S $($config['SQL.ServerName']) -d $($config['SQL.Database']) $($config['SQL.Authentication']) -Q `"EXEC msdb.dbo.sp_delete_job @job_name = N'$($config['Job.JobName'])', @delete_unused_schedule=1;`""
    Invoke-Expression $rollbackCmd
    Write-Host "Rollback complete due to error. See $($config['Paths.ErrorLog'])"
}