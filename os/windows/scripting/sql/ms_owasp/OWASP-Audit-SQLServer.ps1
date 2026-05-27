<#
.SYNOPSIS
    SQL Server Audit Script based on OWASP Database Security Cheat Sheet

.DESCRIPTION
    Performs automated checks against key OWASP database security recommendations
    for Microsoft SQL Server. Produces CSV report, plain text log, and JSON files
    containing failed configurations and recommended hardening values.

.PARAMETER ServerName
    Required. The hostname or IP address of the SQL Server machine.

.PARAMETER InstanceName
    Optional. The named instance (leave empty for default instance MSSQLSERVER).

.PARAMETER OutputPath
    Directory where audit results (CSV, log, JSON files) will be saved.
    Defaults to .\AuditResults

.EXAMPLE
    .\OWASP-Audit-SQLServer.ps1 -ServerName "sqlprod01" -InstanceName "PROD"

.EXAMPLE
    .\OWASP-Audit-SQLServer.ps1 -ServerName "localhost" -OutputPath "C:\SQLAudit\OWASP"

.NOTES
    Requires SQLServer PowerShell module (Install-Module SqlServer)
    Requires sysadmin privileges for most checks
    Some checks (service account, SQL Browser) require administrative rights on the host
    Author: Robert Weber
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$ServerName,
    [string]$InstanceName = "",
    [string]$OutputPath = ".\AuditResults"
)

# Construct full server instance name
$FullServer = if ($InstanceName) { "$ServerName\$InstanceName" } else { $ServerName }

# Import SQLServer module
Import-Module SQLServer -ErrorAction Stop

# Create output directory if not exists
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

# Output files
$CsvFile = Join-Path $OutputPath "AuditResults.csv"
$LogFile = Join-Path $OutputPath "AuditLog.txt"
$FailedConfigJson = Join-Path $OutputPath "FailedConfigs.json"
$HardeningConfigJson = Join-Path $OutputPath "HardeningConfig.json"

# Initialize log
function Write-Log {
    param ([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    Write-Host $Message
}

Write-Log "Starting SQL Server Audit on $FullServer"

# Initialize results array for CSV
$Results = @()

# Failed configs for JSON
$FailedConfigs = @{}

# Recommended hardening configs (static)
$RecommendedConfigs = @{
    "xp_cmdshell" = 0
    "clr_enabled" = 0
    "mixed_mode_auth" = $false
    "sa_disabled" = $true
    "sample_dbs_removed" = $true
    "linked_servers" = 0
    "service_account" = "LowPrivAccount"  # Placeholder, customize
    "sql_browser_disabled" = $true
    # Add more as needed
}

# Function to run SQL query
function Invoke-SqlQuery {
    param ([string]$Query)
    try {
        Invoke-Sqlcmd -ServerInstance $FullServer -Query $Query -TrustServerCertificate
    } catch {
        Write-Log "Error executing query: $_"
        return $null
    }
}

# Check 1: xp_cmdshell disabled
$xpQuery = "SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'"
$xpResult = Invoke-SqlQuery $xpQuery
$xpValue = if ($xpResult) { $xpResult.value_in_use } else { -1 }
$isXpDisabled = $xpValue -eq 0
$Results += [PSCustomObject]@{ Check = "xp_cmdshell Disabled"; Status = if ($isXpDisabled) { "Pass" } else { "Fail" }; Details = "Value: $xpValue" }
if (-not $isXpDisabled) { $FailedConfigs["xp_cmdshell"] = $xpValue }

# Check 2: CLR disabled
$clrQuery = "SELECT value_in_use FROM sys.configurations WHERE name = 'clr enabled'"
$clrResult = Invoke-SqlQuery $clrQuery
$clrValue = if ($clrResult) { $clrResult.value_in_use } else { -1 }
$isClrDisabled = $clrValue -eq 0
$Results += [PSCustomObject]@{ Check = "CLR Disabled"; Status = if ($isClrDisabled) { "Pass" } else { "Fail" }; Details = "Value: $clrValue" }
if (-not $isClrDisabled) { $FailedConfigs["clr_enabled"] = $clrValue }

# Check 3: Mixed Mode Auth (Windows only)
$authQuery = "SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS AuthMode"
$authResult = Invoke-SqlQuery $authQuery
$authValue = if ($authResult) { $authResult.AuthMode } else { -1 }
$isWindowsOnly = $authValue -eq 1
$Results += [PSCustomObject]@{ Check = "Windows Authentication Only"; Status = if ($isWindowsOnly) { "Pass" } else { "Fail" }; Details = "Value: $authValue" }
if (-not $isWindowsOnly) { $FailedConfigs["mixed_mode_auth"] = $true }

# Check 4: sa disabled
$saQuery = "SELECT is_disabled FROM sys.sql_logins WHERE name = 'sa'"
$saResult = Invoke-SqlQuery $saQuery
$saDisabled = if ($saResult) { $saResult.is_disabled -eq 1 } else { $false }
$Results += [PSCustomObject]@{ Check = "sa Account Disabled"; Status = if ($saDisabled) { "Pass" } else { "Fail" }; Details = "" }
if (-not $saDisabled) { $FailedConfigs["sa_disabled"] = $false }

# Check 5: Sample DBs removed
$sampleQuery = "SELECT name FROM sys.databases WHERE name IN ('Northwind', 'AdventureWorks', 'AdventureWorksDW')"
$sampleResult = Invoke-SqlQuery $sampleQuery
$sampleCount = if ($sampleResult) { $sampleResult.Count } else { 0 }
$noSamples = $sampleCount -eq 0
$Results += [PSCustomObject]@{ Check = "Sample Databases Removed"; Status = if ($noSamples) { "Pass" } else { "Fail" }; Details = "Found: $sampleCount" }
if (-not $noSamples) { $FailedConfigs["sample_dbs"] = $sampleResult.name }

# Check 6: Linked Servers
$linkedQuery = "SELECT COUNT(*) AS Count FROM sys.servers WHERE is_linked = 1 AND server_id <> 0"
$linkedResult = Invoke-SqlQuery $linkedQuery
$linkedCount = if ($linkedResult) { $linkedResult.Count } else { 0 }
$noLinked = $linkedCount -eq 0
$Results += [PSCustomObject]@{ Check = "No Linked Servers"; Status = if ($noLinked) { "Pass" } else { "Fail" }; Details = "Count: $linkedCount" }
if (-not $noLinked) { $FailedConfigs["linked_servers"] = $linkedCount }

# Check 7: SQL Version/Patches (report only)
$versionQuery = "SELECT @@VERSION AS Version"
$versionResult = Invoke-SqlQuery $versionQuery
$version = if ($versionResult) { $versionResult.Version } else { "Unknown" }
$Results += [PSCustomObject]@{ Check = "SQL Server Version"; Status = "Info"; Details = $version }

# Check 8: Service Account (low priv - check not LocalSystem)
$serviceName = if ($InstanceName) { "MSSQL`$$InstanceName" } else { "MSSQLSERVER" }
$service = Get-Service -Name $serviceName -ComputerName $ServerName -ErrorAction SilentlyContinue
$serviceAccount = if ($service) { $service.StartName } else { "Unknown" }
$isLowPriv = $serviceAccount -notlike "*LocalSystem*" -and $serviceAccount -notlike "*Administrator*"
$Results += [PSCustomObject]@{ Check = "Low Priv Service Account"; Status = if ($isLowPriv) { "Pass" } else { "Fail" }; Details = "Account: $serviceAccount" }
if (-not $isLowPriv) { $FailedConfigs["service_account"] = $serviceAccount }

# Check 9: SQL Browser Disabled
$browserService = Get-Service -Name "SQLBrowser" -ComputerName $ServerName -ErrorAction SilentlyContinue
$browserStatus = if ($browserService) { $browserService.Status } else { "Not Found" }
$browserStartup = if ($browserService) { $browserService.StartType } else { "Unknown" }
$isBrowserDisabled = ($browserStatus -eq "Stopped") -and ($browserStartup -eq "Disabled")
$Results += [PSCustomObject]@{ Check = "SQL Browser Disabled"; Status = if ($isBrowserDisabled) { "Pass" } else { "Fail" }; Details = "Status: $browserStatus, Startup: $browserStartup" }
if (-not $isBrowserDisabled) { $FailedConfigs["sql_browser"] = @{Status=$browserStatus; Startup=$browserStartup} }

# Check 10: Transaction Logs Separate (for master db as example)
$filesQuery = "SELECT type_desc, physical_name FROM sys.master_files WHERE database_id = 1"
$filesResult = Invoke-SqlQuery $filesQuery
$logDrive = ""
$dataDrive = ""
if ($filesResult) {
    foreach ($file in $filesResult) {
        $drive = [System.IO.Path]::GetPathRoot($file.physical_name)
        if ($file.type_desc -eq "LOG") { $logDrive = $drive }
        if ($file.type_desc -eq "ROWS") { $dataDrive = $drive }
    }
}
$separateLogs = $logDrive -ne $dataDrive -and $logDrive -ne "" -and $dataDrive -ne ""
$Results += [PSCustomObject]@{ Check = "Transaction Logs Separate"; Status = if ($separateLogs) { "Pass" } else { "Fail" }; Details = "Data: $dataDrive, Log: $logDrive" }
if (-not $separateLogs) { $FailedConfigs["separate_logs"] = @{Data=$dataDrive; Log=$logDrive} }

# Additional checks can be added similarly...

# Output to CSV
$Results | Export-Csv -Path $CsvFile -NoTypeInformation
Write-Log "CSV output saved to $CsvFile"

# Output failed configs to JSON
$FailedConfigs | ConvertTo-Json -Depth 3 | Out-File $FailedConfigJson
Write-Log "Failed configs JSON saved to $FailedConfigJson"

# Output static hardening config JSON (recommended settings)
$RecommendedConfigs | ConvertTo-Json -Depth 3 | Out-File $HardeningConfigJson
Write-Log "Hardening config JSON saved to $HardeningConfigJson"

Write-Log "Audit completed."