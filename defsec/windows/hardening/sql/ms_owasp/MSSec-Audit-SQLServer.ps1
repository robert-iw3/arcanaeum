<#
.SYNOPSIS
    SQL Server Audit Script for Microsoft Security Best Practices

.DESCRIPTION
    Performs automated security configuration checks based on Microsoft SQL Server
    security best practices documentation (encryption, auditing, surface area,
    protocol security, etc.). Generates CSV report, log, failed configs JSON,
    and recommended hardening config JSON.

.PARAMETER ServerName
    Required. The hostname or IP address of the SQL Server machine.

.PARAMETER InstanceName
    Optional. Named instance (leave empty for default MSSQLSERVER).

.PARAMETER OutputPath
    Directory where audit results will be saved.
    Defaults to .\AuditResultsMS

.EXAMPLE
    .\MSSec-Audit-SQLServer.ps1 -ServerName "sqlprod01" -InstanceName "INST1"

.EXAMPLE
    .\MSSec-Audit-SQLServer.ps1 -ServerName "localhost" -OutputPath "C:\SQLAudit\MS"

.NOTES
    Requires SQLServer PowerShell module
    Some checks require registry read access and administrative privileges
    Extended Protection and TLS checks may return "Not Configured" on remote servers
    Author: Robert Weber
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$ServerName,
    [string]$InstanceName = "",
    [string]$OutputPath = ".\AuditResultsMS"
)

# Construct full server instance name
$FullServer = if ($InstanceName) { "$ServerName\$InstanceName" } else { $ServerName }

# Import SQLServer module
Import-Module SQLServer -ErrorAction Stop

# Create output directory if not exists
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

# Output files
$CsvFile = Join-Path $OutputPath "AuditResultsMS.csv"
$LogFile = Join-Path $OutputPath "AuditLogMS.txt"
$FailedConfigJson = Join-Path $OutputPath "MSSec-FailedConfig.json"
$HardeningConfigJson = Join-Path $OutputPath "MSSec-HardeningConfig.json"

# Initialize log
function Write-Log {
    param ([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    Write-Host $Message
}

Write-Log "Starting SQL Server Microsoft Best Practices Audit on $FullServer"

# Initialize results array for CSV
$Results = @()

# Failed configs for JSON
$FailedConfigs = @{}

# Recommended hardening configs (static, Microsoft-specific)
$RecommendedConfigs = @{
    "tde_enabled" = $true  # For user databases
    "force_encryption" = $true
    "server_audit_enabled" = $true
    "ole_automation_disabled" = $true
    "remote_access_disabled" = $true
    "contained_db_auth" = $false  # Avoid unless needed
    "gmsa_service_account" = $true
    "extended_protection" = "Required"
    "data_classification" = $true  # Labels applied
    "vulnerability_assessment" = "Enabled"  # Placeholder, as it requires setup
    "tls_version" = "1.2"  # Minimum
    "backup_encrypted" = $true
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

# Check 1: Transparent Data Encryption (TDE) - improved granular check
$tdeStatus = @{
    EncryptedDBs     = 0
    NotEncryptedDBs  = 0
    KeyProtectorType = "None"
}

$tdeQuery = @"
SELECT
    d.name,
    d.is_encrypted,
    k.encryption_state,
    k.percent_complete,
    k.key_algorithm,
    k.key_length
FROM sys.databases d
LEFT JOIN sys.dm_database_encryption_keys k ON d.database_id = k.database_id
WHERE d.database_id > 4  -- exclude system DBs
"@
$tdeInfo = Invoke-SqlQuery $tdeQuery

if ($tdeInfo) {
    $encrypted = $tdeInfo | Where-Object { $_.is_encrypted -eq 1 -and $_.encryption_state -in @(3,4) }  # 3=Encrypted, 4=Encryption in progress
    $tdeStatus.EncryptedDBs = $encrypted.Count
    $tdeStatus.NotEncryptedDBs = $tdeInfo.Count - $encrypted.Count

    if ($encrypted) {
        $tdeStatus.KeyProtectorType = $encrypted[0].key_algorithm ? "$($encrypted[0].key_algorithm)-$($encrypted[0].key_length)" : "Unknown"
    }
} else {
    $tdeStatus.NotEncryptedDBs = "Query failed"
}

$isTdeWellImplemented = ($tdeStatus.EncryptedDBs -gt 0) -and ($tdeStatus.NotEncryptedDBs -eq 0)

$Results += [PSCustomObject]@{
    Check   = "Transparent Data Encryption (TDE)"
    Status  = if ($isTdeWellImplemented) { "Pass" } else { "Partial/ Fail" }
    Details = "$($tdeStatus.EncryptedDBs) encrypted / $($tdeStatus.NotEncryptedDBs) not encrypted | Protector: $($tdeStatus.KeyProtectorType)"
}

if (-not $isTdeWellImplemented) {
    $FailedConfigs["tde_enabled"] = $tdeStatus
}

# Check 2: Force Encryption
try {
    $smoServer = New-Object Microsoft.SqlServer.Management.Smo.Server $FullServer
    $forceEncrypt = $smoServer.ConnectionContext.EncryptConnection
} catch {
    $forceEncrypt = $false
}
$isForceEncrypt = $forceEncrypt
$Results += [PSCustomObject]@{ Check = "Force Encryption"; Status = if ($isForceEncrypt) { "Pass" } else { "Fail" }; Details = "" }
if (-not $isForceEncrypt) { $FailedConfigs["force_encryption"] = $false }

# Check 3: Server Audit Enabled
$auditQuery = "SELECT COUNT(*) AS Count FROM sys.server_audits WHERE is_state_enabled = 1"
$auditResult = Invoke-SqlQuery $auditQuery
$auditCount = if ($auditResult) { $auditResult.Count } else { 0 }
$isAuditEnabled = $auditCount -gt 0
$Results += [PSCustomObject]@{ Check = "Server Audit Enabled"; Status = if ($isAuditEnabled) { "Pass" } else { "Fail" }; Details = "Active Audits: $auditCount" }
if (-not $isAuditEnabled) { $FailedConfigs["server_audit_enabled"] = $false }

# Check 4: OLE Automation Disabled
$oleQuery = "SELECT value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures'"
$oleResult = Invoke-SqlQuery $oleQuery
$oleValue = if ($oleResult) { $oleResult.value_in_use } else { -1 }
$isOleDisabled = $oleValue -eq 0
$Results += [PSCustomObject]@{ Check = "OLE Automation Disabled"; Status = if ($isOleDisabled) { "Pass" } else { "Fail" }; Details = "Value: $oleValue" }
if (-not $isOleDisabled) { $FailedConfigs["ole_automation_disabled"] = $false }

# Check 5: Remote Access Disabled
$remoteQuery = "SELECT value_in_use FROM sys.configurations WHERE name = 'remote access'"
$remoteResult = Invoke-SqlQuery $remoteQuery
$remoteValue = if ($remoteResult) { $remoteResult.value_in_use } else { -1 }
$isRemoteDisabled = $remoteValue -eq 0
$Results += [PSCustomObject]@{ Check = "Remote Access Disabled"; Status = if ($isRemoteDisabled) { "Pass" } else { "Fail" }; Details = "Value: $remoteValue" }
if (-not $isRemoteDisabled) { $FailedConfigs["remote_access_disabled"] = $false }

# Check 6: Contained DB Auth (check if enabled, recommend false unless needed)
$containedQuery = "SELECT value_in_use FROM sys.configurations WHERE name = 'contained database authentication'"
$containedResult = Invoke-SqlQuery $containedQuery
$containedValue = if ($containedResult) { $containedResult.value_in_use } else { -1 }
$isContainedOff = $containedValue -eq 0
$Results += [PSCustomObject]@{ Check = "Contained DB Auth Disabled"; Status = if ($isContainedOff) { "Pass" } else { "Fail" }; Details = "Value: $containedValue" }
if (-not $isContainedOff) { $FailedConfigs["contained_db_auth"] = $true }

# Check 7: gMSA Service Account
$serviceName = if ($InstanceName) { "MSSQL`$$InstanceName" } else { "MSSQLSERVER" }
$service = Get-Service -Name $serviceName -ComputerName $ServerName -ErrorAction SilentlyContinue
$serviceAccount = if ($service) { $service.StartName } else { "Unknown" }
$isGmsa = $serviceAccount -like "*.gmsa*"
$Results += [PSCustomObject]@{ Check = "gMSA Service Account"; Status = if ($isGmsa) { "Pass" } else { "Fail" }; Details = "Account: $serviceAccount" }
if (-not $isGmsa) { $FailedConfigs["gmsa_service_account"] = $false }

# Check 8: Extended Protection (registry-based)
$instanceRegPath = if ($InstanceName) {
    "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer.$InstanceName\MSSQLServer"
} else {
    "HKLM:\SOFTWARE\Microsoft\MSSQLServer\MSSQLServer"
}

$extendedProtValue = "Off"

try {
    $epValue = Get-ItemProperty -Path $instanceRegPath -Name "ExtendedProtection" -ErrorAction Stop
    switch ($epValue.ExtendedProtection) {
        0 { $extendedProtValue = "Off" }
        1 { $extendedProtValue = "Allowed" }
        2 { $extendedProtValue = "Required" }
        default { $extendedProtValue = "Unknown" }
    }
} catch {
    $extendedProtValue = "Not Configured / Error: $($_.Exception.Message)"
}

$isExtendedRequired = $extendedProtValue -eq "Required"

$Results += [PSCustomObject]@{
    Check   = "Extended Protection"
    Status  = if ($isExtendedRequired) { "Pass" } else { "Fail" }
    Details = "Current: $extendedProtValue"
}

if (-not $isExtendedRequired) {
    $FailedConfigs["extended_protection"] = $extendedProtValue
}

# Check 9: Data Classification (check if any labels)
$classQuery = "SELECT COUNT(*) AS Count FROM sys.sensitivity_labels"
$classResult = Invoke-SqlQuery $classQuery
$classCount = if ($classResult) { $classResult.Count } else { 0 }
$isClassified = $classCount -gt 0
$Results += [PSCustomObject]@{ Check = "Data Classification Applied"; Status = if ($isClassified) { "Pass" } else { "Fail" }; Details = "Labels: $classCount" }
if (-not $isClassified) { $FailedConfigs["data_classification"] = $false }

# Check 10: Vulnerability Assessment (info, as it's a tool; assume not enabled if no reports)
$vaStatus = "Not Enabled"  # Would require checking if VA is set up, e.g., via stored procs
$Results += [PSCustomObject]@{ Check = "Vulnerability Assessment"; Status = "Info"; Details = $vaStatus }

# Check 11: TLS Version (Schannel + connections check)
$tlsCompliant = $false
$tlsDetails = ""

# Check 1: OS Schannel - TLS 1.0 & 1.1 should be disabled
$protocols = @(
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"; Enabled = $false }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"; Enabled = $false }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"; Enabled = $true  }
)

$osCompliant = $true
$osIssues = @()

foreach ($proto in $protocols) {
    try {
        $reg = Get-ItemProperty -Path $proto.Path -Name "Enabled" -ErrorAction Stop
        if (($reg.Enabled -eq 1) -ne $proto.Enabled) {
            $osCompliant = $false
            $osIssues += "$($proto.Path.Split('\')[-2]) mismatch"
        }
    } catch {
        $osCompliant = $false
        $osIssues += "$($proto.Path.Split('\')[-2]) not configured properly"
    }
}

# Check 2: Actual connections (recent ones using TLS 1.2+)
$tlsConnQuery = @"
SELECT
    COUNT(*) AS TotalConnections,
    SUM(CASE WHEN encryption_protocol_version >= 0x0303 THEN 1 ELSE 0 END) AS Tls12Plus
FROM sys.dm_exec_connections
WHERE session_id > 50  -- exclude system sessions
"@
$connStats = Invoke-SqlQuery $tlsConnQuery

$tlsPercent = if ($connStats.TotalConnections -gt 0) {
    [math]::Round(($connStats.Tls12Plus / $connStats.TotalConnections) * 100, 1)
} else {
    0
}

$tlsDetails = "OS: $(if($osCompliant){'Compliant'}else{'Non-compliant: ' + ($osIssues -join ', ')}) | Connections TLS 1.2+: $tlsPercent% ($($connStats.Tls12Plus)/$($connStats.TotalConnections))"

$tlsCompliant = $osCompliant -and ($tlsPercent -ge 95)  # allow some legacy during transition

$Results += [PSCustomObject]@{
    Check   = "Minimum TLS 1.2+"
    Status  = if ($tlsCompliant) { "Pass" } else { "Fail" }
    Details = $tlsDetails
}

if (-not $tlsCompliant) {
    $FailedConfigs["tls_version"] = $tlsDetails
}

# Check 12: Backup Encrypted (check recent backups)
$backupQuery = "SELECT TOP 1 is_encrypted FROM msdb.dbo.backupset ORDER BY backup_finish_date DESC"
$backupResult = Invoke-SqlQuery $backupQuery
$backupEncrypted = if ($backupResult) { $backupResult.is_encrypted -eq 1 } else { $false }
$Results += [PSCustomObject]@{ Check = "Recent Backups Encrypted"; Status = if ($backupEncrypted) { "Pass" } else { "Fail" }; Details = "" }
if (-not $backupEncrypted) { $FailedConfigs["backup_encrypted"] = $false }

# Output to CSV
$Results | Export-Csv -Path $CsvFile -NoTypeInformation
Write-Log "CSV output saved to $CsvFile"

# Output failed configs to JSON
$FailedConfigs | ConvertTo-Json -Depth 3 | Out-File $FailedConfigJson
Write-Log "Failed configs JSON saved to $FailedConfigJson"

# Output static hardening config JSON
$RecommendedConfigs | ConvertTo-Json -Depth 3 | Out-File $HardeningConfigJson
Write-Log "Hardening config JSON saved to $HardeningConfigJson"

Write-Log "Microsoft Best Practices Audit completed."