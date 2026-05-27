<#
.SYNOPSIS
    Real-time ePO Monitoring Dashboard (AH + SQL IOPS + Cluster Health)
#>

param (
    [string]$EpoUrl   = "https://epo.contoso.local:8443",
    [string]$SQLServer = "sql01.contoso.local",
    [string]$ClusterName = "EPO-CLUSTER"
)

$cred = Get-Credential "epoadmin"

# === 1. AH Stats via REST ===
$ahStats = Invoke-RestMethod -Uri "$EpoUrl/api/2.0/ah/stats" -Method Get -Credential $cred
$ahTable = $ahStats | Select-Object name, connectedSystems, cpuPercent, memoryUsedMB, avgResponseTimeMs, healthStatus

# === 2. SQL IOPS (live query) ===
$sqlIOPS = Invoke-Sqlcmd -ServerInstance $SQLServer -Query "
    SELECT
        DB_NAME(database_id) AS DatabaseName,
        SUM(num_of_bytes_read + num_of_bytes_written) / 1024.0 / 1024.0 / 60 AS IOPS_MB_per_min,
        SUM(io_stall_read_ms + io_stall_write_ms) / 1000.0 AS IO_Stall_Seconds
    FROM sys.dm_io_virtual_file_stats(NULL, NULL)
    GROUP BY database_id
    HAVING DB_NAME(database_id) = 'ePO'
"

# === 3. Cluster Health ===
$clusterHealth = Get-Cluster -Name $ClusterName | Get-ClusterNode | Select-Object Name, State, NodeWeight, DrainStatus

# === Generate HTML Dashboard ===
$html = @"
<!DOCTYPE html>
<html><head><title>ePO Monitoring Dashboard</title></head><body>
<h1>Trellix ePO 5.10.0 Monitoring Dashboard</h1>
<h2>Agent Handler Status</h2>
$($ahTable | ConvertTo-Html -Fragment)
<h2>SQL IOPS (ePO Database)</h2>
$($sqlIOPS | ConvertTo-Html -Fragment)
<h2>Cluster Health</h2>
$($clusterHealth | ConvertTo-Html -Fragment)
</body></html>
"@

$html | Out-File "C:\Temp\ePO-Dashboard.html" -Encoding utf8
Start-Process "C:\Temp\ePO-Dashboard.html"

Write-Host "Dashboard generated and opened!" -ForegroundColor Green