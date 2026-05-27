<#

.SYNOPSIS
    Tunes SQL Server for Trellix ePolicy Orchestrator (ePO) database and server performance.
    Applies best practices for availability and performance based on Trellix recommendations (KB67184, KB79310, KB90961, KB91176, KB87769, KB000013678, docs.trellix.com):
    - Sets MAXDOP = 1 to prevent parallelism issues
    - Sets recovery model to SIMPLE for ePO databases (event data is non-critical)
    - Checks and logs fragmentation levels (using sys.dm_db_index_physical_stats, as DBCC SHOWCONTIG is deprecated)
    - Performs index maintenance with fragmentation check (rebuild >30%, reorganize 10-30%)
    - Updates statistics
    - Optional: Purges old events from EPOEvents table (batched to avoid log growth)
    - ePO-specific: Prioritizes index rebuild on common high-fragmentation tables like EPOEvents, OrionAuditLog, EPOLeafNode
    - Avoids database shrinking to prevent fragmentation
    - Uses ePO Database Index Maintenance task recommendations where applicable (run during low activity)
    - Checks for SQL Agent backup jobs (full, diff, trans log, system dbs) and alerts if missing

.DESCRIPTION
    Run this script on the SQL Server hosting the ePO databases (or use -SqlInstance for remote).
    Requires the SqlServer PowerShell module (Install-Module SqlServer if needed).
    Default ePO database names: Adjust parameters as needed (common: ePO_<server>, ePO_<server>_Events).

    For large databases, use custom batch purging and run during maintenance windows.
    Error handling: Catches and logs errors per operation, continues where possible.
    Added fragmentation logging before maintenance.
    Checks for SQL Agent jobs handling backups and alerts if not present.

.PARAMETER SqlInstance
    SQL Server instance name (e.g., "SERVER\INSTANCE" or "localhost")

.PARAMETER EpoDatabases
    Array of ePO-related database names to tune/backup

.PARAMETER PurgeDays
    Number of days to keep events/audit logs; purge older (0 = skip purge). Default: 0

.PARAMETER WhatIf
    Show actions without executing

.PARAMETER LogFile
    Path to log file for output and errors. Default: "TuneEpoSql.log"

.EXAMPLE
    .\TuneEpoSql.ps1 -SqlInstance "SQLSERVER01" -EpoDatabases @("ePO_SERVER", "ePO_SERVER_Events") -PurgeDays 90

.NOTES
    Run as SQL admin or with sufficient permissions.
    Test in non-production first.
    For production, schedule during low-activity periods.
    Trellix recommends using ePO server tasks for event purging and index maintenance where possible, but this provides SQL-side option.
    Avoid shrinking databases as per Trellix best practices.

    Author: Robert Weber

#>

param (
    [string]$SqlInstance = "localhost",
    [string[]]$EpoDatabases = @("ePO", "ePO_Events", "Orion"),
    [int]$PurgeDays = 0,
    [switch]$WhatIf,
    [string]$LogFile = "TuneEpoSql.log"
)

# Ensure SqlServer module is available
try {
    if (-not (Get-Module -ListAvailable -Name SqlServer)) {
        throw "SqlServer module not found. Install with: Install-Module SqlServer"
    }
    Import-Module SqlServer -ErrorAction Stop
} catch {
    Write-Error $_.Exception.Message
    exit 1
}

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    if (-not $WhatIf) {
        Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
    }
    Write-Output $logEntry
}

Write-Log "Starting ePO SQL tuning on $SqlInstance..."

function Invoke-Sql {
    param([string]$Query, [string]$Database = "master")
    try {
        if ($WhatIf) {
            Write-Log "WhatIf: Would execute on $Database: $Query"
            return $null
        } else {
            return Invoke-Sqlcmd -ServerInstance $SqlInstance -Database $Database -Query $Query -ErrorAction Stop
        }
    } catch {
        Write-Log "Error executing query on $Database: $_" "ERROR"
        throw
    }
}

try {
    # Check SQL connectivity
    Write-Log "Testing SQL connectivity..."
    Invoke-Sql -Query "SELECT 1" | Out-Null

    # 1. Set MAXDOP = 1 (Trellix KB79310 recommendation)
    Write-Log "Setting MAXDOP to 1..."
    Invoke-Sql -Query @"
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'max degree of parallelism', 1;
RECONFIGURE;
"@

    # 2. Process each database
    foreach ($db in $EpoDatabases) {
        try {
            Write-Log "Processing database: $db"

            # Check if database exists and is online
            $dbStatus = Invoke-Sql -Query "SELECT name, state_desc FROM sys.databases WHERE name = '$db'"
            if (-not $dbStatus) {
                Write-Log "Database $db not found. Skipping." "WARNING"
                continue
            }
            if ($dbStatus.state_desc -ne "ONLINE") {
                Write-Log "Database $db is not online (state: $($dbStatus.state_desc)). Skipping." "WARNING"
                continue
            }

            # Set recovery model to SIMPLE (KB91176)
            Write-Log "  Setting recovery model to SIMPLE..."
            Invoke-Sql -Query "ALTER DATABASE [$db] SET RECOVERY SIMPLE WITH NO_WAIT;" -Database $db

            # Optional: Purge old events (Trellix best practice for DB size management, KB67184, docs.trellix.com)
            if ($PurgeDays -gt 0) {
                Write-Log "  Purging events older than $PurgeDays days (batched)..."
                $purgeQuery = @"
WHILE 1=1
BEGIN
    DELETE TOP (10000) FROM EPOEvents WHERE DetectedUTC < DATEADD(DAY, -$PurgeDays, GETDATE());
    IF @@ROWCOUNT = 0 BREAK;
END
"@
                Invoke-Sql -Query $purgeQuery -Database $db

                # Also purge audit log if applicable
                $purgeAuditQuery = @"
WHILE 1=1
BEGIN
    DELETE TOP (10000) FROM OrionAuditLog WHERE StartTime < DATEADD(DAY, -$PurgeDays, GETDATE());
    IF @@ROWCOUNT = 0 BREAK;
END
"@
                Invoke-Sql -Query $purgeAuditQuery -Database $db
            }

            # Log fragmentation levels (using modern sys.dm_db_index_physical_stats, as DBCC SHOWCONTIG is deprecated)
            Write-Log "  Logging fragmentation levels..."
            $fragQuery = @"
SELECT
    s.name + '.' + o.name AS TableName,
    i.name AS IndexName,
    ps.avg_fragmentation_in_percent
FROM sys.dm_db_index_physical_stats(DB_ID('$db'), NULL, NULL, NULL, 'LIMITED') ps
INNER JOIN sys.indexes i ON ps.object_id = i.object_id AND ps.index_id = i.index_id
INNER JOIN sys.objects o ON ps.object_id = o.object_id
INNER JOIN sys.schemas s ON o.schema_id = s.schema_id
WHERE ps.avg_fragmentation_in_percent > 10
ORDER BY ps.avg_fragmentation_in_percent DESC;
"@
            $fragments = Invoke-Sql -Query $fragQuery -Database $db
            if ($fragments) {
                $fragments | ForEach-Object {
                    Write-Log "    Fragmentation: $($_.TableName).$($_.IndexName) = $($_.avg_fragmentation_in_percent)%"
                }
            } else {
                Write-Log "    No significant fragmentation found."
            }

            # ePO-specific index rebuild on key tables (EPOEvents, OrionAuditLog, EPOLeafNode, etc. - based on KB87769, KB67184, docs.trellix.com)
            Write-Log "  Rebuilding indexes on ePO-specific tables..."
            $epoTables = @("EPOEvents", "OrionAuditLog", "EPOLeafNode", "EPOComputerProperties", "EPOProductProperties", "EPOEventFilterDesc")
            foreach ($table in $epoTables) {
                try {
                    # Check if table exists
                    $tableExists = Invoke-Sql -Query "SELECT 1 FROM sys.tables WHERE name = '$table'" -Database $db
                    if ($tableExists) {
                        Write-Log "    Rebuilding indexes on $table..."
                        Invoke-Sql -Query "ALTER INDEX ALL ON [$table] REBUILD;" -Database $db
                    } else {
                        Write-Log "    Table $table not found in $db. Skipping." "WARNING"
                    }
                } catch {
                    Write-Log "    Error rebuilding indexes on $table: $_" "ERROR"
                }
            }

            # General index maintenance for other indexes (fragmentation-based, KB67184, KB000013678 for large DBs)
            Write-Log "  Performing general index maintenance..."
            $maintenanceQuery = @"
DECLARE @SQL NVARCHAR(MAX) = '';
SELECT @SQL +=
    CASE
        WHEN avg_fragmentation_in_percent > 30 THEN 'ALTER INDEX ' + QUOTENAME(i.name) + ' ON ' + QUOTENAME(s.name) + '.' + QUOTENAME(o.name) + ' REBUILD; '
        WHEN avg_fragmentation_in_percent > 10 THEN 'ALTER INDEX ' + QUOTENAME(i.name) + ' ON ' + QUOTENAME(s.name) + '.' + QUOTENAME(o.name) + ' REORGANIZE; '
        ELSE ''
    END
FROM sys.dm_db_index_physical_stats(DB_ID('$db'), NULL, NULL, NULL, 'LIMITED') ps
INNER JOIN sys.indexes i ON ps.object_id = i.object_id AND ps.index_id = i.index_id
INNER JOIN sys.objects o ON ps.object_id = o.object_id
INNER JOIN sys.schemas s ON o.schema_id = s.schema_id
WHERE ps.avg_fragmentation_in_percent > 10
  AND i.name IS NOT NULL;

IF @SQL <> '' EXEC sp_executesql @SQL;
"@
            Invoke-Sql -Query $maintenanceQuery -Database $db

            # Update statistics (KB67184)
            Write-Log "  Updating statistics..."
            Invoke-Sql -Query "EXEC sp_updatestats;" -Database $db

            # Avoid shrinking (as per docs.trellix.com)
            Write-Log "  Skipping database shrink as per Trellix best practices to avoid fragmentation."

        } catch {
            Write-Log "Error processing database $db: $_" "ERROR"
            # Continue to next DB
        }
    }

    # 3. Check for SQL Agent backup jobs (full, diff, trans log, system dbs)
    Write-Log "Checking for SQL Agent backup jobs..."
    $backupJobsQuery = @"
SELECT j.name AS JobName, s.step_name AS StepName, s.command AS Command
FROM msdb.dbo.sysjobs j
INNER JOIN msdb.dbo.sysjobsteps s ON j.job_id = s.job_id
WHERE s.subsystem = 'TSQL' AND s.command LIKE '%BACKUP%'
ORDER BY j.name, s.step_id;
"@
    $backupJobs = Invoke-Sql -Query $backupJobsQuery -Database "msdb"

    $hasFullBackup = $false
    $hasDiffBackup = $false
    $hasTransLogBackup = $false
    $hasSystemDbBackup = $false

    if ($backupJobs) {
        foreach ($job in $backupJobs) {
            $command = $job.Command.ToUpper()

            if ($command -match 'BACKUP DATABASE' -and $command -notmatch 'DIFFERENTIAL' -and $command -notmatch 'LOG') {
                $hasFullBackup = $true
            }
            if ($command -match 'BACKUP DATABASE' -and $command -match 'DIFFERENTIAL') {
                $hasDiffBackup = $true
            }
            if ($command -match 'BACKUP LOG') {
                $hasTransLogBackup = $true
            }
            if ($command -match 'MASTER' -or $command -match 'MODEL' -or $command -match 'MSDB') {
                $hasSystemDbBackup = $true
            }
        }
    }

    if (-not $hasFullBackup) {
        Write-Log "ALERT: No SQL Agent jobs found for full database backups. Implement backups immediately." "WARNING"
    }
    if (-not $hasDiffBackup) {
        Write-Log "ALERT: No SQL Agent jobs found for differential database backups. Consider implementing if needed." "WARNING"
    }
    if (-not $hasTransLogBackup) {
        Write-Log "ALERT: No SQL Agent jobs found for transaction log backups. Implement if using FULL recovery model on any databases." "WARNING"
    }
    if (-not $hasSystemDbBackup) {
        Write-Log "ALERT: No SQL Agent jobs found for system database backups (master, model, msdb). Implement backups immediately." "WARNING"
    }

    if ($hasFullBackup -and $hasDiffBackup -and $hasTransLogBackup -and $hasSystemDbBackup) {
        Write-Log "All backup types (full, diff, trans log, system dbs) are covered by existing SQL Agent jobs."
    }

    Write-Log "ePO SQL tuning completed successfully."
    if ($WhatIf) { Write-Log "Run without -WhatIf to apply changes." }
} catch {
    Write-Log "Overall script error: $_" "ERROR"
    exit 1
}