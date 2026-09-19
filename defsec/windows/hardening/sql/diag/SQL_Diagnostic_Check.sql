USE master;
GO
/*************************************************************
    SQL Server Comprehensive Diagnostic & Troubleshooting Script
    Compatible with SQL Server 2019 / 2022 / 2025
    - xp_cmdshell: Checked at start, enabled only if needed, always restored at end
    - Full error handling with XACT_ABORT
    - Includes Wait Stats, Blocking, TempDB Contention, Deadlocks, Query Store, Corruption, VLFs, etc.
    - Exports CSV + HTML to Desktop
    @RW
*************************************************************/

SET NOCOUNT ON;
SET XACT_ABORT ON;

DECLARE @OriginalXPCmdShell INT = 0;
DECLARE @ReportPath VARCHAR(500) = 'C:\Users\' + SUSER_NAME() + '\Desktop\SQL_Diagnostic_Report_';
DECLARE @Timestamp VARCHAR(20) = FORMAT(GETDATE(), 'yyyyMMdd_HHmmss');
DECLARE @CSVFile VARCHAR(255) = @ReportPath + @Timestamp + '.csv';
DECLARE @HTMLFile VARCHAR(255) = @ReportPath + @Timestamp + '.html';

-- ===================================================================
-- 1. xp_cmdshell CHECK & TEMPORARY ENABLE
-- ===================================================================
SELECT @OriginalXPCmdShell = CAST(value_in_use AS INT)
FROM sys.configurations
WHERE name = 'xp_cmdshell';

IF @OriginalXPCmdShell = 0
BEGIN
    EXEC sp_configure 'show advanced options', 1;
    RECONFIGURE WITH OVERRIDE;
    EXEC sp_configure 'xp_cmdshell', 1;
    RECONFIGURE WITH OVERRIDE;
    PRINT 'xp_cmdshell temporarily enabled for report export.';
END

-- ===================================================================
-- 2. CREATE FINDINGS TABLE IN TEMPDB
-- ===================================================================
IF OBJECT_ID('tempdb..#DiagnosticFindings') IS NOT NULL
    DROP TABLE tempdb..#DiagnosticFindings;

CREATE TABLE tempdb..#DiagnosticFindings (
    ID              INT IDENTITY(1,1) PRIMARY KEY,
    Priority        VARCHAR(10),
    Category        VARCHAR(50),
    Finding         NVARCHAR(200),
    Details         NVARCHAR(MAX),
    Recommendation  NVARCHAR(MAX)
);

BEGIN TRY
    PRINT '=== Starting Comprehensive SQL Server Diagnostic Check ===';

    /* =============================================
       SECURITY / STIG CHECKS
       ============================================= */
    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT
        CASE WHEN SERVERPROPERTY('IsIntegratedSecurityOnly') = 0 THEN 'HIGH' ELSE 'LOW' END,
        'Security', 'Authentication Mode',
        'Current: ' + CASE SERVERPROPERTY('IsIntegratedSecurityOnly') WHEN 0 THEN 'Mixed' ELSE 'Windows Only' END,
        CASE WHEN SERVERPROPERTY('IsIntegratedSecurityOnly') = 0 THEN 'Switch to Windows Authentication only.' ELSE 'Good.' END;

    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT
        CASE WHEN is_disabled = 0 THEN 'HIGH' ELSE 'LOW' END,
        'Security', 'SA Account',
        'SA is ' + CASE WHEN is_disabled = 1 THEN 'DISABLED' ELSE 'ENABLED' END,
        CASE WHEN is_disabled = 1 THEN 'Good.' ELSE 'Disable and rename SA immediately.' END
    FROM sys.sql_logins WHERE principal_id = 1;

    /* =============================================
       INDEX FRAGMENTATION
       ============================================= */
    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT
        CASE WHEN avg_fragmentation_in_percent > 30 THEN 'HIGH'
             WHEN avg_fragmentation_in_percent > 10 THEN 'MEDIUM' ELSE 'LOW' END,
        'Index Fragmentation',
        'Fragmented Index',
        DB_NAME(ps.database_id) + '.' + SCHEMA_NAME(o.schema_id) + '.' + o.name +
        ' (' + i.name + ') = ' + CONVERT(varchar(10), avg_fragmentation_in_percent) + '%',
        'Rebuild if >30%, reorganize if 10-30%.'
    FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'LIMITED') ps
    JOIN sys.objects o ON ps.object_id = o.object_id
    JOIN sys.indexes i ON ps.object_id = i.object_id AND ps.index_id = i.index_id
    WHERE ps.database_id > 4
      AND ps.index_id > 0
      AND avg_fragmentation_in_percent > 10;

    /* =============================================
       MISSING INDEXES
       ============================================= */
    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT 'MEDIUM', 'Missing Indexes', 'High Impact Missing Index',
           'DB: ' + DB_NAME(mid.database_id) + ' | Impact: ' + CONVERT(varchar(10), ROUND(migs.avg_user_impact,2)) + '%',
           'Consider creating the suggested index.'
    FROM sys.dm_db_missing_index_group_stats migs
    JOIN sys.dm_db_missing_index_groups mig ON migs.group_handle = mig.index_group_handle
    JOIN sys.dm_db_missing_index_details mid ON mig.index_handle = mid.index_handle
    WHERE migs.avg_user_impact > 50 AND migs.user_seeks > 1000;

    /* =============================================
       STATISTICS SUMMARY
       ============================================= */
    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT 'MEDIUM', 'Statistics', 'Stale Statistics',
           DB_NAME() + ' | ' + SCHEMA_NAME(o.schema_id) + '.' + o.name +
           ' | Last Updated: ' + ISNULL(CONVERT(varchar(20), s.last_updated, 120), 'NEVER'),
           'Update statistics with FULLSCAN on large tables.'
    FROM sys.stats s
    JOIN sys.objects o ON s.object_id = o.object_id
    WHERE o.type = 'U'
      AND (s.last_updated IS NULL OR DATEDIFF(DAY, s.last_updated, GETDATE()) > 7);

    /* =============================================
       PERFORMANCE METRICS
       ============================================= */
    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT 'MEDIUM', 'Performance', 'Buffer Cache Hit Ratio',
           CONVERT(varchar(10), ROUND(100.0 * cntr_value /
           (SELECT cntr_value FROM sys.dm_os_performance_counters
            WHERE counter_name = 'Buffer cache hit ratio base'), 2)) + '%',
           'Target > 95%.'
    FROM sys.dm_os_performance_counters
    WHERE counter_name = 'Buffer cache hit ratio';

    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT 'MEDIUM', 'Performance', 'Page Life Expectancy',
           cntr_value + ' seconds',
           'Target > 300 seconds. Low PLE = memory pressure.'
    FROM sys.dm_os_performance_counters
    WHERE counter_name = 'Page life expectancy';

    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT 'HIGH', 'Performance', 'CPU Usage (Last 10 min)',
           CONVERT(varchar(10), AVG(CPU)) + '% average',
           'High sustained CPU may require query/index tuning.'
    FROM (
        SELECT record.value('(./Record/SchedulerMonitorEvent/SystemHealth/ProcessUtilization/text())[1]', 'int') AS CPU
        FROM (SELECT CAST(record AS xml) AS record
              FROM sys.dm_os_ring_buffers
              WHERE ring_buffer_type = N'RING_BUFFER_SCHEDULER_MONITOR'
              AND timestamp > DATEADD(MINUTE, -10, GETDATE())) x
    ) y;

    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT 'MEDIUM', 'Performance', 'Memory Pressure',
           'Available Physical Memory: ' + CONVERT(varchar(20), available_physical_memory_kb/1024) + ' MB',
           'If consistently low, investigate memory pressure.'
    FROM sys.dm_os_sys_memory;

    /* =============================================
       WAIT STATS MONITORING
       ============================================= */
    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT TOP 15
        'MEDIUM',
        'Wait Statistics',
        wait_type,
        CONVERT(varchar(20), waiting_tasks_count) + ' tasks, ' +
        CONVERT(varchar(20), ROUND(wait_time_ms/1000.0, 2)) + ' seconds total wait',
        'Tune queries/indexes or investigate hardware.'
    FROM sys.dm_os_wait_stats
    WHERE wait_type NOT IN (
        'WAITFOR','HADR_FILESTREAM_IOMGR_IOCOMPLETION','LAZYWRITER_SLEEP',
        'LOGMGR_QUEUE','CHECKPOINT_QUEUE','REQUEST_FOR_DEADLOCK_SEARCH',
        'XE_TIMER_EVENT','BROKER_TO_FLUSH','BROKER_TASK_STOP','CLR_AUTO_EVENT',
        'FT_IFTS_SCHEDULER_IDLE_WAIT','XE_DISPATCHER_WAIT','XE_DISPATCHER_JOIN',
        'SQLTRACE_BUFFER_FLUSH','SLEEP_TASK','BROKER_EVENTHANDLER','TRACEWRITE',
        'SLEEP_SYSTEMTASK','DBMIRROR_EVENTS_QUEUE','DBMIRRORING_CMD')
    ORDER BY wait_time_ms DESC;

    /* =============================================
       BLOCKING QUERY ANALYSIS
       ============================================= */
    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT
        CASE WHEN COUNT(*) > 0 THEN 'HIGH' ELSE 'LOW' END,
        'Blocking',
        'Current Blocking Sessions',
        'Head blocker SPID ' + CONVERT(varchar(10), blocking_session_id) +
        ' is blocking ' + CONVERT(varchar(10), COUNT(*)) + ' session(s)',
        'Review blocked queries and tune.'
    FROM sys.dm_exec_requests
    WHERE blocking_session_id <> 0
    GROUP BY blocking_session_id;

    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT
        'HIGH',
        'Blocking',
        'Blocked Query',
        'SPID ' + CONVERT(varchar(10), r.session_id) + ' blocked by SPID ' +
        CONVERT(varchar(10), r.blocking_session_id),
        'Investigate and optimize the blocking query.'
    FROM sys.dm_exec_requests r
    WHERE r.blocking_session_id <> 0;

    /* =============================================
       TEMPDB CONTENTION
       ============================================= */
    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT
        CASE WHEN waiting_tasks_count > 1000 THEN 'HIGH' ELSE 'MEDIUM' END,
        'TempDB Contention',
        'PAGELATCH Contention',
        'High PAGELATCH_XX waits on TempDB (' + CONVERT(varchar(20), waiting_tasks_count) + ' waits)',
        'Add more TempDB data files (1 per core up to 8) and enable trace flag 1118 if needed.'
    FROM sys.dm_os_wait_stats
    WHERE wait_type LIKE 'PAGELATCH%'
      AND waiting_tasks_count > 500;

    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT
        CASE WHEN COUNT(*) < 4 THEN 'HIGH' ELSE 'LOW' END,
        'TempDB Contention',
        'TempDB File Count',
        'Only ' + CONVERT(varchar(10), COUNT(*)) + ' TempDB data files found',
        'Recommended: 1 file per core (max 8) on fast storage.'
    FROM tempdb.sys.database_files
    WHERE type_desc = 'ROWS';

    /* =============================================
       DEADLOCKS (Last 30 Days)
       ============================================= */
    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT
        CASE WHEN COUNT(*) > 0 THEN 'HIGH' ELSE 'LOW' END,
        'Deadlocks',
        'Deadlocks Detected',
        'Found ' + CONVERT(varchar(10), COUNT(*)) + ' deadlock(s) in last 30 days',
        'Review system_health extended event for deadlock graphs.'
    FROM sys.dm_xe_session_targets t
    CROSS APPLY (SELECT CAST(target_data AS xml) AS target_data
                 FROM sys.dm_xe_session_targets WHERE target_id = t.target_id) x
    WHERE t.target_name = 'ring_buffer'
      AND x.target_data.exist('//event[@name="xml_deadlock_report"]') = 1
      AND x.target_data.value('(//event/@timestamp)[1]', 'datetime') > DATEADD(DAY, -30, GETDATE());

    /* =============================================
       QUERY STORE
       ============================================= */
    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT 'MEDIUM', 'Query Store', 'Query Store Status',
           DB_NAME() + ' - Query Store is ' + actual_state_desc,
           'Enable Query Store and set to READ_WRITE if not already.'
    FROM sys.database_query_store_options
    WHERE actual_state_desc IN ('READ_ONLY', 'OFF');

    /* =============================================
       CORRUPTION / LAST GOOD CHECKDB
       ============================================= */
    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT
        CASE WHEN last_good IS NULL OR DATEDIFF(DAY, last_good, GETDATE()) > 30 THEN 'HIGH' ELSE 'MEDIUM' END,
        'Corruption',
        'Last Known Good DBCC CHECKDB',
        db.name + ' - Last successful: ' + ISNULL(CONVERT(varchar(20), last_good, 120), 'NEVER'),
        'Run DBCC CHECKDB ASAP if older than 30 days.'
    FROM sys.databases db
    CROSS APPLY (
        SELECT MAX(backup_finish_date) AS last_good
        FROM msdb.dbo.backupset
        WHERE database_name = db.name AND type = 'D' AND is_copy_only = 0
    ) ca
    WHERE db.database_id > 4;

    /* =============================================
       TRANSACTION LOG VLFs
       ============================================= */
    INSERT INTO tempdb..#DiagnosticFindings (Priority, Category, Finding, Details, Recommendation)
    SELECT
        CASE WHEN vlf_count > 1000 THEN 'HIGH' WHEN vlf_count > 200 THEN 'MEDIUM' ELSE 'LOW' END,
        'Transaction Log',
        'High VLF Count',
        db.name + ' has ' + CONVERT(varchar(20), vlf_count) + ' VLFs',
        'Shrink + grow log in larger increments.'
    FROM (
        SELECT db.name, COUNT(*) AS vlf_count
        FROM sys.databases db
        CROSS APPLY sys.dm_db_log_info(db.database_id) li
        WHERE db.database_id > 4
        GROUP BY db.name
    ) vlf;

    /* =============================================
       EXPORT TO CSV + HTML (LINE-BY-LINE FIX)
       ============================================= */
    DECLARE @LineCmd NVARCHAR(4000);
    DECLARE @CSVRow NVARCHAR(MAX);
    DECLARE @HTMLRow NVARCHAR(MAX);
    DECLARE @SafeHTMLRow NVARCHAR(MAX);

    -- 1. Initialize CSV File with Header (using > to create/overwrite)
    SET @LineCmd = 'echo Priority,Category,Finding,Details,Recommendation > "' + @CSVFile + '"';
    EXEC xp_cmdshell @LineCmd, NO_OUTPUT;

    -- 2. Initialize HTML File with Head/Styles (Escaping < and > with ^ for cmd.exe)
    SET @LineCmd = 'echo ^<html^>^<head^>^<title^>SQL Diagnostic Report^</title^> > "' + @HTMLFile + '"';
    EXEC xp_cmdshell @LineCmd, NO_OUTPUT;

    SET @LineCmd = 'echo ^<style^>table{border-collapse:collapse;width:100%%;} th,td{border:1px solid black;padding:8px;text-align:left;} ^</style^> >> "' + @HTMLFile + '"';
    EXEC xp_cmdshell @LineCmd, NO_OUTPUT;

    SET @LineCmd = 'echo ^<style^>tr.high{background-color:#ffdddd;} tr.medium{background-color:#ffffcc;}^</style^>^</head^>^<body^> >> "' + @HTMLFile + '"';
    EXEC xp_cmdshell @LineCmd, NO_OUTPUT;

    SET @LineCmd = 'echo ^<h1^>SQL Server Comprehensive Diagnostic Report - ' + CONVERT(varchar(20), GETDATE(), 120) + '^</h1^> >> "' + @HTMLFile + '"';
    EXEC xp_cmdshell @LineCmd, NO_OUTPUT;

    SET @LineCmd = 'echo ^<table^>^<tr^>^<th^>Priority^</th^>^<th^>Category^</th^>^<th^>Finding^</th^>^<th^>Details^</th^>^<th^>Recommendation^</th^>^</tr^> >> "' + @HTMLFile + '"';
    EXEC xp_cmdshell @LineCmd, NO_OUTPUT;

    -- 3. Cursor to write data line-by-line
    DECLARE export_cursor CURSOR LOCAL FAST_FORWARD FOR
    SELECT
        -- CSV Format
        Priority + ',' +
        '"' + REPLACE(Category, '"', '""') + '",' +
        '"' + REPLACE(Finding, '"', '""') + '",' +
        '"' + REPLACE(Details, '"', '""') + '",' +
        '"' + REPLACE(Recommendation, '"', '""') + '"',

        -- HTML Format
        '<tr class="' + LOWER(Priority) + '">' +
        '<td>' + Priority + '</td>' +
        '<td>' + Category + '</td>' +
        '<td>' + Finding + '</td>' +
        '<td>' + Details + '</td>' +
        '<td>' + Recommendation + '</td></tr>'
    FROM tempdb..#DiagnosticFindings
    ORDER BY
        CASE Priority WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
        Category, Finding;

    OPEN export_cursor;
    FETCH NEXT FROM export_cursor INTO @CSVRow, @HTMLRow;

    WHILE @@FETCH_STATUS = 0
    BEGIN
        -- Append CSV Row (using >> to append)
        SET @LineCmd = 'echo ' + @CSVRow + ' >> "' + @CSVFile + '"';
        EXEC xp_cmdshell @LineCmd, NO_OUTPUT;

        -- Escape HTML characters for cmd.exe before appending
        SET @SafeHTMLRow = REPLACE(REPLACE(REPLACE(@HTMLRow, '<', '^<'), '>', '^>'), '&', '^&');
        SET @LineCmd = 'echo ' + @SafeHTMLRow + ' >> "' + @HTMLFile + '"';
        EXEC xp_cmdshell @LineCmd, NO_OUTPUT;

        FETCH NEXT FROM export_cursor INTO @CSVRow, @HTMLRow;
    END

    CLOSE export_cursor;
    DEALLOCATE export_cursor;

    -- 4. Close HTML Tags
    SET @LineCmd = 'echo ^</table^>^</body^>^</html^> >> "' + @HTMLFile + '"';
    EXEC xp_cmdshell @LineCmd, NO_OUTPUT;

    PRINT '=== Diagnostic Check Complete ===';
    PRINT 'CSV Report: ' + @CSVFile;
    PRINT 'HTML Report: ' + @HTMLFile;

END TRY
BEGIN CATCH
    PRINT 'ERROR: ' + ERROR_MESSAGE();
    IF @@TRANCOUNT > 0 ROLLBACK;
    THROW;
END CATCH;

-- ===================================================================
-- ALWAYS RESTORE xp_cmdshell TO ORIGINAL STATE
-- ===================================================================
IF @OriginalXPCmdShell = 0
BEGIN
    EXEC sp_configure 'xp_cmdshell', 0;
    RECONFIGURE WITH OVERRIDE;
    PRINT 'xp_cmdshell restored to OFF (original state).';
END

DROP TABLE IF EXISTS tempdb..#DiagnosticFindings;