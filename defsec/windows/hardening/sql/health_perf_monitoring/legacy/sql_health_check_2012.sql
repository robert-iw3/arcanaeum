-- SQL Script for Comprehensive SQL Server Health Check: Agent Jobs, Backups, and Enterprise Monitoring (2012-Compatible)
-- This script gathers extensive metrics on SQL Server health, performance, agent jobs, backups, and potential issues for an always-available production database.
-- It focuses on proactive monitoring to detect trends and issues early for maintenance.
-- Outputs in Prometheus exposition format (text/metrics 0.0.4) using PRINT statements.
-- Run this script periodically via SQL Server Agent job and redirect output to a file, e.g.:
-- sqlcmd -S servername -d master -E -i this_script.sql -t 300 > /path/to/sql_metrics.prom -- Use -t for query timeout (e.g., 300 seconds) to cancel if taking too long
-- Use node_exporter textfile collector or similar to expose to Prometheus.
-- For Loki (logs), the same output can be tailed by Promtail and ingested as logs with labels (e.g., job="sql_monitor", instance="servername").
-- Alternatively, add JSON log outputs if needed, but Prometheus format is primary for metrics.
-- Note: Requires permissions like VIEW SERVER STATE, VIEW DATABASE STATE, access to msdb, and xp_readerrorlog enabled.
-- For trends, run this script on a schedule and let Prometheus/Grafana handle historical analysis.
-- Enhancements: Added SET XACT_ABORT ON for immediate abort on errors; wrapped sections in TRY...CATCH for better error handling with logging;
-- All queries are read-only and use DMVs/system views, so they do not affect server operations (no DML/DDL changes).
-- To handle long-running execution, run with sqlcmd timeout (-t); script cleans up temp objects regardless.
-- If an error occurs, it will abort and rollback any open transaction, printing error details for Loki.
-- 2012 Adaptation: Replaced DATEDIFF_BIG with DATEDIFF(SECOND) * 1000 for approximate timestamp (loses ms precision).

USE master;
GO
SET XACT_ABORT ON; -- Abort on any error, rolling back the transaction if active
SET NOCOUNT ON; -- Suppress row count messages for cleaner output
BEGIN TRY
    BEGIN TRANSACTION; -- Wrap entire script in a transaction for rollback capability (though mostly SELECTs, ensures temp cleanup if needed)
    -- Helper: Unix timestamp in milliseconds (approximate for 2012 compatibility)
    DECLARE @timestamp BIGINT = CAST(DATEDIFF(SECOND, '1970-01-01', GETUTCDATE()) AS BIGINT) * 1000;
    -- Section 1: Core Health and Performance Metrics
    -- Metric: Number of blocked sessions
    DECLARE @blocked_sessions INT;
    SELECT @blocked_sessions = COUNT(*)
    FROM sys.dm_exec_requests
    WHERE blocking_session_id <> 0 AND session_id > 50; -- Exclude system sessions
    PRINT '# HELP sql_blocked_sessions Number of currently blocked user sessions'
    PRINT '# TYPE sql_blocked_sessions gauge'
    PRINT 'sql_blocked_sessions ' + CAST(@blocked_sessions AS VARCHAR(10)) + ' ' + CAST(@timestamp AS VARCHAR(20));
    -- Metric: Number of long-running queries (> 30 seconds)
    DECLARE @long_running_queries INT;
    SELECT @long_running_queries = COUNT(*)
    FROM sys.dm_exec_requests
    WHERE DATEDIFF(SECOND, start_time, GETDATE()) > 30 AND session_id > 50;
    PRINT '# HELP sql_long_running_queries Number of queries running longer than 30 seconds'
    PRINT '# TYPE sql_long_running_queries gauge'
    PRINT 'sql_long_running_queries ' + CAST(@long_running_queries AS VARCHAR(10)) + ' ' + CAST(@timestamp AS VARCHAR(20));
    -- Metric: Active user connections
    DECLARE @active_connections INT;
    SELECT @active_connections = COUNT(*)
    FROM sys.dm_exec_sessions
    WHERE is_user_process = 1;
    PRINT '# HELP sql_active_connections Number of active user connections'
    PRINT '# TYPE sql_active_connections gauge'
    PRINT 'sql_active_connections ' + CAST(@active_connections AS VARCHAR(10)) + ' ' + CAST(@timestamp AS VARCHAR(20));
    -- Metric: CPU usage percentage (approximate from wait stats)
    DECLARE @cpu_usage FLOAT;
    WITH CPUWaits AS (
        SELECT SUM(signal_wait_time_ms) AS signal_wait_time_ms,
               SUM(wait_time_ms - signal_wait_time_ms) AS resource_wait_time_ms
        FROM sys.dm_os_wait_stats
        WHERE wait_type IN ('SOS_SCHEDULER_YIELD', 'THREADPOOL')
    )
    SELECT @cpu_usage = (signal_wait_time_ms * 100.0) / NULLIF((signal_wait_time_ms + resource_wait_time_ms), 0);
    PRINT '# HELP sql_cpu_usage_pct Approximate CPU usage percentage from wait stats'
    PRINT '# TYPE sql_cpu_usage_pct gauge'
    PRINT 'sql_cpu_usage_pct ' + CAST(ISNULL(@cpu_usage, 0) AS VARCHAR(10)) + ' ' + CAST(@timestamp AS VARCHAR(20));
    -- Metric: Available physical memory (MB)
    DECLARE @avail_memory_MB BIGINT;
    SELECT @avail_memory_MB = available_physical_memory_kb / 1024
    FROM sys.dm_os_sys_memory;
    PRINT '# HELP sql_available_memory_mb Available physical memory in MB'
    PRINT '# TYPE sql_available_memory_mb gauge'
    PRINT 'sql_available_memory_mb ' + CAST(@avail_memory_MB AS VARCHAR(20)) + ' ' + CAST(@timestamp AS VARCHAR(20));
    -- Metric: Page life expectancy (seconds)
    DECLARE @page_life_expectancy BIGINT;
    SELECT @page_life_expectancy = cntr_value
    FROM sys.dm_os_performance_counters
    WHERE object_name = 'SQLServer:Buffer Manager' AND counter_name = 'Page life expectancy';
    PRINT '# HELP sql_page_life_expectancy Page life expectancy in seconds'
    PRINT '# TYPE sql_page_life_expectancy gauge'
    PRINT 'sql_page_life_expectancy ' + CAST(@page_life_expectancy AS VARCHAR(20)) + ' ' + CAST(@timestamp AS VARCHAR(20));
    -- Metric: TempDB usage percentage
    DECLARE @tempdb_usage_pct FLOAT;
    SELECT @tempdb_usage_pct = (SUM(allocated_extent_page_count) * 100.0) / NULLIF(SUM(total_page_count), 0)
    FROM tempdb.sys.dm_db_file_space_usage;
    PRINT '# HELP sql_tempdb_usage_pct TempDB space usage percentage'
    PRINT '# TYPE sql_tempdb_usage_pct gauge'
    PRINT 'sql_tempdb_usage_pct ' + CAST(ISNULL(@tempdb_usage_pct, 0) AS VARCHAR(10)) + ' ' + CAST(@timestamp AS VARCHAR(20));
    -- Metric: Average index fragmentation percentage (across all databases, for trend monitoring)
    -- Note: This can be slow on very large DBs; limited mode used
    DECLARE @avg_index_frag_pct FLOAT;
    SELECT @avg_index_frag_pct = AVG(avg_fragmentation_in_percent)
    FROM sys.dm_db_index_physical_stats(NULL, NULL, NULL, NULL, 'LIMITED')
    WHERE alloc_unit_type_desc = 'IN_ROW_DATA' AND page_count > 1000; -- Larger indexes
    PRINT '# HELP sql_avg_index_frag_pct Average index fragmentation percentage for large indexes'
    PRINT '# TYPE sql_avg_index_frag_pct gauge'
    PRINT 'sql_avg_index_frag_pct ' + CAST(ISNULL(@avg_index_frag_pct, 0) AS VARCHAR(10)) + ' ' + CAST(@timestamp AS VARCHAR(20));
    -- Metric: Number of deadlocks (from performance counters)
    DECLARE @deadlocks BIGINT;
    SELECT @deadlocks = cntr_value
    FROM sys.dm_os_performance_counters
    WHERE object_name LIKE '%Locks%' AND counter_name = 'Number of Deadlocks/sec'; -- Cumulative, but for trends in Prometheus
    PRINT '# HELP sql_deadlocks_total Cumulative number of deadlocks (rate in Prometheus)'
    PRINT '# TYPE sql_deadlocks_total counter'
    PRINT 'sql_deadlocks_total ' + CAST(@deadlocks AS VARCHAR(20)) + ' ' + CAST(@timestamp AS VARCHAR(20));
    -- Metric: Top wait type total time (ms, for the top wait)
    DECLARE @top_wait_time_ms BIGINT;
    WITH TopWaits AS (
        SELECT TOP 1 wait_type, wait_time_ms
        FROM sys.dm_os_wait_stats
        WHERE wait_type NOT IN ('SLEEP_TASK', 'WAITFOR', 'XE_TIMER', 'XE_DISPATCHER', 'REQUEST_FOR_DEADLOCK_SEARCH') -- Ignore benign
        ORDER BY wait_time_ms DESC
    )
    SELECT @top_wait_time_ms = wait_time_ms FROM TopWaits;
    PRINT '# HELP sql_top_wait_time_ms Total time (ms) for the top wait type'
    PRINT '# TYPE sql_top_wait_time_ms gauge'
    PRINT 'sql_top_wait_time_ms ' + CAST(@top_wait_time_ms AS VARCHAR(20)) + ' ' + CAST(@timestamp AS VARCHAR(20));
    -- Metric: Database file space usage (per database, labels)
    -- Note: Outputs per DB for detailed monitoring
    PRINT '# HELP sql_db_size_mb Database size in MB'
    PRINT '# TYPE sql_db_size_mb gauge'
    PRINT '# HELP sql_db_free_space_mb Database free space in MB'
    PRINT '# TYPE sql_db_free_space_mb gauge'
    DECLARE @db_space TABLE (db_name SYSNAME, data_size_mb FLOAT, log_size_mb FLOAT, data_free_mb FLOAT, log_free_mb FLOAT);
    INSERT INTO @db_space (db_name, data_size_mb, log_size_mb, data_free_mb, log_free_mb)
    SELECT d.name,
           SUM(CASE WHEN f.type = 0 THEN f.size * 8.0 / 1024 ELSE 0 END) AS data_size_mb,
           SUM(CASE WHEN f.type = 1 THEN f.size * 8.0 / 1024 ELSE 0 END) AS log_size_mb,
           SUM(CASE WHEN f.type = 0 THEN (f.size - FILEPROPERTY(f.name, 'SpaceUsed')) * 8.0 / 1024 ELSE 0 END) AS data_free_mb,
           SUM(CASE WHEN f.type = 1 THEN (f.size - FILEPROPERTY(f.name, 'SpaceUsed')) * 8.0 / 1024 ELSE 0 END) AS log_free_mb
    FROM sys.databases d
    INNER JOIN sys.master_files f ON d.database_id = f.database_id
    WHERE d.database_id > 4 -- User databases
    GROUP BY d.name;
    DECLARE @db_name SYSNAME, @data_size_mb FLOAT, @data_free_mb FLOAT;
    DECLARE db_cursor CURSOR LOCAL FAST_FORWARD FOR SELECT db_name, data_size_mb, data_free_mb FROM @db_space; -- Optimized cursor
    OPEN db_cursor;
    FETCH NEXT FROM db_cursor INTO @db_name, @data_size_mb, @data_free_mb;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        PRINT 'sql_db_size_mb{db_name="' + @db_name + '"} ' + CAST(@data_size_mb AS VARCHAR(20)) + ' ' + CAST(@timestamp AS VARCHAR(20));
        PRINT 'sql_db_free_space_mb{db_name="' + @db_name + '"} ' + CAST(@data_free_mb AS VARCHAR(20)) + ' ' + CAST(@timestamp AS VARCHAR(20));
        FETCH NEXT FROM db_cursor INTO @db_name, @data_size_mb, @data_free_mb;
    END
    CLOSE db_cursor;
    DEALLOCATE db_cursor;
    -- Metric: Recent errors (last 24 hours from error log)
    -- Wrapped in inner TRY...CATCH as xp_readerrorlog might fail if permissions issue
    BEGIN TRY
        CREATE TABLE #ErrorLog (LogDate DATETIME, ProcessInfo VARCHAR(50), [Text] VARCHAR(MAX));
        INSERT INTO #ErrorLog EXEC sp_readerrorlog 0, 1;
        DECLARE @recent_errors INT;
        SELECT @recent_errors = COUNT(*)
        FROM #ErrorLog
        WHERE LogDate >= DATEADD(HOUR, -24, GETDATE()) AND [Text] LIKE '%error%' OR [Text] LIKE '%fail%';
        PRINT '# HELP sql_recent_errors_24h Number of errors in the last 24 hours'
        PRINT '# TYPE sql_recent_errors_24h gauge'
        PRINT 'sql_recent_errors_24h ' + CAST(@recent_errors AS VARCHAR(10)) + ' ' + CAST(@timestamp AS VARCHAR(20));
        DROP TABLE #ErrorLog;
    END TRY
    BEGIN CATCH
        -- Log error to output for Loki
        PRINT '{ "timestamp": "' + CONVERT(VARCHAR(30), GETUTCDATE(), 126) + 'Z", "level": "error", "message": "Error reading error log: ' + ERROR_MESSAGE() + '", "service": "sql_monitor" }';
        PRINT 'sql_recent_errors_24h 0 ' + CAST(@timestamp AS VARCHAR(20)); -- Fallback metric
    END CATCH;
    -- Section 2: SQL Server Agent Job Statuses
    -- Metric: Number of failed jobs in last 24 hours
    DECLARE @failed_jobs_24h INT;
    SELECT @failed_jobs_24h = COUNT(DISTINCT j.job_id)
    FROM msdb.dbo.sysjobs j
    INNER JOIN msdb.dbo.sysjobhistory h ON j.job_id = h.job_id
    WHERE h.run_status = 0 -- Failed
    AND h.run_date >= CONVERT(VARCHAR(8), DATEADD(DAY, -1, GETDATE()), 112);
    PRINT '# HELP sql_failed_jobs_24h Number of failed Agent jobs in last 24 hours'
    PRINT '# TYPE sql_failed_jobs_24h gauge'
    PRINT 'sql_failed_jobs_24h ' + CAST(@failed_jobs_24h AS VARCHAR(10)) + ' ' + CAST(@timestamp AS VARCHAR(20));
    -- Metric: Per-job last status and run time (with labels)
    PRINT '# HELP sql_agent_job_status Last run status of Agent jobs (1=Success, 0=Failed, 3=Canceled)'
    PRINT '# TYPE sql_agent_job_status gauge'
    PRINT '# HELP sql_agent_job_last_run_seconds_ago Seconds since last run'
    PRINT '# TYPE sql_agent_job_last_run_seconds_ago gauge'
    DECLARE @job_status TABLE (job_name SYSNAME, last_status INT, last_run_datetime DATETIME);
    INSERT INTO @job_status (job_name, last_status, last_run_datetime)
    SELECT j.name,
           MAX(h.run_status) AS last_status,
           MAX(CAST(STR(h.run_date,8,0) + ' ' + STUFF(STUFF(REPLACE(STR(h.run_time,6,0),' ','0'),3,0,':'),6,0,':') AS DATETIME)) AS last_run_datetime
    FROM msdb.dbo.sysjobs j
    LEFT JOIN msdb.dbo.sysjobhistory h ON j.job_id = h.job_id
    GROUP BY j.name;
    DECLARE @job_name SYSNAME, @last_status INT, @last_run_datetime DATETIME;
    DECLARE job_cursor CURSOR LOCAL FAST_FORWARD FOR SELECT job_name, last_status, last_run_datetime FROM @job_status; -- Optimized cursor
    OPEN job_cursor;
    FETCH NEXT FROM job_cursor INTO @job_name, @last_status, @last_run_datetime;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        DECLARE @seconds_ago BIGINT = DATEDIFF(SECOND, ISNULL(@last_run_datetime, '1970-01-01'), GETDATE());
        PRINT 'sql_agent_job_status{job_name="' + REPLACE(@job_name, '"', '""') + '"} ' + CAST(ISNULL(@last_status, -1) AS VARCHAR(10)) + ' ' + CAST(@timestamp AS VARCHAR(20));
        PRINT 'sql_agent_job_last_run_seconds_ago{job_name="' + REPLACE(@job_name, '"', '""') + '"} ' + CAST(@seconds_ago AS VARCHAR(20)) + ' ' + CAST(@timestamp AS VARCHAR(20));
        FETCH NEXT FROM job_cursor INTO @job_name, @last_status, @last_run_datetime;
    END
    CLOSE job_cursor;
    DEALLOCATE job_cursor;
    -- Section 3: Backup Statuses
    -- Metric: Number of databases without recent full backup (last 24 hours)
    DECLARE @unbacked_dbs_24h INT;
    SELECT @unbacked_dbs_24h = COUNT(*)
    FROM sys.databases d
    LEFT JOIN msdb.dbo.backupset b ON d.name = b.database_name AND b.type = 'D' -- Full
    WHERE d.database_id > 4
    GROUP BY d.name
    HAVING MAX(b.backup_finish_date) < DATEADD(HOUR, -24, GETDATE()) OR MAX(b.backup_finish_date) IS NULL;
    PRINT '# HELP sql_unbacked_dbs_24h Number of user databases without a full backup in last 24 hours'
    PRINT '# TYPE sql_unbacked_dbs_24h gauge'
    PRINT 'sql_unbacked_dbs_24h ' + CAST(@unbacked_dbs_24h AS VARCHAR(10)) + ' ' + CAST(@timestamp AS VARCHAR(20));
    -- Metric: Per-database backup age in hours (with labels)
    PRINT '# HELP sql_backup_age_hours Hours since last full backup per database'
    PRINT '# TYPE sql_backup_age_hours gauge'
    DECLARE @backup_status TABLE (db_name SYSNAME, last_backup DATETIME);
    INSERT INTO @backup_status (db_name, last_backup)
    SELECT d.name,
           MAX(b.backup_finish_date) AS last_backup
    FROM sys.databases d
    LEFT JOIN msdb.dbo.backupset b ON d.name = b.database_name AND b.type = 'D'
    WHERE d.database_id > 4
    GROUP BY d.name;
    DECLARE @db_name_bk SYSNAME, @last_backup DATETIME;
    DECLARE backup_cursor CURSOR LOCAL FAST_FORWARD FOR SELECT db_name, last_backup FROM @backup_status; -- Optimized cursor
    OPEN backup_cursor;
    FETCH NEXT FROM backup_cursor INTO @db_name_bk, @last_backup;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        DECLARE @age_hours INT = DATEDIFF(HOUR, ISNULL(@last_backup, '1970-01-01'), GETDATE());
        PRINT 'sql_backup_age_hours{db_name="' + @db_name_bk + '"} ' + CAST(@age_hours AS VARCHAR(10)) + ' ' + CAST(@timestamp AS VARCHAR(20));
        FETCH NEXT FROM backup_cursor INTO @db_name_bk, @last_backup;
    END
    CLOSE backup_cursor;
    DEALLOCATE backup_cursor;
    -- Additional: For Loki integration, optionally output JSON logs for events (e.g., if errors > 0)
    -- Example: If recent_errors > 0, PRINT a JSON line
    IF @recent_errors > 0
    BEGIN
        PRINT '{ "timestamp": "' + CONVERT(VARCHAR(30), GETUTCDATE(), 126) + 'Z", "level": "warning", "message": "Recent errors detected: ' + CAST(@recent_errors AS VARCHAR(10)) + '", "service": "sql_monitor" }';
    END
    -- Add similar for other thresholds, e.g., if blocked_sessions > 0, etc.
    IF @blocked_sessions > 0
    BEGIN
        PRINT '{ "timestamp": "' + CONVERT(VARCHAR(30), GETUTCDATE(), 126) + 'Z", "level": "warning", "message": "Blocked sessions detected: ' + CAST(@blocked_sessions AS VARCHAR(10)) + '", "service": "sql_monitor" }';
    END
    COMMIT TRANSACTION; -- Commit if no errors
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0
        ROLLBACK TRANSACTION; -- Rollback on error
    -- Output error details for logging (e.g., to Loki via file tailing)
    DECLARE @error_message NVARCHAR(4000) = ERROR_MESSAGE();
    DECLARE @error_severity INT = ERROR_SEVERITY();
    DECLARE @error_state INT = ERROR_STATE();
    PRINT '{ "timestamp": "' + CONVERT(VARCHAR(30), GETUTCDATE(), 126) + 'Z", "level": "error", "message": "Script error: ' + @error_message + ' (Severity: ' + CAST(@error_severity AS VARCHAR(10)) + ', State: ' + CAST(@error_state AS VARCHAR(10)) + ')", "service": "sql_monitor" }';
    -- Optionally, re-raise for caller awareness
    -- RAISERROR(@error_message, @error_severity, @error_state);
END CATCH;
-- End of Script
GO