### Using `dbxquery` for SQL Queries in Splunk DB Connect

To integrate the health monitoring metrics with Splunk DB Connect using the `| dbxquery` command, you can execute each separate SQL query directly in Splunk searches or saved searches. The `dbxquery` command allows you to run SQL against your configured database connection (e.g., your SQL Server) and return results as Splunk events. This is ideal for scheduled execution every hour (e.g., via saved searches with cron `0 * * * *`), enabling data ingestion for trending over time.

**Important Instructions for Adaptation**:
- Replace `"your_connection_name"` in all examples with your actual DBX connection name (configured in Splunk DB Connect under Connections > New Connection). For example, if your connection is named "sql_server_prod", use `connection="sql_server_prod"`.
- Each query is designed to return tabular data (e.g., fields: `metric_name`, `value`, `timestamp`, optional `label_*` for dimensions like db_name).
- In Splunk, create saved searches for each or group them; set to run hourly. Index to a dedicated index (e.g., `sql_metrics`) for easy querying.
- For overtime trends, use Splunk's `_time` (mapped from `timestamp`) in timecharts (e.g., over last 24h or 7d).
- Test in Splunk Search UI first: Run `| dbxquery connection="your_connection_name" query="your_sql_here"`.
- If errors occur (e.g., permissions), check DBX logs in Splunk.

The separate queries below are optimized for `dbxquery` usage. Each can be pasted directly into the `query` parameter.

#### 1. Blocked Sessions Query
```
| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @blocked_sessions INT; SELECT @blocked_sessions = COUNT(*) FROM sys.dm_exec_requests WHERE blocking_session_id <> 0 AND session_id > 50; SELECT 'sql_blocked_sessions' AS metric_name, @blocked_sessions AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;"
```

#### 2. Long-Running Queries Query
```
| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @long_running_queries INT; SELECT @long_running_queries = COUNT(*) FROM sys.dm_exec_requests WHERE DATEDIFF(SECOND, start_time, GETDATE()) > 30 AND session_id > 50; SELECT 'sql_long_running_queries' AS metric_name, @long_running_queries AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;"
```

#### 3. Active Connections Query
```
| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @active_connections INT; SELECT @active_connections = COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process = 1; SELECT 'sql_active_connections' AS metric_name, @active_connections AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;"
```

#### 4. CPU Usage Query
```
| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @cpu_usage FLOAT; WITH CPUWaits AS ( SELECT SUM(signal_wait_time_ms) AS signal_wait_time_ms, SUM(wait_time_ms - signal_wait_time_ms) AS resource_wait_time_ms FROM sys.dm_os_wait_stats WHERE wait_type IN ('SOS_SCHEDULER_YIELD', 'THREADPOOL') ) SELECT @cpu_usage = (signal_wait_time_ms * 100.0) / NULLIF((signal_wait_time_ms + resource_wait_time_ms), 0) FROM CPUWaits; SELECT 'sql_cpu_usage_pct' AS metric_name, ISNULL(@cpu_usage, 0) AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;"
```

#### 5. Available Memory Query
```
| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @avail_memory_MB BIGINT; SELECT @avail_memory_MB = available_physical_memory_kb / 1024 FROM sys.dm_os_sys_memory; SELECT 'sql_available_memory_mb' AS metric_name, @avail_memory_MB AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;"
```

#### 6. Page Life Expectancy Query
```
| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @page_life_expectancy BIGINT; SELECT @page_life_expectancy = cntr_value FROM sys.dm_os_performance_counters WHERE object_name = 'SQLServer:Buffer Manager' AND counter_name = 'Page life expectancy'; SELECT 'sql_page_life_expectancy' AS metric_name, @page_life_expectancy AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;"
```

#### 7. TempDB Usage Query
```
| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @tempdb_usage_pct FLOAT; SELECT @tempdb_usage_pct = (SUM(allocated_extent_page_count) * 100.0) / NULLIF(SUM(total_page_count), 0) FROM tempdb.sys.dm_db_file_space_usage; SELECT 'sql_tempdb_usage_pct' AS metric_name, ISNULL(@tempdb_usage_pct, 0) AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;"
```

#### 8. Average Index Fragmentation Query
```
| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @avg_index_frag_pct FLOAT; SELECT @avg_index_frag_pct = AVG(avg_fragmentation_in_percent) FROM sys.dm_db_index_physical_stats(NULL, NULL, NULL, NULL, 'LIMITED') WHERE alloc_unit_type_desc = 'IN_ROW_DATA' AND page_count > 1000; SELECT 'sql_avg_index_frag_pct' AS metric_name, ISNULL(@avg_index_frag_pct, 0) AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;"
```

#### 9. Deadlocks Query
```
| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @deadlocks BIGINT; SELECT @deadlocks = cntr_value FROM sys.dm_os_performance_counters WHERE object_name LIKE '%Locks%' AND counter_name = 'Number of Deadlocks/sec'; SELECT 'sql_deadlocks_total' AS metric_name, @deadlocks AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;"
```

#### 10. Top Wait Time Query
```
| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @top_wait_time_ms BIGINT; WITH TopWaits AS ( SELECT TOP 1 wait_type, wait_time_ms FROM sys.dm_os_wait_stats WHERE wait_type NOT IN ('SLEEP_TASK', 'WAITFOR', 'XE_TIMER', 'XE_DISPATCHER', 'REQUEST_FOR_DEADLOCK_SEARCH') ORDER BY wait_time_ms DESC ) SELECT @top_wait_time_ms = wait_time_ms FROM TopWaits; SELECT 'sql_top_wait_time_ms' AS metric_name, @top_wait_time_ms AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;"
```

#### 11. Database Space Usage Query
```
| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); SELECT d.name AS db_name, 'sql_db_size_mb' AS metric_name, SUM(CASE WHEN f.type = 0 THEN f.size * 8.0 / 1024 ELSE 0 END) AS value, @timestamp AS timestamp, d.name AS label_db_name FROM sys.databases d INNER JOIN sys.master_files f ON d.database_id = f.database_id WHERE d.database_id > 4 GROUP BY d.name UNION ALL SELECT d.name AS db_name, 'sql_db_free_space_mb' AS metric_name, SUM(CASE WHEN f.type = 0 THEN (f.size - FILEPROPERTY(f.name, 'SpaceUsed')) * 8.0 / 1024 ELSE 0 END) AS value, @timestamp AS timestamp, d.name AS label_db_name FROM sys.databases d INNER JOIN sys.master_files f ON d.database_id = f.database_id WHERE d.database_id > 4 GROUP BY d.name; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp, NULL AS label_db_name; END CATCH;"
```

#### 12. Recent Errors Query
```
| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); CREATE TABLE #ErrorLog (LogDate DATETIME, ProcessInfo VARCHAR(50), [Text] VARCHAR(MAX)); INSERT INTO #ErrorLog EXEC sp_readerrorlog 0, 1; DECLARE @recent_errors INT; SELECT @recent_errors = COUNT(*) FROM #ErrorLog WHERE LogDate >= DATEADD(HOUR, -24, GETDATE()) AND [Text] LIKE '%error%' OR [Text] LIKE '%fail%'; DROP TABLE #ErrorLog; SELECT 'sql_recent_errors_24h' AS metric_name, @recent_errors AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;"
```

#### 13. Failed Jobs Query
```
| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @failed_jobs_24h INT; SELECT @failed_jobs_24h = COUNT(DISTINCT j.job_id) FROM msdb.dbo.sysjobs j INNER JOIN msdb.dbo.sysjobhistory h ON j.job_id = h.job_id WHERE h.run_status = 0 AND h.run_date >= CONVERT(VARCHAR(8), DATEADD(DAY, -1, GETDATE()), 112); SELECT 'sql_failed_jobs_24h' AS metric_name, @failed_jobs_24h AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;"
```

#### 14. Job Status Query
```
| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @job_status TABLE (job_name SYSNAME, last_status INT, last_run_datetime DATETIME); INSERT INTO @job_status (job_name, last_status, last_run_datetime) SELECT j.name, MAX(h.run_status) AS last_status, MAX(CAST(STR(h.run_date,8,0) + ' ' + STUFF(STUFF(REPLACE(STR(h.run_time,6,0),' ','0'),3,0,':'),6,0,':') AS DATETIME)) AS last_run_datetime FROM msdb.dbo.sysjobs j LEFT JOIN msdb.dbo.sysjobhistory h ON j.job_id = h.job_id GROUP BY j.name; SELECT 'sql_agent_job_status' AS metric_name, last_status AS value, @timestamp AS timestamp, job_name AS label_job_name FROM @job_status UNION ALL SELECT 'sql_agent_job_last_run_seconds_ago' AS metric_name, DATEDIFF(SECOND, ISNULL(last_run_datetime, '1970-01-01'), GETDATE()) AS value, @timestamp AS timestamp, job_name AS label_job_name FROM @job_status; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp, NULL AS label_job_name; END CATCH;"
```

#### 15. Unbacked Databases Query
```
| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @unbacked_dbs_24h INT; SELECT @unbacked_dbs_24h = COUNT(*) FROM sys.databases d LEFT JOIN msdb.dbo.backupset b ON d.name = b.database_name AND b.type = 'D' WHERE d.database_id > 4 GROUP BY d.name HAVING MAX(b.backup_finish_date) < DATEADD(HOUR, -24, GETDATE()) OR MAX(b.backup_finish_date) IS NULL; SELECT 'sql_unbacked_dbs_24h' AS metric_name, @unbacked_dbs_24h AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;"
```

#### 16. Backup Age Query
```
| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @backup_status TABLE (db_name SYSNAME, last_backup DATETIME); INSERT INTO @backup_status (db_name, last_backup) SELECT d.name, MAX(b.backup_finish_date) AS last_backup FROM sys.databases d LEFT JOIN msdb.dbo.backupset b ON d.name = b.database_name AND b.type = 'D' WHERE d.database_id > 4 GROUP BY d.name; SELECT 'sql_backup_age_hours' AS metric_name, DATEDIFF(HOUR, ISNULL(last_backup, '1970-01-01'), GETDATE()) AS value, @timestamp AS timestamp, db_name AS label_db_name FROM @backup_status; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp, NULL AS label_db_name; END CATCH;"
```

### Splunk XML Dashboard Source File (dashboard.xml)

This revised XML uses `| dbxquery` in each panel's search, with `connection="your_connection_name"` (change to your actual connection). Panels refresh every 3600 seconds (1 hour) to align with query intervals. Single values show latest metrics; charts show trends over time (last 24h by default, but adjustable). The dashboard populates overtime by leveraging Splunk's time-based searching on the `timestamp` field (mapped to `_time`).

```xml
<form version="1.1" theme="dark">
  <label>SQL Server Health Dashboard</label>
  <row>
    <panel>
      <single>
        <title>Blocked Sessions</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @blocked_sessions INT; SELECT @blocked_sessions = COUNT(*) FROM sys.dm_exec_requests WHERE blocking_session_id <> 0 AND session_id > 50; SELECT 'sql_blocked_sessions' AS metric_name, @blocked_sessions AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
      </single>
      <chart>
        <title>Blocked Sessions Over Time</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @blocked_sessions INT; SELECT @blocked_sessions = COUNT(*) FROM sys.dm_exec_requests WHERE blocking_session_id <> 0 AND session_id > 50; SELECT 'sql_blocked_sessions' AS metric_name, @blocked_sessions AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">line</option>
      </chart>
    </panel>
    <panel>
      <single>
        <title>Long Running Queries</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @long_running_queries INT; SELECT @long_running_queries = COUNT(*) FROM sys.dm_exec_requests WHERE DATEDIFF(SECOND, start_time, GETDATE()) > 30 AND session_id > 50; SELECT 'sql_long_running_queries' AS metric_name, @long_running_queries AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Long Running Queries Over Time</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @long_running_queries INT; SELECT @long_running_queries = COUNT(*) FROM sys.dm_exec_requests WHERE DATEDIFF(SECOND, start_time, GETDATE()) > 30 AND session_id > 50; SELECT 'sql_long_running_queries' AS metric_name, @long_running_queries AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <single>
        <title>Active Connections</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @active_connections INT; SELECT @active_connections = COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process = 1; SELECT 'sql_active_connections' AS metric_name, @active_connections AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Active Connections Over Time</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @active_connections INT; SELECT @active_connections = COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process = 1; SELECT 'sql_active_connections' AS metric_name, @active_connections AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
    <panel>
      <single>
        <title>CPU Usage %</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @cpu_usage FLOAT; WITH CPUWaits AS ( SELECT SUM(signal_wait_time_ms) AS signal_wait_time_ms, SUM(wait_time_ms - signal_wait_time_ms) AS resource_wait_time_ms FROM sys.dm_os_wait_stats WHERE wait_type IN ('SOS_SCHEDULER_YIELD', 'THREADPOOL') ) SELECT @cpu_usage = (signal_wait_time_ms * 100.0) / NULLIF((signal_wait_time_ms + resource_wait_time_ms), 0) FROM CPUWaits; SELECT 'sql_cpu_usage_pct' AS metric_name, ISNULL(@cpu_usage, 0) AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>CPU Usage Over Time</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @cpu_usage FLOAT; WITH CPUWaits AS ( SELECT SUM(signal_wait_time_ms) AS signal_wait_time_ms, SUM(wait_time_ms - signal_wait_time_ms) AS resource_wait_time_ms FROM sys.dm_os_wait_stats WHERE wait_type IN ('SOS_SCHEDULER_YIELD', 'THREADPOOL') ) SELECT @cpu_usage = (signal_wait_time_ms * 100.0) / NULLIF((signal_wait_time_ms + resource_wait_time_ms), 0) FROM CPUWaits; SELECT 'sql_cpu_usage_pct' AS metric_name, ISNULL(@cpu_usage, 0) AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <single>
        <title>Available Memory (MB)</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @avail_memory_MB BIGINT; SELECT @avail_memory_MB = available_physical_memory_kb / 1024 FROM sys.dm_os_sys_memory; SELECT 'sql_available_memory_mb' AS metric_name, @avail_memory_MB AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Available Memory Over Time</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @avail_memory_MB BIGINT; SELECT @avail_memory_MB = available_physical_memory_kb / 1024 FROM sys.dm_os_sys_memory; SELECT 'sql_available_memory_mb' AS metric_name, @avail_memory_MB AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
    <panel>
      <single>
        <title>Page Life Expectancy (s)</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @page_life_expectancy BIGINT; SELECT @page_life_expectancy = cntr_value FROM sys.dm_os_performance_counters WHERE object_name = 'SQLServer:Buffer Manager' AND counter_name = 'Page life expectancy'; SELECT 'sql_page_life_expectancy' AS metric_name, @page_life_expectancy AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>PLE Over Time</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @page_life_expectancy BIGINT; SELECT @page_life_expectancy = cntr_value FROM sys.dm_os_performance_counters WHERE object_name = 'SQLServer:Buffer Manager' AND counter_name = 'Page life expectancy'; SELECT 'sql_page_life_expectancy' AS metric_name, @page_life_expectancy AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <single>
        <title>TempDB Usage %</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @tempdb_usage_pct FLOAT; SELECT @tempdb_usage_pct = (SUM(allocated_extent_page_count) * 100.0) / NULLIF(SUM(total_page_count), 0) FROM tempdb.sys.dm_db_file_space_usage; SELECT 'sql_tempdb_usage_pct' AS metric_name, ISNULL(@tempdb_usage_pct, 0) AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>TempDB Usage Over Time</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @tempdb_usage_pct FLOAT; SELECT @tempdb_usage_pct = (SUM(allocated_extent_page_count) * 100.0) / NULLIF(SUM(total_page_count), 0) FROM tempdb.sys.dm_db_file_space_usage; SELECT 'sql_tempdb_usage_pct' AS metric_name, ISNULL(@tempdb_usage_pct, 0) AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
    <panel>
      <single>
        <title>Avg Index Frag %</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @avg_index_frag_pct FLOAT; SELECT @avg_index_frag_pct = AVG(avg_fragmentation_in_percent) FROM sys.dm_db_index_physical_stats(NULL, NULL, NULL, NULL, 'LIMITED') WHERE alloc_unit_type_desc = 'IN_ROW_DATA' AND page_count > 1000; SELECT 'sql_avg_index_frag_pct' AS metric_name, ISNULL(@avg_index_frag_pct, 0) AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Index Frag Over Time</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @avg_index_frag_pct FLOAT; SELECT @avg_index_frag_pct = AVG(avg_fragmentation_in_percent) FROM sys.dm_db_index_physical_stats(NULL, NULL, NULL, NULL, 'LIMITED') WHERE alloc_unit_type_desc = 'IN_ROW_DATA' AND page_count > 1000; SELECT 'sql_avg_index_frag_pct' AS metric_name, ISNULL(@avg_index_frag_pct, 0) AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <single>
        <title>Deadlocks Total</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @deadlocks BIGINT; SELECT @deadlocks = cntr_value FROM sys.dm_os_performance_counters WHERE object_name LIKE '%Locks%' AND counter_name = 'Number of Deadlocks/sec'; SELECT 'sql_deadlocks_total' AS metric_name, @deadlocks AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Deadlocks Over Time</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @deadlocks BIGINT; SELECT @deadlocks = cntr_value FROM sys.dm_os_performance_counters WHERE object_name LIKE '%Locks%' AND counter_name = 'Number of Deadlocks/sec'; SELECT 'sql_deadlocks_total' AS metric_name, @deadlocks AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
    <panel>
      <single>
        <title>Top Wait Time (ms)</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @top_wait_time_ms BIGINT; WITH TopWaits AS ( SELECT TOP 1 wait_type, wait_time_ms FROM sys.dm_os_wait_stats WHERE wait_type NOT IN ('SLEEP_TASK', 'WAITFOR', 'XE_TIMER', 'XE_DISPATCHER', 'REQUEST_FOR_DEADLOCK_SEARCH') ORDER BY wait_time_ms DESC ) SELECT @top_wait_time_ms = wait_time_ms FROM TopWaits; SELECT 'sql_top_wait_time_ms' AS metric_name, @top_wait_time_ms AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Top Wait Time Over Time</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @top_wait_time_ms BIGINT; WITH TopWaits AS ( SELECT TOP 1 wait_type, wait_time_ms FROM sys.dm_os_wait_stats WHERE wait_type NOT IN ('SLEEP_TASK', 'WAITFOR', 'XE_TIMER', 'XE_DISPATCHER', 'REQUEST_FOR_DEADLOCK_SEARCH') ORDER BY wait_time_ms DESC ) SELECT @top_wait_time_ms = wait_time_ms FROM TopWaits; SELECT 'sql_top_wait_time_ms' AS metric_name, @top_wait_time_ms AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>DB Size & Free Space (MB)</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); SELECT d.name AS db_name, 'sql_db_size_mb' AS metric_name, SUM(CASE WHEN f.type = 0 THEN f.size * 8.0 / 1024 ELSE 0 END) AS value, @timestamp AS timestamp, d.name AS label_db_name FROM sys.databases d INNER JOIN sys.master_files f ON d.database_id = f.database_id WHERE d.database_id > 4 GROUP BY d.name UNION ALL SELECT d.name AS db_name, 'sql_db_free_space_mb' AS metric_name, SUM(CASE WHEN f.type = 0 THEN (f.size - FILEPROPERTY(f.name, 'SpaceUsed')) * 8.0 / 1024 ELSE 0 END) AS value, @timestamp AS timestamp, d.name AS label_db_name FROM sys.databases d INNER JOIN sys.master_files f ON d.database_id = f.database_id WHERE d.database_id > 4 GROUP BY d.name; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp, NULL AS label_db_name; END CATCH;" | stats latest(value) as val by metric_name, label_db_name</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </table>
      <chart>
        <title>DB Size Over Time</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); SELECT d.name AS db_name, 'sql_db_size_mb' AS metric_name, SUM(CASE WHEN f.type = 0 THEN f.size * 8.0 / 1024 ELSE 0 END) AS value, @timestamp AS timestamp, d.name AS label_db_name FROM sys.databases d INNER JOIN sys.master_files f ON d.database_id = f.database_id WHERE d.database_id > 4 GROUP BY d.name UNION ALL SELECT d.name AS db_name, 'sql_db_free_space_mb' AS metric_name, SUM(CASE WHEN f.type = 0 THEN (f.size - FILEPROPERTY(f.name, 'SpaceUsed')) * 8.0 / 1024 ELSE 0 END) AS value, @timestamp AS timestamp, d.name AS label_db_name FROM sys.databases d INNER JOIN sys.master_files f ON d.database_id = f.database_id WHERE d.database_id > 4 GROUP BY d.name; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp, NULL AS label_db_name; END CATCH;" | timechart span=1h avg(value) by label_db_name</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <single>
        <title>Recent Errors (24h)</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); CREATE TABLE #ErrorLog (LogDate DATETIME, ProcessInfo VARCHAR(50), [Text] VARCHAR(MAX)); INSERT INTO #ErrorLog EXEC sp_readerrorlog 0, 1; DECLARE @recent_errors INT; SELECT @recent_errors = COUNT(*) FROM #ErrorLog WHERE LogDate >= DATEADD(HOUR, -24, GETDATE()) AND [Text] LIKE '%error%' OR [Text] LIKE '%fail%'; DROP TABLE #ErrorLog; SELECT 'sql_recent_errors_24h' AS metric_name, @recent_errors AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Recent Errors Over Time</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); CREATE TABLE #ErrorLog (LogDate DATETIME, ProcessInfo VARCHAR(50), [Text] VARCHAR(MAX)); INSERT INTO #ErrorLog EXEC sp_readerrorlog 0, 1; DECLARE @recent_errors INT; SELECT @recent_errors = COUNT(*) FROM #ErrorLog WHERE LogDate >= DATEADD(HOUR, -24, GETDATE()) AND [Text] LIKE '%error%' OR [Text] LIKE '%fail%'; DROP TABLE #ErrorLog; SELECT 'sql_recent_errors_24h' AS metric_name, @recent_errors AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
    <panel>
      <single>
        <title>Failed Jobs (24h)</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @failed_jobs_24h INT; SELECT @failed_jobs_24h = COUNT(DISTINCT j.job_id) FROM msdb.dbo.sysjobs j INNER JOIN msdb.dbo.sysjobhistory h ON j.job_id = h.job_id WHERE h.run_status = 0 AND h.run_date >= CONVERT(VARCHAR(8), DATEADD(DAY, -1, GETDATE()), 112); SELECT 'sql_failed_jobs_24h' AS metric_name, @failed_jobs_24h AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Failed Jobs Over Time</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @failed_jobs_24h INT; SELECT @failed_jobs_24h = COUNT(DISTINCT j.job_id) FROM msdb.dbo.sysjobs j INNER JOIN msdb.dbo.sysjobhistory h ON j.job_id = h.job_id WHERE h.run_status = 0 AND h.run_date >= CONVERT(VARCHAR(8), DATEADD(DAY, -1, GETDATE()), 112); SELECT 'sql_failed_jobs_24h' AS metric_name, @failed_jobs_24h AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Job Status</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @job_status TABLE (job_name SYSNAME, last_status INT, last_run_datetime DATETIME); INSERT INTO @job_status (job_name, last_status, last_run_datetime) SELECT j.name, MAX(h.run_status) AS last_status, MAX(CAST(STR(h.run_date,8,0) + ' ' + STUFF(STUFF(REPLACE(STR(h.run_time,6,0),' ','0'),3,0,':'),6,0,':') AS DATETIME)) AS last_run_datetime FROM msdb.dbo.sysjobs j LEFT JOIN msdb.dbo.sysjobhistory h ON j.job_id = h.job_id GROUP BY j.name; SELECT 'sql_agent_job_status' AS metric_name, last_status AS value, @timestamp AS timestamp, job_name AS label_job_name FROM @job_status UNION ALL SELECT 'sql_agent_job_last_run_seconds_ago' AS metric_name, DATEDIFF(SECOND, ISNULL(last_run_datetime, '1970-01-01'), GETDATE()) AS value, @timestamp AS timestamp, job_name AS label_job_name FROM @job_status; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp, NULL AS label_job_name; END CATCH;" | stats latest(value) as val by metric_name, label_job_name</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </table>
      <chart>
        <title>Job Last Run (sec ago)</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @job_status TABLE (job_name SYSNAME, last_status INT, last_run_datetime DATETIME); INSERT INTO @job_status (job_name, last_status, last_run_datetime) SELECT j.name, MAX(h.run_status) AS last_status, MAX(CAST(STR(h.run_date,8,0) + ' ' + STUFF(STUFF(REPLACE(STR(h.run_time,6,0),' ','0'),3,0,':'),6,0,':') AS DATETIME)) AS last_run_datetime FROM msdb.dbo.sysjobs j LEFT JOIN msdb.dbo.sysjobhistory h ON j.job_id = h.job_id GROUP BY j.name; SELECT 'sql_agent_job_status' AS metric_name, last_status AS value, @timestamp AS timestamp, job_name AS label_job_name FROM @job_status UNION ALL SELECT 'sql_agent_job_last_run_seconds_ago' AS metric_name, DATEDIFF(SECOND, ISNULL(last_run_datetime, '1970-01-01'), GETDATE()) AS value, @timestamp AS timestamp, job_name AS label_job_name FROM @job_status; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp, NULL AS label_job_name; END CATCH;" | timechart span=1h latest(value) by label_job_name</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <single>
        <title>Unbacked DBs (24h)</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @unbacked_dbs_24h INT; SELECT @unbacked_dbs_24h = COUNT(*) FROM sys.databases d LEFT JOIN msdb.dbo.backupset b ON d.name = b.database_name AND b.type = 'D' WHERE d.database_id > 4 GROUP BY d.name HAVING MAX(b.backup_finish_date) < DATEADD(HOUR, -24, GETDATE()) OR MAX(b.backup_finish_date) IS NULL; SELECT 'sql_unbacked_dbs_24h' AS metric_name, @unbacked_dbs_24h AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Unbacked DBs Over Time</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @unbacked_dbs_24h INT; SELECT @unbacked_dbs_24h = COUNT(*) FROM sys.databases d LEFT JOIN msdb.dbo.backupset b ON d.name = b.database_name AND b.type = 'D' WHERE d.database_id > 4 GROUP BY d.name HAVING MAX(b.backup_finish_date) < DATEADD(HOUR, -24, GETDATE()) OR MAX(b.backup_finish_date) IS NULL; SELECT 'sql_unbacked_dbs_24h' AS metric_name, @unbacked_dbs_24h AS value, @timestamp AS timestamp; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp; END CATCH;" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
    <panel>
      <table>
        <title>Backup Age (hours)</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @backup_status TABLE (db_name SYSNAME, last_backup DATETIME); INSERT INTO @backup_status (db_name, last_backup) SELECT d.name, MAX(b.backup_finish_date) AS last_backup FROM sys.databases d LEFT JOIN msdb.dbo.backupset b ON d.name = b.database_name AND b.type = 'D' WHERE d.database_id > 4 GROUP BY d.name; SELECT 'sql_backup_age_hours' AS metric_name, DATEDIFF(HOUR, ISNULL(last_backup, '1970-01-01'), GETDATE()) AS value, @timestamp AS timestamp, db_name AS label_db_name FROM @backup_status; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp, NULL AS label_db_name; END CATCH;" | stats latest(value) as val by label_db_name</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </table>
      <chart>
        <title>Backup Age Over Time</title>
        <search>
          <query>| dbxquery connection="your_connection_name" query="BEGIN TRY DECLARE @timestamp DATETIME = GETUTCDATE(); DECLARE @backup_status TABLE (db_name SYSNAME, last_backup DATETIME); INSERT INTO @backup_status (db_name, last_backup) SELECT d.name, MAX(b.backup_finish_date) AS last_backup FROM sys.databases d LEFT JOIN msdb.dbo.backupset b ON d.name = b.database_name AND b.type = 'D' WHERE d.database_id > 4 GROUP BY d.name; SELECT 'sql_backup_age_hours' AS metric_name, DATEDIFF(HOUR, ISNULL(last_backup, '1970-01-01'), GETDATE()) AS value, @timestamp AS timestamp, db_name AS label_db_name FROM @backup_status; END TRY BEGIN CATCH SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp, NULL AS label_db_name; END CATCH;" | timechart span=1h avg(value) by label_db_name</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
  </row>
</form>
```