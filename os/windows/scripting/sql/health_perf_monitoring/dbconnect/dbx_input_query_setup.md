### DBX Input Queries for Splunk DB Connect
---

Each query focuses on one or a small group of related metrics, making them suitable for DBX inputs (e.g., rising or batch executions). DBX can run these against your SQL Server, indexing the results as Splunk events with fields like `metric_name`, `value`, `timestamp`, and labels (e.g., `db_name` or `job_name`).

- **Adaptations for DBX/Splunk**:
  - Each query SELECTs results as rows (tabular format). This allows Splunk to index them easily (e.g., fields: `metric_name`, `value`, `timestamp`, `label` if applicable).
  - Timestamp uses `GETUTCDATE()` for consistency; Splunk can use `_time` for trending.
  - For metrics with loops (e.g., per-DB or per-job), the query outputs multiple rows.
  - Run each as a DBX query input in Splunk, set to execute every hour (e.g., cron `* * * * *` for hourly, but adjust for 1-hour interval like `0 * * * *`).
  - In Splunk, use SPL like `| timechart avg(value) by metric_name` for overtime tracking.
  - Error handling: Retained TRY...CATCH where relevant, outputting error rows.

Save each as a separate .sql file (e.g., `blocked_sessions.sql`). In DB Connect, create an input per query, enable rising column (e.g., on timestamp) for incremental ingestion.

**Notes for Splunk Setup**:
- Configure DBX inputs: One per .sql file, execute as "Batch" or "Rising" (use timestamp as rising column), index to `sql_metrics`, sourcetype=`sql_metric`.
- In dashboard XML, replace `index=sql_metrics` with your index. For overtime, the timecharts show trends over 24h.
- Alerts: In Splunk, add saved searches for thresholds (e.g., | search value > 80 | alert).

#### 1. Blocked Sessions Query (blocked_sessions.sql)
```sql
USE master;
GO

BEGIN TRY
    DECLARE @timestamp DATETIME = GETUTCDATE();
    DECLARE @blocked_sessions INT;
    SELECT @blocked_sessions = COUNT(*)
    FROM sys.dm_exec_requests
    WHERE blocking_session_id <> 0 AND session_id > 50;

    SELECT 'sql_blocked_sessions' AS metric_name, @blocked_sessions AS value, @timestamp AS timestamp;
END TRY
BEGIN CATCH
    SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp;
END CATCH;
GO
```

#### 2. Long-Running Queries Query (long_running_queries.sql)
```sql
USE master;
GO

BEGIN TRY
    DECLARE @timestamp DATETIME = GETUTCDATE();
    DECLARE @long_running_queries INT;
    SELECT @long_running_queries = COUNT(*)
    FROM sys.dm_exec_requests
    WHERE DATEDIFF(SECOND, start_time, GETDATE()) > 30 AND session_id > 50;

    SELECT 'sql_long_running_queries' AS metric_name, @long_running_queries AS value, @timestamp AS timestamp;
END TRY
BEGIN CATCH
    SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp;
END CATCH;
GO
```

#### 3. Active Connections Query (active_connections.sql)
```sql
USE master;
GO

BEGIN TRY
    DECLARE @timestamp DATETIME = GETUTCDATE();
    DECLARE @active_connections INT;
    SELECT @active_connections = COUNT(*)
    FROM sys.dm_exec_sessions
    WHERE is_user_process = 1;

    SELECT 'sql_active_connections' AS metric_name, @active_connections AS value, @timestamp AS timestamp;
END TRY
BEGIN CATCH
    SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp;
END CATCH;
GO
```

#### 4. CPU Usage Query (cpu_usage.sql)
```sql
USE master;
GO

BEGIN TRY
    DECLARE @timestamp DATETIME = GETUTCDATE();
    DECLARE @cpu_usage FLOAT;
    WITH CPUWaits AS (
        SELECT SUM(signal_wait_time_ms) AS signal_wait_time_ms,
               SUM(wait_time_ms - signal_wait_time_ms) AS resource_wait_time_ms
        FROM sys.dm_os_wait_stats
        WHERE wait_type IN ('SOS_SCHEDULER_YIELD', 'THREADPOOL')
    )
    SELECT @cpu_usage = (signal_wait_time_ms * 100.0) / NULLIF((signal_wait_time_ms + resource_wait_time_ms), 0)
    FROM CPUWaits;

    SELECT 'sql_cpu_usage_pct' AS metric_name, ISNULL(@cpu_usage, 0) AS value, @timestamp AS timestamp;
END TRY
BEGIN CATCH
    SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp;
END CATCH;
GO
```

#### 5. Available Memory Query (available_memory.sql)
```sql
USE master;
GO

BEGIN TRY
    DECLARE @timestamp DATETIME = GETUTCDATE();
    DECLARE @avail_memory_MB BIGINT;
    SELECT @avail_memory_MB = available_physical_memory_kb / 1024
    FROM sys.dm_os_sys_memory;

    SELECT 'sql_available_memory_mb' AS metric_name, @avail_memory_MB AS value, @timestamp AS timestamp;
END TRY
BEGIN CATCH
    SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp;
END CATCH;
GO
```

#### 6. Page Life Expectancy Query (page_life_expectancy.sql)
```sql
USE master;
GO

BEGIN TRY
    DECLARE @timestamp DATETIME = GETUTCDATE();
    DECLARE @page_life_expectancy BIGINT;
    SELECT @page_life_expectancy = cntr_value
    FROM sys.dm_os_performance_counters
    WHERE object_name = 'SQLServer:Buffer Manager' AND counter_name = 'Page life expectancy';

    SELECT 'sql_page_life_expectancy' AS metric_name, @page_life_expectancy AS value, @timestamp AS timestamp;
END TRY
BEGIN CATCH
    SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp;
END CATCH;
GO
```

#### 7. TempDB Usage Query (tempdb_usage.sql)
```sql
USE master;
GO

BEGIN TRY
    DECLARE @timestamp DATETIME = GETUTCDATE();
    DECLARE @tempdb_usage_pct FLOAT;
    SELECT @tempdb_usage_pct = (SUM(allocated_extent_page_count) * 100.0) / NULLIF(SUM(total_page_count), 0)
    FROM tempdb.sys.dm_db_file_space_usage;

    SELECT 'sql_tempdb_usage_pct' AS metric_name, ISNULL(@tempdb_usage_pct, 0) AS value, @timestamp AS timestamp;
END TRY
BEGIN CATCH
    SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp;
END CATCH;
GO
```

#### 8. Average Index Fragmentation Query (avg_index_frag.sql)
```sql
USE master;
GO

BEGIN TRY
    DECLARE @timestamp DATETIME = GETUTCDATE();
    DECLARE @avg_index_frag_pct FLOAT;
    SELECT @avg_index_frag_pct = AVG(avg_fragmentation_in_percent)
    FROM sys.dm_db_index_physical_stats(NULL, NULL, NULL, NULL, 'LIMITED')
    WHERE alloc_unit_type_desc = 'IN_ROW_DATA' AND page_count > 1000;

    SELECT 'sql_avg_index_frag_pct' AS metric_name, ISNULL(@avg_index_frag_pct, 0) AS value, @timestamp AS timestamp;
END TRY
BEGIN CATCH
    SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp;
END CATCH;
GO
```

#### 9. Deadlocks Query (deadlocks.sql)
```sql
USE master;
GO

BEGIN TRY
    DECLARE @timestamp DATETIME = GETUTCDATE();
    DECLARE @deadlocks BIGINT;
    SELECT @deadlocks = cntr_value
    FROM sys.dm_os_performance_counters
    WHERE object_name LIKE '%Locks%' AND counter_name = 'Number of Deadlocks/sec';

    SELECT 'sql_deadlocks_total' AS metric_name, @deadlocks AS value, @timestamp AS timestamp;
END TRY
BEGIN CATCH
    SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp;
END CATCH;
GO
```

#### 10. Top Wait Time Query (top_wait_time.sql)
```sql
USE master;
GO

BEGIN TRY
    DECLARE @timestamp DATETIME = GETUTCDATE();
    DECLARE @top_wait_time_ms BIGINT;
    WITH TopWaits AS (
        SELECT TOP 1 wait_type, wait_time_ms
        FROM sys.dm_os_wait_stats
        WHERE wait_type NOT IN ('SLEEP_TASK', 'WAITFOR', 'XE_TIMER', 'XE_DISPATCHER', 'REQUEST_FOR_DEADLOCK_SEARCH')
        ORDER BY wait_time_ms DESC
    )
    SELECT @top_wait_time_ms = wait_time_ms FROM TopWaits;

    SELECT 'sql_top_wait_time_ms' AS metric_name, @top_wait_time_ms AS value, @timestamp AS timestamp;
END TRY
BEGIN CATCH
    SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp;
END CATCH;
GO
```

#### 11. Database Space Usage Query (db_space_usage.sql)
```sql
USE master;
GO

BEGIN TRY
    DECLARE @timestamp DATETIME = GETUTCDATE();
    SELECT d.name AS db_name,
           'sql_db_size_mb' AS metric_name,
           SUM(CASE WHEN f.type = 0 THEN f.size * 8.0 / 1024 ELSE 0 END) AS value,
           @timestamp AS timestamp,
           d.name AS label_db_name
    FROM sys.databases d
    INNER JOIN sys.master_files f ON d.database_id = f.database_id
    WHERE d.database_id > 4
    GROUP BY d.name
    UNION ALL
    SELECT d.name AS db_name,
           'sql_db_free_space_mb' AS metric_name,
           SUM(CASE WHEN f.type = 0 THEN (f.size - FILEPROPERTY(f.name, 'SpaceUsed')) * 8.0 / 1024 ELSE 0 END) AS value,
           @timestamp AS timestamp,
           d.name AS label_db_name
    FROM sys.databases d
    INNER JOIN sys.master_files f ON d.database_id = f.database_id
    WHERE d.database_id > 4
    GROUP BY d.name;
END TRY
BEGIN CATCH
    SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp, NULL AS label_db_name;
END CATCH;
GO
```

#### 12. Recent Errors Query (recent_errors.sql)
```sql
USE master;
GO

BEGIN TRY
    DECLARE @timestamp DATETIME = GETUTCDATE();
    CREATE TABLE #ErrorLog (LogDate DATETIME, ProcessInfo VARCHAR(50), [Text] VARCHAR(MAX));
    INSERT INTO #ErrorLog EXEC sp_readerrorlog 0, 1;
    DECLARE @recent_errors INT;
    SELECT @recent_errors = COUNT(*)
    FROM #ErrorLog
    WHERE LogDate >= DATEADD(HOUR, -24, GETDATE()) AND [Text] LIKE '%error%' OR [Text] LIKE '%fail%';
    DROP TABLE #ErrorLog;

    SELECT 'sql_recent_errors_24h' AS metric_name, @recent_errors AS value, @timestamp AS timestamp;
END TRY
BEGIN CATCH
    SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp;
END CATCH;
GO
```

#### 13. Failed Jobs Query (failed_jobs.sql)
```sql
USE master;
GO

BEGIN TRY
    DECLARE @timestamp DATETIME = GETUTCDATE();
    DECLARE @failed_jobs_24h INT;
    SELECT @failed_jobs_24h = COUNT(DISTINCT j.job_id)
    FROM msdb.dbo.sysjobs j
    INNER JOIN msdb.dbo.sysjobhistory h ON j.job_id = h.job_id
    WHERE h.run_status = 0
    AND h.run_date >= CONVERT(VARCHAR(8), DATEADD(DAY, -1, GETDATE()), 112);

    SELECT 'sql_failed_jobs_24h' AS metric_name, @failed_jobs_24h AS value, @timestamp AS timestamp;
END TRY
BEGIN CATCH
    SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp;
END CATCH;
GO
```

#### 14. Job Status Query (job_status.sql)
```sql
USE master;
GO

BEGIN TRY
    DECLARE @timestamp DATETIME = GETUTCDATE();
    DECLARE @job_status TABLE (job_name SYSNAME, last_status INT, last_run_datetime DATETIME);
    INSERT INTO @job_status (job_name, last_status, last_run_datetime)
    SELECT j.name,
           MAX(h.run_status) AS last_status,
           MAX(CAST(STR(h.run_date,8,0) + ' ' + STUFF(STUFF(REPLACE(STR(h.run_time,6,0),' ','0'),3,0,':'),6,0,':') AS DATETIME)) AS last_run_datetime
    FROM msdb.dbo.sysjobs j
    LEFT JOIN msdb.dbo.sysjobhistory h ON j.job_id = h.job_id
    GROUP BY j.name;

    SELECT 'sql_agent_job_status' AS metric_name, last_status AS value, @timestamp AS timestamp, job_name AS label_job_name
    FROM @job_status
    UNION ALL
    SELECT 'sql_agent_job_last_run_seconds_ago' AS metric_name, DATEDIFF(SECOND, ISNULL(last_run_datetime, '1970-01-01'), GETDATE()) AS value, @timestamp AS timestamp, job_name AS label_job_name
    FROM @job_status;
END TRY
BEGIN CATCH
    SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp, NULL AS label_job_name;
END CATCH;
GO
```

#### 15. Unbacked Databases Query (unbacked_dbs.sql)
```sql
USE master;
GO

BEGIN TRY
    DECLARE @timestamp DATETIME = GETUTCDATE();
    DECLARE @unbacked_dbs_24h INT;
    SELECT @unbacked_dbs_24h = COUNT(*)
    FROM sys.databases d
    LEFT JOIN msdb.dbo.backupset b ON d.name = b.database_name AND b.type = 'D'
    WHERE d.database_id > 4
    GROUP BY d.name
    HAVING MAX(b.backup_finish_date) < DATEADD(HOUR, -24, GETDATE()) OR MAX(b.backup_finish_date) IS NULL;

    SELECT 'sql_unbacked_dbs_24h' AS metric_name, @unbacked_dbs_24h AS value, @timestamp AS timestamp;
END TRY
BEGIN CATCH
    SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp;
END CATCH;
GO
```

#### 16. Backup Age Query (backup_age.sql)
```sql
USE master;
GO

BEGIN TRY
    DECLARE @timestamp DATETIME = GETUTCDATE();
    DECLARE @backup_status TABLE (db_name SYSNAME, last_backup DATETIME);
    INSERT INTO @backup_status (db_name, last_backup)
    SELECT d.name,
           MAX(b.backup_finish_date) AS last_backup
    FROM sys.databases d
    LEFT JOIN msdb.dbo.backupset b ON d.name = b.database_name AND b.type = 'D'
    WHERE d.database_id > 4
    GROUP BY d.name;

    SELECT 'sql_backup_age_hours' AS metric_name, DATEDIFF(HOUR, ISNULL(last_backup, '1970-01-01'), GETDATE()) AS value, @timestamp AS timestamp, db_name AS label_db_name
    FROM @backup_status;
END TRY
BEGIN CATCH
    SELECT 'error' AS metric_name, ERROR_MESSAGE() AS value, GETUTCDATE() AS timestamp, NULL AS label_db_name;
END CATCH;
GO
```

### Splunk XML Dashboard Source File (dashboard.xml)

This is the XML for a Splunk dashboard. Import it via Splunk UI (Dashboards > Create New > Source > paste XML). It runs each query every hour (search refresh="3600"), displays current metrics as single values/gauges, and timecharts for overtime trends (e.g., last 24h). Use DBX as the data source (configure DBX inputs to index the query results with sourcetype=sql_metric, fields like metric_name, value, timestamp).

Adjust <search> ref for your DBX input names (e.g., if input named "blocked_sessions_input", use | dbxquery query="..." or search index=sql_index sourcetype=blocked_sessions).

```xml
<form version="1.1" theme="dark">
  <label>SQL Server Health Dashboard</label>
  <row>
    <panel>
      <single>
        <title>Blocked Sessions</title>
        <search>
          <query>index=sql_metrics metric_name="sql_blocked_sessions" | stats latest(value) as val</query>
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
          <query>index=sql_metrics metric_name="sql_blocked_sessions" | timechart span=1h avg(value)</query>
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
          <query>index=sql_metrics metric_name="sql_long_running_queries" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Long Running Queries Over Time</title>
        <search>
          <query>index=sql_metrics metric_name="sql_long_running_queries" | timechart span=1h avg(value)</query>
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
          <query>index=sql_metrics metric_name="sql_active_connections" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Active Connections Over Time</title>
        <search>
          <query>index=sql_metrics metric_name="sql_active_connections" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
    <panel>
      <single>
        <title>CPU Usage %</title>
        <search>
          <query>index=sql_metrics metric_name="sql_cpu_usage_pct" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>CPU Usage Over Time</title>
        <search>
          <query>index=sql_metrics metric_name="sql_cpu_usage_pct" | timechart span=1h avg(value)</query>
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
          <query>index=sql_metrics metric_name="sql_available_memory_mb" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Available Memory Over Time</title>
        <search>
          <query>index=sql_metrics metric_name="sql_available_memory_mb" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
    <panel>
      <single>
        <title>Page Life Expectancy (s)</title>
        <search>
          <query>index=sql_metrics metric_name="sql_page_life_expectancy" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>PLE Over Time</title>
        <search>
          <query>index=sql_metrics metric_name="sql_page_life_expectancy" | timechart span=1h avg(value)</query>
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
          <query>index=sql_metrics metric_name="sql_tempdb_usage_pct" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>TempDB Usage Over Time</title>
        <search>
          <query>index=sql_metrics metric_name="sql_tempdb_usage_pct" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
    <panel>
      <single>
        <title>Avg Index Frag %</title>
        <search>
          <query>index=sql_metrics metric_name="sql_avg_index_frag_pct" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Index Frag Over Time</title>
        <search>
          <query>index=sql_metrics metric_name="sql_avg_index_frag_pct" | timechart span=1h avg(value)</query>
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
          <query>index=sql_metrics metric_name="sql_deadlocks_total" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Deadlocks Over Time</title>
        <search>
          <query>index=sql_metrics metric_name="sql_deadlocks_total" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
    <panel>
      <single>
        <title>Top Wait Time (ms)</title>
        <search>
          <query>index=sql_metrics metric_name="sql_top_wait_time_ms" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Top Wait Time Over Time</title>
        <search>
          <query>index=sql_metrics metric_name="sql_top_wait_time_ms" | timechart span=1h avg(value)</query>
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
          <query>index=sql_metrics metric_name IN ("sql_db_size_mb", "sql_db_free_space_mb") | stats latest(value) as val by metric_name, label_db_name</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </table>
      <chart>
        <title>DB Size Over Time</title>
        <search>
          <query>index=sql_metrics metric_name="sql_db_size_mb" | timechart span=1h avg(value) by label_db_name</query>
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
          <query>index=sql_metrics metric_name="sql_recent_errors_24h" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Recent Errors Over Time</title>
        <search>
          <query>index=sql_metrics metric_name="sql_recent_errors_24h" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
    <panel>
      <single>
        <title>Failed Jobs (24h)</title>
        <search>
          <query>index=sql_metrics metric_name="sql_failed_jobs_24h" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Failed Jobs Over Time</title>
        <search>
          <query>index=sql_metrics metric_name="sql_failed_jobs_24h" | timechart span=1h avg(value)</query>
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
          <query>index=sql_metrics metric_name="sql_agent_job_status" | stats latest(value) as val by label_job_name</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </table>
      <chart>
        <title>Job Last Run (sec ago)</title>
        <search>
          <query>index=sql_metrics metric_name="sql_agent_job_last_run_seconds_ago" | timechart span=1h latest(value) by label_job_name</query>
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
          <query>index=sql_metrics metric_name="sql_unbacked_dbs_24h" | stats latest(value) as val</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </single>
      <chart>
        <title>Unbacked DBs Over Time</title>
        <search>
          <query>index=sql_metrics metric_name="sql_unbacked_dbs_24h" | timechart span=1h avg(value)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
    <panel>
      <table>
        <title>Backup Age (hours)</title>
        <search>
          <query>index=sql_metrics metric_name="sql_backup_age_hours" | stats latest(value) as val by label_db_name</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>3600</refresh>
        </search>
      </table>
      <chart>
        <title>Backup Age Over Time</title>
        <search>
          <query>index=sql_metrics metric_name="sql_backup_age_hours" | timechart span=1h avg(value) by label_db_name</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
  </row>
</form>
```