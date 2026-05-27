### Overall Strategy for Enabling SQL Server Performance Enhancements

Focus is on memory efficiency, controlled parallelism, I/O minimization, and advanced DBA-level tuning using sp_configure, trace flags, and optional Resource Governor to maximize performance without hardware upgrades. Incorporated T-SQL scripts to enable each recommendation, with comments for safe execution (e.g., test in staging, monitor impact). Assume SQL Server 2019+ and appropriate permissions (e.g., sysadmin). Scripts now include enhanced error handling with TRY...CATCH blocks, transactions for DDL/DML where applicable (with ROLLBACK on failure), and tunable variables at the top for easy adjustment by the DBA (e.g., sizes, thresholds). Expanded TempDB optimizations in Phase 5 with detailed guidance on file count, sizing, contention monitoring, and integration with trace flags from Phase 4.

### Phase 1: Assessment
Use these scripts to gather metrics for baselining. Run them ad-hoc or via jobs. These are read-only, so no transactions needed, but wrapped in TRY...CATCH for robustness.

1. **Gather System Metrics**:
   ```sql
   DECLARE @TopWaitsCount INT = 10;  -- Tunable: Number of top waits to return

   BEGIN TRY
       -- CPU and wait stats
       SELECT scheduler_id, current_tasks_count, runnable_tasks_count
       FROM sys.dm_os_schedulers
       WHERE status = 'VISIBLE ONLINE';  -- Per-core load

       SELECT TOP (@TopWaitsCount) wait_type, waiting_tasks_count, wait_time_ms / 1000.0 AS wait_time_sec
       FROM sys.dm_os_wait_stats
       WHERE wait_type NOT LIKE '%SLEEP%' AND wait_type NOT IN ('CLR_AUTO_EVENT', 'CLR_MANUAL_EVENT')
       ORDER BY wait_time_ms DESC;  -- Top waits (e.g., WRITELOG for ingestion)

       -- Memory grants and buffer pool
       SELECT granted_memory_kb / 1024 AS granted_memory_mb, requested_memory_kb / 1024 AS requested_memory_mb
       FROM sys.dm_exec_query_memory_grants
       WHERE granted_memory_kb > 0;  -- Active grants

       SELECT COUNT(*) * 8 / 1024 AS buffer_pool_mb
       FROM sys.dm_os_buffer_descriptors;  -- Buffer pool usage

       -- I/O stalls
       SELECT DB_NAME(database_id) AS db_name, file_id, io_stall_read_ms, io_stall_write_ms
       FROM sys.dm_io_virtual_file_stats(NULL, NULL);  -- Per-file I/O

       -- Connections (for 75k sources via IIS)
       SELECT COUNT(*) AS active_connections, login_name, program_name
       FROM sys.dm_exec_sessions
       WHERE is_user_process = 1
       GROUP BY login_name, program_name;  -- Pooling efficiency
   END TRY
   BEGIN CATCH
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
       -- No rollback needed for read-only queries
   END CATCH;
   ```

2. **Trace Workload**: Enable Query Store for query analysis.
   ```sql
   DECLARE @QueryStoreMaxSizeMB INT = 1024;  -- Tunable: Max storage size for Query Store
   DECLARE @QueryStoreIntervalMinutes INT = 15;  -- Tunable: Capture interval

   BEGIN TRY
       BEGIN TRANSACTION;
       -- Enable Query Store on User Database, replace with your Database
       ALTER DATABASE MyDBHERE SET QUERY_STORE = ON
       (OPERATION_MODE = READ_WRITE,
        INTERVAL_LENGTH_MINUTES = @QueryStoreIntervalMinutes,
        MAX_STORAGE_SIZE_MB = @QueryStoreMaxSizeMB,
        QUERY_CAPTURE_MODE = ALL);
       COMMIT TRANSACTION;

       -- Query for top CPU queries (post-capture; tunable top N)
       DECLARE @TopQueries INT = 10;
       SELECT TOP (@TopQueries) qt.query_sql_text, qrs.avg_cpu_time, qrs.execution_count
       FROM sys.query_store_query_text qt
       INNER JOIN sys.query_store_query q ON qt.query_text_id = q.query_text_id
       INNER JOIN sys.query_store_runtime_stats qrs ON q.query_id = qrs.query_id
       ORDER BY qrs.avg_cpu_time DESC;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

3. **Database Analysis**:
   ```sql
   DECLARE @MinPageCount INT = 1000;  -- Tunable: Minimum page count for index analysis

   BEGIN TRY
       -- Index usage and fragmentation
       SELECT DB_NAME(database_id) AS db_name, OBJECT_NAME(object_id) AS table_name, index_id, user_seeks, user_scans, avg_fragmentation_in_percent
       FROM sys.dm_db_index_physical_stats(NULL, NULL, NULL, NULL, 'LIMITED')
       INNER JOIN sys.dm_db_index_usage_stats ON dm_db_index_physical_stats.database_id = dm_db_index_usage_stats.database_id
       AND dm_db_index_physical_stats.object_id = dm_db_index_usage_stats.object_id
       AND dm_db_index_physical_stats.index_id = dm_db_index_usage_stats.index_id
       WHERE page_count > @MinPageCount
       ORDER BY avg_fragmentation_in_percent DESC;

       -- Partition stats (if partitioned)
       SELECT OBJECT_NAME(p.object_id) AS table_name, ps.used_page_count * 8 / 1024 AS size_mb
       FROM sys.dm_db_partition_stats ps
       INNER JOIN sys.partitions p ON ps.partition_id = p.partition_id;
   END TRY
   BEGIN CATCH
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

4. **Hardware Audit**: No script, but use OS tools like PerfMon for NUMA/SSD metrics.
5. **Workload Classification**: Use above queries to classify; no additional script.

### Phase 2: Planning
No scripts here; focus on defining goals and risks via assessment outputs.

### Phase 3: Hardware and Infrastructure Setup
1. **CPU Affinity (if NUMA imbalance)**:
   ```sql
   DECLARE @AffinityStart INT = 0;  -- Tunable: Starting CPU
   DECLARE @AffinityEnd INT = 31;   -- Tunable: Ending CPU (e.g., for 32-core)

   BEGIN TRY
       BEGIN TRANSACTION;
       -- Set affinity
       ALTER SERVER CONFIGURATION SET PROCESS AFFINITY @AffinityStart TO @AffinityEnd;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Rollback to default
   BEGIN TRY
       BEGIN TRANSACTION;
       ALTER SERVER CONFIGURATION SET PROCESS AFFINITY NOCPUMASK;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

2. **Instant File Initialization**: Grant SQL service account "Perform Volume Maintenance Tasks" via secpol.msc (no script).

3. **Storage Tweaks**: Enable read-ahead if needed (test with trace flag).
   ```sql
   BEGIN TRY
       -- Test disable read-ahead globally (temporary, no transaction needed)
       DBCC TRACEON(652, -1);  -- Disable for scans; monitor I/O
   END TRY
   BEGIN CATCH
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Rollback
   BEGIN TRY
       DBCC TRACEOFF(652, -1);
   END TRY
   BEGIN CATCH
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

### Phase 4: Instance-Level Configurations
Run these in master DB; most are dynamic.

1. **Max Server Memory**:
   ```sql
   DECLARE @MaxMemoryMB INT = 215040;  -- Tunable: ~210 GB; adjust based on OS needs

   BEGIN TRY
       BEGIN TRANSACTION;
       EXEC sp_configure 'show advanced options', 1; RECONFIGURE WITH OVERRIDE;
       EXEC sp_configure 'max server memory (MB)', @MaxMemoryMB;
       RECONFIGURE WITH OVERRIDE;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Rollback to unlimited
   DECLARE @DefaultMaxMemoryMB INT = 2147483647;
   BEGIN TRY
       BEGIN TRANSACTION;
       EXEC sp_configure 'max server memory (MB)', @DefaultMaxMemoryMB; RECONFIGURE WITH OVERRIDE;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

2. **MAXDOP & Cost Threshold**:
   ```sql
   DECLARE @MaxDOP INT = 8;  -- Tunable: 8 for 32-48 CPUs, 12 for 56-64
   DECLARE @CostThreshold INT = 75;  -- Tunable: Prevent cheap parallel plans

   BEGIN TRY
       BEGIN TRANSACTION;
       EXEC sp_configure 'max degree of parallelism', @MaxDOP;
       EXEC sp_configure 'cost threshold for parallelism', @CostThreshold;
       RECONFIGURE;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Rollback to defaults
   DECLARE @DefaultMaxDOP INT = 0;
   DECLARE @DefaultCostThreshold INT = 5;
   BEGIN TRY
       BEGIN TRANSACTION;
       EXEC sp_configure 'max degree of parallelism', @DefaultMaxDOP;
       EXEC sp_configure 'cost threshold for parallelism', @DefaultCostThreshold; RECONFIGURE;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

3. **Advanced Trace Flags**: Add as startup parameters via Configuration Manager (restart required). For testing:
   ```sql
   -- Tunable flags list (comma-separated for enable/disable)
   DECLARE @Flags NVARCHAR(100) = '1117,1118,610,4199,8079';  -- Core; add 834,3226,2371,8015 as needed

   BEGIN TRY
       -- Enable globally for session (test)
       EXEC ('DBCC TRACEON(' + @Flags + ', -1)');
       DBCC TRACESTATUS(-1);  -- Verify
   END TRY
   BEGIN CATCH
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Disable
   BEGIN TRY
       EXEC ('DBCC TRACEOFF(' + @Flags + ', -1)');
   END TRY
   BEGIN CATCH
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

   **LPIM Setup**: Grant "Lock pages in memory" to SQL service account via secpol.msc, then restart service.

4. **Other Advanced Options**:
   ```sql
   DECLARE @OptimizeAdHoc BIT = 1;  -- Tunable: 1 to enable
   DECLARE @MaxWorkers INT = 1024;  -- Tunable: Scale for concurrency
   DECLARE @BlockedThresholdSec INT = 5;  -- Tunable: Seconds for block alerts
   DECLARE @RecoveryIntervalMin INT = 1;  -- Tunable: Minutes for faster recovery

   BEGIN TRY
       BEGIN TRANSACTION;
       EXEC sp_configure 'optimize for ad hoc workloads', @OptimizeAdHoc; RECONFIGURE;
       EXEC sp_configure 'max worker threads', @MaxWorkers; RECONFIGURE;
       EXEC sp_configure 'blocked process threshold (s)', @BlockedThresholdSec; RECONFIGURE;
       EXEC sp_configure 'recovery interval (min)', @RecoveryIntervalMin; RECONFIGURE;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Rollback examples
   BEGIN TRY
       BEGIN TRANSACTION;
       EXEC sp_configure 'optimize for ad hoc workloads', 0; RECONFIGURE;
       EXEC sp_configure 'max worker threads', 0; RECONFIGURE;  -- Auto
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

5. **Optional: Resource Governor** (Enterprise Edition):
   ```sql
   DECLARE @IngestionMaxCPU INT = 60;  -- Tunable: Max CPU % for ingestion
   DECLARE @IngestionMaxMem INT = 45;  -- Tunable: Max memory %
   DECLARE @IngestionMaxGrant INT = 25;  -- Tunable: Max memory grant %
   DECLARE @IngestionReqMaxGrant INT = 5;  -- Tunable: Per-request max grant

   DECLARE @ETLMaxCPU INT = 50;
   DECLARE @ETLMaxMem INT = 55;
   DECLARE @ETLMaxGrant INT = 40;
   DECLARE @ETLReqMaxGrant INT = 25;

   BEGIN TRY
       BEGIN TRANSACTION;
       -- Create pools and groups
       CREATE RESOURCE POOL IngestionPool WITH (MAX_CPU_PERCENT = @IngestionMaxCPU, MAX_MEMORY_PERCENT = @IngestionMaxMem, MAX_MEMORY_GRANT_PERCENT = @IngestionMaxGrant);
       CREATE RESOURCE POOL ETL_ReportingPool WITH (MAX_CPU_PERCENT = @ETLMaxCPU, MAX_MEMORY_PERCENT = @ETLMaxMem, MAX_MEMORY_GRANT_PERCENT = @ETLMaxGrant);

       CREATE WORKLOAD GROUP IngestionGroup WITH (IMPORTANCE = HIGH, REQUEST_MAX_MEMORY_GRANT_PERCENT = @IngestionReqMaxGrant, GROUP_MAX_REQUESTS = 0) USING IngestionPool;
       CREATE WORKLOAD GROUP ETLGroup WITH (IMPORTANCE = NORMAL, REQUEST_MAX_MEMORY_GRANT_PERCENT = @ETLReqMaxGrant) USING ETL_ReportingPool;

       -- Classifier function (customize for IIS/ETL logins)
       CREATE FUNCTION rg_classifier() RETURNS SYSNAME WITH SCHEMABINDING
       AS
       BEGIN
           DECLARE @group_name SYSNAME;
           IF (APP_NAME() LIKE '%IIS%' OR ORIGINAL_LOGIN() LIKE '%IIS%')
               SET @group_name = 'IngestionGroup';
           ELSE IF (APP_NAME() LIKE '%SSIS%' OR ORIGINAL_LOGIN() LIKE '%ETL%')
               SET @group_name = 'ETLGroup';
           ELSE
               SET @group_name = 'default';
           RETURN @group_name;
       END;

       -- Activate
       ALTER RESOURCE GOVERNOR WITH (CLASSIFIER_FUNCTION = dbo.rg_classifier);
       ALTER RESOURCE GOVERNOR RECONFIGURE;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Monitoring
   BEGIN TRY
       SELECT * FROM sys.dm_resource_governor_workload_groups;
       SELECT * FROM sys.dm_resource_governor_resource_pools;
   END TRY
   BEGIN CATCH
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Rollback/Disable
   BEGIN TRY
       BEGIN TRANSACTION;
       ALTER RESOURCE GOVERNOR WITH (CLASSIFIER_FUNCTION = NULL);
       ALTER RESOURCE GOVERNOR RECONFIGURE;
       ALTER RESOURCE GOVERNOR DISABLE;
       DROP WORKLOAD GROUP IngestionGroup;
       DROP WORKLOAD GROUP ETLGroup;
       DROP RESOURCE POOL IngestionPool;
       DROP RESOURCE POOL ETL_ReportingPool;
       DROP FUNCTION dbo.rg_classifier;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

### Phase 5: Database-Level Optimizations
Expanded with TempDB details: For high-concurrency ingestion, optimize TempDB to avoid allocation contention (e.g., PFS/GAM/SGAM pages). Recommend 1 file per 4-8 CPUs (e.g., 4-8 for 32 CPUs, 8-16 for 64), equal sizing to prevent hotspots, placed on dedicated SSDs. Pre-grow files to avoid autogrow during peaks; monitor with `sys.dm_db_file_space_usage` and `sys.dm_os_wait_stats` for TEMPDB-related waits (e.g., PAGELATCH_XX). Integrate with trace flags 1117/1118 from Phase 4 for uniform growth/extents. If contention persists, consider in-memory optimized TempDB objects.

1. **TempDB**:
   ```sql
   DECLARE @TempDBFileCount INT = 8;  -- Tunable: 4-8 for 32 CPUs, 8-16 for 64 (one per 4-8 cores)
   DECLARE @InitialSizeMB INT = 20480;  -- Tunable: Per-file initial size (e.g., 20GB)
   DECLARE @GrowthMB INT = 1024;  -- Tunable: Autogrow increment
   DECLARE @DriveLetter CHAR(1) = 'T';  -- Tunable: Drive for new files

   BEGIN TRY
       BEGIN TRANSACTION;
       -- Modify existing primary file
       ALTER DATABASE tempdb
       MODIFY FILE (NAME = tempdev, SIZE = @InitialSizeMB, FILEGROWTH = @GrowthMB);

       -- Add additional files (loop for count; example for 2-@TempDBFileCount)
       DECLARE @i INT = 2;
       WHILE @i <= @TempDBFileCount
       BEGIN
           DECLARE @FileName NVARCHAR(50) = 'tempdev' + CAST(@i AS NVARCHAR(10));
           DECLARE @FilePath NVARCHAR(100) = @DriveLetter + ':\' + @FileName + '.ndf';
           EXEC ('ALTER DATABASE tempdb ADD FILE (NAME = ''' + @FileName + ''', FILENAME = ''' + @FilePath + ''', SIZE = ' + CAST(@InitialSizeMB AS NVARCHAR(10)) + 'MB, FILEGROWTH = ' + CAST(@GrowthMB AS NVARCHAR(10)) + 'MB)');
           SET @i = @i + 1;
       END;

       -- Monitoring contention (run separately)
       SELECT DB_NAME(database_id) AS db_name, file_id, unallocated_extent_page_count, version_store_reserved_page_count
       FROM sys.dm_db_file_space_usage
       WHERE database_id = 2;  -- TempDB specific

       SELECT wait_type, waiting_tasks_count
       FROM sys.dm_os_wait_stats
       WHERE wait_type LIKE 'PAGELATCH%' AND wait_type LIKE '%TEMPDB%';  -- Contention waits
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Rollback: Remove added files (manual, as removal requires restart; example for one)
   BEGIN TRY
       BEGIN TRANSACTION;
       ALTER DATABASE tempdb REMOVE FILE tempdev2;  -- Repeat for each added
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

2. **Data Compression**:
   ```sql
   DECLARE @CompressionType NVARCHAR(10) = 'ROW';  -- Tunable: 'ROW' for collection, 'PAGE' for reporting

   BEGIN TRY
       BEGIN TRANSACTION;
       -- Apply to table
       ALTER TABLE dbo.IngestionTable REBUILD WITH (DATA_COMPRESSION = @CompressionType, ONLINE = ON);
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Check compression
   BEGIN TRY
       SELECT OBJECT_NAME(object_id) AS table_name, data_compression_desc
       FROM sys.partitions WHERE index_id <= 1;
   END TRY
   BEGIN CATCH
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Rollback to none
   DECLARE @NoCompression NVARCHAR(10) = 'NONE';
   BEGIN TRY
       BEGIN TRANSACTION;
       ALTER TABLE dbo.IngestionTable REBUILD WITH (DATA_COMPRESSION = @NoCompression, ONLINE = ON);
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

3. **Partitioning** (Example for date-based on ingestion table):
   ```sql
   DECLARE @PartitionBoundaries NVARCHAR(MAX) = '''2026-01-01'', ''2026-01-02'', ''2026-01-03''';  -- Tunable: Date values for daily partitions

   BEGIN TRY
       BEGIN TRANSACTION;
       -- Create function and scheme
       EXEC ('CREATE PARTITION FUNCTION PF_IngestionDate (DATETIME2) AS RANGE RIGHT FOR VALUES (' + @PartitionBoundaries + ');');

       CREATE PARTITION SCHEME PS_IngestionDate AS PARTITION PF_IngestionDate ALL TO ([PRIMARY], [PRIMARY], [PRIMARY], [PRIMARY]);  -- Tune filegroups

       -- Apply to new table (or rebuild existing with care)
       CREATE TABLE dbo.IngestionTable (ID BIGINT, IngestionDate DATETIME2, Data NVARCHAR(MAX))
       ON PS_IngestionDate(IngestionDate);

       -- Purge old partition
       ALTER TABLE dbo.IngestionTable SWITCH PARTITION 1 TO dbo.ArchiveTable;
       TRUNCATE TABLE dbo.ArchiveTable;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Rollback: Drop function/scheme (data movement required first)
   BEGIN TRY
       BEGIN TRANSACTION;
       DROP TABLE dbo.ArchiveTable;  -- If created
       DROP PARTITION SCHEME PS_IngestionDate;
       DROP PARTITION FUNCTION PF_IngestionDate;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

4. **Filegroup Placement**:
   ```sql
   DECLARE @FilegroupName NVARCHAR(50) = 'FG_Indexes';  -- Tunable: Filegroup name
   DECLARE @FilePath NVARCHAR(100) = 'I:\Indexes.ndf';  -- Tunable: File path

   BEGIN TRY
       BEGIN TRANSACTION;
       -- Create secondary filegroup, replace with your user db!
       EXEC ('ALTER DATABASE MyUSERDBHERE!!!!!!! ADD FILEGROUP ' + @FilegroupName + ';');
       EXEC ('ALTER DATABASE MyUSERDBHERE!!!!!!! ADD FILE (NAME = IndexesFile, FILENAME = ''' + @FilePath + ''') TO FILEGROUP ' + @FilegroupName + ';');

       -- Move non-clustered index
       CREATE NONCLUSTERED INDEX IX_IngestionDate ON dbo.IngestionTable(IngestionDate)
       WITH (DROP_EXISTING = ON) ON FG_Indexes;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Rollback: Remove filegroup (move objects first)
   BEGIN TRY
       BEGIN TRANSACTION;
       DROP INDEX IX_IngestionDate ON dbo.IngestionTable;  -- If moved
       ALTER DATABASE MyUSERDBHERE!!!!!!! REMOVE FILE IndexesFile;
       ALTER DATABASE MyUSERDBHERE!!!!!!! REMOVE FILEGROUP FG_Indexes;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

### Phase 6: Query and Indexing Enhancements
1. **Indexing Strategy**:
   ```sql
   DECLARE @FilterDateDaysBack INT = 7;  -- Tunable: Days for filtered index

   BEGIN TRY
       BEGIN TRANSACTION;
       -- Filtered index
       EXEC ('CREATE INDEX IX_RecentIngestion ON dbo.IngestionTable(IngestionDate)
       WHERE IngestionDate > DATEADD(DAY, -' + @FilterDateDaysBack + ', GETDATE());');

       -- Columnstore for reporting
       CREATE NONCLUSTERED COLUMNSTORE INDEX CSI_Reporting ON dbo.ReportingTable (Column1, Column2);

       -- Reorganize
       ALTER INDEX ALL ON dbo.IngestionTable REORGANIZE;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Rollback: Drop indexes
   BEGIN TRY
       BEGIN TRANSACTION;
       DROP INDEX IX_RecentIngestion ON dbo.IngestionTable;
       DROP INDEX CSI_Reporting ON dbo.ReportingTable;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

2. **Statistics Maintenance**:
   ```sql
   BEGIN TRY
       BEGIN TRANSACTION;
       -- Update with full scan
       UPDATE STATISTICS dbo.IngestionTable (IngestionDate) WITH FULLSCAN;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Job script example (no transaction needed for sp_updatestats)
   BEGIN TRY
       EXEC sp_updatestats @resample = 'YES';
   END TRY
   BEGIN CATCH
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

3. **Query Tuning**:
   ```sql
   BEGIN TRY
       BEGIN TRANSACTION;
       -- Force parameterization
       ALTER DATABASE MyUSERDBHERE!!!!!!! SET PARAMETERIZATION FORCED;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Example ETL query (no transaction; run as-is)
   DECLARE @LastETLDate DATETIME = DATEADD(DAY, -1, GETDATE());  -- Tunable: Last ETL timestamp
   DECLARE @ETLMaxDOP INT = 4;  -- Tunable: Per-query DOP
   BEGIN TRY
       INSERT INTO INSERTYOURUSERDBHERE!!!!!.dbo.ReportingTable
       SELECT * FROM MyUSERDBHERE!!!!!!!.dbo.IngestionTable
       WHERE IngestionDate > @LastETLDate
       OPTION (USE HINT('ENABLE_PARALLEL_PLAN_PREFERENCE'), MAXDOP @ETLMaxDOP);
   END TRY
   BEGIN CATCH
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Rollback parameterization
   BEGIN TRY
       BEGIN TRANSACTION;
       ALTER DATABASE MyUSERDBHERE!!!!!!! SET PARAMETERIZATION SIMPLE;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

### Phase 7: Maintenance and Monitoring
1. **Schedules** (Create SQL Agent jobs):
   ```sql
   DECLARE @RebuildMaxDOP INT = 4;  -- Tunable: DOP for rebuilds

   BEGIN TRY
       BEGIN TRANSACTION;
       -- Weekly index rebuild
       ALTER INDEX ALL ON dbo.ReportingTable REBUILD WITH (ONLINE = ON, MAXDOP = @RebuildMaxDOP);
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Daily stats update
   BEGIN TRY
       EXEC sp_updatestats @resample = 'YES';
   END TRY
   BEGIN CATCH
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

2. **DBCC Checks**:
   ```sql
   BEGIN TRY
       DBCC CHECKDB('MyUSERDBHERE!!!!!!!') WITH NO_INFOMSGS, ALL_ERRORMSGS;
   END TRY
   BEGIN CATCH
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   BEGIN TRY
       BEGIN TRANSACTION;
       ALTER DATABASE MyUSERDBHERE!!!!!!! SET PAGE_VERIFY CHECKSUM;
       COMMIT TRANSACTION;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

3. **Monitoring** (Custom alert job):
   ```sql
   DECLARE @LowPLEThreshold INT = 300;  -- Tunable: Page life expectancy threshold (seconds)

   BEGIN TRY
       IF (SELECT cntr_value FROM sys.dm_os_performance_counters
           WHERE object_name = 'SQLServer:Buffer Manager' AND counter_name = 'Page life expectancy') < @LowPLEThreshold
       BEGIN
           -- Raise alert (e.g., integrate with sp_send_dbmail)
           RAISERROR('Alert: Low PLE! Current: %d', 16, 1, (SELECT cntr_value FROM sys.dm_os_performance_counters WHERE counter_name = 'Page life expectancy'));
       END
   END TRY
   BEGIN CATCH
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```

### Phase 8: Testing and Rollout
1. **Load Testing**: Use tools like sqlstress or custom scripts; no specific SQL here.
2. **A/B Testing**: Use Query Store.
   ```sql
   DECLARE @QueryID INT = 1;  -- Tunable: From Query Store
   DECLARE @PlanID INT = 1;   -- Tunable: Desired plan

   BEGIN TRY
       EXEC sys.sp_query_store_force_plan @query_id = @QueryID, @plan_id = @PlanID;
   END TRY
   BEGIN CATCH
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;

   -- Unforce
   BEGIN TRY
       EXEC sys.sp_query_store_unforce_plan @query_id = @QueryID, @plan_id = @PlanID;
   END TRY
   BEGIN CATCH
       SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
   END CATCH;
   ```
3. **Rollback**: Included in each script section.
4. **Go-Live**: Monitor with DMVs post-change.

This strategy with embedded, tunable scripts provides a complete, executable path for optimization. All scripts now have enhanced error handling and rollbacks. Execute in a controlled manner, monitoring with DMVs after each change. If issues arise, disable and restart. For further tweaks, share specific assessment outputs.