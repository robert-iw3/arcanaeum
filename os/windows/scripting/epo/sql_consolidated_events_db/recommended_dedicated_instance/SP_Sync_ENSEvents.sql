-- =============================================
-- Stored Procedure: dbo.SP_Sync_ENSEvents
-- Purpose: Unified synchronization of Trellix ENS events from production ePO
--          via linked server to a dedicated ConsolidatedEventsENS instance
-- Modes:
--   - Full Load: Triggered automatically on first run (watermark missing) or manually
--   - Incremental: Default mode for scheduled runs
-- Features:
--   - Pre-sync connectivity/permission test with dummy row
--   - Batch processing for incremental sync
--   - Comprehensive duration tracking and logging
--   - Enhanced TRY/CATCH with detailed error capture
--   - All variables declared at the top
--   - Non-clustered PK to allow clustered timestamp index
--   - Watermark table for sync tracking and health monitoring
-- Deployment: Run on the consolidated SQL Server instance
-- Author: Robert Weber
-- =============================================

SET XACT_ABORT ON;
SET NOCOUNT ON;
GO

CREATE OR ALTER PROCEDURE dbo.SP_Sync_ENSEvents
    -- Parameters (configurable for flexibility)
    @FullLoad               BIT          = 0,      -- Set to 1 for manual full load override
    @LinkedServer           NVARCHAR(128) = N'EPO_PRODUCTION',
    @SourceDatabase         NVARCHAR(128) = N'ePO',
    @SourceSchema           NVARCHAR(128) = N'dbo',
    @SourceTable            NVARCHAR(128) = N'EPOEvents',
    @TargetDatabase         NVARCHAR(128) = N'ConsolidatedEventsENS',
    @TargetSchema           NVARCHAR(128) = N'dbo',
    @TargetTable            NVARCHAR(128) = N'EPOEvents_Consolidated',
    @PKColumn               NVARCHAR(128) = N'AutoID',
    @TimestampColumn        NVARCHAR(128) = N'ReceivedUTC',
    @BatchSize              INT          = 10000,
    @SimpleRecovery         BIT          = 1,
    @SetReadOnly            BIT          = 0
AS
BEGIN
    -- Declare ALL variables at the top
    DECLARE
        @StartTime          DATETIME2(7) = SYSDATETIME(),
        @EndTime            DATETIME2(7),
        @DurationSeconds    INT,
        @LastSyncedAutoID   BIGINT,
        @CurrentMaxAutoID   BIGINT,
        @RowsInserted       INT = 0,
        @TotalRows          INT = 0,
        @ErrorMessage       NVARCHAR(MAX),
        @SQL                NVARCHAR(MAX),
        @TestID             BIGINT = -999999;  -- Dummy ID for pre-test

    DECLARE
        @FullSourceTable    NVARCHAR(512),
        @FullTargetTable    NVARCHAR(512);

    -- Build fully qualified names
    SET @FullSourceTable = QUOTENAME(@LinkedServer) + N'.' + QUOTENAME(@SourceDatabase) + N'.' + QUOTENAME(@SourceSchema) + N'.' + QUOTENAME(@SourceTable);
    SET @FullTargetTable = QUOTENAME(@TargetDatabase) + N'.' + QUOTENAME(@TargetSchema) + N'.' + QUOTENAME(@TargetTable);

    BEGIN TRY
        -- Switch to target database context
        EXEC(N'USE ' + QUOTENAME(@TargetDatabase) + N';');

        -- Pre-sync connectivity and permissions test
        PRINT N'Executing pre-sync connectivity test...';
        DROP TABLE IF EXISTS #TestRead;
        SET @SQL = N'SELECT TOP (1) ' + QUOTENAME(@PKColumn) + N' INTO #TestRead FROM ' + @FullSourceTable + N' WITH (NOLOCK);';
        EXEC sp_executesql @SQL;

        -- Insert dummy test row (schema-safe using key columns)
        -- Fix: Temporarily enable IDENTITY_INSERT for the test row
        SET @SQL = N'SET IDENTITY_INSERT ' + @FullTargetTable + N' ON;
        INSERT INTO ' + @FullTargetTable + N' (' + QUOTENAME(@PKColumn) + N', ' + QUOTENAME(@TimestampColumn) + N', AgentGUID, ThreatName, ThreatSeverity)
        VALUES (@TestID, SYSDATETIME(), N''PRE_SYNC_TEST'', N''TEST'', 0);
        SET IDENTITY_INSERT ' + @FullTargetTable + N' OFF;';
        EXEC sp_executesql @SQL, N'@TestID BIGINT', @TestID;

        -- Clean up test row
        SET @SQL = N'DELETE FROM ' + @FullTargetTable + N' WHERE ' + QUOTENAME(@PKColumn) + N' = @TestID;';
        EXEC sp_executesql @SQL, N'@TestID BIGINT', @TestID;

        PRINT N'Pre-sync test passed: Source readable, target writable.';

        -- Auto-detect full load if watermark missing (override with @FullLoad = 1 if needed)
        IF @FullLoad = 0 AND NOT EXISTS (SELECT 1 FROM sys.objects WHERE object_id = OBJECT_ID(N'dbo.SyncWatermark'))
            SET @FullLoad = 1;

        IF @FullLoad = 1
        BEGIN
            PRINT N'=== EXECUTING INITIAL FULL LOAD ===';

            -- Create database if missing
            IF DB_ID(@TargetDatabase) IS NULL
            BEGIN
                PRINT N'Creating database ' + @TargetDatabase + N'...';
                SET @SQL = N'CREATE DATABASE ' + QUOTENAME(@TargetDatabase);
                EXEC sp_executesql @SQL;
                EXEC(N'USE ' + QUOTENAME(@TargetDatabase) + N';');
            END

            -- Drop existing target table
            SET @SQL = N'
            IF OBJECT_ID(N''dbo.' + QUOTENAME(@TargetTable) + N''') IS NOT NULL
                DROP TABLE dbo.' + QUOTENAME(@TargetTable) + N';';
            EXEC sp_executesql @SQL;

            -- Copy exact schema (empty table)
            PRINT N'Copying schema from source...';
            SET @SQL = N'
            SELECT * INTO dbo.' + QUOTENAME(@TargetTable) + N'
            FROM ' + @FullSourceTable + N' WITH (NOLOCK)
            WHERE 1 = 0;';
            EXEC sp_executesql @SQL;

            -- Add non-clustered primary key
            PRINT N'Adding primary key...';
            SET @SQL = N'
            ALTER TABLE dbo.' + QUOTENAME(@TargetTable) + N'
            ADD CONSTRAINT PK_' + @TargetTable + N' PRIMARY KEY NONCLUSTERED (' + QUOTENAME(@PKColumn) + N');';
            EXEC sp_executesql @SQL;

            -- Full historical data load
            PRINT N'Loading all historical data...';
            SET @SQL = N'
            INSERT INTO dbo.' + QUOTENAME(@TargetTable) + N' WITH (TABLOCK)
            SELECT * FROM ' + @FullSourceTable + N' WITH (NOLOCK);';
            EXEC sp_executesql @SQL;

            -- Performance indexes
            PRINT N'Creating indexes...';
            SET @SQL = N'
            CREATE CLUSTERED INDEX CIX_' + @TimestampColumn + N'
            ON dbo.' + QUOTENAME(@TargetTable) + N' (' + QUOTENAME(@TimestampColumn) + N');

            CREATE NONCLUSTERED INDEX IX_AgentGUID
            ON dbo.' + QUOTENAME(@TargetTable) + N'(AgentGUID) INCLUDE (ThreatName, ' + QUOTENAME(@TimestampColumn) + N');

            CREATE NONCLUSTERED INDEX IX_ThreatName
            ON dbo.' + QUOTENAME(@TargetTable) + N'(ThreatName) INCLUDE (' + QUOTENAME(@TimestampColumn) + N', AgentGUID);

            CREATE NONCLUSTERED INDEX IX_ThreatSeverity
            ON dbo.' + QUOTENAME(@TargetTable) + N'(ThreatSeverity) INCLUDE (' + QUOTENAME(@TimestampColumn) + N');';
            EXEC sp_executesql @SQL;

            -- Update statistics
            PRINT N'Updating statistics...';
            SET @SQL = N'UPDATE STATISTICS dbo.' + QUOTENAME(@TargetTable) + N' WITH FULLSCAN;';
            EXEC sp_executesql @SQL;

            -- Database recovery and read-only options
            IF @SimpleRecovery = 1
            BEGIN
                PRINT N'Setting SIMPLE recovery model...';
                EXEC(N'ALTER DATABASE ' + QUOTENAME(@TargetDatabase) + N' SET RECOVERY SIMPLE;');
            END

            IF @SetReadOnly = 1
            BEGIN
                PRINT N'Setting database READ_ONLY...';
                EXEC(N'ALTER DATABASE ' + QUOTENAME(@TargetDatabase) + N' SET READ_ONLY;');
            END

            -- Create watermark table and seed with current max
            PRINT N'Initializing watermark table...';
            IF NOT EXISTS (SELECT 1 FROM sys.objects WHERE object_id = OBJECT_ID(N'dbo.SyncWatermark'))
            BEGIN
                CREATE TABLE dbo.SyncWatermark (
                    WatermarkID      INT IDENTITY(1,1) PRIMARY KEY,
                    LastSyncedAutoID BIGINT NULL,
                    LastSyncTime     DATETIME2(7) DEFAULT SYSDATETIME(),
                    RowsSynced       INT DEFAULT 0,
                    Status           NVARCHAR(100),
                    ErrorMessage     NVARCHAR(MAX)
                );

                SET @SQL = N'
                INSERT INTO dbo.SyncWatermark (LastSyncedAutoID, Status)
                SELECT MAX(' + QUOTENAME(@PKColumn) + N'), ''FullLoadComplete''
                FROM dbo.' + QUOTENAME(@TargetTable) + N';';
                EXEC sp_executesql @SQL;
            END

            SET @EndTime = SYSDATETIME();
            SET @DurationSeconds = DATEDIFF(SECOND, @StartTime, @EndTime);
            PRINT CONCAT(N'Initial full load completed in ', @DurationSeconds, N' seconds.');
            RETURN;
        END

        -- Incremental sync mode
        PRINT N'=== EXECUTING INCREMENTAL SYNC ===';

        -- Ensure watermark exists
        IF NOT EXISTS (SELECT 1 FROM sys.objects WHERE object_id = OBJECT_ID(N'dbo.SyncWatermark'))
        BEGIN
            RAISERROR(N'Watermark table missing. Execute with @FullLoad = 1 first.', 16, 1);
        END

        -- Get last synced ID
        SELECT TOP (1) @LastSyncedAutoID = ISNULL(LastSyncedAutoID, 0)
        FROM dbo.SyncWatermark
        ORDER BY WatermarkID DESC;

        -- Get current max ID from production
        SET @SQL = N'SELECT @CurrentMaxAutoID = MAX(' + QUOTENAME(@PKColumn) + N') FROM ' + @FullSourceTable + N' WITH (NOLOCK);';
        EXEC sp_executesql @SQL, N'@CurrentMaxAutoID BIGINT OUTPUT', @CurrentMaxAutoID OUTPUT;

        -- No new data
        IF @CurrentMaxAutoID IS NULL OR @CurrentMaxAutoID <= @LastSyncedAutoID
        BEGIN
            INSERT INTO dbo.SyncWatermark (LastSyncedAutoID, RowsSynced, Status)
            VALUES (@LastSyncedAutoID, 0, 'NoNewRows');

            SET @EndTime = SYSDATETIME();
            SET @DurationSeconds = DATEDIFF(SECOND, @StartTime, @EndTime);
            PRINT CONCAT(N'No new rows. Run completed in ', @DurationSeconds, N' seconds.');
            RETURN;
        END

        -- Prepare temp table with source schema
        DROP TABLE IF EXISTS #NewEvents;
        SET @SQL = N'SELECT TOP (0) * INTO #NewEvents FROM ' + @FullSourceTable + N' WITH (NOLOCK);';
        EXEC sp_executesql @SQL;

        SET @SQL = N'ALTER TABLE #NewEvents ADD PRIMARY KEY (' + QUOTENAME(@PKColumn) + N');';
        EXEC sp_executesql @SQL;

        -- FIX: Dynamically generate the column list from the local temp table
        DECLARE @ColList NVARCHAR(MAX);
        SELECT @ColList = STRING_AGG(QUOTENAME(name), ', ')
        FROM tempdb.sys.columns
        WHERE object_id = OBJECT_ID('tempdb..#NewEvents');

        -- Batch loop
        WHILE 1 = 1
        BEGIN
            TRUNCATE TABLE #NewEvents;

            SET @SQL = N'
            INSERT INTO #NewEvents
            SELECT TOP (' + CAST(@BatchSize AS NVARCHAR(10)) + N') *
            FROM ' + @FullSourceTable + N' WITH (NOLOCK)
            WHERE ' + QUOTENAME(@PKColumn) + N' > @LastSyncedAutoID
            ORDER BY ' + QUOTENAME(@PKColumn) + N';';

            EXEC sp_executesql @SQL, N'@LastSyncedAutoID BIGINT', @LastSyncedAutoID;

            SET @RowsInserted = @@ROWCOUNT;
            IF @RowsInserted = 0 BREAK;

            BEGIN TRANSACTION;
            -- FIX: Use the explicit column list and IDENTITY_INSERT
            SET @SQL = N'SET IDENTITY_INSERT ' + @FullTargetTable + N' ON;
                         INSERT INTO ' + @FullTargetTable + N' WITH (TABLOCK) (' + @ColList + N')
                         SELECT ' + @ColList + N' FROM #NewEvents;
                         SET IDENTITY_INSERT ' + @FullTargetTable + N' OFF;';
            EXEC sp_executesql @SQL;
            COMMIT TRANSACTION;

            SET @TotalRows += @RowsInserted;

            SET @SQL = N'SELECT @LastSyncedAutoID = MAX(' + QUOTENAME(@PKColumn) + N') FROM #NewEvents;';
            EXEC sp_executesql @SQL, N'@LastSyncedAutoID BIGINT OUTPUT', @LastSyncedAutoID OUTPUT;
        END

        -- Success logging with duration
        SET @EndTime = SYSDATETIME();
        SET @DurationSeconds = DATEDIFF(SECOND, @StartTime, @EndTime);

        INSERT INTO dbo.SyncWatermark (LastSyncedAutoID, RowsSynced, Status)
        VALUES (@CurrentMaxAutoID, @TotalRows, CONCAT('Success (', @DurationSeconds, N's)'));

        PRINT CONCAT(N'Incremental sync completed: ', @TotalRows, N' rows inserted in ', @DurationSeconds, N' seconds.');
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;

        SET @EndTime = SYSDATETIME();
        SET @DurationSeconds = DATEDIFF(SECOND, @StartTime, @EndTime);
        SET @ErrorMessage = ERROR_MESSAGE() + CONCAT(N' (Line: ', CAST(ERROR_LINE() AS NVARCHAR(10)), N', Duration: ', @DurationSeconds, N's)');

        -- Ensure watermark exists for error logging
        IF NOT EXISTS (SELECT 1 FROM sys.objects WHERE object_id = OBJECT_ID(N'dbo.SyncWatermark'))
        BEGIN
            CREATE TABLE dbo.SyncWatermark (
                WatermarkID      INT IDENTITY(1,1) PRIMARY KEY,
                LastSyncedAutoID BIGINT NULL,
                LastSyncTime     DATETIME2(7) DEFAULT SYSDATETIME(),
                RowsSynced       INT DEFAULT 0,
                Status           NVARCHAR(100),
                ErrorMessage     NVARCHAR(MAX)
            );
        END

        INSERT INTO dbo.SyncWatermark (LastSyncedAutoID, RowsSynced, Status, ErrorMessage)
        VALUES (@LastSyncedAutoID, @TotalRows, 'Failed', @ErrorMessage);

        THROW;
    END CATCH
END
GO

PRINT N'Stored procedure dbo.SP_Sync_ENSEvents created successfully.';
PRINT N'First run (full load): EXEC dbo.SP_Sync_ENSEvents @FullLoad = 1;';
PRINT N'Scheduled runs (incremental): EXEC dbo.SP_Sync_ENSEvents;';