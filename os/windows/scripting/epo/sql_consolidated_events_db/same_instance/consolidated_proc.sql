SET XACT_ABORT ON;
SET NOCOUNT ON;
GO

-- =============================================
-- Stored Procedure: SP_Sync_ENSEvents
-- Features:
-- - Initial full load (@FullLoad = 1): Creates DB/table, schema copy, full load, indexes, stats
-- - Incremental sync (default): Watermark-based, batched, pre-test, duration logging
-- - Pre-sync test: Simple read/write to verify connectivity/permissions
-- - Duration logging in SyncWatermark
-- - READ_ONLY default OFF for ongoing incremental
-- - Non-clustered PK to allow clustered timestamp index
-- - Author: Robert Weber
-- =============================================

CREATE OR ALTER PROCEDURE dbo.SP_Sync_ENSEvents
    @FullLoad               BIT          = 0,
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
        @FullSourceTable    NVARCHAR(512),
        @FullTargetTable    NVARCHAR(512);

    SET @FullSourceTable = QUOTENAME(@SourceDatabase) + N'.' + QUOTENAME(@SourceSchema) + N'.' + QUOTENAME(@SourceTable);
    SET @FullTargetTable = QUOTENAME(@TargetDatabase) + N'.' + QUOTENAME(@TargetSchema) + N'.' + QUOTENAME(@TargetTable);

    BEGIN TRY
        -- Switch to target DB
        EXEC(N'USE ' + QUOTENAME(@TargetDatabase) + N';');

        -- Pre-sync test (read source, write/delete dummy in target)
        PRINT N'Running pre-sync connectivity test...';
        DROP TABLE IF EXISTS #TestRead;
        SET @SQL = N'SELECT TOP (1) ' + QUOTENAME(@PKColumn) + N' INTO #TestRead FROM ' + @FullSourceTable + N' WITH (NOLOCK);';
        EXEC sp_executesql @SQL;

        DECLARE @TestID BIGINT = -999999;
        -- Fix: Temporarily enable IDENTITY_INSERT for the test row
        SET @SQL = N'SET IDENTITY_INSERT ' + @FullTargetTable + N' ON;
        INSERT INTO ' + @FullTargetTable + N' (' + QUOTENAME(@PKColumn) + N', ' + QUOTENAME(@TimestampColumn) + N', AgentGUID, ThreatName, ThreatSeverity)
        VALUES (@TestID, SYSDATETIME(), N''PRE_SYNC_TEST'', N''TEST'', 0);
        SET IDENTITY_INSERT ' + @FullTargetTable + N' OFF;';
        EXEC sp_executesql @SQL, N'@TestID BIGINT', @TestID;

        SET @SQL = N'DELETE FROM ' + @FullTargetTable + N' WHERE ' + QUOTENAME(@PKColumn) + N' = @TestID;';
        EXEC sp_executesql @SQL, N'@TestID BIGINT', @TestID;

        PRINT N'Pre-sync test successful.';

        IF @FullLoad = 1
        BEGIN
            PRINT N'=== INITIAL FULL LOAD ===';

            IF DB_ID(@TargetDatabase) IS NULL
            BEGIN
                SET @SQL = N'CREATE DATABASE ' + QUOTENAME(@TargetDatabase);
                EXEC sp_executesql @SQL;
                EXEC(N'USE ' + QUOTENAME(@TargetDatabase) + N';');
            END

            SET @SQL = N'IF OBJECT_ID(N''dbo.' + QUOTENAME(@TargetTable) + N''') IS NOT NULL DROP TABLE dbo.' + QUOTENAME(@TargetTable) + N';';
            EXEC sp_executesql @SQL;

            SET @SQL = N'SELECT * INTO dbo.' + QUOTENAME(@TargetTable) + N' FROM ' + @FullSourceTable + N' WITH (NOLOCK) WHERE 1 = 0;';
            EXEC sp_executesql @SQL;

            SET @SQL = N'ALTER TABLE dbo.' + QUOTENAME(@TargetTable) + N' ADD CONSTRAINT PK_' + @TargetTable + N' PRIMARY KEY NONCLUSTERED (' + QUOTENAME(@PKColumn) + N');';
            EXEC sp_executesql @SQL;

            SET @SQL = N'INSERT INTO dbo.' + QUOTENAME(@TargetTable) + N' WITH (TABLOCK) SELECT * FROM ' + @FullSourceTable + N' WITH (NOLOCK);';
            EXEC sp_executesql @SQL;

            SET @SQL = N'
            CREATE CLUSTERED INDEX CIX_' + @TimestampColumn + N' ON dbo.' + QUOTENAME(@TargetTable) + N' (' + QUOTENAME(@TimestampColumn) + N');
            CREATE NONCLUSTERED INDEX IX_AgentGUID ON dbo.' + QUOTENAME(@TargetTable) + N'(AgentGUID) INCLUDE (ThreatName, ' + QUOTENAME(@TimestampColumn) + N');
            CREATE NONCLUSTERED INDEX IX_ThreatName ON dbo.' + QUOTENAME(@TargetTable) + N'(ThreatName) INCLUDE (' + QUOTENAME(@TimestampColumn) + N', AgentGUID);
            CREATE NONCLUSTERED INDEX IX_ThreatSeverity ON dbo.' + QUOTENAME(@TargetTable) + N'(ThreatSeverity) INCLUDE (' + QUOTENAME(@TimestampColumn) + N');';
            EXEC sp_executesql @SQL;

            SET @SQL = N'UPDATE STATISTICS dbo.' + QUOTENAME(@TargetTable) + N' WITH FULLSCAN;';
            EXEC sp_executesql @SQL;

            IF @SimpleRecovery = 1
                EXEC(N'ALTER DATABASE ' + QUOTENAME(@TargetDatabase) + N' SET RECOVERY SIMPLE;');

            IF @SetReadOnly = 1
                EXEC(N'ALTER DATABASE ' + QUOTENAME(@TargetDatabase) + N' SET READ_ONLY;');

            -- Watermark
            IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'dbo.SyncWatermark'))
            BEGIN
                CREATE TABLE dbo.SyncWatermark (
                    WatermarkID      INT IDENTITY(1,1) PRIMARY KEY,
                    LastSyncedAutoID BIGINT,
                    LastSyncTime     DATETIME2(7) DEFAULT SYSDATETIME(),
                    RowsSynced       INT DEFAULT 0,
                    Status           NVARCHAR(100),
                    ErrorMessage     NVARCHAR(MAX)
                );

                SET @SQL = N'INSERT INTO dbo.SyncWatermark (LastSyncedAutoID, Status) SELECT MAX(' + QUOTENAME(@PKColumn) + N'), ''FullLoadComplete'' FROM dbo.' + QUOTENAME(@TargetTable) + N';';
                EXEC sp_executesql @SQL;
            END

            SET @EndTime = SYSDATETIME();
            SET @DurationSeconds = DATEDIFF(SECOND, @StartTime, @EndTime);
            PRINT CONCAT(N'Full load completed in ', @DurationSeconds, N' seconds.');
            RETURN;
        END

        -- Incremental
        PRINT N'=== INCREMENTAL SYNC ===';

        IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'dbo.SyncWatermark'))
            RAISERROR(N'Watermark missing - run full load first', 16, 1);

        SELECT TOP (1) @LastSyncedAutoID = ISNULL(LastSyncedAutoID, 0)
        FROM dbo.SyncWatermark ORDER BY WatermarkID DESC;

        SET @SQL = N'SELECT @CurrentMaxAutoID = MAX(' + QUOTENAME(@PKColumn) + N') FROM ' + @FullSourceTable + N' WITH (NOLOCK);';
        EXEC sp_executesql @SQL, N'@CurrentMaxAutoID BIGINT OUTPUT', @CurrentMaxAutoID OUTPUT;

        IF @CurrentMaxAutoID <= @LastSyncedAutoID
        BEGIN
            INSERT INTO dbo.SyncWatermark (LastSyncedAutoID, RowsSynced, Status)
            VALUES (@LastSyncedAutoID, 0, 'NoNewRows');
            RETURN;
        END

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

        SET @EndTime = SYSDATETIME();
        SET @DurationSeconds = DATEDIFF(SECOND, @StartTime, @EndTime);

        INSERT INTO dbo.SyncWatermark (LastSyncedAutoID, RowsSynced, Status)
        VALUES (@CurrentMaxAutoID, @TotalRows, CONCAT('Success (', @DurationSeconds, 's)'));

        PRINT CONCAT(N'Incremental sync completed: ', @TotalRows, N' rows in ', @DurationSeconds, N' seconds.');
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        SET @EndTime = SYSDATETIME();
        SET @DurationSeconds = DATEDIFF(SECOND, @StartTime, @EndTime);
        SET @ErrorMessage = ERROR_MESSAGE() + CONCAT(N' (Duration: ', @DurationSeconds, N's)');
        INSERT INTO dbo.SyncWatermark (LastSyncedAutoID, RowsSynced, Status, ErrorMessage)
        VALUES (@LastSyncedAutoID, @TotalRows, 'Failed', @ErrorMessage);
        THROW;
    END CATCH
END
GO

PRINT N'SP_Sync_ENSEvents deployed successfully.';