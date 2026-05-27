/****************************************************************************************
    Trellix ePO 5.10.0 Database Optimization Script
    Creates dedicated maintenance DB, stored procedures, SQL Agent jobs,
    and assigns full ownership to the declared service account.
    Validated for SQL Server 2019 / 2022 / 2025.
****************************************************************************************/

SET XACT_ABORT ON;
SET NOCOUNT ON;

-- ====================== CONFIGURATION PARAMETERS ======================
DECLARE @MaintenanceDBName sysname = 'ePOMaintenance';
DECLARE @ServiceAccount    sysname = 'DOMAIN\svc-ePO-Maint';   -- <<< CHANGE THIS
DECLARE @DatabaseName      sysname = 'ePO';
DECLARE @EnablePartitioning bit    = 0;                        -- Set to 1 to enable partitioning
DECLARE @EventsTableName   sysname = 'Events';

DECLARE @ErrorMessage nvarchar(4000), @ErrorSeverity int, @ErrorState int;
-- =====================================================================

BEGIN TRY
    PRINT '=== Starting ePO Database Optimization (Maintenance DB Edition) ===';

    -- ============================================================================
    -- 1. Create Dedicated Maintenance Database + Ownership
    -- ============================================================================
    IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE name = @MaintenanceDBName)
    BEGIN
        EXEC('CREATE DATABASE [' + @MaintenanceDBName + '];');
        PRINT '✓ Created maintenance database [' + @MaintenanceDBName + ']';
    END

    EXEC('ALTER AUTHORIZATION ON DATABASE::[' + @MaintenanceDBName + '] TO [' + @ServiceAccount + '];');
    PRINT '✓ Ownership granted to service account';

    -- ============================================================================
    -- 2. Create Stored Procedures
    -- ============================================================================
    DECLARE @CreateProcs nvarchar(max) = '
        USE [' + @MaintenanceDBName + '];

        IF OBJECT_ID(''dbo.IndexMaintenance'') IS NULL
        BEGIN
            EXEC(''CREATE PROCEDURE dbo.IndexMaintenance
            AS
            BEGIN
                SET NOCOUNT ON;
                DECLARE @DB sysname = ''''' + @DatabaseName + ''''';
                EXEC sp_MSforeachtable
                    @command1 = "ALTER INDEX ALL ON ? REORGANIZE;",
                    @replacechar1 = N"?",
                    @whereand = N"AND " + @DB + ".dbo.sys.objects.object_id = OBJECT_ID(''''''''?'''''''')";
                IF DATEPART(DAY, GETDATE()) = 1
                    EXEC sp_MSforeachtable
                        @command1 = "ALTER INDEX ALL ON ? REBUILD WITH (ONLINE = ON, MAXDOP = 4);",
                        @replacechar1 = N"?",
                        @whereand = N"AND " + @DB + ".dbo.sys.objects.object_id = OBJECT_ID(''''''''?'''''''')";
            END;'');
        END

        IF OBJECT_ID(''dbo.UpdateStatistics'') IS NULL
        BEGIN
            EXEC(''CREATE PROCEDURE dbo.UpdateStatistics
            AS
            BEGIN
                SET NOCOUNT ON;
                DECLARE @DB sysname = ''''' + @DatabaseName + ''''';
                EXEC sp_MSforeachtable
                    @command1 = "UPDATE STATISTICS ? WITH FULLSCAN, MAXDOP = 4;",
                    @replacechar1 = N"?",
                    @whereand = N"AND " + @DB + ".dbo.sys.objects.object_id = OBJECT_ID(''''''''?'''''''')";
            END;'');
        END
    ';

    EXEC sp_executesql @CreateProcs;
    PRINT '✓ Created IndexMaintenance and UpdateStatistics stored procedures';

    -- Grant EXEC rights
    EXEC('USE [' + @MaintenanceDBName + ']; GRANT EXECUTE ON dbo.IndexMaintenance TO [' + @ServiceAccount + '];');
    EXEC('USE [' + @MaintenanceDBName + ']; GRANT EXECUTE ON dbo.UpdateStatistics TO [' + @ServiceAccount + '];');
    PRINT '✓ EXEC permissions granted to service account';

    -- ============================================================================
    -- 3. Create SQL Agent Jobs
    -- ============================================================================
    IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = 'ePO - Index Maintenance')
    BEGIN
        EXEC msdb.dbo.sp_add_job @job_name = N'ePO - Index Maintenance', @enabled = 1, @description = N'Weekly index maintenance';
        EXEC msdb.dbo.sp_add_jobstep @job_name = N'ePO - Index Maintenance', @step_name = N'Run Index Maintenance', @subsystem = N'TSQL', @command = 'EXEC [' + @MaintenanceDBName + '].dbo.IndexMaintenance;', @database_name = @MaintenanceDBName;
        EXEC msdb.dbo.sp_add_jobschedule @job_name = N'ePO - Index Maintenance', @name = N'Weekly Sunday 02:00', @freq_type = 8, @freq_interval = 1, @active_start_time = 20000;
        PRINT '✓ Created Index Maintenance job';
    END

    IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = 'ePO - Update Statistics')
    BEGIN
        EXEC msdb.dbo.sp_add_job @job_name = N'ePO - Update Statistics', @enabled = 1, @description = N'Nightly statistics update';
        EXEC msdb.dbo.sp_add_jobstep @job_name = N'ePO - Update Statistics', @step_name = N'Run Statistics Update', @subsystem = N'TSQL', @command = 'EXEC [' + @MaintenanceDBName + '].dbo.UpdateStatistics;', @database_name = @MaintenanceDBName;
        EXEC msdb.dbo.sp_add_jobschedule @job_name = N'ePO - Update Statistics', @name = N'Nightly 01:00', @freq_type = 4, @freq_interval = 1, @active_start_time = 10000;
        PRINT '✓ Created Update Statistics job';
    END

    -- Assign job ownership
    EXEC msdb.dbo.sp_update_job @job_name = N'ePO - Index Maintenance', @owner_login_name = @ServiceAccount;
    EXEC msdb.dbo.sp_update_job @job_name = N'ePO - Update Statistics', @owner_login_name = @ServiceAccount;
    PRINT '✓ Job ownership assigned to service account';

    -- ============================================================================
    -- 4. Core Optimizations (Recovery, TempDB, Max Memory)
    -- ============================================================================
    IF EXISTS (SELECT 1 FROM sys.databases WHERE name = @DatabaseName AND recovery_model_desc <> 'FULL')
    BEGIN
        EXEC('ALTER DATABASE [' + @DatabaseName + '] SET RECOVERY FULL WITH NO_WAIT;');
        PRINT '✓ Recovery model set to FULL';
    END

    -- TempDB optimization
    DECLARE @CPUCount int = (SELECT cpu_count FROM sys.dm_os_sys_info);
    DECLARE @FileCount int = CASE WHEN @CPUCount > 8 THEN 8 ELSE @CPUCount END;
    DECLARE @i int = 1;

    WHILE @i <= @FileCount
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM tempdb.sys.database_files
                       WHERE name = 'tempdev' + CASE WHEN @i > 1 THEN CAST(@i AS varchar(2)) ELSE '' END)
        BEGIN
            EXEC('
                ALTER DATABASE tempdb ADD FILE (
                    NAME = ''tempdev' + CASE WHEN @i > 1 THEN CAST(@i AS varchar(2)) ELSE '' END + ''',
                    FILENAME = ''G:\SQLTempDB\tempdev' + CASE WHEN @i > 1 THEN CAST(@i AS varchar(2)) ELSE '' END + '.mdf'',
                    SIZE = 8192MB,
                    FILEGROWTH = 1024MB
                );
            ');
            PRINT '✓ Added TempDB data file #' + CAST(@i AS varchar(2));
        END
        SET @i += 1;
    END

    ALTER DATABASE tempdb MODIFY FILE (NAME = 'templog', SIZE = 4096MB, FILEGROWTH = 512MB);
    ALTER DATABASE tempdb SET MIXED_PAGE_ALLOCATION OFF;
    ALTER DATABASE tempdb MODIFY FILEGROUP [PRIMARY] AUTOGROW_ALL_FILES;

    EXEC sp_configure 'max server memory (MB)', 0;
    RECONFIGURE WITH OVERRIDE;
    PRINT '✓ Max server memory set to dynamic';

    -- ============================================================================
    -- 5. OPTIONAL Partitioning for Events table
    -- ============================================================================
    IF @EnablePartitioning = 1
    BEGIN
        BEGIN TRY
            IF EXISTS (SELECT 1 FROM sys.tables WHERE name = @EventsTableName AND type = 'U')
            AND EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(@EventsTableName) AND name IN ('TimeStamp', 'EventTime'))
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM sys.partition_functions WHERE name = 'PF_EPOEvents')
                BEGIN
                    EXEC('
                        CREATE PARTITION FUNCTION PF_EPOEvents (datetime)
                        AS RANGE RIGHT FOR VALUES
                        (''2026-01-01'',''2026-02-01'',''2026-03-01'',''2026-04-01'',
                         ''2026-05-01'',''2026-06-01'',''2026-07-01'',''2026-08-01'',
                         ''2026-09-01'',''2026-10-01'',''2026-11-01'',''2026-12-01'');
                    ');
                    PRINT '✓ Partition function created';
                END

                IF NOT EXISTS (SELECT 1 FROM sys.partition_schemes WHERE name = 'PS_EPOEvents')
                BEGIN
                    EXEC('CREATE PARTITION SCHEME PS_EPOEvents AS PARTITION PF_EPOEvents ALL TO ([PRIMARY]);');
                    PRINT '✓ Partition scheme created';
                END

                EXEC('
                    ALTER TABLE [' + @DatabaseName + '].[dbo].[' + @EventsTableName + ']
                    DROP CONSTRAINT IF EXISTS PK_' + @EventsTableName + ';

                    ALTER TABLE [' + @DatabaseName + '].[dbo].[' + @EventsTableName + ']
                    ADD CONSTRAINT PK_' + @EventsTableName + '
                    PRIMARY KEY CLUSTERED (TimeStamp)
                    ON PS_EPOEvents(TimeStamp)
                    WITH (ONLINE = ON, DATA_COMPRESSION = PAGE);
                ');
                PRINT '✓ Partitioning applied to [' + @EventsTableName + '] with PAGE compression';
            END
            ELSE
                PRINT 'Table [' + @EventsTableName + '] or required column not found - skipping partitioning';
        END TRY
        BEGIN CATCH
            PRINT 'Partitioning failed (non-critical): ' + ERROR_MESSAGE();
        END CATCH
    END
    ELSE
        PRINT 'Partitioning disabled';

    PRINT '=== ePO Database Optimization COMPLETED SUCCESSFULLY ===';

END TRY
BEGIN CATCH
    SELECT @ErrorMessage = ERROR_MESSAGE(), @ErrorSeverity = ERROR_SEVERITY(), @ErrorState = ERROR_STATE();
    PRINT 'CRITICAL ERROR: ' + @ErrorMessage;
    RAISERROR(@ErrorMessage, @ErrorSeverity, @ErrorState);
END CATCH