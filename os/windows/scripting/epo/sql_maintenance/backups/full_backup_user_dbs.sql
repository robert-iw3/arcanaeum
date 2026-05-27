-- Routine to perform full backups of all user databases
-- @RW

USE [YourMaintenanceDB];  -- ← Replace with your preferred database
GO

CREATE OR ALTER PROCEDURE dbo.FullUserDatabaseBackup
    @Directory      nvarchar(512)   = N'C:\Backup\FULL', -- ← Replace with your backup directory
    @NumberOfFiles  int             = 4,                 -- ← Number of backup files per database
    @Compress       char(1)         = 'Y',               -- 'Y' to enable compression, 'N' to disable
    @Checksum       char(1)         = 'Y',               -- 'Y' to enable checksum, 'N' to disable
    @Verify         char(1)         = 'Y',               -- 'Y' to verify backups after creation, 'N' to skip verification
    @RetentionDays  int             = 7,                 -- ← Number of days to retain backups
    @Debug          bit             = 1                  -- 1 to enable debug messages, 0 to disable

AS
BEGIN
    SET NOCOUNT ON;

    IF @Compress = 'Y' AND SERVERPROPERTY('Edition') NOT IN ('Enterprise Edition', 'Standard Edition', 'Developer Edition', 'Enterprise Evaluation Edition')
    BEGIN
        RAISERROR(N'Compression requires Enterprise, Standard, or Developer edition.', 16, 1) WITH NOWAIT;
        RETURN 1;
    END

    DECLARE @StartTime      datetime2 = SYSDATETIME();
    DECLARE @Msg            nvarchar(2000);
    DECLARE @CurrentDB      sysname;
    DECLARE @Cmd            nvarchar(max);
    DECLARE @CmdResult      int;
    DECLARE @Error          int = 0;
    DECLARE @ReturnCode     int;
    DECLARE @CutoffDate     datetime2;
    DECLARE @CutoffDateStr  nvarchar(19);

    IF @Debug = 1
    BEGIN
        SET @Msg = N'Full backup procedure started: ' + CONVERT(nvarchar(30), @StartTime, 120);
        RAISERROR(@Msg, 0, 1) WITH NOWAIT;
    END

    -- Ensure directory exists
    EXEC master.dbo.xp_create_subdir @Directory;

    DECLARE @Databases TABLE (DatabaseName sysname);
    INSERT INTO @Databases (DatabaseName)
    SELECT [name]
    FROM sys.databases
    WHERE database_id > 4
      AND [state] = 0
      AND is_read_only = 0
      AND [name] <> N'tempdb';

    DECLARE db_cur CURSOR LOCAL FAST_FORWARD FOR
        SELECT DatabaseName FROM @Databases;

    OPEN db_cur;
    FETCH NEXT FROM db_cur INTO @CurrentDB;

    WHILE @@FETCH_STATUS = 0
    BEGIN
        IF @Debug = 1
        BEGIN
            SET @Msg = N'→ Starting FULL backup for database: ' + QUOTENAME(@CurrentDB);
            RAISERROR(@Msg, 0, 1) WITH NOWAIT;
        END

        DECLARE @Files TABLE (FilePath nvarchar(512));
        DECLARE @i int = 1;

        WHILE @i <= @NumberOfFiles
        BEGIN
            DECLARE @File nvarchar(512) =
                @Directory + N'\' +
                @CurrentDB + N'_FULL_' +
                CONVERT(varchar(8), GETDATE(), 112) + N'_' +
                RIGHT('0'+CAST(DATEPART(hh,GETDATE()) AS varchar(2)),2) +
                RIGHT('0'+CAST(DATEPART(mi,GETDATE()) AS varchar(2)),2) +
                RIGHT('0'+CAST(DATEPART(ss,GETDATE()) AS varchar(2)),2) +
                N'_' + CAST(@i AS varchar(10)) + N'.bak';

            INSERT INTO @Files (FilePath) VALUES (@File);
            SET @i += 1;
        END;

        -- Build BACKUP command
        SET @Cmd = N'BACKUP DATABASE ' + QUOTENAME(@CurrentDB) + N' TO ';
        SELECT @Cmd += N'DISK = N''' + FilePath + N'''' +
                       CASE WHEN ROW_NUMBER() OVER (ORDER BY FilePath) < @NumberOfFiles THEN N', ' ELSE N'' END
        FROM @Files ORDER BY FilePath;

        -- Build options list to avoid trailing comma
        DECLARE @Options nvarchar(max) = N'';
        IF @Compress = 'Y' SET @Options += N'COMPRESSION, ';
        IF @Checksum = 'Y' SET @Options += N'CHECKSUM, ';

        -- FIX: Only trim if options were added
        IF LEN(@Options) > 0
            SET @Options = LEFT(@Options, LEN(@Options) - 2);

        IF @Options <> N'' SET @Cmd += N' WITH ' + @Options;

        IF @Debug = 1
            RAISERROR(N'  Executing backup command...', 0, 1) WITH NOWAIT;

        BEGIN TRY
            EXEC @CmdResult = sp_executesql @Cmd;
            IF @CmdResult <> 0 SET @Error = @CmdResult;
        END TRY
        BEGIN CATCH
            SET @Error = ERROR_NUMBER();
            SET @Msg = N'  BACKUP failed for ' + QUOTENAME(@CurrentDB) + N' → ' + ERROR_MESSAGE();
            RAISERROR(@Msg, 16, 1) WITH NOWAIT;
        END CATCH

        IF @Error = 0 AND @Verify = 'Y'
        BEGIN
            IF @Debug = 1
                RAISERROR(N'  Verifying backup files...', 0, 1) WITH NOWAIT;

            SET @Cmd = N'RESTORE VERIFYONLY FROM ';
            SELECT @Cmd += N'DISK = N''' + FilePath + N'''' +
                           CASE WHEN ROW_NUMBER() OVER (ORDER BY FilePath) < @NumberOfFiles THEN N', ' ELSE N'' END
            FROM @Files ORDER BY FilePath;

            -- Verify options
            DECLARE @VerifyOptions nvarchar(max) = N'';
            IF @Checksum = 'Y' SET @VerifyOptions += N'CHECKSUM';
            IF @VerifyOptions <> N'' SET @Cmd += N' WITH ' + @VerifyOptions;

            BEGIN TRY
                EXEC @CmdResult = sp_executesql @Cmd;
                IF @CmdResult <> 0 SET @Error = @CmdResult;
            END TRY
            BEGIN CATCH
                SET @Error = ERROR_NUMBER();
                SET @Msg = N'  VERIFYONLY failed for ' + QUOTENAME(@CurrentDB) + N' → ' + ERROR_MESSAGE();
                RAISERROR(@Msg, 16, 1) WITH NOWAIT;
            END CATCH
        END

        IF @Debug = 1
        BEGIN
            SET @Msg = N'← Finished ' + QUOTENAME(@CurrentDB) +
                       CASE WHEN @Error = 0 THEN N' (SUCCESS)' ELSE N' (FAILED - error ' + CAST(@Error AS nvarchar(20)) + N')' END;
            RAISERROR(@Msg, 0, 1) WITH NOWAIT;
        END

        FETCH NEXT FROM db_cur INTO @CurrentDB;
    END;

    CLOSE db_cur;
    DEALLOCATE db_cur;

    -- Cleanup old files
    IF @Error = 0 AND @RetentionDays > 0
    BEGIN
        IF @Debug = 1
            RAISERROR(N'Starting retention cleanup (older than %d days)...', 0, 1, @RetentionDays) WITH NOWAIT;

        SET @CutoffDate = DATEADD(DAY, -@RetentionDays, SYSDATETIME());
        SET @CutoffDateStr = CONVERT(nvarchar(19), @CutoffDate, 126);

        EXEC @ReturnCode = master.dbo.xp_delete_file 0, @Directory, N'bak', @CutoffDateStr;
        IF @ReturnCode <> 0
        BEGIN
            SET @Error = @ReturnCode;
            SET @Msg = N'Cleanup failed with return code ' + CAST(@ReturnCode AS nvarchar(20));
            RAISERROR(@Msg, 16, 1) WITH NOWAIT;
        END
        ELSE IF @Debug = 1
            RAISERROR(N'Cleanup completed.', 0, 1) WITH NOWAIT;
    END

    DECLARE @Duration int = DATEDIFF(SECOND, @StartTime, SYSDATETIME());
    SET @Msg = N'Full backup procedure finished in ' + CAST(@Duration AS nvarchar(20)) + N' seconds.';
    IF @Error = 0
        RAISERROR(@Msg, 0, 1) WITH NOWAIT;
    ELSE
        RAISERROR(@Msg, 16, 1) WITH NOWAIT;

    RETURN @Error;
END
GO