-- Routine to perform differential backups of all user databases
-- @RW

USE [YourMaintenanceDB];
GO

CREATE OR ALTER PROCEDURE dbo.DiffUserDatabaseBackup
    @Directory      nvarchar(512)   = N'C:\Backup\DIFF',  -- ← Replace with your backup directory
    @NumberOfFiles  int             = 4,                  -- ← Number of backup files per database
    @Compress       char(1)         = 'Y',                -- 'Y' to enable compression, 'N' to disable
    @Checksum       char(1)         = 'Y',                -- 'Y' to enable checksum, 'N' to disable
    @Verify         char(1)         = 'Y',                -- 'Y' to verify backups after creation, 'N' to skip verification
    @RetentionDays  int             = 14,                 -- ← Number of days to retain backups
    @Debug          bit             = 1                   -- 1 to enable debug messages, 0 to disable

AS
BEGIN
    SET NOCOUNT ON;

    -- Operability check for compression
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
        RAISERROR(N'Differential backup procedure started: %s', 0, 1, CONVERT(nvarchar(30), @StartTime, 120)) WITH NOWAIT;

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
        -- Operability check: Skip if no prior FULL backup (DIFF requires it)
        IF NOT EXISTS (SELECT 1 FROM msdb.dbo.backupset WHERE database_name = @CurrentDB AND type = 'D')
        BEGIN
            SET @Msg = N'  Skipping DIFF for ' + QUOTENAME(@CurrentDB) + N' - No prior FULL backup found.';
            RAISERROR(@Msg, 0, 1) WITH NOWAIT;
            GOTO NextDB;
        END

        IF @Debug = 1
            RAISERROR(N'→ Starting DIFF backup for %s', 0, 1, QUOTENAME(@CurrentDB)) WITH NOWAIT;

        DECLARE @Files TABLE (FilePath nvarchar(512));
        DECLARE @i int = 1;

        WHILE @i <= @NumberOfFiles
        BEGIN
            DECLARE @File nvarchar(512) =
                @Directory + N'\' +
                @CurrentDB + N'_DIFF_' +
                CONVERT(varchar(8), GETDATE(), 112) + N'_' +
                RIGHT('0'+CAST(DATEPART(hh,GETDATE()) AS varchar(2)),2) +
                RIGHT('0'+CAST(DATEPART(mi,GETDATE()) AS varchar(2)),2) +
                RIGHT('0'+CAST(DATEPART(ss,GETDATE()) AS varchar(2)),2) +
                N'_' + CAST(@i AS varchar(10)) + N'.bak';

            INSERT INTO @Files (FilePath) VALUES (@File);
            SET @i += 1;
        END;

        SET @Cmd = N'BACKUP DATABASE ' + QUOTENAME(@CurrentDB) + N' TO ';
        SELECT @Cmd += N'DISK = N''' + FilePath + N'''' +
                       CASE WHEN ROW_NUMBER() OVER (ORDER BY FilePath) < @NumberOfFiles THEN N', ' ELSE N'' END
        FROM @Files ORDER BY FilePath;

        SET @Cmd += N' WITH DIFFERENTIAL';
        IF @Compress = 'Y' SET @Cmd += N', COMPRESSION';
        IF @Checksum = 'Y' SET @Cmd += N', CHECKSUM';

        IF @Debug = 1
            RAISERROR(N'  Executing differential backup...', 0, 1) WITH NOWAIT;

        BEGIN TRY
            EXEC @CmdResult = sp_executesql @Cmd;
            IF @CmdResult <> 0 SET @Error = @CmdResult;
        END TRY
        BEGIN CATCH
            SET @Error = ERROR_NUMBER();
            SET @Msg = N'  DIFF backup failed for ' + QUOTENAME(@CurrentDB) + N' → ' + ERROR_MESSAGE();
            RAISERROR(@Msg, 16, 1) WITH NOWAIT;
        END CATCH

        IF @Error = 0 AND @Verify = 'Y'
        BEGIN
            IF @Debug = 1
                RAISERROR(N'  Verifying differential backup...', 0, 1) WITH NOWAIT;

            SET @Cmd = N'RESTORE VERIFYONLY FROM ';
            SELECT @Cmd += N'DISK = N''' + FilePath + N'''' +
                           CASE WHEN ROW_NUMBER() OVER (ORDER BY FilePath) < @NumberOfFiles THEN N', ' ELSE N'' END
            FROM @Files ORDER BY FilePath;

            DECLARE @VerifyOptions nvarchar(max) = N'';
            IF @Checksum = 'Y' SET @VerifyOptions += N'CHECKSUM';
            IF @VerifyOptions <> N'' SET @Cmd += N' WITH ' + @VerifyOptions;

            BEGIN TRY
                EXEC @CmdResult = sp_executesql @Cmd;
                IF @CmdResult <> 0 SET @Error = @CmdResult;
            END TRY
            BEGIN CATCH
                SET @Error = ERROR_NUMBER();
                SET @Msg = N'  VERIFY failed for DIFF ' + QUOTENAME(@CurrentDB) + N' → ' + ERROR_MESSAGE();
                RAISERROR(@Msg, 16, 1) WITH NOWAIT;
            END CATCH
        END

        IF @Debug = 1
            RAISERROR(N'← Finished DIFF %s (%s)', 0, 1,
                      QUOTENAME(@CurrentDB),
                      CASE WHEN @Error = 0 THEN N'SUCCESS' ELSE N'FAILED' END) WITH NOWAIT;

        NextDB:
        FETCH NEXT FROM db_cur INTO @CurrentDB;
    END;

    CLOSE db_cur;
    DEALLOCATE db_cur;

    IF @Error = 0 AND @RetentionDays > 0
    BEGIN
        IF @Debug = 1
            RAISERROR(N'Starting DIFF retention cleanup...', 0, 1) WITH NOWAIT;

        SET @CutoffDate = DATEADD(DAY, -@RetentionDays, SYSDATETIME());
        SET @CutoffDateStr = CONVERT(nvarchar(19), @CutoffDate, 126);

        EXEC @ReturnCode = master.dbo.xp_delete_file 0, @Directory, N'bak', @CutoffDateStr;
        IF @ReturnCode <> 0
        BEGIN
            SET @Error = @ReturnCode;
            RAISERROR(N'DIFF cleanup failed (code %d)', 16, 1, @ReturnCode) WITH NOWAIT;
        END
    END

    DECLARE @Duration int = DATEDIFF(SECOND, @StartTime, SYSDATETIME());
    SET @Msg = N'Differential backup procedure completed in ' + CAST(@Duration AS nvarchar(20)) + N' seconds.';
    RAISERROR(@Msg, CASE WHEN @Error=0 THEN 0 ELSE 16 END, 1) WITH NOWAIT;

    RETURN @Error;
END
GO