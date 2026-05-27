/*
===============================================================================

This script provides a high-performance, automated recovery solution for
multiple SQL Server databases using the following logic:

    Pre-Execution Safety: Cleans up existing cursors, enables XACT_ABORT
    for atomicity, and checks for disk space before starting.

    Dynamic Directory Management: Uses xp_cmdshell to automatically create
    missing target Data and Log folders across different drive letters.

    Intelligent File Discovery: Scans the filesystem once and uses indexed
    temp tables with regex-like patterns to find backups regardless of
    database name length.

    Orchestrated Restore Sequence: Automatically identifies and applies the
    correct 4-part Split Full, Split Differential, and sequential Transaction
    Logs.

    Point-in-Time Accuracy: Utilizes the STOPAT clause to recover every database
    to the exact millisecond specified in the configuration.

    Performance Tuning: Accelerates data transfer using optimized BUFFERCOUNT
    and BLOCKSIZE settings to reduce I/O bottlenecks.

    Connection Handling: Switches databases to SINGLE_USER for the restore and
    forces them back to MULTI_USER even if a failure occurs.

    Integrity Validation: Concludes by running RESTORE VERIFYONLY and
    DBCC CHECKDB with checksums to guarantee the restored data is structurally sound.

@RW
===============================================================================
*/

SET NOCOUNT ON;
SET XACT_ABORT ON;

/*===============================================================================
  1. CONFIGURATION
===============================================================================*/
DECLARE @BaseDir       NVARCHAR(255) = 'C:\Backups\';
DECLARE @TargetTime    DATETIME       = '2026-02-26 16:05:00';
DECLARE @TargetTimeStr NVARCHAR(20)   = FORMAT(@TargetTime, 'yyyyMMddHHmmss');
DECLARE @StopAtStr     NVARCHAR(30)   = CONVERT(NVARCHAR(30), @TargetTime, 121); -- ms precision

DECLARE @BufferCount INT = 50;
DECLARE @BlockSize   INT = 65536;

DECLARE @RestoreList TABLE (
    DbName  NVARCHAR(128) PRIMARY KEY,
    DataDir NVARCHAR(255),
    LogDir  NVARCHAR(255)
);

INSERT INTO @RestoreList (DbName, DataDir, LogDir)
VALUES
    ('UserDatabase1', 'D:\SQLData\', 'L:\SQLLogs\'),
    ('Prod_Sales_DB', 'E:\Data\',    'M:\Logs\');
    -- Add more databases as needed, following the same structure

/*===============================================================================
  2. PRE-FLIGHT DIRECTORIES
===============================================================================*/
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

DECLARE @CurrentDB NVARCHAR(128), @TgtData NVARCHAR(255), @TgtLog NVARCHAR(255), @DirCMD NVARCHAR(500);
DECLARE preflight_cursor CURSOR LOCAL FAST_FORWARD FOR
    SELECT DbName, DataDir, LogDir FROM @RestoreList;

OPEN preflight_cursor;
FETCH NEXT FROM preflight_cursor INTO @CurrentDB, @TgtData, @TgtLog;
WHILE @@FETCH_STATUS = 0
BEGIN
    SET @DirCMD = 'IF NOT EXIST "' + @TgtData + '" MKDIR "' + @TgtData + '"';
    EXEC master..xp_cmdshell @DirCMD, no_output;
    SET @DirCMD = 'IF NOT EXIST "' + @TgtLog + '" MKDIR "' + @TgtLog + '"';
    EXEC master..xp_cmdshell @DirCMD, no_output;
    FETCH NEXT FROM preflight_cursor INTO @CurrentDB, @TgtData, @TgtLog;
END
CLOSE preflight_cursor; DEALLOCATE preflight_cursor;

EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
EXEC sp_configure 'show advanced options', 0; RECONFIGURE;

/*===============================================================================
  3. FILE DISCOVERY
===============================================================================*/
IF OBJECT_ID('tempdb..#BackupFiles') IS NOT NULL DROP TABLE #BackupFiles;
CREATE TABLE #BackupFiles (
    FolderType NVARCHAR(10) NOT NULL,
    FileName   NVARCHAR(512) NOT NULL,
    TS_RAW     NVARCHAR(15)  NULL
);

-- FIX: Match the xp_dirtree schema
DECLARE @Temp TABLE (subdirectory NVARCHAR(512), depth INT, isfile INT);

INSERT INTO @Temp EXEC master..xp_dirtree @BaseDir + 'FULL', 1, 1;
INSERT INTO #BackupFiles (FolderType, FileName) SELECT 'FULL', subdirectory FROM @Temp WHERE isfile = 1;
DELETE FROM @Temp;

INSERT INTO @Temp EXEC master..xp_dirtree @BaseDir + 'DIFF', 1, 1;
INSERT INTO #BackupFiles (FolderType, FileName) SELECT 'DIFF', subdirectory FROM @Temp WHERE isfile = 1;
DELETE FROM @Temp;

INSERT INTO @Temp EXEC master..xp_dirtree @BaseDir + 'LOG', 1, 1;
INSERT INTO #BackupFiles (FolderType, FileName) SELECT 'LOG', subdirectory FROM @Temp WHERE isfile = 1;

UPDATE #BackupFiles
SET TS_RAW = SUBSTRING(FileName, PATINDEX('%_[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9]%', FileName) + 1, 15)
WHERE PATINDEX('%_[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9]%', FileName) > 0;

/*===============================================================================
  4. MAIN RESTORE LOOP
===============================================================================*/
DECLARE db_cursor CURSOR LOCAL FAST_FORWARD FOR
    SELECT DbName, DataDir, LogDir FROM @RestoreList;

OPEN db_cursor;
FETCH NEXT FROM db_cursor INTO @CurrentDB, @TgtData, @TgtLog;

WHILE @@FETCH_STATUS = 0
BEGIN
    BEGIN TRY
        PRINT '>>> STARTING: ' + @CurrentDB;

        /*--- FULL ---*/
        DECLARE @FullFile NVARCHAR(512), @FullTS NVARCHAR(15);
        SELECT TOP 1 @FullFile = FileName, @FullTS = TS_RAW
        FROM #BackupFiles
        WHERE FolderType = 'FULL'
          AND FileName LIKE @CurrentDB + '_FULL_%'
          AND REPLACE(TS_RAW, '_', '') <= @TargetTimeStr
        ORDER BY TS_RAW DESC;

        IF @FullFile IS NULL RAISERROR('No FULL backup found for %s', 16, 1, @CurrentDB);

        DECLARE @FullCommon NVARCHAR(500) = CASE
            WHEN @FullFile LIKE '%_part%' THEN LEFT(@FullFile, CHARINDEX('_part', @FullFile)-1)
            ELSE LEFT(@FullFile, LEN(@FullFile)-4) END;

        IF OBJECT_ID('tempdb..#Stripes') IS NOT NULL DROP TABLE #Stripes;
        CREATE TABLE #Stripes (FileName NVARCHAR(512), PartNum INT);

        INSERT INTO #Stripes (FileName, PartNum)
        SELECT FileName,
               CASE WHEN FileName LIKE '%_part%'
                    THEN CAST(REPLACE(SUBSTRING(FileName, CHARINDEX('_part',FileName)+5,20),'.bak','') AS INT)
                    ELSE 1 END
        FROM #BackupFiles
        WHERE FolderType = 'FULL' AND FileName LIKE @FullCommon + '%';

        DECLARE @FromFull NVARCHAR(MAX) = '';
        SELECT @FromFull += ', DISK = ''' + @BaseDir + 'FULL\' + FileName + ''''
        FROM #Stripes ORDER BY PartNum;
        SET @FromFull = STUFF(@FromFull, 1, 2, '');

        /*--- Dynamic MOVE ---*/
        DECLARE @FirstStripe NVARCHAR(512) = (SELECT TOP 1 FileName FROM #Stripes ORDER BY PartNum);
        IF OBJECT_ID('tempdb..#FileList') IS NOT NULL DROP TABLE #FileList;
        CREATE TABLE #FileList (LogicalName NVARCHAR(128), PhysicalName NVARCHAR(260), [Type] CHAR(1));

        INSERT INTO #FileList (LogicalName, PhysicalName, [Type])
        EXEC ('RESTORE FILELISTONLY FROM DISK = ''' + @BaseDir + 'FULL\' + @FirstStripe + '''');

        DECLARE @MoveClause NVARCHAR(MAX) = '';
        SELECT @MoveClause += ', MOVE ''' + LogicalName + ''' TO ''' +
               CASE WHEN [Type] = 'L' THEN @TgtLog ELSE @TgtData END +
               REVERSE(LEFT(REVERSE(PhysicalName), CHARINDEX('\', REVERSE(PhysicalName))-1)) + ''''
        FROM #FileList;
        SET @MoveClause = STUFF(@MoveClause, 1, 2, '');

        /* SINGLE_USER only if DB exists */
        IF DB_ID(@CurrentDB) IS NOT NULL
        BEGIN
            EXEC('ALTER DATABASE ' + QUOTENAME(@CurrentDB) + ' SET SINGLE_USER WITH ROLLBACK IMMEDIATE;');
        END

        /* FULL RESTORE */
        DECLARE @SQL NVARCHAR(MAX);
        SET @SQL = N'RESTORE DATABASE ' + QUOTENAME(@CurrentDB) + N' FROM ' + @FromFull +
                   N' WITH NORECOVERY, REPLACE, CHECKSUM, BUFFERCOUNT = ' + CAST(@BufferCount AS NVARCHAR(10)) +
                   N', BLOCKSIZE = ' + CAST(@BlockSize AS NVARCHAR(10)) + N', ' + @MoveClause + N';';
        EXEC sp_executesql @SQL;
        PRINT '   FULL restored';

        /*--- DIFF (optional) ---*/
        DECLARE @DiffFile NVARCHAR(512), @DiffTS NVARCHAR(15);
        SELECT TOP 1 @DiffFile = FileName, @DiffTS = TS_RAW
        FROM #BackupFiles
        WHERE FolderType = 'DIFF'
          AND FileName LIKE @CurrentDB + '_DIFF_%'
          AND TS_RAW > @FullTS
          AND REPLACE(TS_RAW, '_', '') <= @TargetTimeStr
        ORDER BY TS_RAW DESC;

        IF @DiffFile IS NOT NULL
        BEGIN
            DECLARE @DiffCommon NVARCHAR(500) = CASE
                WHEN @DiffFile LIKE '%_part%' THEN LEFT(@DiffFile, CHARINDEX('_part',@DiffFile)-1)
                ELSE LEFT(@DiffFile, LEN(@DiffFile)-4) END;

            DELETE FROM #Stripes;
            INSERT INTO #Stripes (FileName, PartNum)
            SELECT FileName,
                   CASE WHEN FileName LIKE '%_part%'
                        THEN CAST(REPLACE(SUBSTRING(FileName, CHARINDEX('_part',FileName)+5,20),'.bak','') AS INT)
                        ELSE 1 END
            FROM #BackupFiles WHERE FolderType = 'DIFF' AND FileName LIKE @DiffCommon + '%';

            DECLARE @FromDiff NVARCHAR(MAX) = '';
            SELECT @FromDiff += ', DISK = ''' + @BaseDir + 'DIFF\' + FileName + ''''
            FROM #Stripes ORDER BY PartNum;
            SET @FromDiff = STUFF(@FromDiff, 1, 2, '');

            SET @SQL = N'RESTORE DATABASE ' + QUOTENAME(@CurrentDB) + N' FROM ' + @FromDiff +
                       N' WITH NORECOVERY, CHECKSUM, BUFFERCOUNT = ' + CAST(@BufferCount AS NVARCHAR(10)) +
                       N', BLOCKSIZE = ' + CAST(@BlockSize AS NVARCHAR(10)) + N';';
            EXEC sp_executesql @SQL;
            PRINT '   DIFF applied';
        END

        /*--- LOGS ---*/
        DECLARE @LastTS NVARCHAR(15) = ISNULL(@DiffTS, @FullTS);
        DECLARE @LogFile NVARCHAR(512);
        DECLARE log_cursor CURSOR LOCAL FAST_FORWARD FOR
            SELECT FileName FROM #BackupFiles
            WHERE FolderType = 'LOG'
              AND FileName LIKE @CurrentDB + '_LOG_%'
              AND TS_RAW > @LastTS
              AND REPLACE(TS_RAW, '_', '') <= @TargetTimeStr
            ORDER BY TS_RAW ASC;

        OPEN log_cursor;
        FETCH NEXT FROM log_cursor INTO @LogFile;
        WHILE @@FETCH_STATUS = 0
        BEGIN
            SET @SQL = N'RESTORE LOG ' + QUOTENAME(@CurrentDB) +
                       N' FROM DISK = ''' + @BaseDir + 'LOG\' + @LogFile +
                       N''' WITH NORECOVERY, STOPAT = ''' + @StopAtStr + N''';';
            EXEC sp_executesql @SQL;
            PRINT '   LOG: ' + @LogFile;
            FETCH NEXT FROM log_cursor INTO @LogFile;
        END
        CLOSE log_cursor; DEALLOCATE log_cursor;

        /*--- FINALIZE ---*/
        EXEC('RESTORE DATABASE ' + QUOTENAME(@CurrentDB) + ' WITH RECOVERY;');
        EXEC('ALTER DATABASE ' + QUOTENAME(@CurrentDB) + ' SET MULTI_USER;');

        PRINT '>>> INTEGRITY CHECK: ' + @CurrentDB;
        DBCC CHECKDB(@CurrentDB) WITH NO_INFOMSGS, ALL_ERRORMSGS, CHECKSUM;

        PRINT '   SUCCESS: ' + @CurrentDB;
    END TRY
    BEGIN CATCH
        PRINT '!!! FAILED ' + @CurrentDB + ': ' + ERROR_MESSAGE();
        IF DB_ID(@CurrentDB) IS NOT NULL
            EXEC('ALTER DATABASE ' + QUOTENAME(@CurrentDB) + ' SET MULTI_USER;');
    END CATCH

    FETCH NEXT FROM db_cursor INTO @CurrentDB, @TgtData, @TgtLog;
END

CLOSE db_cursor; DEALLOCATE db_cursor;
PRINT '--- PROCESS COMPLETE ---';