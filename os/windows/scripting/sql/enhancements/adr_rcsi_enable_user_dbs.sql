-- SQL Script to Enable Accelerated Database Recovery (ADR) and Read Committed Snapshot Isolation (RCSI)
-- for User Databases in SQL Server 2022.
-- Includes error handling, backout logic, necessary checks, and SET XACT_ABORT ON for safety.
-- Assumptions: Run this script as a user with ALTER DATABASE permissions.
-- Warnings: This will temporarily set databases to single-user mode, rolling back any active transactions.
--           Ensure this is run during a maintenance window. Test in non-production first. Backups are mandatory.
-- Monitoring: After running, query sys.databases to confirm settings and check error logs.
-- @RW

SET NOCOUNT ON;

-- Declare variables
DECLARE @db_name NVARCHAR(128);
DECLARE @sql NVARCHAR(MAX);
DECLARE @error_message NVARCHAR(4000);
DECLARE @is_adr_on BIT;
DECLARE @is_rcsi_on BIT;
DECLARE @compat_level INT;
DECLARE @active_session_count INT;
DECLARE @current_user_access NVARCHAR(60);

-- Table to log results and errors
CREATE TABLE #Log (
    DatabaseName NVARCHAR(128),
    Action NVARCHAR(50),
    Status NVARCHAR(50),
    ErrorMessage NVARCHAR(4000) NULL,
    Timestamp DATETIME DEFAULT GETDATE()
);

-- Cursor for user databases: online, not system, not read-only
DECLARE db_cursor CURSOR LOCAL FAST_FORWARD FOR
SELECT name
FROM sys.databases
WHERE database_id > 4  -- Exclude system databases (master, model, msdb, tempdb)
  AND state = 0        -- Online
  AND is_read_only = 0 -- Not read-only
  AND name NOT LIKE 'distribution%' -- Exclude distribution database if any;

OPEN db_cursor;
FETCH NEXT FROM db_cursor INTO @db_name;

WHILE @@FETCH_STATUS = 0
BEGIN
    BEGIN TRY
        -- Set XACT_ABORT ON for this database's operations (ensures rollback on error)
        SET XACT_ABORT ON;

        -- Check for active sessions (extra safety: skip if any other connections, to avoid killing sessions)
        SELECT @active_session_count = COUNT(*)
        FROM sys.dm_exec_sessions
        WHERE database_id = DB_ID(@db_name)
          AND session_id <> @@SPID;  -- Exclude current session

        IF @active_session_count > 0
        BEGIN
            INSERT INTO #Log (DatabaseName, Action, Status, ErrorMessage)
            VALUES (@db_name, 'Check Active Sessions', 'Skipped', 'Active sessions detected; retry during low activity.');
            GOTO NextDB;
        END

        -- Check if database is mirrored (ADR not supported with mirroring)
        IF EXISTS (SELECT 1 FROM sys.database_mirroring WHERE database_id = DB_ID(@db_name))
        BEGIN
            INSERT INTO #Log (DatabaseName, Action, Status, ErrorMessage)
            VALUES (@db_name, 'Check Mirroring', 'Skipped', 'Database is mirrored; ADR not supported.');
            GOTO NextDB;
        END

        -- Check compatibility level (>=150 recommended for SQL Server 2022 features)
        SELECT @compat_level = compatibility_level
        FROM sys.databases
        WHERE name = @db_name;

        IF @compat_level < 150
        BEGIN
            INSERT INTO #Log (DatabaseName, Action, Status, ErrorMessage)
            VALUES (@db_name, 'Check Compatibility', 'Skipped', 'Compatibility level < 150; Update recommended before enabling ADR/RCSI.');
            GOTO NextDB;
        END

        -- Get current settings for backout if needed
        SELECT
            @is_adr_on = is_accelerated_database_recovery_on,
            @is_rcsi_on = is_read_committed_snapshot_on,
            @current_user_access = user_access_desc
        FROM sys.databases
        WHERE name = @db_name;

        -- Log start
        INSERT INTO #Log (DatabaseName, Action, Status)
        VALUES (@db_name, 'Start Processing', 'In Progress');

        -- Set to single-user mode to acquire exclusive lock (rolls back active transactions)
        SET @sql = N'ALTER DATABASE [' + @db_name + N'] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;';
        EXEC sp_executesql @sql;

        -- Enable ADR if not already enabled
        IF @is_adr_on = 0
        BEGIN
            SET @sql = N'ALTER DATABASE [' + @db_name + N'] SET ACCELERATED_DATABASE_RECOVERY = ON;';
            EXEC sp_executesql @sql;
            INSERT INTO #Log (DatabaseName, Action, Status)
            VALUES (@db_name, 'Enable ADR', 'Success');
        END
        ELSE
        BEGIN
            INSERT INTO #Log (DatabaseName, Action, Status)
            VALUES (@db_name, 'Enable ADR', 'Already Enabled');
        END

        -- Enable RCSI if not already enabled (utilizes ADR's persistent version store for row versioning)
        IF @is_rcsi_on = 0
        BEGIN
            SET @sql = N'ALTER DATABASE [' + @db_name + N'] SET READ_COMMITTED_SNAPSHOT ON;';
            EXEC sp_executesql @sql;
            INSERT INTO #Log (DatabaseName, Action, Status)
            VALUES (@db_name, 'Enable RCSI', 'Success');
        END
        ELSE
        BEGIN
            INSERT INTO #Log (DatabaseName, Action, Status)
            VALUES (@db_name, 'Enable RCSI', 'Already Enabled');
        END

        -- Set back to original user access mode (typically MULTI_USER)
        SET @sql = N'ALTER DATABASE [' + @db_name + N'] SET ' + @current_user_access + N' WITH NO_WAIT;';
        EXEC sp_executesql @sql;

        -- Log completion
        INSERT INTO #Log (DatabaseName, Action, Status)
        VALUES (@db_name, 'Complete Processing', 'Success');

        -- Reset XACT_ABORT (optional, but good to scope it)
        SET XACT_ABORT OFF;

    END TRY
    BEGIN CATCH
        -- Capture error
        SET @error_message = ERROR_MESSAGE();

        -- Attempt backout: Ensure exclusive access, restore original settings, then original mode
        BEGIN TRY
            -- Get current user access (in case changed)
            SELECT @current_user_access = user_access_desc
            FROM sys.databases
            WHERE name = @db_name;

            -- If not already single-user (e.g., error before set), force it for reverts
            IF @current_user_access <> 'SINGLE_USER'
            BEGIN
                SET @sql = N'ALTER DATABASE [' + @db_name + N'] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;';
                EXEC sp_executesql @sql;
            END

            -- Revert ADR to original if changed
            DECLARE @current_adr BIT;
            SELECT @current_adr = is_accelerated_database_recovery_on
            FROM sys.databases
            WHERE name = @db_name;

            IF @current_adr <> @is_adr_on
            BEGIN
                SET @sql = N'ALTER DATABASE [' + @db_name + N'] SET ACCELERATED_DATABASE_RECOVERY = ' + CASE WHEN @is_adr_on = 1 THEN 'ON' ELSE 'OFF' END + ';';
                EXEC sp_executesql @sql;
            END

            -- Revert RCSI to original if changed
            DECLARE @current_rcsi BIT;
            SELECT @current_rcsi = is_read_committed_snapshot_on
            FROM sys.databases
            WHERE name = @db_name;

            IF @current_rcsi <> @is_rcsi_on
            BEGIN
                SET @sql = N'ALTER DATABASE [' + @db_name + N'] SET READ_COMMITTED_SNAPSHOT = ' + CASE WHEN @is_rcsi_on = 1 THEN 'ON' ELSE 'OFF' END + ';';
                EXEC sp_executesql @sql;
            END

            -- Set back to multi-user (or original mode)
            SET @sql = N'ALTER DATABASE [' + @db_name + N'] SET MULTI_USER WITH ROLLBACK IMMEDIATE;';
            EXEC sp_executesql @sql;

            INSERT INTO #Log (DatabaseName, Action, Status, ErrorMessage)
            VALUES (@db_name, 'Backout', 'Success', 'Reverted to original settings and MULTI_USER.');

        END TRY
        BEGIN CATCH
            -- If backout fails, log (manual intervention needed)
            INSERT INTO #Log (DatabaseName, Action, Status, ErrorMessage)
            VALUES (@db_name, 'Backout', 'Failed', ERROR_MESSAGE());
        END CATCH

        -- Log the error
        INSERT INTO #Log (DatabaseName, Action, Status, ErrorMessage)
        VALUES (@db_name, 'Error', 'Failed', @error_message);

        -- Reset XACT_ABORT in case of error
        SET XACT_ABORT OFF;

    END CATCH

NextDB:
    FETCH NEXT FROM db_cursor INTO @db_name;
END

CLOSE db_cursor;
DEALLOCATE db_cursor;

-- Output the log
SELECT * FROM #Log ORDER BY Timestamp;

DROP TABLE #Log;