/* =============================================================================
   QA VALIDATION SCRIPT: VERIFY CONNECTION & ENCRYPTION
   =============================================================================
   INSTRUCTIONS:
   1. Connect to the REPORTING SERVER in SSMS.
   2. Run this script as an Administrator first to validate the link.
   3. (Optional) Run as the Service Account (SHIFT+Right Click SSMS -> Run as different user)
      to validate "Least Privilege" access.
*/

USE [master];
GO

SET NOCOUNT ON;

-- =============================================================================
-- 1. CONFIGURATION VARIABLES
-- =============================================================================
DECLARE @LinkedServerName NVARCHAR(128) = 'LS_PROD_RO'; -- <--- UPDATE IF NEEDED
DECLARE @TestDatabase     NVARCHAR(128) = 'master';     -- DB to test connectivity against

-- =============================================================================
-- 2. EXECUTION LOGIC (DO NOT EDIT BELOW)
-- =============================================================================
PRINT '>>> STARTING VERIFICATION FOR: ' + @LinkedServerName;
PRINT '--------------------------------------------------';

DECLARE @SQL NVARCHAR(MAX);
DECLARE @ParamDefinition NVARCHAR(500);

--------------------------------------------------------------------------------
-- TEST 1: ENCRYPTION HANDSHAKE (Is the data secure?)
--------------------------------------------------------------------------------
PRINT 'TEST 1: CHECKING ENCRYPTION STATUS...';

-- We build the OPENQUERY string dynamically to insert the variable
SET @SQL = N'
    SELECT
        ''Encryption Check'' AS Test,
        c.session_id,
        c.client_net_address,
        c.auth_scheme,
        CASE
            WHEN c.encrypt_option = ''TRUE'' THEN ''PASS (Encrypted - Secure)''
            ELSE ''FAIL (Unencrypted - Insecure)''
        END AS [Status]
    FROM OPENQUERY(' + QUOTENAME(@LinkedServerName) + N',
        ''SELECT session_id, client_net_address, auth_scheme, encrypt_option
          FROM sys.dm_exec_connections
          WHERE session_id = @@SPID'') c;';

BEGIN TRY
    EXEC sp_executesql @SQL;
END TRY
BEGIN CATCH
    PRINT '   [CRITICAL FAIL] Could not query connection stats.';
    PRINT '   Error: ' + ERROR_MESSAGE();
END CATCH;

PRINT '--------------------------------------------------';

--------------------------------------------------------------------------------
-- TEST 2: DATA ACCESSIBILITY (Can we actually read data?)
--------------------------------------------------------------------------------
PRINT 'TEST 2: CHECKING READ ACCESS...';

SET @SQL = N'
    SELECT TOP 1
        ''Read Access Check'' AS Test,
        name AS [Remote DB Name],
        ''PASS (Data Readable)'' AS [Status]
    FROM OPENQUERY(' + QUOTENAME(@LinkedServerName) + N',
        ''SELECT name FROM ' + QUOTENAME(@TestDatabase) + N'.sys.databases'');';

BEGIN TRY
    EXEC sp_executesql @SQL;
END TRY
BEGIN CATCH
    PRINT '   [FAIL] Could not read data from remote server.';
    PRINT '   Error: ' + ERROR_MESSAGE();
    PRINT '   Hint: Check if the remote user has access to the DB.';
END CATCH;

PRINT '--------------------------------------------------';
PRINT '>>> VERIFICATION COMPLETE';
GO