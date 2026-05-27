USE [master];
GO
/****************************************/
/* CONFIGURATION - EDIT THIS SECTION    */
/****************************************/
DECLARE @auditName      varchar(25)  = 'STIG_AUDIT';
DECLARE @auditPath      varchar(260) = 'C:\Audits';
DECLARE @auditFileSize  varchar(4)   = '200';     -- MB
DECLARE @auditFileCount varchar(5)   = '50';      -- -1 = UNLIMITED

-- =============================================
-- LIST OF LOGINS TO EXCLUDE FROM AUDITING
-- Add any application service accounts, batch jobs, monitoring accounts, etc.
-- =============================================
DECLARE @ExcludedLogins TABLE (LoginName sysname);
INSERT INTO @ExcludedLogins (LoginName) VALUES
    ('renamed_sa'),                     -- STIG renamed SA
    ('svc_app1'),                       -- Example app service account
    ('svc_app2'),                       -- Add more as needed
    ('svc_monitoring'),
    ('NT AUTHORITY\SYSTEM'),            -- Optional: exclude system account
    ('NT SERVICE\MSSQLSERVER');         -- SQL service account (if desired)

/****************************************/
/* Build exclusion predicate            */
/****************************************/
DECLARE @ExcludePredicate nvarchar(max) = '';

IF EXISTS (SELECT 1 FROM @ExcludedLogins)
BEGIN
    SET @ExcludePredicate = 'WHERE original_login_name NOT IN (';

    SELECT @ExcludePredicate = @ExcludePredicate + '''' + LoginName + ''','
    FROM @ExcludedLogins;

    -- Remove trailing comma and close parenthesis
    SET @ExcludePredicate = LEFT(@ExcludePredicate, LEN(@ExcludePredicate)-1) + ')';
END
ELSE
    SET @ExcludePredicate = '';   -- No exclusions

PRINT 'Exclusion predicate: ' + @ExcludePredicate;

/****************************************/
/* Drop existing audit if it exists     */
/****************************************/
DECLARE @SQL nvarchar(max);

-- Disable & drop Server Audit Specification
SET @SQL = '
IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = ''' + @auditName + '_SERVER_SPECIFICATION'')
BEGIN
    ALTER SERVER AUDIT SPECIFICATION [' + @auditName + '_SERVER_SPECIFICATION] WITH (STATE = OFF);
    DROP SERVER AUDIT SPECIFICATION [' + @auditName + '_SERVER_SPECIFICATION];
END';
EXEC(@SQL);

-- Disable & drop Server Audit
SET @SQL = '
IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = ''' + @auditName + ''')
BEGIN
    ALTER SERVER AUDIT [' + @auditName + '] WITH (STATE = OFF);
    DROP SERVER AUDIT [' + @auditName + '];
END';
EXEC(@SQL);

/****************************************/
/* Create the Server Audit with filter  */
/****************************************/
DECLARE @CreateAudit nvarchar(max);

SET @CreateAudit = '
CREATE SERVER AUDIT [' + @auditName + ']
TO FILE
(
    FILEPATH = ''' + @auditPath + ''',
    MAXSIZE = ' + @auditFileSize + ' MB,
    MAX_ROLLOVER_FILES = ' + CASE WHEN @auditFileCount = '' OR @auditFileCount = '-1' THEN 'UNLIMITED' ELSE @auditFileCount END + ',
    RESERVE_DISK_SPACE = OFF
)
WITH
(
    QUEUE_DELAY = 1000,
    ON_FAILURE = SHUTDOWN,
    AUDIT_GUID = NEWID()
)';

-- Append the exclusion predicate if any
IF @ExcludePredicate <> ''
    SET @CreateAudit = @CreateAudit + CHAR(13) + CHAR(10) + @ExcludePredicate;

EXEC(@CreateAudit);
GO

/****************************************/
/* Enable the Audit                     */
/****************************************/
ALTER SERVER AUDIT [STIG_AUDIT] WITH (STATE = ON);
GO

/****************************************/
/* Create the Server Audit Specification */
/****************************************/
CREATE SERVER AUDIT SPECIFICATION [STIG_AUDIT_SERVER_SPECIFICATION]
FOR SERVER AUDIT [STIG_AUDIT]
    ADD (APPLICATION_ROLE_CHANGE_PASSWORD_GROUP),
    ADD (AUDIT_CHANGE_GROUP),
    ADD (BACKUP_RESTORE_GROUP),
    ADD (DATABASE_CHANGE_GROUP),
    ADD (DATABASE_OBJECT_ACCESS_GROUP),
    ADD (DATABASE_OBJECT_CHANGE_GROUP),
    ADD (DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP),
    ADD (DATABASE_OBJECT_PERMISSION_CHANGE_GROUP),
    ADD (DATABASE_OPERATION_GROUP),
    ADD (DATABASE_OWNERSHIP_CHANGE_GROUP),
    ADD (DATABASE_PERMISSION_CHANGE_GROUP),
    ADD (DATABASE_PRINCIPAL_CHANGE_GROUP),
    ADD (DATABASE_PRINCIPAL_IMPERSONATION_GROUP),
    ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP),
    ADD (DBCC_GROUP),
    ADD (FAILED_LOGIN_GROUP),
    ADD (LOGIN_CHANGE_PASSWORD_GROUP),
    ADD (LOGOUT_GROUP),
    -- ADD (SCHEMA_OBJECT_ACCESS_GROUP),   -- Commented out per original script
    ADD (SCHEMA_OBJECT_CHANGE_GROUP),
    ADD (SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP),
    ADD (SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP),
    ADD (SERVER_OBJECT_CHANGE_GROUP),
    ADD (SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP),
    ADD (SERVER_OBJECT_PERMISSION_CHANGE_GROUP),
    ADD (SERVER_OPERATION_GROUP),
    ADD (SERVER_PERMISSION_CHANGE_GROUP),
    ADD (SERVER_PRINCIPAL_CHANGE_GROUP),
    ADD (SERVER_PRINCIPAL_IMPERSONATION_GROUP),
    ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),
    ADD (SERVER_STATE_CHANGE_GROUP),
    ADD (SUCCESSFUL_LOGIN_GROUP),
    ADD (TRACE_CHANGE_GROUP),
    ADD (USER_CHANGE_PASSWORD_GROUP)
WITH (STATE = ON);
GO

PRINT '=== STIG Audit with exclusions successfully created/enabled ===';
GO