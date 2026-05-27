-- =============================================
-- INSTANCE STIG AUTOMATED FIXES (SQL Server 2022/2025)
-- =============================================

EXEC sp_configure 'show advanced options', 1;
RECONFIGURE WITH OVERRIDE;

-- Windows Authentication only (V-271265)
EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 2;

-- SA account disabled + renamed (V-274444 / V-274445)
IF EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = 'sa')
BEGIN
    ALTER LOGIN sa DISABLE;
    ALTER LOGIN sa WITH NAME = renamed_sa;
    PRINT 'SA account disabled and renamed';
END

-- Hardening sp_configure settings
EXEC sp_configure 'xp_cmdshell', 0;
EXEC sp_configure 'clr enabled', 0;
EXEC sp_configure 'Ole Automation Procedures', 0;
EXEC sp_configure 'user options', 0;
EXEC sp_configure 'Ad Hoc Distributed Queries', 0;
EXEC sp_configure 'cross db ownership chaining', 0;
EXEC sp_configure 'remote admin connections', 0;
EXEC sp_configure 'default trace enabled', 1;
EXEC sp_configure 'backup compression default', 1;
EXEC sp_configure 'scan for startup procs', 0;
EXEC sp_configure 'filestream access level', 0;

RECONFIGURE WITH OVERRIDE;
PRINT '=== Instance STIG fixes completed ===';
GO